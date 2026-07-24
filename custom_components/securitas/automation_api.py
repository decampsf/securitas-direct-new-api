"""Client for the Verisure Automation API used by door/window sensors."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from typing import Any

from aiohttp import BasicAuth, ClientError, ClientSession


class AutomationApiError(Exception):
    """Base error raised by the Verisure Automation API client."""


class AutomationAuthenticationError(AutomationApiError):
    """The Automation API rejected the current credentials or session."""


class AutomationMfaRequiredError(AutomationApiError):
    """The Automation API sent an MFA challenge."""


@dataclass(frozen=True, slots=True)
class AutomationInstallation:
    """Installation returned by the Automation account query."""

    giid: str
    alias: str


@dataclass(frozen=True, slots=True)
class AutomationContact:
    """Door/window contact returned by the Automation overview query."""

    device_label: str
    name: str
    area: str
    state: str
    report_time: str | None = None

    @property
    def is_open(self) -> bool | None:
        """Return the normalized opening state."""
        state = self.state.strip().upper()
        if state == "OPEN":
            return True
        if state in {"CLOSE", "CLOSED"}:
            return False
        return None


_INSTALLATIONS_QUERY = """
query fetchAllInstallations($email: String!) {
  account(email: $email) {
    installations {
      giid
      alias
    }
  }
}
"""

_CONTACTS_QUERY = """
query Overview($giid: String!) {
  installation(giid: $giid) {
    alias
    doorWindows {
      device {
        deviceLabel
        area
        gui {
          label
        }
      }
      state
      reportTime
    }
  }
}
"""


class VerisureAutomationClient:
    """Small async client for automation01/02.verisure.com."""

    _HOSTS = ("automation01.verisure.com", "automation02.verisure.com")

    def __init__(
        self,
        session: ClientSession,
        username: str,
        *,
        cookies: dict[str, str] | None = None,
        on_cookies_changed: Callable[[dict[str, str]], None] | None = None,
    ) -> None:
        self._session = session
        self.username = username
        self._cookies = dict(cookies or {})
        self._on_cookies_changed = on_cookies_changed
        self._host_index = 0

    @property
    def cookies(self) -> dict[str, str]:
        """Return a copy of the current session cookies."""
        return dict(self._cookies)

    @property
    def host(self) -> str:
        """Return the currently selected Automation host."""
        return self._HOSTS[self._host_index]

    def _switch_host(self) -> None:
        self._host_index = (self._host_index + 1) % len(self._HOSTS)

    def _cookie_header(self) -> str:
        return ";".join(f"{name}={value}" for name, value in self._cookies.items())

    def _replace_response_cookies(self, response: Any) -> None:
        response_cookies = {
            name: morsel.value for name, morsel in response.cookies.items()
        }
        if not response_cookies:
            return
        if response_cookies == self._cookies:
            return
        self._cookies = response_cookies
        if self._on_cookies_changed is not None:
            self._on_cookies_changed(self.cookies)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "Home Assistant Verisure OWA",
        }
        if self._cookies:
            headers["Cookie"] = self._cookie_header()
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        auth: BasicAuth | None = None,
        retry_server_error: bool = True,
        replace_cookies: bool = False,
    ) -> tuple[int, str]:
        attempts = 2 if retry_server_error else 1
        for attempt in range(attempts):
            request = self._session.post if method == "POST" else self._session.get
            kwargs: dict[str, Any] = {"headers": self._headers()}
            if json_body is not None:
                kwargs["json"] = json_body
            if auth is not None:
                kwargs["auth"] = auth
            try:
                async with request(f"https://{self.host}{path}", **kwargs) as response:
                    if replace_cookies:
                        self._replace_response_cookies(response)
                    text = await response.text()
                    if response.status >= 500 and attempt == 0:
                        self._switch_host()
                        continue
                    return response.status, text
            except ClientError as err:
                if attempt == 0 and retry_server_error:
                    self._switch_host()
                    continue
                raise AutomationApiError(
                    f"Unable to connect to the Automation API: {err}"
                ) from err
        raise AutomationApiError("Automation request failed")

    @staticmethod
    def _raise_for_status(status: int, action: str) -> None:
        if status == 401:
            raise AutomationAuthenticationError(
                f"Automation authentication failed during {action}"
            )
        if status >= 400:
            raise AutomationApiError(
                f"Automation request failed during {action} (HTTP {status})"
            )

    async def authenticate(self, password: str) -> None:
        """Authenticate with a password and retain only returned cookies."""
        self._cookies = {}
        status, _ = await self._request(
            "POST",
            "/auth/login",
            json_body={},
            auth=BasicAuth(self.username, password),
            replace_cookies=True,
        )
        self._raise_for_status(status, "login")
        if "vs-stepup" in self._cookies:
            mfa_status, _ = await self._request("POST", "/auth/mfa", json_body={})
            self._raise_for_status(mfa_status, "MFA challenge")
            raise AutomationMfaRequiredError("Automation MFA code required")
        if not self._cookies:
            raise AutomationAuthenticationError(
                "Automation login returned no session cookies"
            )

    async def validate_mfa(self, code: str) -> None:
        """Complete a pending Automation MFA challenge."""
        status, _ = await self._request(
            "POST",
            "/auth/mfa/validate",
            json_body={"token": code},
            replace_cookies=True,
        )
        self._raise_for_status(status, "MFA validation")
        if "vid" not in self._cookies:
            raise AutomationAuthenticationError(
                "Automation MFA validation returned no session"
            )

    async def refresh_session(self) -> None:
        """Refresh expired Automation cookies."""
        status, _ = await self._request("GET", "/auth/token", replace_cookies=True)
        self._raise_for_status(status, "session refresh")

    async def _graphql_once(
        self, operation_name: str, variables: dict[str, Any], query: str
    ) -> dict[str, Any]:
        status, text = await self._request(
            "POST",
            "/graphql",
            json_body={
                "operationName": operation_name,
                "variables": variables,
                "query": query,
            },
        )
        self._raise_for_status(status, operation_name)
        try:
            body = json.loads(text)
        except json.JSONDecodeError as err:
            raise AutomationApiError(
                f"Automation returned invalid JSON during {operation_name}"
            ) from err
        errors = body.get("errors")
        if errors:
            message = errors[0].get("message", "unknown GraphQL error")
            raise AutomationApiError(f"{operation_name} failed: {message}")
        data = body.get("data")
        if not isinstance(data, dict):
            raise AutomationApiError(f"{operation_name} returned no data")
        return data

    async def _graphql(
        self, operation_name: str, variables: dict[str, Any], query: str
    ) -> dict[str, Any]:
        try:
            return await self._graphql_once(operation_name, variables, query)
        except AutomationAuthenticationError:
            await self.refresh_session()
            return await self._graphql_once(operation_name, variables, query)

    async def get_installations(self) -> list[AutomationInstallation]:
        """Return the Automation installations for this account."""
        data = await self._graphql(
            "fetchAllInstallations",
            {"email": self.username},
            _INSTALLATIONS_QUERY,
        )
        account = data.get("account") or {}
        return [
            AutomationInstallation(
                giid=str(item.get("giid", "")), alias=str(item.get("alias", ""))
            )
            for item in account.get("installations") or []
            if item.get("giid")
        ]

    async def get_contacts(self, giid: str) -> list[AutomationContact]:
        """Return current door/window states for one installation."""
        data = await self._graphql("Overview", {"giid": giid}, _CONTACTS_QUERY)
        installation = data.get("installation") or {}
        contacts: list[AutomationContact] = []
        for item in installation.get("doorWindows") or []:
            device = item.get("device") or {}
            label = str(device.get("deviceLabel", ""))
            if not label:
                continue
            gui = device.get("gui") or {}
            area = str(device.get("area", ""))
            name = str(gui.get("label") or area or label)
            contacts.append(
                AutomationContact(
                    device_label=label,
                    name=name,
                    area=area,
                    state=str(item.get("state", "")),
                    report_time=(
                        str(item["reportTime"])
                        if item.get("reportTime") is not None
                        else None
                    ),
                )
            )
        return contacts


def select_automation_installation(
    installations: list[AutomationInstallation], alias: str
) -> AutomationInstallation | None:
    """Match an Automation installation to the OWA installation alias."""

    def normalize(value: str) -> str:
        return "".join(char for char in value.casefold() if char.isalnum())

    wanted = normalize(alias)
    for installation in installations:
        if normalize(installation.alias) == wanted:
            return installation
    if len(installations) == 1:
        return installations[0]
    return None
