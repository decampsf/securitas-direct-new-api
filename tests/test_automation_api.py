"""Tests for the optional Verisure Automation API client."""

from __future__ import annotations

from http.cookies import SimpleCookie
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.securitas.automation_api import (
    AutomationInstallation,
    AutomationMfaRequiredError,
    VerisureAutomationClient,
    select_automation_installation,
)


def _response(
    *, status: int = 200, body: dict | str = "", cookies: dict[str, str] | None = None
) -> AsyncMock:
    response = AsyncMock()
    response.status = status
    response.text = AsyncMock(
        return_value=json.dumps(body) if isinstance(body, dict) else body
    )
    jar = SimpleCookie()
    for name, value in (cookies or {}).items():
        jar[name] = value
    response.cookies = jar
    return response


def _wire(method: MagicMock, responses: list[AsyncMock]) -> None:
    iterator = iter(responses)

    def factory(*_args, **_kwargs):
        context = AsyncMock()
        context.__aenter__ = AsyncMock(return_value=next(iterator))
        context.__aexit__ = AsyncMock(return_value=False)
        return context

    method.side_effect = factory


@pytest.mark.asyncio
async def test_authenticate_keeps_only_session_cookies() -> None:
    session = MagicMock()
    session.post = MagicMock()
    _wire(
        session.post,
        [_response(cookies={"vid": "vid-token", "vs-refresh": "refresh-token"})],
    )
    changed = MagicMock()
    client = VerisureAutomationClient(
        session, "user@example.com", on_cookies_changed=changed
    )

    await client.authenticate("password")

    assert client.cookies == {
        "vid": "vid-token",
        "vs-refresh": "refresh-token",
    }
    changed.assert_called_once_with(client.cookies)
    _, kwargs = session.post.call_args
    assert kwargs["auth"].login == "user@example.com"
    assert kwargs["auth"].password == "password"


@pytest.mark.asyncio
async def test_mfa_challenge_and_validation() -> None:
    session = MagicMock()
    session.post = MagicMock()
    _wire(
        session.post,
        [
            _response(cookies={"vs-stepup": "challenge"}),
            _response(),
            _response(
                cookies={
                    "vid": "vid-token",
                    "vs-access": "access-token",
                    "vs-refresh": "refresh-token",
                }
            ),
        ],
    )
    client = VerisureAutomationClient(session, "user@example.com")

    with pytest.raises(AutomationMfaRequiredError):
        await client.authenticate("password")
    await client.validate_mfa("123456")

    assert client.cookies["vid"] == "vid-token"
    assert session.post.call_count == 3


@pytest.mark.asyncio
async def test_installations_and_contact_states() -> None:
    session = MagicMock()
    session.post = MagicMock()
    session.get = MagicMock()
    _wire(
        session.post,
        [
            _response(
                body={
                    "data": {
                        "account": {"installations": [{"giid": "123", "alias": "Home"}]}
                    }
                }
            ),
            _response(
                body={
                    "data": {
                        "installation": {
                            "doorWindows": [
                                {
                                    "device": {
                                        "deviceLabel": "MG 01",
                                        "area": "Front door",
                                        "gui": {"label": "Entrance"},
                                    },
                                    "state": "OPEN",
                                    "reportTime": "2026-07-24T12:00:00Z",
                                },
                                {
                                    "device": {
                                        "deviceLabel": "MG 02",
                                        "area": "Kitchen",
                                        "gui": {},
                                    },
                                    "state": "CLOSE",
                                },
                            ]
                        }
                    }
                }
            ),
        ],
    )
    client = VerisureAutomationClient(
        session, "user@example.com", cookies={"vid": "token"}
    )

    installations = await client.get_installations()
    contacts = await client.get_contacts("123")

    assert installations == [AutomationInstallation(giid="123", alias="Home")]
    assert contacts[0].name == "Entrance"
    assert contacts[0].is_open is True
    assert contacts[1].name == "Kitchen"
    assert contacts[1].is_open is False


@pytest.mark.asyncio
async def test_expired_session_refreshes_and_retries() -> None:
    session = MagicMock()
    session.post = MagicMock()
    session.get = MagicMock()
    _wire(
        session.post,
        [
            _response(status=401),
            _response(
                body={
                    "data": {
                        "account": {"installations": [{"giid": "123", "alias": "Home"}]}
                    }
                }
            ),
        ],
    )
    _wire(
        session.get,
        [_response(cookies={"vid": "new", "vs-refresh": "new-refresh"})],
    )
    client = VerisureAutomationClient(
        session, "user@example.com", cookies={"vid": "old"}
    )

    installations = await client.get_installations()

    assert installations[0].giid == "123"
    assert client.cookies["vid"] == "new"
    assert session.post.call_count == 2
    assert session.get.call_count == 1


def test_select_installation_matches_normalized_alias_or_single_fallback() -> None:
    installations = [
        AutomationInstallation(giid="1", alias="5 Rue des Quatre-Chevaliers"),
        AutomationInstallation(giid="2", alias="Office"),
    ]

    assert (
        select_automation_installation(installations, "5 RUE DES QUATRE CHEVALIERS")
        == installations[0]
    )
    assert select_automation_installation(installations, "Unknown") is None
    assert (
        select_automation_installation([installations[1]], "Unknown")
        == (installations[1])
    )
