"""Verisure OWA binary sensor platform."""

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import DOMAIN, VerisureDevice
from .automation_api import AutomationContact
from .coordinators import AlarmCoordinator, AutomationContactCoordinator
from .entity import securitas_device_info
from .verisure_owa_api import Installation

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Verisure OWA binary sensor entities."""
    entry_data = hass.data[DOMAIN][entry.entry_id]
    coordinator: AlarmCoordinator = entry_data["alarm_coordinator"]
    securitas_devices: list[VerisureDevice] = entry_data["devices"]

    entities: list[BinarySensorEntity] = [
        WifiConnectedSensor(coordinator, device.installation)
        for device in securitas_devices
    ]
    contact_coordinator: AutomationContactCoordinator | None = entry_data.get(
        "automation_contact_coordinator"
    )
    if contact_coordinator is not None and securitas_devices:
        installation = securitas_devices[0].installation
        entities.extend(
            AutomationContactOpeningSensor(contact_coordinator, installation, contact)
            for contact in contact_coordinator.data.contacts.values()
        )
    async_add_entities(entities, False)


class WifiConnectedSensor(  # type: ignore[override]
    CoordinatorEntity[AlarmCoordinator],
    BinarySensorEntity,
):
    """WiFi connection status from coordinator — no independent polling."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_has_entity_name = True
    _attr_name = "WiFi Connected"
    _attr_should_poll = False

    def __init__(
        self, coordinator: AlarmCoordinator, installation: Installation
    ) -> None:
        super().__init__(coordinator)
        self._installation = installation
        self._attr_unique_id = (
            f"v4_securitas_direct.{installation.number}_wifi_connected"
        )
        self._attr_device_info = securitas_device_info(installation)

    @property
    def is_on(self) -> bool | None:  # type: ignore[override]
        """Return True if WiFi is connected."""
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.status.wifi_connected


class AutomationContactOpeningSensor(  # type: ignore[override]
    CoordinatorEntity[AutomationContactCoordinator],
    BinarySensorEntity,
):
    """Door/window contact exposed by the Verisure Automation API."""

    _attr_device_class = BinarySensorDeviceClass.OPENING
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        coordinator: AutomationContactCoordinator,
        installation: Installation,
        contact: AutomationContact,
    ) -> None:
        super().__init__(coordinator)
        self._device_label = contact.device_label
        self._attr_name = contact.name
        self._attr_unique_id = (
            f"v4_securitas_direct.{installation.number}_automation_contact_"
            f"{contact.device_label}"
        )
        self._attr_device_info = securitas_device_info(installation)

    @property
    def is_on(self) -> bool | None:  # type: ignore[override]
        """Return True when the contact reports open."""
        contact = self.coordinator.data.contacts.get(self._device_label)
        return contact.is_open if contact is not None else None

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return the last report timestamp when supplied by Verisure."""
        contact = self.coordinator.data.contacts.get(self._device_label)
        if contact is None or contact.report_time is None:
            return {}
        return {"report_time": contact.report_time}
