from enum import Enum
import logging

from weconnect.addressable import AddressableAttribute
from weconnect.elements.generic_status import GenericStatus

LOG = logging.getLogger("weconnect")


class PlugStatus(GenericStatus):
    def __init__(
        self,
        vehicle,
        parent,
        statusId,
        fromDict=None,
        fixAPI=True,
    ):
        self.plugConnectionState = AddressableAttribute(
            localAddress='plugConnectionState', parent=self, value=None, valueType=PlugStatus.PlugConnectionState)
        self.plugLockState = AddressableAttribute(
            localAddress='plugLockState', value=None, parent=self, valueType=PlugStatus.PlugLockState)
        self.externalPower = AddressableAttribute(
            localAddress='externalPower', value=None, parent=self, valueType=PlugStatus.ExternalPower)
        self.ledColor = AddressableAttribute(localAddress='ledColor', value=None, parent=self, valueType=PlugStatus.LedColor)
        super().__init__(vehicle=vehicle, parent=parent, statusId=statusId, fromDict=fromDict, fixAPI=fixAPI)

    def update(self, fromDict, ignoreAttributes=None):
        ignoreAttributes = ignoreAttributes or []
        LOG.debug('Update Plug status from dict')

        if 'plugStatus' in fromDict:
            self.plugConnectionState.fromDict(fromDict['plugStatus'], 'plugConnectionState')
            self.plugLockState.fromDict(fromDict['plugStatus'], 'plugLockState')
            self.externalPower.fromDict(fromDict['plugStatus'], 'externalPower')
            self.ledColor.fromDict(fromDict['plugStatus'], 'ledColor')
        else:
            self.plugConnectionState.enabled = False
            self.plugLockState.enabled = False
            self.externalPower.enabled = False
            self.ledColor.enabled = False

        super().update(fromDict=fromDict, ignoreAttributes=(
            ignoreAttributes + ['plugConnectionState', 'plugLockState', 'externalPower', 'ledColor']))

    def __str__(self):
        string = super().__str__()
        string += '\n\tPlug:'
        if self.plugConnectionState.enabled:
            string += f' {self.plugConnectionState}, '  # pylint: disable=no-member
        if self.plugLockState.enabled:
            string += f'{self.plugLockState}'  # pylint: disable=no-member
        if self.externalPower.enabled:
            string += f', External Power: {self.externalPower}'  # pylint: disable=no-member
        if self.ledColor.enabled:
            string += f', Led color: {self.ledColor}'  # pylint: disable=no-member
        return string

    class PlugConnectionState(Enum,):
        CONNECTED = 'Connected'
        DISCONNECTED = 'Disconnected'
        INVALID = 'Invalid'
        UNSUPPORTED = 'Unsupported'
        UNKNOWN = 'Unknown unlock plug state'

    class PlugLockState(Enum,):
        LOCKED = 'Locked'
        UNLOCKED = 'Unlocked'
        INVALID = 'Invalid'
        UNSUPPORTED = 'Unsupported'
        UNKNOWN = 'Unknown unlock plug state'

    class ExternalPower(Enum,):
        READY = 'ready'
        ACTIVE = 'active'
        UNAVAILABLE = 'unavailable'
        INVALID = 'invalid'
        UNSUPPORTED = 'unsupported'
        UNKNOWN = 'unknown external power'

    class LedColor(Enum,):
        NONE = 'none'
        GREEN = 'green'
        RED = 'red'
        UNKNOWN = 'unknown plug led color'
