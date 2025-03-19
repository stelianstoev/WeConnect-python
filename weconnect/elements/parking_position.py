import logging

from weconnect.addressable import AddressableAttribute
from weconnect.elements.generic_status import GenericStatus

from myskoda.models.position import PositionType

LOG = logging.getLogger("weconnect")


class ParkingPosition(GenericStatus):
    def __init__(
        self,
        vehicle,
        parent,
        statusId,
        fromDict=None,
        fixAPI=True,
    ):
        self.latitude = AddressableAttribute(localAddress='latitude', parent=self, value=None, valueType=float)
        self.longitude = AddressableAttribute(localAddress='longitude', parent=self, value=None, valueType=float)
        super().__init__(vehicle=vehicle, parent=parent, statusId=statusId, fromDict=fromDict, fixAPI=fixAPI)

    def update(self, fromDict, ignoreAttributes=None):
        ignoreAttributes = ignoreAttributes or []
        LOG.debug('Update ParkingPosition from dict')

        pos = next(pos for pos in fromDict['positions'] if pos['type'] == PositionType.VEHICLE)

        if 'latitude' in pos['gps_coordinates']:
            
            self.latitude.fromDict(pos['gps_coordinates'], 'latitude')
            self.longitude.fromDict(pos['gps_coordinates'], 'longitude')
            fromDict.update({'value':{'carCapturedTimestamp': fromDict['timestamp']}})
            self.latitude.enabled = True
            self.longitude.enabled = True
            self.enabled = True
        else:
            self.latitude.enabled = False
            self.longitude.enabled = False
            self.enabled = False

        super().update(fromDict=fromDict, ignoreAttributes=(ignoreAttributes + ['lat', 'lon']))

    def __str__(self):
        string = super().__str__()
        if self.latitude.enabled:
            string += f'\n\tLatitude: {self.latitude.value}'
        if self.longitude.enabled:
            string += f'\n\tLongitude: {self.longitude.value}'
        return string
