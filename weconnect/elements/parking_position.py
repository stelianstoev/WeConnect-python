import logging

from weconnect.addressable import AddressableAttribute
from weconnect.elements.generic_status import GenericStatus

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

        # rename dict key to match new structure
        if 'data' in fromDict:
            fromDict['value'] = fromDict['data']
            del fromDict['data']

        if 'latitude' in fromDict:
            self.latitude = fromDict['latitude']
            self.longitude = fromDict['longitude']
            fromDict.update({'value':{'carCapturedTimestamp': fromDict['lastUpdatedAt']}})
            del fromDict['lastUpdatedAt']
        else:
            self.latitude.enabled = False
            self.longitude.enabled = False
            self.enabled = False

        super().update(fromDict=fromDict, ignoreAttributes=(ignoreAttributes + ['lat', 'lon']))

    def __str__(self):
        string = super().__str__()
        if self.latitude:
            string += f'\n\tLatitude: {self.latitude}'
        if self.longitude:
            string += f'\n\tLongitude: {self.longitude}'
        return string
