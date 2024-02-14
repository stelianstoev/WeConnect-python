import logging

from weconnect.addressable import AddressableAttribute
from weconnect.elements.generic_status import GenericStatus

LOG = logging.getLogger("weconnect")


class BatteryStatus(GenericStatus):
    def __init__(
        self,
        vehicle,
        parent,
        statusId,
        fromDict=None,
        fixAPI=True,
    ):
        self.currentSOC_pct = AddressableAttribute(
            localAddress='currentSOC_pct', parent=self, value=None, valueType=int)
        self.cruisingRangeElectric_km = AddressableAttribute(
            localAddress='cruisingRangeElectric_km', value=None, parent=self, valueType=int)
        super().__init__(vehicle=vehicle, parent=parent, statusId=statusId, fromDict=fromDict, fixAPI=fixAPI)

    def update(self, fromDict, ignoreAttributes=None):
        ignoreAttributes = ignoreAttributes or []
        LOG.debug('Update battery status from dict')

        if 'batteryStatus' in fromDict:
            if 'cruisingRangeElectric_km' in fromDict['batteryStatus']:
                cruisingRangeElectric_km = int(fromDict['batteryStatus']['cruisingRangeElectric_km']/1000)

                if self.fixAPI and cruisingRangeElectric_km == 0x3FFF:
                    cruisingRangeElectric_km = None
                    LOG.info('%s: Attribute cruisingRangeElectric_km was error value 0x3FFF. Setting error state instead'
                             ' of 16383 km.', self.getGlobalAddress())

                if (self.fixAPI
                    and round((self.cruisingRangeElectric_km.value or 0) * 0.621371) == cruisingRangeElectric_km and cruisingRangeElectric_km != 0
                        and self.currentSOC_pct.value == int(fromDict['batteryStatus']['currentSOC_pct'])):
                    LOG.info('%s: Attribute cruisingRangeElectric_km was miscalculated (miles/km) this is a bug in the API and the new value will not be used',
                             self.getGlobalAddress())
                else:
                    self.cruisingRangeElectric_km.setValueWithCarTime(
                        cruisingRangeElectric_km, lastUpdateFromCar=None, fromServer=True)
            else:
                self.cruisingRangeElectric_km.enabled = False

            self.currentSOC_pct.fromDict(fromDict['batteryStatus'], 'currentSOC_pct')
            self.currentSOC_pct.enabled= True
            self.cruisingRangeElectric_km.enabled = True
        else:
            self.currentSOC_pct.enabled = False
            self.cruisingRangeElectric_km.enabled = False

        super().update(fromDict=fromDict, ignoreAttributes=(
            ignoreAttributes + ['currentSOC_pct', 'cruisingRangeElectric_km']))

    def __str__(self):
        string = super().__str__()
        if self.currentSOC_pct.enabled:
            string += f'\n\tCurrent SoC: {self.currentSOC_pct}%'
        if self.cruisingRangeElectric_km.enabled:
            if self.cruisingRangeElectric_km is not None:
                string += f'\n\tRange: {self.cruisingRangeElectric_km}km'
            else:
                string += '\n\tRange: currently unknown'
        return string
