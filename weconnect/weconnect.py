from __future__ import annotations
from typing import Dict, List, Set, Tuple, Callable, Any, Optional, Union

import os
from threading import Lock
import string
import locale
import logging
import json
from datetime import datetime, timedelta

import requests

from weconnect.auth.session_manager import SessionManager, Service, SessionUser
from weconnect.elements.vehicle import Vehicle
from weconnect.domain import Domain
from weconnect.elements.charging_station import ChargingStation
from weconnect.elements.general_controls import GeneralControls
from weconnect.addressable import AddressableLeaf, AddressableObject, AddressableDict
from weconnect.errors import RetrievalError, TooManyRequestsError
from weconnect.weconnect_errors import ErrorEventType
from weconnect.util import ExtendedEncoder
from weconnect.api.skoda_endpoints import Brand, APIEndpoints
from weconnect.api.skoda_mapper import map_skoda_vehicle
from weconnect.auth.openid_session import AccessType

LOG = logging.getLogger("weconnect")


class WeConnect(AddressableObject):  # pylint: disable=too-many-instance-attributes, too-many-public-methods
    """Main class used to interact with Skoda Connect (formerly WeConnect)"""

    def __init__(  # noqa: C901 # pylint: disable=too-many-arguments
        self,
        username: str,
        password: str,
        spin: Union[str, bool] = None,
        tokenfile: Optional[str] = None,
        updateAfterLogin: bool = True,
        loginOnInit: bool = False,
        fixAPI: bool = True,
        proxy: Optional[str] = None,
        maxAge: Optional[int] = None,
        maxAgePictures: Optional[int] = None,
        updateCapabilities: bool = True,
        updatePictures: bool = True,
        numRetries: int = 3,
        timeout: bool = None,
        selective: Optional[list[Domain]] = None,
        forceReloginAfter: Optional[int] = None,
        acceptTermsOnLogin: Optional[bool] = False,
    ) -> None:
        """Initialize Skoda Connect interface.

        Args:
            username (str): Username used with MySkoda. This is your Skoda ID.
            password (str): Password used with MySkoda.
            tokenfile (str, optional): Optional file to read/write token from/to. Defaults to None.
            updateAfterLogin (bool, optional): Update data from Skoda after logging in. Defaults to True.
            loginOnInit (bool, optional): Login after initialization. Defaults to False.
            fixAPI (bool, optional): Automatically fix known issues with the API responses. Defaults to True.
            proxy (str, optional): Set a proxy IP address and port
            maxAge (int, optional): Maximum age of the cache before data is fetched again. Defaults to None.
            maxAgePictures (Optional[int], optional): Maximum age of pictures in cache. Defaults to None.
            updateCapabilities (bool, optional): Update car capabilities. Defaults to True.
            updatePictures (bool, optional): Fetch and update pictures. Defaults to True.
            numRetries (int, optional): Number of retries when http requests fail. Defaults to 3.
            timeout (bool, optional): Timeout in seconds for connections.
            selective (list[Domain], optional): Domains to request data for.
            forceReloginAfter (int, optional): Force relogin after seconds.
        """
        super().__init__(localAddress='', parent=None)
        self.lock = Lock()
        self.username: str = username
        self.password: str = password
        self.spin: Union[str, bool] = spin

        self.__session: requests.Session = requests.Session()

        self.__vehicles: AddressableDict[str, Vehicle] = AddressableDict(localAddress='vehicles', parent=self)
        self.__stations: AddressableDict[str, ChargingStation] = AddressableDict(localAddress='chargingStations', parent=self)
        self.__controls: GeneralControls = GeneralControls(localAddress='controls', parent=self)
        self.__cache: Dict[str, Any] = {}
        self.fixAPI: bool = fixAPI
        self.proxy: Optional[str] = proxy

        if proxy:
            self.proxystring = {'http': 'http://' + self.proxy, 'https': 'http://' + self.proxy}
        else:
            self.proxystring = ""

        self.maxAge: Optional[int] = maxAge
        self.maxAgePictures: Optional[int] = maxAgePictures
        self.latitude: Optional[float] = None
        self.longitude: Optional[float] = None
        self.searchRadius: Optional[int] = None
        self.market: Optional[str] = None
        self.useLocale: Optional[str] = locale.getlocale()[0]
        self.__elapsed: List[timedelta] = []

        self.__enableTracker: bool = False

        self.__errorObservers: Set[Tuple[Callable[[Optional[Any], ErrorEventType], None], ErrorEventType]] = set()

        self.tokenfile = tokenfile

        # Skoda only - use MY_SKODA service
        self.__manager = SessionManager(tokenstorefile=tokenfile)
        self.__session = self.__manager.getSession(Service.MY_SKODA, SessionUser(username=username, password=password))
        self.__session.proxies.update(self.proxystring)
        self.__session.timeout = timeout
        self.__session.retries = numRetries
        self.__session.forceReloginAfter = forceReloginAfter

        if loginOnInit:
            self.__session.login()

        if updateAfterLogin:
            self.update(updateCapabilities=updateCapabilities, updatePictures=updatePictures, selective=selective)

    def __del__(self) -> None:
        self.disconnect()
        return super().__del__()

    def disconnect(self) -> None:
        pass

    @property
    def session(self) -> requests.Session:
        return self.__session

    @property
    def cache(self) -> Dict[str, Any]:
        return self.__cache

    def persistTokens(self) -> None:
        if self.__manager is not None and self.tokenfile is not None:
            self.__manager.saveTokenstore(self.tokenfile)

    def persistCacheAsJson(self, filename: str) -> None:
        with open(filename, 'w', encoding='utf8') as file:
            json.dump(self.__cache, file, cls=ExtendedEncoder)
        LOG.info('Writing cachefile %s', filename)

    def fillCacheFromJson(self, filename: str, maxAge: int, maxAgePictures: Optional[int] = None) -> None:
        self.maxAge = maxAge
        if maxAgePictures is None:
            self.maxAgePictures = maxAge
        else:
            self.maxAgePictures = maxAgePictures

        try:
            with open(filename, 'r', encoding='utf8') as file:
                self.__cache = json.load(file)
        except json.decoder.JSONDecodeError:
            LOG.error('Cachefile %s seems corrupted will delete it and try to create a new one. '
                      'If this problem persists please check if a problem with your disk exists.', filename)
            os.remove(filename)
        LOG.info('Reading cachefile %s', filename)

    def fillCacheFromJsonString(self, jsonString, maxAge: int, maxAgePictures: Optional[int] = None) -> None:
        self.maxAge = maxAge
        if maxAgePictures is None:
            self.maxAgePictures = maxAge
        else:
            self.maxAgePictures = maxAgePictures

        self.__cache = json.loads(jsonString)
        LOG.info('Reading cache from string')

    def clearCache(self) -> None:
        self.__cache.clear()
        LOG.info('Clearing cache')

    def enableTracker(self) -> None:
        self.__enableTracker = True
        for vehicle in self.vehicles:
            vehicle.enableTracker()

    def disableTracker(self) -> None:
        self.__enableTracker = True
        for vehicle in self.vehicles:
            vehicle.disableTracker()

    def login(self) -> None:
        self.__session.login()

    @property
    def vehicles(self) -> AddressableDict[str, Vehicle]:
        return self.__vehicles

    def get_garage_url(self) -> str:
        """Get the garage API URL for Skoda."""
        return APIEndpoints.get_full_url('vehicle', 'garage')

    def get_vehicle_status_url(self, vin: str) -> str:
        """Get the vehicle status API URL."""
        return APIEndpoints.get_full_url('vehicle', 'vehicle_status', vin=vin)

    def get_parking_position_url(self, vin: str) -> str:
        """Get the parking position API URL (Cariad)."""
        return APIEndpoints.get_cariad_url('parking_position', vin=vin)

    def get_vehicle_images_url(self, vin: str) -> str:
        """Get the vehicle images API URL (Skoda API)."""
        return APIEndpoints.get_skoda_url('images', vin=vin)

    def get_charging_stations_url(self) -> str:
        """Get the charging stations API URL."""
        return APIEndpoints.get_charging_stations_url()

    def update(self, updateCapabilities: bool = True, updatePictures: bool = True, force: bool = False,
               selective: Optional[list[Domain]] = None) -> None:
        self.__elapsed.clear()
        try:
            self.updateVehicles(updateCapabilities=updateCapabilities, updatePictures=updatePictures, force=force, selective=selective)
            self.updateChargingStations(force=force)
        finally:
            self.updateComplete()
            self.__session.cookies.clear()

    def updateVehicles(self, updateCapabilities: bool = True, updatePictures: bool = True, force: bool = False,  # noqa: C901
                       selective: Optional[list[Domain]] = None) -> None:
        with self.lock:
            catchedRetrievalError = None
            # Skoda uses garage endpoint
            url = self.get_garage_url()
            data = self.fetchData(url, force)
            if data is not None:
                # Skoda uses 'vehicles' key in 'garage' response
                vehicle_list = None
                if 'vehicles' in data and data['vehicles']:
                    vehicle_list = data['vehicles']
                
                if vehicle_list:
                    vins: List[str] = []
                    for vehicleDict in vehicle_list:
                        # Map Skoda response to WeConnect-Python format
                        vehicleDict = map_skoda_vehicle(vehicleDict)
                        
                        if 'vin' not in vehicleDict:
                            break
                        vin: str = vehicleDict['vin']
                        vins.append(vin)
                        try:
                            if vin not in self.__vehicles:
                                vehicle = Vehicle(weConnect=self, vin=vin, parent=self.__vehicles, fromDict=vehicleDict, fixAPI=self.fixAPI,
                                                  updateCapabilities=updateCapabilities, updatePictures=updatePictures, selective=selective,
                                                  enableTracker=self.__enableTracker)
                                self.__vehicles[vin] = vehicle
                            else:
                                self.__vehicles[vin].update(fromDict=vehicleDict, updateCapabilities=updateCapabilities, updatePictures=updatePictures,
                                                            selective=selective)
                        except RetrievalError as retrievalError:
                            catchedRetrievalError = retrievalError
                            LOG.error('Failed to retrieve data for VIN %s: %s', vin, retrievalError)
                    # delete those vins that are not anymore available
                    for vin in [vin for vin in self.__vehicles if vin not in vins]:
                        del self.__vehicles[vin]

                    self.__cache[url] = (data, str(datetime.utcnow()))
            if catchedRetrievalError:
                raise catchedRetrievalError

    def setChargingStationSearchParameters(self, latitude: float, longitude: float, searchRadius: Optional[int] = None, market: Optional[str] = None,
                                           useLocale: Optional[str] = locale.getlocale()[0]) -> None:
        self.latitude = latitude
        self.longitude = longitude
        self.searchRadius = searchRadius
        self.market = market
        self.useLocale = useLocale

    def getChargingStations(self, latitude, longitude, searchRadius=None, market=None, useLocale=None,  # noqa: C901
                            force=False) -> AddressableDict[str, ChargingStation]:
        chargingStationMap: AddressableDict[str, ChargingStation] = AddressableDict(localAddress='', parent=None)
        base_url = self.get_charging_stations_url()
        
        # Skoda uses POST with JSON body
        radius = searchRadius if searchRadius is not None else 1000
        post_data = {
            'placeTypes': ['CHARGING_STATION'],
            'location': {'latitude': latitude, 'longitude': longitude},
            'radiusInMeters': radius,
            'requirements': {}
        }
        
        try:
            response = self.session.post(base_url, json=post_data, allow_redirects=False, access_type=AccessType.ACCESS)
            self.recordElapsed(response.elapsed)
            
            if response.status_code == requests.codes['ok']:
                data = response.json()
                if data is not None and 'nearbyPlaces' in data:
                    for place in data['nearbyPlaces']:
                        if 'id' not in place or 'location' not in place:
                            continue
                        
                        # Calculate distance
                        lat_diff = place['location']['latitude'] - latitude
                        lon_diff = place['location']['longitude'] - longitude
                        distance = ((lat_diff**2 + lon_diff**2)**0.5) * 111000  # Approximate meters
                        place['distance'] = distance
                        
                        # Convert to charging station format
                        station_dict = self._convert_skoda_place_to_station(place)
                        stationId = place['id']
                        station = ChargingStation(weConnect=self, stationId=stationId, parent=chargingStationMap, fromDict=station_dict,
                                                fixAPI=self.fixAPI)
                        chargingStationMap[stationId] = station
                        
                    # Sort by distance
                    sorted_stations = sorted(chargingStationMap.values(), key=lambda s: s.distance.value if s.distance.enabled else float('inf'))
                    # Rebuild dict in sorted order
                    chargingStationMap = AddressableDict(localAddress='', parent=None)
                    for station in sorted_stations:
                        chargingStationMap[station.id.value] = station
                        
                    self.__cache[base_url] = (data, str(datetime.utcnow()))
        except requests.exceptions.ConnectionError as connectionError:
            LOG.warning('Could not fetch charging stations: %s', connectionError)
        except requests.exceptions.ChunkedEncodingError as chunkedEncodingError:
            LOG.warning('Could not fetch charging stations: %s', chunkedEncodingError)
        except requests.exceptions.ReadTimeout as timeoutError:
            LOG.warning('Could not fetch charging stations: %s', timeoutError)
            
        return chargingStationMap
    
    def _convert_skoda_place_to_station(self, place: Dict) -> Dict:
        """Convert Skoda place data to charging station format."""
        station = {
            'id': place.get('id', ''),
            'name': place.get('name', ''),
            'latitude': place.get('location', {}).get('latitude', 0),
            'longitude': place.get('location', {}).get('longitude', 0),
            'distance': place.get('distance', 0),
        }
        
        if 'address' in place:
            addr = place['address']
            formatted_address = []
            if addr.get('street'):
                formatted_address.append(addr['street'])
                if addr.get('houseNumber'):
                    formatted_address[-1] += ' ' + addr['houseNumber']
            if addr.get('zipCode'):
                formatted_address.append(addr['zipCode'])
            if addr.get('city'):
                formatted_address.append(addr['city'])
            if addr.get('country'):
                formatted_address.append(addr['country'])
            station['address'] = {
                'formattedAddress': ', '.join(formatted_address),
                'street': addr.get('street', ''),
                'houseNumber': addr.get('houseNumber', ''),
                'city': addr.get('city', ''),
                'postalCode': addr.get('zipCode', ''),
                'country': addr.get('country', '')
            }
        
        if 'chargingStation' in place:
            cs = place['chargingStation']
            station['chargingPower'] = cs.get('maxElectricPowerInKw', 0)
            
            # Convert to charging spots format
            total_spots = cs.get('totalCountChargingPoints', 0)
            available_spots = cs.get('availableCountChargingPoints', 0)
            charging_spots = []
            for i in range(total_spots):
                spot = {
                    'maxChargePower': cs.get('maxElectricPowerInKw', 0),
                    'status': 'AVAILABLE' if i < available_spots else 'OCCUPIED'
                }
                charging_spots.append(spot)
            station['chargingSpots'] = charging_spots
        
        return station

    def updateChargingStations(self, force: bool = False) -> None:  # noqa: C901 # pylint: disable=too-many-branches
        if self.latitude is not None and self.longitude is not None:
            base_url = self.get_charging_stations_url()
            url: str = f'{base_url}?latitude={self.latitude}&longitude={self.longitude}'
            if self.market is not None:
                url += f'&market={self.market}'
            if self.useLocale is not None:
                url += f'&locale={self.useLocale}'
            if self.searchRadius is not None:
                url += f'&searchRadius={self.searchRadius}'
            if self.session.userId is not None:
                url += f'&userId={self.session.userId}'
            data = self.fetchData(url, force)
            if data is not None:
                if 'chargingStations' in data and data['chargingStations']:
                    ids: List[str] = []
                    for stationDict in data['chargingStations']:
                        if 'id' not in stationDict:
                            break
                        stationId: str = stationDict['id']
                        ids.append(stationId)
                        if stationId not in self.__stations:
                            station: ChargingStation = ChargingStation(weConnect=self, stationId=stationId, parent=self.__stations, fromDict=stationDict,
                                                                       fixAPI=self.fixAPI)
                            self.__stations[stationId] = station
                        else:
                            self.__stations[stationId].update(fromDict=stationDict)
                    # delete those station IDs that are not available anymore
                    for stationId in [stationId for stationId in ids if stationId not in self.__stations]:
                        del self.__stations[stationId]

                    self.__cache[url] = (data, str(datetime.utcnow()))

    def getLeafChildren(self) -> List[AddressableLeaf]:
        leafChildren = [children for vehicle in self.__vehicles.values() for children in vehicle.getLeafChildren()] \
            + [children for station in self.__stations.values() for children in station.getLeafChildren()]
        if self.__controls.spinControl is not None and self.__controls.spinControl.enabled:
            leafChildren += [self.__controls.spinControl]
        return leafChildren

    def __str__(self) -> str:
        returnString: str = ''
        for vin, vehicle in self.__vehicles.items():
            returnString += f'Vehicle: {vin}\n{vehicle}\n'
        for stationId, station in sorted(self.__stations.items(), key=lambda x: x[1].distance.value if x[1].distance.value is not None else -1, reverse=False):
            returnString += f'Charging Station: {stationId}\n{station}\n'
        return returnString

    def addErrorObserver(self, observer: Callable, errortype: ErrorEventType) -> None:
        self.__errorObservers.add((observer, errortype))
        LOG.debug('%s: Error event observer added for type: %s', self.getGlobalAddress(), errortype)

    def removeErrorObserver(self, observer: Callable, errortype: Optional[ErrorEventType] = None) -> None:
        self.__errorObservers = filter(lambda observerEntry: observerEntry[0] == observer
                                       or (errortype is not None and observerEntry[1] == errortype), self.__errorObservers)

    def getErrorObservers(self, errortype) -> List[Any]:
        return [observerEntry[0] for observerEntry in self.getErrorObserverEntries(errortype)]

    def getErrorObserverEntries(self, errortype: ErrorEventType) -> List[Any]:
        observers: Set[Tuple[Callable, ErrorEventType]] = set()
        for observerEntry in self.__errorObservers:
            observer, observertype = observerEntry
            del observer
            if errortype & observertype:
                observers.add(observerEntry)
        return observers

    def notifyError(self, element, errortype: ErrorEventType, detail: string, message: string = None) -> None:
        observers: List[Callable] = self.getErrorObservers(errortype)
        for observer in observers:
            observer(element=element, errortype=errortype, detail=detail, message=message)
        LOG.debug('%s: Notify called for errors with type: %s for %d observers', self.getGlobalAddress(), errortype, len(observers))

    def recordElapsed(self, elapsed: timedelta) -> None:
        self.__elapsed.append(elapsed)

    def getMinElapsed(self) -> timedelta:
        if len(self.__elapsed) == 0:
            return None
        return min(self.__elapsed)

    def getMaxElapsed(self) -> timedelta:
        if len(self.__elapsed) == 0:
            return None
        return max(self.__elapsed)

    def getAvgElapsed(self) -> timedelta:
        if len(self.__elapsed) == 0:
            return None
        return sum(self.__elapsed, timedelta()) / len(self.__elapsed)

    def getTotalElapsed(self) -> timedelta:
        if len(self.__elapsed) == 0:
            return None
        return sum(self.__elapsed, timedelta())

    def fetchData(self, url, force=False, allowEmpty=False, allowHttpError=False, allowedErrors=None) -> Optional[Dict[str, Any]]:  # noqa: C901
        data: Optional[Dict[str, Any]] = None
        cacheDate: Optional[datetime] = None
        if not force and (self.maxAge is not None and self.cache is not None and url in self.cache):
            data, cacheDateString = self.cache[url]
            cacheDate = datetime.fromisoformat(cacheDateString)
        if data is None or self.maxAge is None \
                or (cacheDate is not None and cacheDate < (datetime.utcnow() - timedelta(seconds=self.maxAge))):
            try:
                statusResponse: requests.Response = self.session.get(url, allow_redirects=False)
                self.recordElapsed(statusResponse.elapsed)
                if statusResponse.status_code in (requests.codes['ok'], requests.codes['multiple_status']):
                    data = statusResponse.json()
                    if self.cache is not None:
                        self.cache[url] = (data, str(datetime.utcnow()))
                elif statusResponse.status_code == requests.codes['too_many_requests']:
                    self.notifyError(self, ErrorEventType.HTTP, str(statusResponse.status_code),
                                     'Could not fetch data due to too many requests from your account')
                    raise TooManyRequestsError('Could not fetch data due to too many requests from your account. '
                                               f'Status Code was: {statusResponse.status_code}')
                elif statusResponse.status_code == requests.codes['unauthorized']:
                    LOG.info('Server asks for new authorization')
                    self.login()
                    statusResponse = self.session.get(url, allow_redirects=False)
                    self.recordElapsed(statusResponse.elapsed)

                    if statusResponse.status_code in (requests.codes['ok'], requests.codes['multiple_status']):
                        data = statusResponse.json()
                        if self.cache is not None:
                            self.cache[url] = (data, str(datetime.utcnow()))
                    elif not allowHttpError or (allowedErrors is not None and statusResponse.status_code not in allowedErrors):
                        self.notifyError(self, ErrorEventType.HTTP, str(statusResponse.status_code), 'Could not fetch data due to server error')
                        raise RetrievalError(f'Could not fetch data even after re-authorization. Status Code was: {statusResponse.status_code}')
                elif not allowHttpError or (allowedErrors is not None and statusResponse.status_code not in allowedErrors):
                    self.notifyError(self, ErrorEventType.HTTP, str(statusResponse.status_code), 'Could not fetch data due to server error')
                    raise RetrievalError(f'Could not fetch data. Status Code was: {statusResponse.status_code}')
            except requests.exceptions.ConnectionError as connectionError:
                self.notifyError(self, ErrorEventType.CONNECTION, 'connection', 'Could not fetch data due to connection problem')
                raise RetrievalError from connectionError
            except requests.exceptions.ChunkedEncodingError as chunkedEncodingError:
                self.notifyError(self, ErrorEventType.CONNECTION, 'chunked encoding error',
                                 'Could not fetch data due to connection problem with chunked encoding')
                raise RetrievalError from chunkedEncodingError
            except requests.exceptions.ReadTimeout as timeoutError:
                self.notifyError(self, ErrorEventType.TIMEOUT, 'timeout', 'Could not fetch data due to timeout')
                raise RetrievalError from timeoutError
            except requests.exceptions.RetryError as retryError:
                raise RetrievalError from retryError
            except requests.exceptions.JSONDecodeError as jsonError:
                if allowEmpty:
                    data = None
                else:
                    self.notifyError(self, ErrorEventType.JSON, 'json', 'Could not fetch data due to error in returned data')
                    raise RetrievalError from jsonError
        return data
