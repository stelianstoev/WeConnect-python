"""
API Endpoint mappings for Skoda car brand.
This module provides URL mappings for Skoda.
"""

from enum import Enum


class Brand(Enum):
    """Supported car brands - Skoda only."""
    SKODA = 'skoda'


class APIEndpoints:
    """API endpoint URLs for Skoda car brand."""
    
    # Base URL for Skoda
    BASE_URL = 'https://mysmob.api.connect.skoda-auto.cz'
    
    # VW/Cariad API base URL (for parking position and images)
    CARIAD_BASE_URL = 'https://emea.bff.cariad.digital'
    
    # Identity URLs (OAuth)
    IDENTITY_URLS = {
        'authorize': 'https://identity.vwgroup.io/oidc/v1/authorize',
        'token_exchange': 'https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/exchange-authorization-code?tokenType=CONNECT',
        'token_refresh': 'https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/refresh-token?tokenType=CONNECT',
        'authorize_base': 'https://identity.vwgroup.io/oidc/v1/authorize',
    }
    
    # Vehicle API endpoints
    VEHICLE_URLS = {
        'garage': '/api/v2/garage',
        'vehicle_status': '/api/v2/vehicle-status/{vin}',
        'vehicle_status_full': '/api/v2/vehicle-status/{vin}',
        'driving_range': '/api/v2/vehicle-status/{vin}/driving-range',
        'parking_position': '/api/v1/maps/positions?vin={vin}',
        'trips': '/api/v1/trips/{vin}',
        'images': '/api/v1/vehicle-information/{vin}/renders',
        'vehicle_details': '/api/v2/garage/vehicles/{vin}',
    }
    
    # VW/Cariad endpoints (for parking position and images)
    CARIAD_URLS = {
        'parking_position': '/vehicle/v1/vehicles/{vin}/parkingposition',
        'vehicle_status': '/vehicle/v1/vehicles/{vin}/selectivestatus',
        'images': '/media/v2/vehicle-images/{vin}',
    }
    
    # Skoda-specific endpoints
    SKODA_URLS = {
        'images': '/api/v1/vehicle-information/{vin}/renders',
        'parking_position': '/api/v1/maps/positions?vin={vin}',
    }
    
    # Charging endpoints
    CHARGING_URLS = {
        'charging': '/api/v1/charging/{vin}',
        'charging_start': '/api/v1/charging/{vin}/start',
        'charging_stop': '/api/v1/charging/{vin}/stop',
        'charge_limit': '/api/v1/charging/{vin}/set-charge-limit',
        'charge_current': '/api/v1/charging/{vin}/set-charging-current',
        'auto_unlock': '/api/v1/charging/{vin}/set-auto-unlock-plug',
    }
    
    # Air conditioning endpoints
    AIR_CONDITIONING_URLS = {
        'air_conditioning': '/api/v2/air-conditioning/{vin}',
        'air_conditioning_start': '/api/v2/air-conditioning/{vin}/start',
        'air_conditioning_stop': '/api/v2/air-conditioning/{vin}/stop',
        'target_temperature': '/api/v2/air-conditioning/{vin}/settings/target-temperature',
        'ac_at_unlock': '/api/v2/air-conditioning/{vin}/settings/ac-at-unlock',
        'window_heating_start': '/api/v2/air-conditioning/{vin}/start-window-heating',
        'window_heating_stop': '/api/v2/air-conditioning/{vin}/stop-window-heating',
    }
    
    # Other endpoints
    OTHER_URLS = {
        'spin_verify': '/api/v1/spin/verify',
        'vehicle_wakeup': '/api/v1/vehicle-wakeup/{vin}?applyRequestLimiter=true',
        'access': '/api/v1/vehicle-access/{vin}/{action}',
        'honk_and_flash': '/api/v1/vehicle-access/{vin}/honk-and-flash',
        'lock': '/api/v1/vehicle-access/{vin}/lock',
        'unlock': '/api/v1/vehicle-access/{vin}/unlock',
        'connection_status': '/api/v2/connection-status/{vin}/readiness',
        'maintenance': '/api/v3/vehicle-maintenance/{vin}/report',
        'users': '/api/v1/users',
    }
    
    # Charging stations
    CHARGING_STATION_URL = '/api/v1/charging-stations'
    
    @classmethod
    def get_base_url(cls) -> str:
        """Get the base API URL for Skoda."""
        return cls.BASE_URL
    
    @classmethod
    def get_cariad_base_url(cls) -> str:
        """Get the Cariad API base URL."""
        return cls.CARIAD_BASE_URL
    
    @classmethod
    def get_full_url(cls, endpoint_type: str, endpoint_key: str, **kwargs) -> str:
        """Get a full URL for an endpoint.
        
        Args:
            endpoint_type: Type of endpoint (vehicle, charging, air_conditioning, etc.)
            endpoint_key: The specific endpoint key
            **kwargs: Variables to substitute in the URL (e.g., vin, action)
            
        Returns:
            The full URL
        """
        # Select the appropriate endpoint dictionary
        if endpoint_type == 'vehicle':
            endpoint_map = cls.VEHICLE_URLS
        elif endpoint_type == 'charging':
            endpoint_map = cls.CHARGING_URLS
        elif endpoint_type == 'air_conditioning':
            endpoint_map = cls.AIR_CONDITIONING_URLS
        elif endpoint_type == 'other':
            endpoint_map = cls.OTHER_URLS
        elif endpoint_type == 'cariad':
            endpoint_map = cls.CARIAD_URLS
        else:
            endpoint_map = cls.VEHICLE_URLS
        
        # Get the endpoint path
        endpoint_path = endpoint_map.get(endpoint_key, '')
        
        # Substitute variables in the URL
        if kwargs:
            endpoint_path = endpoint_path.format(**kwargs)
        
        return cls.BASE_URL + endpoint_path
    
    @classmethod
    def get_cariad_url(cls, endpoint_key: str, **kwargs) -> str:
        """Get a full URL for a Cariad endpoint."""
        endpoint_path = cls.CARIAD_URLS.get(endpoint_key, '')
        
        if kwargs:
            endpoint_path = endpoint_path.format(**kwargs)
        
        return cls.CARIAD_BASE_URL + endpoint_path
    
    @classmethod
    def get_skoda_url(cls, endpoint_key: str, **kwargs) -> str:
        """Get a full URL for a Skoda-specific endpoint."""
        endpoint_path = cls.SKODA_URLS.get(endpoint_key, '')
        
        if kwargs:
            endpoint_path = endpoint_path.format(**kwargs)
        
        return cls.BASE_URL + endpoint_path
    
    @classmethod
    def get_identity_url(cls, url_type: str) -> str:
        """Get an identity/OAuth URL."""
        return cls.IDENTITY_URLS.get(url_type, '')
    
    @classmethod
    def get_charging_stations_url(cls) -> str:
        """Get the charging stations URL."""
        return cls.BASE_URL + cls.CHARGING_STATION_URL

    # Legacy compatibility methods for brand parameter
    @classmethod
    def get_full_url_brand(cls, brand: Brand, endpoint_type: str, endpoint_key: str, **kwargs) -> str:
        """Legacy method that ignores brand (Skoda only)."""
        return cls.get_full_url(endpoint_type, endpoint_key, **kwargs)
    
    @classmethod
    def get_charging_stations_url_brand(cls, brand: Brand) -> str:
        """Legacy method that ignores brand (Skoda only)."""
        return cls.get_charging_stations_url()
