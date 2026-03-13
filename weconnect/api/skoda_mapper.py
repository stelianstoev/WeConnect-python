"""
Skoda-specific data mapping for WeConnect-Python.
Maps Skoda API response fields to WeConnect-Python's expected format.
"""
import logging
from typing import Dict, Any

LOG = logging.getLogger("weconnect")


def map_skoda_vehicle(vehicle_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map Skoda API vehicle response to WeConnect-Python format.
    
    Skoda returns different field names than VW. This function converts them.
    
    Args:
        vehicle_dict: Raw response from Skoda API
        
    Returns:
        Dictionary with field names that WeConnect-Python expects
    """
    mapped = dict(vehicle_dict)  # Start with a copy
    
    # Map Skoda-specific fields to WeConnect-Python expected fields
    
    # title -> model (e.g., "Škoda Enyaq" -> "Enyaq")
    if 'title' in vehicle_dict and 'model' not in vehicle_dict:
        title = vehicle_dict.get('title', '')
        # Extract model name from title (e.g., "Škoda Enyaq" -> "Enyaq")
        if 'Enyaq' in title:
            mapped['model'] = 'Enyaq'
        elif 'Octavia' in title:
            mapped['model'] = 'Octavia'
        elif 'Superb' in title:
            mapped['model'] = 'Superb'
        elif 'Kodiaq' in title:
            mapped['model'] = 'Kodiaq'
        elif 'Karoq' in title:
            mapped['model'] = 'Karoq'
        elif 'Scala' in title:
            mapped['model'] = 'Scala'
        elif 'Kamiq' in title:
            mapped['model'] = 'Kamiq'
        else:
            mapped['model'] = title
    
    # systemModelId -> similar to model ID
    if 'systemModelId' in vehicle_dict:
        mapped['modelCode'] = vehicle_dict['systemModelId']
    
    # state -> enrollmentStatus
    if 'state' in vehicle_dict:
        state = vehicle_dict['state']
        if state == 'ACTIVATED':
            mapped['enrollmentStatus'] = 'enrolled'
        elif state == 'DEACTIVATED':
            mapped['enrollmentStatus'] = 'not_enrolled'
        else:
            mapped['enrollmentStatus'] = state.lower()
    
    # images -> keep as is but may have different structure
    if 'renders' in vehicle_dict:
        # Skoda uses 'renders' instead of 'images'
        # WeConnect-Python expects images to be a dict, not a list
        if 'images' not in vehicle_dict:
            # Convert renders to empty dict to avoid type error
            mapped['images'] = {}
    
    # Remove Skoda-specific fields that WeConnect-Python doesn't understand
    fields_to_remove = [
        'renders', 'compositeRenders', 'priority', 
        'systemModelId', 'state', 'title'
    ]
    for field in fields_to_remove:
        if field in mapped:
            del mapped[field]
    
    return mapped


def map_skoda_status(domain: str, status_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map Skoda API status response to WeConnect-Python format.
    
    Args:
        domain: The domain name (e.g., 'battery', 'charging', 'climatisation')
        status_dict: Raw status from Skoda API
        
    Returns:
        Dictionary with field names that WeConnect-Python expects
    """
    mapped = dict(status_dict)
    
    # Battery status mapping
    if domain == 'battery' or 'batteryStatus' in status_dict:
        # Skoda uses different field names for battery
        if 'stateOfChargeInPercent' in status_dict and 'batteryStatus' not in status_dict:
            mapped['batteryStatus'] = {
                'currentSOC_pct': status_dict.get('stateOfChargeInPercent'),
                'chargingState': status_dict.get('chargingStatus', 'Unknown'),
                'remainingRange_km': status_dict.get('cruisingRangeElectricInMeters', 0) / 1000,
            }
        
        if 'batteryLevel' in status_dict and 'currentSOC_pct' not in str(mapped.get('batteryStatus', '')):
            if 'batteryStatus' not in mapped:
                mapped['batteryStatus'] = {}
            mapped['batteryStatus']['currentSOC_pct'] = status_dict.get('batteryLevel')
    
    # Window status mapping
    if 'windows' in status_dict:
        for window_key, window_data in status_dict['windows'].items():
            # Skoda uses 'windowOpen_pct' instead of 'openState'
            if 'windowOpen_pct' in window_data:
                open_pct = window_data.get('windowOpen_pct', 0)
                if open_pct == 0:
                    window_data['openState'] = 'closed'
                elif open_pct > 0 and open_pct < 100:
                    window_data['openState'] = 'open'
                else:
                    window_data['openState'] = 'unknown'
    
    # Charging status mapping
    if 'charging' in status_dict or domain == 'charging':
        if 'chargeType' in status_dict:
            # Skoda charge types: 'AC' -> 'AC', 'DC' -> 'DC'
            mapped['chargingSettings'] = {
                'chargeType': status_dict.get('chargeType'),
                'maxChargeCurrent': status_dict.get('maxChargeCurrent', 'maximum'),
                'targetChargeLevel': status_dict.get('targetChargeLevel', 100),
            }
    
    return mapped
