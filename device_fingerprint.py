import hashlib
import json
import logging
from datetime import datetime

class DeviceFingerprint:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_fingerprint(self, device_info):
        """Make a unique device ID"""
        try:
            # Get device info
            hardware_id = f"{device_info.get('ID_VENDOR_ID', '')}:{device_info.get('ID_MODEL_ID', '')}"
            serial = device_info.get('ID_SERIAL_SHORT', '')
            manufacturer = device_info.get('ID_VENDOR', '')
            product = device_info.get('ID_MODEL', '')
            
            # Make unique ID
            device_data = {
                'hardware_id': hardware_id,
                'serial': serial,
                'manufacturer': manufacturer,
                'product': product,
                'timestamp': datetime.now().isoformat()
            }
            
            # Make hash
            behavioral_hash = hashlib.sha256(
                json.dumps(device_data, sort_keys=True).encode()
            ).hexdigest()
            
            # Create fingerprint
            fingerprint = {
                'hardware_id': hardware_id,
                'serial': serial,
                'manufacturer': manufacturer,
                'product': product,
                'behavioral_hash': behavioral_hash,
                'timestamp': device_data['timestamp']
            }
            
            self.logger.info(f"Made fingerprint for device: {hardware_id}")
            return fingerprint
            
        except Exception as e:
            self.logger.error(f"Error making fingerprint: {e}")
            return None 


