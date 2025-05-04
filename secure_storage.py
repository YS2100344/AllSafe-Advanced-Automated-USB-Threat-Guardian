import sqlite3 as sqlite
import logging
import os
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
import base64
import secrets
import struct

class SQLCipherDatabase:
    def __init__(self):
        # Use db in home dir for better permissions
        self.db_path = os.path.expanduser("~/usb_monitor.db")
        self.key_version = 1  # Current version
        
        # Get encryption key
        try:
            logging.info("Trying to load existing key...")
            # Try to load key
            self.encryption_key = self._load_key_components()
            logging.info("🔑 Got existing key")
        except Exception as e:
            logging.warning(f"Couldn't load key: {str(e)}")
            try:
                logging.info("Trying to make new key...")
                # Generate new key if loading fails
                self.encryption_key = self._generate_encryption_key()
                logging.info("🔑 Made new key")
            except Exception as e:
                logging.error(f"Failed to make key: {str(e)}")
                raise Exception(f"Key init failed: {str(e)}")
        
        # Check key is set
        if not hasattr(self, 'encryption_key') or not self.encryption_key:
            raise Exception("Key not properly set up")
            
        self.init_database()

    def _generate_encryption_key(self):
        """Make a strong key with PBKDF2"""
        try:
            logging.info("Starting key gen...")
            # Random salt
            salt = secrets.token_bytes(32)  # Big salt
            logging.info("Made salt")
            
            # Random passphrase
            passphrase = secrets.token_urlsafe(64)  # Long passphrase
            logging.info("Made passphrase")
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),  
                length=32,  
                salt=salt,
                iterations=500000, 
            )
            logging.info("Set up PBKDF2")
            
            # Make the key
            key = kdf.derive(passphrase.encode())
            logging.info("Made key")
            
            # Save salt and passphrase
            self._store_key_components(salt, passphrase, key)
            logging.info("Saved key parts")
            
            return key
        except Exception as e:
            logging.error(f"Error in _generate_encryption_key: {str(e)}")
            raise

    def _store_key_components(self, salt, passphrase, key):
        """Save key parts with extra protection"""
        try:
            key_file = os.path.expanduser("~/usb_monitor.key")
            logging.info(f"Saving key parts to {key_file}")
            
            # Add version and time
            timestamp = int(datetime.now().timestamp())
            version_data = struct.pack('!II', self.key_version, timestamp)
            
            # Make HMAC for checking later
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(version_data + salt + passphrase.encode())
            hmac_digest = h.finalize()
            
            with open(key_file, 'wb') as f:
                f.write(version_data)
                f.write(hmac_digest)
                f.write(salt)
                f.write(b'\n')
                f.write(passphrase.encode())
            
            # Set tight permissions
            os.chmod(key_file, 0o600)
            logging.info("🔑 Saved key parts safely")
        except Exception as e:
            logging.error(f"Error saving key parts: {str(e)}")
            raise

    def _load_key_components(self):
        """Load key parts and check they're good"""
        try:
            key_file = os.path.expanduser("~/usb_monitor.key")
            logging.info(f"Loading key from {key_file}")
            
            if not os.path.exists(key_file):
                raise FileNotFoundError(f"Key file missing: {key_file}")
            
            with open(key_file, 'rb') as f:
                # Read version and time
                version_data = f.read(8)
                version, timestamp = struct.unpack('!II', version_data)
                
                # Read HMAC
                stored_hmac = f.read(32)
                
                # Read salt and passphrase
                salt = f.readline().strip()
                passphrase = f.readline().strip().decode()
                
                # Make key to check HMAC
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=salt,
                    iterations=500000,
                )
                key = kdf.derive(passphrase.encode())
                
                # Check if HMAC matches
                h = hmac.HMAC(key, hashes.SHA256())
                h.update(version_data + salt + passphrase.encode())
                computed_hmac = h.finalize()
                
                if not secrets.compare_digest(stored_hmac, computed_hmac):
                    raise ValueError("Key file looks tampered with")
                
                logging.info("🔑 Loaded key parts")
                return key
        except Exception as e:
            logging.error(f"Error loading key: {str(e)}")
            raise

    def _encrypt_data(self, data):
        """Encrypt data with AES-256-GCM"""
        try:
            # Random nonce
            nonce = secrets.token_bytes(12)
            
            # Make AESGCM
            aesgcm = AESGCM(self.encryption_key)
            
            # Prep data
            if isinstance(data, dict):
                data = json.dumps(data)
            data_bytes = data.encode() if isinstance(data, str) else data
            
            # Encrypt it
            encrypted_data = aesgcm.encrypt(nonce, data_bytes, None)
            
            # Combine nonce and encrypted data
            result = nonce + encrypted_data
            
            logging.info("🔒 Data encrypted")
            return result
        except Exception as e:
            logging.error(f"❌ Encryption error: {e}")
            raise

    def _decrypt_data(self, encrypted_data):
        """Decrypt data with AES-256-GCM"""
        try:
            # Split nonce and data
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Make AESGCM
            aesgcm = AESGCM(self.encryption_key)
            
            # Decrypt it
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            
            try:
                # Try to parse as JSON
                return json.loads(decrypted_data.decode())
            except json.JSONDecodeError:
                # Return as string if not JSON
                return decrypted_data.decode()
        except Exception as e:
            logging.error(f"❌ Decryption error: {e}")
            raise

    def init_database(self):
        """Set up database and tables if needed"""
        try:
            # Connect to db
            conn = sqlite.connect(self.db_path)
            
            # Set encryption key
            key_hex = self.encryption_key.hex()
            conn.execute(f"PRAGMA key = \"x'{key_hex}'\";")
            
            # Make tables with encrypted columns
            conn.execute('''
                CREATE TABLE IF NOT EXISTS device_fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hardware_id BLOB,  -- Encrypted
                    manufacturer BLOB, -- Encrypted
                    product BLOB,      -- Encrypted
                    timestamp TEXT,
                    risk_score INTEGER,
                    scan_results BLOB, -- Encrypted
                    behavioral_hash BLOB, -- Encrypted
                    serial BLOB        -- Encrypted
                )
            ''')
            
            # Make authorized devices table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS authorized_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hardware_id BLOB,  -- Encrypted
                    behavioral_hash BLOB, -- Encrypted
                    serial BLOB,       -- Encrypted
                    is_authorized INTEGER DEFAULT 0,
                    authorization_date TEXT,
                    authorized_by BLOB, -- Encrypted
                    notes BLOB,        -- Encrypted
                    last_seen TEXT
                )
            ''')
            
            conn.commit()
            logging.info("🔐 Database set up with encryption")
            
        except Exception as e:
            logging.error(f"❌ Database setup error: {str(e)}")
        finally:
            if 'conn' in locals():
                conn.close()

    def connect(self):
        """Connect to the encrypted database"""
        try:
            conn = sqlite.connect(self.db_path)
            key_hex = self.encryption_key.hex()
            conn.execute(f"PRAGMA key = \"x'{key_hex}'\";")
            return conn
        except Exception as e:
            logging.error(f"❌ Database connection error: {str(e)}")
            raise

    def store_encrypted(self, data):
        """Store encrypted data in database"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            fingerprint = data.get('fingerprint', {})
            
            # Encrypt sensitive stuff
            encrypted_hw_id = self._encrypt_data(fingerprint.get('hardware_id', ''))
            encrypted_mfr = self._encrypt_data(fingerprint.get('manufacturer', ''))
            encrypted_prod = self._encrypt_data(fingerprint.get('product', ''))
            encrypted_scan = self._encrypt_data(data.get('scan_results', {}))
            encrypted_bhash = self._encrypt_data(fingerprint.get('behavioral_hash', ''))
            encrypted_serial = self._encrypt_data(fingerprint.get('serial', ''))
            
            cursor.execute('''
                INSERT INTO device_fingerprints 
                (hardware_id, manufacturer, product, timestamp, risk_score, 
                 scan_results, behavioral_hash, serial)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                encrypted_hw_id,
                encrypted_mfr,
                encrypted_prod,
                data.get('timestamp', ''),
                data.get('risk_score', 0),
                encrypted_scan,
                encrypted_bhash,
                encrypted_serial
            ))
            
            conn.commit()
            logging.info(f"🔒 Stored data for device: {fingerprint.get('hardware_id', 'unknown')}")
            
        except Exception as e:
            logging.error(f"❌ Error storing data: {e}")
        finally:
            if 'conn' in locals():
                conn.close()

    def get_all_devices(self):
        """Get all devices and their auth status"""
        try:
            conn = self.connect()
            
            # Join tables to get complete info
            cursor = conn.execute('''
                SELECT 
                    f.id, f.hardware_id, f.manufacturer, f.product, f.timestamp, 
                    f.risk_score, f.scan_results, f.behavioral_hash, f.serial,
                    a.is_authorized, a.authorization_date, a.authorized_by, a.notes, a.last_seen
                FROM 
                    device_fingerprints f
                LEFT JOIN 
                    authorized_devices a ON f.hardware_id = a.hardware_id
                GROUP BY 
                    f.hardware_id
                ORDER BY 
                    f.timestamp DESC
            ''')
            
            devices = []
            for row in cursor.fetchall():
                # Decrypt sensitive data
                try:
                    hardware_id = self._decrypt_data(row[1]) if row[1] else ''
                    manufacturer = self._decrypt_data(row[2]) if row[2] else ''
                    product = self._decrypt_data(row[3]) if row[3] else ''
                    scan_results = self._decrypt_data(row[6]) if row[6] else {}
                    behavioral_hash = self._decrypt_data(row[7]) if row[7] else ''
                    serial = self._decrypt_data(row[8]) if row[8] else ''
                    authorized_by = self._decrypt_data(row[10]) if row[10] else ''
                    notes = self._decrypt_data(row[11]) if row[11] else ''
                except Exception as e:
                    logging.error(f"❌ Error decrypting device data: {e}")
                    continue
                
                device = {
                    'id': row[0],
                    'hardware_id': hardware_id,
                    'manufacturer': manufacturer,
                    'product': product,
                    'timestamp': row[4],
                    'risk_score': row[5],
                    'scan_results': scan_results,
                    'behavioral_hash': behavioral_hash,
                    'serial': serial,
                    'is_authorized': bool(row[9]) if row[9] is not None else None,
                    'authorization_date': row[10],
                    'authorized_by': authorized_by,
                    'notes': notes,
                    'last_seen': row[12]
                }
                devices.append(device)
            
            logging.info(f"🔓 Got and decrypted {len(devices)} devices")
            return devices
            
        except Exception as e:
            logging.error(f"❌ Error getting devices: {e}")
            return []
        finally:
            if 'conn' in locals():
                conn.close()

    def get_authorization_status(self, hardware_id=None, behavioral_hash=None, serial=None):
        """Check if a device is authorized"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # Encrypt search params
            if hardware_id:
                hardware_id = self._encrypt_data(hardware_id)
            if behavioral_hash:
                behavioral_hash = self._encrypt_data(behavioral_hash)
            if serial:
                serial = self._encrypt_data(serial)
            
            query = '''
                SELECT is_authorized, authorization_date, authorized_by, notes, last_seen
                FROM authorized_devices
                WHERE hardware_id = ? OR behavioral_hash = ? OR serial = ?
            '''
            cursor.execute(query, (hardware_id, behavioral_hash, serial))
            result = cursor.fetchone()
            
            if result:
                # Decrypt stuff
                authorized_by = self._decrypt_data(result[2]) if result[2] else ''
                notes = self._decrypt_data(result[3]) if result[3] else ''
                
                return {
                    'is_authorized': bool(result[0]),
                    'authorization_date': result[1],
                    'authorized_by': authorized_by,
                    'notes': notes,
                    'last_seen': result[4]
                }
            return None
            
        except Exception as e:
            logging.error(f"❌ Error getting auth status: {e}")
            return None
        finally:
            if 'conn' in locals():
                conn.close()

    def set_device_authorization(self, hardware_id, is_authorized, authorized_by, notes="", behavioral_hash=None, serial=None):
        """Set device as authorized or blocked"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # Encrypt stuff
            encrypted_hw_id = self._encrypt_data(hardware_id)
            encrypted_auth_by = self._encrypt_data(authorized_by)
            encrypted_notes = self._encrypt_data(notes)
            encrypted_bhash = self._encrypt_data(behavioral_hash) if behavioral_hash else None
            encrypted_serial = self._encrypt_data(serial) if serial else None
            
            current_time = datetime.now().isoformat()
            
            # Check if already exists
            cursor.execute("SELECT id FROM authorized_devices WHERE hardware_id = ?", (encrypted_hw_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing
                cursor.execute('''
                    UPDATE authorized_devices 
                    SET is_authorized = ?, authorization_date = ?, 
                        authorized_by = ?, notes = ?, last_seen = ?,
                        behavioral_hash = ?, serial = ?
                    WHERE hardware_id = ?
                ''', (
                    1 if is_authorized else 0,
                    current_time,
                    encrypted_auth_by,
                    encrypted_notes,
                    current_time,
                    encrypted_bhash,
                    encrypted_serial,
                    encrypted_hw_id
                ))
            else:
                # Insert new
                cursor.execute('''
                    INSERT INTO authorized_devices 
                    (hardware_id, behavioral_hash, serial, is_authorized, 
                     authorization_date, authorized_by, notes, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    encrypted_hw_id,
                    encrypted_bhash,
                    encrypted_serial,
                    1 if is_authorized else 0,
                    current_time,
                    encrypted_auth_by,
                    encrypted_notes,
                    current_time
                ))
            
            conn.commit()
            logging.info(f"🔐 Device {hardware_id} {'authorized' if is_authorized else 'blocked'} by {authorized_by}")
            return True
            
        except Exception as e:
            logging.error(f"❌ Error setting auth: {e}")
            return False
        finally:
            if 'conn' in locals():
                conn.close()

    # Add a test device for debugging
    def insert_sample_data(self):
        """Add a test device for testing"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # Check if table is empty
            cursor.execute("SELECT COUNT(*) FROM device_fingerprints")
            count = cursor.fetchone()[0]
            
            # Only add test data if empty
            if count == 0:
                sample_fingerprint = {
                    'hardware_id': 'VID:PID:1234:5678',
                    'manufacturer': 'Sample USB Device',
                    'product': 'USB Flash Drive',
                    'timestamp': '2023-06-15T14:30:00',
                    'risk_score': 35,
                    'scan_results': json.dumps({
                        'malicious_files': [],
                        'yara_matches': 0,
                        'clamav_detections': 0,
                        'otx_matches': 0
                    }),
                    'behavioral_hash': 'abcdef1234567890',
                    'serial': 'SAMPLE-USB-001'
                }
                
                cursor.execute('''
                    INSERT INTO device_fingerprints 
                    (hardware_id, manufacturer, product, timestamp, risk_score, 
                     scan_results, behavioral_hash, serial)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    sample_fingerprint['hardware_id'],
                    sample_fingerprint['manufacturer'],
                    sample_fingerprint['product'],
                    sample_fingerprint['timestamp'],
                    sample_fingerprint['risk_score'],
                    sample_fingerprint['scan_results'],
                    sample_fingerprint['behavioral_hash'],
                    sample_fingerprint['serial']
                ))
                
                conn.commit()
                logging.info("Added sample device")
            
        except Exception as e:
            logging.error(f"Error adding sample data: {e}")
        finally:
            if 'conn' in locals():
                conn.close()

    def rotate_key(self):
        """Change encryption key and re-encrypt all data"""
        try:
            if not hasattr(self, 'encryption_key') or not self.encryption_key:
                raise Exception("Key not set up")
                
            # Make new key
            new_key = self._generate_encryption_key()
            
            # Get all encrypted data
            conn = self.connect()
            cursor = conn.cursor()
            
            # Get columns to re-encrypt
            tables = {
                'device_fingerprints': ['hardware_id', 'manufacturer', 'product', 'scan_results', 'behavioral_hash', 'serial'],
                'authorized_devices': ['hardware_id', 'behavioral_hash', 'serial', 'authorized_by', 'notes']
            }
            
            # Save old key
            old_key = self.encryption_key
            
            # Update to new key
            self.encryption_key = new_key
            
            # Re-encrypt everything
            for table, columns in tables.items():
                for column in columns:
                    cursor.execute(f"SELECT id, {column} FROM {table}")
                    for row in cursor.fetchall():
                        if row[1]:  # If data exists
                            try:
                                # Decrypt with old key
                                self.encryption_key = old_key
                                decrypted = self._decrypt_data(row[1])
                                
                                # Encrypt with new key
                                self.encryption_key = new_key
                                encrypted = self._encrypt_data(decrypted)
                                
                                # Update database
                                cursor.execute(f"UPDATE {table} SET {column} = ? WHERE id = ?", (encrypted, row[0]))
                            except Exception as e:
                                logging.error(f"Error re-encrypting data: {e}")
                                continue
            
            conn.commit()
            logging.info("🔐 Changed encryption key")
            return True
            
        except Exception as e:
            logging.error(f"❌ Error changing key: {e}")
            return False
        finally:
            if 'conn' in locals():
                conn.close() 
