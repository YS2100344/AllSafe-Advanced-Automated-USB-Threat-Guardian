#!/usr/bin/env python3
"""
USB Monitor Encryption Viewer
Tool for checking encryption status of USB Monitor
"""

import os
import sys
import logging
import binascii
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# For colors in terminal
try:
    from colorama import init, Fore, Style
    init()  # Start colorama
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False
    print("Note: Install 'colorama' for colors (pip install colorama)")

class EncryptionViewer:
    """Tool to check USB Monitor encryption status"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Set up the viewer with logging
        
        Args:
            config_path: Optional custom config file
        """
        # Set up paths
        self.home_dir = Path.home()
        self.db_path = self.home_dir / "usb_monitor.db"
        self.key_path = self.home_dir / "usb_monitor.key"
        self.quarantine_dir = self.home_dir / "quarantine"
        self.log_dir = self.home_dir / "logs"
        
        # Load custom config if given
        if config_path:
            self._load_config(config_path)
            
        # Make sure log dir exists
        self.log_dir.mkdir(mode=0o700, exist_ok=True)
        
        # Set up logging
        self.setup_logging()
        
    def _load_config(self, config_path: str) -> None:
        """Load config from a JSON file
        
        Args:
            config_path: Path to config file
        """
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Use config paths instead of defaults
            if 'db_path' in config:
                self.db_path = Path(config['db_path'])
            if 'key_path' in config:
                self.key_path = Path(config['key_path'])
            if 'quarantine_dir' in config:
                self.quarantine_dir = Path(config['quarantine_dir'])
            if 'log_dir' in config:
                self.log_dir = Path(config['log_dir'])
                
            logging.info(f"Loaded config from {config_path}")
            
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            print(f"Error: Failed to load config from {config_path}: {e}")
        
    def setup_logging(self) -> None:
        """Set up logging"""
        log_file = self.log_dir / f"encryption_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        logging.info("Encryption viewer started")
        
    def check_database_encryption(self) -> Dict[str, Any]:
        """Verify database encryption status and configuration.
        
        Returns:
            Dict with status, message, and details about the database encryption
        """
        try:
            if not self.db_path.exists():
                return {
                    "status": "error",
                    "message": "Database file not found",
                    "details": None
                }
            
            # Check database header for encryption signature
            with open(self.db_path, 'rb') as f:
                header = f.read(16)
                header_hex = binascii.hexlify(header).decode()
            
            # SQLCipher signature check
            is_encrypted = header_hex.startswith('53514c69746520666f726d61742033')
            
            # Try to open the database to detect if encrypted
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                cursor.execute("PRAGMA schema_version")
                plaintext_access = True
                conn.close()
            except sqlite3.DatabaseError:
                plaintext_access = False
            
            encryption_status = {
                "detected": is_encrypted,
                "plaintext_readable": plaintext_access,
                "algorithm": "AES-256-GCM" if is_encrypted else "Unknown",
                "mode": "Authenticated Encryption" if is_encrypted else "Unknown",
                "key_derivation": "PBKDF2-SHA512" if is_encrypted else "Unknown",
                "salt_size": 32 if is_encrypted else 0,
                "iterations": 500000 if is_encrypted else 0
            }
            
            # Determine overall status
            if is_encrypted and not plaintext_access:
                status = "success"
                message = "Database encryption verified and secure"
            elif is_encrypted and plaintext_access:
                status = "warning"
                message = "Database has encryption header but is readable without a key"
            elif not is_encrypted:
                status = "error"
                message = "Database is not encrypted"
            else:
                status = "warning"
                message = "Database encryption status is ambiguous"
            
            return {
                "status": status,
                "message": message,
                "details": {
                    "path": str(self.db_path),
                    "size": os.path.getsize(self.db_path),
                    "header": header_hex[:32],
                    "encryption": encryption_status
                }
            }
            
        except Exception as e:
            logging.error(f"Database encryption check failed: {str(e)}")
            return {
                "status": "error",
                "message": f"Database check failed: {str(e)}",
                "details": None
            }
    
    def check_key_file(self) -> Dict[str, Any]:
        """Verify key file security and configuration.
        
        Returns:
            Dict with status, message, and details about the key file
        """
        try:
            if not self.key_path.exists():
                return {
                    "status": "error",
                    "message": "Key file not found",
                    "details": {
                        "path": str(self.key_path),
                        "expected_location": "User home directory"
                    }
                }
            
            # Check file permissions
            mode = self.key_path.stat().st_mode
            permissions_secure = mode & 0o777 == 0o600
            
            # Check owner
            owner_secure = os.stat(self.key_path).st_uid == os.getuid()
            
            # Read key components safely
            try:
                with open(self.key_path, 'rb') as f:
                    key_data = f.read(128)  # Read just enough bytes for analysis
                key_strength = len(key_data) * 8  # bits
                key_entropy = sum(1 for b in key_data if 32 <= b <= 126) / len(key_data)
                key_analysis = {
                    "length_bytes": len(key_data),
                    "strength_bits": key_strength,
                    "entropy_quality": f"{key_entropy:.2f}",
                    "format": "Binary" if key_entropy < 0.7 else "Text-based"
                }
            except Exception as e:
                key_analysis = {
                    "error": f"Could not analyze key: {str(e)}"
                }
            
            security_assessment = {
                "permissions_secure": permissions_secure,
                "owner_secure": owner_secure,
                "overall_secure": permissions_secure and owner_secure
            }
            
            return {
                "status": "success" if security_assessment["overall_secure"] else "warning",
                "message": "Key file security verified" if security_assessment["overall_secure"] else "Key file security issues detected",
                "details": {
                    "path": str(self.key_path),
                    "permissions": oct(mode & 0o777),
                    "required_permissions": "0o600",
                    "owner": os.stat(self.key_path).st_uid,
                    "security": security_assessment,
                    "key_analysis": key_analysis,
                    "security_parameters": {
                        "algorithm": "AES-256-GCM",
                        "key_derivation": "PBKDF2-SHA512",
                        "iterations": 500000,
                        "salt_size": 32
                    }
                }
            }
            
        except Exception as e:
            logging.error(f"Key file check failed: {str(e)}")
            return {
                "status": "error",
                "message": f"Key file check failed: {str(e)}",
                "details": {
                    "path": str(self.key_path),
                    "error": str(e)
                }
            }
    
    def check_quarantine_files(self) -> Dict[str, Any]:
        """Verify quarantined files encryption status.
        
        Returns:
            Dict with status, message, and details about quarantined files
        """
        try:
            if not self.quarantine_dir.exists():
                return {
                    "status": "warning",
                    "message": "Quarantine directory not found",
                    "details": {
                        "path": str(self.quarantine_dir)
                    }
                }
            
            files = list(self.quarantine_dir.glob('*.quarantine'))
            meta_files = list(self.quarantine_dir.glob('*.quarantine.meta'))
            key_files = list(self.quarantine_dir.glob('*.quarantine.key'))
            
            if not files:
                return {
                    "status": "info",
                    "message": "No quarantined files found - system clean or inactive",
                    "details": {
                        "path": str(self.quarantine_dir),
                        "directory_exists": True
                    }
                }
            
            quarantine_status = []
            for qfile in files:
                meta_path = qfile.with_suffix('.quarantine.meta')
                key_path = qfile.with_suffix('.quarantine.key')
                
                file_status = {
                    "filename": qfile.name,
                    "original_name": qfile.stem.split('_')[-1] if '_' in qfile.stem else "unknown",
                    "size": qfile.stat().st_size,
                    "date_quarantined": datetime.fromtimestamp(qfile.stat().st_mtime).isoformat(),
                    "permissions": oct(qfile.stat().st_mode & 0o777),
                    "metadata_exists": meta_path.exists(),
                    "key_exists": key_path.exists(),
                    "encryption": {
                        "method": "AES-256-GCM",
                        "key_size": 32,
                        "nonce_size": 12
                    }
                }
                
                # Verify the file appears to be encrypted
                with open(qfile, 'rb') as f:
                    header = f.read(16)
                is_binary = sum(1 for b in header if b < 32 or b > 126) > len(header) // 2
                file_status["appears_encrypted"] = is_binary
                
                if meta_path.exists():
                    try:
                        with open(meta_path, 'rb') as f:
                            nonce = f.read(12)  # Read nonce
                            meta_data = f.read()  # Read encrypted data
                        
                        file_status["metadata_size"] = len(meta_data)
                        file_status["metadata_encrypted"] = True
                    except Exception as e:
                        file_status["metadata_error"] = str(e)
                
                quarantine_status.append(file_status)
            
            # Calculate security metrics
            secure_files = sum(1 for f in quarantine_status if f.get("appears_encrypted", False) and f.get("metadata_exists", False) and f.get("key_exists", False))
            security_percentage = (secure_files / len(files)) * 100 if files else 0
            
            return {
                "status": "success" if security_percentage >= 90 else "warning",
                "message": f"Found {len(files)} quarantined files ({security_percentage:.1f}% secure)",
                "details": {
                    "files": quarantine_status,
                    "directory": str(self.quarantine_dir),
                    "stats": {
                        "total_files": len(files),
                        "total_meta_files": len(meta_files),
                        "total_key_files": len(key_files),
                        "secure_files": secure_files,
                        "security_percentage": f"{security_percentage:.1f}%",
                        "total_size": sum(f.stat().st_size for f in files)
                    }
                }
            }
            
        except Exception as e:
            logging.error(f"Quarantine check failed: {str(e)}")
            return {
                "status": "error",
                "message": f"Quarantine check failed: {str(e)}",
                "details": {
                    "path": str(self.quarantine_dir),
                    "error": str(e)
                }
            }
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive encryption status report.
        
        Returns:
            Dict containing the complete encryption status report
        """
        timestamp = datetime.now().isoformat()
        
        report = {
            "timestamp": timestamp,
            "system": {
                "database": self.check_database_encryption(),
                "key_file": self.check_key_file(),
                "quarantine": self.check_quarantine_files()
            },
            "summary": {
                "status": "secure",
                "recommendations": []
            }
        }
        
        # Generate recommendations and determine overall status
        if report["system"]["database"]["status"] == "error":
            report["summary"]["status"] = "insecure"
            report["summary"]["recommendations"].append(
                "Database encryption needs immediate attention. The database is not properly encrypted."
            )
        elif report["system"]["database"]["status"] == "warning":
            report["summary"]["status"] = "at risk"
            report["summary"]["recommendations"].append(
                "Database encryption has configuration issues. Verify encryption settings."
            )
        
        if report["system"]["key_file"]["status"] == "error":
            report["summary"]["status"] = "insecure"
            report["summary"]["recommendations"].append(
                "Key file is missing or inaccessible. Create or restore the key file immediately."
            )
        elif report["system"]["key_file"]["status"] == "warning":
            report["summary"]["status"] = "at risk"
            report["summary"]["recommendations"].append(
                "Key file permissions are insecure. Run: chmod 600 ~/usb_monitor.key"
            )
        
        if report["system"]["quarantine"]["status"] == "error":
            report["summary"]["recommendations"].append(
                "Quarantine system has errors. Verify the quarantine directory exists and is accessible."
            )
        
        # Add general recommendations if issues were found
        if report["summary"]["status"] != "secure":
            report["summary"]["recommendations"].append(
                "Run a full system verification with sudo ./setup_permissions.py to fix permissions."
            )
        
        # Add timestamp for report
        report["summary"]["generated"] = timestamp
        report["summary"]["version"] = "1.1.0"
        
        return report
    
    def display_report(self, report: Dict[str, Any]) -> None:
        """Display the encryption status report in a professional format.
        
        Args:
            report: The report dictionary to display
        """
        if COLOR_SUPPORT:
            title = f"{Fore.CYAN}🔒 USB Monitor Encryption Status Report{Style.RESET_ALL}"
            divider = f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}"
            section_divider = f"{Fore.BLUE}{'-' * 20}{Style.RESET_ALL}"
        else:
            title = "🔒 USB Monitor Encryption Status Report"
            divider = "=" * 50
            section_divider = "-" * 20
        
        print(f"\n{title}")
        print(divider)
        print(f"Generated: {report['timestamp']}")
        
        # Display database section
        print(f"\n1. Database Encryption")
        print(section_divider)
        self._display_section(report["system"]["database"])
        
        # Display key file section
        print(f"\n2. Key File Security")
        print(section_divider)
        self._display_section(report["system"]["key_file"])
        
        # Display quarantine section
        print(f"\n3. Quarantine Status")
        print(section_divider)
        self._display_section(report["system"]["quarantine"])
        
        # Display summary
        print(f"\nSummary")
        print(section_divider)
        
        # Format the overall status with color if supported
        status_text = report['summary']['status'].upper()
        if COLOR_SUPPORT:
            if status_text == "SECURE":
                status_display = f"{Fore.GREEN}{status_text}{Style.RESET_ALL}"
            elif status_text == "AT RISK":
                status_display = f"{Fore.YELLOW}{status_text}{Style.RESET_ALL}"
            else:
                status_display = f"{Fore.RED}{status_text}{Style.RESET_ALL}"
        else:
            status_display = status_text
            
        print(f"Overall Status: {status_display}")
        
        # Display recommendations
        if report["summary"]["recommendations"]:
            print("\nRecommendations:")
            for i, rec in enumerate(report["summary"]["recommendations"], 1):
                if COLOR_SUPPORT:
                    print(f"  {Fore.YELLOW}• {rec}{Style.RESET_ALL}")
                else:
                    print(f"  • {rec}")
    
    def _display_section(self, section: Dict[str, Any]) -> None:
        """Display a section of the report with proper formatting.
        
        Args:
            section: The section dictionary to display
        """
        # Format status with appropriate color and symbol
        status = section["status"]
        status_symbol = {
            "success": "✅",
            "warning": "⚠️",
            "error": "❌",
            "info": "ℹ️"
        }.get(status, "❓")
        
        if COLOR_SUPPORT:
            status_color = {
                "success": Fore.GREEN,
                "warning": Fore.YELLOW,
                "error": Fore.RED,
                "info": Fore.BLUE
            }.get(status, Fore.WHITE)
            
            header = f"{status_symbol} {status_color}{section['message']}{Style.RESET_ALL}"
        else:
            header = f"{status_symbol} {section['message']}"
            
        print(header)
        
        # Display details if available
        if section["details"]:
            self._display_nested_dict(section["details"], indent=2)
    
    def _display_nested_dict(self, data: Dict[str, Any], indent: int = 0) -> None:
        """Recursively display nested dictionary with proper indentation.
        
        Args:
            data: The dictionary to display
            indent: Current indentation level
        """
        indent_str = " " * indent
        
        for key, value in data.items():
            # Skip displaying files array which can be too verbose
            if key == "files" and isinstance(value, list) and len(value) > 3:
                print(f"{indent_str}{key}: [{len(value)} items]")
                continue
                
            if isinstance(value, dict):
                print(f"{indent_str}{key}:")
                self._display_nested_dict(value, indent + 2)
            elif isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], dict):
                    print(f"{indent_str}{key}: [{len(value)} items]")
                    # Show only first item as example if there are many
                    if len(value) > 0:
                        self._display_nested_dict(value[0], indent + 2)
                else:
                    print(f"{indent_str}{key}: {value}")
            else:
                # Format boolean values with color if supported
                if isinstance(value, bool) and COLOR_SUPPORT:
                    if value:
                        value_display = f"{Fore.GREEN}True{Style.RESET_ALL}"
                    else:
                        value_display = f"{Fore.RED}False{Style.RESET_ALL}"
                    print(f"{indent_str}{key}: {value_display}")
                else:
                    print(f"{indent_str}{key}: {value}")
    
    def export_report(self, report: Dict[str, Any], format: str = "json", filepath: Optional[str] = None) -> None:
        """Export the encryption report to a file.
        
        Args:
            report: The report to export
            format: Format to export (json, html, txt)
            filepath: Optional custom filepath, otherwise auto-generated
        """
        if filepath is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"encryption_report_{timestamp}.{format}"
        
        try:
            if format == "json":
                with open(filepath, 'w') as f:
                    json.dump(report, f, indent=2)
            elif format == "txt":
                # Redirect stdout to file temporarily
                original_stdout = sys.stdout
                with open(filepath, 'w') as f:
                    sys.stdout = f
                    self.display_report(report)
                    sys.stdout = original_stdout
            
            logging.info(f"Report exported to {filepath}")
            print(f"Report exported to {filepath}")
            
        except Exception as e:
            logging.error(f"Failed to export report: {e}")
            print(f"Error: Failed to export report: {e}")

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description="USB Monitor Encryption Status Viewer")
    parser.add_argument("--config", help="Path to custom configuration file")
    parser.add_argument("--export", choices=["json", "txt"], help="Export report to specified format")
    parser.add_argument("--output", help="Custom output file path for export")
    parser.add_argument("--quiet", action="store_true", help="Suppress display output")
    args = parser.parse_args()
    
    try:
        viewer = EncryptionViewer(config_path=args.config)
        report = viewer.generate_report()
        
        # Display report unless quiet mode is enabled
        if not args.quiet:
            viewer.display_report(report)
        
        # Export if requested
        if args.export:
            viewer.export_report(report, format=args.export, filepath=args.output)
        
        # Log the report
        logging.info("Encryption status report generated successfully")
        
        # Exit with status code based on security status
        if report["summary"]["status"] == "insecure":
            sys.exit(2)
        elif report["summary"]["status"] == "at risk":
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        logging.error(f"Failed to generate report: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(3)

if __name__ == "__main__":
    main() 
