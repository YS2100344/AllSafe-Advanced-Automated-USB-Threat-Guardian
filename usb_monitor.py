#!/usr/bin/python3
import os
import subprocess
import logging
import requests
import re
import yara
import hashlib
from pyudev import Context, Monitor
from fpdf import FPDF  # For PDF report generation
from OTXv2 import OTXv2
import IndicatorTypes
from datetime import datetime
from device_fingerprint import DeviceFingerprint
from secure_storage import SQLCipherDatabase
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import secrets

# Logging setup
LOG_FILE = "/var/log/usb_monitor.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Email configuration
EMAIL_RECIPIENT = "yousef.shhh03@gmail.com"

# API Keys
VIRUSTOTAL_API_KEY = "d657b7c6cc94a23c543aae05256a7baf7e0ad3fd1f36e2bcdd9110b0367202c3"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"
HYBRID_ANALYSIS_API_KEY = "o3wfxhgdf8a2e39cl6hzc26scf1b07feknmpapoqac5c0552zlmbzvx34b0fdfc9"
HYBRID_ANALYSIS_URL = "https://www.hybrid-analysis.com/api/v2/submit/file"
OTX_API_KEY = "2069c533c4e7fce5f68d8fcbec674723e35fc7490903ee5ce7e9164d28690bb0"

# YARA Rules Path
YARA_RULES_PATH = "/home/kali/usb-monitor/rules.yar"

# Load YARA rules
try:
    rules = yara.compile(filepath=YARA_RULES_PATH)
except Exception as e:
    logging.error(f"Failed to load YARA rules: {e}")
    rules = None

# Initialize OTX
otx = OTXv2(OTX_API_KEY)

def compute_sha256(file_path):
    """Get SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def send_email(subject, body, attachment_path=None):
    """Send email alert with optional attachment"""
    try:
        if attachment_path:
            email_command = f'echo "{body}" | mail -s "{subject}" -A {attachment_path} {EMAIL_RECIPIENT}'
        else:
            email_command = f'echo "{body}" | mail -s "{subject}" {EMAIL_RECIPIENT}'
        subprocess.run(email_command, shell=True, check=True)
        logging.info(f"Email sent to {EMAIL_RECIPIENT} with subject: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

def submit_to_virustotal(file_path):
    """Send file to VirusTotal and get link"""
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json"
    }
    try:
        # Get file hash
        file_hash = compute_sha256(file_path)
        
        # Check if already analyzed
        report_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(report_url, headers=headers)
        
        if response.status_code == 200:
            logging.info(f"Found existing VirusTotal report for {file_path}")
            return f"https://www.virustotal.com/gui/file/{file_hash}/detection"
        
        # If not, upload file
        with open(file_path, "rb") as file:
            files = {"file": file}
            response = requests.post(VIRUSTOTAL_URL, headers=headers, files=files)
            
        if response.status_code == 200:
            logging.info(f"File sent to VirusTotal: {file_path}")
            return f"https://www.virustotal.com/gui/file/{file_hash}/detection"
        else:
            logging.error(f"VirusTotal Error: {response.text}")
            return None
    except Exception as e:
        logging.error(f"Error with VirusTotal: {e}")
        return None

def submit_to_hybrid_analysis(file_path):
    """Send file to Hybrid Analysis and get link"""
    headers = {
        "User-Agent": "Falcon Sandbox",
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "accept": "application/json"
    }
    try:
        # Get file hash
        file_hash = compute_sha256(file_path)
        
        # Check if already analyzed
        check_url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
        response = requests.post(check_url, headers=headers, data={"hash": file_hash})
        
        if response.status_code == 200 and response.json():
            logging.info(f"Found existing Hybrid Analysis report for {file_path}")
            return f"https://www.hybrid-analysis.com/sample/{file_hash}"
        
        # If not, upload file
        files = {"file": open(file_path, "rb")}
        data = {
            "environment_id": 200,
            "no_share_third_party": True,
            "allow_community_access": True
        }
        
        response = requests.post(HYBRID_ANALYSIS_URL, headers=headers, files=files, data=data)
        
        if response.status_code == 201:
            logging.info(f"File sent to Hybrid Analysis: {file_path}")
            return f"https://www.hybrid-analysis.com/sample/{file_hash}"
        else:
            logging.error(f"Hybrid Analysis Error: {response.text}")
            return None
    except Exception as e:
        logging.error(f"Error with Hybrid Analysis: {e}")
        return None
    finally:
        if 'files' in locals():
            files["file"].close()

def quarantine_file(file_path):
    """Move bad file to a safe place and encrypt it"""
    try:
        # Make quarantine folder in home dir
        quarantine_dir = os.path.expanduser("~/quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # Make unique filename with hash
        file_hash = compute_sha256(file_path)
        file_name = os.path.basename(file_path)
        quarantine_path = os.path.join(quarantine_dir, f"{file_hash}_{file_name}.quarantine")
        
        # Read file
        with open(file_path, "rb") as f:
            file_content = f.read()
        
        # Make encryption key from hash
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=file_hash.encode(),
            iterations=500000,
        )
        key = kdf.derive(file_hash.encode())
        
        # Make nonce
        nonce = secrets.token_bytes(12)
        
        # Set up AES
        aesgcm = AESGCM(key)
        
        # Encrypt file
        encrypted_content = aesgcm.encrypt(nonce, file_content, None)
        
        # Save encrypted file
        with open(quarantine_path, "wb") as f:
            f.write(nonce + encrypted_content)
        
        # Save file info
        metadata = {
            "original_path": file_path,
            "original_name": file_name,
            "hash": file_hash,
            "quarantine_time": datetime.now().isoformat(),
            "encryption_method": "AES-256-GCM",
            "key_derivation": "PBKDF2-SHA512",
            "iterations": 500000,
            "nonce": base64.b64encode(nonce).decode(),
            "security_level": "high"
        }
        
        # Encrypt the info too
        metadata_key = secrets.token_bytes(32)
        metadata_nonce = secrets.token_bytes(12)
        metadata_aesgcm = AESGCM(metadata_key)
        encrypted_metadata = metadata_aesgcm.encrypt(
            metadata_nonce,
            json.dumps(metadata).encode(),
            None
        )
        
        # Save encrypted info
        with open(f"{quarantine_path}.meta", "wb") as f:
            f.write(metadata_nonce + encrypted_metadata)
        
        # Save key safely
        key_file = f"{quarantine_path}.key"
        with open(key_file, "wb") as f:
            f.write(metadata_key)
        os.chmod(key_file, 0o600)
        
        logging.info(f"Quarantined file: {file_path} -> {quarantine_path}")
        logging.info("File encrypted with AES-256-GCM")
        
        # Try to delete original
        try:
            os.remove(file_path)
            logging.info(f"Removed original bad file: {file_path}")
        except Exception as e:
            logging.error(f"Couldn't remove original file: {e}")
        
        return quarantine_path
    except Exception as e:
        logging.error(f"Error quarantining file {file_path}: {e}")
        return None

def check_with_otx(indicator, indicator_type):
    """Check if something is bad using OTX"""
    try:
        if indicator_type == "ip":
            result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, indicator, 'general')
        elif indicator_type == "domain":
            result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, indicator, 'general')
        elif indicator_type == "url":
            result = otx.get_indicator_details_by_section(IndicatorTypes.URL, indicator, 'general')
        elif indicator_type == "hash":
            # For files, get hash first
            file_hash = compute_sha256(indicator)
            result = otx.get_indicator_details_by_section(IndicatorTypes.FILE_HASH_SHA256, file_hash, 'general')
        else:
            return None
        return result
    except Exception as e:
        logging.error(f"Error checking with OTX: {e}")
        return None

def extract_ips_and_domains(file_path):
    """Extract IPs and domains from a text file."""
    ips = []
    domains = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                # Extract IPs using regex
                ip_matches = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
                ips.extend(ip_matches)
                # Extract domains using regex
                domain_matches = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", line)
                domains.extend(domain_matches)
        return ips, domains
    except Exception as e:
        logging.error(f"Error parsing {file_path}: {e}")
        return [], []

def calculate_severity_score(yara_results, clamav_results, otx_results):
    """Calculate the overall severity score based on various factors."""
    score = 0
    
    # YARA matches (weight: 2)
    # Only count if we have multiple detections or specific high-risk matches
    if len(yara_results) > 0:
        high_risk_patterns = ['ransomware', 'keylogger', 'shellcode', 'meterpreter']
        high_risk_matches = sum(1 for result in yara_results if any(pattern in result.lower() for pattern in high_risk_patterns))
        score += min(high_risk_matches * 2 + (len(yara_results) - high_risk_matches), 10)
    
    # ClamAV detections (weight: 3)
    # ClamAV is more reliable for known malware
    if len(clamav_results) > 0:
        for result in clamav_results:
            if isinstance(result, dict):
                # Higher score for known malware families
                if any(family in result['threat'].lower() for family in ['trojan', 'ransomware', 'backdoor']):
                    score += 3
                else:
                    score += 2
            else:
                score += 2
        score = min(score, 15)  # Cap ClamAV score
    
    # OTX results (weight: 2)
    for result in otx_results:
        base_score = 0
        
        # Evaluate malware families
        if 'malware_families' in result and result['malware_families']:
            if isinstance(result['malware_families'], list):
                base_score += min(len(result['malware_families']), 3)
            else:
                base_score += 1
        
        # Evaluate pulse count (more reports = more reliable)
        if 'pulse_count' in result:
            pulse_score = min(result['pulse_count'] // 5, 3)  # Cap at 3 points
            base_score += pulse_score
        
        # Add points for attack techniques
        if 'attack_techniques' in result and result['attack_techniques']:
            if isinstance(result['attack_techniques'], list):
                base_score += min(len(result['attack_techniques']), 2)
            else:
                base_score += 1
        
        # Add points for CVE references
        if 'cve_references' in result and result['cve_references']:
            if isinstance(result['cve_references'], list):
                base_score += min(len(result['cve_references']), 2)
            else:
                base_score += 1
        
        score += min(base_score * 2, 10)  # Cap individual OTX result score
    
    # Cap total score at 100
    return min(score, 100)

def get_severity_level(score):
    """Convert severity score to level and color."""
    if score >= 80:
        return "CRITICAL", (255, 0, 0)  # Red
    elif score >= 50:
        return "HIGH", (255, 165, 0)  # Orange
    elif score >= 25:
        return "MEDIUM", (255, 255, 0)  # Yellow
    else:
        return "LOW", (0, 255, 0)  # Green

def generate_pdf_report(device_id, device_name, malicious_files, yara_results, clamav_results, virus_total_results,
                        hybrid_analysis_results, otx_results, initial_risk_score=0):
    """Generate a comprehensive PDF report for the detected malware."""
    pdf = FPDF()
    
    # Add a page
    pdf.add_page()
    
    # Set font for title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "USB Security Scan Report", ln=True, align="C")
    
    # Add timestamp
    pdf.set_font("Arial", "I", 10)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="R")
    
    # Use the provided risk score or calculate it if not provided
    if initial_risk_score > 0:
        severity_score = initial_risk_score  # Don't cap at 100
    else:
        severity_score = calculate_severity_score(yara_results, clamav_results, otx_results)
    
    severity_level, severity_color = get_severity_level(severity_score)
    
    # Severity Rating Section
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Severity Rating", ln=True)
    
    # Create severity box
    pdf.set_fill_color(*severity_color)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(40, 15, severity_level, 1, 0, 'C', True)
    pdf.cell(0, 15, f"Score: {severity_score}", 1, 1, 'C', True)
    
    # Add severity description
    pdf.set_font("Arial", "", 12)
    severity_descriptions = {
        "CRITICAL": "Immediate action required. Multiple high-risk threats detected.",
        "HIGH": "Urgent attention needed. Significant security risks identified.",
        "MEDIUM": "Attention recommended. Some security concerns detected.",
        "LOW": "Minimal risk. No significant security threats detected."
    }
    pdf.cell(0, 10, severity_descriptions[severity_level], ln=True)
    pdf.ln(5)
    
    # Device Information Section
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Device Information", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.cell(40, 10, "Device ID:", 0)
    pdf.cell(0, 10, device_id, ln=True)
    pdf.cell(40, 10, "Device Name:", 0)
    pdf.cell(0, 10, device_name, ln=True)
    pdf.ln(5)
    
    # Summary Section with Threat Statistics
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Scan Summary", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Total Files Scanned: {len(malicious_files)}", ln=True)
    pdf.cell(0, 10, f"Malicious Files Detected: {len(malicious_files)}", ln=True)
    pdf.cell(0, 10, f"YARA Matches: {len(yara_results)}", ln=True)
    pdf.cell(0, 10, f"ClamAV Detections: {len(clamav_results)}", ln=True)
    pdf.cell(0, 10, f"Suspicious Indicators: {len(otx_results)}", ln=True)
    pdf.ln(5)
    
    # Malicious Files Section with Risk Level
    if malicious_files:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Detected Malicious Files", ln=True)
        pdf.set_font("Arial", "", 12)
        for file in malicious_files:
            pdf.cell(10, 10, "-", 0)
            file_score = 0
            if file in yara_results:
                file_score += 3
            if file in clamav_results:
                file_score += 2
            file_level, _ = get_severity_level(file_score)
            pdf.cell(0, 10, f"{file} [Risk: {file_level}]", ln=True)
        pdf.ln(5)
    
    # YARA Results Section
    if yara_results:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "YARA Analysis Results", ln=True)
        pdf.set_font("Arial", "", 12)
        for result in yara_results:
            pdf.cell(10, 10, "-", 0)
            pdf.cell(0, 10, result, ln=True)
        pdf.ln(5)
    
    # ClamAV Results Section
    if clamav_results:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "ClamAV Scan Results", ln=True)
        pdf.set_font("Arial", "", 12)
        for result in clamav_results:
            pdf.cell(10, 10, "-", 0)
            pdf.cell(0, 10, result['file_name'], ln=True)
            pdf.cell(0, 10, f"Threat: {result['threat']}", ln=True)
        pdf.ln(5)
    
    # VirusTotal Results Section
    if virus_total_results:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "VirusTotal Analysis Reports", ln=True)
        pdf.set_font("Arial", "", 12)
        for link in virus_total_results:
            pdf.cell(10, 10, "-", 0)
            pdf.set_text_color(0, 0, 255)
            pdf.cell(0, 10, link, ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)
    
    # Hybrid Analysis Results Section
    if hybrid_analysis_results:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Hybrid Analysis Reports", ln=True)
        pdf.set_font("Arial", "", 12)
        for link in hybrid_analysis_results:
            pdf.cell(10, 10, "-", 0)
            pdf.set_text_color(0, 0, 255)
            pdf.cell(0, 10, link, ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)
    
    # OTX Results Section
    if otx_results:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "AlienVault OTX Analysis Results", ln=True)
        pdf.set_font("Arial", "", 12)
        for result in otx_results:
            pdf.cell(10, 10, "-", 0)
            pdf.cell(0, 10, f"Indicator: {result['indicator']}", ln=True)
            pdf.cell(20, 10, "", 0)  # Indentation
            pdf.cell(0, 10, f"Type: {result['type']}", ln=True)
            if 'country' in result:
                pdf.cell(20, 10, "", 0)
                pdf.cell(0, 10, f"Country: {result['country']}", ln=True)
            if 'asn' in result:
                pdf.cell(20, 10, "", 0)
                pdf.cell(0, 10, f"ASN: {result['asn']}", ln=True)
            if 'malware_families' in result:
                pdf.cell(20, 10, "", 0)
                pdf.cell(0, 10, f"Malware Families: {', '.join(result['malware_families'])}", ln=True)
            if 'attack_techniques' in result and result['attack_techniques']:
                pdf.cell(20, 10, "", 0)
                if isinstance(result['attack_techniques'], list):
                    pdf.cell(0, 10, f"MITRE ATT&CK: {', '.join(result['attack_techniques'])}", ln=True)
                else:
                    pdf.cell(0, 10, f"MITRE ATT&CK: {result['attack_techniques']}", ln=True)
            if 'cve_references' in result and result['cve_references']:
                pdf.cell(20, 10, "", 0)
                if isinstance(result['cve_references'], list):
                    pdf.cell(0, 10, f"CVE References: {', '.join(result['cve_references'])}", ln=True)
                else:
                    pdf.cell(0, 10, f"CVE References: {result['cve_references']}", ln=True)
            if 'pulse_count' in result:
                pdf.cell(20, 10, "", 0)
                pdf.cell(0, 10, f"Pulse Count: {result['pulse_count']}", ln=True)
            pdf.ln(5)
    
    # Enhanced Recommendations Section based on severity
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Security Recommendations", ln=True)
    pdf.set_font("Arial", "", 12)
    
    # Base recommendations
    recommendations = [
        "1. IMMEDIATE ACTION: Disconnect the USB device from all systems and secure it for forensic analysis.",
        "2. DEVICE CONTAINMENT: Add the device ID to your blocklist to prevent future connections.",
        "3. SYSTEM SCANNING: Conduct full malware scans on all systems that were connected to this device.",
        "4. SECURITY UPDATES: Apply latest security patches and update antivirus signatures.",
        "5. POLICY REVIEW: Review and enhance your organization's USB security policies.",
        "6. ACCESS CONTROL: Implement hardware-based USB device control with allowlisting capabilities.",
        "7. NETWORK MONITORING: Increase monitoring for suspicious network traffic related to detected indicators.",
        "8. INCIDENCE DOCUMENTATION: Record this incident with all details in your security incident log.",
        "9. THREAT HUNTING: Conduct threat hunting activities to detect potential persistence mechanisms."
    ]
    
    # Add severity-specific recommendations
    if severity_level == "CRITICAL":
        recommendations.extend([
            "10. INCIDENT RESPONSE: Activate your incident response team immediately.",
            "11. EXECUTIVE NOTIFICATION: Notify executive management and relevant stakeholders.",
            "12. SYSTEM ISOLATION: Isolate affected systems from the network until fully remediated.",
            "13. FORENSIC ANALYSIS: Conduct forensic analysis of affected systems to determine scope.",
            "14. DATA BREACH ASSESSMENT: Evaluate if data exfiltration occurred and prepare response.",
            "15. EXTERNAL ASSISTANCE: Consider engaging external security experts for incident response.",
            "16. BUSINESS CONTINUITY: Activate business continuity plans for affected systems."
        ])
    elif severity_level == "HIGH":
        recommendations.extend([
            "10. SECURITY ESCALATION: Escalate to security team for comprehensive response.",
            "11. ENHANCED MONITORING: Implement enhanced monitoring on affected systems.",
            "12. SECURITY CONTROLS: Review and strengthen security controls around removable media.",
            "13. USER TRAINING: Conduct targeted security awareness training for affected users.",
            "14. SECURITY ASSESSMENT: Schedule a comprehensive security assessment to identify gaps."
        ])
    elif severity_level == "MEDIUM":
        recommendations.extend([
            "10. SECURITY REVIEW: Conduct a focused review of security controls for removable media.",
            "11. TARGETED MONITORING: Monitor affected systems for unusual activities.",
            "12. USER NOTIFICATION: Notify affected users about the security incident.",
            "13. TRAINING OPPORTUNITY: Use this incident as a security awareness training example."
        ])
    
    for rec in recommendations:
        pdf.cell(10, 10, "-", 0)
        pdf.cell(0, 10, rec, ln=True)
    
    # Footer with severity level
    pdf.set_y(-40)
    pdf.set_font("Arial", "I", 10)
    pdf.cell(0, 10, "This report was automatically generated by USB Security Monitor", ln=True)
    pdf.cell(0, 10, f"Severity Level: {severity_level}", ln=True)
    pdf.cell(0, 10, "For security purposes, please handle this report with appropriate confidentiality", ln=True)
    
    # Save the PDF with a timestamp and severity level in the filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = f"usb_security_report_{severity_level.lower()}_{timestamp}.pdf"
    pdf.output(pdf_path)
    
    logging.info(f"Generated comprehensive PDF report: {pdf_path} with severity level: {severity_level}")
    return pdf_path

def block_usb_device(device_path):
    """Block a USB device by unmounting it and blacklisting to make it completely inaccessible."""
    logging.info(f"Blocking USB device: {device_path}")
    
    try:
        # First, try to find all mounted points from this device
        mount_info = subprocess.run(
            ["findmnt", "-S", device_path, "-o", "TARGET", "-n"],
            capture_output=True,
            text=True,
            check=False
        )
        
        # If we found mount points, try to unmount each one
        if mount_info.returncode == 0 and mount_info.stdout.strip():
            mount_points = mount_info.stdout.strip().split("\n")
            for mount_point in mount_points:
                mount_point = mount_point.strip()
                if mount_point:
                    logging.info(f"Attempting to unmount {mount_point}")
                    subprocess.run(
                        ["sudo", "umount", "-f", mount_point],
                        check=False,
                        capture_output=True
                    )
                    logging.info(f"Unmounted {mount_point}")
        else:
            # If findmnt didn't find anything, try direct unmount
            subprocess.run(
                ["sudo", "umount", "-f", device_path],
                check=False,
                capture_output=True
            )
            logging.info(f"Directly unmounted {device_path}")
        
        # Force eject/power off the device using udisks if possible
        try:
            device_base = os.path.basename(device_path)
            device_name = device_base.rstrip('0123456789')  # Remove partition numbers (e.g., sdb1 -> sdb)
            
            logging.info(f"Attempting to power off device {device_name}")
            # First try udisksctl
            subprocess.run(
                ["sudo", "udisksctl", "power-off", "-b", f"/dev/{device_name}"],
                check=False,
                capture_output=True
            )
            
            # Also try eject as a fallback
            subprocess.run(
                ["sudo", "eject", f"/dev/{device_name}"],
                check=False,
                capture_output=True
            )
            
            logging.info(f"Device powering off commands sent to {device_name}")
        except Exception as e:
            logging.error(f"Error powering off device: {e}")
        
        # Create a temporary udev rule to make this device completely inaccessible
        device_id = None
        try:
            # Get device attributes
            usb_device_info = subprocess.run(
                ["sudo", "udevadm", "info", "--name", device_path],
                capture_output=True,
                text=True,
                check=False
            )
            
            # Find ID_VENDOR_ID and ID_MODEL_ID in the output
            id_vendor = None
            id_model = None
            
            for line in usb_device_info.stdout.splitlines():
                if "ID_VENDOR_ID=" in line:
                    id_vendor = line.split("=")[1].strip().strip('"')
                if "ID_MODEL_ID=" in line:
                    id_model = line.split("=")[1].strip().strip('"')
            
            if id_vendor and id_model:
                device_id = f"{id_vendor}:{id_model}"
                # Create a udev rule to block this device
                rule_content = f'SUBSYSTEM=="usb", ATTR{{idVendor}}=="{id_vendor}", ATTR{{idProduct}}=="{id_model}", ATTR{{authorized}}="0"\n'
                rule_path = os.path.expanduser("~/99-usb-quarantine.rules")
                
                with open(rule_path, "a") as f:
                    f.write(rule_content)
                
                # Copy the rule to udev rules directory (requires sudo)
                subprocess.run(
                    ["sudo", "cp", rule_path, "/etc/udev/rules.d/99-usb-quarantine.rules"],
                    check=False,
                    capture_output=True
                )
                
                # Reload udev rules
                subprocess.run(
                    ["sudo", "udevadm", "control", "--reload-rules"],
                    check=False,
                    capture_output=True
                )
                
                # Trigger udev to apply rules
                subprocess.run(
                    ["sudo", "udevadm", "trigger"],
                    check=False,
                    capture_output=True
                )
                
                logging.info(f"Created udev rule to block USB device with ID {device_id}")
        except Exception as e:
            logging.error(f"Error creating udev rule: {e}")
        
        # Add device to USB block list in user's home directory
        blocklist_path = os.path.expanduser("~/usb_blocklist.txt")
        try:
            with open(blocklist_path, "a") as f:
                if device_id:
                    f.write(f"{device_path} {device_id}\n")
                else:
                    f.write(f"{device_path}\n")
            logging.info(f"Added {device_path} to blocklist at {blocklist_path}")
        except Exception as e:
            logging.error(f"Error updating blocklist: {e}")
        
        # For complete removal, try to unbind the device from the USB driver
        try:
            # Find the device's sys path
            cmd = ["find", "/sys/bus/usb/devices", "-name", device_base]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.stdout.strip():
                device_sys_path = result.stdout.strip().split("\n")[0]
                parent_path = os.path.dirname(device_sys_path)
                
                # Unbind by writing to authorized
                try:
                    subprocess.run(
                        ["sudo", "sh", "-c", f"echo 0 > {parent_path}/authorized"],
                        check=False,
                        capture_output=True
                    )
                    logging.info(f"Unbinded USB device from driver: {parent_path}")
                except Exception as e:
                    logging.error(f"Error unbinding USB device: {e}")
        except Exception as e:
            logging.error(f"Error finding device in sysfs: {e}")
            
        return True
    except Exception as e:
        logging.error(f"Error blocking USB device {device_path}: {e}")
        return False

def scan_usb(device_path, device_id, device_name):
    """Scan a USB device for malware and suspicious indicators."""
    logging.info(f"Scanning USB device: {device_path} (ID: {device_id}, Name: {device_name})")
    
    # Initialize fingerprinting and database
    fingerprinter = DeviceFingerprint()
    db = SQLCipherDatabase()
    
    mount_point = "/mnt/usbscan"
    os.makedirs(mount_point, exist_ok=True)
    
    try:
        # Mount with explicit read-write permissions and permissive umask
        subprocess.run(["sudo", "mount", "-o", "rw,umask=000", device_path, mount_point], check=True)
        logging.info("USB device mounted successfully with read-write permissions.")
        
        detected_malware = False
        malicious_files = []
        yara_results = []
        clamav_results = []
        virus_total_results = []
        hybrid_analysis_results = []
        otx_results = []
        initial_risk_score = 0

        # Scan files
        for root, _, files in os.walk(mount_point):
            for file in files:
                file_path = os.path.join(root, file)
                
                # YARA scanning
                if rules and rules.match(file_path):
                    initial_risk_score += 15
                    malicious_files.append(file_path)
                    yara_results.append(file_path)
                    logging.info(f"YARA detected malware in: {file_path}")
                    detected_malware = True
                    
                    # Submit to VirusTotal
                    vt_link = submit_to_virustotal(file_path)
                    if vt_link:
                        virus_total_results.append(vt_link)
                        logging.info(f"VirusTotal Analysis Link: {vt_link}")

                    # Submit to Hybrid Analysis
                    ha_link = submit_to_hybrid_analysis(file_path)
                    if ha_link:
                        hybrid_analysis_results.append(ha_link)
                        logging.info(f"Hybrid Analysis Report Link: {ha_link}")
                    
                    # Quarantine the file
                    quarantine_path = quarantine_file(file_path)
                    if quarantine_path:
                        logging.info(f"Quarantined file: {file_path}")
                
                # Enhanced ClamAV scanning with detailed output
                try:
                    logging.info(f"Scanning with ClamAV: {file_path}")
                    clamav_result = subprocess.run(
                        ["clamscan", "--verbose", "--detect-pua=yes", "--heuristic-alerts=yes", 
                         "--heuristic-scan-precedence=yes", "--scan-archive=yes", "--stdout", file_path],
                        capture_output=True,
                        text=True,
                        timeout=60  
                    )
                    
                    # Check for detection either by return code or output text
                    detected = False
                    threat_name = ""
                    
                    # Successful detection via return code
                    if clamav_result.returncode == 1:
                        detected = True
                        threat_parts = clamav_result.stdout.split(": ")
                        if len(threat_parts) > 1:
                            threat_name = threat_parts[-1].strip()
                        else:
                            threat_name = "Unknown threat"
                    
                    # Even if no return code, check output for detection keywords
                    elif "FOUND" in clamav_result.stdout or "Infected files: 1" in clamav_result.stdout:
                        detected = True
                        for line in clamav_result.stdout.splitlines():
                            if "FOUND" in line:
                                threat_name = line.split("FOUND")[0].strip()
                                break
                        if not threat_name:
                            threat_name = "Suspicious content"
                    
                    if detected:
                        initial_risk_score += 12
                        malicious_files.append(file_path)
                        clamav_results.append({
                            'file_name': os.path.basename(file_path),
                            'path': file_path,
                            'threat': threat_name
                        })
                        detected_malware = True
                        logging.info(f"ClamAV detected threat in {file_path}: {threat_name}")
                        # Quarantine the file if not already quarantined
                        if file_path not in yara_results:  # Avoid double quarantine
                            quarantine_path = quarantine_file(file_path)
                            if quarantine_path:
                                logging.info(f"Quarantined file: {file_path}")
                    else:
                        logging.info(f"ClamAV scan completed for {file_path}: No threats found")
                except subprocess.TimeoutExpired:
                    logging.warning(f"ClamAV scan timeout for {file_path}")
                    # If scan times out, treat as suspicious
                    initial_risk_score += 5
                    clamav_results.append({
                        'file_name': os.path.basename(file_path),
                        'path': file_path,
                        'threat': 'Scan timeout (suspicious)'
                    })
                except Exception as e:
                    logging.error(f"ClamAV scan error for {file_path}: {e}")

                # Check text files for suspicious content
                if file.endswith('.txt'):
                    ips, domains = extract_ips_and_domains(file_path)
                    if ips or domains:
                        initial_risk_score += 5
                        for ip in ips:
                            otx_result = check_with_otx(ip, "ip")
                            if otx_result:
                                initial_risk_score += 8
                                otx_results.append(otx_result)
                                logging.info(f"OTX Analysis Result: {json.dumps(otx_result)}")
                        for domain in domains:
                            otx_result = check_with_otx(domain, "domain")
                            if otx_result:
                                initial_risk_score += 8
                                otx_results.append(otx_result)
                                logging.info(f"OTX Analysis Result: {json.dumps(otx_result)}")

        # Create device info dictionary for fingerprinting
        device_info = {
            'ID_VENDOR_ID': device_id.split(':')[0] if ':' in device_id else '',
            'ID_MODEL_ID': device_id.split(':')[1] if ':' in device_id else '',
            'ID_VENDOR': device_name.split(' ')[0] if device_name else '',
            'ID_MODEL': device_name,
            'ID_SERIAL_SHORT': device_path,
            'timestamp': datetime.now().isoformat()
        }

        # Store fingerprint with results
        if fingerprint := fingerprinter.generate_fingerprint(device_info):
            db.store_encrypted({
                'fingerprint': fingerprint,
                'timestamp': datetime.now().isoformat(),
                'risk_score': initial_risk_score,
                'scan_results': {
                    'malicious_files': malicious_files,
                    'yara_matches': len(yara_results),
                    'clamav_detections': len(clamav_results),
                    'otx_matches': len(otx_results),
                    'virus_total_links': virus_total_results,
                    'hybrid_analysis_links': hybrid_analysis_results
                }
            })
            logging.info(f"Stored device fingerprint with risk score: {initial_risk_score}")

        # Generate report if threats detected
        if detected_malware or otx_results:
            pdf_path = generate_pdf_report(
                device_id, device_name, malicious_files,
                yara_results, clamav_results,
                virus_total_results, hybrid_analysis_results,
                otx_results, initial_risk_score
            )
            
            email_subject = "⚠️ Malware or Suspicious Indicators Detected on USB Device!"
            email_body = (
                f"A malicious file or suspicious indicator was detected on the USB device:\n"
                f"Device ID: {device_id}\n"
                f"Device Name: {device_name}\n"
                f"Risk Score: {initial_risk_score}\n"
                f"Malicious Files:\n" + "\n".join(malicious_files) + "\n"
                f"YARA Results:\n" + "\n".join(yara_results) + "\n"
                f"ClamAV Results:\n" + "\n".join([f"{result['file_name']} | {result['threat']}" 
                                                 for result in clamav_results]) + "\n"
                f"VirusTotal Reports:\n" + "\n".join(virus_total_results) + "\n"
                f"Hybrid Analysis Reports:\n" + "\n".join(hybrid_analysis_results) + "\n"
                f"AlienVault OTX Results:\n" + "\n".join([
                    f"{result.get('indicator', 'Unknown')} | "
                    f"Type: {result.get('type', 'Unknown')} | "
                    f"Country: {result.get('country', 'Unknown')} | "
                    f"Malware: {', '.join(result.get('malware_families', ['None']))} | "
                    f"ATT&CK: {', '.join(result.get('attack_techniques', ['None']))} | "
                    f"CVEs: {', '.join(result.get('cve_references', ['None']))}"
                    for result in otx_results
                ])
            )
            
            send_email(email_subject, email_body, pdf_path)
            
            # First safely unmount our mount point
            try:
                subprocess.run(["sudo", "umount", mount_point], check=False)
                logging.info(f"Unmounted scan directory {mount_point}")
            except Exception as e:
                logging.error(f"Error unmounting scan directory: {e}")
            
            # Then block the device completely
            if block_usb_device(device_path):
                logging.info(f"USB device {device_id} has been blocked due to detected malware or suspicious indicators.")
            else:
                logging.warning(f"Failed to block USB device {device_id} after malware detection.")
        else:
            logging.info(f"USB device {device_id} is clean. No threats found. Risk score: {initial_risk_score}")

    except Exception as e:
        logging.error(f"Error scanning USB device: {e}")
    finally:
        try:
            # Always try to unmount our scan directory
            subprocess.run(["sudo", "umount", mount_point], check=False)
            logging.info(f"Unmounted scan directory {mount_point}")
        except Exception as e:
            logging.error(f"Error unmounting scan directory: {e}")

def main():
    logging.info("USB Monitoring Script Started")
    
    # Check ClamAV installation and database status
    try:
        clam_version = subprocess.run(
            ["clamscan", "--version"],
            capture_output=True,
            text=True,
            check=False
        )
        if clam_version.returncode == 0:
            logging.info(f"ClamAV version: {clam_version.stdout.strip()}")
            
            # Check freshclam database status
            freshclam_status = subprocess.run(
                ["freshclam", "--list-mirrors", "-V"],
                capture_output=True,
                text=True,
                check=False
            )
            if "ClamAV database" in freshclam_status.stdout:
                logging.info("ClamAV database status: OK")
            else:
                logging.warning("ClamAV database may need updating. Run 'sudo freshclam'")
        else:
            logging.warning("ClamAV may not be properly installed. Check 'clamscan --version'")
    except Exception as e:
        logging.error(f"Error checking ClamAV: {e}")
    
    context = Context()
    monitor = Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block', device_type='partition')
    for device in iter(monitor.poll, None):
        if device.action == "add":
            device_path = device.device_node
            device_id = f"{device.get('ID_VENDOR_ID')}:{device.get('ID_MODEL_ID')}"
            device_name = device.get('ID_MODEL')
            if device_path and "sd" in device_path:
                scan_usb(device_path, device_id, device_name)

if __name__ == "__main__":
    main()
