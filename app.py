from flask import Flask, render_template, jsonify, send_from_directory, send_file, request
import os
import json
from datetime import datetime
import re
from secure_storage import SQLCipherDatabase
from device_fingerprint import DeviceFingerprint
import logging
import secrets

app = Flask(__name__,
    template_folder='templates',
    static_folder='static')

LOG_FILE = "/var/log/usb_monitor.log"

def parse_logs():
    """Parse logs and count stuff"""
    metrics = {
        "malware_detected": 0,
        "usb_scans": 0,
        "logs": [],
        "virus_total_results": [],
        "hybrid_analysis_results": [],
        "yara_results": set(),  # Using set to avoid duplicates
        "clamav_results": [],
        "otx_results": [],
        "quarantined_files": []
    }

    if not os.path.exists(LOG_FILE):
        print("Log file missing.")
        return metrics

    try:
        with open(LOG_FILE, 'r') as f:
            content = f.read()
            lines = content.splitlines()

        # Save all logs
        metrics["logs"] = lines
        # Go through each line
        for line in lines:
            # Count scans
            if "Scanning USB device" in line:
                metrics["usb_scans"] += 1

            # VirusTotal Links
            if "VirusTotal Analysis Link:" in line:
                link = line.split("VirusTotal Analysis Link:")[-1].strip()
                if link and link not in metrics["virus_total_results"]:
                    metrics["virus_total_results"].append(link)

            # Hybrid Analysis Links
            if "Hybrid Analysis Report Link:" in line:
                link = line.split("Hybrid Analysis Report Link:")[-1].strip()
                if link and link not in metrics["hybrid_analysis_results"]:
                    metrics["hybrid_analysis_results"].append(link)

            # YARA Results
            if "YARA detected malware in:" in line:
                file_path = line.split("YARA detected malware in:")[-1].strip()
                if file_path:
                    metrics["yara_results"].add(file_path)
                    # Only count new detections
                    if len(metrics["yara_results"]) > metrics["malware_detected"]:
                        metrics["malware_detected"] += 1

            # ClamAV Results
            if "ClamAV Results:" in line:
                clam_summary = line.split("ClamAV Results:")[-1].strip()
                files = clam_summary.strip("[]").replace("'", "").split(", ")
                for file_path in files:
                    if file_path:
                        file_name = os.path.basename(file_path)
                        if file_name not in [r.get('file_name') if isinstance(r, dict) else r for r in metrics["clamav_results"]]:
                            metrics["clamav_results"].append(file_name)

            # OTX Results
            if "OTX Analysis Result:" in line:
                try:
                    # Get JSON part
                    json_str = line.split("OTX Analysis Result:")[-1].strip()
                    if json_str:
                        result = json.loads(json_str)
                        # Check if valid
                        if isinstance(result, dict):
                            # Add if not duplicate
                            if not any(r.get("indicator") == result.get("indicator") for r in metrics["otx_results"]):
                                metrics["otx_results"].append(result)
                except json.JSONDecodeError as e:
                    print(f"Error parsing OTX JSON: {e}")
                    continue

            # Quarantined Files
            if "Quarantined file:" in line:
                quarantined_file = line.split("Quarantined file:")[-1].strip()
                if quarantined_file and quarantined_file not in metrics["quarantined_files"]:
                    metrics["quarantined_files"].append(quarantined_file)

        # Convert YARA set to list for JSON
        metrics["yara_results"] = list(metrics["yara_results"])

        # Print debug info
        print("Parsed results:")
        print(f"VirusTotal: {len(metrics['virus_total_results'])}")
        print(f"Hybrid Analysis: {len(metrics['hybrid_analysis_results'])}")
        print(f"YARA: {len(metrics['yara_results'])}")
        print(f"ClamAV: {len(metrics['clamav_results'])}")
        print(f"OTX: {len(metrics['otx_results'])}")
        print(f"Malware detected: {metrics['malware_detected']}")

    except Exception as e:
        print(f"Error parsing logs: {e}")
        
    return metrics

@app.route('/')
def dashboard():
    metrics = parse_logs()
    return render_template('dashboard.html', metrics=metrics)

@app.route('/metrics')
def get_metrics():
    metrics = parse_logs()
    return jsonify(metrics)

@app.route('/analysis/virustotal')
def get_virustotal_analysis():
    metrics = parse_logs()
    return jsonify(metrics.get('virus_total_results', []))

@app.route('/analysis/hybrid')
def get_hybrid_analysis():
    metrics = parse_logs()
    return jsonify(metrics.get('hybrid_analysis_results', []))

@app.route('/analysis/yara')
def get_yara_results():
    try:
        results = parse_logs()
        return jsonify({
            'success': True,
            'results': list(results['yara_results']),
            'total': len(results['yara_results'])
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/analysis/clamav')
def get_clamav_analysis():
    metrics = parse_logs()
    return jsonify(metrics.get('clamav_results', []))

@app.route('/analysis/otx')
def get_otx_results():
    try:
        results = parse_logs()
        return jsonify({
            'success': True,
            'results': results['otx_results'],
            'total': len(results['otx_results'])
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/analysis/all')
def get_all_results():
    try:
        results = parse_logs()
        return jsonify({
            'success': True,
            'data': {
                'virus_total_results': results['virus_total_results'],
                'hybrid_analysis_results': results['hybrid_analysis_results'],
                'clamav_results': results['clamav_results'],
                'quarantined_files': results['quarantined_files']
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/quarantined')
def get_quarantined_files():
    metrics = parse_logs()
    return jsonify(metrics.get('quarantined_files', []))

@app.route('/debug-results')
def debug_results():
    """Show raw parsing results for debugging"""
    metrics = parse_logs()
    return jsonify({
        'virus_total_count': len(metrics['virus_total_results']),
        'hybrid_analysis_count': len(metrics['hybrid_analysis_results']),
        'yara_count': len(metrics['yara_results']),
        'otx_count': len(metrics['otx_results']),
        'quarantined_count': len(metrics['quarantined_files']),
        'virus_total': metrics['virus_total_results'][:5],  # First 5 results
        'hybrid_analysis': metrics['hybrid_analysis_results'][:5],
        'yara': metrics['yara_results'][:5],
        'otx': metrics['otx_results'][:5],
        'quarantined': metrics['quarantined_files'][:5]
    })

@app.route('/policies/<path:filename>')
def serve_policy(filename):
    try:
        policy_path = os.path.join('/home/kali/usb-monitor/policies', filename)
        if os.path.exists(policy_path):
            return send_file(
                policy_path,
                mimetype='application/pdf',
                as_attachment=False,
                download_name=filename
            )
        else:
            return "Policy file not found", 404
    except Exception as e:
        print(f"Error serving policy file: {e}")
        return "Error serving policy file", 500

@app.route('/generate_compliance_report', methods=['POST'])
def generate_compliance_report():
    try:
        from fpdf import FPDF
        from datetime import datetime
        
        # Make PDF
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "USB Security Compliance Report", ln=True, align="C")
        
        # Add timestamp
        pdf.set_font("Arial", "I", 10)
        pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="R")
        
        # Summary section
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Compliance Summary", ln=True)
        
        # Parse metrics
        metrics = parse_logs()
        
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Total USB Scans: {metrics['usb_scans']}", ln=True)
        pdf.cell(0, 10, f"Malware Detected: {metrics['malware_detected']}", ln=True)
        pdf.cell(0, 10, f"Quarantined Files: {len(metrics['quarantined_files'])}", ln=True)
        
        # Compliance standards section
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Compliance Standards", ln=True)
        
        pdf.set_font("Arial", "", 12)
        standards = [
            {"name": "ISO 27001 - USB Media Controls", "status": "Compliant" if metrics['usb_scans'] > 0 else "Non-Compliant"},
            {"name": "NIST SP 800-53 - Removable Media Protection", "status": "Compliant"},
            {"name": "PCI DSS - Removable Media Security", "status": "Compliant" if len(metrics['quarantined_files']) > 0 else "Partially Compliant"},
            {"name": "HIPAA - Portable Media Security", "status": "Compliant"},
            {"name": "GDPR - Data Protection Measures", "status": "Compliant"}
        ]
        
        for standard in standards:
            pdf.cell(120, 10, standard["name"], 1)
            pdf.cell(70, 10, standard["status"], 1, ln=True)
        
        # Threat Intelligence Summary
        pdf.ln(10)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Threat Intelligence Summary", ln=True)
        
        pdf.set_font("Arial", "", 12)
        
        # OTX Findings
        if len(metrics.get('otx_results', [])) > 0:
            pdf.ln(5)
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "OTX Intelligence Findings:", ln=True)
            pdf.set_font("Arial", "", 10)
            
            # List countries
            countries = set()
            for result in metrics.get('otx_results', []):
                if 'country' in result and result['country'] != 'Unknown':
                    countries.add(result['country'])
            
            if countries:
                pdf.cell(0, 10, f"Countries of Origin: {', '.join(countries)}", ln=True)
            
            # List MITRE ATT&CK techniques
            attack_techniques = set()
            for result in metrics.get('otx_results', []):
                if 'attack_techniques' in result and result['attack_techniques']:
                    if isinstance(result['attack_techniques'], list):
                        for technique in result['attack_techniques']:
                            attack_techniques.add(technique)
                    else:
                        attack_techniques.add(result['attack_techniques'])
            
            if attack_techniques:
                pdf.cell(0, 10, f"MITRE ATT&CK Techniques: {', '.join(attack_techniques)}", ln=True)
            
            # List CVEs
            cves = set()
            for result in metrics.get('otx_results', []):
                if 'cve_references' in result and result['cve_references']:
                    if isinstance(result['cve_references'], list):
                        for cve in result['cve_references']:
                            cves.add(cve)
                    else:
                        cves.add(result['cve_references'])
            
            if cves:
                pdf.cell(0, 10, f"CVE References: {', '.join(cves)}", ln=True)
        else:
            pdf.cell(0, 10, "No threat intelligence findings from OTX.", ln=True)
        
        # Security recommendations
        pdf.ln(10)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Security Recommendations", ln=True)
        
        pdf.set_font("Arial", "", 12)
        recommendations = [
            "1. Regularly update the USB security monitoring system",
            "2. Ensure all USB ports are monitored by the security system",
            "3. Conduct regular audits of USB usage and access",
            "4. Update YARA rules with the latest threat intelligence",
            "5. Implement a formal USB device management policy",
            "6. Provide security awareness training for all employees",
            "7. Consider implementing hardware-level USB port control",
            "8. Review quarantined files regularly for false positives"
        ]
        
        # Add CVE recommendations if any found
        if len(cves) > 0:
            recommendations.append("9. Patch systems against the detected CVEs")
            recommendations.append("10. Implement additional monitoring for the identified attack techniques")
        
        for rec in recommendations:
            pdf.cell(10, 10, "-", 0)
            pdf.cell(0, 10, rec, ln=True)
        
        # Save report
        report_name = f"compliance_report_{datetime.now().strftime('%Y%m%d')}.pdf"
        report_path = os.path.join('/tmp', report_name)
        pdf.output(report_path)
        
        # Send the PDF
        return send_file(
            report_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=report_name
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/device_fingerprints')
def get_device_fingerprints():
    try:
        logging.info("Getting device fingerprints")
        db = SQLCipherDatabase()
        conn = db.connect()
        
        # Check if any fingerprints exist
        cursor = conn.execute("SELECT COUNT(*) FROM device_fingerprints")
        count = cursor.fetchone()[0]
        logging.info(f"Found {count} fingerprints in database")
        
        if count == 0:
            logging.info("No fingerprints found in database")
            return jsonify([])
        
        cursor = conn.execute("""
            SELECT hardware_id, manufacturer, product, timestamp, risk_score, 
                  scan_results, behavioral_hash, serial
            FROM device_fingerprints 
            ORDER BY timestamp DESC LIMIT 10
        """)
        
        fingerprints = []
        for row in cursor.fetchall():
            try:
                # Decrypt the fields
                fingerprint = {
                    'hardware_id': db._decrypt_data(row[0]) if row[0] else '',
                    'manufacturer': db._decrypt_data(row[1]) if row[1] else '',
                    'product': db._decrypt_data(row[2]) if row[2] else '',
                    'timestamp': row[3] or '',
                    'risk_score': row[4] or 0,
                    'scan_results': db._decrypt_data(row[5]) if row[5] else '{}',
                    'behavioral_hash': db._decrypt_data(row[6]) if row[6] else '',
                    'serial': db._decrypt_data(row[7]) if row[7] else ''
                }
                fingerprints.append(fingerprint)
                logging.info(f"Decrypted fingerprint for device: {fingerprint['hardware_id']}")
            except Exception as e:
                logging.error(f"Error decrypting fingerprint data: {e}")
                continue
        
        conn.close()
        logging.info(f"Got {len(fingerprints)} fingerprints")
        return jsonify(fingerprints)
    except Exception as e:
        logging.error(f"Error getting fingerprints: {e}")
        return jsonify({"error": str(e)}), 500

# Device authorization endpoints
@app.route('/devices')
def get_all_devices():
    """Get all devices with auth status"""
    try:
        db = SQLCipherDatabase()
        devices = db.get_all_devices()
        return jsonify(devices)
    except Exception as e:
        logging.error(f"Error getting all devices: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/device/<hardware_id>')
def get_device_details(hardware_id):
    """Get details about a device"""
    try:
        db = SQLCipherDatabase()
        conn = db.connect()
        
        # Get device info
        cursor = conn.execute("""
            SELECT hardware_id, manufacturer, product, timestamp, risk_score, 
                  scan_results, behavioral_hash, serial
            FROM device_fingerprints 
            WHERE hardware_id = ?
            ORDER BY timestamp DESC LIMIT 1
        """, (hardware_id,))
        
        device_row = cursor.fetchone()
        if not device_row:
            return jsonify({"error": "Device not found"}), 404
            
        device = {
            'hardware_id': device_row[0] or '',
            'manufacturer': device_row[1] or '',
            'product': device_row[2] or '',
            'timestamp': device_row[3] or '',
            'risk_score': device_row[4] or 0,
            'scan_results': json.loads(device_row[5] or '{}'),
            'behavioral_hash': device_row[6] or '',
            'serial': device_row[7] or ''
        }
        
        # Get auth status
        auth_status = db.get_authorization_status(hardware_id)
        if auth_status:
            device.update(auth_status)
        else:
            device.update({
                'is_authorized': None,
                'authorization_date': '',
                'authorized_by': '',
                'notes': ''
            })
        
        conn.close()
        return jsonify(device)
    except Exception as e:
        logging.error(f"Error getting device details: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/authorize_device', methods=['POST'])
def authorize_device():
    """Auth or block a device"""
    try:
        data = request.json
        if not data or 'hardware_id' not in data or 'is_authorized' not in data:
            return jsonify({"error": "Missing required params"}), 400
            
        hardware_id = data['hardware_id']
        is_authorized = bool(data['is_authorized'])
        authorized_by = data.get('authorized_by', 'admin')
        notes = data.get('notes', '')
        behavioral_hash = data.get('behavioral_hash', '')
        serial = data.get('serial', '')
        
        db = SQLCipherDatabase()
        success = db.set_device_authorization(
            hardware_id, 
            is_authorized, 
            authorized_by, 
            notes, 
            behavioral_hash, 
            serial
        )
        
        if success:
            return jsonify({
                "success": True,
                "message": f"Device {hardware_id} {'authorized' if is_authorized else 'blocked'}"
            })
        else:
            return jsonify({"error": "Failed to update device auth"}), 500
    except Exception as e:
        logging.error(f"Error updating device auth: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/rotate-keys', methods=['POST'])
def rotate_keys():
    """Change encryption keys for database"""
    try:
        # Check admin auth
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing/invalid auth header'}), 401
            
        token = auth_header.split(' ')[1]
        admin_token = os.getenv('ADMIN_TOKEN', 'Allsafe_password543')
        
        if not secrets.compare_digest(token, admin_token):
            return jsonify({'error': 'Invalid token'}), 401
            
        # Change the key
        db = SQLCipherDatabase()
        if db.rotate_key():
            return jsonify({'message': 'Keys rotated successfully'})
        else:
            return jsonify({'error': 'Failed to rotate keys'}), 500
            
    except Exception as e:
        logging.error(f"Error rotating keys: {str(e)}")
        return jsonify({'error': str(e)}), 500

def calculate_compliance_score(metrics):
    """Calculate compliance score from metrics"""
    total_score = 0
    max_score = 100
    
    # Base score for having a system
    total_score += 20
    
    # USB Scans (20 points)
    if metrics['usb_scans'] > 0:
        total_score += 20
        logging.info("USB scanning active (+20 points)")
    
    # Malware Detection (30 points)
    if metrics['malware_detected'] > 0:
        # Points for detecting malware (shows system works)
        total_score += 15
        logging.info("Malware detection working (+15 points)")
        
        # Points for handling malware
        if len(metrics['quarantined_files']) > 0:
            total_score += 15
            logging.info("Quarantine working (+15 points)")
    
    # Analysis Tools (30 points)
    analysis_tools_score = 0
    
    # YARA (10 points)
    if len(metrics['yara_results']) > 0:
        analysis_tools_score += 10
        logging.info("YARA working (+10 points)")
    
    # ClamAV (10 points)
    if len(metrics['clamav_results']) > 0:
        analysis_tools_score += 10
        logging.info("ClamAV working (+10 points)")
    
    # OTX (10 points)
    if len(metrics['otx_results']) > 0:
        analysis_tools_score += 10
        logging.info("OTX working (+10 points)")
    
    total_score += analysis_tools_score
    
    # Extra Security (20 points)
    security_measures_score = 0
    
    # VirusTotal (5 points)
    if len(metrics['virus_total_results']) > 0:
        security_measures_score += 5
        logging.info("VirusTotal working (+5 points)")
    
    # Hybrid Analysis (5 points)
    if len(metrics['hybrid_analysis_results']) > 0:
        security_measures_score += 5
        logging.info("Hybrid Analysis working (+5 points)")
    
    # Quarantine (10 points)
    if len(metrics['quarantined_files']) > 0:
        security_measures_score += 10
        logging.info("Quarantine working (+10 points)")
    
    total_score += security_measures_score
    
    # Cap at max
    final_score = min(total_score, max_score)
    
    # Get percentage
    percentage = (final_score / max_score) * 100
    
    # Get status
    if percentage >= 90:
        status = "Excellent"
    elif percentage >= 75:
        status = "Good"
    elif percentage >= 50:
        status = "Fair"
    else:
        status = "Poor"
    
    logging.info(f"Final score: {final_score}/{max_score} ({percentage:.1f}%) - Status: {status}")
    
    return {
        "score": final_score,
        "max_score": max_score,
        "percentage": percentage,
        "status": status,
        "details": {
            "base_monitoring": 20,
            "usb_scans": 20 if metrics['usb_scans'] > 0 else 0,
            "malware_detection": 15 if metrics['malware_detected'] > 0 else 0,
            "malware_quarantine": 15 if len(metrics['quarantined_files']) > 0 else 0,
            "analysis_tools": analysis_tools_score,
            "security_measures": security_measures_score
        }
    }

@app.route('/compliance_status')
def get_compliance_status():
    """Get compliance status"""
    try:
        metrics = parse_logs()
        compliance = calculate_compliance_score(metrics)
        return jsonify(compliance)
    except Exception as e:
        logging.error(f"Error calculating compliance: {e}")
        return jsonify({
            "error": str(e),
            "score": 0,
            "max_score": 100,
            "percentage": 0,
            "status": "Error"
        }), 500

if __name__ == "__main__":
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
