# USB Security Monitor

This is my graduation project for cybersecurity. It's a system that monitors USB devices, scans them for malware, and keeps track of which ones are allowed to connect.

## What it does

- Monitors when USB devices are plugged in
- Scans files on USB devices using YARA rules and ClamAV
- Creates "fingerprints" of devices to identify them later
- Quarantines suspicious files by encrypting them
- Blocks malicious USB devices
- Shows everything in a web dashboard
- Checks files with VirusTotal and other online services
- Stores everything securely with encryption
- Generates security reports

## Setup

### Requirements

- Python 3.8+
- ClamAV (`sudo apt-get install clamav`)
- SQLite3
- Flask (for the web dashboard)

### Python Libraries

```
pip install -r requirements.txt
```

The requirements.txt should have:
```
flask
cryptography
pyudev
yara-python
OTXv2
requests
fpdf
colorama
```

### Installation

1. Clone this repository
```
git clone https://github.com/yourusername/usb-security-monitor.git
cd usb-security-monitor
```

2. Install the requirements
```
pip install -r requirements.txt
```

3. Update ClamAV definitions
```
sudo freshclam
```

4. Create YARA rules file at `/home/kali/usb-monitor/rules.yar` or edit `usb_monitor.py` to point to your rules file

## Running the System

### Start the USB Monitor
```
sudo python usb_monitor.py
```
*Needs sudo to access USB devices*

### Start the Web Dashboard
```
python app.py
```
Then open http://localhost:5000 in your browser

## How to Use

1. **Monitoring USBs**: Just plug in a USB device and the system will automatically scan it

2. **Web Dashboard**: Shows scan results, device history, and lets you set which devices are authorized

3. **Managing Devices**: You can authorize or block devices from the dashboard

4. **Compliance Reports**: Generate reports showing your system security status

## File Structure

- `usb_monitor.py` - Main scanning script
- `app.py` - Web dashboard
- `secure_storage.py` - Handles encrypted database
- `device_fingerprint.py` - Creates unique IDs for USB devices
- `encryption_viewer.py` - Lets you check encryption status
- `templates/` - HTML files for the web dashboard
- `static/` - CSS, JavaScript, and images

## Security Features

- All data is encrypted in the database
- Quarantined files use AES-256-GCM encryption
- Secure key management with PBKDF2
- Access control for device authorization

## Troubleshooting

- **No devices detected?** Make sure you're running with sudo
- **ClamAV errors?** Try updating definitions with `sudo freshclam`
- **Database issues?** Check if `~/usb_monitor.db` exists and has correct permissions
- **Web dashboard not working?** Make sure Flask is installed and port 5000 isn't blocked

## API Keys

The system uses these services with API keys (you should get your own for production):
- VirusTotal
- Hybrid Analysis
- AlienVault OTX

## Note

This is an educational project. For a production environment, you'd want to:
- Use HTTPS for the web dashboard
- Implement proper user authentication
- Configure and review the quarantine settings
- Rotate encryption keys regularly

Made by [Your Name] 
