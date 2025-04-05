# EthicalIPRecon Configuration
# WARNING: Keep this file secure and never commit API keys to version control

import os
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

class API_KEYS:
    """Container for all API keys with validation"""
    
    # Shodan API (https://developer.shodan.io/)
    SHODAN_API = os.getenv('SHODAN_API_KEY', 'YOUR_API_KEY_HERE')
    
    # AlienVault OTX (https://otx.alienvault.com/api/)
    OTX_API = os.getenv('OTX_API_KEY', 'YOUR_OTX_KEY_HERE')
    
    # VirusTotal API (https://developers.virustotal.com/)
    VT_API = os.getenv('VT_API_KEY', 'YOUR_API_KEY_HERE')
    
    # AbuseIPDB API (https://docs.abuseipdb.com/)
    ABUSEIPDB_API = os.getenv('ABUSEIPDB_KEY', 'YOUR_API_KEY_HERE')
    
    # Censys API (https://search.censys.io/api)
    CENSYS_API_ID = os.getenv('CENSYS_API_ID', 'YOUR_API_ID_HERE')
    CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', 'YOUR_API_SECRET_HERE')
    
    # MaxMind GeoIP (https://dev.maxmind.com/geoip/)
    GEOIP_ACCOUNT = os.getenv('GEOIP_ACCOUNT', 'YOUR_ACCOUNT_ID')
    GEOIP_LICENSE = os.getenv('GEOIP_LICENSE', 'YOUR_LICENSE_KEY')

# Validate required API keys
REQUIRED_KEYS = {
    'Shodan': API_KEYS.SHODAN_API,
    'VirusTotal': API_KEYS.VT_API
}

def validate_api_keys():
    """Check if required API keys are configured"""
    missing_keys = [name for name, key in REQUIRED_KEYS.items() if key.startswith('YOUR_')]
    if missing_keys:
        print("\033[1;33mWARNING: Missing API keys for: " + ", ".join(missing_keys) + "\033[0m")
        print("Some features may be limited without proper API configuration\n")
    return len(missing_keys) == 0

# Global configuration
SCAN_TIMEOUT = 10  # seconds
MAX_PORTS_TO_SCAN = 100  # Safety limit for port scanning
REPORT_DIR = "reports"  # Output directory for generated reports