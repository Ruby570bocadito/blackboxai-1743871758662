#!/usr/bin/env python3
"""
Enhanced passive reconnaissance module for EthicalIPRecon
"""

import socket
import time
import dns.resolver
import whois
import geoip2.database
import requests
import OpenSSL
import logging
from datetime import datetime
from config import API_KEYS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='ethicaliprecon.log'
)
logger = logging.getLogger(__name__)
from urllib.parse import urlparse
from termcolor import colored
from tqdm import tqdm

class PassiveRecon:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = {
            'whois': {},
            'geoip': {}, 
            'dns': {},
            'reputation': {},
            'threat_intel': {},
            'ssl': {},
            'timestamp': datetime.now().isoformat()
        }
        
    def _print_verbose(self, message, color=None):
        """Print verbose output if enabled"""
        if self.verbose:
            if color:
                print(colored(f"[*] {message}", color))
            else:
                print(f"[*] {message}")

    def _validate_target(self, target):
        """Validate target as either IP or domain"""
        try:
            socket.inet_aton(target)
            return 'ip'
        except socket.error:
            if '.' in target and not target.startswith(('http://', 'https://')):
                return 'domain'
            return False

    def whois_lookup(self):
        """Perform WHOIS lookup on target"""
        try:
            w = whois.whois(self.target)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers,
                'emails': w.emails
            }
        except Exception as e:
            self.results['whois']['error'] = str(e)

    def geoip_lookup(self):
        """Get geographic location of target"""
        try:
            target = self.target
            target_type = self._validate_target(target)
            
            if target_type == 'domain':
                target = socket.gethostbyname(target)
                
            with geoip2.database.Reader('EthicalIPRecon/GeoLite2-City.mmdb') as reader:
                response = reader.city(target)
                self.results['geoip'] = {
                    'country': response.country.name,
                    'city': response.city.name,
                    'postal': response.postal.code,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'timezone': response.location.time_zone
                }
        except Exception as e:
            self.results['geoip']['error'] = str(e)

    def dns_lookup(self):
        """Perform DNS lookups"""
        try:
            target_type = self._validate_target(self.target)
            self.results['dns']['type'] = target_type
            
            if target_type == 'ip':
                # Reverse lookup for IPs
                self.results['dns']['forward'] = socket.gethostbyaddr(self.target)[0]
                resolver = dns.resolver.Resolver()
                self.results['dns']['reverse'] = [
                    str(answer) for answer in resolver.resolve(
                        '.'.join(reversed(self.target.split('.'))) + '.in-addr.arpa',
                        'PTR'
                    )
                ]
            elif target_type == 'domain':
                # Forward lookup for domains
                self.results['dns']['a_records'] = [
                    str(answer) for answer in dns.resolver.resolve(self.target, 'A')
                ]
                try:
                    self.results['dns']['mx_records'] = [
                        str(answer) for answer in dns.resolver.resolve(self.target, 'MX')
                    ]
                except:
                    pass
        except Exception as e:
            self.results['dns']['error'] = str(e)

    def ssl_analysis(self):
        """Analyze SSL certificate for domain targets"""
        try:
            if self._validate_target(self.target) == 'domain':
                # Disable warnings for unverified requests
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    requests.get(f"https://{self.target}", 
                               verify=False,  # Still not verifying for flexibility
                               timeout=5).content
                )
                self.results['ssl'] = {
                    'issuer': cert.get_issuer().CN,
                    'expires': cert.get_notAfter().decode('utf-8'),
                    'subject': cert.get_subject().CN,
                    'version': cert.get_version(),
                    'sig_alg': cert.get_signature_algorithm().decode('utf-8')
                }
        except Exception as e:
            self.results['ssl'] = {'error': str(e)}

    def check_reputation(self):
        """Check IP reputation using APIs"""
        if self._validate_target(self.target) != 'ip':
            self.results['reputation']['error'] = "Reputation checks require IP targets"
            return

        try:
            # VirusTotal check
            if API_KEYS.VT_API != 'YOUR_API_KEY_HERE':
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.target}"
                headers = {"x-apikey": API_KEYS.VT_API}
                self.results['reputation']['virustotal'] = self._api_request(vt_url, headers=headers)
            
            # AbuseIPDB check
            if API_KEYS.ABUSEIPDB_API != 'YOUR_API_KEY_HERE':
                url = "https://api.abuseipdb.com/api/v2/check"
                params = {'ipAddress': self.target}
                headers = {'Key': API_KEYS.ABUSEIPDB_API}
                self.results['reputation']['abuseipdb'] = self._api_request(url, headers=headers, params=params)

            # Shodan check
            if API_KEYS.SHODAN_API != 'YOUR_API_KEY_HERE':
                shodan_url = f"https://api.shodan.io/shodan/host/{self.target}?key={API_KEYS.SHODAN_API}"
                shodan_data = self._api_request(shodan_url)
                if shodan_data:
                    self.results['shodan'] = {
                        'ports': shodan_data.get('ports', []),
                        'vulns': shodan_data.get('vulns', []),
                        'hostnames': shodan_data.get('hostnames', []),
                        'org': shodan_data.get('org', 'Unknown')
                    }

        except Exception as e:
            self.results['reputation']['error'] = f"API error: {str(e)}"

    def check_threat_intel(self):
        """Check threat intelligence feeds"""
        target_type = self._validate_target(self.target)
        if target_type != 'ip':
            self.results['threat_intel']['error'] = "Threat intelligence requires IP targets"
            return

        try:
            # AlienVault OTX
            if API_KEYS.OTX_API != 'YOUR_OTX_KEY_HERE':
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{self.target}/general"
                headers = {'X-OTX-API-KEY': API_KEYS.OTX_API}
                response = self._api_request(url, headers=headers)
                self.results['threat_intel'] = {
                    'pulse_count': response.get('pulse_info', {}).get('count', 0),
                    'malware': response.get('malware', []),
                    'reputation': response.get('reputation', None)
                }
        except Exception as e:
            self.results['threat_intel'] = {'error': str(e)}

    def _api_request(self, url, headers=None, params=None, retries=3):
        """Wrapper for API requests with retry logic"""
        for attempt in range(retries):
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=10
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                if attempt == retries - 1:
                    raise
                time.sleep(1 * (attempt + 1))
        return None

    def run_all(self):
        """Execute all passive reconnaissance methods"""
        target_type = self._validate_target(self.target)
        if not target_type:
            raise ValueError("Invalid target - must be IP address or domain name")

        self.whois_lookup()
        
        if target_type == 'domain':
            self.ssl_analysis()
            
        self.geoip_lookup() 
        self.dns_lookup()
        
        if target_type == 'ip':
            self.check_reputation()
            self.check_threat_intel()
            
        return self.results
