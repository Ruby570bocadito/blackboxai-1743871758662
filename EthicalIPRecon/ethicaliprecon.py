#!/usr/bin/env python3
"""
EthicalIPRecon - Ethical IP reconnaissance tool
"""

import argparse
import sys
from datetime import datetime

# ASCII Art Banner
BANNER = r"""
  ______ _   _ _____ _____ _____ _____ _____ _____ _____ 
 |  ____| | | |_   _|  __ \_   _|  __ \_   _/ ____|  __ \
 | |__  | |_| | | | | |__) || | | |__) || || |    | |__) |
 |  __| |  _  | | | |  ___/ | | |  _  / | || |    |  ___/ 
 | |____| | | |_| |_| |    _| |_| | \ \_| || |____| |     
 |______|_| |_|_____|_|   |_____|_|  \_____\_____|_|     
"""

def display_banner():
    print(BANNER)
    print("\033[1;31m" + "WARNING: For authorized security testing only!" + "\033[0m")
    print("\033[1;33m" + "Unauthorized use against systems you don't own is illegal." + "\033[0m\n")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Ethical IP Reconnaissance Tool',
        epilog='Example: ethicaliprecon.py -t 192.168.1.1 -m passive'
    )
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-m', '--module', choices=['passive', 'active', 'vuln', 'report'],
                       default='passive', help='Module to execute')
    parser.add_argument('--accept-risk', action='store_true',
                       help='Acknowledge legal risks (required for active scans)')
    parser.add_argument('--format', choices=['terminal', 'html', 'pdf', 'json', 'all'],
                       default='terminal', help='Report output format')
    parser.add_argument('--output-dir', default='reports',
                       help='Directory to save reports (default: reports)')
    return parser.parse_args()

from modules.passive import PassiveRecon
from termcolor import colored
import json

def display_results(results):
    """Display formatted results to console"""
    print("\n" + colored("=== PASSIVE RECONNAISSANCE RESULTS ===", 'green'))
    
    # Whois results
    print(colored("\n[WHOIS]", 'yellow'))
    if 'error' in results['whois']:
        print(colored(f"Error: {results['whois']['error']}", 'red'))
    else:
        print(f"Registrar: {results['whois'].get('registrar', 'N/A')}")
        print(f"Created: {results['whois'].get('creation_date', 'N/A')}")
        print(f"Expires: {results['whois'].get('expiration_date', 'N/A')}")
        print(f"Name Servers: {', '.join(results['whois'].get('name_servers', []))}")
    
    # GeoIP results
    print(colored("\n[GEOIP]", 'yellow'))
    if 'error' in results['geoip']:
        print(colored(f"Error: {results['geoip']['error']}", 'red'))
    else:
        print(f"Location: {results['geoip'].get('city', 'N/A')}, {results['geoip'].get('country', 'N/A')}")
        print(f"Coordinates: {results['geoip'].get('latitude', 'N/A')}, {results['geoip'].get('longitude', 'N/A')}")
        print(f"Timezone: {results['geoip'].get('timezone', 'N/A')}")
    
    # DNS results
    print(colored("\n[DNS]", 'yellow'))
    if 'error' in results['dns']:
        print(colored(f"Error: {results['dns']['error']}", 'red'))
    else:
        print(f"Forward: {results['dns'].get('forward', 'N/A')}")
        print(f"Reverse: {', '.join(results['dns'].get('reverse', []))}")
    
    # Reputation results
    print(colored("\n[REPUTATION]", 'yellow'))
    if 'error' in results['reputation']:
        print(colored(f"Error: {results['reputation']['error']}", 'red'))
    else:
        if 'virustotal' in results['reputation']:
            vt = results['reputation']['virustotal']
            print(f"VirusTotal: {vt['data']['attributes']['last_analysis_stats']['malicious']} malicious detections")
        if 'abuseipdb' in results['reputation']:
            abuse = results['reputation']['abuseipdb']['data']
            print(f"AbuseIPDB: Score {abuse['abuseConfidenceScore']}% (Total reports: {abuse['totalReports']})")

def main():
    display_banner()
    args = parse_arguments()
    
    if args.module != 'passive' and not args.accept_risk:
        print("\n\033[1;31mERROR: Active scanning requires --accept-risk flag\033[0m")
        print("This acknowledges you have permission to scan the target\n")
        sys.exit(1)
        
    print(f"\n[+] Starting {args.module} reconnaissance on {args.target}")
    print(f"[+] Scan initiated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    if args.module == 'passive':
        recon = PassiveRecon(args.target)
        results = recon.run_all()
        
        from modules.report import ReportGenerator
        reporter = ReportGenerator(results, args.target)
        
        if args.format == 'terminal':
            display_results(results)
        elif args.format == 'html':
            reporter.generate_html()
        elif args.format == 'pdf':
            reporter.generate_pdf()
        elif args.format == 'json':
            reporter.generate_json()
        elif args.format == 'all':
            reporter.generate_all()
        else:
            display_results(results)  # Default to terminal output
            
    else:
        print("[!] Module not yet implemented")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Scan aborted by user\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[1;31m[!] Error: {str(e)}\033[0m")
        sys.exit(1)