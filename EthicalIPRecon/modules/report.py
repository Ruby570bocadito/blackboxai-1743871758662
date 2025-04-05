#!/usr/bin/env python3
"""
Report generation module for EthicalIPRecon
"""

import json
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from termcolor import colored
from datetime import datetime
import sys

class ReportGenerator:
    def __init__(self, results, target):
        self.results = results
        self.target = target
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
        
    def _get_template(self):
        """Load Jinja2 template"""
        template_dir = Path(__file__).parent.parent / "report_templates"
        env = Environment(loader=FileSystemLoader(template_dir))
        return env.get_template("report.html")
    
    def generate_html(self):
        """Generate HTML report"""
        print(colored("\n[+] Generating HTML report...", "blue"))
        try:
            template = self._get_template()
            html = template.render(
                target=self.target,
                timestamp=self.timestamp,
                **self.results
            )
            
            report_path = self.report_dir / f"report_{self.target}_{self.timestamp}.html"
            with open(report_path, "w") as f:
                f.write(html)
                
            print(colored(f"[✓] HTML report saved to: {report_path}", "green"))
            return str(report_path)
        except Exception as e:
            print(colored(f"[!] Error generating HTML report: {str(e)}", "red"))
            return None
    
    def generate_pdf(self, html_path=None):
        """Generate PDF report from HTML"""
        print(colored("\n[+] Generating PDF report...", "blue"))
        try:
            if not html_path:
                html_path = self.generate_html()
                if not html_path:
                    return None
                    
            pdf_path = self.report_dir / f"report_{self.target}_{self.timestamp}.pdf"
            HTML(html_path).write_pdf(pdf_path)
            
            print(colored(f"[✓] PDF report saved to: {pdf_path}", "green"))
            return str(pdf_path)
        except Exception as e:
            print(colored(f"[!] Error generating PDF report: {str(e)}", "red"))
            return None
    
    def generate_terminal(self):
        """Display results in terminal-friendly format"""
        print(colored("\n=== SCAN RESULTS ===", "cyan"))
        print(colored(f"\nTarget: {self.target}", "yellow"))
        print(colored(f"Timestamp: {self.timestamp.replace('_', ' ')}", "yellow"))
        
        # Whois summary
        whois = self.results.get('whois', {})
        print(colored("\n[WHOIS]", "magenta"))
        print(f"Registrar: {whois.get('registrar', 'N/A')}")
        print(f"Created: {whois.get('creation_date', 'N/A')}")
        
        # GeoIP summary
        geoip = self.results.get('geoip', {})
        print(colored("\n[LOCATION]", "magenta"))
        print(f"Location: {geoip.get('city', 'N/A')}, {geoip.get('country', 'N/A')}")
        print(f"Coordinates: {geoip.get('latitude', 'N/A')}, {geoip.get('longitude', 'N/A')}")
        
        # Reputation summary
        rep = self.results.get('reputation', {})
        print(colored("\n[REPUTATION]", "magenta"))
        if 'virustotal' in rep:
            print(f"VirusTotal: {rep['virustotal']['data']['attributes']['last_analysis_stats']['malicious']} malicious")
        if 'abuseipdb' in rep:
            print(f"AbuseIPDB Score: {rep['abuseipdb']['data']['abuseConfidenceScore']}%")
    
    def generate_json(self):
        """Generate JSON report"""
        print(colored("\n[+] Generating JSON report...", "blue"))
        try:
            report_data = {
                "target": self.target,
                "timestamp": self.timestamp,
                "results": self.results
            }
            
            json_path = self.report_dir / f"report_{self.target}_{self.timestamp}.json"
            with open(json_path, "w") as f:
                json.dump(report_data, f, indent=2)
                
            print(colored(f"[✓] JSON report saved to: {json_path}", "green"))
            return str(json_path)
        except Exception as e:
            print(colored(f"[!] Error generating JSON report: {str(e)}", "red"))
            return None

    def generate_all(self):
        """Generate all report formats"""
        self.generate_terminal()
        html_path = self.generate_html()
        if html_path:
            self.generate_pdf(html_path)
        self.generate_json()