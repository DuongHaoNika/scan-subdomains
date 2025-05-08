import requests
import json
from typing import Dict, List
import sys
from datetime import datetime
import httpx
import socket
from urllib.parse import urlparse
import concurrent.futures
import threading
import os
from dotenv import load_dotenv

load_dotenv()

class SubdomainScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.securitytrails.com/v1"
        self.headers = {
            'apikey': api_key,
            'Accept': 'application/json'
        }
        # Common ports to scan
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        self.lock = threading.Lock()

    def get_subdomains(self, domain: str) -> List[str]:
        """Get all subdomains for a given domain using SecurityTrails API."""
        url = f"{self.base_url}/domain/{domain}/subdomains"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            
            if 'subdomains' in data:
                return [f"{subdomain}.{domain}" for subdomain in data['subdomains']]
            return []
        except requests.exceptions.RequestException as e:
            print(f"Error fetching subdomains: {e}")
            return []

    def get_ip_address(self, domain: str) -> str:
        """Get IP address for a domain."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return "N/A"

    def scan_port(self, ip: str, port: int) -> Dict:
        """Scan a single port."""
        if ip == "N/A":
            return None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return {
                    'port': port,
                    'service': service
                }
        except:
            pass
        return None

    def scan_ports(self, ip: str) -> List[Dict]:
        """Scan multiple ports concurrently."""
        if ip == "N/A":
            return []
            
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in self.common_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports, key=lambda x: x['port'])

    def detect_technologies(self, headers: Dict) -> List[str]:
        """Detect technologies based on headers."""
        technologies = []
        
        # Server detection
        if 'server' in headers:
            server = headers['server'].lower()
            if 'nginx' in server:
                technologies.append('Nginx')
            elif 'apache' in server:
                technologies.append('Apache')
            elif 'iis' in server:
                technologies.append('IIS')
            elif 'cloudflare' in server:
                technologies.append('Cloudflare')
        
        # CMS detection
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'wordpress' in powered_by:
                technologies.append('WordPress')
            elif 'php' in powered_by:
                technologies.append('PHP')
        
        # Framework detection
        if 'x-aspnet-version' in headers:
            technologies.append('ASP.NET')
        elif 'x-drupal-cache' in headers:
            technologies.append('Drupal')
        
        return technologies if technologies else ['Unknown']

    def check_subdomain_status(self, subdomain: str) -> Dict:
        """Check the status of a subdomain."""
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"https://{subdomain}", follow_redirects=True)
                ip = self.get_ip_address(subdomain)
                return {
                    'subdomain': subdomain,
                    'status_code': response.status_code,
                    'is_active': True,
                    'headers': dict(response.headers),
                    'ip': ip,
                    'technologies': self.detect_technologies(dict(response.headers)),
                    'open_ports': self.scan_ports(ip)
                }
        except Exception:
            ip = self.get_ip_address(subdomain)
            return {
                'subdomain': subdomain,
                'status_code': None,
                'is_active': False,
                'ip': ip,
                'technologies': ['Unknown'],
                'open_ports': self.scan_ports(ip)
            }

def main():
    API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
    
    if len(sys.argv) != 2:
        print("Usage: python main.py <domain>")
        print("Example: python main.py apple.com")
        sys.exit(1)

    domain = sys.argv[1]
    scanner = SubdomainScanner(API_KEY)
    
    print(f"\n[*] Scanning subdomains for {domain}")
    print("-" * 50)
    
    subdomains = scanner.get_subdomains(domain)
    
    if not subdomains:
        print("No subdomains found or error occurred.")
        return

    print(f"\nFound {len(subdomains)} subdomains. Checking their status...\n")
    
    # Collect all results
    results = []
    for subdomain in subdomains:
        print(f"Checking {subdomain}...")
        status = scanner.check_subdomain_status(subdomain)
        results.append(status)
    
    # Sort results: active first, then inactive
    results.sort(key=lambda x: (not x['is_active'], x['subdomain']))
    
    # Create output file
    output_file = f"results/{domain}.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Subdomain scan results for {domain}\n")
        f.write("-" * 50 + "\n\n")
        
        # Write active subdomains first
        active_count = sum(1 for r in results if r['is_active'])
        inactive_count = len(results) - active_count
        
        f.write(f"Active Subdomains ({active_count}):\n")
        f.write("-" * 30 + "\n")
        for status in results:
            if status['is_active']:
                f.write(f"[+] {status['subdomain']}\n")
                f.write(f"    Status: {status['status_code']}\n")
                f.write(f"    IP: {status['ip']}\n")
                f.write(f"    Technologies: {', '.join(status['technologies'])}\n")
                if status['open_ports']:
                    f.write(f"    Open Ports:\n")
                    for port in status['open_ports']:
                        f.write(f"        - Port {port['port']} ({port['service']})\n")
                f.write("\n")
        
        # Write inactive subdomains
        if inactive_count > 0:
            f.write(f"\nInactive Subdomains ({inactive_count}):\n")
            f.write("-" * 30 + "\n")
            for status in results:
                if not status['is_active']:
                    f.write(f"[-] {status['subdomain']}\n")
                    f.write(f"    Status: Inactive\n")
                    f.write(f"    IP: {status['ip']}\n")
                    f.write(f"    Technologies: {', '.join(status['technologies'])}\n")
                    if status['open_ports']:
                        f.write(f"    Open Ports:\n")
                        for port in status['open_ports']:
                            f.write(f"        - Port {port['port']} ({port['service']})\n")
                    f.write("\n")
    
    print(f"\nResults have been saved to {output_file}")

if __name__ == "__main__":
    main()
