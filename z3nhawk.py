#!/usr/bin/env python3
"""
Z3NHAWK v3.0 - Standalone Modular OSINT Framework
Pure Python - No external tools required
"""

import sys
import requests
from modules import (banner, whois_lookup, dns_enum, ip_geo, 
                     http_headers, ssl_cert, port_scanner, 
                     subdomain_enum, tech_detect, dir_bruteforce, email_harvest,cve_search,waf_detect)
from utils.helpers import resolve_domain, print_error

def get_port_choice():
    """Get port scan options from user"""
    print("\n[*] Port Scan Options:")
    print("    1. Quick Scan (Top ports from assets/top_ports.txt)")
    print("    2. Custom Range (e.g., 1-1000)")
    print("    3. Skip port scan")
    
    try:
        choice = input("\n[?] Select option [1]: ").strip() or "1"
        
        if choice == "1":
            return None  # Use defaults from file
        elif choice == "2":
            range_input = input("[?] Enter range (start-end, e.g., 80-443): ").strip()
            start, end = map(int, range_input.split('-'))
            return (start, end)
        elif choice == "3":
            return False  # Skip
        else:
            return None
    except:
        return None

def main():
    """Main function"""
    banner.show()
    
    # Get target
    try:
        target = input("[?] Enter target domain/IP: ").strip()
        if not target:
            print_error("No target provided")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
        sys.exit(0)
    
    # Resolve domain and IP
    domain, ip = resolve_domain(target)
    print(f"\n[+] Target: {domain} | IP: {ip or 'N/A'}\n")
    
    # Create shared sessionclea
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    # Core modules (always run)
    modules = [
        ("WHOIS Lookup", lambda: whois_lookup.run(domain)),
        ("DNS Enumeration", lambda: dns_enum.run(domain)),
        ("IP Geolocation", lambda: ip_geo.run(ip)),
        ("HTTP Headers", lambda: http_headers.run(domain, session)),
        ("SSL Certificate", lambda: ssl_cert.run(domain)),
         ("WAF Detection", lambda: waf_detect.run(domain, session)),
    ]
    
    # Port scan with user choice
    ports = get_port_choice()
    if ports is not False:
        modules.append(("Port Scanner", lambda: port_scanner.run(ip, ports)))
    
    # Ask for advanced modules
    print("\n[?] Run advanced modules? [y/N]: ", end="")
    try:
        if input().lower().startswith('y'):
            modules.extend([
                ("Subdomain Enum", lambda: subdomain_enum.run(domain)),
                ("Tech Detection", lambda: tech_detect.run(domain, session)),
                ("CVE Search", lambda: cve_search.run(domain, session)),
                ("Dir Bruteforce", lambda: dir_bruteforce.run(domain, session)),
                ("Email Harvest", lambda: email_harvest.run(domain)),
            ])
    except:
        pass
    
    # Run all modules
    for name, module in modules:
        try:
            print(f"\n{'='*60}")
            print(f"[*] Module: {name}")
            print(f"{'='*60}")
            module()
        except KeyboardInterrupt:
            print(f"\n[!] Interrupted by user")
            break
        except Exception as e:
            print_error(f"Module failed: {e}")
            continue
    
    print(f"\n{'='*60}")
    print("[+] Reconnaissance completed!")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()