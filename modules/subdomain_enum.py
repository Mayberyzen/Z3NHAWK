#!/usr/bin/env python3
"""Subdomain Enumeration - External Wordlist"""

import socket
import requests
import concurrent.futures
import dns.resolver
from tabulate import tabulate
from utils.helpers import print_info, print_error, print_warning, print_success

def load_wordlist(filepath='assets/subdomains.txt'):
    """Load subdomain wordlist from file"""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print_warning(f"{filepath} not found, using minimal defaults")
        # Minimal fallback
        return ['www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop', 'test', 'dev', 'vpn']

def check_subdomain(sub, domain):
    """DNS resolution check"""
    full = f"{sub}.{domain}"
    try:
        answers = dns.resolver.resolve(full, 'A')
        ips = [str(rdata) for rdata in answers]
        return [full, ips[0]]
    except:
        return None

def passive_crtsh(domain):
    """Passive: Certificate Transparency (no auth required)"""
    found = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get('name_value', '').lower().strip()
                if name and '*' not in name and '@' not in name:
                    found.update(name.split('\n'))
    except Exception as e:
        print_error(f"crt.sh error: {e}")
    return found

def run(domain, wordlist_path='assets/subdomains.txt'):
    """Run subdomain enumeration"""
    print_info("Starting subdomain enumeration...")
    
    all_subs = set()
    
    # Passive sources (always run)
    print_info("Phase 1: Passive sources...")
    crtsh_results = passive_crtsh(domain)
    all_subs.update(crtsh_results)
    print_success(f"crt.sh found: {len(crtsh_results)}")
    
    # Active brute force with external wordlist
    wordlist = load_wordlist(wordlist_path)
    print_info(f"Phase 2: Brute forcing with {len(wordlist)} subdomains...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_subdomain, sub, domain) for sub in wordlist]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                all_subs.add(result[0])
    
    # Display results
    if all_subs:
        sorted_subs = sorted(all_subs)
        table = [[i+1, sub] for i, sub in enumerate(sorted_subs[:50])]  # Show top 50
        print(tabulate(table, headers=['#', 'Subdomain'], tablefmt='grid'))
        
        if len(sorted_subs) > 50:
            print_info(f"... and {len(sorted_subs)-50} more")
        
        print_success(f"Total unique subdomains: {len(sorted_subs)}")
        
        # Save results
        filename = f"{domain}_subdomains.txt"
        with open(filename, 'w') as f:
            f.write('\n'.join(sorted_subs))
        print_success(f"Saved to {filename}")
    else:
        print_warning("No subdomains found")