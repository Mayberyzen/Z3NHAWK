#!/usr/bin/env python3
"""HTTP headers analysis module - Truncated for readability"""

import requests
from tabulate import tabulate
from utils.helpers import print_info, print_error, print_warning
from utils.colors import Colors

def truncate(value, length=60):
    """Truncate long strings"""
    if not value:
        return "Not Set"
    if len(str(value)) > length:
        return str(value)[:length] + "..."
    return str(value)

def run(domain, session=None):
    """Analyze HTTP security headers"""
    print_info("Analyzing HTTP Headers...")
    
    if session is None:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    urls = [f"https://{domain}", f"http://{domain}"]
    
    for url in urls:
        try:
            resp = session.get(url, timeout=10, allow_redirects=True)
            headers = resp.headers
            
            # Security headers to check (truncated)
            security_headers = [
                ['Strict-Transport-Security', truncate(headers.get('Strict-Transport-Security'))],
                ['Content-Security-Policy', truncate(headers.get('Content-Security-Policy'))],
                ['X-Frame-Options', truncate(headers.get('X-Frame-Options'))],
                ['X-Content-Type-Options', truncate(headers.get('X-Content-Type-Options'))],
                ['Referrer-Policy', truncate(headers.get('Referrer-Policy'))],
                ['Permissions-Policy', truncate(headers.get('Permissions-Policy'))],
                ['Server', truncate(headers.get('Server'))],
                ['X-Powered-By', truncate(headers.get('X-Powered-By'))]
            ]
            
            print(f"\n{Colors.OKBLUE}[+] URL: {resp.url} (Status: {resp.status_code}){Colors.ENDC}")
            print(tabulate(security_headers, headers=['Header', 'Value'], tablefmt='simple'))
            
            # Check for missing security headers
            missing = [row[0] for row in security_headers if row[1] == "Not Set" 
                      and row[0] not in ['Server', 'X-Powered-By']]
            if missing:
                print_warning(f"Missing: {', '.join(missing)}")
            
            return headers
            
        except requests.exceptions.SSLError:
            continue
        except Exception as e:
            print_error(f"Error fetching {url}: {e}")
            continue
    
    return None