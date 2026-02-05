#!/usr/bin/env python3
"""Directory Bruteforcer - External Wordlist"""

import requests
import concurrent.futures
from tabulate import tabulate
from utils.helpers import print_info, print_error, print_warning, print_success

def load_wordlist(filepath='assets/directories.txt'):
    """Load directory wordlist from file"""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print_warning(f"{filepath} not found, using minimal defaults")
        return ['admin', 'login', 'api', 'backup', 'config', 'test', 'dev', 'robots.txt']

def check_path(base_url, path):
    """Check if path exists"""
    url = f"{base_url}/{path}"
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        # Interesting status codes
        if resp.status_code in [200, 201, 204, 301, 302, 401, 403, 405, 500]:
            size = len(resp.content)
            return [url, resp.status_code, size]
    except:
        pass
    return None

def run(domain, session=None, wordlist_path='assets/directories.txt'):
    """Run directory bruteforce"""
    print_info("Starting directory bruteforce...")
    
    if session is None:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    wordlist = load_wordlist(wordlist_path)
    found = []
    urls = [f"https://{domain}", f"http://{domain}"]
    
    for base in urls:
        print_info(f"Scanning {base} with {len(wordlist)} paths...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(check_path, base, path) for path in wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
    
    if found:
        # Remove duplicates, sort by status
        seen = set()
        unique = []
        for item in found:
            if item[0] not in seen:
                seen.add(item[0])
                unique.append(item)
        
        unique.sort(key=lambda x: x[1])
        print(tabulate(unique, headers=['URL', 'Status', 'Size'], tablefmt='grid'))
        print_success(f"Found {len(unique)} interesting paths")
        
        # Highlight sensitive
        sensitive = ['admin', 'config', 'backup', '.env', '.git', 'phpmyadmin']
        critical = [u for u in unique if any(s in u[0].lower() for s in sensitive)]
        if critical:
            print_warning("Potentially sensitive paths detected!")
    else:
        print_warning("No interesting paths found")