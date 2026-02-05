#!/usr/bin/env python3
"""Technology Detection Module"""

import requests
import re
from tabulate import tabulate
from utils.helpers import print_info, print_error, print_warning

def run(domain, session=None):
    """Detect technologies from HTTP headers and content"""
    print_info("Detecting technologies...")
    
    if session is None:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    detected = []
    
    urls = [f"https://{domain}", f"http://{domain}"]
    
    for url in urls:
        try:
            resp = session.get(url, timeout=10)
            headers = resp.headers
            
            # Check headers
            tech_headers = {
                'Server': headers.get('Server'),
                'X-Powered-By': headers.get('X-Powered-By'),
                'X-AspNet-Version': headers.get('X-AspNet-Version'),
                'X-Generator': headers.get('X-Generator'),
                'Via': headers.get('Via')
            }
            
            for header, value in tech_headers.items():
                if value:
                    detected.append([header, value])
            
            # Check for CMS in content
            content = resp.text.lower()
            cms_patterns = {
                'WordPress': 'wp-content' in content or 'wordpress' in content,
                'Drupal': 'drupal' in content,
                'Joomla': 'joomla' in content,
                'Magento': 'magento' in content,
                'Shopify': 'shopify' in content,
                'React': 'react' in content,
                'Angular': 'angular' in content,
                'Vue.js': 'vue' in content
            }
            
            for cms, found in cms_patterns.items():
                if found:
                    detected.append(['CMS/Framework', cms])
            
            # Only need first successful response
            break
            
        except Exception as e:
            continue
    
    if detected:
        # Remove duplicates
        seen = set()
        unique = []
        for item in detected:
            key = f"{item[0]}:{item[1]}"
            if key not in seen:
                seen.add(key)
                unique.append(item)
        
        print(tabulate(unique, headers=['Source', 'Technology'], tablefmt='grid'))
        print(f"[+] Found {len(unique)} technologies")
    else:
        print_warning("No technologies detected")