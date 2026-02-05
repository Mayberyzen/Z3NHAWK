#!/usr/bin/env python3
"""Technology Detection & CVE Mapping"""

import requests
import re
from tabulate import tabulate
from utils.helpers import print_info, print_error, print_success, print_warning

# Technology fingerprints
TECH_SIGNATURES = {
    'WordPress': {'headers': ['X-Powered-By: PHP', 'wp-content'], 'meta': ['WordPress']},
    'Drupal': {'headers': ['Drupal', 'X-Generator: Drupal'], 'meta': ['Drupal']},
    'Joomla': {'headers': ['Joomla'], 'meta': ['Joomla']},
    'Magento': {'headers': ['Magento'], 'meta': ['Magento']},
    'Shopify': {'headers': ['Shopify'], 'meta': ['Shopify']},
    'React': {'headers': [], 'meta': [], 'js': ['react', 'reactjs']},
    'Angular': {'headers': [], 'meta': [], 'js': ['angular']},
    'Vue.js': {'headers': [], 'meta': [], 'js': ['vue', 'vuejs']},
    'jQuery': {'headers': [], 'meta': [], 'js': ['jquery']},
    'Bootstrap': {'headers': [], 'meta': [], 'css': ['bootstrap']},
    'Apache': {'headers': ['Apache'], 'meta': []},
    'Nginx': {'headers': ['nginx'], 'meta': []},
    'IIS': {'headers': ['Microsoft-IIS'], 'meta': []},
    'Cloudflare': {'headers': ['cloudflare'], 'meta': []},
    'AWS': {'headers': ['aws', 'amazonaws'], 'meta': []},
    'PHP': {'headers': ['PHP', 'X-Powered-By: PHP'], 'meta': []},
    'ASP.NET': {'headers': ['ASP.NET', 'X-AspNet-Version'], 'meta': []},
    'Django': {'headers': ['WSGIServer', 'Python'], 'meta': []},
    'Ruby on Rails': {'headers': ['Ruby', 'Rails'], 'meta': []},
    'Express.js': {'headers': ['Express'], 'meta': []},
}

def detect_tech(url, session):
    """Detect technologies used"""
    detected = []
    
    try:
        resp = session.get(url, timeout=10)
        headers = str(resp.headers).lower()
        content = resp.text.lower()
        
        for tech, sigs in TECH_SIGNATURES.items():
            # Check headers
            for header in sigs.get('headers', []):
                if header.lower() in headers:
                    detected.append([tech, 'HTTP Header', header])
                    break
            
            # Check meta tags
            for meta in sigs.get('meta', []):
                if meta.lower() in content:
                    detected.append([tech, 'HTML Content', meta])
                    break
            
            # Check JS files
            js_files = re.findall(r'src=["\'](.*?\.js)["\']', resp.text)
            for js in js_files:
                if any(s in js.lower() for s in sigs.get('js', [])):
                    detected.append([tech, 'JavaScript', js])
                    break
    
    except Exception as e:
        print_error(f"Detection error: {e}")
    
    return detected

def search_cves(tech_name, version=None):
    """Search CVEs for detected technology"""
    cves = []
    
    # Use circl.lu API (free, no auth)
    try:
        query = tech_name
        if version:
            query += f" {version}"
        
        url = f"https://cve.circl.lu/api/search/{query.replace(' ', '/')}"
        resp = requests.get(url, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            for item in data[:5]:  # Top 5 CVEs
                cves.append([
                    item.get('id', 'N/A'),
                    item.get('summary', 'N/A')[:80] + '...',
                    item.get('cvss', 'N/A')
                ])
    except:
        pass
    
    return cves

def run(domain, session=None):
    """Run technology detection"""
    print_info("Detecting technologies...")
    
    if session is None:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    urls = [f"https://{domain}", f"http://{domain}"]
    all_tech = []
    
    for url in urls:
        try:
            tech = detect_tech(url, session)
            all_tech.extend(tech)
        except:
            continue
    
    if all_tech:
        print(tabulate(all_tech, headers=['Technology', 'Detection Method', 'Evidence'], tablefmt='grid'))
        
        # CVE lookup for detected tech
        print_info("Searching for related CVEs...")
        unique_tech = list(set([t[0] for t in all_tech]))
        
        for tech in unique_tech[:3]:  # Check top 3 technologies
            cves = search_cves(tech)
            if cves:
                print_warning(f"Found CVEs for {tech}:")
                print(tabulate(cves, headers=['CVE ID', 'Summary', 'CVSS'], tablefmt='grid'))
            else:
                print_info(f"No recent CVEs found for {tech}")
    else:
        print_warning("No technologies detected")