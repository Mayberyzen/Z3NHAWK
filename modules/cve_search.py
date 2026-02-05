#!/usr/bin/env python3
"""CVE Search Module - Automatic vulnerability lookup"""

import requests
import re
from tabulate import tabulate
from utils.helpers import print_info, print_error, print_warning, print_success

def extract_version(string):
    """Try to extract version number from string"""
    match = re.search(r'(\d+\.\d+(\.\d+)?)', string)
    if match:
        return match.group(1)
    return None

def search_circl_lu(tech, version=None):
    """Search CVEs using CIRCL.lu API (free, no auth)"""
    cves = []
    try:
        query = tech.split('/')[0].lower()  # Clean tech name (remove version)
        if version:
            query += f"/{version}"
        
        url = f"https://cve.circl.lu/api/search/{query}"
        print_info(f"Querying CIRCL.lu: {url}")
        
        resp = requests.get(url, timeout=10)
        print_info(f"Response status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            print_info(f"Found {len(data)} results from CIRCL.lu")
            
            for item in data[:10]:
                cves.append([
                    item.get('id', 'N/A'),
                    item.get('summary', 'N/A')[:70] + '...' if len(item.get('summary', '')) > 70 else item.get('summary', 'N/A'),
                    item.get('cvss', 'N/A') or 'N/A'
                ])
        else:
            print_warning(f"CIRCL.lu returned status {resp.status_code}")
            
    except Exception as e:
        print_error(f"CIRCL.lu error: {e}")
    
    return cves

def search_nvd(tech):
    """Search CVEs using NVD API (free, no auth required)"""
    cves = []
    try:
        # Clean tech name for search
        keyword = tech.split('/')[0]
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=10"
        print_info(f"Querying NVD API...")
        
        resp = requests.get(url, timeout=15)
        print_info(f"NVD Response status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            vulnerabilities = data.get('vulnerabilities', [])
            print_info(f"Found {len(vulnerabilities)} results from NVD")
            
            for item in vulnerabilities:
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'N/A')
                
                # Get description
                descriptions = cve.get('descriptions', [])
                desc = 'N/A'
                for d in descriptions:
                    if d.get('lang') == 'en':
                        desc = d.get('value', 'N/A')[:70]
                        break
                
                # Get CVSS score
                score = 'N/A'
                metrics = cve.get('metrics', {})
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 'N/A')
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    score = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 'N/A')
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 'N/A')
                
                cves.append([cve_id, desc + '...' if len(desc) > 70 else desc, score])
        else:
            print_warning(f"NVD returned status {resp.status_code}")
            
    except Exception as e:
        print_error(f"NVD error: {e}")
    
    return cves

def run(domain, session=None):
    """Run CVE search based on detected technologies"""
    print_info("CVE Lookup...")
    
    if session is None:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    # Detect technologies from headers
    techs = []
    try:
        # Try HTTPS first
        try:
            resp = session.get(f"https://{domain}", timeout=5)
            print_info("Connected via HTTPS")
        except:
            resp = session.get(f"http://{domain}", timeout=5)
            print_info("Connected via HTTP")
        
        server = resp.headers.get('Server', '')
        powered = resp.headers.get('X-Powered-By', '')
        
        if server:
            techs.append(server)
            print_info(f"Detected Server: {server}")
        if powered:
            techs.append(powered)
            print_info(f"Detected Platform: {powered}")
            
        if not techs:
            print_warning("No Server/X-Powered-By headers found")
            # Try to detect from body
            if 'wordpress' in resp.text.lower():
                techs.append('WordPress')
                print_info("Detected WordPress from body content")
            elif 'drupal' in resp.text.lower():
                techs.append('Drupal')
                print_info("Detected Drupal from body content")
            
    except Exception as e:
        print_error(f"Detection error: {e}")
        return
    
    if not techs:
        print_warning("No technologies detected for CVE lookup")
        return
    
    # Search CVEs for each tech
    all_cves = []
    for tech in techs:
        print_info(f"\nSearching CVEs for: {tech}")
        
        # Try to extract version for better results
        version = extract_version(tech)
        if version:
            print_info(f"Extracted version: {version}")
        
        # Search CIRCL.lu first (faster)
        cves = search_circl_lu(tech, version)
        
        # If no results, try NVD
        if not cves:
            print_info("No results from CIRCL.lu, trying NVD...")
            cves = search_nvd(tech)
        
        if cves:
            all_cves.extend([[tech] + cve for cve in cves])
        else:
            print_warning(f"No CVEs found for {tech}")
    
    # Display results
    if all_cves:
        print(f"\n[+] Found {len(all_cves)} CVEs:")
        print(tabulate(all_cves, headers=['Technology', 'CVE ID', 'Description', 'CVSS'], tablefmt='grid'))
        
        # Highlight critical (CVSS >= 7.0)
        critical = []
        for c in all_cves:
            try:
                score = float(c[3])
                if score >= 7.0:
                    critical.append(c)
            except:
                pass
        
        if critical:
            print(f"\n[!] HIGH SEVERITY CVEs DETECTED ({len(critical)}):")
            for c in critical:
                print(f"    ! {c[1]} - CVSS: {c[3]}")
    else:
        print_warning("No CVEs found for any detected technologies")
        print_info("You can manually search at:")
        for tech in techs:
            clean_tech = tech.split('/')[0]
            print(f"    - https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&query={clean_tech}")