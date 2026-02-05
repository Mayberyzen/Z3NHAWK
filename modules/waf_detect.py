#!/usr/bin/env python3
"""WAF (Web Application Firewall) Detector"""

import requests
from tabulate import tabulate
from utils.helpers import print_info, print_error, print_success, print_warning

# WAF signatures (headers, cookies, response patterns)
WAF_SIGNATURES = {
    'Cloudflare': ['CF-RAY', 'cloudflare', '__cfduid', 'cf-ray'],
    'AWS WAF': ['X-AMZ-CF-ID', 'awsalb', 'awselb'],
    'Akamai': ['AkamaiGHost', 'X-Akamai', 'akamai'],
    'Incapsula': ['X-Iinfo', 'incap_ses', 'visid_incap'],
    'Sucuri': ['X-Sucuri', 'sucuri'],
    'ModSecurity': ['mod_security', 'Mod_Security', 'NOYB'],
    'F5 BIG-IP': ['X-WA-Info', 'F5', 'BIG-IP'],
    'Fortinet': ['FGT_', 'FortiGate'],
    'Barracuda': ['barra'],
    'Citrix': ['Citrix NetScaler', 'ns_af'],
    'Wordfence': ['wordfence'],
    'Cloudfront': ['X-Cache: Error from cloudfront'],
}

def run(domain, session=None):
    """Detect WAF"""
    print_info("Detecting Web Application Firewall...")
    
    if session is None:
        session = requests.Session()
    
    detected = []
    
    try:
        # Trigger potential WAF by sending suspicious request
        test_urls = [
            f"http://{domain}/?id=1' OR '1'='1",  # SQL injection test
            f"http://{domain}/?cmd=cat+/etc/passwd",  # Command injection
            f"http://{domain}/<script>alert(1)</script>",  # XSS
        ]
        
        headers_list = [
            {'User-Agent': 'Mozilla/5.0'},
            {'User-Agent': 'sqlmap/1.0'},  # Attack tool signature
        ]
        
        for test_url in test_urls:
            for headers in headers_list:
                try:
                    resp = session.get(test_url, headers=headers, timeout=5, allow_redirects=False)
                    
                    resp_headers = str(resp.headers).lower()
                    resp_text = resp.text.lower()
                    cookies = str(resp.cookies).lower()
                    
                    for waf_name, signatures in WAF_SIGNATURES.items():
                        for sig in signatures:
                            if sig.lower() in resp_headers or sig.lower() in resp_text or sig.lower() in cookies:
                                if waf_name not in [d[0] for d in detected]:
                                    detected.append([waf_name, sig, resp.status_code])
                                    break
                    
                    # Check for generic block page indicators
                    if resp.status_code in [403, 406, 429, 501, 502]:
                        block_indicators = ['blocked', 'firewall', 'security', 'access denied', 'forbidden']
                        if any(ind in resp_text for ind in block_indicators):
                            if 'Generic/Unknown' not in [d[0] for d in detected]:
                                detected.append(['Generic/Unknown WAF', 'Block page detected', resp.status_code])
                    
                except:
                    continue
        
        if detected:
            print(tabulate(detected, headers=['WAF', 'Signature', 'Status'], tablefmt='simple'))
            print_success(f"Detected {len(detected)} WAF/protection layer(s)")
        else:
            print_info("No WAF detected (or WAF is silent)")
            
    except Exception as e:
        print_error(f"WAF detection error: {e}")