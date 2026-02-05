#!/usr/bin/env python3
"""IP geolocation and ASN lookup module"""

import requests
from ipwhois import IPWhois
from tabulate import tabulate
from utils.helpers import print_info, print_error

def run(ip):
    """Get IP geolocation and ASN information"""
    if not ip:
        print_error("Cannot get geolocation without IP")
        return
    
    print_info("IP Geolocation & ASN Info...")
    
    data = {'IP Address': ip}
    
    # ASN lookup via IPWhois
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        data.update({
            'ASN': result.get('asn', 'N/A'),
            'ASN Description': result.get('asn_description', 'N/A'),
            'Country': result.get('asn_country_code', 'N/A'),
            'Network': result.get('network', {}).get('cidr', 'N/A')
        })
    except Exception as e:
        data['ASN Error'] = str(e)
    
    # Geolocation via ip-api.com (free, no auth)
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        geo = resp.json()
        if geo.get('status') == 'success':
            data.update({
                'City': geo.get('city', 'N/A'),
                'Region': geo.get('regionName', 'N/A'),
                'ISP': geo.get('isp', 'N/A'),
                'Organization': geo.get('org', 'N/A'),
                'Coordinates': f"{geo.get('lat')}, {geo.get('lon')}"
            })
    except Exception:
        pass
    
    table = [[k, v] for k, v in data.items()]
    print(tabulate(table, headers=['Property', 'Value'], tablefmt='grid'))