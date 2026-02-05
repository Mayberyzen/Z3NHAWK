#!/usr/bin/env python3
"""WHOIS lookup module"""

import whois
from tabulate import tabulate
from utils.colors import Colors
from utils.helpers import print_info, print_error

def run(domain):
    """Perform WHOIS lookup"""
    print_info("Performing WHOIS Lookup...")
    
    try:
        w = whois.whois(domain)
        
        # Handle different data types (string or list)
        def clean_value(val):
            if isinstance(val, list):
                return ', '.join(str(x) for x in val[:3])
            return str(val) if val else 'N/A'
        
        data = [
            ['Domain', clean_value(w.domain_name)],
            ['Registrar', clean_value(w.registrar)],
            ['Creation Date', clean_value(w.creation_date)],
            ['Expiration Date', clean_value(w.expiration_date)],
            ['Name Servers', clean_value(w.name_servers)],
            ['Status', clean_value(w.status)],
            ['Emails', clean_value(w.emails)]
        ]
        
        # Remove empty rows
        data = [row for row in data if row[1] != 'N/A']
        
        print(tabulate(data, headers=['Property', 'Value'], tablefmt='grid'))
        
    except whois.parser.PywhoisError as e:
        print_error(f"WHOIS lookup failed: {e}")
    except Exception as e:
        print_error(f"WHOIS Error: {e}")