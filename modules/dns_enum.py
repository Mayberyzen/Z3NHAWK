#!/usr/bin/env python3
"""DNS enumeration module"""

import dns.resolver
from tabulate import tabulate
from utils.helpers import print_info, print_error, print_warning

def run(domain):
    """Fetch DNS records"""
    print_info("Fetching DNS Records...")
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
    results = []
    
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                results.append([record, str(rdata)])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.Timeout:
            continue
        except Exception:
            continue
    
    if results:
        print(tabulate(results, headers=['Type', 'Value'], tablefmt='grid'))
    else:
        print_warning("No DNS records found")