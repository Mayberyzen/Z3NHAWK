#!/usr/bin/env python3
"""SSL/TLS certificate analysis module"""

import socket
import ssl
from datetime import datetime
from tabulate import tabulate
from utils.helpers import print_info, print_error
from utils.colors import Colors

def truncate(value, length=50):
    """Truncate long strings"""
    if not value:
        return "N/A"
    if len(str(value)) > length:
        return str(value)[:length] + "..."
    return str(value)

def run(domain):
    """Analyze SSL certificate"""
    print_info("SSL/TLS Certificate Analysis...")
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Parse dates
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.utcnow()).days
                
                data = [
                    ['Subject', truncate(str(cert.get('subject')))],
                    ['Issuer', truncate(str(cert.get('issuer')))],
                    ['Version', version],
                    ['Cipher Suite', truncate(cipher[0])],
                    ['Key Size', f"{cipher[2]} bits"],
                    ['Not Before', str(not_before)],
                    ['Not After', str(not_after)],
                    ['Days Left', days_left],
                    ['Serial', truncate(cert.get('serialNumber'))]
                ]
                
                if days_left < 30:
                    data.append(['Status', f"{Colors.FAIL}EXPIRING SOON{Colors.ENDC}"])
                else:
                    data.append(['Status', f"{Colors.OKGREEN}Valid{Colors.ENDC}"])
                
                print(tabulate(data, headers=['Property', 'Value'], tablefmt='simple'))
                
    except ssl.SSLError as e:
        print_error(f"SSL Error: {e}")
    except socket.timeout:
        print_error("Connection timed out")
    except Exception as e:
        print_error(f"Certificate analysis failed: {e}")