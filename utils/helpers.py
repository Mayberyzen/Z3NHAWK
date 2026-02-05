#!/usr/bin/env python3
"""Helper functions used across modules"""

import socket
from urllib.parse import urlparse
from .colors import Colors

def print_error(msg):
    """Print formatted error message"""
    print(f"{Colors.FAIL}[-] {msg}{Colors.ENDC}")

def print_success(msg):
    """Print formatted success message"""
    print(f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}")

def print_warning(msg):
    """Print formatted warning message"""
    print(f"{Colors.WARNING}[!] {msg}{Colors.ENDC}")

def print_info(msg):
    """Print formatted info message"""
    print(f"{Colors.OKBLUE}[*] {msg}{Colors.ENDC}")

def resolve_domain(target):
    """Extract domain and resolve IP"""
    if target.startswith(('http://', 'https://')):
        domain = urlparse(target).netloc
    else:
        domain = target
    
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        ip = None
    
    return domain, ip