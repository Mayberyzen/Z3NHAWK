#!/usr/bin/env python3
import socket
import concurrent.futures
from tabulate import tabulate
from utils.helpers import print_info, print_error, print_warning, print_success

def load_top_ports(filepath='assets/top_ports.txt', default_count=20):
    """Load top ports from file or use defaults"""
    ports = []
    try:
        with open(filepath, 'r') as f:
            ports = [int(line.strip()) for line in f if line.strip().isdigit()]
        return ports[:default_count]
    except FileNotFoundError:
        print_warning(f"{filepath} not found, using defaults")
        # Fallback to hardcoded top 20 (only if file missing)
        return [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017, 5000]

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            
            # Try generic banner grab first
            try:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner[:60]
            except:
                pass
            
            # HTTP-specific probe
            if port in [80, 443, 8080, 8443, 8000, 8888]:
                s.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                for line in banner.split('\n'):
                    if 'Server:' in line:
                        return line.split(':', 1)[1].strip()[:60]
                return "HTTP Server"
                
    except:
        pass
    return ""

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except:
        pass
    return None

def scan_range(ip, start, end):
    print_info(f"Scanning port range {start}-{end} ({end-start+1} ports)...")
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(lambda p: scan_port(ip, p), range(start, end+1)))
    
    return [p for p in results if p]

def run(ip, ports=None):
    if not ip:
        print_error("No IP address provided")
        return
    
    # If ports is tuple (start, end), scan range
    if isinstance(ports, tuple) and len(ports) == 2:
        open_ports = scan_range(ip, ports[0], ports[1])
    else:
        # Use provided list or load from file
        if ports is None:
            ports = load_top_ports()
        
        print_info(f"Scanning {len(ports)} ports on {ip}...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(lambda p: scan_port(ip, p), ports))
        
        open_ports = [p for p in results if p]
    
    if not open_ports:
        print_warning("No open ports found")
        return
    
    # Grab banners for open ports
    print_info("Grabbing banners...")
    results = []
    for port in sorted(open_ports):
        banner = grab_banner(ip, port)
        try:
            service = socket.getservbyport(port)
        except:
            service = "unknown"
        results.append([port, service, banner[:40] if banner else "-"])
    
    print(tabulate(results, headers=['Port', 'Service', 'Banner'], tablefmt='grid'))
    print_success(f"Found {len(open_ports)} open ports")