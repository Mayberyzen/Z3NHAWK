import socket
import threading

def scan_ports(target, port_list=None, thread_count=50):
    """Multi-threaded port scanner with optimized speed."""
    open_ports = []
    threads = []
    lock = threading.Lock()
    
    if port_list is None:
        port_list = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080, 8443]  # Common ports
    
    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3) 
        if sock.connect_ex((target, port)) == 0:
            with lock:
                open_ports.append(port)
        sock.close()
    
    for port in port_list:
        while threading.active_count() > thread_count:
            pass  
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return open_ports if open_ports else None

def detect_services(target, open_ports):
    """Detects services and attempts to grab banners for version detection."""
    service_dict = {}
    
    for port in open_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
        except (socket.timeout, ConnectionRefusedError, UnicodeDecodeError):
            banner = "Unknown Version"
        
        try:
            service_name = socket.getservbyport(port)
        except OSError:
            service_name = "Unknown"
        
        service_dict[port] = f"{service_name} - {banner}" if banner != "Unknown Version" else service_name
    
    return service_dict
