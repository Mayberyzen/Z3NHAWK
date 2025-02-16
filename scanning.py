
# scanning.py - Multi-threaded Port Scanning and Service Detection
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
        sock.settimeout(0.3)  # Reduced timeout for faster scanning
        if sock.connect_ex((target, port)) == 0:
            with lock:
                open_ports.append(port)
        sock.close()
    
    for port in port_list:
        while threading.active_count() > thread_count:
            pass  # Limit active threads to avoid overload
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return open_ports if open_ports else None
def detect_services(target, open_ports):
    """Detects services running on open ports."""
    service_dict = {}
    
    for port in open_ports:
        try:
            service_name = socket.getservbyport(port)
        except OSError:
            service_name = "Unknown"
        service_dict[port] = service_name
    
    return service_dict


