import socket  # For network connections and resolving domains to IPs
import requests  # For making HTTP requests to fetch headers
import whois  # For fetching WHOIS domain information
import ssl  # For retrieving SSL certificate details
from dns import resolver  # For retrieving DNS records
from ipwhois import IPWhois  # For fetching IP geolocation and ASN details
from urllib.parse import urlparse  # For parsing URLs
from rich.console import Console  # For styled console output
from rich.table import Table  # For formatted tables
from rich.panel import Panel  # For boxed panels
from rich import print as rprint  # For styled console printing

# Initialize console for rich output
console = Console()

def get_whois_info(domain):
    """Fetch WHOIS information for a domain."""
    try:
        w = whois.whois(domain)
        return {
            "Domain": domain,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiry Date": w.expiration_date
        }
    except Exception:
        return None

def get_dns_records(domain):
    """Retrieve DNS records for a domain."""
    records = {}
    try:
        records['A'] = [ip.address for ip in resolver.resolve(domain, 'A')]  # Get A records (IP addresses)
        records['MX'] = [str(mx.exchange) for mx in resolver.resolve(domain, 'MX')]  # Get Mail Exchange records
        records['TXT'] = [txt.strings for txt in resolver.resolve(domain, 'TXT')]  # Get TXT records
    except Exception:
        return None
    return records

def get_ip_info(ip):
    """Fetch IP geolocation and ASN (Autonomous System Number) information."""
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()  # Perform RDAP lookup for detailed IP info
        return {
            "IP Address": ip,
            "ASN": results.get("asn"),  # ASN Number
            "Country": results.get("asn_country_code"),  # Country associated with ASN
            "ISP": results.get("asn_description")  # ISP or organization using the IP
        }
    except Exception:
        return None

def get_http_headers(url):
    """Retrieve HTTP headers of a given URL."""
    try:
        response = requests.get(url, timeout=5)  # Fetch HTTP headers with a timeout of 5 seconds
        return dict(response.headers)  # Convert headers to dictionary format
    except Exception:
        return None

def get_ssl_info(hostname):
    """Fetch SSL/TLS certificate details."""
    try:
        ctx = ssl.create_default_context()  # Create an SSL context
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)  # Wrap socket with SSL
        conn.connect((hostname, 443))  # Connect to the host on port 443 (HTTPS)
        cert = conn.getpeercert()  # Retrieve SSL certificate
        return {
            "Issuer": cert.get("issuer"),  # Certificate issuer details
            "Valid From": cert.get("notBefore"),  # Certificate start date
            "Valid Until": cert.get("notAfter")  # Certificate expiry date
        }
    except Exception:
        return None

def scan_ports(target):
    """Scan all ports (1-65535) on a given IP or domain."""
    open_ports = []
    for port in range(1, 65536):  # Scan all ports from 1 to 65535
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
        sock.settimeout(0.5)  # Set timeout to 0.5 seconds for faster scanning
        if sock.connect_ex((target, port)) == 0:  # Check if the port is open
            open_ports.append(port)
        sock.close()
    return open_ports if open_ports else None

def display_results(title, data):
    """Helper function to display results in a formatted table."""
    if data:
        table = Table(title=title, show_header=True, header_style="bold cyan")
        table.add_column("Key", style="bold green")
        table.add_column("Value", style="bold white")
        for key, value in data.items():
            table.add_row(str(key), str(value))  # Add each key-value pair to the table
        console.print(table)
    else:
        rprint(f"[bold red]{title}: Not Available[/bold red]")

def main():
    """Main function to execute the tool."""
    console.print(Panel(f"[bold cyan]Z3NHAWK by Ryzen - Information Gathering Tool[/bold cyan]", style="bold white"))
    target = input("Enter the target IP or URL: ")  # Get user input for target
    parsed_url = urlparse(target)  # Parse the input to extract domain if needed
    domain = parsed_url.netloc if parsed_url.netloc else target  # Handle both URL and direct domain input
    
    try:
        ip = socket.gethostbyname(domain)  # Resolve domain to IP
    except socket.gaierror:
        console.print(f"[bold red]Error: Could not resolve {domain}[/bold red]")
        return
    
    display_results("WHOIS Information", get_whois_info(domain))
    display_results("DNS Records", get_dns_records(domain))
    display_results("IP  Info", get_ip_info(ip))
    display_results("HTTP Headers", get_http_headers(target))
    display_results("SSL/TLS Certificate Details", get_ssl_info(domain))
    
    ports = scan_ports(ip)
    if ports:
        console.print(Panel(f"[bold green]Open Ports:[/bold green] {', '.join(map(str, ports))}", style="bold white"))
    else:
        rprint("[bold red]Open Ports: Not Available[/bold red]")

if __name__ == "__main__":
    main()
