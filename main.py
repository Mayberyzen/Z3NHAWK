from recon import perform_ip_lookup, get_dns_records, get_ip_info, enumerate_subdomains
from scanning import scan_ports, detect_services
from vulnerability import check_vulnerabilities
from report import display_results
import socket
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from pyfiglet import Figlet
import random

banner_fonts = [
    'graffiti', 'slant', 'doom', 'big', 'standard', 'block', 'starwars', 'larry3d', 'bubble',
    'lean', 'isometric1', 'isometric3', 'isometric4', 'caligraphy', 'colossal', 'smkeyboard',
    'shadow', 'univers', 'rectangles', 'bell'
]

random_font = random.choice(banner_fonts)
custom_fig = Figlet(font=random_font)
print(custom_fig.renderText('RYZEN'))
console = Console()

def main():
    """Main function to execute Z3nHawk 2.0 ."""
    console.print(Panel("[bold cyan]Z3NHAWK 2.0 by Ryzen - Automated Recon & Pentest Tool[/bold cyan]", style="bold white"))

    target = input("Enter the target IP or URL: ").strip()
    parsed_url = urlparse(target)
    domain = parsed_url.netloc if parsed_url.netloc else target

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        console.print(f"[bold red]Error: Could not resolve {domain}[/bold red]")
        return

   
    results = {}
    results["WHOIS Information"] = perform_ip_lookup(domain)
    results["DNS Records"] = get_dns_records(domain)
    results["IP Information"] = get_ip_info(ip)
    results["Subdomain Enumeration"] = enumerate_subdomains(domain)

    
    open_ports = scan_ports(ip)
    if open_ports:
        console.print(Panel(f"[bold green]Open Ports:[/bold green] {', '.join(map(str, open_ports))}", style="bold white"))
        services = detect_services(ip, open_ports)
        results["Service Detection"] = services

        
        vulnerabilities = check_vulnerabilities(services)
        results["Vulnerability Scan (CVE Lookup)"] = vulnerabilities
    else:
        console.print("[bold red]No open ports found[/bold red]")

   
    for section, data in results.items():
        display_results(section, data)

if __name__ == "__main__":
    main()
