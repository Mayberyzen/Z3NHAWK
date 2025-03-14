import whois
import requests
import socket
from dns import resolver
from ipwhois import IPWhois


def perform_ip_lookup(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"[INFO] Resolved {domain} to IP address: {ip_address}")
    except socket.gaierror:
        return {"error": f"Unable to resolve domain: {domain}"}

    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        response.raise_for_status()
        ip_info = response.json()
    except requests.RequestException as e:
        return {"error": f"Error fetching IP information: {e}"}
 
    ip_details = {
        "IP Address": ip_address,
        "Hostname": ip_info.get("hostname", "N/A"),
        "City": ip_info.get("city", "N/A"),
        "Region": ip_info.get("region", "N/A"),
        "Country": ip_info.get("country", "N/A"),
        "Location": ip_info.get("loc", "N/A"),
        "Organization": ip_info.get("org", "N/A"),
        "ASN": ip_info.get("asn", {}).get("asn", "N/A"),
        "ISP": ip_info.get("asn", {}).get("name", "N/A"),
    }

    return ip_details
def get_dns_records(domain):
    """Fetches A, MX, and TXT records for a domain."""
    records = {}
    try:
        records['A'] = [ip.address for ip in resolver.resolve(domain, 'A')]
        records['MX'] = [str(mx.exchange) for mx in resolver.resolve(domain, 'MX')]
        records['TXT'] = [txt.strings for txt in resolver.resolve(domain, 'TXT')]
    except Exception:
        return {"Error": "DNS lookup failed"}
    
    return records

def get_ip_info(ip):
    """Fetches IP WHOIS information."""
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        return {
            "IP Address": ip,
            "ASN": results.get("asn"),
            "Country": results.get("asn_country_code"),
            "ISP": results.get("asn_description"),
        }
    except Exception:
        return {"Error": "IP lookup failed"}
    
def enumerate_subdomains(domain):
    """Enumerate subdomains using crt.sh API and brute-force."""
    subdomains = set()
    subdomains.update(get_subdomains_from_crtsh(domain))
    subdomains.update(brute_force_subdomains(domain))

    return {"Subdomains": list(subdomains)}

def get_subdomains_from_crtsh(domain):
    """Fetch subdomains from crt.sh API."""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return set(entry['name_value'] for entry in response.json())
    except Exception:
        return set()
    return set()

def brute_force_subdomains(domain):
    """Brute-force subdomains using a wordlist."""
    subdomains = set()
    
    try:
        with open("subdomains.txt", "r") as file:
            wordlist = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        wordlist = ["www", "mail", "ftp", "api", "dev", "portal", "admin", "login", "test"]

    for sub in wordlist:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)  
            subdomains.add(full_domain)
        except socket.gaierror:
            continue

    return subdomains
