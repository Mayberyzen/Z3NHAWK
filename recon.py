import whois
import requests
import socket
from dns import resolver
from ipwhois import IPWhois

def get_whois_info(domain):
    """Get WHOIS info with RDAP API fallback."""
    try:
        print(f"[*] Fetching WHOIS data for {domain}...")

        # Attempt WHOIS lookup
        w = whois.whois(domain)

        if w.registrar:  # If successful, return WHOIS data
            return {
                "Domain": domain,
                "Registrar": w.registrar,
                "Creation Date": w.creation_date,
                "Expiration Date": w.expiration_date,
                "Name Servers": w.name_servers,
            }

    except Exception:
        pass  # WHOIS failed, try RDAP API instead

    return get_whois_from_api(domain)  # Fallback

def get_whois_from_api(domain):
    """Fallback WHOIS lookup using RDAP API."""
    api_url = f"https://rdap.org/domain/{domain}"
    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            whois_data = response.json()
            return {
                "Domain": domain,
                "Registrar": whois_data.get("handle", "N/A"),
                "Creation Date": whois_data.get("events", [{}])[0].get("eventDate", "N/A"),
                "Expiration Date": whois_data.get("events", [{}])[1].get("eventDate", "N/A"),
                "Name Servers": whois_data.get("nameservers", "N/A"),
            }
    except Exception:
        return {"Error": "WHOIS data unavailable (Blocked or Protected)"}

# ----------------------------------------
# ✅ DNS RECORD LOOKUP
# ----------------------------------------

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

# ----------------------------------------
# ✅ IP WHOIS INFORMATION
# ----------------------------------------

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

# ----------------------------------------
# ✅ SUBDOMAIN ENUMERATION (Passive + Brute-Force)
# ----------------------------------------

def enumerate_subdomains(domain):
    """Enumerate subdomains using crt.sh API and brute-force."""
    subdomains = set()

    # Fetch subdomains from crt.sh API
    subdomains.update(get_subdomains_from_crtsh(domain))

    # Add brute-force subdomains
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
            socket.gethostbyname(full_domain)  # Check if subdomain resolves
            subdomains.add(full_domain)
        except socket.gaierror:
            continue

    return subdomains
