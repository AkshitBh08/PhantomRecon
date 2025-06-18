import requests
from colorama import Fore, Style
import socket

def get_ip_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        response.raise_for_status()  # Raise an error for bad status codes
        data = response.json()
        city = data.get('city', 'Unknown')
        region = data.get('region', 'Unknown')
        country = data.get('country', 'Unknown')
        return f"{city}, {region}, {country}"
    except requests.RequestException as e:
        print(Fore.RED + f"Error fetching IP location: {e}" + Style.RESET_ALL)
        return "Unknown"

def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(Fore.RED + f"Unable to resolve domain {domain}" + Style.RESET_ALL)
        return None