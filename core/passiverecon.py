import socket
import whois
import shodan
from colorama import Fore, Style
import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

def get_whois_info(hostname):
    try:
        domain_info = whois.whois(hostname)
        return {
            "Registrar": domain_info.registrar or "Unknown",
            "Creation Date": str(domain_info.creation_date) if domain_info.creation_date else "Unknown",
            "Expiration Date": str(domain_info.expiration_date) if domain_info.expiration_date else "Unknown"
        }
    except Exception as e:
        print(Fore.RED + f"WHOIS lookup failed: {e}" + Style.RESET_ALL)
        return {"Error": str(e)}

def get_shodan_info(ip):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        data = api.host(ip)
        return {
            "ISP": data.get("isp", "Unknown"),
            "Organization": data.get("org", "Unknown"),
            "OS": data.get("os", "Unknown"),
            "Ports": data.get("ports", [])
        }
    except shodan.APIError as e:
        print(Fore.RED + f"Shodan API error: {e}" + Style.RESET_ALL)
        return {
            "ISP": "Unknown",
            "Organization": "Unknown",
            "OS": "Unknown",
            "Ports": []
        }