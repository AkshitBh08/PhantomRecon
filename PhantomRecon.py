import os
import re
import json
import csv
import requests
import shodan
import nmap
import whois
import socket
import time
from colorama import Fore, Style
import sys

# 🔹 Configure Shodan API Key
SHODAN_API_KEY = "your_shodan_api_key"
EXPLOIT_DB_API = "https://www.exploit-db.com/search?cve="  # 🔹 Exploit-DB URL

# 🔹 Function to check if the script is running as root
def check_root():
    if os.geteuid() != 0:
        print(Fore.RED + "Error: This script must be run as root!" + Style.RESET_ALL)
        sys.exit(1)

# 🔹 Function to get geolocation of IP
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

# 🔹 Function to resolve domain name to IP address
def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(Fore.RED + f"Unable to resolve domain {domain}" + Style.RESET_ALL)
        return None

# 🔹 Function to get WHOIS information
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

# 🔹 Function to get Shodan data
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

def scan_with_nmap(target, scan_type, port_range, vuln_scan=False):
    nm = nmap.PortScanner()
    try:
        print(Fore.YELLOW + f"Running Nmap scan: {scan_type} on {target}..." + Style.RESET_ALL)

        # Add vulnerability scanning if enabled
        if vuln_scan:
            scan_type += " --script vuln"

        nm.scan(target, port_range, scan_type)

        result = {
            "host": target,
            "status": nm[target].state(),
            "latency": nm[target].get("times", {}).get("srtt", 0) / 1000,
            "ports": [],
            "os": "Unknown",
            "mac_address": nm[target]["addresses"].get("mac", "N/A"),
            "firewall_detected": "No",
            "service_info": "",
            "vulnerabilities": [],
        }

        # Get Port Information
        for port in nm[target]['tcp']:
            port_info = nm[target]['tcp'][port]
            if port_info['state'] == "open":
                cpe = port_info.get('cpe', 'N/A')
                result["ports"].append({
                    "port": port,
                    "state": port_info['state'],
                    "service": port_info.get('name', 'Unknown'),
                    "version": port_info.get('version', 'Unknown'),
                    "cpe": cpe
                })

        # Detect Firewall (filtered ports indicate a firewall)
        filtered_ports = [p for p in nm[target]['tcp'] if nm[target]['tcp'][p]['state'] == 'filtered']
        if filtered_ports:
            result["firewall_detected"] = "Yes"

        # Get OS Detection
        os_matches = nm[target].get("osmatch", [])
        if os_matches:
            result["os"] = os_matches[0]["name"]

        # Get Vulnerability Scan Results
        if vuln_scan:
            print("Full Nmap Scan Output:")  # To debug and inspect results
            print(nm[target])  # Log the entire scan result for debugging

            # Get detailed vulnerabilities from scripts
            if 'script' in nm[target]:
                for vuln in nm[target]['script']:
                    result["vulnerabilities"].append({
                        "vuln_name": vuln,
                        "vuln_details": nm[target]['script'][vuln]
                    })

        return result
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
        return None

# 🔹 Function to search for exploits in ExploitDB
def get_exploit_db(cve):
    try:
        response = requests.get(EXPLOIT_DB_API + cve)
        response.raise_for_status()  # Ensure a successful response
        return f"🔗 Exploit-DB Link: {EXPLOIT_DB_API}{cve}"
    except requests.RequestException as e:
        print(Fore.RED + f"Error fetching exploit info: {e}" + Style.RESET_ALL)
        return "No known exploits found"

# 🔹 Function to ping a host and get latency, status
def ping_host(host):
    try:
        nm = nmap.PortScanner()
        nm.scan(host, '1-1024')  # Scan a range of ports just to check if the host is up
        if nm.all_hosts():
            return "Online", 0  # Host is up, return "Online" and set latency to 0
        else:
            return "Offline", None  # Host is not up
    except Exception as e:
        print(Fore.RED + f"Error pinging host {host}: {e}" + Style.RESET_ALL)
        return "Offline", None

# 🔹 Modify the scan_ports function to include the OS and MAC address detection, plus --osscan-guess
def scan_ports(target, port_range, vuln_scan=False):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, port_range, arguments='-O --osscan-guess')
        open_ports = []
        os_info = "Unknown"  # Default OS info
        mac_address = "00:00:00:00:00:00"  # Default MAC address
        vulnerabilities = []

        # Get the open ports and OS info
        for port in nm[target]['tcp']:
            port_info = nm[target]['tcp'][port]
            if port_info['state'] == "open":
                service = port_info.get('name', 'Unknown')
                open_ports.append({"port": port, "service": service})

        # OS and MAC address info
        if "osmatch" in nm[target]:
            os_info = nm[target]["osmatch"][0]["name"]
        if "mac" in nm[target]["addresses"]:
            mac_address = nm[target]["addresses"]["mac"]

        return open_ports, os_info, mac_address, vulnerabilities
    except Exception as e:
        print(Fore.RED + f"Error scanning ports: {e}" + Style.RESET_ALL)
        return [], "Unknown", "00:00:00:00:00:00", []

# 🔹 Function to save results in the chosen format
def save_results(scan_results, file_type):
    base_filename = f"scan_results_{scan_results['host']}"

    try:
        if file_type == "json":
            with open(f"{base_filename}.json", "w") as json_file:
                json.dump(scan_results, json_file, indent=4)
            print(Fore.GREEN + f"Results saved as {base_filename}.json" + Style.RESET_ALL)
        elif file_type == "csv":
            with open(f"{base_filename}.csv", "w", newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(["Port", "State", "Service", "Version"])
                for port in scan_results['ports']:
                    writer.writerow([port['port'], port['state'], port['service'], port.get('version', 'N/A')])
            print(Fore.GREEN + f"Results saved as {base_filename}.csv" + Style.RESET_ALL)
        elif file_type == "txt":
            with open(f"{base_filename}.txt", "w") as txt_file:
                txt_file.write(json.dumps(scan_results, indent=4))
            print(Fore.GREEN + f"Results saved as {base_filename}.txt" + Style.RESET_ALL)
        elif file_type == "md":
            with open(f"{base_filename}.md", "w") as md_file:
                md_file.write(f"# Scan Results for {scan_results['host']}\n")
                for port in scan_results['ports']:
                    md_file.write(f"- **Port {port['port']}** - {port['service']} (Version: {port.get('version', 'N/A')})\n")
            print(Fore.GREEN + f"Results saved as {base_filename}.md" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Invalid file type selected!" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error saving results: {e}" + Style.RESET_ALL)

# 🔹 Function to display results in a readable format
def display_results(scan_results):
    print(Fore.CYAN + f"📡 PhantomRecon Results for {scan_results['host']}:" + Style.RESET_ALL)
    print(Fore.YELLOW + f"📌 Status: {scan_results['status']}" + Style.RESET_ALL)
    if scan_results['status'] == "Online":
        print(Fore.CYAN + f"⏳ Latency: {scan_results['latency']} ms" + Style.RESET_ALL)
    print(Fore.GREEN + f"🌍 Location: {scan_results['location']}" + Style.RESET_ALL)
    print(Fore.BLUE + f"🖥️ Operating System: {scan_results['os']}" + Style.RESET_ALL)
    print(Fore.CYAN + f"🔧 Mac Address: {scan_results['mac_address']}" + Style.RESET_ALL)

    # WHOIS Information
    print(Fore.MAGENTA + "\n🌐 WHOIS Information:" + Style.RESET_ALL)
    if isinstance(scan_results["whois"], dict):
        for key, value in scan_results["whois"].items():
            print(f"📖 {key}: {value}")
    else:
        print(Fore.RED + f"⚠️ {scan_results['whois']}" + Style.RESET_ALL)

    # Shodan Information
    print(Fore.MAGENTA + "\n🔍 Shodan Info:" + Style.RESET_ALL)
    print(Fore.GREEN + f"ISP: {scan_results['shodan']['ISP']}" + Style.RESET_ALL)
    print(Fore.GREEN + f"Organization: {scan_results['shodan']['Organization']}" + Style.RESET_ALL)
    print(Fore.GREEN + f"Operating System: {scan_results['shodan']['OS']}" + Style.RESET_ALL)
    print(Fore.GREEN + f"Ports: {', '.join(map(str, scan_results['shodan']['Ports']))}" + Style.RESET_ALL)

    # Open ports
    if scan_results["ports"]:
        print(Fore.MAGENTA + "\n🔓 Open Ports:" + Style.RESET_ALL)
        for port in scan_results["ports"]:
            print(Fore.GREEN + f"Port {port['port']} - {port['service']}" + Style.RESET_ALL)

    # Vulnerabilities
    if scan_results.get("vulnerabilities"):
        print(Fore.RED + "\n⚠️ Vulnerabilities Detected:" + Style.RESET_ALL)
        for vuln in scan_results["vulnerabilities"]:
            print(Fore.YELLOW + f"• {vuln['vuln_name']}: {vuln['vuln_details']}" + Style.RESET_ALL)

# 🔹 Modify the phantom_recon function to use the updated scan_ports function
def phantom_recon():
    check_root()  # Check if running as root

    os.system("cls" if os.name == "nt" else "clear")
    print(Fore.CYAN + "Welcome to PhantomRecon: the Ultimate scanner!" + Style.RESET_ALL)

    while True:
        banner = '''
        ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
        ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
        ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
        ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
        ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
        ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                                          '''

        print(banner)

        target = input(Fore.YELLOW + "Enter target IP/Hostname (or multiple, comma-separated): " + Style.RESET_ALL)
        if target.lower() == 'exit':
            print(Fore.RED + "Exiting the scanner..." + Style.RESET_ALL)
            break  # Exit the loop and terminate the script

        targets = [t.strip() for t in target.split(",")]

        # Resolve domain to IP if provided as a domain name
        if any("." in t for t in targets):  # Check if domain
            targets = [resolve_domain_to_ip(t) if "." in t else t for t in targets]

        print(Fore.YELLOW + "\nChoose scan type:\n1. sS - Stealth Scan\n2. sT - Full TCP Scan\n3. -A - Aggressive Scan" + Style.RESET_ALL)
        scan_type = input("Enter scan parameters (e.g., sS, sT, -A): ").strip() or "-A"
        port_range = input("Enter port range (default: 1-65535): ").strip() or "1-65535"
        bypass_firewall = input("Enable firewall bypass techniques? (yes/no): ").strip().lower() == "yes"
        passive_mode = input("Enable Passive Recon? (yes/no) (Only WHOIS and Shodan recon): ").strip().lower() == "yes"

        # Automatically enable vulnerability scanning with --script vuln if requested
        vuln_scan = input("Enable vulnerability scanning with --script vuln? (yes/no): ").strip().lower() == "yes"
        if vuln_scan:
            print(Fore.RED + "Warning: '--script vuln' may take a long time and trigger alarms!" + Style.RESET_ALL)
            scan_type += " --script vuln"

        print(Fore.YELLOW + f"\nScanning {target} with {scan_type} and port range {port_range}" + Style.RESET_ALL)

        for target in targets:
            # Check host status and latency
            status, latency = ping_host(target)
            open_ports, os_info, mac_address, vulnerabilities = scan_ports(target, port_range, vuln_scan)

            result = {
                "host": target,
                "status": status,
                "latency": latency,
                "location": get_ip_location(target),
                "os": os_info,
                "mac_address": mac_address,
                "ports": open_ports,
                "shodan": get_shodan_info(target),
                "whois": get_whois_info(target),
                "vulnerabilities": vulnerabilities
            }

            if status == "Online":
                display_results(result)

                save_option = input("Do you want to save the results? (yes/no): ").strip().lower()
                if save_option == "yes":
                    file_type = input("Choose file type to save (json/csv/txt/md): ").strip().lower()
                    save_results(result, file_type)

        back_to_menu = input("Do you want to scan another target? (yes/no): ").strip().lower()
        if back_to_menu != "yes":
            print(Fore.RED + "Exiting the scanner..." + Style.RESET_ALL)
            break  # Exit the loop and terminate the script
# 🔹 Run the PhantomRecon scanner
if __name__ == "__main__":
    phantom_recon()
