import os
import sys
import requests
import time
from colorama import Fore, Style

from core.saveresult import save_results
from core.displayresults import display_results
from core.scan import scan_with_nmap
from core.passiverecon import get_whois_info, get_shodan_info
from core.domain_to_ip import get_ip_location, resolve_domain_to_ip
from core.pinghost import ping_host

EXPLOIT_DB_API = "https://www.exploit-db.com/search?cve="


def check_root():
    if os.name != "nt" and os.geteuid() != 0:
        print(Fore.RED + "❌ Error: This script must be run as root!" + Style.RESET_ALL)
        sys.exit(1)


def get_exploit_db(cve):
    try:
        response = requests.get(EXPLOIT_DB_API + cve, timeout=5)
        if cve in response.text:
            return f"🔗 Exploit-DB: {EXPLOIT_DB_API}{cve}"
        return "No known public exploit"
    except requests.RequestException:
        return "❌ Error reaching Exploit-DB"


def phantom_recon():
    check_root()
    os.system("cls" if os.name == "nt" else "clear")

    print(Fore.CYAN + "Welcome to PhantomRecon: The Ultimate Recon Toolkit\n" + Style.RESET_ALL)

    banner = '''
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
    '''

    print(Fore.GREEN + banner + Style.RESET_ALL)

    while True:
        target_input = input(Fore.YELLOW + "\nEnter target IP/Hostname (comma-separated or 'exit'): " + Style.RESET_ALL)
        if target_input.lower() == 'exit':
            print(Fore.RED + "Exiting PhantomRecon..." + Style.RESET_ALL)
            break

        raw_targets = [t.strip() for t in target_input.split(",")]
        targets = []
        for raw in raw_targets:
            resolved = resolve_domain_to_ip(raw)
            if resolved:
                targets.append(resolved)
            else:
                print(Fore.RED + f"⚠ Could not resolve: {raw}" + Style.RESET_ALL)

        if not targets:
            print(Fore.RED + "No valid targets found. Try again." + Style.RESET_ALL)
            continue

        passive_mode = input("Enable Passive Recon? (yes/no): ").strip().lower() == "yes"

        if not passive_mode:
            print(Fore.YELLOW + "\nChoose scan type:\n1. Stealth (-sS)\n2. Full TCP (-sT)\n3. Aggressive (-A)\n" + Style.RESET_ALL)
            scan_choice = input("Enter scan type (1/2/3): ").strip()
            scan_flags = {"1": "-sS", "2": "-sT", "3": "-A"}
            scan_type = scan_flags.get(scan_choice, "-A")

            port_range = input("Enter port range (default: 1-65535): ").strip() or "1-65535"

            bypass_firewall = input("Attempt to bypass firewalls? (yes/no): ").strip().lower() == "yes"
            if bypass_firewall:
                print(Fore.YELLOW + "🛡️ Firewall evasion may affect detection accuracy or scan speed." + Style.RESET_ALL)

            vuln_scan = input("Enable vulnerability scanning? (yes/no): ").strip().lower() == "yes"
            if vuln_scan:
                print(Fore.RED + "⚠ Warning: Vulnerability scanning may trigger alarms!" + Style.RESET_ALL)
                if input("Proceed with vulnerability scan? (yes/no): ").strip().lower() != "yes":
                    vuln_scan = False
        else:
            scan_type, port_range, vuln_scan, bypass_firewall = "", "", False, False

        print(Fore.CYAN + f"\n🔍 Starting scans for {len(targets)} target(s)...\n" + Style.RESET_ALL)

        for target in targets:
            print(Fore.CYAN + f"\n🔎 Scanning {target}..." + Style.RESET_ALL)
            status, latency = ping_host(target)

            if not passive_mode:
                result = scan_with_nmap(target, scan_type, port_range, vuln_scan, bypass_firewall)
                if not result:
                    print(Fore.RED + f"[!] Scan failed for {target}" + Style.RESET_ALL)
                    continue

                result.update({
                    "status": status,
                    "latency": latency,
                    "location": get_ip_location(target),
                    "shodan": get_shodan_info(target),
                    "whois": get_whois_info(target),
                })

                # Enrich vulnerabilities
                for vuln in result.get("vulnerabilities", []):
                    details = vuln.get("details", "")
                    if "CVE" in details:
                        cves = [x for x in details.split() if x.startswith("CVE-")]
                        vuln["exploits"] = [get_exploit_db(cve) for cve in cves]

                # Enrich port data
                for port in result.get("ports", []):
                    cpe = port.get("cpe")
                    if cpe and "cpe:/" in cpe:
                        port["exploit_db_link"] = f"https://www.exploit-db.com/search?q={cpe.split(':')[-1]}"
            else:
                result = {
                    "host": target,
                    "status": status,
                    "latency": latency,
                    "location": get_ip_location(target),
                    "shodan": get_shodan_info(target),
                    "whois": get_whois_info(target),
                    "mac_address": "Passive Recon - MAC not detected",
                    "os": "Passive Recon - OS not detected",
                    "ports": [],
                    "vulnerabilities": [],
                    "firewall_detected": "N/A",
                    "service_info": "N/A"
                }

            if status == "Online":
                display_results(result)

                if input("Do you want to save the results? (yes/no): ").strip().lower() == "yes":
                    file_type = input("Choose file type to save (json/csv/txt/md): ").strip().lower()
                    save_results(result, file_type)

            time.sleep(0.5)

        if input("\nScan another target? (yes/no): ").strip().lower() != "yes":
            break


if __name__ == "__main__":
    phantom_recon()
