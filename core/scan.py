# scan.py

import nmap
from colorama import Fore, Style
from core.firewall_evasion import get_firewall_evasion_flags, detect_firewall
from core.vulncheck import parse_vulnerabilities

def scan_with_nmap(target, scan_type, port_range="1-65535", vuln_scan=False, bypass_firewall=False):
    nm = nmap.PortScanner()
    scan_flags = scan_type

    if "-sV" not in scan_flags:
        scan_flags += " -sV"

    if vuln_scan and "--script" not in scan_flags:
        scan_flags += " --script vuln,vulners"

    if bypass_firewall:
        scan_flags += " " + " ".join(get_firewall_evasion_flags())

    print(Fore.CYAN + f"\n🔍 Starting scanning on {target}" + Style.RESET_ALL)

    try:
        nm.scan(hosts=target, ports=port_range, arguments=scan_flags)

        if target not in nm.all_hosts():
            print(Fore.RED + f"❌ No response from {target}" + Style.RESET_ALL)
            return None

        host_data = nm[target]

        result = {
            "host": target,
            "status": host_data.state(),
            "latency_ms": host_data.get("times", {}).get("srtt", 0) / 1000,
            "os": "Unknown",
            "mac_address": host_data.get("addresses", {}).get("mac", "N/A"),
            "ports": [],
            "firewall_detected": "No",
            "firewall_bypass_suggestions": [],
            "service_info": [],
            "vulnerabilities": []
        }

        # OS Detection
        if "osmatch" in host_data and host_data["osmatch"]:
            result["os"] = host_data["osmatch"][0].get("name", "Unknown")

        # Port analysis
        for protocol in ["tcp", "udp"]:
            if protocol in host_data:
                for port, info in host_data[protocol].items():
                    state = info.get("state", "unknown")
                    service = info.get("name", "Unknown")
                    version = info.get("version", "Unknown")
                    product = info.get("product", "")
                    extra_info = info.get("extrainfo", "")
                    cpe = info.get("cpe", "N/A")

                    if state == "open":
                        banner = f"{product} {version} {extra_info}".strip()
                        result["ports"].append({
                            "protocol": protocol,
                            "port": port,
                            "state": state,
                            "service": service,
                            "version": banner,
                            "cpe": cpe,
                        })

        # Firewall Detection
        fw_info = detect_firewall(host_data)
        result["firewall_detected"] = fw_info["firewall_detected"]
        result["firewall_bypass_suggestions"] = fw_info["bypass_suggestions"]

        # Vulnerability parsing
        if vuln_scan:
            result["vulnerabilities"] = parse_vulnerabilities(host_data)

        return result

    except Exception as e:
        print(Fore.RED + f"❌ Nmap Scan Error: {e}" + Style.RESET_ALL)
        return None
