from colorama import Fore, Style
from datetime import datetime
import random

def display_results(scan_results):
    print(Fore.CYAN + f"\n📡 PhantomRecon Results for {scan_results.get('host', 'Unknown Host')}:" + Style.RESET_ALL)

    # Status and Latency
    print(Fore.YELLOW + f"📌 Status: {scan_results.get('status', 'Unknown')}" + Style.RESET_ALL)
    latency = scan_results.get('latency_ms')
    if latency and scan_results.get('status', '').lower() == "online":
        print(Fore.CYAN + f"⏳ Latency: {latency:.2f} ms" + Style.RESET_ALL)

    # Location, OS, MAC
    print(Fore.GREEN + f"🌍 Location: {scan_results.get('location', 'N/A')}" + Style.RESET_ALL)
    print(Fore.BLUE + f"🖥️ Operating System: {scan_results.get('os', 'Unknown')}" + Style.RESET_ALL)
    print(Fore.CYAN + f"🔧 MAC Address: {scan_results.get('mac_address', 'N/A')}" + Style.RESET_ALL)

    # Firewall Detection
    print(Fore.MAGENTA + f"\n🛡️ Firewall Detected: {scan_results.get('firewall_detected', 'No')}" + Style.RESET_ALL)
    if scan_results.get("firewall_bypass_suggestions"):
        print(Fore.YELLOW + "💡 Possible Firewall Evasion Techniques:" + Style.RESET_ALL)
        for suggestion in scan_results["firewall_bypass_suggestions"]:
            print(Fore.MAGENTA + f"  ↪ {suggestion}" + Style.RESET_ALL)

    # WHOIS Information
    print(Fore.MAGENTA + "\n🌐 WHOIS Information:" + Style.RESET_ALL)
    whois_info = scan_results.get("whois")

    if whois_info:
        for key, value in whois_info.items():
            label = key.replace('_', ' ').title()  # Clean the key name

            # Format list values
            if isinstance(value, list):
                formatted_list = []
                for v in value:
                    if isinstance(v, datetime):
                        formatted_list.append(v.strftime("%A, %d %B %Y • %I:%M %p"))
                    else:
                        formatted_list.append(str(v))
                value_str = ", ".join(formatted_list)
            elif isinstance(value, datetime):
                value_str = value.strftime("%A, %d %B %Y • %I:%M %p")
            else:
                value_str = str(value)

            # Highlight important dates (creation/expiration)
            if "creation" in key.lower() or "created" in key.lower():
                print(Fore.GREEN + f"📅 {label}: {value_str}" + Style.RESET_ALL)
            elif "expiry" in key.lower() or "expiration" in key.lower():
                print(Fore.RED + f"⏳ {label}: {value_str}" + Style.RESET_ALL)
            else:
                print(Fore.WHITE + f"📖 {label}: {value_str}" + Style.RESET_ALL)
    else:
        print(Fore.WHITE + "No WHOIS information available." + Style.RESET_ALL)

    # Shodan Information
    print(Fore.MAGENTA + "\n🔍 Shodan Info:" + Style.RESET_ALL)
    shodan_info = scan_results.get("shodan", {})
    print(Fore.GREEN + f"ISP: {shodan_info.get('isp', 'N/A')}" + Style.RESET_ALL)
    print(Fore.GREEN + f"Organization: {shodan_info.get('org', 'N/A')}" + Style.RESET_ALL)
    print(Fore.GREEN + f"Operating System: {shodan_info.get('os', 'N/A')}" + Style.RESET_ALL)
    ports = shodan_info.get('ports', [])
    if ports:
        print(Fore.GREEN + f"Ports: {', '.join(map(str, ports))}" + Style.RESET_ALL)

    # Open Ports
    ports_info = scan_results.get("ports", [])
    if ports_info:
        print(Fore.MAGENTA + "\n🔓 Open Ports:" + Style.RESET_ALL)
        for port in sorted(ports_info, key=lambda x: x.get("port", 0)):
            port_number = port.get('port', 'N/A')
            protocol = port.get("protocol", "").upper()
            service = port.get('service', 'Unknown')
            version = port.get("version", "").strip()
            cpe = port.get("cpe", "")
            print(Fore.GREEN + f"• {protocol} Port {port_number} - {service} {version}".strip() + Style.RESET_ALL)
            if cpe and cpe != "N/A":
                print(Fore.WHITE + f"   ↪ CPE: {cpe}" + Style.RESET_ALL)
            if port.get("exploit_db_link"):
                print(Fore.MAGENTA + f"   ↪ Exploit DB: {port['exploit_db_link']}" + Style.RESET_ALL)

    # Vulnerabilities
    vulnerabilities = scan_results.get("vulnerabilities", [])
    if vulnerabilities:
        print(Fore.RED + "\n⚠️ Vulnerabilities Detected:" + Style.RESET_ALL)
        for vuln in vulnerabilities:
            name = vuln.get("name", "Unnamed Vulnerability")
            details = vuln.get("details", "No details available")
            if "ERROR" in details.upper():
                print(Fore.RED + f"• {name}: {details}" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + f"• {name}: {details}" + Style.RESET_ALL)

            if "exploits" in vuln:
                for link in vuln["exploits"]:
                    print(Fore.MAGENTA + f"   → {link}" + Style.RESET_ALL)

    print(Fore.CYAN + "\n✅ End of Report\n" + Style.RESET_ALL)

    outros = [
        "🎩 Recon complete! If the target had secrets... we probably found them.",
        "💻 Mission accomplished. Time to vanish into the shadows like a caffeinated ninja.",
        "📡 PhantomRecon signing off. May your packets be swift and your ports always open (except the vulnerable ones).",
        "🕳️ Scan deep, stay stealthy, and always log out like a ghost.",
        "🎯 Target neutralized. No firewalls were harmed (we think).",
        "🚪 All ports checked, all doors knocked. We out!",
        "🐱‍💻 PhantomRecon done. Now go stretch, hydrate, and maybe don’t hack the planet.",
        "🔌 Disconnecting from the matrix... brb updating scans.",
        "📖 Another chapter of digital espionage ends. Until the next recon...",
        "🧙‍♂️ Scanned like a wizard, vanished like a myth. PhantomRecon out.",
    ]
    print(Fore.YELLOW + random.choice(outros) + Style.RESET_ALL)
    print(Style.RESET_ALL)
    