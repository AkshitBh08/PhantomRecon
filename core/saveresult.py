import json
import csv
from colorama import Fore, Style

def save_results(scan_results, file_type):
    base_filename = f"scan_results_{scan_results['host']}"

    try:
        if file_type == "json":
            with open(f"{base_filename}.json", "w") as json_file:
                json.dump(scan_results, json_file, indent=4)
            print(Fore.GREEN + f"✅ Results saved as {base_filename}.json" + Style.RESET_ALL)

        elif file_type == "csv":
            with open(f"{base_filename}.csv", "w", newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(["Protocol", "Port", "State", "Service", "Version", "CPE"])
                for port in scan_results['ports']:
                    writer.writerow([
                        port['protocol'],
                        port['port'],
                        port['state'],
                        port['service'],
                        port.get('version', 'N/A'),
                        port.get('cpe', 'N/A')
                    ])
            print(Fore.GREEN + f"✅ Results saved as {base_filename}.csv" + Style.RESET_ALL)

        elif file_type == "txt":
            with open(f"{base_filename}.txt", "w") as txt_file:
                txt_file.write(f"Host: {scan_results['host']}\n")
                txt_file.write(f"Status: {scan_results['status']}\n")
                txt_file.write(f"OS: {scan_results['os']}\n")
                txt_file.write(f"MAC Address: {scan_results['mac_address']}\n")
                txt_file.write(f"Latency: {scan_results['latency_ms']} ms\n")
                txt_file.write(f"Firewall Detected: {scan_results['firewall_detected']}\n\n")

                txt_file.write("Open Ports:\n")
                for port in scan_results['ports']:
                    txt_file.write(
                        f"  - {port['protocol'].upper()}/{port['port']} → {port['service']} "
                        f"(Version: {port.get('version', 'N/A')}, CPE: {port.get('cpe', 'N/A')})\n"
                    )

                if scan_results['firewall_bypass_suggestions']:
                    txt_file.write("\nFirewall Bypass Suggestions:\n")
                    for method in scan_results['firewall_bypass_suggestions']:
                        txt_file.write(f"  • {method}\n")

                if scan_results['vulnerabilities']:
                    txt_file.write("\nVulnerabilities Found:\n")
                    for vuln in scan_results['vulnerabilities']:
                        if vuln["type"] == "hostscript":
                            txt_file.write(f"  [Hostscript] {vuln['name']}: {vuln['details']}\n")
                        else:
                            txt_file.write(
                                f"  [Portscript] {vuln['protocol']}/{vuln['port']} {vuln['name']}: {vuln['details']}\n"
                            )

            print(Fore.GREEN + f"✅ Results saved as {base_filename}.txt" + Style.RESET_ALL)

        elif file_type == "md":
            with open(f"{base_filename}.md", "w") as md_file:
                md_file.write(f"# Scan Results for {scan_results['host']}\n\n")
                md_file.write(f"**Status**: {scan_results['status']}\n\n")
                md_file.write(f"**OS Detected**: {scan_results['os']}\n\n")
                md_file.write(f"**MAC Address**: {scan_results['mac_address']}\n\n")
                md_file.write(f"**Latency**: {scan_results['latency_ms']} ms\n\n")

                md_file.write(f"## Open Ports\n")
                for port in scan_results['ports']:
                    md_file.write(
                        f"- `{port['protocol']}/{port['port']}`: **{port['service']}** "
                        f"(Version: {port.get('version', 'N/A')}, CPE: {port.get('cpe', 'N/A')})\n"
                    )

                if scan_results['firewall_detected'] == "Yes":
                    md_file.write(f"\n> ⚠️ **Firewall detected**\n")
                    md_file.write(f"### Suggested Firewall Evasion Techniques:\n")
                    for method in scan_results['firewall_bypass_suggestions']:
                        md_file.write(f"- {method}\n")

                if scan_results['vulnerabilities']:
                    md_file.write(f"\n## Vulnerabilities\n")
                    for vuln in scan_results['vulnerabilities']:
                        if vuln["type"] == "hostscript":
                            md_file.write(f"- **[Host] {vuln['name']}**: {vuln['details']}\n")
                        else:
                            md_file.write(
                                f"- **[Port {vuln['protocol']}/{vuln['port']}] {vuln['name']}**: {vuln['details']}\n"
                            )

            print(Fore.GREEN + f"✅ Results saved as {base_filename}.md" + Style.RESET_ALL)

        else:
            print(Fore.RED + "❌ Invalid file type selected!" + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"❌ Error saving results: {e}" + Style.RESET_ALL)
