# PhantomRecon: Ultimate Network Reconnaissance Tool

PhantomRecon is a powerful and customizable network reconnaissance tool that gathers detailed information about hosts and services on a network. It leverages a combination of multiple network tools such as Nmap, Shodan, WHOIS, IP geolocation services, and vulnerability databases to offer a comprehensive overview of a target system. 

## Features

- **IP Geolocation Lookup**: Retrieves geographic location details of an IP address using ipinfo.io.
- **WHOIS Information**: Fetches domain registration details like registrar, creation date, and expiration date.
- **Shodan Integration**: Queries Shodan to get metadata about hosts including ISP, organization, operating system, and open ports.
- **Nmap Scanning**: Conducts various types of Nmap scans such as Stealth, Full TCP, and Aggressive scans to gather information about open ports, services, operating systems, and more.
- **Exploit Database Lookup**: Retrieves known exploits for the target by querying Exploit-DB for CVEs.
- **Vulnerability Scanning**: Uses Nmap’s script engine to perform vulnerability scans for detailed analysis.
- **Result Export**: Saves scan results in multiple formats including JSON, CSV, TXT, and Markdown.
- **Firewall Detection**: Identifies the presence of a firewall based on filtered ports during Nmap scans.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Scan Types](#scan-types)
- [Result Formats](#result-formats)
- [Example Output](#example-output)
- [Dependencies](#dependencies)
- [License](#license)

## Installation

Follow these steps to set up PhantomRecon on your local machine:

### 1. Clone the Repository

Clone the repository from GitHub:
bash
git clone https://github.com/AkshitBh08/PhantomRecon.git
cd PhantomRecon

2. Install Dependencies

Run the install.py script to install all necessary Python dependencies:
python install.py

This script will install:
requests: For making HTTP requests to external services like IP geolocation and Exploit-DB.
shodan: For querying Shodan API.
nmap: For conducting network scans.
whois: For WHOIS lookups.
colorama: For colored output in the terminal.
It will also check that nmap is installed on your system. If it's missing, you will be prompted to install it from nmap.org.

3. Run PhantomRecon
Once the dependencies are installed, you can start the tool:

python PhantomRecon.py

Usage:

PhantomRecon will guide you through an interactive process where you will be asked to provide:

Target(s): IP addresses or hostnames for scanning. You can specify multiple targets, separated by commas.
Scan Type: Choose the type of scan you want to run:
sS (Stealth Scan): A TCP SYN scan that is less detectable by firewalls.
sT (Full TCP Scan): A standard TCP scan.
-A (Aggressive Scan): Scans all services, OS details, and runs vulnerability scripts.
Port Range: The range of ports to scan (default is 1-65535).
Firewall Bypass: Enable firewall bypass techniques (e.g., using decoy hosts).
Passive Mode: Perform passive reconnaissance, only using WHOIS and Shodan information.
Vulnerability Scanning: Enable additional vulnerability scanning using Nmap scripts.

Example Input:
Enter target IP/Hostname (or multiple, comma-separated): 192.168.1.1
Choose scan type:
1. sS - Stealth Scan
2. sT - Full TCP Scan
3. -A - Aggressive Scan
Enter scan parameters (e.g., sS, sT, -A): -A
Enter port range (default: 1-65535): 1-1024
Enable firewall bypass techniques? (yes/no): no
Enable Passive Recon? (yes/no): yes
Enable vulnerability scanning with --script vuln? (yes/no): yes
Scan Types:
sS: Stealth Scan (TCP SYN scan)
sT: Full TCP Scan (TCP connect scan)
-A: Aggressive Scan (includes OS, service version, and vulnerability scan)
Result Formats:
JSON: Saves results as a structured JSON file.
CSV: Exports results as a CSV file with port information.
TXT: Saves results in a human-readable text format.
Markdown: Saves results as a Markdown file with a clean and formatted output.

Example Output

Once the scan is completed, PhantomRecon will display a comprehensive summary of the findings:

📡 PhantomRecon Results for 192.168.1.1:
📌 Status: Online
⏳ Latency: 15 ms
🌍 Location: New York, NY, USA
🖥️ Operating System: Linux 3.10.0-327.el7.x86_64
🔧 Mac Address: 00:0a:95:9d:68:16

🌐 WHOIS Information:
📖 Registrar: Example Registrar
📖 Creation Date: 2020-01-01
📖 Expiration Date: 2023-01-01

🔍 Shodan Info:
ISP: Example ISP
Organization: Example Org
Operating System: Linux
Ports: 22, 80, 443

🔓 Open Ports:
Port 22 - SSH
Port 80 - HTTP
Port 443 - HTTPS

⚠️ Vulnerabilities Detected:
• CVE-2020-1234: Example vulnerability details
Dependencies
To ensure that PhantomRecon runs smoothly, you must install the following dependencies:

requests: For HTTP requests to external APIs like Shodan and Exploit-DB.
shodan: For querying Shodan’s host information.
python-nmap: A Python wrapper for Nmap used to scan ports.
python-whois: To fetch WHOIS information for domains.
colorama: To colorize terminal output.
These dependencies are listed in the requirements.txt file, and you can install them using the following command:

pip install -r requirements.txt
Additionally, ensure that Nmap is installed on your system. Nmap is a powerful open-source network scanner, and you can install it from Nmap's official website.

Contributions
Feel free to fork this repository, contribute improvements, report bugs, or suggest new features. Open pull requests or raise issues as needed.

For any questions or support, please contact the repository owner or create an issue in the GitHub repository.

### Key Sections:

1. **Features**: Lists all the functionalities that PhantomRecon provides.
2. **Table of Contents**: A quick navigation guide.
3. **Installation**: Instructions for cloning the repo, installing dependencies, and setting up Nmap.
4. **Usage**: Detailed explanation of the prompts users will encounter, with example input.
5. **Scan Types and Result Formats**: Descriptions of scan types and result file formats available.
6. **Example Output**: What the user can expect to see after running a scan.
7. **Dependencies**: Lists Python dependencies and system requirements (e.g., Nmap).
