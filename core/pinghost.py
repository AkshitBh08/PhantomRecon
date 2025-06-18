import nmap
from colorama import Fore, Style
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