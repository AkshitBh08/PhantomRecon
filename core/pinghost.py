import nmap
from colorama import Fore, Style
def ping_host(host):
    try:
        nm = nmap.PortScanner()
        nm.scan(host, '1-1024')
        if nm.all_hosts():
            return "Online", 0
        else:
            return "Offline", None
    except Exception as e:
        print(Fore.RED + f"Error pinging host {host}: {e}" + Style.RESET_ALL)
        return "Offline", None
