# firewallevasion.py

from colorama import Fore, Style

def get_firewall_evasion_flags():
    return [
        "-f",                      # Fragment packets
        "--data-length 50",        # Pad packets
        "--source-port 53",        # Spoof DNS port
        "-D RND:10",               # Decoy scan
        "--scan-delay 1s",         # Slow scan
        "--max-retries 1",         # Fewer retries
    ]

def detect_firewall(host_data):
    filtered_count = 0
    for protocol in ["tcp", "udp"]:
        if protocol in host_data:
            for _, info in host_data[protocol].items():
                if info.get("state") == "filtered":
                    filtered_count += 1

    firewall_detected = filtered_count > 0

    if firewall_detected:
        print(Fore.RED + f"\n🛡️ Possible firewall detected! {filtered_count} port(s) filtered." + Style.RESET_ALL)
        suggestions = [
            "-f (fragment packets)",
            "--mtu 24 (set smaller MTU)",
            "--data-length <num> (pad packets)",
            "--source-port 53 (bypass with DNS port)",
            "-D RND:10 (use decoys)",
            "--scan-delay <time> (slow scan)",
        ]
        for method in suggestions:
            print(Fore.MAGENTA + f"  ↪ {method}" + Style.RESET_ALL)
    else:
        suggestions = []

    return {
        "firewall_detected": "Yes" if firewall_detected else "No",
        "bypass_suggestions": suggestions
    }
