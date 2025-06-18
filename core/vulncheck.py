# core/vulncheck.py

def parse_vulnerabilities(host_data):
    vulnerabilities = []

    # Host-level scripts
    for script in host_data.get("hostscript", []):
        script_id = script.get("id", "Unknown Script")
        script_output = script.get("output", "No details")
        vulnerabilities.append({
            "type": "hostscript",
            "name": script_id,
            "details": script_output
        })

    # Port-level scripts
    for protocol in ["tcp", "udp"]:
        if protocol in host_data:
            for port, info in host_data[protocol].items():
                for script_id, script_output in info.get("script", {}).items():
                    vulnerabilities.append({
                        "type": "portscript",
                        "protocol": protocol,
                        "port": port,
                        "name": script_id,
                        "details": script_output
                    })

    return vulnerabilities
