import subprocess
import json

command = [
    "tshark",
    "-i", "eth0",
    "-c", "10",
    "-T", "fields",
    "-e", "ip.src",
    "-e", "_ws.col.Protocol"
]

result = subprocess.run(
    command,
    capture_output=True,
    text=True
)

icmp_count = 0
source_ip = "Unknown"

for line in result.stdout.splitlines():

    fields = line.split()

    if len(fields) >= 2:

        source_ip = fields[0]
        protocol = fields[1]

        if protocol == "ICMP":
            icmp_count += 1

if icmp_count > 3:

    alert = {
        "alert_type": "High ICMP Activity",
        "severity": "Medium",
        "source_ip": source_ip,
        "packet_count": icmp_count
    }

    print(json.dumps(alert, indent=4))

else:

    print("No Alert Generated")
