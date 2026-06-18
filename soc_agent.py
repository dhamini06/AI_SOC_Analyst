import subprocess
import json
from google import genai
import os

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)

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
dns_count = 0
source_ip = "Unknown"

for line in result.stdout.splitlines():

    fields = line.split()

    if len(fields) >= 2:

        protocol = fields[1]
        if protocol == "DNS":
            source_ip = fields[0]
            dns_count += 1

        if protocol == "ICMP":
            source_ip = fields[0]
            icmp_count += 1
print(f"DNS Packets Detected: {dns_count}")
if dns_count > 5:
    print("ALERT: High DNS Activity Detected!")

    dns_alert = {
        "alert_id": f"DNS-{dns_count:04d}",
        "alert_type": "High DNS Activity",
        "severity": "Medium",
        "source_ip": source_ip,
        "packet_count": dns_count
    }

    dns_prompt = f"""
You are a SOC Analyst.

Analyze this security alert:

{json.dumps(dns_alert, indent=4)}

Provide:

1. Threat Classification
2. Severity
3. Risk Score (0-100)
4. Recommended Actions
5. Incident Summary
"""

    dns_response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=dns_prompt
    )

    print("\n===== DNS AI ANALYSIS =====\n")
    print(dns_response.text)
if icmp_count > 3:

    alert = {
        "alert_id": f"INC-{icmp_count:04d}",
        "alert_type": "High ICMP Activity",
        "severity": "Medium",
        "source_ip": source_ip,
        "packet_count": icmp_count
    }

    prompt = f"""
You are a SOC Analyst.

Analyze this security alert:

{json.dumps(alert, indent=4)}

Provide:

1. Threat Classification
2. Severity
3. Risk Score (0-100)
4. Recommended Actions
5. Incident Summary
"""

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt
    )
    print("\n===== ALERT =====\n")
    print(json.dumps(alert, indent=4))

    try:
        with open("alerts.json", "r") as file:
            alerts = json.load(file)
    except:
        alerts = []

    alerts.append(alert)

    with open("alerts.json", "w") as file:
        json.dump(alerts, file, indent=4)

    print("\n===== AI ANALYSIS =====\n")
    print(response.text)

#else:
#   print("No suspicious activity detected.")