import subprocess

command = [
    "tshark",
    "-i", "eth0",
    "-c", "10",
    "-T", "fields",
    "-e", "_ws.col.Protocol"
]

result = subprocess.run(
    command,
    capture_output=True,
    text=True
)

icmp_count = 0

for line in result.stdout.splitlines():
    if line.strip() == "ICMP":
        icmp_count += 1

print(f"ICMP Packets Detected: {icmp_count}")

if icmp_count > 3:
    print("ALERT: High ICMP Activity Detected!")
else:
    print("Status: Normal Traffic")
