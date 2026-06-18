import subprocess

command = [
    "tshark",
    "-i", "eth0",
    "-c", "5",
    "-T", "fields",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "_ws.col.Protocol"
]

result = subprocess.run(
    command,
    capture_output=True,
    text=True
)

print("Captured Packets:\n")

for line in result.stdout.splitlines():
    print(line)
