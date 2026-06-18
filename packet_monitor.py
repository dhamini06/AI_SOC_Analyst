import subprocess

print("Starting Packet Monitor...")

command = [
    "tshark",
    "-i", "eth0",
    "-c", "5"
]

result = subprocess.run(
    command,
    capture_output=True,
    text=True
)

print(result.stdout)
