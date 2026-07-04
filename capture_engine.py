import time
import random
import threading
from typing import Callable, Optional

# Try importing Scapy. Scapy might require winpcap/npcap on Windows, so we wrap it gracefully.
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    pass

class CaptureEngine:
    """
    Handles network packet sniffing. Automatically falls back to simulation mode
    if Scapy is not available, or if sniffing fails due to insufficient permissions.
    """
    def __init__(self, interface: str = "eth0", callback: Optional[Callable] = None):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.mode = "live" if SCAPY_AVAILABLE else "simulation"
        self.sim_threat_type: Optional[str] = None
        self.sim_ips = ["192.168.1.10", "10.0.2.15", "172.16.0.4", "192.168.1.45"]
        self.target_ip = "10.0.2.5"

    def set_mode(self, mode: str):
        if mode == "live" and not SCAPY_AVAILABLE:
            raise ValueError("Scapy is not installed. Live mode is unavailable.")
        self.mode = mode

    def start(self):
        if self.running:
            return
        self.running = True
        if self.mode == "live":
            self.thread = threading.Thread(target=self._live_sniff_loop, daemon=True)
        else:
            self.thread = threading.Thread(target=self._sim_sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

    def trigger_simulated_threat(self, threat_type: str):
        """Allows dashboard to force-trigger a threat simulation sequence."""
        self.sim_threat_type = threat_type

    def _process_scapy_packet(self, packet):
        if not self.callback:
            return

        # We only care about IP packets for our detection rules
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = "OTHER"
            sport = None
            dport = None
            info = ""

            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if DNS in packet and packet[DNS].qr == 0:  # DNS Query
                    proto = "DNS"
                    if packet.haslayer(DNSQR):
                        info = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            elif ICMP in packet:
                proto = "ICMP"
                info = "ICMP Echo Request" if packet[ICMP].type == 8 else "ICMP Reply"

            packet_dict = {
                "timestamp": time.time(),
                "src": src_ip,
                "dst": dst_ip,
                "proto": proto,
                "sport": sport,
                "dport": dport,
                "size": len(packet),
                "info": info
            }
            self.callback(packet_dict)

    def _live_sniff_loop(self):
        try:
            print(f"[CaptureEngine] Starting live capture on interface {self.interface}...")
            # sniff runs blocked, so we use stop_filter to check running status
            sniff(
                iface=self.interface,
                prn=self._process_scapy_packet,
                stop_filter=lambda p: not self.running,
                store=0
            )
        except Exception as e:
            print(f"[CaptureEngine] Live capture error: {e}. Falling back to simulation mode.")
            self.mode = "simulation"
            self._sim_sniff_loop()

    def _sim_sniff_loop(self):
        print("[CaptureEngine] Starting simulation capture loop...")
        
        # Threat sequence trackers
        sim_threat_counter = 0
        threat_src = "192.168.88.22"

        while self.running:
            # If a specific threat simulation is triggered, execute it
            if self.sim_threat_type:
                threat = self.sim_threat_type
                print(f"[CaptureEngine] Simulating threat: {threat}")
                
                if threat == "ping_flood":
                    # Generate 8 ICMP packets quickly
                    for _ in range(8):
                        packet_dict = {
                            "timestamp": time.time(),
                            "src": threat_src,
                            "dst": self.target_ip,
                            "proto": "ICMP",
                            "sport": None,
                            "dport": None,
                            "size": 64,
                            "info": "ICMP Echo Request (Simulated)"
                        }
                        if self.callback:
                            self.callback(packet_dict)
                        time.sleep(0.1)
                        
                elif threat == "port_scan":
                    # Generate connections to 15 different ports
                    for port in range(1020, 1035):
                        packet_dict = {
                            "timestamp": time.time(),
                            "src": threat_src,
                            "dst": self.target_ip,
                            "proto": "TCP",
                            "sport": random.randint(49152, 65535),
                            "dport": port,
                            "size": 40,
                            "info": f"SYN (Simulated Port Scan on port {port})"
                        }
                        if self.callback:
                            self.callback(packet_dict)
                        time.sleep(0.05)
                        
                elif threat == "dns_tunnel":
                    # Generate 6 anomalous DNS txt/cname queries
                    subdomains = [
                        "d3VzZXJfaWQ9NDIK.exfil.attacker.com",
                        "cGFzc3dvcmQ9c2VjcmV0.exfil.attacker.com",
                        "aG9zdG5hbWU9a2FsaS12bQ==.exfil.attacker.com",
                        "aXBhZGRyPTEwLjAuMi4xNQ==.exfil.attacker.com",
                        "Y21kPXdhaG9hbWk=.exfil.attacker.com",
                        "ZmlsZW5hbWU9Y29uZmln.exfil.attacker.com"
                    ]
                    for sub in subdomains:
                        packet_dict = {
                            "timestamp": time.time(),
                            "src": threat_src,
                            "dst": "8.8.8.8",
                            "proto": "DNS",
                            "sport": random.randint(49152, 65535),
                            "dport": 53,
                            "size": 110,
                            "info": sub
                        }
                        if self.callback:
                            self.callback(packet_dict)
                        time.sleep(0.2)

                self.sim_threat_type = None  # Reset trigger

            else:
                # Generate normal background traffic
                src = random.choice(self.sim_ips)
                proto = random.choice(["TCP", "UDP", "DNS", "ICMP"])
                sport = random.randint(1024, 65535)
                dport = random.choice([80, 443, 22, 53])
                info = ""
                
                if proto == "DNS":
                    dport = 53
                    info = f"{random.choice(['google.com', 'github.com', 'streamlit.io', 'python.org'])}"
                elif proto == "ICMP":
                    info = "ICMP Echo Request"
                    sport = None
                    dport = None
                
                packet_dict = {
                    "timestamp": time.time(),
                    "src": src,
                    "dst": self.target_ip if proto != "DNS" else "8.8.8.8",
                    "proto": proto,
                    "sport": sport,
                    "dport": dport,
                    "size": random.randint(40, 1500),
                    "info": info
                }
                
                if self.callback:
                    self.callback(packet_dict)
                
            time.sleep(random.uniform(0.5, 2.0))
