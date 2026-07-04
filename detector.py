import time
from collections import defaultdict
from typing import Callable, Optional, Dict, List

class Detector:
    """
    Stateful threat detection processor. Tracks packets over sliding windows
    to identify patterns of ICMP Flooding, Port Scanning, and DNS Tunneling.
    """
    def __init__(self, alert_callback: Callable[[Dict], None]):
        self.alert_callback = alert_callback
        
        # Threat detection thresholds
        self.ICMP_THRESHOLD = 5         # packets
        self.ICMP_WINDOW = 5.0          # seconds
        
        self.PORT_SCAN_THRESHOLD = 8    # unique ports
        self.PORT_SCAN_WINDOW = 5.0     # seconds
        
        self.DNS_TUNNEL_THRESHOLD = 5   # queries
        self.DNS_TUNNEL_WINDOW = 5.0    # seconds
        self.DNS_LEN_THRESHOLD = 25     # query string length
        
        self.COOLDOWN_PERIOD = 20.0     # seconds (prevent duplicate alerts for same IP + threat)

        # State tracking: IP -> list of timestamps/metadata
        self.icmp_history = defaultdict(list)
        self.port_scan_history = defaultdict(list)  # IP -> list of (timestamp, port)
        self.dns_history = defaultdict(list)        # IP -> list of (timestamp, domain)
        
        # Cooldown state: (source_ip, threat_type) -> timestamp of last alert
        self.cooldowns = {}

    def process_packet(self, packet: Dict):
        now = packet["timestamp"]
        src = packet["src"]
        proto = packet["proto"]
        
        # Clean up old records to prevent memory growth
        self._prune_history(now)

        # 1. ICMP FLOOD DETECTION
        if proto == "ICMP":
            self.icmp_history[src].append(now)
            # Count recent ICMP packets
            recent_icmp = [t for t in self.icmp_history[src] if now - t <= self.ICMP_WINDOW]
            if len(recent_icmp) >= self.ICMP_THRESHOLD:
                self._trigger_alert(
                    ip=src,
                    threat_type="High ICMP Activity",
                    severity="High" if len(recent_icmp) > 10 else "Medium",
                    packet_count=len(recent_icmp),
                    details=f"Detected {len(recent_icmp)} ICMP packets in {self.ICMP_WINDOW}s window."
                )

        # 2. PORT SCAN DETECTION
        elif proto == "TCP" and packet["dport"] is not None:
            dport = packet["dport"]
            self.port_scan_history[src].append((now, dport))
            # Get unique ports scanned in the window
            recent_connections = [p for t, p in self.port_scan_history[src] if now - t <= self.PORT_SCAN_WINDOW]
            unique_ports = set(recent_connections)
            
            if len(unique_ports) >= self.PORT_SCAN_THRESHOLD:
                self._trigger_alert(
                    ip=src,
                    threat_type="Port Scanning Detected",
                    severity="High" if len(unique_ports) > 12 else "Medium",
                    packet_count=len(recent_connections),
                    details=f"IP connected to {len(unique_ports)} unique ports in {self.PORT_SCAN_WINDOW}s. Ports: {sorted(list(unique_ports))}"
                )

        # 3. DNS TUNNELING / ANOMALOUS DNS DETECTION
        elif proto == "DNS" and packet["info"]:
            domain = packet["info"]
            self.dns_history[src].append((now, domain))
            
            # Check for unusually long queries (often base64 encoded data exfiltration)
            clean_domain = domain.rstrip('.')
            subdomains = clean_domain.split('.')
            longest_label_len = max([len(sub) for sub in subdomains]) if subdomains else 0
            
            # Scenario A: Single extremely long DNS query label
            if longest_label_len > self.DNS_LEN_THRESHOLD:
                self._trigger_alert(
                    ip=src,
                    threat_type="DNS Tunneling Suspected",
                    severity="High",
                    packet_count=1,
                    details=f"Anomalous query string length ({len(domain)} chars, label {longest_label_len} chars): '{domain}'."
                )
                
            # Scenario B: High volume of DNS requests in short window
            recent_dns = [d for t, d in self.dns_history[src] if now - t <= self.DNS_TUNNEL_WINDOW]
            if len(recent_dns) >= self.DNS_TUNNEL_THRESHOLD:
                # Check how many have long queries
                long_queries = [d for d in recent_dns if len(d) > 20]
                if len(long_queries) >= 3:
                    self._trigger_alert(
                        ip=src,
                        threat_type="DNS Tunneling Suspected",
                        severity="High",
                        packet_count=len(recent_dns),
                        details=f"High frequency DNS requests ({len(recent_dns)} in {self.DNS_TUNNEL_WINDOW}s) with complex subdomains."
                    )

    def _trigger_alert(self, ip: str, threat_type: str, severity: str, packet_count: int, details: str):
        now = time.time()
        cooldown_key = (ip, threat_type)
        
        # Check cooldown
        if cooldown_key in self.cooldowns:
            if now - self.cooldowns[cooldown_key] < self.COOLDOWN_PERIOD:
                return  # Skip triggering duplicate alert
                
        self.cooldowns[cooldown_key] = now
        
        alert_id = f"{threat_type[:3].upper()}-{int(now) % 10000:04d}"
        
        alert = {
            "alert_id": alert_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "alert_type": threat_type,
            "severity": severity,
            "source_ip": ip,
            "packet_count": packet_count,
            "details": details
        }
        self.alert_callback(alert)

    def _prune_history(self, now: float):
        # Prune ICMP history
        for ip in list(self.icmp_history.keys()):
            self.icmp_history[ip] = [t for t in self.icmp_history[ip] if now - t <= self.ICMP_WINDOW * 2]
            if not self.icmp_history[ip]:
                del self.icmp_history[ip]
                
        # Prune Port scan history
        for ip in list(self.port_scan_history.keys()):
            self.port_scan_history[ip] = [(t, p) for t, p in self.port_scan_history[ip] if now - t <= self.PORT_SCAN_WINDOW * 2]
            if not self.port_scan_history[ip]:
                del self.port_scan_history[ip]
                
        # Prune DNS history
        for ip in list(self.dns_history.keys()):
            self.dns_history[ip] = [(t, d) for t, d in self.dns_history[ip] if now - t <= self.DNS_TUNNEL_WINDOW * 2]
            if not self.dns_history[ip]:
                del self.dns_history[ip]
                
        # Prune cooldowns
        for key in list(self.cooldowns.keys()):
            if now - self.cooldowns[key] > self.COOLDOWN_PERIOD * 2:
                del self.cooldowns[key]
