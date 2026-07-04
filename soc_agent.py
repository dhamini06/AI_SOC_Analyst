import os
import json
import time
import threading
from typing import Dict, List, Optional
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from capture_engine import CaptureEngine
from detector import Detector

# Define target JSON file path
ALERTS_FILE = "alerts.json"

# Define the Pydantic schema for structured Gemini output
class SecurityInvestigation(BaseModel):
    threat_classification: str = Field(description="Categorize the threat (e.g. Ping Flood, Port Scan, DNS Tunneling, Normal, Suspicious)")
    risk_score: int = Field(description="Risk rating from 0 (Safe) to 100 (Critical)")
    incident_summary: str = Field(description="An overview of what occurred, explaining why this activity is suspicious")
    recommended_actions: List[str] = Field(description="Checklist of remediation and defense actions (3-5 items)")

class SOCAgent:
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        
        # Initialize Gemini Client if key is available
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.client = None
        if self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
                print("[SOC Agent] Gemini Client initialized successfully.")
            except Exception as e:
                print(f"[SOC Agent] Warning: Failed to initialize Gemini Client: {e}")
        else:
            print("[SOC Agent] Warning: GEMINI_API_KEY environment variable not set. Running in Offline Rule Mode.")

        # Initialize detector and capture engine
        self.detector = Detector(alert_callback=self.handle_alert)
        self.capture_engine = CaptureEngine(interface=self.interface, callback=self.detector.process_packet)
        self.lock = threading.Lock()

    def start(self):
        """Starts the capture engine."""
        self.capture_engine.start()

    def stop(self):
        """Stops the capture engine."""
        self.capture_engine.stop()

    def handle_alert(self, alert: Dict):
        """
        Callback triggered by the Detector. Enriches the alert with AI analysis
        and writes it to alerts.json.
        """
        print(f"\n[SOC Agent] ALERT TRIGGERED: {alert['alert_type']} from {alert['source_ip']}")
        
        # Investigate using Gemini
        ai_result = self.investigate_with_gemini(alert)
        
        # Enrich the alert dictionary
        alert["ai_analysis"] = ai_result
        
        # Save to alerts.json
        self.save_alert(alert)

    def investigate_with_gemini(self, alert: Dict) -> Dict:
        """
        Sends the alert to Gemini to get a structured threat analysis.
        Falls back to offline rule-based templates if the API key is missing or fails.
        """
        prompt = f"""
You are an expert Lead SOC Analyst.
Analyze the following raw network intrusion alert:

Alert Metadata:
- ID: {alert['alert_id']}
- Type: {alert['alert_type']}
- Severity: {alert['severity']}
- Source IP: {alert['source_ip']}
- Packet Count: {alert['packet_count']}
- Detection Details: {alert['details']}

Perform a security investigation and return your findings.
"""
        if self.client:
            try:
                print(f"[SOC Agent] Sending alert {alert['alert_id']} to Gemini for analysis...")
                response = self.client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=SecurityInvestigation,
                        temperature=0.2
                    )
                )
                
                # Parse JSON output from response
                analysis_dict = json.loads(response.text)
                print(f"[SOC Agent] Gemini investigation completed (Risk Score: {analysis_dict.get('risk_score')})")
                return analysis_dict
                
            except Exception as e:
                print(f"[SOC Agent] Gemini investigation failed: {e}. Falling back to offline mode.")
        
        # Offline fallback if API key is missing or fails
        return self.get_offline_investigation(alert)

    def get_offline_investigation(self, alert: Dict) -> Dict:
        """
        Generates standard security response content if offline or Gemini fails.
        """
        threat_type = alert["alert_type"]
        ip = alert["source_ip"]
        
        if "ICMP" in threat_type:
            return {
                "threat_classification": "ICMP Flood / Ping Sweep (Local Detection)",
                "risk_score": 60,
                "incident_summary": f"High volume of ICMP Echo requests detected from host {ip}. This is characteristic of reconnaissance scans (host discovery) or a Denial of Service (DoS) ping flood attempt targeting local assets.",
                "recommended_actions": [
                    "Verify if host is authorized to perform monitoring/audits.",
                    "Configure local firewalls (e.g., iptables/ufw) to rate-limit ICMP traffic.",
                    "Verify if other security logs report system degradation on the target host."
                ]
            }
        elif "Port" in threat_type:
            return {
                "threat_classification": "TCP Port Scanning / Reconnaissance (Local Detection)",
                "risk_score": 75,
                "incident_summary": f"Host {ip} was observed scanning multiple TCP ports in a very short duration. This strongly suggests scanning reconnaissance to identify active services and vulnerabilities.",
                "recommended_actions": [
                    "Check network access lists (ACLs) and block the source IP if it is unauthorized.",
                    "Inspect system logs on the target system for successful authentication attempts from this IP.",
                    "Validate firewall rules to ensure unneeded services are blocked."
                ]
            }
        elif "DNS" in threat_type:
            return {
                "threat_classification": "DNS Tunneling / Data Exfiltration (Local Detection)",
                "risk_score": 90,
                "incident_summary": f"Detected query names containing long subdomains from {ip}. This signature matches DNS tunneling techniques where internal data is encoded and exfiltrated via UDP 53 query channels.",
                "recommended_actions": [
                    "Isolate the source host immediately from the network.",
                    "Analyze DNS server logs to see the volume and destinations of these tunneling queries.",
                    "Review active processes on the source host for suspicious beaconing scripts or malware."
                ]
            }
        else:
            return {
                "threat_classification": "Suspicious Activity (Local Detection)",
                "risk_score": 50,
                "incident_summary": f"Suspicious network behavior detected from source host {ip}. Detailed signature information is unavailable.",
                "recommended_actions": [
                    "Investigate host activity history.",
                    "Monitor connection logs for further deviations from baseline traffic."
                ]
            }

    def save_alert(self, alert: Dict):
        """Reads alerts.json, appends the new alert, and writes it back safely."""
        with self.lock:
            alerts = []
            if os.path.exists(ALERTS_FILE):
                try:
                    with open(ALERTS_FILE, "r") as f:
                        alerts = json.load(f)
                except Exception as e:
                    print(f"[SOC Agent] Error reading alerts file: {e}. Starting fresh.")
                    alerts = []
            
            alerts.append(alert)
            
            # Keep only the last 100 alerts to save space and maintain performance
            if len(alerts) > 100:
                alerts = alerts[-100:]
                
            try:
                with open(ALERTS_FILE, "w") as f:
                    json.dump(alerts, f, indent=4)
            except Exception as e:
                print(f"[SOC Agent] Error writing to alerts file: {e}")

if __name__ == "__main__":
    # If run standalone, run the agent for 60 seconds capturing simulated threats
    print("=== Starting Standalone AI SOC Agent (60-second trial run) ===")
    agent = SOCAgent()
    agent.start()
    
    # Trigger a port scan simulation in 5 seconds to test
    def trigger_test():
        time.sleep(5)
        print("\n--- Injecting Simulated Port Scan ---")
        agent.capture_engine.trigger_simulated_threat("port_scan")
        
    threading.Thread(target=trigger_test, daemon=True).start()
    
    try:
        time.sleep(40)
    except KeyboardInterrupt:
        pass
    
    print("\nStopping Agent...")
    agent.stop()
    print("Done.")