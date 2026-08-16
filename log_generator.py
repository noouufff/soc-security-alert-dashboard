"""
Log Generator for SOC Simulation
Produces realistic authentication, firewall, and network logs containing both legitimate
baseline traffic and injected attack patterns.
"""

import json
from datetime import datetime, timedelta, timezone

def generate_sample_logs():
    base_time = datetime.now(timezone.utc) - timedelta(hours=3)
    logs = []

    def make_ts(offset_mins):
        return (base_time + timedelta(minutes=offset_mins)).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Normal Operations Baseline
    logs.append({"timestamp": make_ts(10), "event_type": "auth", "username": "alice", "src_ip": "192.168.1.50", "status": "SUCCESS", "service": "SSH"})
    logs.append({"timestamp": make_ts(12), "event_type": "auth", "username": "bob", "src_ip": "192.168.1.55", "status": "SUCCESS", "service": "WEB_PORTAL"})
    logs.append({"timestamp": make_ts(15), "event_type": "network", "src_ip": "192.168.1.50", "dest_ip": "8.8.8.8", "dest_port": 53, "bytes_sent": 512, "action": "ALLOWED"})

    # 2. Attack Scenario A: SSH Brute Force against 'db_admin'
    for i in range(5):
        logs.append({
            "timestamp": make_ts(20 + i),
            "event_type": "auth",
            "username": "db_admin",
            "src_ip": "198.51.100.44",
            "status": "FAILURE",
            "service": "SSH"
        })

    # 3. Attack Scenario B: Password Spraying across corporate users
    target_users = ["jdoe", "asmith", "finance_lead", "hr_team", "ceo"]
    for i, user in enumerate(target_users):
        logs.append({
            "timestamp": make_ts(35 + (i * 2)),
            "event_type": "auth",
            "username": user,
            "src_ip": "203.0.113.89",
            "status": "FAILURE",
            "service": "O365_SSO"
        })

    # 4. Attack Scenario C: Threat Intelligence hit from Tor Exit Node
    logs.append({
        "timestamp": make_ts(45),
        "event_type": "web_access",
        "username": "guest",
        "src_ip": "185.220.101.5",
        "dest_host": "api.internal.corp",
        "action": "ALLOWED",
        "http_status": 200,
        "endpoint": "/api/v1/auth"
    })

    # 5. Attack Scenario D: Off-Hours Root Login (02:15 UTC)
    off_hour_ts = base_time.replace(hour=2, minute=15).strftime("%Y-%m-%d %H:%M:%S UTC")
    logs.append({
        "timestamp": off_hour_ts,
        "event_type": "auth",
        "username": "root",
        "src_ip": "10.0.4.15",
        "status": "SUCCESS",
        "service": "PAM_SUDO"
    })

    # 6. Attack Scenario E: Data Exfiltration via External HTTPS
    logs.append({
        "timestamp": make_ts(75),
        "event_type": "network",
        "src_ip": "10.0.10.88",
        "dest_ip": "198.51.100.200",
        "dest_port": 443,
        "bytes_sent": 84500000,  # ~80.5 MB
        "action": "ALLOWED"
    })

    # 7. Attack Scenario F: Port Reconnaissance Scan
    scan_ports = [21, 22, 23, 80, 443, 445, 3389, 8080]
    for port in scan_ports:
        logs.append({
            "timestamp": make_ts(90),
            "event_type": "network",
            "src_ip": "93.184.216.34",
            "dest_ip": "10.0.0.1",
            "dest_port": port,
            "bytes_sent": 64,
            "action": "DROPPED"
        })

    return logs

if __name__ == "__main__":
    logs = generate_sample_logs()
    with open("sample_logs.json", "w") as f:
        json.dump(logs, f, indent=2)
    print(f"Generated {len(logs)} logs in sample_logs.json")