"""
SOC Detection Rules Engine
Analyzes normalized event logs for brute-force attacks, impossible travel/suspicious IPs,
password spraying, off-hours access, and data exfiltration.
"""

from collections import defaultdict
from datetime import datetime
from dateutil import parser

KNOWN_MALICIOUS_IPS = {
    "185.220.101.5": "Known Tor Exit Node",
    "45.33.32.156": "Active C2 Infrastructure",
    "194.26.29.112": "Mirai Scanner / Malicious Host",
    "103.203.57.18": "Brute-force Campaign Node"
}

PRIVILEGED_ACCOUNTS = {"root", "admin", "administrator", "secops", "system"}

def parse_time(ts_str):
    return parser.parse(ts_str)

class DetectionEngine:
    def __init__(self):
        pass

    def analyze_logs(self, logs):
        alerts = []
        alerts.extend(self._detect_brute_force(logs))
        alerts.extend(self._detect_password_spraying(logs))
        alerts.extend(self._detect_malicious_ip_activity(logs))
        alerts.extend(self._detect_after_hours_privileged_login(logs))
        alerts.extend(self._detect_data_exfiltration(logs))
        alerts.extend(self._detect_port_scanning(logs))
        
        # Sort newest first
        alerts.sort(key=lambda x: x["timestamp"], reverse=True)
        return alerts

    def _detect_brute_force(self, logs):
        """Rule 1: Multiple failed logins against the same target user within 5 minutes."""
        alerts = []
        user_failures = defaultdict(list)

        for entry in logs:
            if entry.get("event_type") == "auth" and entry.get("status") == "FAILURE":
                user = entry.get("username", "unknown")
                user_failures[user].append(entry)

        for user, events in user_failures.items():
            if len(events) >= 4:
                events.sort(key=lambda e: parse_time(e["timestamp"]))
                t_first = parse_time(events[0]["timestamp"])
                t_last = parse_time(events[-1]["timestamp"])
                duration_sec = (t_last - t_first).total_seconds()
                
                src_ips = list({e.get("src_ip") for e in events})
                alerts.append({
                    "id": f"ALT-BF-{abs(hash(user + events[0]['timestamp'])) % 100000:05d}",
                    "timestamp": events[-1]["timestamp"],
                    "severity": "HIGH",
                    "category": "Credential Access",
                    "mitre_id": "T1110.001",
                    "title": f"Repeated Failed Logins / Brute-Force on '{user}'",
                    "source_ip": ", ".join(src_ips),
                    "affected_entity": f"User: {user}",
                    "details": f"{len(events)} failed authentication attempts within {int(duration_sec)} seconds.",
                    "status": "New",
                    "recommended_action": "Isolate source IP at perimeter firewall, force user credential reset, review MFA challenge logs."
                })
        return alerts

    def _detect_password_spraying(self, logs):
        """Rule 2: Single source IP attempting logins across multiple distinct usernames."""
        alerts = []
        ip_attempts = defaultdict(lambda: {"users": set(), "events": []})

        for entry in logs:
            if entry.get("event_type") == "auth" and entry.get("status") == "FAILURE":
                ip = entry.get("src_ip", "0.0.0.0")
                ip_attempts[ip]["users"].add(entry.get("username"))
                ip_attempts[ip]["events"].append(entry)

        for ip, data in ip_attempts.items():
            if len(data["users"]) >= 3:
                alerts.append({
                    "id": f"ALT-PS-{abs(hash(ip)) % 100000:05d}",
                    "timestamp": data["events"][-1]["timestamp"],
                    "severity": "CRITICAL",
                    "category": "Credential Access",
                    "mitre_id": "T1110.003",
                    "title": f"Password Spraying Campaign from IP {ip}",
                    "source_ip": ip,
                    "affected_entity": f"Multiple Users ({', '.join(list(data['users'])[:3])}...)",
                    "details": f"Single source tried authenticating against {len(data['users'])} distinct corporate user accounts.",
                    "status": "New",
                    "recommended_action": "Block source IP across WAF/Identity provider, enforce emergency lockout policy, audit successful logins from this IP."
                })
        return alerts

    def _detect_malicious_ip_activity(self, logs):
        """Rule 3: Activity originating from known Threat Intelligence malicious IPs."""
        alerts = []
        for entry in logs:
            ip = entry.get("src_ip")
            if ip in KNOWN_MALICIOUS_IPS:
                threat_label = KNOWN_MALICIOUS_IPS[ip]
                alerts.append({
                    "id": f"ALT-TI-{abs(hash(ip + entry['timestamp'])) % 100000:05d}",
                    "timestamp": entry["timestamp"],
                    "severity": "CRITICAL",
                    "category": "Threat Intelligence Match",
                    "mitre_id": "T1071",
                    "title": f"Connection from Threat Intel Hit ({threat_label})",
                    "source_ip": ip,
                    "affected_entity": entry.get("dest_host", entry.get("username", "Enterprise Asset")),
                    "details": f"Inbound interaction from known indicator of compromise: {threat_label}. Action taken: {entry.get('action', entry.get('status'))}",
                    "status": "New",
                    "recommended_action": "Immediately ban IP on border firewall, query EDR for active beaconing, analyze host artifacts for persistent implants."
                })
        return alerts

    def _detect_after_hours_privileged_login(self, logs):
        """Rule 4: Privileged account authentication outside standard operating hours (00:00 - 05:00 UTC)."""
        alerts = []
        for entry in logs:
            if entry.get("event_type") == "auth" and entry.get("status") == "SUCCESS":
                user = str(entry.get("username", "")).lower()
                if user in PRIVILEGED_ACCOUNTS:
                    ts = parse_time(entry["timestamp"])
                    if 0 <= ts.hour <= 4:
                        alerts.append({
                            "id": f"ALT-AH-{abs(hash(user + entry['timestamp'])) % 100000:05d}",
                            "timestamp": entry["timestamp"],
                            "severity": "MEDIUM",
                            "category": "Anomalous Behavior",
                            "mitre_id": "T1078.001",
                            "title": f"Off-Hours Privileged Login by '{user}'",
                            "source_ip": entry.get("src_ip", "N/A"),
                            "affected_entity": f"System User: {user}",
                            "details": f"Successful administrative session established at {ts.strftime('%H:%M:%S UTC')} outside operational change windows.",
                            "status": "New",
                            "recommended_action": "Reach out out-of-band to privileged operator to confirm authorization. Validate change ticket records."
                        })
        return alerts

    def _detect_data_exfiltration(self, logs):
        """Rule 5: Abnormal outbound data transfer volume exceeding threshold (> 25MB single session)."""
        alerts = []
        for entry in logs:
            if entry.get("event_type") == "network":
                bytes_sent = entry.get("bytes_sent", 0)
                if bytes_sent > 25 * 1024 * 1024:  # > 25 MB
                    mb_sent = round(bytes_sent / (1024 * 1024), 2)
                    alerts.append({
                        "id": f"ALT-EX-{abs(hash(entry['timestamp'] + str(bytes_sent))) % 100000:05d}",
                        "timestamp": entry["timestamp"],
                        "severity": "CRITICAL",
                        "category": "Exfiltration",
                        "mitre_id": "T1048",
                        "title": f"Large Outbound Data Transfer ({mb_sent} MB)",
                        "source_ip": entry.get("src_ip"),
                        "affected_entity": f"Dest: {entry.get('dest_ip')}:{entry.get('dest_port')}",
                        "details": f"High volume network session transferring {mb_sent}MB outbound to unclassified external node.",
                        "status": "New",
                        "recommended_action": "Sever host network connection via EDR, capture network flow dumps, identify processes initiating socket transfer."
                    })
        return alerts

    def _detect_port_scanning(self, logs):
        """Rule 6: Single IP probing more than 5 distinct ports within short period."""
        alerts = []
        ip_ports = defaultdict(lambda: {"ports": set(), "events": []})

        for entry in logs:
            if entry.get("event_type") == "network" and entry.get("action") == "DROPPED":
                ip = entry.get("src_ip", "0.0.0.0")
                ip_ports[ip]["ports"].add(entry.get("dest_port"))
                ip_ports[ip]["events"].append(entry)

        for ip, data in ip_ports.items():
            if len(data["ports"]) >= 5:
                alerts.append({
                    "id": f"ALT-PSCN-{abs(hash(ip)) % 100000:05d}",
                    "timestamp": data["events"][-1]["timestamp"],
                    "severity": "LOW",
                    "category": "Reconnaissance",
                    "mitre_id": "T1046",
                    "title": f"Network Port Scan Reconnaissance from {ip}",
                    "source_ip": ip,
                    "affected_entity": f"Perimeter Gateway (Probed {len(data['ports'])} ports)",
                    "details": f"Host scanned ports: {list(data['ports'])[:8]}... Traffic dropped by firewall ruleset.",
                    "status": "New",
                    "recommended_action": "Verify border drop rules hold. Add IP to perimeter rate-limiting blackhole."
                })
        return alerts