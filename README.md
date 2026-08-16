# 🛡️ SOC Security Alert & Incident Command Dashboard

An interactive defensive cybersecurity platform simulating a Security Operations Center (SOC) workflow. The application ingests multi-source security telemetry, correlates events against heuristic detection rules mapped to the **MITRE ATT&CK** framework, and provides a real-time triage interface for security analysts.

---

## 📌 Project Overview
This project simulates real-world Security Operations Center operations:
1. Telemetry Ingestion: Ingests authentication logs, firewall records, and network traffic flows.
2. Rule-Based Correlation Engine: Real-time heuristic parsing and threat scoring.
3. Analyst Command Dashboard: Live alert triage matrix, severity indicators, and actionable containment playbooks.

---

## 🎯 Threat Detection & MITRE ATT&CK Mapping

| Rule Name | Severity | MITRE ATT&CK ID | Description & Heuristic Trigger |
| :--- | :--- | :--- | :--- |
| **Auth Brute-Force** | `HIGH` | `T1110.001` | 4 or more failed authentication attempts on a single account within 5 minutes. |
| **Password Spraying** | `CRITICAL` | `T1110.003` | Single source IP attempting logins across 3 or more distinct user accounts. |
| **Threat Intel Hit** | `CRITICAL` | `T1071` | Inbound traffic matching known Tor Exit Nodes or malicious C2 infrastructure. |
| **Off-Hours Privileged Login** | `MEDIUM` | `T1078.001` | Administrative/root session established between 00:00 - 05:00 UTC. |
| **Abnormal Data Exfiltration** | `CRITICAL` | `T1048` | Outbound single data transfer spike exceeding 25 MB. |
| **Port Reconnaissance** | `LOW` | `T1046` | Single IP probing 5 or more distinct destination ports. |

---

## 🛠️ Tech Stack
- Backend: Python 3, Flask REST API
- Frontend: Tailwind CSS, HTML5, Vanilla JavaScript
- Detection & Correlation: Python Heuristics Engine

---

## ⚙️ Local Installation & Run

1. Clone the repository:
git clone https://github.com/noouufff/soc-security-alert-dashboard.git
cd soc-security-alert-dashboard

2. Install dependencies:
pip install -r requirements.txt

3. Start the SOC server:
python app.py

4. Access the dashboard:
http://127.0.0.1:5000

---

## 🌐 Public Deployment & Remote Access

To expose the dashboard via a public TLS tunnel for live demonstrations:
ssh -R 80:127.0.0.1:5000 nokey@localhost.run
