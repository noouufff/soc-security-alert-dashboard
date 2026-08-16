# 🛡️ SOC Security Alert & Incident Command Dashboard

An interactive defensive cybersecurity platform simulating a Security Operations Center (SOC) workflow. The application ingests multi-source security telemetry, correlates events against heuristic detection rules mapped to the **MITRE ATT&CK** framework, and provides a real-time triage interface for security analysts.

---

## 🚀 Key Features & Detection Capabilities

- **Automated SIEM Telemetry Correlation**: Ingests authentication, firewall, and web traffic logs.
- **MITRE ATT&CK Mapping**:
  - `T1110.001` — Repeated Failed Logins (SSH / Auth Brute-Force).
  - `T1110.003` — Password Spraying across multiple accounts.
  - `T1071` — Threat Intelligence Hits (Known Tor Exit Nodes & C2 Indicators).
  - `T1078.001` — Anomalous After-Hours Administrative Logins.
  - `T1048` — Abnormal Data Exfiltration Spikes (>25 MB outbound).
  - `T1046` — Network Port Scan Reconnaissance.
- **Analyst Triage Matrix**: Interactive severity filtering, status management (`New`, `In Progress`, `Resolved`, `False Positive`), and actionable containment playbooks.

---

## 🛠️ Tech Stack

- **Backend**: Python 3, Flask REST API
- **Frontend**: Tailwind CSS, HTML5, Vanilla JavaScript
- **Detection & Correlation**: Python Heuristics Engine

---

## ⚙️ Local Installation & Run

1. **Clone the repository:**
   ```bash
   git clone https://github.com/noouufff/soc-security-alert-dashboard.git
   cd soc-security-alert-dashboard

  2.  pip install -r requirements.txt
  3.  http://127.0.0.1:5000
  4.  To expose the dashboard via a public TLS tunnel for live demonstrations:
ssh -R 80:127.0.0.1:5000 nokey@localhost.run
3. Click the green button **`Commit changes`** on the top right.

Now all 4 steps plus the public access command will be fully visible!

   
