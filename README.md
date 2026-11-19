# SentinelAI: Threat Intelligence & SIEM Log Anomaly Detector

SentinelAI is an intelligent SIEM (Security Information and Event Management) log analysis engine designed to detect multi-stage cyber attacks, map anomalous behaviors to the MITRE ATT&CK framework, and generate actionable SOC remediation playbooks.

---

## 🔍 The Problem
Modern Security Operations Centers (SOCs) ingest millions of disparate log lines per day across firewalls, authentication gateways, web servers, and cloud audit trails. Traditional alert filters suffer from two fatal flaws:
1. **Alert Fatigue**: Thousands of low-priority, disconnected alerts overwhelm analysts.
2. **Failure to Correlate Multi-Stage Attacks**: Stealthy adversaries mask their tracks by spacing out brute-force credential stuffing, lateral movement, privilege escalation, and data staging across different services.

## 💡 The Solution
SentinelAI provides a unified threat correlation and response engine:
1. **Multi-Format Log Parser**: Ingests Syslog (RFC 3164/5424), ArcSight CEF, JSON, and Web Access logs into normalized schema events.
2. **Heuristic & Signature Detection**: Flags known RCE signatures (Log4Shell, SQL injection, directory traversal, reverse shells) and statistical brute-force clusters.
3. **Multi-Stage Attack Correlator**: Links separate actions across time (e.g., authentication failures -> successful login -> `sudo` privilege escalation).
4. **MITRE ATT&CK Mapping**: Automatically maps detected techniques to standard tactics (Initial Access, Credential Access, Privilege Escalation, Discovery).
5. **Automated SOC Playbook Generator**: Synthesizes host firewall blocks (`iptables`), user credential revocation, and process memory forensics with target SLA containment estimates.

---

## 🏛️ System Architecture

```
Raw Multi-Format Logs (Syslog, CEF, JSON, Web)
                      │
                      ▼
             [Log Parser Engine]
                      │ (Normalized Events)
                      ▼
     ┌─────────────────────────────────┐
     │   Anomaly & Exploit Detector    │
     │  - Brute Force Clustering       │
     │  - RCE / LFI / SQLi Signatures  │
     │  - Web Reconnaissance Scans     │
     └────────────────┬────────────────┘
                      │
                      ▼
          [Multi-Stage Correlator]
                      │
                      ▼
         [MITRE ATT&CK Matrix Tagger]
                      │
                      ▼
        [SOC Playbook Synthesizer]
                      │
                      ▼
     Interactive SOC Console & REST API
```

---

## 🛠️ Technology Stack
- **Backend**: Python 3.11, FastAPI, Pydantic v2
- **Threat Intelligence**: MITRE ATT&CK Enterprise Matrix
- **Testing**: Pytest, Starlette TestClient
- **Frontend**: Dark-Mode SOC Operations Dashboard (Tailwind CSS, FontAwesome)
- **Deployment**: Docker, Docker Compose, GitHub Actions CI

---

## 🚀 Getting Started

### Installation
```bash
cd sentinel-ai-security-log-analyzer

# Create virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### Running the Application
```bash
python -m uvicorn app.main:app --reload --port 8002
```
Access the SOC Console at `http://localhost:8002` or inspect OpenAPI docs at `http://localhost:8002/docs`.

---

## 🧪 Running Automated Tests
```bash
pytest tests/ -v
```

---

## 🐳 Docker Deployment
```bash
docker compose up --build
```
Navigate to `http://localhost:8002`.

---

## 📡 API Reference

### Analyze Security Log Stream
`POST /api/logs/analyze`
```json
{
  "raw_logs": "Oct 11 02:14:10 edge-server sshd[3101]: Failed password for invalid user admin from 198.51.100.44 port 38221 ssh2\n..."
}
```

Response:
```json
{
  "incident_id": "INC-79A1B2C3",
  "total_logs_analyzed": 8,
  "anomalies_detected": 1,
  "attack_detected": true,
  "overall_severity": "CRITICAL",
  "attack_summary": "Multi-stage intrusion campaign confirmed...",
  "alerts": [
    {
      "alert_id": "ALT-BRUTE-198_51_100_44",
      "severity": "HIGH",
      "title": "Distributed / High-Frequency Brute Force Authentication",
      "source_ip": "198.51.100.44",
      "mitre_technique": {
        "technique_id": "T1110",
        "tactic": "Credential Access",
        "name": "Brute Force"
      }
    }
  ],
  "mitre_tactics_observed": ["Credential Access", "Initial Access", "Privilege Escalation"],
  "playbook": {
    "incident_type": "Automated Intrusion Containment & Forensics",
    "remediation_steps": [
      {
        "step_number": 1,
        "action_type": "FIREWALL_BLOCK",
        "command": "iptables -I INPUT 1 -s 198.51.100.44 -j DROP",
        "automated": true
      }
    ]
  }
}
```

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

