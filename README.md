# Aegis AI Defender 🛡️
### Autonomous Cyber Defense, Vulnerability Assessment & Critical Alert Routing Platform

Aegis AI is an enterprise-grade cyber defense and vulnerability management platform inspired by the Darktrace **Cyber AI Loop** (*Prevent, Detect, Respond, Heal*) and aligned with the **Seven Pillars of DoD Zero Trust**.

---

## 🚀 Key Capabilities

### 1. 🛡️ Prevent: Comprehensive Attack Surface Assessment
- **High-Concurrency Port Scanner**: Asynchronous TCP/UDP discovery engine probing custom ports or top enterprise services.
- **Service Fingerprinting & Banner Grabbing**: Protocol negotiation for HTTP, SSH, FTP, SMTP, SMB, DNS, MySQL, Postgres, Redis, and more.
- **Automated CVE & CPE Mapping**: Correlates discovered services against authoritative vulnerability definitions.
- **Declarative Security Checks**:
  - TLS/SSL cipher suite analysis & certificate validation.
  - HTTP security header audits (CSP, CORS, HSTS, Actuator endpoints).
  - SMB signing & null session detection.
  - DNS zone transfer (`AXFR`) auditing.
- **Executive HTML Assessment Reports**: Stripe/Palantir-grade executive reports with TruRisk posture gauges (A+ to F), CISA KEV indicators, technical proof blocks, and printable print stylesheets.

### 2. 👁️ Detect: Real-Time Network Telemetry & Behavioral AI
- **Continuous Network Activity Monitoring**: Real-time socket and connection tracking with interactive network topology HUD.
- **Rolling Behavioral Baselines**: Sliding-window statistical z-score engine detecting connection rate spikes, abnormal outbound volume, and novel destinations.
- **Pre-Built Threat Detection Patterns**:
  - `AEGIS-BEH-001`: Port Scanning Activity
  - `AEGIS-BEH-002`: C2 Beaconing Patterns
  - `AEGIS-BEH-003`: Large Outbound Data Exfiltration
  - `AEGIS-BEH-004`: Malicious Remote Ports
  - `AEGIS-BEH-005`: Lateral Movement
  - `AEGIS-BEH-006`: DNS Tunneling
  - `AEGIS-BEH-007`: Authentication Brute Force Spikes
  - `AEGIS-BEH-008`: Anonymous Proxy & Tor Egress
  - `AEGIS-BEH-010`: SMB Ransomware Propagation
  - `AEGIS-BEH-012`: Target DNS Drift Detection
- **AI Analyst Incident Correlation**: Groups behavioral alerts by MITRE ATT&CK tactics into correlated security incident narratives.

### 3. ⚡ Respond: Host-Level Containment & Remediation
- **Process Termination**: Instantly halts malicious or suspicious processes while safeguarding core Windows system processes.
- **Firewall IP Isolation**: Generates Windows Defender Firewall rules (`netsh advfirewall`) to block inbound and outbound communication with attacker IPs.
- **Socket Session Termination**: Disconnects active socket connections holding malicious sessions.

### 4. 🚨 Critical Alert Routing & DoD Zero Trust Escalation
- **Autonomous Cascading Dispatch**:
  - **Primary**: Telegram Bot / WhatsApp Cloud API / Webhook (interactive buttons).
  - **Fallback**: Local Ghanaian SMS via **Arkesel** or **Hubtel** (sub-10s delivery across MTN, Telecel, and AT networks).
  - **Out-of-Band (OOB)**: Physical serial 4G/LTE modem (`AT+CMGS` on `COM3`) for air-gapped critical emergency dispatch.
- **Zero Trust Cryptographic Triage Links**: Outbound SMS/chat alerts contain **no sensitive IP or CVE details**; alerts include short-lived HMAC-SHA256 tokens requiring authentication.
- **Dead-Man Escalation Matrix**:
  - `T + 0 min`: Dispatches to primary on-call responder.
  - `T + 5 min`: Escalates to SOC Team Lead if unacknowledged.
  - `T + 10 min`: Escalates to Incident Commander.
- **Flap Damping & Storm Control**: Prevents notification storms with sliding-window deduplication and rate limiting.
- **Dead-Man Canary Heartbeat**: Pings an off-premises watchdog to alert if Aegis is killed or silenced by an adversary.

### 5. 🌐 Multi-Source Threat Intelligence Connectors
- **CISA KEV Catalog**: Authoritative exploited vulnerabilities list.
- **NIST NVD 2.0 API**: CVE scoring and CVSS v3.1 vectors.
- **FIRST.org EPSS**: Machine-learning exploit prediction scoring.
- **Abuse.ch ThreatFox**: Malware C2 and payload indicators.
- **AbuseIPDB**: Crowdsourced malicious IP reputation checks.
- **AlienVault OTX**: Threat pulses and adversary infrastructure tracking.

---

## 🏛️ Alignment with Seven Pillars of DoD Zero Trust

| Pillar | Aegis Capability |
|---|---|
| **User** | Authentication brute force spike detection; SSH root login audits. |
| **Device** | Host OS fingerprinting; behavioral profiles; host containment via process & IP isolation. |
| **Application & Workload** | Automated CPE-to-CVE matching; declarative HTTP/TLS misconfiguration auditing. |
| **Data** | Outbound exfiltration spike detection; sensitive path checks. |
| **Network & Environment** | Port discovery; SMB lateral movement detection; C2 beaconing alerts; Windows firewall policy enforcement. |
| **Automation & Orchestration** | Playbook correlation; automated cascading alert dispatch; local containment execution. |
| **Visibility & Analytics** | Executive HTML reports; live WebSocket network activity map; composite TruRisk scoring. |

---

## 🛠️ Quick Start

### Prerequisites
- Python 3.10+
- Windows 10/11 or Windows Server (for native firewall containment)

### Installation
```bash
# Clone the repository
git clone https://github.com/Debrino2525/Aegis-AI-Defender.git
cd Aegis-AI-Defender

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
```

### Starting the Platform
```bash
# Run with python directly
python -m uvicorn server:app --host 0.0.0.0 --port 8000

# Or launch via the included launcher batch file
START_AEGIS.bat
```

Open your browser to:
```
http://localhost:8000
```

---

## ⚙️ Configuration & Settings

You can configure all Threat Intelligence feeds, SMS gateways, and on-call responders directly in the UI under **Settings** (gear icon in sidebar), or by editing `.env`:

```env
# NIST NVD 2.0 API Key (Increases rate limit by 10x)
NVD_API_KEY=

# Local Ghana SMS Gateways (MTN, Telecel, AT)
ARKESEL_API_KEY=
ARKESEL_SENDER_ID=AegisAI

HUBTEL_CLIENT_ID=
HUBTEL_CLIENT_SECRET=
HUBTEL_SENDER_ID=AegisAI

# ChatOps Messaging Gateways
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
WHATSAPP_API_TOKEN=
WHATSAPP_PHONE_NUMBER_ID=

# Cellular Serial Modem (Out-of-Band)
MODEM_SERIAL_PORT=COM3
MODEM_BAUDRATE=115200

# Dead-Man Canary Heartbeat
CANARY_HEARTBEAT_URL=
```

---

## 🧪 Testing

Run the full automated test suite:
```bash
python tests/test_alerting.py
```

---

## 📄 License
Proprietary & Confidential — Globitech Ghana / Aegis AI Defense Team.
