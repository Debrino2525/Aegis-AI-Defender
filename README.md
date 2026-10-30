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
- **Analyst Assist**: Groups behavioral alerts by host, time, and tactic. Multi-phase lists and hop paths appear only when a sample exists. Related detections are other pattern IDs on that host.

### 3. ⚡ Respond: Host-Level Containment & Remediation
- **Process Termination**: Instantly halts malicious or suspicious processes while safeguarding core Windows system processes.
- **Firewall IP Isolation**: Generates Windows Defender Firewall rules (`netsh advfirewall`) to block inbound and outbound communication with attacker IPs.
- **Socket Session Termination**: Disconnects active socket connections holding malicious sessions.

### 4. 🚨 Critical Alert Routing & DoD Zero Trust Escalation
- **Autonomous Cascading Dispatch**:
  - **Primary**: Telegram Bot / WhatsApp Cloud API / Webhook (interactive buttons).
  - **Fallback**: SMS through a configured gateway (Arkesel or Hubtel) after chat dispatch does not succeed.
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
- **Abuse.ch ThreatFox**: Last-day malware IOC snapshot when `THREATFOX_AUTH_KEY` is set. The key is sent as the `Auth-Key` header. The card count is the size of that response.
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
# Listens on 127.0.0.1:8000 unless AEGIS_HOST / AEGIS_PORT say otherwise
python server.py

# Or launch via the included launcher batch file (same default)
START_AEGIS.bat
```

Open your browser to `http://127.0.0.1:8000` and sign in. See [Run securely on this machine](#run-securely-on-this-machine).

---

## Run securely on this machine

Aegis is a single-process console for the operator sitting at this host. It is not a multi-user service, and it does not ship a default password.

1. Copy the template and do not commit the result: `cp .env.example .env`
2. Set an admin credential in the environment or in `.env`:
   - `AEGIS_ADMIN_TOKEN` — bearer token (`Authorization: Bearer <token>`) and the value the browser login form accepts.
   - `AEGIS_ADMIN_PASSWORD` — password for that same form. If no token is set, the password is also accepted as a bearer token.
   - If both are empty, the first start writes a random token to `~/.aegis/admin_token` (file mode `600`) and prints it **once** on stderr. There is no built-in password.
3. Leave `ALERT_SIGNING_KEY` empty. The old example value `aegis-defense-secret-key-zt-2026` was published with the repo and is **rejected**. Aegis generates `~/.aegis/alert_signing_key` and uses that for HMAC triage links. A real `ALERT_SIGNING_KEY` in the environment overrides the file.
4. Start with `python server.py`. The default listen address is `127.0.0.1`. Set `AEGIS_HOST` only when you intend to expose the port. `0.0.0.0` is honored and logged as a warning.
5. Sign in at `http://127.0.0.1:8000`. Containment (`terminate_process`, `block_ip`, `isolate_connections`, resolve) uses the same session or bearer token.

What this build actually enforces:

- HTTP routes under `/api` and both WebSockets (`/ws/monitor`, `/ws/scan/{id}`) require the admin session cookie or bearer token. Exceptions: `/api/alerting/triage/{token}` (the HMAC token is the credential for that one alert) and `/api/fleet/enroll` / `/api/fleet/heartbeat` (one-time enrollment token, then the host’s client certificate). Listing Assets still requires the admin session.
- `GET /api/settings` masks API keys, client secrets, bot tokens, webhook URLs, the canary URL, and the signing key. Saving the masked preview back does not overwrite the stored secret.
- Scan reports, behavioral monitor alerts, and incident containment notes are stored in `~/.aegis/history.sqlite3` and are loaded again after a restart. Critical alert routing was already stored in `~/.aegis/alert_queue.sqlite3`. A scan that was still running when the process died is marked `interrupted`.

Still true, and not fixed here: there are no user accounts, RBAC, or SSO. Host containment is Windows-oriented (`netsh`, process kill). OTX and VirusTotal cards record whether a key is present; they do not perform live lookups. ThreatFox syncs when `THREATFOX_AUTH_KEY` is set. AbuseIPDB syncs its blacklist when `ABUSEIPDB_API_KEY` is set. Do not bind this process on a public interface.

---

## Host agents (fleet)

A thin collector enrolls Windows and Linux hosts into this console. Assets lists only hosts that have sent a real heartbeat. There are no placeholder hosts and no packet tap.

```bash
# On the console: Settings → Host agents → Mint one-time token
# On each server:
python -m aegis.agent enroll --url http://CONSOLE:8000 --token PASTE
python -m aegis.agent run
```

Cert files land in `~/.aegis/agent/` (`ca.crt`, `client.crt`, `client.key`). The site CA lives on the console under `~/.aegis/ca/`. Lab bootstrap can set `AEGIS_ENROLLMENT_TOKEN` in `.env` instead of minting; that value is reusable until rotated. This is not NDR: the agent sends identity, host health, and listen-port counts — not pcap.

Keep the agent running:

```bash
# Linux (systemd). Enroll first.
./scripts/aegis-agent.sh enroll --url https://CONSOLE:8000 --token PASTE --ca /path/to/ca.crt
sudo ./scripts/aegis-agent.sh install --enable
# or, without root: ./scripts/aegis-agent.sh install --user --enable

# Windows. Enroll first, then register a startup task.
scripts\aegis-agent.bat enroll --url https://CONSOLE:8000 --token PASTE --ca C:\path\ca.crt
scripts\aegis-agent.bat install
scripts\aegis-agent.bat start
```

`scripts/aegis-agent.service` is the unit template. For a real Windows service, copy `scripts/aegis-agent.winsw.xml` next to [WinSW](https://github.com/winsw/winsw) renamed `aegis-agent.exe` and run `aegis-agent.exe install`.

Revoke or re-enroll a host from **Assets** or **Settings → Host agents**. A revoked client certificate fails heartbeat. Re-enroll mints a one-time token that reissues a cert for the same agent id; the old fingerprint stays revoked.

### Enable HTTPS and mTLS

HTTP labs still authenticate heartbeats with the signed client PEM. Production should serve HTTPS and require a TLS client certificate on heartbeat.

1. Leave the site CA at `~/.aegis/ca/` (created on console start).
2. Set `AEGIS_TLS=1` in `.env` and point `AEGIS_CONSOLE_URL` at `https://…`.
3. Restart: `python server.py` listens with
   - `--ssl-certfile ~/.aegis/ca/server.crt`
   - `--ssl-keyfile ~/.aegis/ca/server.key`
   - `--ssl-ca-certs ~/.aegis/ca/ca.crt`
   - `ssl_cert_reqs = CERT_OPTIONAL` (handshake still allows the browser and first enroll; TLS 1.2 so the server can request a client certificate without failing clients that do not have one)
4. `/api/fleet/heartbeat` then **requires** a verified client certificate (`CERT_REQUIRED` for the agent). Enroll still uses the one-time token over HTTPS.
5. On the host, copy the site CA and enroll with `--ca`:
   `python -m aegis.agent enroll --url https://CONSOLE:8000 --token PASTE --ca ca.crt`

Optional env:

| Variable | Purpose |
|---|---|
| `AEGIS_TLS_CERTFILE` / `AEGIS_TLS_KEYFILE` | Let's Encrypt (or other) server cert instead of the site CA server cert. Client certs are still verified against the site CA. |
| `AEGIS_TLS_CA_CERTS` | CA used to verify agent client certs. Defaults to `~/.aegis/ca/ca.crt`. |
| `AEGIS_TLS_CERT_REQS=required` | Handshake-level `ssl.CERT_REQUIRED` (`--ssl-cert-reqs 2`). Agent-only port: the browser and first enroll cannot connect without a client cert. |
| `AEGIS_TLS_PROXY=1` | Trust `X-SSL-Client-Cert` / `X-SSL-Client-Verify` from nginx. Do not set this unless TLS is terminated in front of Aegis. |

nginx snippet for heartbeat-only `ssl_verify_client on` (CERT_REQUIRED at the terminator):

```nginx
location /api/fleet/heartbeat {
    ssl_verify_client on;
    proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
    proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
    proxy_pass http://127.0.0.1:8000;
}
location /api/fleet/enroll {
    ssl_verify_client off;
    proxy_pass http://127.0.0.1:8000;
}
```

Set `AEGIS_TLS_PROXY=1` when using that terminator. The default site server certificate SAN is `localhost`, `127.0.0.1`, and the console hostname — use `AEGIS_TLS_CERTFILE` for a real DNS name.

---

## ⚙️ Configuration & Settings

You can configure all Threat Intelligence feeds, SMS gateways, and on-call responders directly in the UI under **Settings** (gear icon in sidebar), or by editing `.env`:

```env
# Admin credential. No default password. See "Run securely on this machine".
AEGIS_ADMIN_TOKEN=

# NIST NVD 2.0 API Key (Increases rate limit by 10x)
NVD_API_KEY=

# SMS gateways
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

```bash
pip install pytest
pytest -q
```

`python tests/test_alerting.py` still runs the alert-routing checks on their own. GitHub Actions runs `pytest` on push and pull request.

---

## 📄 License
Proprietary & Confidential — Globitech Ghana / Aegis AI Defense Team.
