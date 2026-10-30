# Aegis AI Defender — Functionality / Performance / Capabilities Audit

Read-and-measure only. No product files were modified. Throwaway scripts and raw JSON live in `_audit_scratch/` (safe to delete).

Host: Python 3.12.3, Linux 6.12.94+ x86_64 (glibc 2.39), IPv4 `127.0.0.1` / `172.30.0.2` / `172.17.0.1`.
Repo path: `/workspace`. Branch of this report: `cursor/functionality-audit-2439`.

---

## PART 1 — Environment and baseline

### 1.1 Python, OS, `pip install`

**VERIFIED-BY-RUNNING**

| Item | Value |
|---|---|
| Python | `3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0]` |
| OS | `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct 27 12:38:43 UTC 2026 x86_64` |
| `pip install -r requirements.txt` | Succeeds cleanly. Second run: every requirement “already satisfied”. Only install-time messages: scripts installed to `/home/ubuntu/.local/bin` not on PATH (`uvicorn`, `httpx`, `fastapi`, `dotenv`, `websockets`, …). No package resolution errors. |

Command:

```
python3 --version && uname -a && python3 -m pip install -r requirements.txt
```

### 1.2 Import errors and deprecation warnings

**VERIFIED-BY-RUNNING** (`python3 _audit_scratch/01_env_and_imports.py`, `python3 _audit_scratch/18_utcnow_warns.py`)

All audited modules import successfully once the warning hook is not broken. Warnings captured:

| Category | Where | Message (trimmed) |
|---|---|---|
| `PydanticDeprecatedSince20` | `aegis/core/config.py:17` | Support for class-based `config` is deprecated, use ConfigDict instead |
| `DeprecationWarning` | `server.py:80` and `server.py:87` | `on_event is deprecated, use lifespan event handlers instead` (`@app.on_event("startup")` / `shutdown`) |
| `DeprecationWarning` | `datetime.utcnow()` when `Finding` is constructed (`aegis/core/models.py:65` default_factory) | `datetime.datetime.utcnow() is deprecated … Use datetime.datetime.now(datetime.UTC)` |

`datetime.utcnow` call sites (VERIFIED-BY-READING): `server.py:185,212,357`, `aegis/core/engine.py:36,77,161`, `aegis/core/models.py:65`, `aegis/database/sync.py:260`, `aegis/monitor/network_monitor.py:198,504,601,629`, `aegis/reporting/html_reporter.py:94`, `aegis/checks/tls_auditor.py:173`.

No import-time failures on this Python 3.12.3.

### 1.3 `python tests/test_alerting.py`

**VERIFIED-BY-RUNNING.** Exit 0. Raw output:

```
[+] test_classifier_behavioral (C2): PASSED
[+] test_classifier_behavioral (Benign): PASSED
[+] test_classifier_scan_finding: PASSED
[+] test_flap_damper_rate_limiting: PASSED
[+] test_sqlite_alert_queue: PASSED
[+] test_security_tokens: PASSED
[+] test_escalation_manager: PASSED

[=== ALL CRITICAL ALERT ROUTING TESTS PASSED ===]
EXIT:0
```

What each test actually asserts (`tests/test_alerting.py`):

| Test | Asserts |
|---|---|
| `test_classifier_behavioral` (C2) | `AEGIS-BEH-002` + severity CRITICAL → `CriticalAlert`; pillars include NETWORK_ENVIRONMENT and DEVICE (L24–42) |
| `test_classifier_behavioral` (Benign) | `AEGIS-BEH-009` MEDIUM Discovery → `classify_behavioral_alert` returns `None` (L44–53) |
| `test_classifier_scan_finding` | CISA KEV + CVSS 9.8 + EPSS 0.85 → `CriticalAlert` CRITICAL with APPLICATION_WORKLOAD pillar (L56–70) |
| `test_flap_damper_rate_limiting` | First `should_dispatch` True count 1; immediate second False and reason contains `"Throttled"` (L73–87). Uses window=60, max=2 — **not** production defaults (900s / 3 in `aegis/alerting/router.py:30`) |
| `test_sqlite_alert_queue` | enqueue new, `get_pending_alerts` length 1, ack, pending empty (L90–120) |
| `test_security_tokens` | valid token payload `aid`/`cid`; expired token invalid with `"expired"`; sanitized public message has no `192.168` and contains triage URL (L123–144) |
| `test_escalation_manager` | CIDR `10.20.0.0/16` maps `10.20.5.12` → env `Core-Banking-VLAN`, timeout 5 (L147–163) |

Not covered by this file: adapters, `AlertRouter` dispatch cascade, canary heartbeat, monitor detectors, scanner, VDB, UI, remediation.

`aegis/intel/test_intel.py` exists but is **not** invoked by `python tests/test_alerting.py`.

### 1.4 Modules with zero test coverage

**VERIFIED-BY-READING.** 56 `.py` files. `tests/test_alerting.py` only imports alerting classifier/dedup/queue/escalation/security/models.

Zero coverage (never imported by that test):

`server.py`, `run.py`, `aegis/__init__.py`, `aegis/alerting/__init__.py`, `aegis/alerting/adapters/{base,modem_oob,sms_local,webhook}.py`, `aegis/alerting/heartbeat.py`, `aegis/alerting/router.py`, `aegis/checks/*`, `aegis/core/*`, `aegis/credentialed/*`, `aegis/database/*`, `aegis/discovery/*`, `aegis/intel/*` (including `test_intel.py` which is a smoke script, not pytest), `aegis/monitor/*`, `aegis/reporting/*`, `aegis/scoring/*`.

### 1.5 Server boot and every GET

**VERIFIED-BY-RUNNING.** Command: `python3 -m uvicorn server:app --host 127.0.0.1 --port 8765`

Uvicorn log (raw):

```
INFO:     Started server process [2904]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8765
```

`~/.aegis/admin_token` does **not** exist on this VM. No Trusted Night gate observed: all GETs below returned without a token. Token was not printed.

**MEASURED** (`python3 _audit_scratch/08_get_endpoints.py`, base `http://127.0.0.1:8765`):

| Path | Status | elapsed_ms | Trimmed JSON shape (keys/types) |
|---|---:|---:|---|
| `/` | 200 | 13.179280000031213 | HTML `text/html; charset=utf-8` len=230997 |
| `/api/scans` | 200 | 1.7157190000034461 | `[]` |
| `/api/scans/DOESNOTEXIST` | 404 | 0.9277179999571672 | `{detail: str}` |
| `/api/scans/DOESNOTEXIST/download/html` | 404 | 1.82 | `{detail: str}` |
| `.../download/csv` | 404 | 0.82 | `{detail: str}` |
| `.../download/sarif` | 404 | 0.68 | `{detail: str}` |
| `.../download/json` | 404 | 0.58 | `{detail: str}` |
| `/api/findings/instructions?finding_id=CVE-1&title=t&target=127.0.0.1&port=80` | 200 | 1.36 | `{method, curl_command, powershell_command, tool: str, steps: [str], expected_vulnerable, expected_remediated: str}` |
| `/api/intelligence` | 200 | 1.65 | `{risk_score:int, risk_label:str, total_assets:int, total_findings:int, severity_totals:{CRITICAL,HIGH,MEDIUM,LOW,INFO:int}, business_risk:{estimated_breach_cost:int, formatted:str, kev_count:int, critical_count:int}, contributing_factors:[{name,count,color,pct}], attack_summary:{tactic_counts, technique_hits, ransomware_cves, tactic_colors}, top_insights:[], tech_categories:{}, hosts:[]}` |
| `/api/threat/feeds` | 200 | 17.00888999999961 | `[{id,name,provider,type,status,auth_required,has_key,record_count,description,signup_url,docs}]` |
| `/api/monitor` | 200 | 1.2328380000212746 | see §3.7 (running, started_at, uptime_seconds, stats, alerts, connections, monitored_targets, graph, baselines, connection_history, alert_summary, incidents) |
| `/api/monitor/targets` | 200 | 0.7163919999584323 | `[]` |
| `/api/alerting/status` | 200 | 1.08 | `{running, total_recent_critical_alerts, unacknowledged_critical_count, contacts_count:int, channels:{sms_local_arkesel,sms_local_hubtel,telegram,whatsapp,generic_webhook,modem_oob_configured:bool}, canary_heartbeat}` |
| `/api/alerting/alerts` | 200 | 1.17 | `[{alert_id,fingerprint,title,severity,summary,source_ip,dest_ip,dest_port,process,tactic,technique,cve_id,cvss_score,epss_score,is_cisa_kev,zt_pillars,…}]` |
| `/api/alerting/triage/invalidtoken` | 403 | 0.79 | `{detail: str}` |
| `/api/settings` | 200 | 0.89 | `{threat_intel:{nvd_api_key,abuseipdb_api_key,otx_api_key,virustotal_api_key:str, has_nvd,has_abuseipdb,has_otx,has_virustotal:bool}, alerting:{arkesel_*, hubtel_*, telegram_*, whatsapp_*, critical_alert_webhook_url, modem_serial_port, modem_baudrate, canary_heartbeat_url, aegis_console_url}}` |
| `/api/alerting/contacts` | 200 | 1.06 | `[{contact_id,name,role,phone,email,telegram_chat_id,whatsapp_number,is_active}]` |
| `/api/alerting/mappings` | 200 | 1.21 | `[{cidr_or_host,environment,owner_team,primary_contact_id,escalation_contact_id,escalation_timeout_mins}]` |
| `/static/index.html` | 200 | 5.15 | HTML len=230997 |
| `/docs` | 200 | 0.90 | HTML len=1026 |
| `/openapi.json` | 200 | 17.24 | `{openapi, info:{title,version}, paths:…}` |

---

## PART 2 — Specific findings (confirm / refute)

### A. `_check_beaconing` flags a persistent long-lived external `:443` as “C2 Beaconing”

**CONFIRMED. VERIFIED-BY-RUNNING** using the real `_sample_connections` path, and again on this machine’s live connections.

Mechanism (VERIFIED-BY-READING `aegis/monitor/network_monitor.py`):

- Every ESTABLISHED non-loopback connection is appended to `conn_history[(laddr,rip,rport)]` once per 5s sample (L210–216).
- `_check_beaconing` (L423–454) looks at ports `{80,443,8080,8443,4444,4443}` for **external** dests, requires `len(timestamps) >= 4`, `stddev < 5.0`, and **`5 < avg_interval < 300`** (strict greater-than 5).

**MEASURED** (`python3 _audit_scratch/03_beaconing.py`):

1. Exact 5.0s injected timestamps: `avg_interval=5.0`, `stddev=0.0`, `5 < avg` is **false**, **no alert**. Boundary case.
2. Real `asyncio.sleep(5)` timestamps: intervals `[5.005463123321533, 5.003056764602661, 5.005340576171875, 5.005254507064819, 5.00532341003418]`, `avg_interval=5.004887676239013`, `stddev=0.0009179241699735565`, **emitted=true**, title `C2 Beaconing Detected: 10.0.0.1 → 9.9.9.9`.
3. Held a real TCP connection to `172.30.0.2:8080` and called `_sample_connections` 6 times with 5s sleeps. History for that 5-tuple: 6 timestamps, intervals `5.067455768585205, 5.0098395347595215, 5.01076078414917, 5.00998330116272, 5.009909629821777`. That dest is RFC1918 so `_check_beaconing` skips it (`is_private_ip`, L426–427). **Same run** emitted `AEGIS-BEH-002` for a **real** external flow already on the box:

```
title: C2 Beaconing Detected: 172.30.0.2 → 34.225.159.174
evidence: Interval: 5.0s ± 0.0s over 4 connections | Key: ('172.30.0.2', '34.225.159.174', 443)
```

4. 10-minute live run (Part 4.2–4.3): **7 of 8 alerts were BEH-002** on persistent `:443` to `34.225.159.174`, `172.65.90.24`, `172.65.90.26`, `20.209.35.129`, `3.92.129.183`. Process names on those sockets included `node` and `MainThread`. These are long-lived HTTPS sessions (Cursor/cloud agent), not C2. Also `AEGIS-BEH-001` because one sample saw 11 unique dest ports (ephemeral high ports).

Conclusion: a persistent ESTABLISHED connection to an external IP:443, sampled every 5s, produces ~5.00x s intervals with near-zero stddev and **is classified CRITICAL C2 Beaconing** after 4 samples (~20s). Dedup key `AEGIS-BEH-002:{src}:{dst}` allows a re-fire after 300s (`_emit_alert` L481–489) — observed at elapsed 30.006474018096924s and again at 330.05485939979553s for `34.225.159.174`.

### B. `RollingStats.z_score` returns 0 when stddev==0; `score_anomaly` averages; 100x spike vs 75

**CONFIRMED. VERIFIED-BY-RUNNING** (`python3 _audit_scratch/02_behavioral.py`) and VERIFIED-BY-READING `aegis/monitor/behavioral_engine.py:41–46,103–127` and `network_monitor.py:297–314`.

Raw z_score cases:

| case | values | probe | mean | stddev | z_score |
|---|---|---:|---:|---:|---:|
| empty | [] | 100 | 0.0 | 0.0 | 0.0 |
| single | [5.0] | 100 | 5.0 | 0.0 | 0.0 |
| flat5 | [5.0]×10 | 500 | 5.0 | 0.0 | 0.0 |
| flat0 | [0.0]×10 | 100 | 0.0 | 0.0 | 0.0 |
| varied | 1,2,3,4,5 | 100 | 3.0 | 1.4142135623730951 | 68.58935777509511 |

After 10 flat samples (`new_connections=1`, all other metrics 0), a **100x spike** `new_connections=100`:

- per-metric z for `new_connections`: **0.0** (stddev 0)
- `score_anomaly` = **0.0**
- `would_alert_at_75`: **false**
- `would_alert_at_45`: **false**

Even a 100x spike in `bytes_sent_delta` after a non-zero flat baseline of 1000 scored **0.0** for the same reason.

Averaging: L127 `return round(min(100.0, sum(scores) / len(scores)), 1)` over metrics with `count >= 5`. A single-metric spike, even if z were huge, is diluted by five other zeros. With stddev==0 it never gets that far.

Alert threshold in `_check_behavioral_anomaly`: **75.0** (HIGH BEH-008) / **45.0** (MEDIUM BEH-009). A flat baseline **can never alert** via this path.

### C. Baseline sample hard-codes `bytes_sent_delta = 0` / `bytes_recv_delta = 0`; `new_connections = len(ports)`

**CONFIRMED. VERIFIED-BY-READING** `aegis/monitor/network_monitor.py:247–258`:

```
sample = {
    "new_connections": len(ports),      # unique dest ports this sample, not new TCP handshakes
    "bytes_sent_delta": 0,
    "bytes_recv_delta": 0,
    ...
}
```

Places bytes data is actually used:

| File:line | Use |
|---|---|
| `network_monitor.py:134–136` | `psutil.net_io_counters()` deltas → `sent_rate`/`recv_rate` for `_check_exfiltration` only |
| `network_monitor.py:138–143` | store last counters |
| `network_monitor.py:250–251` | hard-coded 0 into behavioral sample |
| `behavioral_engine.py:90–91` | `bytes_sent_rate.add(0)` / `bytes_recv_rate.add(0)` every sample |
| `behavioral_engine.py:112` | `bytes_sent_delta` included in `score_anomaly` (always 0 vs 0) |
| `behavioral_engine.py:136` | `avg_bytes_sent` exposed in baseline dict (always 0.0) |
| `threat_patterns.py:71` | `bytes_sent_stddev_multiplier: 3.0` — **never read** |

`bytes_recv_rate` is updated but **not** in the `score_anomaly` metrics list (L110–117).

### D. `_check_exfiltration` uses a fixed 10 MB/s system-wide threshold, not a baseline

**CONFIRMED. VERIFIED-BY-READING** `aegis/monitor/network_monitor.py:456–473`:

```
MB = 1024 * 1024
if sent_rate > 10 * MB:  # >10 MB/s outbound
```

No comparison to `behavioral_engine` stats. Pattern text at `threat_patterns.py:67–71` claims “significantly exceeding established behavioral baseline” / `bytes_sent_stddev_multiplier: 3.0` — that threshold is unused.

### E. AEGIS-BEH-006 (DNS tunneling) and AEGIS-BEH-012; every `_emit_alert` pattern_id vs `THREAT_PATTERNS`

**VERIFIED-BY-READING.** Every `_emit_alert(` call in `network_monitor.py`:

| Line | pattern_id | What the code actually emits | THREAT_PATTERNS name / tactic | Match? |
|---:|---|---|---|---|
| 281 | `AEGIS-BEH-006` | High-Risk Outbound Protocol (SSH/SMTP/DB/… to **external** IP) / tactic Command and Control / T1095 | DNS Tunneling / Exfiltration / T1048.003 | **ID+tactic mismatch** |
| 300 | `AEGIS-BEH-008` | Severe Network Anomaly (score≥75) / Defense Evasion / T1071 | Tor / Anonymous Proxy / T1090.003 | **ID+tactic mismatch** |
| 316 | `AEGIS-BEH-009` | Elevated Baseline Deviation (score≥45) / Discovery / T1046 | Spike in New Outbound Connections / C2 / T1071 | **tactic mismatch** |
| 335 | `AEGIS-BEH-005` | New **External** Destination / Initial Access / T1190 | Lateral Movement — New **Internal** Connection / T1021 | **ID+tactic mismatch** |
| 354 | `AEGIS-BEH-004` | Malicious port | Connection to Known Malicious Port / C2 / T1095 | yes |
| 372 | `AEGIS-BEH-001` | Port scan (`len(ports) >= 10` in one 5s sample) | Port Scan / Discovery / T1046 | yes (window is 5s not 60s) |
| 390 | `AEGIS-BEH-010` | SMB count ≥ 3 | SMB Lateral Movement | partial (counts connections, not unique hosts; no internal-only check) |
| 408 | `AEGIS-BEH-007` | auth_count ≥ 15 | Brute Force | partial (per 5s sample, not per 60s) |
| 440 | `AEGIS-BEH-002` | C2 Beaconing | C2 Beaconing | yes (but see A) |
| 460 | `AEGIS-BEH-003` | Exfil 10 MB/s | Data Exfiltration | partial (fixed rate, not baseline) |
| 637 | `AEGIS-BEH-012` | DNS Drift on **watched target** IP change | **absent from THREAT_PATTERNS** | README lists it; library does not |
| 687 | `AEGIS-BEH-011` | New port on watched host | **absent from THREAT_PATTERNS and README** | extra |

`THREAT_PATTERNS` (`threat_patterns.py:43–144`) defines **001–010 only**. `PATTERN_BY_ID` (L147) is never referenced elsewhere.

**AEGIS-BEH-006 DNS tunneling:** there is **no** code path that counts DNS queries or emits BEH-006 as DNS tunneling. The only BEH-006 emitter is `_check_high_risk_egress`. **README claim is false.**

**AEGIS-BEH-012:** only emitted from `_probe_single_target` when a **watched** target’s resolved IP changes (L635–650). No general “target DNS drift” on arbitrary hosts. Can emit as described **only** after `POST /api/monitor/targets`.

Tor ports 9001/9050/9051 sit in `MALICIOUS_PORTS` (emit BEH-004) and 9001/9050 also in `HIGH_RISK_REMOTE_PORTS` (emit BEH-006). They never emit BEH-008.

### F. `scan_udp` never succeeds; `ScanEngine.run` never calls it

**CONFIRMED. VERIFIED-BY-RUNNING** against a local UDP echo server on `127.0.0.1:18053`.

**MEASURED** (`python3 _audit_scratch/05_udp_scan.py`):

```
scan_udp_against_echo: result=[], error=null, elapsed_s=2.0025070789999972
_probe_udp_port: result=[18053, false], elapsed_s=2.002318410999976
ScanEngine.run_contains_scan_udp: false
```

**MEASURED** with `PYTHONASYNCIODEBUG=1` (`_audit_scratch/05b_udp_debug.py`):

```
gettimeout: 2.0
send: ValueError: the socket must be non-blocking
  File ".../asyncio/selector_events.py", line 600, in sock_sendto
nonblocking_send_to_discard: ok
```

Cause: `sock.settimeout(self.config.connect_timeout)` at `port_scanner.py:38` (blocking+timeout) then `await loop.sock_sendto(...)` at L41. Without debug the probe still returns False after ~2s. `scan_target(..., scan_udp=False)` (L56–68) **ignores** the `scan_udp` flag and only runs TCP `_probe_port`. `ScanEngine.run` (`aegis/core/engine.py:69`) only calls `scan_target`.

### G. `VersionMatcher.normalize_version`: Debian rule before Ubuntu rule

**CONFIRMED. VERIFIED-BY-RUNNING.** Rule order is dict insertion order in `aegis/database/matcher.py:15–29`: OpenSSH `p`, **Debian `X.Y.Z-N`**, RPM, **Ubuntu**, letter suffix, `+`, `~`.

Input `2.4.49-3ubuntu0.1`: Debian-alone → `2.4.49.3ubuntu0.1`; Ubuntu-alone → `2.4.49`; **actual `normalize_version` → `2.4.49.3.ubuntu0.1`** (then letter rule).

Table (≥25 real-world strings). Parses = `packaging.version.parse` succeeds (Y/N):

| input | normalized | parses in | parses out |
|---|---|---|---|
| `8.9p1` | `8.9.1` | N | Y |
| `9.3p2` | `9.3.2` | N | Y |
| `9.8p1` | `9.8.1` | N | Y |
| `OpenSSH_8.9p1` | `openssh_8.9.1` | N | N |
| `2.4.49` | `2.4.49` | Y | Y |
| `2.4.49-1` | `2.4.49.1` | Y | Y |
| `2.4.52-1ubuntu4.8` | `2.4.52.1.ubuntu4.8` | N | N |
| `1.18.0-0ubuntu1.4` | `1.18.0.0.ubuntu1.4` | N | N |
| `1.1.1f-1ubuntu2.22` | `1.1.1.f-1ubuntu2.22` | N | N |
| `1.1.1w` | `1.1.1.w` | N | N |
| `8.0.36-log` | `8.0.36-log` | N | N |
| `8.0.36` | `8.0.36` | Y | Y |
| `10.11.6-MariaDB` | `10.11.6-mariadb` | N | N |
| `10.11.6` | `10.11.6` | Y | Y |
| `1.3.5` | `1.3.5` | Y | Y |
| `1.3.5a` | `1.3.5.a` | Y | Y |
| `3.7.10` | `3.7.10` | Y | Y |
| `2.4.49.el8` | `2.4.49` | N | Y |
| `2.4.57-1.el9` | `2.4.57.1` | N | Y |
| `1.21.6-1.el8` | `1.21.6.1` | N | Y |
| `9.2p1 Debian-2+deb12u3` | `9.2.1 debian-2deb12u3` | N | N |
| `9.2p1` | `9.2.1` | N | Y |
| `1.18.0-2+deb12u3` | `1.18.0.2deb12u3` | Y | N |
| `2.4.62-1~deb12u1` | `2.4.62.1deb12u1` | N | N |
| `10.0` | `10.0` | Y | Y |
| `10.0.17763` | `10.0.17763` | Y | Y |
| `8.0.36+` | `8.0.36` | N | Y |
| `1.20.1~` | `1.20.1` | N | Y |
| `1.24.0` | `1.24.0` | Y | Y |
| `11.4.0` | `11.4.0` | Y | Y |
| `*` | `*` | N | N |
| `` | `` | N | N |
| `deb12u3` | `deb12u3` | N | N |
| `1ubuntu2.22` | `1ubuntu2.22` | N | N |

OpenSSH `p` works. Ubuntu/Debian suffixes and MySQL `-log` / MariaDB / OpenSSL `1.1.1f-1ubuntu…` **fail to parse after normalize**, so `is_version_vulnerable` hits `except` and can return False or skip bounds (`matcher.py:67–72, 84–86, 98–100`).

### H. `ServiceFingerprinter` probe selection gated by port

**CONFIRMED. VERIFIED-BY-RUNNING** fake servers on non-standard ports (`python3 _audit_scratch/06_fingerprint_nonstd.py`).

| Intended | Non-std port | service_name | product | version | identified? |
|---|---:|---|---|---|---|
| HTTP nginx/1.24.0 | 18080 | `unknown` | null | null | **NO** (banner was the raw HTTP response including `Server: nginx/1.24.0`) |
| SSH OpenSSH_9.2p1 | 18022 | ssh | openssh | 9.2p1 | YES via `_analyze_banner` regex, not `_probe_ssh` |
| FTP ProFTPD 1.3.8 | 18021 | ftp | proftpd | 1.3.8 | YES via banner regex |
| SMTP Postfix 3.7.10 | 18025 | `unknown` | null | null | **NO** (banner present; `_analyze_banner` has no SMTP regex; `_probe_smtp` only on 25/587/465) |
| MySQL 8.0.36 | 18036 | mysql | mysql | 8.0.36-0ubuntu0 | YES via banner fallback |
| Redis PING/PONG | 18079 | `unknown` | null | null | **NO** (empty banner; `_probe_redis` only on 6379) |

Standard-port controls (where bind was allowed):

| Port | Result |
|---:|---|
| 8080 HTTP | `http` / `nginx` / `1.24.0` |
| 3306 MySQL | `mysql` / `mysql` / `8.0.36-0ubuntu0` |
| 6379 Redis | `redis` / `redis` / version null, banner `+PONG` |
| 21/22/25 | COULD-NOT-VERIFY (EACCES bind) |

Gates: HTTP list `fingerprint.py:28`; protocol probes L74–97 (`port == 22`, `21`, `in [25,587,465]`, `53`, `3306`, `5432`, `6379`, `27017`).

### I. ScanEngine HTTP/TLS/SMB/DNS/template steps are sequential; wall-clock

**CONFIRMED sequential. VERIFIED-BY-READING** `aegis/core/engine.py:137–155` (HTTP then TLS then SMB then DNS then templates) and `server.py:942–993` (HTTP, TLS, templates, SMB, DNS — same sequential `for svc in …` awaits). Fingerprint uses `asyncio.gather` (engine L87–88); checks do not.

**MEASURED** localhost (`python3 _audit_scratch/11_scan_perf.py`). No remote lab host — remote (b) is **COULD-NOT-VERIFY** (not scanning unknown internet; `scanme.nmap.org` not needed because localhost answered the timing question for port discovery).

| label | n_ports | port_discovery_s | open_ports | fingerprint_s | http_s | tls_s | templates_s | smb_s | dns_s | total_s |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| localhost_default_33 | 33 | 0.0037631499999406515 | [] | — | — | — | — | — | — | 0.004354864999868369 |
| localhost_1_1024 | 1024 | 0.06669113899988588 | [] | — | — | — | — | — | — | 0.0667038120000143 |
| localhost_1_65535 | 65535 | 4.191424581999854 | [2375, 5901, 18022, 18080, 26053, 26054, 26055, 26058, 26500, 50052] | 3.155043285999909 | 3.8600001062150113e-07 (0 http svcs) | 1.2300006346777081e-07 | 0.13411998699984906 (1 finding, 6 templates) | ~4e-07 | ~2.5e-07 | 7.480647325000064 |

Default 33 ports (`TOP_PORTS` has 33 entries, `config.py:10–13`) missed Docker 2375. Full 1–65535 found it; templates produced 1 finding (`AEGIS-TMPL-006` Docker unauth — port 2375 in template).

Local HTTP listener on 18080 (`_audit_scratch/11b_local_http_pipeline.py`):

| step | seconds |
|---|---:|
| port_discovery (6 ports) | 0.0012138050001340162 |
| fingerprint sequential | 1.0192517250000037 |
| fingerprint gather | 1.0166490280000744 |
| HTTP checks (forced on 18080; engine would skip because service_name=`unknown`) | 0.048910444000057396 (15 findings) |
| TLS | 3.0600017453252804e-07 (0 tls services) |
| templates | 7.764199995108356e-05 |
| total | 2.0918814389999625 |

TLS step on a real TLS target was **not** exercised (no local TLS listener). **COULD-NOT-VERIFY** TLS-auditor wall-clock on a TLS service. HTTP check time above is a real HTTP/1.1 200 on 18080.

---

## PART 3 — Facts not available from a casual read

### 3.1 Vulnerability DB

**Seed. VERIFIED-BY-RUNNING** on a fresh temp SQLite (`python3 _audit_scratch/07_vdb_seed.py`):

- `_seed_initial_database` inserts **7** rows (skips if `COUNT(*) > 0`, `db.py:130–135,259–260`).
- IDs: CVE-2021-41773, CVE-2021-42013, CVE-2024-6387, CVE-2023-38408, CVE-2022-22965, CVE-2021-23017, CVE-2015-3306.

Rows by vendor: apache 2, openbsd 2, vmware 1, f5 1, proftpd 1.
Rows by product: http_server 2, openssh 2, spring_framework 1, nginx 1, proftpd 1.

`CPE_LOOKUP` has **65** keys, **50** unique (vendor, product) pairs. **45** unique pairs have **zero** seed rows. Seeded pairs: `apache/http_server`, `openbsd/openssh`, `vmware/spring_framework`, `f5/nginx`, `proftpd/proftpd`. Zero-row examples include docker, redis, mysql, mariadb, postgresql, mongodb, kubernetes, elasticsearch, iis, tomcat, openssl, wordpress, … (full list in `_audit_scratch/results/07_vdb.json`).

**Sync. VERIFIED-BY-READING** `aegis/database/sync.py:144–158`: `sync_all` = CISA KEV + EPSS + `sync_nvd_recent(days=60)` + `sync_nvd_by_keywords` (only first 5 of the 12 keywords, L333). ThreatFox / AbuseIPDB / OTX URLs are defined (L33–34, 43–45) but **not called** from `sync_all`. ThreatFox `record_count` is hardcoded **1250** (L111).

**MEASURED bounded HTTP (not a full sync):**

| call | status | elapsed_s | result |
|---|---:|---:|---|
| CISA KEV GET | 200 | 0.12607372299999042 | 1826755 bytes, catalogVersion `2026.10.30`, **1766** vulnerabilities |
| NVD keyword `openssh` resultsPerPage=2 | 200 | 0.0969667920000461 | totalResults **203**, returned 2; `_extract_cpe_info` on first → `{}` (CVE-1999-0661 has **no** `configurations`) |
| EPSS `CVE-2021-41773` | 200 | 0.06996656200004736 | `epss=0.999920000`, percentile `0.999860000`, date `2026-10-30` |
| ThreatFox POST `get_iocs` days=1 | **401** | 0.23384140899997874 | `{"error": "Unauthorized"}` |

Full `sync_all` (KEV 1766 writes + NVD 200 recent HIGH/CRITICAL + 5×50 keyword pages) was **not** executed against the user VDB. **COULD-NOT-VERIFY** full-sync wall-clock and post-sync row count on this VM (would mutate `~/.aegis/vdb.sqlite3` with thousands of rows and NVD rate-limits without `NVD_API_KEY`). Need: isolated temp DB + API key + permission to pull ~60 days NVD.

**CPE range mapping (`_extract_cpe_info`, `sync.py:390–416`):** looks for `cpe_match.get("cpe23Uri")`. **MEASURED** NVD 2.0 `cpeMatch` objects use **`criteria`**, plus `versionStartIncluding` / `versionEndIncluding` / `versionEndExcluding` — **no `cpe23Uri`**. Example (CVE-2023-24482):

```
"criteria": "cpe:2.3:a:siemens:comos:*:*:*:*:*:*:*:*",
"versionStartIncluding": "10.2",
"versionEndExcluding": "10.3.3.1.45"
```

So even when `configurations` exist, extract returns `{}` unless a record still has the old key. When it does parse, it sets **`min_version = max_version = CPE version component`** (L413–414), ignoring NVD range fields. CISA KEV writes `min_version: None, max_version: None` (L195–196). `query_vulnerabilities` with a concrete version and both bounds None returns **True** (`matcher.py:74–101` skip empty bounds). Unknown version → never matches (`db.py:109–111`).

### 3.2 Fingerprinting inventory

**VERIFIED-BY-READING** `aegis/discovery/fingerprint.py`. Closed product strings the code can emit:

Literal `"product":` values (14): bind, exim, mariadb, microsoft_ftp, microsoft_smtp, mongodb, openssh, postfix, postgresql, proftpd, pure-ftpd, redis, sendmail, vsftpd.

Default map without banner (`_analyze_banner` L499–516) adds: ftp, ssh, telnet, smtp, dns, http, https, smb, microsoft_sql_server, oracle_database, mysql, ms-wbt-server, postgresql, redis, mongodb.

Union closed set **27** names (including `unknown`). HTTP `_parse_http_server` (L484–494) is **open-ended**: any `Name/version` Server header lowercased.

Port-gated probes listed in Part 2H. Banner regex additionally: OpenSSH, vsftpd/ProFTPD (Pure-FTPd banners are labeled `proftpd`, L524–527), redis, mysql/mariadb.

Count of **distinct closed products the fingerprinter can name without HTTP Server header**: 27 including unknown/generic port defaults.

### 3.3 YAML templates

**VERIFIED-BY-READING** `aegis/checks/templates/*.yaml` + `template_engine.py:84–126`.

Match rule: each check runs only if `port in open_ports` (L101–102). `tcp_banner`: optional `send`, then `contains` (case-insensitive) and not `not_contains`. `http_response`: scheme https iff port in (443, 8443) (L165), status in list, contains / not_contains. **First successful check** produces one Finding; further checks in that template are skipped (L126).

| id | file | checks | how match |
|---|---|---|---|
| AEGIS-TMPL-001 | redis-unauth.yaml | tcp_banner 6379 send `PING` contains `+PONG` | unauthenticated Redis PING |
| AEGIS-TMPL-002 | mongodb-unauth.yaml | tcp_banner 27017 contains `MongoDB` | banner contains MongoDB (not actually an auth test) |
| AEGIS-TMPL-003 | elasticsearch-unauth.yaml | http_response 9200 GET `/` status 200 contains `cluster_name` | |
| AEGIS-TMPL-004 | ftp-anonymous.yaml | tcp_banner 21 send `USER anonymous` contains `331` | 331 ≠ logged-in; “anonymous accepted” overstated |
| AEGIS-TMPL-005 | kubernetes-unauth.yaml | http 8080 then 6443 GET `/api/v1/namespaces` 200 contains `namespaces` | 6443 treated as **http not https** (only 443/8443 get TLS) |
| AEGIS-TMPL-006 | docker-unauth.yaml | http_response 2375 GET `/version` 200 contains `ApiVersion` | |

### 3.4 `_emit_alert` dedup / cooldown / pruning

**VERIFIED-BY-READING** `network_monitor.py:476–520`.

- Key: `dedup_key = f"{pattern_id}:{source_ip}:{dest_ip}"` (L482). **Port is not in the key.** Process is not in the key.
- TTL: scan **last 50** alerts (`self.alerts[-50:]`, L486). If same key and `now - existing._timestamp < 300` → return (5 minutes).
- `self.alerts` pruned to **last 500** (L510–511). Older-than-500 alerts drop out of the 50-window scan as well.
- `seen_alert_keys` (`L68`) is **never written**. Only cleared in `server.py:254` reset. Never pruned because unused. Always `len==0` in the 10-minute run.
- `conn_history` timestamps pruned to `BEACON_WINDOW=120` per key (L214–216); **empty keys are never deleted**.
- Graph **edges** pruned at 30s (`_update_graph` L552–555). Graph **nodes** only dropped when `get_state()` runs (60s, L759–766).

### 3.5 `ai_analyst.py`

**VERIFIED-BY-READING + VERIFIED-BY-RUNNING** (`python3 _audit_scratch/13_ai_narrative.py`).

No ML: no sklearn/torch/numpy. Templated rules only (`NARRATIVE_TEMPLATES` L82–122).

- Grouping key: `source_ip` (L291–295). One incident per source (`_src_to_incident`).
- Time window: `CORRELATION_WINDOW = 600` seconds (L258); `_cluster_by_time` splits when consecutive `_timestamp` delta > 600 (L339–350). New clusters still attach to the **same** incident id for that source (L308–322) — the cluster split does not create a second incident.
- Scoring (`_update_scores` L352–359): `confidence = min(len(alerts)*15, 60) + min(crit_count*10, 25) + min(len(tactics)*5, 15)`, cap 100. Urgency: CRITICAL if has_critical **and** ≥2 tactics; HIGH if critical or (high and multi-tactic); else MEDIUM/LOW.

**Real generated narrative** (MEASURED, 3 synthetic alerts C2+SMB+scan on `10.0.0.8`):

```
A correlated sequence of 3 alerts from host 10.0.0.8 spans Command and Control, Discovery, Lateral Movement. This multi-stage pattern is consistent with an Advanced Persistent Threat (APT) kill chain: the adversary appears to have progressed from Discovery through to Command and Control. This represents a severe, active compromise requiring immediate incident response activation.
```

confidence=80, urgency=CRITICAL, incident `INC-0001`. Executable actions included `Terminate Process: svchost.exe` (protected in remediator) and `Block IP: multiple internal` (string not stripped in `_build_executable_actions` L190 vs `to_dict` dest filter L232).

### 3.6 Alerting

**Classifier** (`aegis/alerting/classifier.py:23–92`) — a behavioral alert is “critical” (becomes `CriticalAlert`) iff:

1. `pattern_id == AEGIS-BEH-002` or title contains `"Beaconing"`, or
2. BEH-003 / title contains `"Exfiltration"`, or
3. BEH-010 / title contains `"SMB Lateral"`, or
4. BEH-004, or
5. `severity == CRITICAL` **and** tactic in `{Impact, Command and Control, Exfiltration, Lateral Movement}`.

Scan findings: `is_cisa_kev and (cvss >= 8.5 or epss >= 0.40)` (L107–108).

**Escalation timings** (`escalation.py:133–165`, default mapping `escalation_timeout_mins=5` L69):

- T+0: primary dispatch in `_dispatch_critical_alert` (`router.py:89–139`) ChatOps → SMS → modem.
- Level 0 → 1 when elapsed ≥ `timeout_mins * 60` (5 min default) → notify lead via SMS (`router.py:168–169`).
- Level 1 → 2 when elapsed ≥ `2 * timeout` (10 min default). Same lead contact. README T+0 / T+5 / T+10 matches the **default** mapping only.

`FlapDamper` production: 900s window, max 3 dispatches, 60s inter-alert cooldown (`router.py:30`, `dedup.py:64–68`). `cleanup_expired` (L74–79) is never called.

**Tests cover vs not:** see Part 1.3. Not covered: router cascade, adapters, heartbeat, escalation **timer**, production damper settings, BEH-001/005/006/007/008/011/012 classification, monitor `_emit_alert`.

### 3.7 API / UI contract

UI: `static/index.html`. Server: `server.py`.

**WebSocket `/ws/monitor`** (server L768–782): **no client request payload**. Server pushes every 2s the object `monitor.get_state()` plus `incidents: analyst.analyze(alerts)`, with `_timestamp` / `_dedup_key` stripped from alerts.

Pushed fields the UI reads (`updateMonitorUI` L2202–2259):

```
running: bool
stats.uptime_seconds, stats.total_connections_seen, stats.alerts_generated, stats.hosts_profiled
incidents: [ Incident.to_dict — see below ]
alert_summary.{CRITICAL,HIGH,MEDIUM,LOW,unacknowledged}
monitored_targets: [{id, raw, host, url_scheme, specified_port, resolved_ip, status, latency_ms, open_ports, http_status, server_header, last_checked, added_at, drift_alerts, traffic_seen_locally}]
alerts: [{id, pattern_id, severity, title, description, source_ip, dest_ip, dest_port, process, evidence, tactic, technique, timestamp, acknowledged}]
connections: [{local_ip, remote_ip, remote_port, status, pid, process, is_internal, port_label, timestamp}]  # capped 200
graph.nodes: [{id, type, connections, last_seen, is_suspicious, ip?}]
graph.edges: [{source, target, port, process, suspicious, last_seen}]
connection_history: [{timestamp:float, count:int}]
baselines: [{host, first_seen, last_seen, baseline_samples, avg_conn_rate, avg_bytes_sent, known_destinations, known_ports, anomaly_score, alert_count, established}]
```

Incident object (`ai_analyst.py:224–248`): `id, alert_count, source_ips, dest_ips, processes, tactics, techniques, severity, confidence, urgency, narrative, recommended_actions, executable_actions[{id,label,action,target,danger,description}], actions_taken, first_seen, last_seen, duration_seconds, status, alert_ids, alerts`.

**WebSocket `/ws/scan/{scan_id}`** (server L786–822): no client messages. Server sends:

- `{type:"log", message:str}`
- `{type:"progress", progress:int, status:str, open_ports:[int]}`
- `{type:"complete", scan: <scan dict>}`
- `{type:"error", message:"Scan not found"}`

UI handles `log` / `progress` / `complete` only (`index.html:1650–1654`). **Does not handle `type=error`.**

**REST the UI calls** (all exist on this branch):

| UI call | method | body/params |
|---|---|---|
| `/api/intelligence` | GET | |
| `/api/scans` | GET, POST `{target, ports, concurrency}` | |
| `/api/scans/{id}` | GET, DELETE | |
| `/api/scans/{id}/download/{html\|csv\|sarif\|json}` | GET | |
| `/api/alerting/status` | GET | |
| `/api/alerting/alerts` | GET | |
| `/api/alerting/alerts/{aid}/ack` | POST | |
| `/api/alerting/test` | POST `{title, target}` | |
| `/api/update` | POST | |
| `/api/reset` | POST | |
| `/api/threat/feeds` | GET | |
| `/api/threat/feeds/sync` | POST | |
| `/api/monitor` | GET | |
| `/api/monitor/start\|stop` | POST | |
| `/api/monitor/alerts/{id}/ack` | POST | |
| `/api/monitor/targets` | POST `{target}` | |
| `/api/monitor/targets/{id}` | DELETE | |
| `/api/incidents/action` | POST `{incident_id, action_type, target?, pid?, note?}` | |
| `/api/findings/instructions` | GET query `finding_id,title,target,port` | |
| `/api/findings/verify` | POST `{finding_id,title,target,port}` | |
| `/api/settings` | GET, POST `{threat_intel, alerting}` | |
| `/api/alerting/contacts` | GET, POST, DELETE | |
| `/api/alerting/mappings` | GET, POST, DELETE | |
| `/api/settings/test-channel` | POST `{channel, recipient}` | |

**Exists, UI does not GET:** `/api/monitor/targets` GET (list comes from WS `monitored_targets`); `/api/alerting/triage/{token}` (intended for SMS links, not `index.html`); `/docs`, `/openapi.json`.

**UI calls that 404:** none on this branch.

Scan dict fields UI uses on complete: `total_findings`, `duration`, `findings`, `target`, `status`, `id`, `severity_breakdown`, `started_at`.

### 3.8 Windows-specific code on Linux

**VERIFIED-BY-RUNNING** (`python3 _audit_scratch/16_windows_linux.py`) + VERIFIED-BY-READING.

| Call | File:line | On this Linux VM |
|---|---|---|
| `ctypes.windll.shell32.IsUserAnAdmin` | `remediation.py:35–36` | `ctypes` has **no** `windll`; `is_running_as_admin()` → **False** (except L37–38) |
| `netsh advfirewall …` | `remediation.py:204–221` | `FileNotFoundError(2, 'No such file or directory')` |
| `taskkill /F` | `remediation.py:169,280` | `FileNotFoundError`; only used when access denied |
| `MODEM_SERIAL_PORT=COM3` | `modem_oob.py:25`, `server.py:569` | `pyserial` not in `requirements.txt`; adapter returns “pyserial not installed”. `/dev/ttyUSB0` and `COM3` absent |
| `START_AEGIS.bat` / `start_aegis_admin.bat` | repo root | not executed (cmd.exe) |
| `enforce_pending_containment.bat` | `remediation.py:29,41–79` | **created** by `block_remote_ip("192.0.2.1")` |

`block_remote_ip` **MEASURED** return (Linux): `success: true`, message tells user to run `start_aegis_admin.bat`, `staged_file: /workspace/enforce_pending_containment.bat`. Functional: reports success without enforcing a firewall rule. Bat was deleted after measurement so it is not in this PR.

`terminate_process` on a missing name: `success: false`, `No active process matching …`. `isolate_socket_connections` uses `psutil` (works) then `taskkill` only on AccessDenied.

`server.py:15–16` / `run.py:13–16`: `sys.stdout.reconfigure` only if `win32` — skipped.

### 3.9 README claims

| claim | implemented? | evidence |
|---|---|---|
| High-concurrency TCP port scanner | yes | `port_scanner.py:19–29`, `engine.py:69` |
| UDP discovery | **no** | `scan_udp` never called; probe returns false (Part 2F) |
| Fingerprint HTTP, SSH, FTP, SMTP, SMB, DNS, MySQL, Postgres, Redis | **partial** | probes exist but **port-gated**; SMB has no protocol probe (port 445 default map only); SMTP/HTTP/Redis miss nonstandard ports (Part 2H) |
| Automated CVE & CPE mapping | **partial** | seed 7 CVEs; NVD extract broken (`cpe23Uri`); KEV min/max None |
| TLS/SSL cipher & cert checks | yes | `tls_auditor.py` invoked from engine L141–143 if `svc.tls` or port in (443,8443) |
| HTTP headers CSP/CORS/HSTS/Actuator | **partial** | HSTS/CSP/XFO/XCTO/Referrer/Permissions `http_checks.py:50–`; Actuator paths L186–187; **no CORS check** |
| SMB signing & null session | yes (code present) | `smb_checks.py` via engine L146–147 |
| DNS AXFR | yes (code present) | `dns_checks.py` via engine L150–151 |
| Executive HTML + TruRisk gauges A+ to F | **partial** | HTML reporter `html_reporter.py:60–85` uses posture A+/A/B/C/**F** (no D). TruRisk 0–1000 is `compute_aegis_risk_score` (`asset_intelligence.py:50–71`), a weighted sum, not Qualys TruRisk |
| Continuous network monitoring + topology HUD | yes | `NetworkMonitor` + `/ws/monitor` |
| Rolling z-score baselines | **broken** | stddev==0 ⇒ z=0 forever (Part 2B); bytes always 0 (Part 2C) |
| AEGIS-BEH-001 Port scanning | yes | `network_monitor.py:369–385` |
| AEGIS-BEH-002 C2 Beaconing | yes, with critical FPs | Part 2A |
| AEGIS-BEH-003 Exfiltration | **partial** | fixed 10 MB/s, not baseline |
| AEGIS-BEH-004 Malicious remote ports | yes | L350–367 |
| AEGIS-BEH-005 Lateral movement | **no** (ID reused) | emits “new external dest” L331–348 |
| AEGIS-BEH-006 DNS tunneling | **no** | ID reused for high-risk egress L272–295 |
| AEGIS-BEH-007 Auth brute force | **partial** | ≥15 auth-port conns / 5s |
| AEGIS-BEH-008 Tor / anonymous proxy | **no** (ID reused) | emits statistical anomaly L297–314; Tor ports fire BEH-004 |
| AEGIS-BEH-010 SMB ransomware prop. | **partial** | ≥3 SMB **connections** not unique internal hosts |
| AEGIS-BEH-012 DNS drift | **partial** | watched targets only L635–650; not in THREAT_PATTERNS |
| AI Analyst correlation | **partial** | templates, no ML (Part 3.5) |
| Process termination | **partial** | psutil works; Windows taskkill/admin path on Linux stages a .bat and may still `success: true` |
| Firewall IP isolation `netsh` | **no** on Linux | FileNotFoundError then staged .bat with success true |
| Socket session termination | **partial** | kills owning PID via psutil; does not use `ss`/`tcpkill` |
| Telegram/WhatsApp/Webhook primary | **partial** | adapters exist; unconfigured → fail; not exercised with live creds |
| Ghana SMS Arkesel/Hubtel | **partial** | adapter exists; no keys here |
| OOB modem COM3 AT+CMGS | **no** here | pyserial missing, no COM port |
| HMAC triage links | yes | `alerting/security.py`; tests pass |
| Dead-man T+0/5/10 | **partial** | default 5 min mapping; SMS-only escalate; not tested |
| Flap damping | yes | `FlapDamper`; tests use different constants |
| Dead-man canary | **partial** | no-ops if `CANARY_HEARTBEAT_URL` empty (`heartbeat.py:29–30`) |
| CISA KEV connector | yes | `sync_cisa_kev`; live GET 1766 vulns |
| NIST NVD 2.0 | **partial** | code runs; CPE parse does not match NVD 2.0 schema |
| FIRST EPSS | **partial** | updates up to 100 existing CVE rows (`sync.py:219–226`) |
| ThreatFox | **no** | URL unused in `sync_all`; live API 401; UI count 1250 hardcoded |
| AbuseIPDB | **no** | check URL unused; status KEY_REQUIRED without key |
| AlienVault OTX | **no** | key stored in settings only; no lookup function |
| SARIF reports | yes | `sarif_reporter.py` + `GET /api/scans/{id}/download/sarif` + `run.py --output sarif` |
| CSV reports | yes | `csv_reporter.py` + download/csv |
| SSH credentialed audit | **no** in product path | `SSHAuditor` never imported outside `ssh_auditor.py`; `paramiko` not in `requirements.txt` |
| Windows 10/11 prerequisite | **partial** | scanner/monitor run on Linux; containment/firewall do not |

### 3.10 Dead or unused code

**VERIFIED-BY-READING** (ripgrep, no other callers):

| Symbol | File:line | Notes |
|---|---|---|
| `seen_alert_keys` | `network_monitor.py:68` | never `.add` |
| `SSHAuditor` | `credentialed/ssh_auditor.py` | never imported |
| `AsyncPortScanner.scan_udp` / `_probe_udp_port` | `port_scanner.py:31,70` | never called from engine |
| `scan_target(..., scan_udp=)` | `port_scanner.py:56` | flag ignored |
| `BehavioralEngine.is_new_port` | `behavioral_engine.py:174` | never called |
| `FlapDamper.cleanup_expired` | `dedup.py:74` | never called |
| `_mask_key` | `server.py:516` | never called; settings returns raw env |
| `PATTERN_BY_ID` | `threat_patterns.py:147` | never read |
| `EXFIL_PORTS` | `threat_patterns.py:37` | never read |
| `SUSPICIOUS_ASNS` | `threat_patterns.py:40` | never read |
| `ScanConfig.enable_service_probe` / `enable_template_checks` / `enable_cpe_vdb_matching` | `config.py:24–26` | never read |
| `stats["packets_analyzed"]` | `network_monitor.py:97` | stays 0 (10-min run confirmed) |
| `THREATFOX_URL` / `ABUSEIPDB_CHECK_URL` | `sync.py:33–34` | unused in `sync_all` |
| `virustotal_api_key` | `sync.py:45` | stored/status only |
| `bytes_recv_rate` in scoring | `behavioral_engine.py:70,91` | updated, omitted from `score_anomaly` |

THREAT_PATTERNS thresholds ignored because detectors hardcode numbers: BEH-001 `unique_ports_per_60s:10` vs `len(ports)>=10` per **5s**; BEH-003 `bytes_sent_stddev_multiplier:3.0` vs 10 MB/s; BEH-005 `new_internal_hosts_per_5min:3` unused; BEH-006 `dns_queries_per_60s:30` unused; BEH-007 `auth_connections_per_60s:15` vs per 5s; BEH-010 `smb_targets_per_60s:3` vs connection count.

---

## PART 4 — Performance (this machine)

### 4.1 `psutil.net_connections` and `Process.name`; `_sample_connections` × 100

**MEASURED** (`python3 _audit_scratch/09_sample_timing.py`). Idle ~37–43 inet connections, 17 PID lookups.

| metric | p50 | p95 | max | min | mean |
|---|---:|---:|---:|---:|---:|
| `net_connections(kind="inet")` seconds (n=20) | 0.0021575174999668434 | 0.00269170305001012 | 0.0038697800000022653 | 0.0020594449999862263 | — |
| per `Process(pid).name()` seconds (n=17) | 1.595600002701758e-05 | 6.14942000083829e-05 | 7.193900000856956e-05 | — | total 0.00039036300012185166 |
| `_sample_connections` × 100 seconds | 0.004010882999978094 | 0.004292887900032838 | **0.07157604799999717** (first/cold) | 0.003707367999993494 | 0.004698201450000852 |

After loopback filter, `current_connections` count was **28** every sample.

Event-loop probe during one sample: `sample_s=0.01115119999997205`, `max_ping_gap_s=0.0012412059999746816`. `net_connections` is in an executor (`network_monitor.py:154`); **`Process.name()` runs on the event loop** (L182–185). At 28 conns this is ~1 ms; see 4.5 for 4000 conns.

### 4.2 10-minute monitor snapshots (every 30s)

**MEASURED** (`python3 _audit_scratch/10_monitor_10min.py`, `DURATION_S=600`). Process is the monitor script itself.

| elapsed_s | rss_bytes | rss_MiB | cpu% | conn_history | alerts | seen_alert_keys | graph_nodes | graph_edges | current_conns |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.00015878677368164062 | 33075200 | 31.54 | 0.0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 30.006474018096924 | 46338048 | 44.19 | 0.4 | 19 | 2 | 0 | 7 | 19 | 19 |
| 60.00746393203735 | 47190016 | 45.00 | 0.1 | 21 | 3 | 0 | 8 | 21 | 18 |
| 90.0131344795227 | 47976448 | 45.75 | 0.1 | 26 | 4 | 0 | 8 | 23 | 13 |
| 120.01884341239929 | 47980544 | 45.76 | 0.1 | 26 | 4 | 0 | 8 | 13 | 13 |
| 150.02494764328003 | 47984640 | 45.76 | 0.1 | 26 | 4 | 0 | 8 | 12 | 7 |
| 180 | 45.76 MiB | 0.1 | 28 | 4 | 0 | 9 | 9 | 9 |
| 210.0329668521881 | ~45.83 | 0.1 | 31 | 6 | 0 | 10 | 12 | 12 |
| 240–300 | 45.84–45.86 | 0.1 | 31 | 6 | 0 | 10 | 11 | 10–12 |
| 330.05485939979553 | 45.88 | 0.1 | 31 | 7 | 0 | 10 | 10 | 10 |
| 360–480 | 45.88–45.89 | 0.1 | 31 | 7 | 0 | 10 | 10 | 10 |
| 510.08820962905884 | 46.30 | 0.1 | 31 | 8 | 0 | 10 | 10 | 10 |
| 540–570 | 46.34 | 0.1 | 31 | 8 | 0 | 10 | 9 | 10 |
| **600.1** | **48611328** | **46.36** | **0.1** | **31** | **8** | **0** | **10** | **9** | **10** |

Grow-without-bound?

- RSS: 33075200 → 48611328 (+15.5 MiB), then flat after ~90s. **No unbounded growth in 10 min.**
- `conn_history`: 0 → 31 then **flat** (keys persist; timestamps pruned to 120s). Would grow with **new 5-tuples**, keys never deleted.
- `alerts`: 0 → 8 (capped 500).
- `seen_alert_keys`: **always 0**.
- `graph_nodes`: 0 → 10 then flat (no `get_state` prune in this script; still bounded by distinct IPs).
- `graph_edges`: peaks 23 then pruned by 30s TTL to 9.
- `packets_analyzed`: **0** every snapshot.

### 4.3 Alerts during the 10-minute idle run

**MEASURED.** 8 alerts in 600s → **0.8 alerts/minute**.

| elapsed_s | pattern_id | severity | title | classification |
|---:|---|---|---|---|
| 30.006474018096924 | AEGIS-BEH-001 | HIGH | Port Scan Detected from `::ffff:172.30.0.2` evidence unique ports 11 sample `[40000, 40002, 40012, 40020, 40034, 40040, 40042, 40046, 44578, 44582]` | **False positive.** Ephemeral high dest ports of existing sessions, not a scanner. IPv4-mapped IPv6 not treated as duplicate of `172.30.0.2`. |
| 30.006474018096924 | AEGIS-BEH-002 | CRITICAL | C2 Beaconing `172.30.0.2 → 34.225.159.174:443` Interval 5.0s ± 0.0s over 4 connections | **False positive.** Persistent HTTPS (`node` / `MainThread`) |
| 60.00746393203735 | AEGIS-BEH-002 | CRITICAL | → `172.65.90.24:443` | **FP** (Cloudflare-range HTTPS) |
| 90.0131344795227 | AEGIS-BEH-002 | CRITICAL | → `172.65.90.26:443` | **FP** |
| 210.0329668521881 | AEGIS-BEH-002 | CRITICAL | → `20.209.35.129:443` | **FP** (Microsoft-range HTTPS) |
| 210.0329668521881 | AEGIS-BEH-002 | CRITICAL | → `3.92.129.183:443` | **FP** (AWS us-east-1) |
| 330.05485939979553 | AEGIS-BEH-002 | CRITICAL | → `34.225.159.174` again (24 connections; 300s cooldown elapsed) | **FP** re-fire |
| 510.08820962905884 | AEGIS-BEH-002 | CRITICAL | → `3.92.129.183` again | **FP** re-fire |

No plausible true positive on this idle cloud VM. Final live sockets included `node` → `34.225.159.174:443` ESTABLISHED.

Note: `is_loopback('::ffff:127.0.0.1')` is False in Python, so IPv4-mapped loopback **is recorded** (`conn_history` sample key `['::ffff:127.0.0.1','::ffff:127.0.0.1',58860,24]`).

### 4.4 Scan performance

See Part 2I tables. Default 33 ports on localhost: **0.0037631499999406515 s** discovery, 0 open. Ports 1–1024: **0.06669113899988588 s**. Ports 1–65535: **4.191424581999854 s** discovery + **3.155043285999909 s** fingerprint + **0.13411998699984906 s** templates = **7.480647325000064 s** total.

Remote lab (b): **COULD-NOT-VERIFY** (no host we control off-box; did not scan scanme.nmap.org).

### 4.5 2000+ concurrent connections

**MEASURED** (`python3 _audit_scratch/12_conn_flood.py`). Server+2000 clients on `172.30.0.2:18443` (non-loopback so the monitor does **not** skip them).

```
requested: 2000
opened: 2000
open_errors: 0
open_s: 0.4174953120000282
baseline_net_connections_n: 23   in 0.0034810369998012902 s
loaded_net_connections_n: 4030   in 0.03828734700005043 s
baseline _sample_connections: 0.005182002999845281 s, kept=12
loaded  _sample_connections: 0.66531186300017 s, kept=4012, timed_out=false
  alert: AEGIS-BEH-001 (unique dest ports from 2000 local sockets)
```

4030 inet sockets ≈ 2000 connections × 2 ends on the same host + baseline.

UI WebSocket (uvicorn still running, `get_state` caps `connections[:200]` so payload did not explode):

| | WS elapsed_s | WS bytes | GET /api/monitor elapsed_s | bytes |
|---|---:|---:|---:|---:|
| before flood | 0.011939635999851816 | 38659 | 0.05026893800004473 | 38725 |
| after 2000 opened | 0.0037663870000415045 | 38659 | 0.018879225000091537 | 38725 |

WS stayed responsive at these instants because the **server’s** monitor sample is every 5s and the JSON is capped. The **sample loop** itself jumped **0.005182002999845281 → 0.66531186300017 s** (~128×). An earlier flood attempt without timeouts left the process in `ep_poll` for >5 minutes while holding ~2006 FDs — do not treat that hang as a clean number; the timed run above is the MEASURED result.

---

## PART 5 — Gaps summary

### Capability matrix

| capability | status | one-line reason |
|---|---|---|
| TCP port discovery | works reliably | localhost 1–65535 in 4.191424581999854 s; concurrent `open_connection` |
| UDP discovery | broken | blocking socket vs `sock_sendto`; never called |
| Service fingerprint | works with caveats | port-gated probes; HTTP/SMTP/Redis miss nonstandard ports |
| CVE/CPE matching | works with caveats | 7 seeds work; NVD `cpe23Uri` missing; Ubuntu versions often unparsable |
| HTTP misconfig checks | works with caveats | only if `service_name in {http,https}`; 15 findings on a local HTTP 200 |
| TLS audit | works with caveats | only tls or ports 443/8443; not timed on a real TLS service here |
| YAML templates | works with caveats | 6 templates; K8s 6443 uses HTTP; Mongo “unauth” is banner-only |
| SARIF/CSV/HTML reports | works reliably | generators exist; download routes 404 only when scan missing |
| Live connection monitor | works with caveats | boots; loopback/v4-mapped holes; 200-conn UI cap |
| Behavioral z-score “AI” | broken | stddev 0 ⇒ score 0; bytes hard-coded 0 |
| C2 beaconing | broken | long-lived HTTPS → CRITICAL; 0.8 alerts/min idle, all FP |
| DNS tunneling BEH-006 | missing | ID reused for egress |
| Lateral movement BEH-005 | missing | ID reused for first-time external dest |
| Tor BEH-008 | missing | ID reused for anomaly score |
| DNS drift BEH-012 | works with caveats | watchlist only |
| Exfil BEH-003 | works with caveats | 10 MB/s absolute, not baseline |
| AI Analyst | works with caveats | templates only; grouping by src IP; can recommend killing svchost |
| Critical alert routing | works with caveats | classifier+queue+damper tested; adapters unconfigured here |
| Windows firewall/process kill | broken on Linux | netsh/taskkill missing; `success: true` staging a .bat |
| SSH credentialed audit | missing | class never wired; paramiko not in requirements |
| NVD sync | works with caveats | HTTP 200; CPE mapping wrong |
| KEV sync | works reliably | GET 1766 vulns; but min/max None matches all versions |
| EPSS sync | works with caveats | live 1-CVE GET ok; only patches ≤100 existing rows |
| ThreatFox | missing | not in `sync_all`; API 401 |
| AbuseIPDB / OTX / VirusTotal | missing | keys stored; no lookup in sync path |
| TruRisk | works with caveats | 0–1000 weighted sum, not Qualys; HTML grades skip D |

### 10 highest-impact functional defects (do not implement)

1. **Persistent external HTTPS is CRITICAL C2.** `network_monitor.py:210–216,423–454`. Proposed fix: sample **new** 4-tuples or SYN/byte deltas, not every ESTABLISHED row; require jitter vs a learned interval, not `stddev < 5` on the 5s poll clock.
2. **RollingStats.z_score returns 0 when stddev==0, so a 100x spike scores 0.0 vs threshold 75.** `behavioral_engine.py:41–46,103–127`. Proposed fix: if stddev==0 and value ≠ mean and count≥5, treat as anomalous (or use a MAD/min-stdev floor) **before** averaging.
3. **`bytes_sent_delta`/`bytes_recv_delta` hard-coded 0.** `network_monitor.py:250–251`. Proposed fix: pass per-host or system `net_io_counters` deltas (already computed in `_io_loop`) into the sample.
4. **Pattern IDs do not match THREAT_PATTERNS/README (BEH-005/006/008); DNS tunneling has no emitter.** `network_monitor.py:281,300,335` vs `threat_patterns.py:84–123`. Proposed fix: emit the library IDs for the logic that actually exists, and implement or drop DNS tunneling.
5. **NVD CPE extract reads `cpe23Uri` and collapses ranges to a single version.** `sync.py:390–416`. Proposed fix: parse `criteria` + `versionStartIncluding`/`versionEndExcluding`.
6. **UDP scan cannot succeed and is not in `ScanEngine.run`.** `port_scanner.py:38–41,56–68`; `engine.py:69`. Proposed fix: `sock.setblocking(False)` and either call `scan_udp` from `run` or remove the UDP claim.
7. **Debian version regex runs before Ubuntu and breaks `2.4.49-3ubuntu0.1` → `2.4.49.3.ubuntu0.1` (unparsable).** `matcher.py:15–23,33–42`. Proposed fix: apply the Ubuntu rule before the generic `-N` Debian rule; strip `-log` / `+deb12u`.
8. **Protocol probes gated by well-known ports; HTTP on 18080 identified as `unknown` so HTTP checks never run in the engine.** `fingerprint.py:28,71–97`; `engine.py:196`. Proposed fix: try HTTP/banner/protocol probes independent of port (or on TLS/HTTP hints), then map checks by detected `service_name` **or** banner.
9. **SSH credentialed audit is dead code.** `credentialed/ssh_auditor.py` (no callers); `paramiko` absent from `requirements.txt`. Proposed fix: wire it behind an explicit CLI/API flag or delete the README claim.
10. **ThreatFox/OTX/AbuseIPDB are advertised but not synced; ThreatFox returns 401; UI count 1250 is a constant.** `sync.py:33–34,111,144–158`. Proposed fix: implement `sync_all` callers or mark feeds inactive with record_count 0.

### Tried but could not verify

| item | why | what is needed |
|---|---|---|
| Full NVD+KEV+EPSS `sync_all` duration and resulting row count | bounded dry-run only; full pull would mutate `~/.aegis/vdb.sqlite3` and is rate-limited without `NVD_API_KEY` | temp DB, NVD key, permission to write ~2k+ KEV + 200 NVD + 5 keyword pages |
| TLS auditor timing on a real TLS service | localhost had no TLS listener | a local TLS server we control, or an allowed lab host |
| Scan performance vs a remote lab host | none under our control; spec forbids random internet | an owned lab VM |
| Fingerprint on privileged ports 21/22/25 | bind EACCES | CAP_NET_BIND_SERVICE or `authbind` |
| Trusted Night admin token | `~/.aegis/admin_token` missing; GETs worked open | a build that actually enforces the token |
| Live Telegram/SMS/modem dispatch | no credentials / no modem | out of scope to send real pages |
| `ScanEngine` UDP via `run()` | no call site | n/a — confirmed absent |
| Qualys TruRisk compatibility | only an internal 0–1000 sum | vendor definition; not in repo |

### Scripts (throwaway)

All under `/workspace/_audit_scratch/`. Raw JSON under `/workspace/_audit_scratch/results/`. Delete after review.
