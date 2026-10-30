"""
Threat Pattern Library — Genuine behavioral threat signatures.
Each pattern describes a real attack technique with detection logic.
"""

import ipaddress
from typing import Dict, List, Any

# Well-known malicious / suspicious ports
MALICIOUS_PORTS = {
    1337: "Leet / Backdoor",
    4444: "Metasploit default listener",
    5555: "Android Debug Bridge / RAT",
    6666: "IRC C2",
    6667: "IRC C2",
    7777: "Backdoor",
    8888: "C2 / Cobalt Strike alt",
    9001: "Tor relay",
    9050: "Tor SOCKS proxy",
    9051: "Tor control",
    31337: "Back Orifice / Elite backdoor",
    1080: "SOCKS proxy",
    3128: "Squid proxy C2",
    4899: "Radmin RAT",
    5900: "VNC (watch for unauth)",
    12345: "NetBus RAT",
    27374: "Sub7 RAT",
    65535: "Backdoor",
}

# High-risk outbound services (unexpected egress)
HIGH_RISK_REMOTE_PORTS = {
    22, 23, 25, 110, 143, 445, 1433, 3306, 5432, 4444, 5555, 6667,
    9001, 9050, 31337, 12345, 4899
}

# Ports indicating data exfiltration risk
EXFIL_PORTS = {53, 80, 443, 8080, 8443, 4443, 8888}

# Known CDN/cloud ranges that C2 often abuses
SUSPICIOUS_ASNS = ["AS16509", "AS14618"]  # AWS commonly abused for C2

# Public web edges. Regular browser traffic here is not a C2 beacon.
# Ports outside WEB_EDGE_PORTS are still eligible for detection.
_WEB_EDGE_CIDRS = (
    # Google
    "64.233.160.0/19",
    "66.102.0.0/20",
    "66.249.64.0/19",
    "72.14.192.0/18",
    "74.125.0.0/16",
    "108.177.0.0/17",
    "142.250.0.0/15",
    "172.217.0.0/16",
    "172.253.0.0/16",
    "173.194.0.0/16",
    "209.85.128.0/17",
    "216.58.192.0/19",
    "216.239.32.0/19",
    "192.178.0.0/15",
    # Cloudflare
    "104.16.0.0/12",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    # Fastly
    "151.101.0.0/16",
    # Akamai CDN
    "2.16.0.0/13",
    "23.32.0.0/11",
    "23.192.0.0/11",
    "95.100.0.0/15",
    "184.24.0.0/13",
    "184.50.0.0/15",
    "184.84.0.0/14",
    # Amazon CloudFront
    "13.32.0.0/15",
    "13.35.0.0/16",
    "52.84.0.0/15",
    "54.182.0.0/16",
    "54.192.0.0/16",
    "54.230.0.0/16",
    "99.84.0.0/16",
    "108.156.0.0/16",
    "130.176.0.0/16",
    "143.204.0.0/16",
    # Microsoft 365 service front ends, not customer virtual networks
    "52.96.0.0/14",
    "52.100.0.0/14",
)
WEB_EDGE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in _WEB_EDGE_CIDRS)
WEB_EDGE_PORTS = {80, 443, 8080, 8443}


def is_well_known_web_edge(ip: str) -> bool:
    """True when an address is in a published Google or major-CDN web range."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(addr in network for network in WEB_EDGE_NETWORKS)


def is_routine_web_edge_traffic(ip: str, port: int) -> bool:
    """Browser-like ports on a well-known web edge. Other ports stay detectable."""
    try:
        port_n = int(port)
    except (TypeError, ValueError):
        return False
    return port_n in WEB_EDGE_PORTS and is_well_known_web_edge(ip)


def is_routine_web_edge_beacon(alert: dict) -> bool:
    """A saved C2 beacon that only describes routine web-edge traffic."""
    if not isinstance(alert, dict) or alert.get("pattern_id") != "AEGIS-BEH-002":
        return False
    return is_routine_web_edge_traffic(alert.get("dest_ip") or "", alert.get("dest_port") or 0)


# One workstation opening many regular web flows is a browser, not a C2 channel.
FANOUT_WEB_DESTS = 4


def suppress_web_beacon(dest_ip: str, dest_port, sibling_web_dests: int = 1) -> bool:
    """True when this beacon must not be shown or routed as command-and-control."""
    try:
        port_n = int(dest_port) if dest_port not in (None, "") else 0
    except (TypeError, ValueError):
        port_n = 0
    if port_n and port_n not in WEB_EDGE_PORTS:
        return False
    check_port = port_n or 443
    if is_routine_web_edge_traffic(str(dest_ip or ""), check_port):
        return True
    return sibling_web_dests >= FANOUT_WEB_DESTS


def hidden_queued_beacon_ids(rows: List[Dict[str, Any]]) -> set:
    """Alert ids that are routine web beacons and must leave the operator queue."""
    groups: Dict[str, set] = {}
    beacons = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        meta = row.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        pattern = str(meta.get("raw_pattern_id") or row.get("pattern_id") or "")
        title = str(row.get("title") or "")
        if pattern != "AEGIS-BEH-002" and "Beaconing" not in title:
            continue
        beacons.append(row)
        try:
            port_n = int(row.get("dest_port")) if row.get("dest_port") not in (None, "") else 0
        except (TypeError, ValueError):
            port_n = 0
        if port_n in WEB_EDGE_PORTS or port_n == 0:
            groups.setdefault(str(row.get("source_ip") or ""), set()).add(str(row.get("dest_ip") or ""))
    hidden = set()
    for row in beacons:
        siblings = len(groups.get(str(row.get("source_ip") or ""), ()))
        if suppress_web_beacon(row.get("dest_ip") or "", row.get("dest_port"), siblings):
            alert_id = row.get("alert_id")
            if alert_id:
                hidden.add(alert_id)
    return hidden


def visible_monitor_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop routine web beacons. Other alerts stay."""
    groups: Dict[str, set] = {}
    for alert in alerts or []:
        if not isinstance(alert, dict) or alert.get("pattern_id") != "AEGIS-BEH-002":
            continue
        port = alert.get("dest_port") or 0
        try:
            port_n = int(port)
        except (TypeError, ValueError):
            port_n = 0
        if port_n in WEB_EDGE_PORTS or port_n == 0:
            groups.setdefault(str(alert.get("source_ip") or ""), set()).add(str(alert.get("dest_ip") or ""))
    kept = []
    for alert in alerts or []:
        if isinstance(alert, dict) and alert.get("pattern_id") == "AEGIS-BEH-002":
            siblings = len(groups.get(str(alert.get("source_ip") or ""), ()))
            if suppress_web_beacon(alert.get("dest_ip") or "", alert.get("dest_port"), siblings):
                continue
        kept.append(alert)
    return kept

# Connection state patterns
THREAT_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "AEGIS-BEH-001",
        "name": "Port Scan Detected",
        "description": "High number of unique destination ports contacted from a single source within a short window, indicating active port scanning behavior.",
        "tactic": "Discovery",
        "technique": "T1046",
        "severity": "HIGH",
        "threshold": {"unique_ports_per_60s": 10},
        "remediation": "Investigate source host for compromise. Block outbound port scanning via firewall egress rules.",
    },
    {
        "id": "AEGIS-BEH-002",
        "name": "C2 Beaconing Pattern",
        "description": "Highly regular periodic connections to a remote IP at consistent intervals — characteristic of malware C2 check-in behavior (RAT, botnet, Cobalt Strike).",
        "tactic": "Command and Control",
        "technique": "T1071",
        "severity": "CRITICAL",
        "threshold": {"interval_stddev_seconds": 5, "min_connections": 4},
        "remediation": "Isolate the host immediately. Block the remote IP at perimeter firewall. Perform full forensic investigation.",
    },
    {
        "id": "AEGIS-BEH-003",
        "name": "Data Exfiltration — Large Outbound Transfer",
        "description": "Unusually large volume of data being sent outbound to a single external IP, significantly exceeding established behavioral baseline.",
        "tactic": "Exfiltration",
        "technique": "T1048",
        "severity": "CRITICAL",
        "threshold": {"bytes_sent_stddev_multiplier": 3.0},
        "remediation": "Block outbound connection immediately. Identify data involved. Report as potential breach under applicable regulations.",
    },
    {
        "id": "AEGIS-BEH-004",
        "name": "Connection to Known Malicious Port",
        "description": "Active connection established to a port associated with known RATs, backdoors, or C2 frameworks.",
        "tactic": "Command and Control",
        "technique": "T1095",
        "severity": "CRITICAL",
        "threshold": {},
        "remediation": "Terminate connection. Isolate host and perform malware scan. Block the destination IP/port at firewall.",
    },
    {
        "id": "AEGIS-BEH-005",
        "name": "Lateral Movement — New Internal Connection",
        "description": "A host is establishing connections to new internal hosts/services not seen in the behavioral baseline — indicative of lateral movement post-compromise.",
        "tactic": "Lateral Movement",
        "technique": "T1021",
        "severity": "HIGH",
        "threshold": {"new_internal_hosts_per_5min": 3},
        "remediation": "Investigate source host. Review authentication logs. Consider network segmentation to limit blast radius.",
    },
    {
        "id": "AEGIS-BEH-006",
        "name": "DNS Tunneling Suspected",
        "description": "Unusually high volume of DNS queries from a single host, potentially used for data exfiltration or C2 communication via DNS tunneling.",
        "tactic": "Exfiltration",
        "technique": "T1048.003",
        "severity": "HIGH",
        "threshold": {"dns_queries_per_60s": 30},
        "remediation": "Block DNS to all resolvers except approved corporate DNS. Analyze DNS query content for encoded payloads.",
    },
    {
        "id": "AEGIS-BEH-007",
        "name": "Brute Force Authentication Attempt",
        "description": "High frequency of connection attempts to authentication services (SSH/RDP/SMB) suggesting automated credential stuffing or brute force attack.",
        "tactic": "Credential Access",
        "technique": "T1110",
        "severity": "HIGH",
        "threshold": {"auth_connections_per_60s": 15},
        "remediation": "Block source IP. Enable account lockout policies. Implement MFA. Review successful logins from the source.",
    },
    {
        "id": "AEGIS-BEH-008",
        "name": "Tor / Anonymous Proxy Connection",
        "description": "Connection established to or from Tor relay ports or known anonymization infrastructure, commonly used to hide attacker identity.",
        "tactic": "Command and Control",
        "technique": "T1090.003",
        "severity": "HIGH",
        "threshold": {},
        "remediation": "Block Tor exit node ranges at perimeter. Investigate host for malware. Review proxy bypass policies.",
    },
    {
        "id": "AEGIS-BEH-009",
        "name": "Spike in New Outbound Connections",
        "description": "Sudden significant increase in the rate of new outbound connections from a host, deviating significantly from its established behavioral baseline.",
        "tactic": "Command and Control",
        "technique": "T1071",
        "severity": "MEDIUM",
        "threshold": {"new_conn_rate_stddev_multiplier": 2.5},
        "remediation": "Investigate the process initiating connections. Check for scheduled tasks or new services installed on the host.",
    },
    {
        "id": "AEGIS-BEH-010",
        "name": "SMB Lateral Movement Detected",
        "description": "Connection attempts to SMB port 445 on multiple internal hosts — common technique used for lateral movement and ransomware propagation.",
        "tactic": "Lateral Movement",
        "technique": "T1021.002",
        "severity": "CRITICAL",
        "threshold": {"smb_targets_per_60s": 3},
        "remediation": "Isolate source host immediately. Block SMB at network segment boundaries. Check for ransomware indicators.",
    },
]

# Quick pattern lookup
PATTERN_BY_ID = {p["id"]: p for p in THREAT_PATTERNS}
