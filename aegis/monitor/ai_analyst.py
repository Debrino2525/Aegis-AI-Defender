"""
Aegis AI Analyst — Incident Correlation & Narrative Generation Engine.

Correlates raw behavioral alerts into coherent security incidents,
generates natural language summaries, recommends response actions,
and tracks executed containment actions.
"""

import time
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict
from datetime import datetime, timezone


# ── Tactic severity weights ───────────────────────────────────────────────────
TACTIC_WEIGHT = {
    "Command and Control": 10,
    "Exfiltration":        10,
    "Lateral Movement":    9,
    "Credential Access":   8,
    "Discovery":           5,
    "Execution":           7,
    "Persistence":         7,
    "Defense Evasion":     6,
    "Impact":              10,
    "Initial Access":      8,
    "Reconnaissance":      4,
}

# ── Known kill-chain stage ordering ──────────────────────────────────────────
KILL_CHAIN_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Exfiltration", "Command and Control", "Impact",
]

# ── Response playbooks keyed by tactic ───────────────────────────────────────
RESPONSE_PLAYBOOKS: Dict[str, List[str]] = {
    "Command and Control": [
        "Immediately isolate the source host from the network",
        "Block all outbound connections from source IP at the firewall",
        "Capture a memory dump for forensic analysis",
        "Search for scheduled tasks, startup entries, and registry run keys on the host",
        "Run full AV/EDR scan and check for unsigned or newly created executables",
    ],
    "Exfiltration": [
        "Block outbound traffic from the source IP immediately",
        "Identify all files accessed by the process in the last 24h",
        "Check DLP logs for sensitive data transfer",
        "Preserve network flow logs for forensic analysis",
        "Notify data protection officer if PII/PCI data is in scope",
    ],
    "Lateral Movement": [
        "Disable the source host's Active Directory account immediately",
        "Reset credentials for all accounts seen on source host",
        "Audit SMB/RDP access logs across the network segment",
        "Search for PsExec, WMI exec, or PowerShell remoting artifacts",
        "Enable enhanced logging on domain controllers",
    ],
    "Credential Access": [
        "Lock the targeted account(s) after threshold exceeded",
        "Enable MFA on all targeted services immediately",
        "Check for successful logins following the brute-force attempts",
        "Review authentication logs for the past 48 hours",
        "Alert the account owner and require password reset",
    ],
    "Discovery": [
        "Identify the source process performing the scanning",
        "Verify whether the host is an authorized scanner or pentest system",
        "If unauthorized, isolate the host and investigate for compromise",
        "Block internal scanning if originating from non-admin host",
    ],
    "Default": [
        "Investigate the source host for indicators of compromise",
        "Collect and preserve relevant logs",
        "Review network flows to/from source IP",
        "Escalate to SOC Tier 2 analyst for deeper investigation",
    ],
}

# ── Incident narrative templates ─────────────────────────────────────────────
NARRATIVE_TEMPLATES = {
    "single_c2": (
        "A single host ({src}) has been observed making highly regular, low-jitter connections "
        "to an external IP ({dst}), consistent with Command & Control (C2) beaconing behavior. "
        "The communication pattern matches known RAT/botnet check-in intervals. "
        "This is a high-confidence indicator of active malware infection."
    ),
    "lateral_movement": (
        "Host {src} is actively connecting to multiple internal hosts via SMB (port 445), "
        "a pattern consistent with ransomware propagation or a worm-like lateral movement campaign. "
        "{count} SMB connections were observed within the detection window. "
        "Immediate containment is recommended to prevent further spread."
    ),
    "multi_tactic_apt": (
        "A correlated sequence of {count} alerts from host {src} spans {tactics}. "
        "This multi-stage pattern is consistent with an Advanced Persistent Threat (APT) kill chain: "
        "the adversary appears to have progressed from {first_tactic} through to {last_tactic}. "
        "This represents a severe, active compromise requiring immediate incident response activation."
    ),
    "bruteforce_with_c2": (
        "Host {src} first conducted credential brute-forcing against authentication services, "
        "followed shortly by C2 beaconing behavior. This sequence suggests a successful credential "
        "compromise that led to malware installation. Both the brute-force target and the "
        "beaconing source should be treated as compromised."
    ),
    "exfil_alert": (
        "Anomalously high outbound data transfer has been detected from this host at {rate}. "
        "This rate significantly exceeds the established behavioral baseline and is consistent "
        "with active data exfiltration. All outbound connections should be reviewed immediately."
    ),
    "port_scan": (
        "Host {src} performed an aggressive port scan, touching {port_count} unique ports "
        "within a {window}-second window. This is a strong indicator of internal network "
        "reconnaissance, potentially preceding a lateral movement attempt."
    ),
    "generic": (
        "{count} behavioral alert(s) have been generated from host {src}. "
        "The alerts cover {tactics} and collectively suggest suspicious activity "
        "that warrants immediate investigation by a security analyst."
    ),
}


class Incident:
    """Represents a correlated security incident derived from multiple alerts."""

    def __init__(self, incident_id: str):
        self.id = incident_id
        self.alerts: List[Dict] = []
        self.source_ips: Set[str] = set()
        self.dest_ips: Set[str] = set()
        self.processes: Set[str] = set()
        self.tactics: Set[str] = set()
        self.techniques: Set[str] = set()
        self.severities: List[str] = []
        self.first_seen: float = time.time()
        self.last_seen: float = time.time()
        self.narrative: str = ""
        self.confidence: int = 0      # 0–100
        self.urgency: str = "LOW"     # LOW / MEDIUM / HIGH / CRITICAL
        self.recommended_actions: List[str] = []
        self.actions_taken: List[Dict[str, Any]] = []
        self.status: str = "ACTIVE"   # ACTIVE / CONTAINED / RESOLVED

    def add_alert(self, alert: Dict):
        self.alerts.append(alert)
        if alert.get("source_ip"):
            self.source_ips.add(alert["source_ip"])
        if alert.get("dest_ip"):
            self.dest_ips.add(alert["dest_ip"])
        proc = alert.get("process")
        if proc and proc.strip() and proc.lower() not in ("unknown", "none", "system idle process"):
            self.processes.add(proc.strip())
        if alert.get("tactic"):
            self.tactics.add(alert["tactic"])
        if alert.get("technique"):
            self.techniques.add(alert["technique"])
        self.severities.append(alert.get("severity", "LOW"))
        ts = alert.get("_timestamp", time.time())
        self.last_seen = max(self.last_seen, ts)
        self.first_seen = min(self.first_seen, ts)

    def record_action(self, action_result: Dict[str, Any]):
        """Records an action execution result onto the incident."""
        self.actions_taken.append(action_result)
        action_type = action_result.get("action")
        if action_type in ("terminate_process", "block_ip", "isolate_connections"):
            if self.status != "RESOLVED":
                self.status = "CONTAINED"
        elif action_type == "resolve":
            self.status = "RESOLVED"

    def _build_executable_actions(self) -> List[Dict[str, Any]]:
        """Builds one-click actionable containment buttons specific to this incident."""
        actions = []

        # 1. Terminate offending processes
        for proc in sorted(self.processes):
            actions.append({
                "id": f"kill_{proc}",
                "label": f"Terminate Process: {proc}",
                "action": "terminate_process",
                "target": proc,
                "danger": True,
                "description": f"Terminate running instances of '{proc}' locally on this machine."
            })

        # 2. Block remote destination IPs
        clean_dests = [d for d in self.dest_ips if d and d not in ("localhost", "multiple", "external", "127.0.0.1", "::1")]
        for dst in clean_dests:
            actions.append({
                "id": f"block_{dst}",
                "label": f"Block IP: {dst}",
                "action": "block_ip",
                "target": dst,
                "danger": True,
                "description": f"Add Windows Defender Firewall rule to block all inbound and outbound traffic to {dst}."
            })

        # 3. Drop active socket connections
        for dst in clean_dests:
            actions.append({
                "id": f"drop_{dst}",
                "label": f"Drop Sockets to {dst}",
                "action": "isolate_connections",
                "target": dst,
                "danger": False,
                "description": f"Terminate any active network socket sessions connected to {dst}."
            })

        # 4. Resolve/contain incident
        actions.append({
            "id": "resolve_incident",
            "label": "Mark Contained & Resolve Incident",
            "action": "resolve",
            "target": self.id,
            "danger": False,
            "description": "Mark this security incident as contained and archive it from the active triage list."
        })

        return actions

    def to_dict(self) -> Dict:
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        top_sev = max(self.severities, key=lambda s: sev_order.get(s, 0)) if self.severities else "LOW"

        return {
            "id": self.id,
            "alert_count": len(self.alerts),
            "source_ips": sorted(self.source_ips - {"", "localhost", "external"}),
            "dest_ips": sorted(self.dest_ips - {"", "multiple", "multiple internal"}),
            "processes": sorted(self.processes),
            "tactics": sorted(self.tactics),
            "techniques": sorted(self.techniques),
            "severity": top_sev,
            "confidence": self.confidence,
            "urgency": self.urgency,
            "narrative": self.narrative,
            "recommended_actions": self.recommended_actions,
            "executable_actions": self._build_executable_actions(),
            "actions_taken": self.actions_taken,
            "first_seen": datetime.fromtimestamp(self.first_seen, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat(),
            "duration_seconds": round(self.last_seen - self.first_seen, 1),
            "status": self.status,
            "alert_ids": [a.get("id") for a in self.alerts],
            "alerts": [{k: v for k, v in a.items() if not k.startswith('_')} for a in self.alerts[-25:]],
        }


class AIAnalyst:
    """
    Correlates behavioral alerts into incidents, maintains state across cycles,
    generates summaries, and supports direct action containment.
    """

    CORRELATION_WINDOW = 600   # 10 minutes
    MAX_INCIDENTS = 100

    def __init__(self):
        self._incidents_by_id: Dict[str, Incident] = {}
        self._src_to_incident: Dict[str, str] = {}
        self._inc_counter = 0
        self._pending_restore: List[Dict] = []

    @property
    def incidents(self) -> Dict[str, Incident]:
        return self._incidents_by_id

    def clear(self):
        self._incidents_by_id.clear()
        self._src_to_incident.clear()
        self._inc_counter = 0
        self._pending_restore.clear()

    def restore_operator_state(self, rows: List[Dict]) -> None:
        """Reattach containment actions after a process restart, keyed by source IP."""
        self._pending_restore = list(rows or [])

    def export_operator_state(self) -> List[Dict]:
        rows = []
        for src, inc_id in self._src_to_incident.items():
            inc = self._incidents_by_id.get(inc_id)
            if not inc:
                continue
            if inc.status == "ACTIVE" and not inc.actions_taken:
                continue
            rows.append({
                "source_ip": src,
                "incident_id": inc.id,
                "status": inc.status,
                "actions_taken": list(inc.actions_taken),
            })
        return rows

    def _apply_pending_restore(self, inc: Incident, src_ip: str) -> None:
        if not self._pending_restore:
            return
        kept = []
        for row in self._pending_restore:
            if row.get("source_ip") == src_ip:
                if row.get("status"):
                    inc.status = row["status"]
                actions = row.get("actions_taken") or []
                if actions:
                    inc.actions_taken = list(actions)
            else:
                kept.append(row)
        self._pending_restore = kept

    def _new_id(self) -> str:
        self._inc_counter += 1
        return f"INC-{self._inc_counter:04d}"

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self._incidents_by_id.get(incident_id)

    def analyze(self, alerts: List[Dict]) -> List[Dict]:
        """
        Main entry point. Correlates alerts into persistent incidents,
        updating existing incidents without erasing analyst action history.
        """
        if not alerts:
            # Return any previously tracked incidents
            return [inc.to_dict() for inc in self._incidents_by_id.values()]

        # Group alerts by source IP
        by_source: Dict[str, List[Dict]] = defaultdict(list)
        for alert in alerts:
            src = alert.get("source_ip", "unknown")
            by_source[src].append(alert)

        for src_ip, src_alerts in by_source.items():
            if not src_alerts:
                continue

            src_alerts.sort(key=lambda a: a.get("_timestamp", 0))
            clusters = self._cluster_by_time(src_alerts, self.CORRELATION_WINDOW)

            for cluster in clusters:
                if not cluster:
                    continue

                # Check if we already have an incident for this source
                existing_id = self._src_to_incident.get(src_ip)
                if existing_id and existing_id in self._incidents_by_id:
                    inc = self._incidents_by_id[existing_id]
                    # Update alerts if new ones arrived
                    existing_alert_ids = {a.get("id") for a in inc.alerts}
                    for a in cluster:
                        if a.get("id") not in existing_alert_ids:
                            inc.add_alert(a)
                    # Re-score confidence
                    self._update_scores(inc, src_ip)
                else:
                    inc = self._build_incident(src_ip, cluster)
                    self._incidents_by_id[inc.id] = inc
                    self._src_to_incident[src_ip] = inc.id
                self._apply_pending_restore(inc, src_ip)

        # Sort by status (ACTIVE first), urgency, confidence
        status_order = {"ACTIVE": 2, "CONTAINED": 1, "RESOLVED": 0}
        urg_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sorted_incs = sorted(
            self._incidents_by_id.values(),
            key=lambda i: (
                status_order.get(i.status, 0),
                urg_order.get(i.urgency, 0),
                i.confidence
            ),
            reverse=True
        )

        return [inc.to_dict() for inc in sorted_incs[:self.MAX_INCIDENTS]]

    def _cluster_by_time(self, alerts: List[Dict], window: float) -> List[List[Dict]]:
        if not alerts:
            return []
        clusters: List[List[Dict]] = [[alerts[0]]]
        for alert in alerts[1:]:
            last_ts = clusters[-1][-1].get("_timestamp", 0)
            curr_ts = alert.get("_timestamp", 0)
            if curr_ts - last_ts <= window:
                clusters[-1].append(alert)
            else:
                clusters.append([alert])
        return clusters

    def _update_scores(self, inc: Incident, src_ip: str):
        """Updates confidence and urgency for an updated incident."""
        alerts = inc.alerts
        base = min(len(alerts) * 15, 60)
        crit_count = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        sev_bonus = min(crit_count * 10, 25)
        tactic_bonus = min(len(inc.tactics) * 5, 15)
        inc.confidence = min(base + sev_bonus + tactic_bonus, 100)

        has_critical = any(a.get("severity") == "CRITICAL" for a in alerts)
        has_high = any(a.get("severity") == "HIGH" for a in alerts)
        multi_tactic = len(inc.tactics) >= 2

        if has_critical and multi_tactic:
            inc.urgency = "CRITICAL"
        elif has_critical or (has_high and multi_tactic):
            inc.urgency = "HIGH"
        elif has_high:
            inc.urgency = "MEDIUM"
        else:
            inc.urgency = "LOW"

        inc.narrative = self._generate_narrative(src_ip, alerts, inc)
        inc.recommended_actions = self._get_response_actions(inc)

    def _build_incident(self, src_ip: str, alerts: List[Dict]) -> Incident:
        inc = Incident(self._new_id())
        for alert in alerts:
            inc.add_alert(alert)
        self._update_scores(inc, src_ip)
        return inc

    def _generate_narrative(self, src_ip: str, alerts: List[Dict], inc: Incident) -> str:
        tactics = inc.tactics
        pattern_ids = {a.get("pattern_id", "") for a in alerts}
        dest_ips = list(inc.dest_ips - {"", "multiple", "multiple internal", "external"})
        dst_str = dest_ips[0] if dest_ips else "external host"

        has_c2 = "AEGIS-BEH-002" in pattern_ids or "AEGIS-BEH-004" in pattern_ids
        has_lateral = "AEGIS-BEH-010" in pattern_ids
        has_bruteforce = "AEGIS-BEH-007" in pattern_ids
        has_scan = "AEGIS-BEH-001" in pattern_ids
        has_exfil = "AEGIS-BEH-003" in pattern_ids
        multi_tactic = len(tactics) >= 3

        if multi_tactic:
            ordered = [t for t in KILL_CHAIN_ORDER if t in tactics]
            first = ordered[0] if ordered else list(tactics)[0]
            last = ordered[-1] if ordered else list(tactics)[-1]
            return NARRATIVE_TEMPLATES["multi_tactic_apt"].format(
                count=len(alerts),
                src=src_ip,
                tactics=", ".join(sorted(tactics)),
                first_tactic=first,
                last_tactic=last,
            )

        if has_c2 and has_bruteforce:
            return NARRATIVE_TEMPLATES["bruteforce_with_c2"].format(src=src_ip, dst=dst_str)

        if has_lateral:
            smb_alert = next((a for a in alerts if a.get("pattern_id") == "AEGIS-BEH-010"), alerts[0])
            count = smb_alert.get("evidence", "").split(" ")[2] if smb_alert.get("evidence") else str(len(alerts))
            return NARRATIVE_TEMPLATES["lateral_movement"].format(src=src_ip, count=count)

        if has_c2:
            return NARRATIVE_TEMPLATES["single_c2"].format(src=src_ip, dst=dst_str)

        if has_exfil:
            exfil_alert = next((a for a in alerts if a.get("pattern_id") == "AEGIS-BEH-003"), alerts[0])
            rate = "unknown rate"
            if "evidence" in exfil_alert:
                rate = exfil_alert["evidence"].split("|")[0].strip()
            return NARRATIVE_TEMPLATES["exfil_alert"].format(src=src_ip, rate=rate)

        if has_scan:
            scan_alert = next((a for a in alerts if a.get("pattern_id") == "AEGIS-BEH-001"), alerts[0])
            port_count = len(alerts)
            try:
                ev = scan_alert.get("evidence", "")
                port_count = int(ev.split("Unique ports contacted:")[1].split("|")[0].strip())
            except Exception:
                pass
            return NARRATIVE_TEMPLATES["port_scan"].format(src=src_ip, port_count=port_count, window=5)

        if has_bruteforce:
            return NARRATIVE_TEMPLATES["generic"].format(
                count=len(alerts), src=src_ip,
                tactics="Credential Access / Brute Force"
            )

        return NARRATIVE_TEMPLATES["generic"].format(
            count=len(alerts), src=src_ip,
            tactics=", ".join(sorted(tactics)) if tactics else "unknown"
        )

    def _get_response_actions(self, inc: Incident) -> List[str]:
        best_tactic = max(
            inc.tactics,
            key=lambda t: TACTIC_WEIGHT.get(t, 0),
            default=None
        )
        playbook = RESPONSE_PLAYBOOKS.get(best_tactic, RESPONSE_PLAYBOOKS["Default"])
        return list(playbook) + [
            f"Document all containment actions in incident registry (Incident ID: {inc.id})",
        ]
