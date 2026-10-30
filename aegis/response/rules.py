"""Response rules. A proposal exists only when evidence on the incident matches."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

RESPONSE_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "AEGIS-RSP-001",
        "title": "Block C2 destination",
        "action": "block_ip",
        "target_kind": "dest_ip",
        "pattern_ids": ("AEGIS-BEH-002", "AEGIS-BEH-004"),
        "tactics": ("Command and Control",),
        "min_severity": "MEDIUM",
        "rollback_action": "unblock_ip",
        "rollback_possible": True,
    },
    {
        "rule_id": "AEGIS-RSP-002",
        "title": "Drop lateral sockets",
        "action": "isolate_connections",
        "target_kind": "dest_ip",
        "pattern_ids": ("AEGIS-BEH-005", "AEGIS-BEH-010"),
        "tactics": ("Lateral Movement",),
        "min_severity": "MEDIUM",
        "rollback_action": None,
        "rollback_possible": False,
    },
    {
        "rule_id": "AEGIS-RSP-003",
        "title": "Stop offending process",
        "action": "terminate_process",
        "target_kind": "process",
        "pattern_ids": (),
        "tactics": (),
        "min_severity": "HIGH",
        "rollback_action": None,
        "rollback_possible": False,
    },
    {
        "rule_id": "AEGIS-RSP-004",
        "title": "Quarantine host",
        "action": "quarantine_host",
        "target_kind": "asset",
        "pattern_ids": (),
        "tactics": (),
        "min_severity": "CRITICAL",
        "min_tactics": 2,
        "rollback_action": "unquarantine_host",
        "rollback_possible": True,
    },
    {
        "rule_id": "AEGIS-RSP-005",
        "title": "Isolate host",
        "action": "quarantine_host",
        "target_kind": "asset",
        "pattern_ids": (),
        "tactics": (),
        "min_severity": "HIGH",
        "requires_closed_loop": True,
        "rollback_action": "unquarantine_host",
        "rollback_possible": True,
    },
]


OPERATOR_RULE = {
    "rule_id": "AEGIS-RSP-000",
    "title": "Operator-directed contain",
    "action": "",
    "target_kind": "manual",
    "rollback_action": None,
    "rollback_possible": False,
}

_ROLLBACK = {
    "block_ip": "unblock_ip",
    "unblock_ip": "block_ip",
    "quarantine_host": "unquarantine_host",
    "unquarantine_host": "quarantine_host",
}


def get_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    if rule_id == OPERATOR_RULE["rule_id"]:
        return dict(OPERATOR_RULE)
    for rule in RESPONSE_RULES:
        if rule["rule_id"] == rule_id:
            return dict(rule)
    return None


def rule_for_action(action: str) -> Optional[Dict[str, Any]]:
    action = (action or "").strip()
    for rule in RESPONSE_RULES:
        if rule["action"] == action or rule.get("rollback_action") == action:
            return dict(rule)
    if action in {
        "block_ip", "unblock_ip", "isolate_connections",
        "terminate_process", "quarantine_host", "unquarantine_host",
    }:
        rollback = _ROLLBACK.get(action)
        return {
            **OPERATOR_RULE,
            "action": action,
            "rollback_action": rollback,
            "rollback_possible": rollback is not None,
        }
    return None


def _severity_ok(alerts: Sequence[Dict[str, Any]], minimum: str) -> bool:
    floor = SEVERITY_RANK.get((minimum or "LOW").upper(), 1)
    return any(SEVERITY_RANK.get(str(a.get("severity") or "LOW").upper(), 0) >= floor for a in alerts)


def _alert_ids(alerts: Sequence[Dict[str, Any]]) -> List[str]:
    ids = []
    for alert in alerts:
        aid = alert.get("id") or alert.get("alert_id")
        if aid and aid not in ids:
            ids.append(str(aid))
    return ids


def match_rules(
    incident: Dict[str, Any],
    action: Optional[str] = None,
    target: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return proposals that have a rule id, evidence samples, and a concrete target."""
    alerts = [a for a in (incident.get("alerts") or []) if isinstance(a, dict)]
    dests = [
        d for d in (incident.get("dest_ips") or [])
        if d and str(d) not in {"", "localhost", "multiple", "multiple internal", "external", "127.0.0.1", "::1"}
    ]
    processes = [p for p in (incident.get("processes") or []) if p]
    tactics = {str(t) for t in (incident.get("tactics") or []) if t}
    pattern_ids = {str(a.get("pattern_id") or "") for a in alerts if a.get("pattern_id")}
    top_sev = str(incident.get("severity") or "LOW").upper()
    wanted_action = (action or "").strip() or None
    wanted_target = (target or "").strip() or None

    proposals: List[Dict[str, Any]] = []
    loop = incident.get("loop") if isinstance(incident.get("loop"), dict) else {}
    loop_closed = bool(loop.get("closed"))
    loop_findings = []
    if loop_closed:
        loop_findings = [
            str(row.get("finding_id") or row.get("id"))
            for row in ((loop.get("prevent") or {}).get("findings") or [])
            if row.get("finding_id") or row.get("id")
        ]

    for rule in RESPONSE_RULES:
        if wanted_action and rule["action"] != wanted_action:
            continue
        if rule.get("requires_closed_loop") and not loop_closed:
            continue
        matching_alerts = alerts
        if rule.get("pattern_ids"):
            matching_alerts = [a for a in alerts if a.get("pattern_id") in rule["pattern_ids"]]
            if not matching_alerts:
                continue
        if rule.get("tactics") and not (tactics & set(rule["tactics"])):
            if not matching_alerts:
                continue
        if not _severity_ok(matching_alerts or alerts, rule.get("min_severity") or "LOW"):
            if SEVERITY_RANK.get(top_sev, 0) < SEVERITY_RANK.get(str(rule.get("min_severity") or "LOW").upper(), 0):
                continue
        min_tactics = int(rule.get("min_tactics") or 0)
        if min_tactics and len(tactics) < min_tactics:
            continue

        kind = rule["target_kind"]
        if kind == "dest_ip":
            candidates = dests
            if rule.get("pattern_ids"):
                from_alerts = [
                    str(a.get("dest_ip") or "")
                    for a in matching_alerts
                    if a.get("dest_ip") and a.get("dest_ip") not in {"", "localhost", "multiple", "multiple internal", "external"}
                ]
                if from_alerts:
                    candidates = [d for d in dests if d in from_alerts] or from_alerts
        elif kind == "process":
            candidates = processes
        else:
            candidates = [incident.get("asset_id") or incident.get("id") or "host"]

        if wanted_target:
            if wanted_target not in candidates and kind != "asset":
                # Operator asked for a specific target; only accept it when evidence includes it.
                continue
            candidates = [wanted_target]

        evidence_ids = _alert_ids(matching_alerts or alerts)
        if not evidence_ids:
            continue

        for item in candidates:
            if not item:
                continue
            proposals.append({
                "rule_id": rule["rule_id"],
                "title": rule["title"],
                "action": rule["action"],
                "target": item,
                "target_kind": kind,
                "rollback_action": rule.get("rollback_action"),
                "rollback_possible": bool(rule.get("rollback_possible")),
                "evidence": {
                    "alert_ids": evidence_ids,
                    "finding_ids": loop_findings,
                    "pattern_ids": sorted({str(a.get("pattern_id") or "") for a in (matching_alerts or alerts) if a.get("pattern_id")}),
                    "tactics": sorted(tactics),
                    "incident_id": incident.get("id"),
                    "severity": top_sev,
                    "loop_closed": loop_closed,
                },
            })
    return proposals
