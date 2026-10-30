"""Close Prevent → Detect → Respond on one incident.

A loop exists only when this site has:
1. An enrolled host with a verified HIGH or CISA KEV finding on its posture.
2. A later behavioral detection (real pattern id + sample) on that same host.

Nothing is invented. Empty when any piece is missing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from aegis.assets.identity import host_keys, is_unusable_ip, normalize_host
from aegis.assets.posture import is_verified_high_kev, posture_for_keys
from aegis.monitor.analyst_assist import PRODUCT_NAME, _alert_sample, _claim

ISOLATE_ACTION = "quarantine_host"
EMPTY_NO_HOST = "No enrolled host matches this incident."
EMPTY_NO_FINDING = "No verified HIGH or KEV finding on this host's posture."
EMPTY_NO_DETECT = "No later behavioral detection on this host."
EMPTY_DETECT_NOT_LATER = "Behavioral detection is not later than the Prevent finding."


def _parse_ts(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def finding_sample(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    finding_id = str(finding.get("id") or finding.get("finding_id") or "").strip()
    scan_id = str(finding.get("scan_id") or "").strip()
    if not finding_id:
        return None
    sample_id = f"{scan_id}:{finding_id}" if scan_id else finding_id
    sample: Dict[str, Any] = {
        "kind": "finding",
        "id": sample_id,
        "finding_id": finding_id,
        "scan_id": scan_id or None,
        "title": finding.get("title") or finding_id,
        "severity": finding.get("severity"),
        "cve_id": finding.get("cve_id"),
        "is_cisa_kev": bool(finding.get("is_cisa_kev")),
        "confidence": finding.get("confidence"),
        "verified": True,
        "target": finding.get("target"),
        "port": finding.get("port"),
        "evidence": finding.get("evidence") or "",
        "timestamp": finding.get("timestamp"),
    }
    verification = finding.get("verification")
    if isinstance(verification, dict) and verification:
        sample["verification"] = {
            "status": verification.get("status"),
            "is_vulnerable": bool(verification.get("is_vulnerable")),
            "timestamp": verification.get("timestamp"),
            "summary": verification.get("summary") or "",
        }
    return {k: v for k, v in sample.items() if v is not None}


def qualifying_findings(posture: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not posture or posture.get("empty_reason"):
        return []
    rows: List[Dict[str, Any]] = []
    for finding in posture.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        if not is_verified_high_kev(finding):
            continue
        sample = finding_sample(finding)
        if sample:
            rows.append(sample)
    return rows


def incident_address_keys(incident: Dict[str, Any]) -> Set[str]:
    keys: Set[str] = set()
    values: List[Any] = []
    values.extend(incident.get("source_ips") or [])
    values.append(incident.get("source_ip"))
    for alert in incident.get("alerts") or []:
        if isinstance(alert, dict):
            values.append(alert.get("source_ip"))
    for raw in values:
        host = normalize_host(raw)
        if host and not is_unusable_ip(host):
            keys.add(host)
    return keys


def matching_enrolled_host(
    incident: Dict[str, Any],
    hosts: Sequence[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    keys = incident_address_keys(incident)
    if not keys:
        return None
    for host in hosts or []:
        if not isinstance(host, dict) or not host.get("agent_id"):
            continue
        if keys & host_keys(host):
            return host
    return None


def _alert_event_ts(alert: Dict[str, Any]) -> Optional[float]:
    iso = _parse_ts(alert.get("timestamp") or alert.get("created_at"))
    if iso is not None:
        return iso
    raw = alert.get("_timestamp")
    if isinstance(raw, (int, float)) and float(raw) >= 1_000_000_000:
        return float(raw)
    return None


def later_detections(
    alerts: Sequence[Dict[str, Any]],
    finding_ts: Optional[float],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        pattern_id = str(alert.get("pattern_id") or "").strip()
        if not pattern_id.startswith("AEGIS-BEH-"):
            continue
        sample = _alert_sample(alert)
        if not sample:
            continue
        detect_ts = _alert_event_ts(alert)
        if finding_ts is not None and detect_ts is not None and detect_ts < finding_ts:
            continue
        rows.append(sample)
    return rows


def empty_loop(reason: str) -> Dict[str, Any]:
    return {
        "closed": False,
        "empty_reason": reason,
        "prevent": {"findings": []},
        "detect": {"alerts": [], "pattern_ids": []},
        "host": None,
    }


def _earliest_finding_ts(findings: Sequence[Dict[str, Any]]) -> Optional[float]:
    stamps = [_parse_ts(row.get("timestamp")) for row in findings]
    stamps = [ts for ts in stamps if ts is not None]
    return min(stamps) if stamps else None


def closed_loop_for_incident(
    incident: Dict[str, Any],
    *,
    hosts: Sequence[Dict[str, Any]],
    scans: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    host = matching_enrolled_host(incident, hosts)
    if not host:
        return empty_loop(EMPTY_NO_HOST)

    posture = host.get("posture") if isinstance(host.get("posture"), dict) else None
    if posture is None:
        posture = posture_for_keys(host_keys(host), scans)
    findings = qualifying_findings(posture)
    if not findings:
        return empty_loop(EMPTY_NO_FINDING)

    finding_ts = _earliest_finding_ts(findings)
    detections = later_detections(incident.get("alerts") or [], finding_ts)
    if not detections:
        raw_alerts = [a for a in (incident.get("alerts") or []) if isinstance(a, dict) and a.get("pattern_id")]
        if raw_alerts and finding_ts is not None:
            detect_times = [_alert_event_ts(a) for a in raw_alerts]
            detect_times = [ts for ts in detect_times if ts is not None]
            if detect_times and max(detect_times) < finding_ts:
                return empty_loop(EMPTY_DETECT_NOT_LATER)
        return empty_loop(EMPTY_NO_DETECT)

    pattern_ids: List[str] = []
    for sample in detections:
        pid = str(sample.get("pattern_id") or "").strip()
        if pid and pid not in pattern_ids:
            pattern_ids.append(pid)

    return {
        "closed": True,
        "empty_reason": None,
        "prevent": {"findings": findings},
        "detect": {"alerts": detections, "pattern_ids": pattern_ids},
        "host": {
            "agent_id": host.get("agent_id"),
            "hostname": host.get("hostname") or "",
            "ipv4": list(host.get("ipv4") or []),
        },
    }


def _isolate_action(loop: Dict[str, Any]) -> Dict[str, Any]:
    host = loop.get("host") or {}
    target = host.get("agent_id") or host.get("hostname") or "host"
    finding_ids = [row.get("finding_id") for row in (loop.get("prevent") or {}).get("findings") or [] if row.get("finding_id")]
    pattern_ids = list((loop.get("detect") or {}).get("pattern_ids") or [])
    return {
        "id": "isolate_host",
        "label": "Isolate host",
        "action": ISOLATE_ACTION,
        "target": target,
        "danger": True,
        "description": (
            "Recommend isolate on the enrolled host. Confirm queues isolation, "
            "signs the audit, and pages Slack, Teams, or email under the hourly cap."
        ),
        "evidence": {
            "finding_ids": finding_ids,
            "pattern_ids": pattern_ids,
        },
    }


def _merge_loop_claims(incident: Dict[str, Any], loop: Dict[str, Any]) -> None:
    assist = incident.get("analyst_assist")
    if not isinstance(assist, dict):
        assist = {"product": PRODUCT_NAME, "claims": [], "gaps": []}
        incident["analyst_assist"] = assist
    claims = list(assist.get("claims") or [])
    for index, finding in enumerate((loop.get("prevent") or {}).get("findings") or []):
        claims.append(
            _claim(
                f"claim-prevent-{finding.get('finding_id') or index}",
                (
                    f"Prevent finding {finding.get('finding_id')}: "
                    f"{finding.get('title') or finding.get('finding_id')}."
                ),
                finding,
            )
        )
    for index, sample in enumerate((loop.get("detect") or {}).get("alerts") or []):
        claims.append(
            _claim(
                f"claim-detect-{sample.get('id') or index}",
                (
                    f"Detect {sample.get('pattern_id') or sample.get('id')}: "
                    f"{sample.get('title') or sample.get('id')}."
                ),
                sample,
            )
        )
    linked = []
    for claim in claims:
        sample = claim.get("sample")
        sample_id = claim.get("sample_id")
        if not sample or not sample_id or sample.get("id") != sample_id:
            continue
        linked.append(claim)
    assist["claims"] = linked
    assist["evidence_linked"] = bool(linked) and len(linked) == len(claims)
    assist["loop"] = {
        "closed": True,
        "finding_ids": [f.get("finding_id") for f in (loop.get("prevent") or {}).get("findings") or []],
        "pattern_ids": list((loop.get("detect") or {}).get("pattern_ids") or []),
    }
    finding_ids = ", ".join(
        str(f.get("finding_id")) for f in (loop.get("prevent") or {}).get("findings") or [] if f.get("finding_id")
    )
    pattern_ids = ", ".join((loop.get("detect") or {}).get("pattern_ids") or [])
    host = (loop.get("host") or {}).get("hostname") or (incident.get("source_ips") or ["host"])[0]
    extra = (
        f" Closed Prevent → Detect loop on {host}: findings {finding_ids or 'none'}; "
        f"detections {pattern_ids or 'none'}."
    )
    narrative = str(incident.get("narrative") or assist.get("summary") or "").rstrip()
    if "Closed Prevent" not in narrative:
        incident["narrative"] = (narrative + extra).strip()
        assist["summary"] = incident["narrative"]


def attach_closed_loop(
    incidents: Iterable[Dict[str, Any]],
    *,
    hosts: Sequence[Dict[str, Any]],
    scans: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Annotate Analyst Assist incidents. Does not invent incidents from findings alone."""
    out: List[Dict[str, Any]] = []
    for incident in incidents or []:
        row = dict(incident)
        loop = closed_loop_for_incident(row, hosts=hosts, scans=scans)
        row["loop"] = loop
        if loop.get("closed"):
            _merge_loop_claims(row, loop)
            actions = list(row.get("executable_actions") or [])
            isolate = _isolate_action(loop)
            if not any(a.get("action") == ISOLATE_ACTION for a in actions):
                actions.insert(0, isolate)
            row["executable_actions"] = actions
            recommended = list(row.get("recommended_actions") or [])
            isolate_text = "Recommend isolate on the enrolled host, then confirm to sign the audit and page Slack, Teams, or email."
            if isolate_text not in recommended:
                recommended.insert(0, isolate_text)
            row["recommended_actions"] = recommended
        out.append(row)
    return out
