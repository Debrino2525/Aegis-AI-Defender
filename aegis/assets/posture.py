"""Join completed Prevent scans onto enrolled fleet hosts.

Posture is computed on read from live scans and fleet heartbeats. Empty when
this site has no matching scan. Never invents a CVE or a host.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from aegis.assets.identity import host_keys, normalize_host, value_hits
from aegis.intel.asset_intelligence import compute_aegis_risk_score, compute_risk_label

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
HIGH_SEV = {"HIGH", "CRITICAL"}
VERIFY_OK = {"VULNERABLE", "CONFIRMED"}

NO_SCANS = "No completed scans on this site."
NO_MATCH = "No completed scan matches this host's addresses."


def empty_posture(reason: str) -> Dict[str, Any]:
    return {
        "finding_count": 0,
        "severity_breakdown": {name: 0 for name in SEVERITIES},
        "findings": [],
        "cves": [],
        "kev_count": 0,
        "risk_score": 0,
        "risk_label": "Minimal",
        "open_ports": [],
        "scan_ids": [],
        "last_scanned_at": None,
        "empty_reason": reason,
    }


def _scan_ts(scan: Dict[str, Any]) -> str:
    return str(scan.get("completed_at") or scan.get("started_at") or "")


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    text = str(value).strip()
    return text or None


def active_scans(scans: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Latest completed scan per normalized target. Running or queued scans do not count."""
    by_target: Dict[str, Dict[str, Any]] = {}
    for scan in scans or []:
        if not isinstance(scan, dict):
            continue
        if str(scan.get("status") or "") != "done":
            continue
        if not str(scan.get("id") or "").strip():
            continue
        target = normalize_host(scan.get("target"))
        if not target:
            continue
        previous = by_target.get(target)
        if previous is None or _scan_ts(scan) >= _scan_ts(previous):
            by_target[target] = scan
    return list(by_target.values())


def _scan_hits(scan: Dict[str, Any], keys: Set[str]) -> bool:
    return value_hits(scan.get("target"), keys) or value_hits(scan.get("ip"), keys)


def matching_scans(
    scans: Sequence[Dict[str, Any]],
    keys: Set[str],
) -> List[Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
    matched: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]] = []
    if not keys:
        return matched
    for scan in active_scans(scans):
        hits = _scan_hits(scan, keys)
        findings: List[Dict[str, Any]] = []
        for finding in scan.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            if hits or value_hits(finding.get("target"), keys):
                findings.append(finding)
        if hits or findings:
            matched.append((scan, findings))
    return matched


def finding_is_verified(finding: Dict[str, Any]) -> bool:
    """CISA KEV, HIGH confidence, or a live re-test that still holds. Needs id + evidence."""
    finding_id = str(finding.get("id") or finding.get("finding_id") or "").strip()
    evidence = str(finding.get("evidence") or "").strip()
    if not finding_id or not evidence:
        return False
    verification = finding.get("verification") if isinstance(finding.get("verification"), dict) else {}
    status = str(verification.get("status") or "").upper()
    if verification.get("is_vulnerable") or status in VERIFY_OK:
        return True
    if bool(finding.get("is_cisa_kev")):
        return True
    return str(finding.get("confidence") or "").upper() == "HIGH"


def is_verified_high_kev(finding: Dict[str, Any]) -> bool:
    if not finding_is_verified(finding):
        return False
    if bool(finding.get("is_cisa_kev")):
        return True
    return str(finding.get("severity") or "").upper() in HIGH_SEV


def _public_finding(scan: Dict[str, Any], finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    finding_id = str(finding.get("id") or "").strip()
    scan_id = str(scan.get("id") or "").strip()
    if not finding_id or not scan_id:
        return None
    cve_id = str(finding.get("cve_id") or "").strip() or None
    verification = finding.get("verification") if isinstance(finding.get("verification"), dict) else None
    public = {
        "id": finding_id,
        "scan_id": scan_id,
        "title": finding.get("title") or finding_id,
        "severity": finding.get("severity"),
        "cve_id": cve_id,
        "port": finding.get("port"),
        "is_cisa_kev": bool(finding.get("is_cisa_kev")),
        "confidence": finding.get("confidence"),
        "target": finding.get("target") or scan.get("target"),
        "timestamp": _iso(finding.get("timestamp") or scan.get("started_at")),
        "evidence": finding.get("evidence") or "",
    }
    if verification:
        public["verification"] = {
            "status": verification.get("status"),
            "is_vulnerable": bool(verification.get("is_vulnerable")),
            "timestamp": _iso(verification.get("timestamp")),
            "summary": verification.get("summary") or "",
        }
    public["verified"] = finding_is_verified(public) or finding_is_verified(finding)
    return public


def _public_cve(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cve_id = str(row.get("cve_id") or "").strip()
    if not cve_id.upper().startswith("CVE-"):
        return None
    return {
        "cve_id": cve_id,
        "severity": row.get("severity"),
        "title": row.get("title"),
        "scan_id": row.get("scan_id"),
        "finding_id": row.get("id"),
        "is_cisa_kev": bool(row.get("is_cisa_kev")),
        "port": row.get("port"),
    }


def _open_ports(scan: Dict[str, Any]) -> List[int]:
    ports: List[int] = []
    seen = set()
    for item in scan.get("open_ports") or []:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    return ports


def posture_for_keys(keys: Set[str], scans: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not active_scans(scans):
        return empty_posture(NO_SCANS)
    matched = matching_scans(scans, keys)
    if not matched:
        return empty_posture(NO_MATCH)

    findings: List[Dict[str, Any]] = []
    scan_ids: List[str] = []
    ports: List[int] = []
    port_seen = set()
    last_scanned = None
    for scan, raw_findings in matched:
        scan_id = str(scan.get("id") or "").strip()
        if scan_id:
            scan_ids.append(scan_id)
        stamp = _iso(scan.get("completed_at") or scan.get("started_at"))
        if stamp and (last_scanned is None or stamp > last_scanned):
            last_scanned = stamp
        for port in _open_ports(scan):
            if port not in port_seen:
                port_seen.add(port)
                ports.append(port)
        for finding in raw_findings:
            public = _public_finding(scan, finding)
            if public:
                findings.append(public)

    breakdown = {name: 0 for name in SEVERITIES}
    for row in findings:
        sev = str(row.get("severity") or "INFO").upper()
        if sev not in breakdown:
            sev = "INFO"
        breakdown[sev] += 1
    cves = [cve for cve in (_public_cve(row) for row in findings) if cve]
    kev_count = sum(1 for row in findings if row.get("is_cisa_kev"))
    risk_score = compute_aegis_risk_score(findings)
    return {
        "finding_count": len(findings),
        "severity_breakdown": breakdown,
        "findings": findings,
        "cves": cves,
        "kev_count": kev_count,
        "risk_score": risk_score,
        "risk_label": compute_risk_label(risk_score),
        "open_ports": ports,
        "scan_ids": scan_ids,
        "last_scanned_at": last_scanned,
        "empty_reason": None,
    }


def attach_host_posture(
    hosts: Iterable[Dict[str, Any]],
    scans: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows = list(hosts or [])
    for host in rows:
        host["posture"] = posture_for_keys(host_keys(host), scans)
    return rows


def unmatched_scans(
    hosts: Sequence[Dict[str, Any]],
    scans: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    claimed: Set[str] = set()
    for host in hosts or []:
        for scan, _findings in matching_scans(scans, host_keys(host)):
            scan_id = str(scan.get("id") or "").strip()
            if scan_id:
                claimed.add(scan_id)
    rows: List[Dict[str, Any]] = []
    for scan in active_scans(scans):
        scan_id = str(scan.get("id") or "").strip()
        if not scan_id or scan_id in claimed:
            continue
        findings = [f for f in (scan.get("findings") or []) if isinstance(f, dict)]
        breakdown = {name: 0 for name in SEVERITIES}
        for finding in findings:
            sev = str(finding.get("severity") or "INFO").upper()
            if sev not in breakdown:
                sev = "INFO"
            breakdown[sev] += 1
        rows.append(
            {
                "scan_id": scan_id,
                "target": scan.get("target") or "",
                "finding_count": len(findings),
                "severity_breakdown": breakdown,
                "open_ports": _open_ports(scan),
                "started_at": _iso(scan.get("started_at")),
                "status": scan.get("status"),
            }
        )
    rows.sort(key=lambda row: str(row.get("started_at") or ""), reverse=True)
    return rows
