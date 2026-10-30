"""Analyst Assist: evidence-linked correlator output.

Groups alerts by host + time + tactic. Emits a multi-phase list only when
more than one kill-chain phase has an alert sample. Emits a hop list only
when monitor sockets, flows, or agent hop connections actually show A→B→C
on RDP/SMB/SSH. Related detections are other pattern IDs on that host in
the window. Product name stays Analyst Assist until every claim points at
a sample — this module refuses claims that cannot.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

PRODUCT_NAME = "Analyst Assist"

HOP_PORTS = {
    22: "SSH",
    139: "SMB",
    445: "SMB",
    3389: "RDP",
}

PHASE_OF = {
    "Reconnaissance": "initial",
    "Initial Access": "initial",
    "Execution": "initial",
    "Credential Access": "lateral",
    "Discovery": "lateral",
    "Lateral Movement": "lateral",
    "Exfiltration": "impact",
    "Command and Control": "impact",
    "Impact": "impact",
}

PHASE_ORDER = ("initial", "lateral", "impact")

UNUSABLE_HOSTS = {
    "",
    "unknown",
    "multiple",
    "multiple internal",
    "external",
    "localhost",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_host(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    if text.count(":") == 1 and "." in text.split(":", 1)[0]:
        text = text.split(":", 1)[0]
    if "%" in text:
        text = text.split("%", 1)[0]
    return text.strip()


def usable_ip(value: Any) -> str:
    host = normalize_host(value)
    if not host or host in UNUSABLE_HOSTS:
        return ""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host
    if (
        addr.is_loopback
        or addr.is_unspecified
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    ):
        return ""
    return host


def hop_protocol(port: Any) -> Optional[str]:
    try:
        return HOP_PORTS.get(int(port))
    except (TypeError, ValueError):
        return None


def _ts_iso(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return None
    text = str(value)
    return text or None


def _alert_id(alert: Dict[str, Any]) -> str:
    return str(alert.get("id") or alert.get("alert_id") or "").strip()


def _pattern_id(alert: Dict[str, Any]) -> str:
    return str(alert.get("pattern_id") or "").strip()


def _tactic_of(alert: Dict[str, Any]) -> str:
    return str(alert.get("tactic") or "Ungrouped").strip() or "Ungrouped"


def _alert_sample(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    alert_id = _alert_id(alert)
    if not alert_id:
        return None
    sample: Dict[str, Any] = {
        "kind": "alert",
        "id": alert_id,
        "title": alert.get("title") or "",
        "pattern_id": _pattern_id(alert) or None,
        "tactic": _tactic_of(alert),
        "technique": alert.get("technique"),
        "source_ip": alert.get("source_ip"),
        "dest_ip": alert.get("dest_ip"),
        "dest_port": alert.get("dest_port"),
        "process": alert.get("process") or "",
        "evidence": alert.get("evidence") or alert.get("summary") or "",
        "timestamp": alert.get("timestamp") or alert.get("created_at"),
        "severity": alert.get("severity"),
    }
    return {k: v for k, v in sample.items() if v is not None}


def _claim(claim_id: str, text: str, sample: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": claim_id,
        "text": text,
        "sample_id": sample["id"],
        "sample": sample,
    }


def cluster_alerts_by_time(alerts: Sequence[Dict[str, Any]], window: float) -> List[List[Dict[str, Any]]]:
    if not alerts:
        return []
    ordered = sorted(alerts, key=lambda a: a.get("_timestamp", 0) or 0)
    clusters: List[List[Dict[str, Any]]] = [[ordered[0]]]
    for alert in ordered[1:]:
        last_ts = clusters[-1][-1].get("_timestamp", 0) or 0
        curr_ts = alert.get("_timestamp", 0) or 0
        if curr_ts - last_ts <= window:
            clusters[-1].append(alert)
        else:
            clusters.append([alert])
    return clusters


def group_alerts_by_host_time_tactic(
    alerts: Sequence[Dict[str, Any]],
    window: float,
) -> List[Dict[str, Any]]:
    """One group per (host, time cluster, tactic). Not a pile of BEH titles."""
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for alert in alerts:
        host = usable_ip(alert.get("source_ip")) or normalize_host(alert.get("source_ip")) or "unknown"
        by_host.setdefault(host, []).append(alert)

    groups: List[Dict[str, Any]] = []
    for host, host_alerts in by_host.items():
        for cluster in cluster_alerts_by_time(host_alerts, window):
            by_tactic: Dict[str, List[Dict[str, Any]]] = {}
            for alert in cluster:
                by_tactic.setdefault(_tactic_of(alert), []).append(alert)
            for tactic, tactic_alerts in by_tactic.items():
                evidence = []
                pattern_ids = []
                alert_ids = []
                for alert in tactic_alerts:
                    sample = _alert_sample(alert)
                    if not sample:
                        continue
                    alert_ids.append(sample["id"])
                    pid = _pattern_id(alert)
                    if pid and pid not in pattern_ids:
                        pattern_ids.append(pid)
                    evidence.append(
                        {
                            "alert_id": sample["id"],
                            "pattern_id": pid or None,
                            "title": sample.get("title") or sample["id"],
                            "sample_id": sample["id"],
                            "sample": sample,
                        }
                    )
                if not evidence:
                    continue
                stamps = [a.get("_timestamp", 0) or 0 for a in tactic_alerts]
                groups.append(
                    {
                        "host": host,
                        "tactic": tactic,
                        "first_seen": _ts_iso(min(stamps) if stamps else None),
                        "last_seen": _ts_iso(max(stamps) if stamps else None),
                        "alert_ids": alert_ids,
                        "pattern_ids": pattern_ids,
                        "evidence": evidence,
                    }
                )
    return groups


def phases_from_groups(groups: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """initial → lateral → impact, only for phases that have evidence. Empty unless 2+."""
    buckets: Dict[str, Dict[str, Any]] = {}
    for group in groups:
        phase = PHASE_OF.get(group.get("tactic") or "")
        if not phase:
            continue
        bucket = buckets.setdefault(
            phase,
            {"phase": phase, "tactics": [], "alert_ids": [], "evidence": []},
        )
        tactic = group.get("tactic")
        if tactic and tactic not in bucket["tactics"]:
            bucket["tactics"].append(tactic)
        for item in group.get("evidence") or []:
            alert_id = item.get("alert_id")
            if alert_id and alert_id not in bucket["alert_ids"]:
                bucket["alert_ids"].append(alert_id)
                bucket["evidence"].append(
                    {
                        "alert_id": alert_id,
                        "sample_id": item.get("sample_id") or alert_id,
                        "tactic": tactic,
                        "title": item.get("title") or alert_id,
                        "sample": item.get("sample"),
                    }
                )
    ordered = [buckets[name] for name in PHASE_ORDER if name in buckets and buckets[name]["evidence"]]
    if len(ordered) < 2:
        return []
    return ordered


def related_detections(alerts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Other pattern IDs on this host in the window, each pointing at an alert sample."""
    by_pattern: Dict[str, Dict[str, Any]] = {}
    for alert in alerts:
        pid = _pattern_id(alert)
        sample = _alert_sample(alert)
        if not pid or not sample:
            continue
        row = by_pattern.setdefault(
            pid,
            {
                "pattern_id": pid,
                "title": sample.get("title") or pid,
                "tactic": sample.get("tactic"),
                "alert_ids": [],
                "sample_id": sample["id"],
                "sample": sample,
            },
        )
        if sample["id"] not in row["alert_ids"]:
            row["alert_ids"].append(sample["id"])
        if not row.get("title"):
            row["title"] = sample.get("title") or pid
    return list(by_pattern.values())


def _edge_sample(
    src: str,
    dst: str,
    port: int,
    protocol: str,
    seen_by: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    sample_id = f"hop:{seen_by}:{src}:{dst}:{port}"
    if extra:
        agent_id = str(extra.get("agent_id") or "").strip()
        if agent_id:
            sample_id = f"hop:agent:{agent_id}:{src}:{dst}:{port}"
        elif extra.get("id"):
            sample_id = str(extra["id"])
    sample: Dict[str, Any] = {
        "kind": "hop",
        "id": sample_id,
        "local_ip": src,
        "remote_ip": dst,
        "remote_port": port,
        "protocol": protocol,
        "seen_by": seen_by,
    }
    if extra:
        for key in ("agent_id", "process", "timestamp", "status", "pid"):
            if extra.get(key) not in (None, ""):
                sample[key] = extra[key]
    return sample


def hop_edge_from_observation(obs: Dict[str, Any], seen_by: str) -> Optional[Dict[str, Any]]:
    src = usable_ip(obs.get("local_ip") or obs.get("source_ip"))
    dst = usable_ip(obs.get("remote_ip") or obs.get("dest_ip"))
    port = obs.get("remote_port")
    if port in (None, "", 0):
        port = obs.get("dest_port")
    proto = hop_protocol(port)
    if not src or not dst or not proto or src == dst:
        return None
    port_i = int(port)
    sample = _edge_sample(src, dst, port_i, proto, seen_by, obs)
    return {
        "src": src,
        "dst": dst,
        "port": port_i,
        "protocol": proto,
        "seen_by": seen_by,
        "sample_id": sample["id"],
        "sample": sample,
    }


def hop_edges_from_observations(
    connections: Optional[Iterable[Dict[str, Any]]] = None,
    conn_history: Optional[Dict[Any, Any]] = None,
    hosts: Optional[Iterable[Dict[str, Any]]] = None,
    alerts: Optional[Iterable[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Directed RDP/SMB/SSH edges the monitor or an agent actually sampled.

    Alerts contribute an edge only when source and dest are real IPs on a hop
    port. Titles like "SMB to multiple internal hosts" do not become hops.
    """
    seen: Set[Tuple[str, str, int, str]] = set()
    edges: List[Dict[str, Any]] = []

    def add(edge: Optional[Dict[str, Any]]) -> None:
        if not edge:
            return
        key = (edge["src"], edge["dst"], edge["port"], edge["seen_by"])
        if key in seen:
            return
        seen.add(key)
        edges.append(edge)

    for conn in connections or []:
        add(hop_edge_from_observation(conn, "monitor"))

    for raw_key, stamps in (conn_history or {}).items():
        if not stamps:
            continue
        if not isinstance(raw_key, (tuple, list)) or len(raw_key) < 3:
            continue
        src, dst, port = raw_key[0], raw_key[1], raw_key[2]
        add(
            hop_edge_from_observation(
                {
                    "kind": "flow",
                    "id": f"flow:{src}:{dst}:{port}",
                    "local_ip": src,
                    "remote_ip": dst,
                    "remote_port": port,
                },
                "monitor",
            )
        )

    for host in hosts or []:
        agent_id = str(host.get("agent_id") or "").strip()
        for hop in host.get("hop_connections") or []:
            if not isinstance(hop, dict):
                continue
            payload = dict(hop)
            payload["agent_id"] = agent_id or hop.get("agent_id")
            add(hop_edge_from_observation(payload, "agent"))

    for alert in alerts or []:
        add(hop_edge_from_observation(alert, "monitor"))

    return edges


def hop_paths(edges: Sequence[Dict[str, Any]], hosts: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """A→B→C only. A star A→B and A→C is not a hop path."""
    by_src: Dict[str, List[Dict[str, Any]]] = {}
    for edge in edges:
        by_src.setdefault(edge["src"], []).append(edge)

    paths: List[Dict[str, Any]] = []
    seen_paths: Set[Tuple[str, ...]] = set()
    for first in edges:
        a, b = first["src"], first["dst"]
        for second in by_src.get(b, []):
            c = second["dst"]
            if c in {a, b}:
                continue
            path = (a, b, c)
            if path in seen_paths:
                continue
            if hosts and not any(node in hosts for node in path):
                continue
            seen_paths.add(path)
            paths.append(
                {
                    "path": [a, b, c],
                    "edges": [first, second],
                }
            )
    return paths


def hop_observations_from_sources(
    connections: Optional[Iterable[Dict[str, Any]]] = None,
    conn_history: Optional[Dict[Any, Any]] = None,
    hosts: Optional[Iterable[Dict[str, Any]]] = None,
    alerts: Optional[Iterable[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for conn in connections or []:
        row = dict(conn)
        row.setdefault("seen_by", "monitor")
        rows.append(row)
    for raw_key, stamps in (conn_history or {}).items():
        if not stamps or not isinstance(raw_key, (tuple, list)) or len(raw_key) < 3:
            continue
        src, dst, port = raw_key[0], raw_key[1], raw_key[2]
        rows.append(
            {
                "id": f"flow:{src}:{dst}:{port}",
                "local_ip": src,
                "remote_ip": dst,
                "remote_port": port,
                "kind": "flow",
                "seen_by": "monitor",
            }
        )
    for host in hosts or []:
        agent_id = str(host.get("agent_id") or "").strip()
        for hop in host.get("hop_connections") or []:
            if not isinstance(hop, dict):
                continue
            row = dict(hop)
            row["agent_id"] = agent_id or hop.get("agent_id")
            row["seen_by"] = "agent"
            rows.append(row)
    for alert in alerts or []:
        rows.append(dict(alert))
    return rows


def build_analyst_assist(
    alerts: Sequence[Dict[str, Any]],
    *,
    window: float = 600,
    connections: Optional[Iterable[Dict[str, Any]]] = None,
    conn_history: Optional[Dict[Any, Any]] = None,
    hosts: Optional[Iterable[Dict[str, Any]]] = None,
    hop_observations: Optional[Iterable[Dict[str, Any]]] = None,
    focus_hosts: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    alerts = [a for a in alerts if isinstance(a, dict)]
    groups = group_alerts_by_host_time_tactic(alerts, window)
    phases = phases_from_groups(groups)
    related = related_detections(alerts)

    incident_hosts: Set[str] = set()
    for alert in alerts:
        for field in ("source_ip", "dest_ip"):
            host = usable_ip(alert.get(field))
            if host:
                incident_hosts.add(host)
    for group in groups:
        if group.get("host") and group["host"] != "unknown":
            incident_hosts.add(str(group["host"]))
    for raw in focus_hosts or []:
        host = usable_ip(raw) or normalize_host(raw)
        if host and host not in UNUSABLE_HOSTS:
            incident_hosts.add(host)

    obs_rows = list(hop_observations or [])
    edges = hop_edges_from_observations(
        connections=list(connections or []) + obs_rows,
        conn_history=conn_history,
        hosts=hosts,
        alerts=alerts,
    )
    hops = hop_paths(edges, hosts=incident_hosts) if incident_hosts else []

    claims: List[Dict[str, Any]] = []
    gaps: List[str] = []

    for index, group in enumerate(groups):
        sample = (group["evidence"][0] or {}).get("sample")
        if not sample:
            continue
        pattern_text = ", ".join(group["pattern_ids"]) or "no pattern id"
        claims.append(
            _claim(
                f"claim-group-{index}-{group['tactic']}",
                (
                    f"Host {group['host']}: {group['tactic']} "
                    f"({len(group['alert_ids'])} alert"
                    f"{'' if len(group['alert_ids']) == 1 else 's'}; {pattern_text})."
                ),
                sample,
            )
        )

    if len(phases) >= 2:
        for phase in phases:
            sample = (phase["evidence"][0] or {}).get("sample")
            if not sample:
                continue
            claims.append(
                _claim(
                    f"claim-phase-{phase['phase']}",
                    (
                        f"Phase {phase['phase']} has evidence from "
                        f"{', '.join(phase['tactics'])}."
                    ),
                    sample,
                )
            )
    elif groups:
        mapped = {PHASE_OF.get(g["tactic"]) for g in groups if PHASE_OF.get(g.get("tactic") or "")}
        mapped.discard(None)
        if len(mapped) < 2:
            gaps.append("Multi-phase list omitted: fewer than two kill-chain phases have evidence.")

    if hops:
        for index, hop in enumerate(hops):
            for edge in hop["edges"]:
                claims.append(
                    _claim(
                        f"claim-hop-{index}-{edge['src']}-{edge['dst']}-{edge['port']}",
                        (
                            f"Observed {edge['protocol']} {edge['src']} → "
                            f"{edge['dst']}:{edge['port']} "
                            f"({edge['seen_by']})."
                        ),
                        edge["sample"],
                    )
                )
    else:
        gaps.append(
            "No hop path A→B→C: monitor and agent samples did not show a two-step RDP/SMB/SSH chain."
        )

    for detection in related:
        sample = detection.get("sample")
        if not sample:
            continue
        claims.append(
            _claim(
                f"claim-pattern-{detection['pattern_id']}",
                (
                    f"Related detection {detection['pattern_id']} "
                    f"on this host ({len(detection['alert_ids'])} alert"
                    f"{'' if len(detection['alert_ids']) == 1 else 's'})."
                ),
                sample,
            )
        )

    linked_claims = []
    for claim in claims:
        sample = claim.get("sample")
        sample_id = claim.get("sample_id")
        if not sample or not sample_id or sample.get("id") != sample_id:
            continue
        linked_claims.append(claim)

    evidence_linked = bool(linked_claims) and len(linked_claims) == len(claims)
    if not alerts:
        evidence_linked = True
        gaps.append("No alerts in this window to group.")

    summary = _summary(groups, phases, hops, linked_claims)

    return {
        "product": PRODUCT_NAME,
        "evidence_linked": evidence_linked,
        "summary": summary,
        "groups": groups,
        "phases": phases,
        "hops": hops,
        "related_detections": related,
        "claims": linked_claims,
        "gaps": gaps,
        "assembled_at": _now_iso(),
    }


def _summary(
    groups: Sequence[Dict[str, Any]],
    phases: Sequence[Dict[str, Any]],
    hops: Sequence[Dict[str, Any]],
    claims: Sequence[Dict[str, Any]],
) -> str:
    if not groups:
        return "Analyst Assist has no alerts to group for this host and window."
    hosts = sorted({g["host"] for g in groups})
    tactics = [g["tactic"] for g in groups]
    host_text = ", ".join(hosts)
    tactic_text = ", ".join(tactics)
    parts = [
        f"Analyst Assist grouped {sum(len(g['alert_ids']) for g in groups)} alert(s) "
        f"on {host_text} by tactic: {tactic_text}."
    ]
    if phases:
        parts.append(
            "Evidence-linked phases: "
            + " → ".join(f"{p['phase']} ({', '.join(p['tactics'])})" for p in phases)
            + "."
        )
    if hops:
        paths = "; ".join(" → ".join(h["path"]) for h in hops)
        parts.append(f"Observed hop path(s): {paths}.")
    if not claims:
        parts.append("No evidence-linked claim could be formed.")
    return " ".join(parts)
