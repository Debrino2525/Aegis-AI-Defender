"""Assemble one investigation from live monitor, agent, and scan samples.

Nothing is invented. A claim is emitted only when it can point at a sample
(socket, alert, finding, agent telemetry, or scan record).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote

from aegis.assets.identity import host_keys as _host_keys
from aegis.assets.identity import is_unusable_ip as _is_unusable_ip
from aegis.assets.identity import normalize_host
from aegis.assets.identity import value_hits as _value_hits
from aegis.assets.posture import matching_scans, posture_for_keys
from aegis.monitor.analyst_assist import build_analyst_assist
from aegis.monitor.closed_loop import closed_loop_for_incident
from aegis.monitor.remediation import PROTECTED_PROCESS_NAMES, preview_contain_action


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_investigation_key(raw: str) -> Tuple[str, str]:
    key = unquote(str(raw or "")).strip()
    if key.startswith("host:"):
        return "host", key[5:].strip()
    if key.startswith("ip:"):
        return "ip", normalize_host(key[3:])
    if key.startswith("agt_"):
        return "host", key
    return "ip", normalize_host(key)


def investigation_id(kind: str, value: str) -> str:
    if kind == "host":
        return f"host:{value}"
    return f"ip:{normalize_host(value)}"


def _sample(kind: str, sample_id: str, **fields: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"kind": kind, "id": sample_id}
    for name, value in fields.items():
        if value is not None:
            payload[name] = value
    return payload


@dataclass
class DeviceSources:
    hosts: List[Dict[str, Any]] = field(default_factory=list)
    connections: List[Dict[str, Any]] = field(default_factory=list)
    conn_history: Dict[Any, List[float]] = field(default_factory=dict)
    monitor_alerts: List[Dict[str, Any]] = field(default_factory=list)
    routed_alerts: List[Dict[str, Any]] = field(default_factory=list)
    scans: List[Dict[str, Any]] = field(default_factory=list)


def _socket_sample(conn: Dict[str, Any], index: int) -> Dict[str, Any]:
    local_ip = conn.get("local_ip") or ""
    remote_ip = conn.get("remote_ip") or ""
    port = conn.get("remote_port")
    pid = conn.get("pid")
    sample_id = f"sock:{local_ip}:{remote_ip}:{port}:{pid if pid is not None else index}"
    return _sample(
        "socket",
        sample_id,
        local_ip=local_ip,
        remote_ip=remote_ip,
        remote_port=port,
        status=conn.get("status"),
        pid=pid,
        process=conn.get("process") or "",
        timestamp=conn.get("timestamp"),
        is_internal=conn.get("is_internal"),
        port_label=conn.get("port_label") or "",
    )


def _alert_sample(alert: Dict[str, Any], source: str) -> Optional[Dict[str, Any]]:
    alert_id = str(alert.get("id") or alert.get("alert_id") or "").strip()
    if not alert_id:
        return None
    return _sample(
        "alert",
        alert_id,
        source=source,
        title=alert.get("title") or "",
        severity=alert.get("severity"),
        pattern_id=alert.get("pattern_id"),
        source_ip=alert.get("source_ip"),
        dest_ip=alert.get("dest_ip"),
        dest_port=alert.get("dest_port"),
        process=alert.get("process") or "",
        tactic=alert.get("tactic"),
        technique=alert.get("technique"),
        evidence=alert.get("evidence") or alert.get("summary") or "",
        timestamp=alert.get("timestamp") or alert.get("created_at") or alert.get("last_occurrence"),
        acknowledged=alert.get("acknowledged"),
    )


def _finding_sample(scan: Dict[str, Any], finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    finding_id = str(finding.get("id") or "").strip()
    scan_id = str(scan.get("id") or "").strip()
    if not finding_id or not scan_id:
        return None
    ts = finding.get("timestamp") or scan.get("started_at")
    if hasattr(ts, "isoformat"):
        ts = ts.isoformat()
    return _sample(
        "finding",
        f"{scan_id}:{finding_id}",
        scan_id=scan_id,
        finding_id=finding_id,
        title=finding.get("title") or finding_id,
        target=finding.get("target") or scan.get("target"),
        port=finding.get("port"),
        severity=finding.get("severity"),
        cve_id=finding.get("cve_id"),
        evidence=finding.get("evidence") or "",
        timestamp=ts,
    )


def _telemetry_sample(host: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = str(host.get("agent_id") or "")
    listening = host.get("listening_tcp") or []
    if not isinstance(listening, list):
        listening = []
    return _sample(
        "agent_telemetry",
        agent_id,
        hostname=host.get("hostname") or "",
        os_name=host.get("os_name") or "",
        os_version=host.get("os_version") or "",
        arch=host.get("arch") or "",
        last_seen=host.get("last_seen"),
        enrolled_at=host.get("enrolled_at"),
        status=host.get("status"),
        ipv4=list(host.get("ipv4") or []),
        ipv6=list(host.get("ipv6") or []),
        remote_ip=host.get("remote_ip") or "",
        listen_count=host.get("listen_count"),
        listening_tcp=listening[:64],
        connection_count=host.get("connection_count"),
        process_count=host.get("process_count"),
        cpu_percent=host.get("cpu_percent"),
        memory_percent=host.get("memory_percent"),
        hop_connections=list(host.get("hop_connections") or [])[:32],
    )


def _scan_sample(scan: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    scan_id = str(scan.get("id") or "").strip()
    if not scan_id:
        return None
    return _sample(
        "scan",
        scan_id,
        target=scan.get("target"),
        status=scan.get("status"),
        started_at=scan.get("started_at"),
        total_findings=scan.get("total_findings"),
        open_ports=scan.get("open_ports") or [],
    )


def _flow_sample(src: str, dst: str, port: int, stamps: Sequence[float]) -> Dict[str, Any]:
    last = max(stamps) if stamps else 0.0
    ts = datetime.fromtimestamp(last, tz=timezone.utc).isoformat() if last else None
    sample_id = f"flow:{src}:{dst}:{port}"
    return _sample(
        "flow",
        sample_id,
        local_ip=src,
        remote_ip=dst,
        remote_port=port,
        observations=len(stamps),
        timestamp=ts,
    )


def _match_host(sources: DeviceSources, kind: str, value: str) -> Tuple[Optional[Dict[str, Any]], Set[str], str, str]:
    if kind == "host":
        wanted = value.strip()
        for host in sources.hosts:
            if str(host.get("agent_id") or "") == wanted:
                keys = _host_keys(host)
                return host, keys, "enrolled_host", investigation_id("host", wanted)
        for host in sources.hosts:
            if wanted.lower() in _host_keys(host):
                keys = _host_keys(host)
                agent_id = str(host.get("agent_id") or "")
                return host, keys, "enrolled_host", investigation_id("host", agent_id)
        return None, set(), "enrolled_host", investigation_id("host", wanted)

    ip = normalize_host(value)
    for host in sources.hosts:
        keys = _host_keys(host)
        if ip in keys:
            agent_id = str(host.get("agent_id") or "")
            return host, keys, "enrolled_host", investigation_id("host", agent_id)
    return None, {ip} if ip else set(), "source_ip", investigation_id("ip", ip)


def _matching_connections(sources: DeviceSources, keys: Set[str]) -> List[Dict[str, Any]]:
    rows = []
    for index, conn in enumerate(sources.connections or []):
        if _value_hits(conn.get("local_ip"), keys) or _value_hits(conn.get("remote_ip"), keys):
            rows.append(_socket_sample(conn, index))
    return rows


def _matching_flows(sources: DeviceSources, keys: Set[str]) -> List[Dict[str, Any]]:
    rows = []
    for raw_key, stamps in (sources.conn_history or {}).items():
        if not stamps:
            continue
        if not isinstance(raw_key, (tuple, list)) or len(raw_key) < 3:
            continue
        src, dst, port = raw_key[0], raw_key[1], raw_key[2]
        if not (_value_hits(src, keys) or _value_hits(dst, keys)):
            continue
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            continue
        rows.append(_flow_sample(str(src), str(dst), port_i, list(stamps)))
    return rows


def _matching_monitor_alerts(sources: DeviceSources, keys: Set[str]) -> List[Dict[str, Any]]:
    rows = []
    for alert in sources.monitor_alerts or []:
        if _value_hits(alert.get("source_ip"), keys) or _value_hits(alert.get("dest_ip"), keys):
            sample = _alert_sample(alert, "monitor")
            if sample:
                rows.append(sample)
    return rows


def _matching_routed_alerts(sources: DeviceSources, keys: Set[str]) -> List[Dict[str, Any]]:
    rows = []
    for alert in sources.routed_alerts or []:
        if _value_hits(alert.get("source_ip"), keys) or _value_hits(alert.get("dest_ip"), keys):
            sample = _alert_sample(alert, "routed")
            if sample:
                rows.append(sample)
    return rows


def _matching_scans(sources: DeviceSources, keys: Set[str]) -> List[Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
    matched: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]] = []
    for scan, findings in matching_scans(sources.scans or [], keys):
        samples = []
        for finding in findings:
            sample = _finding_sample(scan, finding)
            if sample:
                samples.append(sample)
        matched.append((scan, samples))
    return matched


def _claim(claim_id: str, text: str, sample: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": claim_id,
        "text": text,
        "sample_id": sample["id"],
        "sample": sample,
    }


def _timeline_entry(sample: Dict[str, Any], title: str, detail: str = "") -> Dict[str, Any]:
    return {
        "id": sample["id"],
        "ts": sample.get("timestamp") or sample.get("last_seen") or sample.get("started_at"),
        "kind": sample["kind"],
        "title": title,
        "detail": detail,
        "sample": sample,
    }


def _contain_from_samples(
    sockets: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def add(action: str, target: str, sample: Dict[str, Any]) -> None:
        key = f"{action}:{target}"
        if not target or key in seen:
            return
        if action in {"block_ip", "isolate_connections"} and _is_unusable_ip(target):
            return
        preview = preview_contain_action(action, target, sockets=sockets)
        preview["evidence_sample_id"] = sample["id"]
        preview["evidence"] = {
            "kind": sample["kind"],
            "id": sample["id"],
        }
        seen.add(key)
        actions.append(preview)

    for sock in sockets:
        remote = str(sock.get("remote_ip") or "")
        add("isolate_connections", remote, sock)
        add("block_ip", remote, sock)
        proc = str(sock.get("process") or "").strip()
        if proc and proc.lower() not in PROTECTED_PROCESS_NAMES:
            add("terminate_process", proc, sock)

    for alert in alerts:
        dest = str(alert.get("dest_ip") or "")
        add("block_ip", dest, alert)
        proc = str(alert.get("process") or "").strip()
        if proc and proc.lower() not in PROTECTED_PROCESS_NAMES:
            add("terminate_process", proc, alert)

    return actions


def build_investigation(sources: DeviceSources, key: str) -> Optional[Dict[str, Any]]:
    kind, value = parse_investigation_key(key)
    if kind == "ip" and not value:
        return None
    if kind == "host" and not value:
        return None

    host, keys, device_kind, inv_id = _match_host(sources, kind, value)
    if kind == "host" and host is None:
        return None
    if not keys:
        return None

    sockets = _matching_connections(sources, keys)
    flows = _matching_flows(sources, keys)
    monitor_alerts = _matching_monitor_alerts(sources, keys)
    routed_alerts = _matching_routed_alerts(sources, keys)
    scan_hits = _matching_scans(sources, keys)

    claims: List[Dict[str, Any]] = []
    timeline: List[Dict[str, Any]] = []
    gaps: List[str] = []
    sources_used: List[str] = []

    device: Dict[str, Any]
    if host:
        telemetry = _telemetry_sample(host)
        sources_used.append("agent_telemetry")
        device = {
            "kind": "enrolled_host",
            "agent_id": host.get("agent_id"),
            "hostname": host.get("hostname") or "",
            "addresses": sorted(k for k in keys if k != str(host.get("agent_id") or "").lower()),
            "os_name": host.get("os_name") or "",
            "os_version": host.get("os_version") or "",
            "arch": host.get("arch") or "",
            "status": host.get("status"),
            "last_seen": host.get("last_seen"),
            "enrolled_at": host.get("enrolled_at"),
            "posture": posture_for_keys(keys, sources.scans or []),
            "sample": telemetry,
        }
        listen_n = host.get("listen_count")
        listen_text = f"{listen_n} listening TCP port" + ("" if listen_n == 1 else "s")
        if listen_n is None:
            listen_text = "no listen-count field on the last heartbeat"
        claims.append(
            _claim(
                "claim-heartbeat",
                (
                    f"Enrolled host {host.get('hostname') or host.get('agent_id')} "
                    f"last heartbeated at {host.get('last_seen') or 'unknown'} "
                    f"({listen_text})."
                ),
                telemetry,
            )
        )
        timeline.append(
            _timeline_entry(
                telemetry,
                f"Agent heartbeat {host.get('hostname') or host.get('agent_id')}",
                f"status {host.get('status') or 'unknown'}",
            )
        )
        for listen in (host.get("listening_tcp") or [])[:16]:
            if not isinstance(listen, dict):
                continue
            port = listen.get("port")
            ip = listen.get("ip") or ""
            listen_sample = _sample(
                "listen",
                f"listen:{host.get('agent_id')}:{ip}:{port}",
                agent_id=host.get("agent_id"),
                ip=ip,
                port=port,
                timestamp=host.get("last_seen"),
            )
            timeline.append(
                _timeline_entry(
                    listen_sample,
                    f"Listening {ip}:{port}",
                    "From the last agent heartbeat, not a packet capture.",
                )
            )
    else:
        device = {
            "kind": "source_ip",
            "agent_id": None,
            "hostname": "",
            "addresses": sorted(keys),
            "os_name": "",
            "os_version": "",
            "arch": "",
            "status": None,
            "last_seen": None,
            "enrolled_at": None,
            "posture": posture_for_keys(keys, sources.scans or []),
            "sample": None,
        }
        gaps.append("No enrolled host matches this address. Investigation is keyed by source IP only.")

    if sockets:
        sources_used.append("monitor_sockets")
        first = sockets[0]
        claims.append(
            _claim(
                "claim-sockets",
                f"{len(sockets)} live socket sample"
                + ("" if len(sockets) == 1 else "s")
                + f" on this console involve {', '.join(sorted(keys))}.",
                first,
            )
        )
        for sock in sockets:
            route = f"{sock.get('local_ip')} → {sock.get('remote_ip')}:{sock.get('remote_port')}"
            proc = sock.get("process") or "unknown process"
            timeline.append(_timeline_entry(sock, f"Socket {route}", proc))
    else:
        gaps.append("No live monitor socket sample matches this host.")

    if flows:
        sources_used.append("monitor_flows")
        for flow in flows:
            timeline.append(
                _timeline_entry(
                    flow,
                    (
                        f"Recent flow {flow.get('local_ip')} → {flow.get('remote_ip')}:"
                        f"{flow.get('remote_port')}"
                    ),
                    f"{flow.get('observations')} timestamp"
                    + ("" if flow.get("observations") == 1 else "s")
                    + " in the monitor window.",
                )
            )

    related: List[Dict[str, Any]] = []
    if monitor_alerts:
        sources_used.append("monitor_alerts")
        for alert in monitor_alerts:
            related.append(
                {
                    "id": alert["id"],
                    "source": "monitor",
                    "severity": alert.get("severity"),
                    "title": alert.get("title") or alert["id"],
                    "pattern_id": alert.get("pattern_id"),
                    "sample": alert,
                }
            )
            claims.append(
                _claim(
                    f"claim-alert-{alert['id']}",
                    f"Monitor alert {alert['id']}: {alert.get('title') or alert['id']}.",
                    alert,
                )
            )
            timeline.append(
                _timeline_entry(
                    alert,
                    alert.get("title") or alert["id"],
                    alert.get("evidence") or "",
                )
            )
    if routed_alerts:
        sources_used.append("routed_alerts")
        for alert in routed_alerts:
            related.append(
                {
                    "id": alert["id"],
                    "source": "routed",
                    "severity": alert.get("severity"),
                    "title": alert.get("title") or alert["id"],
                    "pattern_id": alert.get("pattern_id"),
                    "sample": alert,
                }
            )
            claims.append(
                _claim(
                    f"claim-routed-{alert['id']}",
                    f"Routed alert {alert['id']}: {alert.get('title') or alert['id']}.",
                    alert,
                )
            )
            if not any(item["id"] == alert["id"] for item in timeline):
                timeline.append(
                    _timeline_entry(
                        alert,
                        alert.get("title") or alert["id"],
                        alert.get("evidence") or "",
                    )
                )
    if not related:
        gaps.append("No related alerts for this host in the current monitor or routing queue.")

    finding_count = 0
    for scan, findings in scan_hits:
        scan_sample = _scan_sample(scan)
        if scan_sample:
            sources_used.append("scans")
            timeline.append(
                _timeline_entry(
                    scan_sample,
                    f"Scan {scan_sample['id']} of {scan.get('target')}",
                    f"status {scan.get('status') or 'unknown'}",
                )
            )
        for finding in findings:
            finding_count += 1
            claims.append(
                _claim(
                    f"claim-finding-{finding['id']}",
                    f"Scan finding {finding.get('finding_id')}: {finding.get('title')}.",
                    finding,
                )
            )
            timeline.append(
                _timeline_entry(
                    finding,
                    finding.get("title") or finding["id"],
                    finding.get("evidence") or "",
                )
            )
    if not scan_hits:
        gaps.append("No scan target or finding matches this host.")

    timeline.sort(key=lambda row: str(row.get("ts") or ""), reverse=True)

    contain_actions = _contain_from_samples(sockets, monitor_alerts + routed_alerts)
    if not contain_actions:
        gaps.append("No contain dry-run: there is no socket or alert sample with a blockable address or process.")

    for claim in claims:
        if not claim.get("sample") or not claim.get("sample_id"):
            raise ValueError("investigation assembler emitted a claim without a sample")

    assist = build_analyst_assist(
        [alert for alert in (monitor_alerts + routed_alerts)],
        connections=sources.connections,
        conn_history=sources.conn_history,
        hosts=sources.hosts,
        focus_hosts=keys,
    )
    if assist.get("hops"):
        sources_used.append("analyst_assist_hops")

    loop = closed_loop_for_incident(
        {
            "id": inv_id,
            "source_ips": sorted(keys),
            "alerts": monitor_alerts + routed_alerts,
            "analyst_assist": assist,
        },
        hosts=sources.hosts or ([device] if device_kind == "enrolled_host" and device else []),
        scans=sources.scans or [],
    )
    if loop.get("closed"):
        sources_used.append("closed_loop")

    return {
        "id": inv_id,
        "device": device,
        "device_kind": device_kind,
        "product": assist.get("product") or "Analyst Assist",
        "loop": loop,
        "analyst_assist": assist,
        "claims": claims,
        "timeline": timeline,
        "related_alerts": related,
        "contain": {
            "mode": "dry_run",
            "mutates": False,
            "scope": "This console host. Dry-run does not push isolate to a fleet agent.",
            "actions": contain_actions,
        },
        "counts": {
            "claims": len(claims),
            "timeline": len(timeline),
            "related_alerts": len(related),
            "sockets": len(sockets),
            "findings": finding_count,
            "assist_groups": len(assist.get("groups") or []),
            "assist_hops": len(assist.get("hops") or []),
        },
        "gaps": gaps + list(assist.get("gaps") or []),
        "sources_used": sorted(set(sources_used)),
        "assembled_at": _now_iso(),
    }


def list_investigations(sources: DeviceSources) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    covered: Set[str] = set()

    for host in sources.hosts or []:
        agent_id = str(host.get("agent_id") or "").strip()
        if not agent_id:
            continue
        inv = build_investigation(sources, investigation_id("host", agent_id))
        if not inv:
            continue
        covered |= set(inv["device"].get("addresses") or [])
        covered.add(agent_id.lower())
        hostname = normalize_host(host.get("hostname"))
        if hostname:
            covered.add(hostname)
        rows.append(
            {
                "id": inv["id"],
                "kind": "enrolled_host",
                "label": host.get("hostname") or agent_id,
                "agent_id": agent_id,
                "addresses": inv["device"].get("addresses") or [],
                "status": host.get("status"),
                "alert_count": inv["counts"]["related_alerts"],
                "socket_count": inv["counts"]["sockets"],
                "finding_count": inv["counts"]["findings"],
                "kev_count": (inv["device"].get("posture") or {}).get("kev_count") or 0,
            }
        )

    extra_ips: Set[str] = set()
    for conn in sources.connections or []:
        for field_name in ("local_ip", "remote_ip"):
            addr = normalize_host(conn.get(field_name))
            if addr and not _is_unusable_ip(addr) and addr not in covered:
                extra_ips.add(addr)
    for alert in list(sources.monitor_alerts or []) + list(sources.routed_alerts or []):
        for field_name in ("source_ip", "dest_ip"):
            addr = normalize_host(alert.get(field_name))
            if addr and not _is_unusable_ip(addr) and addr not in covered:
                extra_ips.add(addr)
    for scan in sources.scans or []:
        addr = normalize_host(scan.get("target"))
        if addr and not _is_unusable_ip(addr) and addr not in covered:
            extra_ips.add(addr)

    for ip in sorted(extra_ips):
        inv = build_investigation(sources, investigation_id("ip", ip))
        if not inv:
            continue
        rows.append(
            {
                "id": inv["id"],
                "kind": "source_ip",
                "label": ip,
                "agent_id": None,
                "addresses": inv["device"].get("addresses") or [ip],
                "status": None,
                "alert_count": inv["counts"]["related_alerts"],
                "socket_count": inv["counts"]["sockets"],
                "finding_count": inv["counts"]["findings"],
                "kev_count": (inv["device"].get("posture") or {}).get("kev_count") or 0,
            }
        )

    return {"investigations": rows}
