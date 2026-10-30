"""
Real-Time Network Monitor — Core Engine.
Uses psutil to monitor all live network connections and interface I/O.
Runs continuously in a background asyncio task, feeding the behavioral engine.
"""

import asyncio
import time
import socket
import ipaddress
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from datetime import datetime

import psutil
import httpx
from urllib.parse import urlparse

from aegis.monitor.behavioral_engine import BehavioralEngine
from aegis.monitor.geoip import collect_monitor_ips, geoip_snapshot
from aegis.monitor.threat_patterns import (
    MALICIOUS_PORTS, HIGH_RISK_REMOTE_PORTS, THREAT_PATTERNS,
    is_routine_web_edge_traffic,
    is_well_known_web_edge,
)


def is_private_ip(ip: str) -> bool:
    """Returns True if the IP is RFC-1918 private."""
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except Exception:
        return True


def get_local_ips() -> Set[str]:
    """Returns the set of all local machine IP addresses."""
    ips = set()
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ips.add(addr.address)
    except Exception:
        pass
    return ips


class NetworkMonitor:
    """
    Continuously monitors network connections using psutil.
    Detects behavioral anomalies and generates genuine security alerts.
    """

    SAMPLE_INTERVAL = 5   # seconds between observation samples
    BEACON_WINDOW = 120   # seconds to look back for beaconing detection
    SCAN_WINDOW = 60      # seconds window for port scan detection

    def __init__(self):
        self.running = False
        self.started_at: Optional[float] = None
        self.behavioral_engine = BehavioralEngine()
        self.alerts: List[Dict[str, Any]] = []
        self.seen_alert_keys: Set[str] = set()

        # Connection history: {(src_ip, dst_ip, dst_port): [timestamps]}
        self.conn_history: Dict[Tuple, List[float]] = defaultdict(list)

        # Per-source scan tracking: {src_ip: {dst_port: last_seen}}
        self.scan_tracker: Dict[str, Dict[int, float]] = defaultdict(dict)

        # Network I/O snapshots for delta calculation
        self._last_io: Dict[str, Any] = {}
        self._last_io_time: float = 0

        # Current connections snapshot
        self.current_connections: List[Dict] = []
        self.connection_count_history: List[Dict] = []

        # Monitored Targets Watchlist (URLs / IPs)
        self.watched_targets: Dict[str, Dict[str, Any]] = {}
        self._target_counter: int = 0

        # Network graph: nodes and edges
        self.graph_nodes: Dict[str, Dict] = {}
        self.graph_edges: Dict[str, Dict] = {}

        # Stats
        self.stats = {
            "total_connections_seen": 0,
            "alerts_generated": 0,
            "hosts_profiled": 0,
            "packets_analyzed": 0,
            "uptime_seconds": 0,
        }

        self.local_ips = get_local_ips()

    async def start(self):
        """Starts the monitoring loop."""
        self.running = True
        self.started_at = time.time()
        asyncio.create_task(self._monitor_loop())
        asyncio.create_task(self._io_loop())
        asyncio.create_task(self._probe_targets_loop())

    def stop(self):
        self.running = False

    # ── Core monitoring loop ─────────────────────────────────────────────────
    async def _monitor_loop(self):
        """Main loop: sample connections every SAMPLE_INTERVAL seconds."""
        while self.running:
            try:
                await self._sample_connections()
            except Exception as e:
                pass  # Don't crash the monitor on errors
            await asyncio.sleep(self.SAMPLE_INTERVAL)

    async def _io_loop(self):
        """Tracks network I/O bytes delta for exfiltration detection."""
        while self.running:
            try:
                self.stats["uptime_seconds"] = int(time.time() - (self.started_at or time.time()))
                now = time.time()
                io = psutil.net_io_counters()
                if self._last_io:
                    dt = now - self._last_io_time
                    if dt > 0:
                        sent_rate = (io.bytes_sent - self._last_io.get("bytes_sent", 0)) / dt
                        recv_rate = (io.bytes_recv - self._last_io.get("bytes_recv", 0)) / dt
                        self._check_exfiltration(sent_rate, recv_rate)

                self._last_io = {
                    "bytes_sent": io.bytes_sent,
                    "bytes_recv": io.bytes_recv,
                    "packets_sent": io.packets_sent,
                    "packets_recv": io.packets_recv,
                }
                self._last_io_time = now
            except Exception:
                pass
            await asyncio.sleep(10)

    # ── Connection sampling ──────────────────────────────────────────────────
    async def _sample_connections(self):
        """Samples all current TCP connections and runs detection logic."""
        loop = asyncio.get_event_loop()
        try:
            conns = await loop.run_in_executor(None, lambda: psutil.net_connections(kind="inet"))
        except Exception:
            return

        now = time.time()
        current_snapshot = []

        # Track per-source stats for this sample
        src_port_map: Dict[str, Set[int]] = defaultdict(set)
        src_dst_map: Dict[str, Set[str]] = defaultdict(set)
        src_smb: Dict[str, int] = defaultdict(int)
        src_auth: Dict[str, int] = defaultdict(int)

        for conn in conns:
            if not conn.raddr:
                continue

            laddr = conn.laddr.ip if conn.laddr else ""
            rip = conn.raddr.ip
            rport = conn.raddr.port
            status = conn.status

            # Skip loopback
            if is_loopback(rip) or is_loopback(laddr):
                continue

            # Get process name
            proc_name = ""
            try:
                if conn.pid:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
            except Exception:
                pass

            conn_dict = {
                "local_ip": laddr,
                "remote_ip": rip,
                "remote_port": rport,
                "status": status,
                "pid": conn.pid,
                "process": proc_name,
                "is_internal": is_private_ip(rip),
                "port_label": MALICIOUS_PORTS.get(rport, ""),
                "timestamp": datetime.utcnow().isoformat(),
            }
            current_snapshot.append(conn_dict)

            # Track for scan/lateral movement detection
            src_port_map[laddr].add(rport)
            src_dst_map[laddr].add(rip)
            if rport == 445:
                src_smb[laddr] += 1
            if rport in (22, 3389, 23, 110, 143):
                src_auth[laddr] += 1

            # Log connection history for beaconing detection
            key = (laddr, rip, rport)
            self.conn_history[key].append(now)
            # Prune old entries
            self.conn_history[key] = [
                t for t in self.conn_history[key] if now - t < self.BEACON_WINDOW
            ]

            # Immediate checks
            self._check_malicious_port(laddr, rip, rport, proc_name)
            self._check_high_risk_egress(laddr, rip, rport, proc_name)

            # Update graph
            self._update_graph(laddr, rip, rport, proc_name)

            self.stats["total_connections_seen"] += 1

        self.current_connections = current_snapshot

        # Prune old scan data
        for src in list(self.scan_tracker.keys()):
            self.scan_tracker[src] = {
                port: ts for port, ts in self.scan_tracker[src].items()
                if now - ts < self.SCAN_WINDOW
            }
            for conn in current_snapshot:
                if conn["local_ip"] == src:
                    self.scan_tracker[src][conn["remote_port"]] = now

        # Run batch detections
        for src_ip, ports in src_port_map.items():
            self._check_port_scan(src_ip, ports, now)
            self._check_smb_lateral(src_ip, src_smb.get(src_ip, 0))
            self._check_auth_bruteforce(src_ip, src_auth.get(src_ip, 0))
            self._check_beaconing(src_ip, src_dst_map.get(src_ip, set()), now)

            # Update behavioral baseline & score anomalies
            dest_set = src_dst_map.get(src_ip, set())
            sample = {
                "new_connections": len(ports),
                "bytes_sent_delta": 0,
                "bytes_recv_delta": 0,
                "unique_ports_count": len(ports),
                "unique_destinations": len(dest_set),
                "smb_connections": src_smb.get(src_ip, 0),
                "auth_connections": src_auth.get(src_ip, 0),
                "destinations": list(dest_set),
                "ports": list(ports),
            }
            anomaly_score = self.behavioral_engine.update_and_score(src_ip, sample)
            self._check_behavioral_anomaly(src_ip, anomaly_score, sample)
            self._check_novel_destinations(src_ip, dest_set)

        self.stats["hosts_profiled"] = len(self.behavioral_engine.baselines)
        self.connection_count_history.append({
            "timestamp": now,
            "count": len(current_snapshot)
        })
        # Keep last 360 samples (30 min at 5s intervals)
        self.connection_count_history = self.connection_count_history[-360:]

    # ── Detection methods ───────────────────────────────────────────────────
    def _check_high_risk_egress(self, src: str, dst: str, port: int, proc: str):
        """Detects direct outbound connections to sensitive infrastructure ports on external IPs."""
        if port in HIGH_RISK_REMOTE_PORTS and not is_private_ip(dst):
            service_names = {
                22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
                445: "SMB", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB"
            }
            svc = service_names.get(port, f"Port {port}")
            self._emit_alert(
                pattern_id="AEGIS-BEH-006",
                severity="HIGH",
                title=f"High-Risk Outbound Protocol: {svc} to {dst}:{port}",
                description=f"Process '{proc or 'unknown'}' on {src} initiated outbound {svc} (port {port}) "
                            f"connection to external remote IP {dst}. Unexpected egress on administrative services "
                            f"often indicates data exfiltration or remote control.",
                source_ip=src,
                dest_ip=dst,
                dest_port=port,
                process=proc,
                evidence=f"{src} → {dst}:{port} ({svc}) | Process: {proc or 'N/A'}",
                tactic="Command and Control",
                technique="T1095",
            )

    def _check_behavioral_anomaly(self, src_ip: str, score: float, sample: Dict[str, Any]):
        """Emits alerts when statistical deviation exceeds baseline thresholds."""
        if score >= 75.0:
            self._emit_alert(
                pattern_id="AEGIS-BEH-008",
                severity="HIGH",
                title=f"Severe Network Anomaly on {src_ip} (Score: {score:.1f}/100)",
                description=f"Host {src_ip} demonstrated statistical deviation (anomaly score {score:.1f}/100) "
                            f"across unique destinations ({sample.get('unique_destinations')}) and connection rate "
                            f"compared to historical baseline.",
                source_ip=src_ip,
                dest_ip="multiple",
                dest_port=0,
                process="",
                evidence=f"Anomaly score: {score:.1f}/100 | Sample: {sample.get('unique_destinations')} dsts, {sample.get('new_connections')} conns",
                tactic="Defense Evasion",
                technique="T1071",
            )
        elif score >= 45.0:
            self._emit_alert(
                pattern_id="AEGIS-BEH-009",
                severity="MEDIUM",
                title=f"Elevated Baseline Deviation on {src_ip} (Score: {score:.1f}/100)",
                description=f"Host {src_ip} traffic patterns deviated from established baseline profile "
                            f"(anomaly score {score:.1f}/100).",
                source_ip=src_ip,
                dest_ip="multiple",
                dest_port=0,
                process="",
                evidence=f"Anomaly score: {score:.1f}/100 | Sample destinations: {sample.get('unique_destinations')}",
                tactic="Discovery",
                technique="T1046",
            )

    def _check_novel_destinations(self, src: str, dest_set: Set[str]):
        """Flags initial connections to unprofiled external IP addresses."""
        for dst in list(dest_set)[:8]:
            if is_well_known_web_edge(dst):
                continue
            if not is_private_ip(dst) and self.behavioral_engine.is_new_destination(src, dst):
                self._emit_alert(
                    pattern_id="AEGIS-BEH-005",
                    severity="LOW",
                    title=f"New External Destination Contacted: {dst}",
                    description=f"Host {src} established first-time communication with external IP {dst} "
                                f"not observed in previous behavioral profiles.",
                    source_ip=src,
                    dest_ip=dst,
                    dest_port=0,
                    process="",
                    evidence=f"New destination IP: {dst} | Source: {src}",
                    tactic="Initial Access",
                    technique="T1190",
                )

    def _check_malicious_port(self, src: str, dst: str, port: int, proc: str):
        """Flags connections to known malicious/RAT ports."""
        if port in MALICIOUS_PORTS and not is_private_ip(dst):
            label = MALICIOUS_PORTS[port]
            self._emit_alert(
                pattern_id="AEGIS-BEH-004",
                severity="CRITICAL",
                title=f"Connection to Malicious Port {port} ({label})",
                description=f"Process '{proc or 'unknown'}' on {src} established a connection to {dst}:{port} "
                            f"— a port associated with: {label}. This strongly indicates malware or backdoor activity.",
                source_ip=src,
                dest_ip=dst,
                dest_port=port,
                process=proc,
                evidence=f"{src} → {dst}:{port} | Port label: {label} | Process: {proc or 'N/A'}",
                tactic="Command and Control",
                technique="T1095",
            )

    def _check_port_scan(self, src: str, ports: Set[int], now: float):
        """Detects port scanning behavior."""
        if len(ports) >= 10:
            self._emit_alert(
                pattern_id="AEGIS-BEH-001",
                severity="HIGH",
                title=f"Port Scan Detected from {src}",
                description=f"Host {src} contacted {len(ports)} unique destination ports in the last "
                            f"{self.SAMPLE_INTERVAL}s — a clear indicator of automated port scanning.",
                source_ip=src,
                dest_ip="multiple",
                dest_port=0,
                process="",
                evidence=f"Unique ports contacted: {len(ports)} | Sample ports: {sorted(list(ports))[:10]}",
                tactic="Discovery",
                technique="T1046",
            )

    def _check_smb_lateral(self, src: str, smb_count: int):
        """Detects SMB-based lateral movement."""
        if smb_count >= 3:
            self._emit_alert(
                pattern_id="AEGIS-BEH-010",
                severity="CRITICAL",
                title=f"SMB Lateral Movement from {src}",
                description=f"Host {src} is making SMB connections to {smb_count} internal hosts — "
                            f"typical of ransomware propagation or worm-like lateral movement.",
                source_ip=src,
                dest_ip="multiple internal",
                dest_port=445,
                process="",
                evidence=f"SMB (port 445) connections to {smb_count} unique hosts from {src}",
                tactic="Lateral Movement",
                technique="T1021.002",
            )

    def _check_auth_bruteforce(self, src: str, auth_count: int):
        """Detects brute force on authentication services."""
        if auth_count >= 15:
            self._emit_alert(
                pattern_id="AEGIS-BEH-007",
                severity="HIGH",
                title=f"Brute Force Attack from {src}",
                description=f"Host {src} made {auth_count} connections to authentication services "
                            f"(SSH/RDP/SMTP) — characteristic of automated credential brute forcing.",
                source_ip=src,
                dest_ip="multiple",
                dest_port=22,
                process="",
                evidence=f"{auth_count} auth service connections from {src} in {self.SAMPLE_INTERVAL}s",
                tactic="Credential Access",
                technique="T1110",
            )

    def _check_beaconing(self, src: str, dsts: Set[str], now: float):
        """Detects regular interval beaconing (C2 check-in pattern)."""
        for dst in dsts:
            if is_private_ip(dst):
                continue
            for port in [80, 443, 8080, 8443, 4444, 4443]:
                if is_routine_web_edge_traffic(dst, port):
                    continue
                key = (src, dst, port)
                timestamps = self.conn_history.get(key, [])
                if len(timestamps) < 4:
                    continue
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                if not intervals:
                    continue
                avg_interval = sum(intervals) / len(intervals)
                stddev = (sum((x - avg_interval)**2 for x in intervals) / len(intervals)) ** 0.5
                # Low stddev = highly regular = beaconing
                if stddev < 5.0 and 5 < avg_interval < 300:
                    self._emit_alert(
                        pattern_id="AEGIS-BEH-002",
                        severity="CRITICAL",
                        title=f"C2 Beaconing Detected: {src} → {dst}",
                        description=f"Host {src} is making highly regular connections to {dst}:{port} every "
                                    f"~{avg_interval:.0f}s (stddev={stddev:.1f}s) — a strong indicator of "
                                    f"malware C2 check-in (RAT, botnet, Cobalt Strike).",
                        source_ip=src,
                        dest_ip=dst,
                        dest_port=port,
                        process="",
                        evidence=f"Interval: {avg_interval:.1f}s ± {stddev:.1f}s over {len(timestamps)} connections | Key: {key}",
                        tactic="Command and Control",
                        technique="T1071",
                    )

    def _check_exfiltration(self, sent_rate: float, recv_rate: float):
        """Flags unusually high outbound data rates."""
        MB = 1024 * 1024
        if sent_rate > 10 * MB:  # >10 MB/s outbound
            self._emit_alert(
                pattern_id="AEGIS-BEH-003",
                severity="CRITICAL",
                title=f"Data Exfiltration Alert — {sent_rate/MB:.1f} MB/s Outbound",
                description=f"System-wide outbound data rate of {sent_rate/MB:.1f} MB/s detected — "
                            f"significantly above normal baseline. Potential data exfiltration in progress.",
                source_ip="localhost",
                dest_ip="external",
                dest_port=0,
                process="",
                evidence=f"Outbound rate: {sent_rate/MB:.2f} MB/s | Inbound rate: {recv_rate/MB:.2f} MB/s",
                tactic="Exfiltration",
                technique="T1048",
            )

    # ── Alert emission ──────────────────────────────────────────────────────
    def _emit_alert(self, pattern_id: str, severity: str, title: str,
                    description: str, source_ip: str, dest_ip: str,
                    dest_port: int, process: str, evidence: str,
                    tactic: str, technique: str):
        """Emits a deduplicated alert."""
        # Deduplicate: same pattern + same source within 5 minutes
        dedup_key = f"{pattern_id}:{source_ip}:{dest_ip}"
        now = time.time()

        # Check if we already emitted this alert in the last 5 minutes
        for existing in self.alerts[-50:]:
            if existing.get("_dedup_key") == dedup_key:
                if now - existing.get("_timestamp", 0) < 300:
                    return  # Suppress duplicate

        alert = {
            "id": f"ALT-{len(self.alerts)+1:04d}",
            "pattern_id": pattern_id,
            "severity": severity,
            "title": title,
            "description": description,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "process": process,
            "evidence": evidence,
            "tactic": tactic,
            "technique": technique,
            "timestamp": datetime.utcnow().isoformat(),
            "acknowledged": False,
            "_timestamp": now,
            "_dedup_key": dedup_key,
        }
        self.alerts.append(alert)
        # Keep last 500 alerts
        self.alerts = self.alerts[-500:]
        self.stats["alerts_generated"] += 1
        self._persist_monitor_alert(alert)
        try:
            from aegis.alerting.router import alert_router
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(alert_router.route_behavioral_alert(alert))
        except Exception:
            pass

    # ── Network graph ───────────────────────────────────────────────────────
    def _update_graph(self, src: str, dst: str, port: int, proc: str):
        """Maintains a live network connection graph for visualization."""
        # Add/update nodes
        for ip in [src, dst]:
            if ip not in self.graph_nodes:
                self.graph_nodes[ip] = {
                    "id": ip,
                    "type": "local" if ip in self.local_ips else ("internal" if is_private_ip(ip) else "external"),
                    "connections": 0,
                    "last_seen": time.time(),
                    "is_suspicious": False,
                }
            self.graph_nodes[ip]["connections"] += 1
            self.graph_nodes[ip]["last_seen"] = time.time()

        # Mark suspicious nodes
        if port in MALICIOUS_PORTS:
            self.graph_nodes[dst]["is_suspicious"] = True

        # Add/update edge
        edge_key = f"{src}->{dst}:{port}"
        self.graph_edges[edge_key] = {
            "source": src,
            "target": dst,
            "port": port,
            "process": proc,
            "suspicious": port in MALICIOUS_PORTS,
            "last_seen": time.time(),
        }
        # Prune stale edges (not seen in last 30s)
        stale = [k for k, v in self.graph_edges.items() if time.time() - v["last_seen"] > 30]
        for k in stale:
            del self.graph_edges[k]

    # ── Monitored Targets Watchlist ──────────────────────────────────────────
    def add_target(self, raw_input: str) -> Dict[str, Any]:
        """Adds a URL, domain, or IP address to continuous threat monitoring."""
        raw = raw_input.strip()
        if not raw:
            raise ValueError("Target cannot be empty")

        url_scheme = ""
        host = raw
        port = None

        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            url_scheme = parsed.scheme
            host = parsed.hostname or raw
            port = parsed.port
        elif "://" in raw:
            parsed = urlparse(raw)
            host = parsed.hostname or raw
            port = parsed.port
        elif ":" in raw and not raw.startswith("["):
            parts = raw.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        self._target_counter += 1
        tid = f"TGT-{self._target_counter:03d}"

        target_obj = {
            "id": tid,
            "raw": raw,
            "host": host,
            "url_scheme": url_scheme,
            "specified_port": port,
            "resolved_ip": None,
            "status": "INITIALIZING",  # ONLINE, DEGRADED, OFFLINE
            "latency_ms": None,
            "open_ports": [],
            "http_status": None,
            "server_header": None,
            "last_checked": None,
            "added_at": datetime.utcnow().isoformat(),
            "drift_alerts": 0,
            "traffic_seen_locally": False,
        }
        self.watched_targets[tid] = target_obj
        return target_obj

    def remove_target(self, target_id: str) -> bool:
        if target_id in self.watched_targets:
            del self.watched_targets[target_id]
            return True
        return False

    async def _probe_targets_loop(self):
        """Periodically probes all watched targets for availability, port drift, and threats."""
        while self.running:
            try:
                targets = list(self.watched_targets.values())
                for tgt in targets:
                    await self._probe_single_target(tgt)
            except Exception:
                pass
            await asyncio.sleep(15)

    async def _probe_single_target(self, tgt: Dict[str, Any]):
        """Probes a single watched target for reachability, open ports, and live threat signals."""
        host = tgt["host"]
        now = time.time()
        tgt["last_checked"] = datetime.utcnow().isoformat()

        # 1. DNS Resolution
        loop = asyncio.get_event_loop()
        try:
            resolved_ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(host))
            if tgt["resolved_ip"] and tgt["resolved_ip"] != resolved_ip:
                # DNS IP changed!
                self._emit_alert(
                    pattern_id="AEGIS-BEH-012",
                    severity="MEDIUM",
                    title=f"DNS Drift Detected for Watched Target {host}",
                    description=f"Target {host} IP address changed from {tgt['resolved_ip']} to {resolved_ip}. "
                                f"Verify if this is legitimate CDN/load balancer behavior or DNS hijacking.",
                    source_ip="localhost",
                    dest_ip=resolved_ip,
                    dest_port=53,
                    process="AegisWatch",
                    evidence=f"Previous IP: {tgt['resolved_ip']} | New IP: {resolved_ip}",
                    tactic="Impact",
                    technique="T1584",
                )
                tgt["drift_alerts"] += 1
            tgt["resolved_ip"] = resolved_ip
        except Exception:
            tgt["status"] = "OFFLINE"
            tgt["latency_ms"] = None
            return

        target_ip = tgt["resolved_ip"] or host

        # 2. Port check (sample key ports)
        ports_to_check = [80, 443, 22, 21, 8080, 8443, 3389, 3306, 6379]
        if tgt["specified_port"] and tgt["specified_port"] not in ports_to_check:
            ports_to_check.insert(0, tgt["specified_port"])

        new_open_ports = []
        best_latency = None

        for p in ports_to_check:
            t0 = time.time()
            try:
                conn_task = asyncio.open_connection(target_ip, p)
                reader, writer = await asyncio.wait_for(conn_task, timeout=1.5)
                rtt = round((time.time() - t0) * 1000, 1)
                writer.close()
                await writer.wait_closed()
                new_open_ports.append(p)
                if best_latency is None or rtt < best_latency:
                    best_latency = rtt
            except Exception:
                pass

        # Check for unexpected newly opened ports
        old_ports = set(tgt.get("open_ports", []))
        current_ports = set(new_open_ports)
        added_ports = current_ports - old_ports
        if old_ports and added_ports:
            self._emit_alert(
                pattern_id="AEGIS-BEH-011",
                severity="HIGH",
                title=f"New Port Exposed on Watched Host {host}",
                description=f"Host {host} ({target_ip}) newly opened port(s): {sorted(list(added_ports))}. "
                            f"Unscheduled port exposure indicates potential unauthorized service launch or backdoor.",
                source_ip=target_ip,
                dest_ip="external",
                dest_port=list(added_ports)[0],
                process="",
                evidence=f"Previously observed ports: {sorted(list(old_ports))} | Newly open: {sorted(list(added_ports))}",
                tactic="Initial Access",
                technique="T1190",
            )
            tgt["drift_alerts"] += 1

        tgt["open_ports"] = new_open_ports
        tgt["latency_ms"] = best_latency

        # 3. HTTP Health Probe if web ports are open or URL was specified
        if 80 in new_open_ports or 443 in new_open_ports or tgt["url_scheme"]:
            scheme = tgt["url_scheme"] or ("https" if 443 in new_open_ports else "http")
            url = f"{scheme}://{host}"
            if tgt["specified_port"]:
                url += f":{tgt['specified_port']}"
            try:
                async with httpx.AsyncClient(verify=False, timeout=3.0, follow_redirects=True) as client:
                    resp = await client.get(url)
                    tgt["http_status"] = resp.status_code
                    tgt["server_header"] = resp.headers.get("Server", "undisclosed")
            except Exception:
                pass

        # Status calculation
        if new_open_ports or tgt["http_status"]:
            tgt["status"] = "ONLINE"
        else:
            tgt["status"] = "OFFLINE"

        # 4. Check if local host has any active connections to this watched target
        traffic_detected = any(
            c.get("remote_ip") == target_ip or c.get("remote_ip") == host
            for c in self.current_connections
        )
        tgt["traffic_seen_locally"] = traffic_detected

        # 5. Add/Update Network Graph node cleanly (no duplicates)
        node_id = host
        existing = self.graph_nodes.get(node_id) or (self.graph_nodes.get(target_ip) if target_ip else None)
        if existing:
            existing["type"] = "monitored"
            existing["ip"] = target_ip
            existing["connections"] = max(existing.get("connections", 0), len(new_open_ports))
            existing["last_seen"] = now
            existing["is_suspicious"] = tgt["status"] == "OFFLINE" or tgt["drift_alerts"] > 0
        else:
            self.graph_nodes[node_id] = {
                "id": node_id,
                "type": "monitored",
                "ip": target_ip,
                "connections": max(1, len(new_open_ports)),
                "last_seen": now,
                "is_suspicious": tgt["status"] == "OFFLINE" or tgt["drift_alerts"] > 0,
            }

    # ── Data access ─────────────────────────────────────────────────────────
    def get_state(self) -> Dict[str, Any]:
        """Returns the full current monitor state for the API."""
        now = time.time()
        # Prune stale graph nodes and deduplicate by canonical ID
        seen_ids = set()
        active_nodes = []
        for k, v in list(self.graph_nodes.items()):
            if now - v.get("last_seen", 0) < 60:
                nid = v.get("id")
                if nid and nid not in seen_ids:
                    seen_ids.add(nid)
                    active_nodes.append(v)
            else:
                self.graph_nodes.pop(k, None)

        return {
            "running": self.running,
            "started_at": self.started_at,
            "uptime_seconds": self.stats["uptime_seconds"],
            "stats": self.stats,
            "alerts": list(reversed(self.alerts[-100:])),
            "connections": self.current_connections[:200],
            "monitored_targets": list(self.watched_targets.values()),
            "graph": {
                "nodes": active_nodes,
                "edges": list(self.graph_edges.values())[-150:],
            },
            "baselines": self.behavioral_engine.get_all_baselines(),
            "connection_history": self.connection_count_history[-60:],
            "alert_summary": {
                "CRITICAL": sum(1 for a in self.alerts if a["severity"] == "CRITICAL"),
                "HIGH": sum(1 for a in self.alerts if a["severity"] == "HIGH"),
                "MEDIUM": sum(1 for a in self.alerts if a["severity"] == "MEDIUM"),
                "LOW": sum(1 for a in self.alerts if a["severity"] == "LOW"),
                "unacknowledged": sum(1 for a in self.alerts if not a["acknowledged"]),
            },
            "geoip": geoip_snapshot(collect_monitor_ips(self.current_connections, active_nodes)),
        }

    def acknowledge_alert(self, alert_id: str) -> bool:
        for a in self.alerts:
            if a["id"] == alert_id:
                a["acknowledged"] = True
                self._persist_monitor_alert(a)
                return True
        return False

    def _persist_monitor_alert(self, alert: Dict[str, Any]) -> None:
        try:
            from aegis.persistence.history_store import get_history_store
            get_history_store().save_monitor_alert(alert)
        except Exception as exc:
            print(f"[AEGIS] Failed to persist monitor alert {alert.get('id')}: {exc}")
