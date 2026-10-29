"""
Central scan orchestrator — ties all engines together into one coherent scan pipeline.
"""

import asyncio
import socket
import uuid
from datetime import datetime
from typing import List
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from aegis.core.config import ScanConfig
from aegis.core.models import HostScanResult, ScanReport, Finding, Severity
from aegis.discovery.port_scanner import AsyncPortScanner
from aegis.discovery.fingerprint import ServiceFingerprinter
from aegis.discovery.cpe_matcher import CPEMatcher
from aegis.database.db import VulnerabilityDatabase
from aegis.scoring.risk_engine import RiskPrioritizationEngine

console = Console()


class ScanEngine:
    """Aegis scan orchestrator that coordinates all discovery, matching, and reporting pipelines."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.port_scanner = AsyncPortScanner(config)
        self.fingerprinter = ServiceFingerprinter(config)
        self.vdb = VulnerabilityDatabase(config.data_dir / "vdb.sqlite3")
        self.risk_engine = RiskPrioritizationEngine()

    async def run(self) -> ScanReport:
        """Executes the full scan pipeline and returns a structured ScanReport."""
        started_at = datetime.utcnow()
        scan_id = str(uuid.uuid4())[:8].upper()

        console.print(f"\n[bold cyan]  ██████  AEGIS VULNERABILITY SCANNER  ██████[/bold cyan]")
        console.print(f"[dim]  Scan ID: {scan_id} | Target: {self.config.target}[/dim]\n")

        # --- Step 1: Resolve Target ---
        from aegis.core.target import normalize_target
        clean_host, custom_port = normalize_target(self.config.target)
        host = clean_host or self.config.target
        if custom_port and custom_port not in self.config.ports:
            self.config.ports = [custom_port] + [p for p in self.config.ports if p != custom_port]
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            console.print(f"[red][!] Could not resolve host: {host}[/red]")
            ip = host

        console.print(f"[bold green][+] Target resolved:[/bold green] {host} → {ip}")

        host_result = HostScanResult(host=host, ip=ip)
        findings: List[Finding] = []

        # --- Step 2: Port Discovery ---
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"[cyan]Scanning {len(self.config.ports)} ports...", total=len(self.config.ports))

            open_ports = await self.port_scanner.scan_target(ip, self.config.ports)
            progress.update(task, completed=len(self.config.ports))

        host_result.open_ports = open_ports
        console.print(f"\n[bold green][+] Open ports found:[/bold green] {open_ports or 'None'}\n")

        if not open_ports:
            console.print("[yellow][!] No open ports found. Host may be filtered or offline.[/yellow]")
            completed_at = datetime.utcnow()
            return ScanReport(
                scan_id=scan_id, target=host,
                started_at=started_at, completed_at=completed_at,
                duration_seconds=(completed_at - started_at).total_seconds(),
                hosts=[host_result], total_findings=0, severity_breakdown={}
            )

        # --- Step 3: Service Fingerprinting ---
        console.print("[bold cyan][*] Fingerprinting services on open ports...[/bold cyan]")
        fingerprint_tasks = [self.fingerprinter.fingerprint(ip, port) for port in open_ports]
        services = await asyncio.gather(*fingerprint_tasks, return_exceptions=True)

        for svc in services:
            if isinstance(svc, Exception):
                continue
            # Generate CPE if we have product/version
            if svc.product:
                svc.cpe = CPEMatcher.generate_cpe(svc.product, svc.version)
            host_result.services.append(svc)

            console.print(
                f"  [green]PORT {svc.port}/tcp[/green] "
                f"[white]{svc.service_name.upper():10s}[/white] "
                f"[yellow]{svc.product or '':20s}[/yellow] "
                f"[dim]{svc.version or ''}[/dim]"
            )

        # --- Step 4: CVE / VDB Matching ---
        console.print("\n[bold cyan][*] Correlating with vulnerability database...[/bold cyan]")
        for svc in host_result.services:
            if not svc.product:
                continue

            # Determine vendor/product from CPE or raw product name
            vendor, product = self._resolve_vendor_product(svc)
            vulns = self.vdb.query_vulnerabilities(vendor, product, svc.version)

            for vuln in vulns:
                detection_method = "cve_exact_match" if svc.version else "cve_partial_match"
                finding = Finding(
                    id=vuln.id,
                    title=vuln.title,
                    target=host,
                    port=svc.port,
                    service=svc.service_name,
                    severity=vuln.severity,
                    cvss_score=vuln.cvss_score,
                    epss_score=vuln.epss_score,
                    is_cisa_kev=vuln.is_cisa_kev,
                    description=vuln.description,
                    evidence=f"Detected {svc.product} {svc.version or '(version unknown)'} on port {svc.port}",
                    remediation=vuln.remediation,
                    cve_id=vuln.id if vuln.id.startswith("CVE-") else None,
                    references=vuln.references,
                )
                # Apply composite risk prioritization with detection method
                finding = self.risk_engine.prioritize_finding(finding, detection_method=detection_method)
                findings.append(finding)

        # --- Step 5: HTTP Misconfiguration Checks ---
        http_findings = await self._run_http_checks(host, ip, host_result)
        findings.extend(http_findings)

        # --- Step 6: TLS Deep Audit ---
        tls_findings = await self._run_tls_checks(ip, host_result)
        findings.extend(tls_findings)

        # --- Step 7: SMB Security Checks ---
        smb_findings = await self._run_smb_checks(host, ip, host_result)
        findings.extend(smb_findings)

        # --- Step 8: DNS Security Checks ---
        dns_findings = await self._run_dns_checks(host, ip, host_result)
        findings.extend(dns_findings)

        # --- Step 9: YAML Template Engine ---
        template_findings = await self._run_templates(host, ip, open_ports)
        findings.extend(template_findings)

        # Sort by composite risk score descending
        findings.sort(key=lambda f: f.composite_risk_score, reverse=True)
        host_result.findings = findings

        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()

        severity_breakdown = {s.value: 0 for s in Severity}
        for f in findings:
            severity_breakdown[f.severity.value] += 1

        report = ScanReport(
            scan_id=scan_id,
            target=host,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            hosts=[host_result],
            total_findings=len(findings),
            severity_breakdown=severity_breakdown
        )

        return report

    def _resolve_vendor_product(self, svc):
        """Resolves vendor and product name for database lookup from CPE or raw product."""
        from aegis.discovery.cpe_matcher import CPE_LOOKUP
        if svc.cpe:
            _, vendor, product, _ = CPEMatcher.parse_cpe(svc.cpe)
            return vendor, product
        prod = (svc.product or "").lower()
        if prod in CPE_LOOKUP:
            return CPE_LOOKUP[prod]
        return prod, prod

    async def _run_http_checks(self, host: str, ip: str, host_result: HostScanResult) -> List[Finding]:
        """Runs safe HTTP misconfiguration checks on discovered HTTP/HTTPS services."""
        from aegis.checks.http_checks import HTTPMisconfigChecker
        findings = []
        http_services = [s for s in host_result.services if s.service_name in ("http", "https")]
        for svc in http_services:
            checker = HTTPMisconfigChecker(self.config)
            port_findings = await checker.check(host, svc.port, svc.tls)
            findings.extend(port_findings)
        return findings

    async def _run_tls_checks(self, host: str, host_result: HostScanResult) -> List[Finding]:
        """Runs deep TLS/SSL audits on any TLS-enabled service."""
        from aegis.checks.tls_auditor import TLSAuditor
        findings = []
        tls_services = [s for s in host_result.services if s.tls or s.port in (443, 8443)]
        for svc in tls_services:
            auditor = TLSAuditor(self.config)
            port_findings = await auditor.audit(host, svc.port)
            findings.extend(port_findings)
        return findings

    async def _run_templates(self, host: str, ip: str, open_ports: List[int]) -> List[Finding]:
        """Runs all YAML declarative detection templates."""
        from aegis.checks.template_engine import TemplateEngine
        engine = TemplateEngine(self.config)
        if not engine.templates:
            return []
        return await engine.run_all(ip, open_ports)

    async def _run_smb_checks(self, host: str, ip: str, host_result: HostScanResult) -> List[Finding]:
        """Runs SMB security checks on discovered SMB services."""
        from aegis.checks.smb_checks import SMBAuditor
        findings = []
        smb_ports = [s.port for s in host_result.services if s.service_name in ("smb", "microsoft-ds", "netbios-ssn") or s.port in (139, 445)]
        for port in smb_ports:
            auditor = SMBAuditor(self.config)
            port_findings = await auditor.audit(host, port)
            findings.extend(port_findings)
        return findings

    async def _run_dns_checks(self, host: str, ip: str, host_result: HostScanResult) -> List[Finding]:
        """Runs DNS security checks on discovered DNS services."""
        from aegis.checks.dns_checks import DNSAuditor
        findings = []
        dns_ports = [s.port for s in host_result.services if s.service_name == "dns" or s.port == 53]
        for port in dns_ports:
            auditor = DNSAuditor(self.config)
            port_findings = await auditor.audit(host, port)
            findings.extend(port_findings)
        return findings
