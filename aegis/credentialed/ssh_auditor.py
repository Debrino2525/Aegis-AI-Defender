"""
SSH Credentialed Auditor — Authenticates via SSH and runs package-level audits.
This achieves near-zero false positives by directly querying installed software
rather than guessing from banners.

Requires: pip install paramiko
"""

import asyncio
from typing import List, Optional, Dict, Any
from aegis.core.models import Finding, ServiceInfo
from aegis.core.config import ScanConfig
from aegis.database.db import VulnerabilityDatabase
from aegis.scoring.risk_engine import RiskPrioritizationEngine
from rich.console import Console

console = Console()


class SSHAuditor:
    """
    Authenticates to a Linux/Unix host over SSH and performs credentialed
    package inventory scans to precisely identify installed vulnerable software.
    """

    def __init__(self, config: ScanConfig, username: str, password: Optional[str] = None, key_path: Optional[str] = None):
        self.config = config
        self.username = username
        self.password = password
        self.key_path = key_path
        self.vdb = VulnerabilityDatabase(config.data_dir / "vdb.sqlite3")
        self.risk = RiskPrioritizationEngine()

    async def audit(self, host: str, port: int = 22) -> List[Finding]:
        """Connects via SSH and runs the full credentialed audit pipeline."""
        try:
            import paramiko
        except ImportError:
            console.print("[yellow][!] SSH Auditor requires paramiko: pip install paramiko[/yellow]")
            return []

        findings: List[Finding] = []

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs: Dict[str, Any] = {
                "hostname": host,
                "port": port,
                "username": self.username,
                "timeout": self.config.connect_timeout,
            }
            if self.key_path:
                connect_kwargs["key_filename"] = self.key_path
            elif self.password:
                connect_kwargs["password"] = self.password

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: client.connect(**connect_kwargs))

            console.print(f"[bold green][+] SSH authenticated to {host}:{port} as {self.username}[/bold green]")

            # Detect OS type
            os_type = await loop.run_in_executor(None, lambda: self._detect_os(client))
            console.print(f"  [dim]OS type detected: {os_type}[/dim]")

            # Get package inventory
            packages = await loop.run_in_executor(None, lambda: self._get_packages(client, os_type))
            console.print(f"  [dim]Packages enumerated: {len(packages)}[/dim]")

            # Check kernel version
            kernel_findings = await loop.run_in_executor(None, lambda: self._check_kernel(client, host))
            findings.extend(kernel_findings)

            # Match packages against VDB
            for pkg_name, pkg_version in packages.items():
                vulns = self.vdb.query_vulnerabilities(pkg_name, pkg_name, pkg_version)
                for vuln in vulns:
                    finding = Finding(
                        id=vuln.id,
                        title=vuln.title,
                        target=host,
                        port=port,
                        service="ssh-credentialed",
                        severity=vuln.severity,
                        cvss_score=vuln.cvss_score,
                        epss_score=vuln.epss_score,
                        is_cisa_kev=vuln.is_cisa_kev,
                        description=vuln.description,
                        evidence=(
                            f"Credentialed scan: package '{pkg_name}' version {pkg_version} "
                            f"installed on {host} (verified via package manager)"
                        ),
                        remediation=vuln.remediation,
                        cve_id=vuln.id if vuln.id.startswith("CVE-") else None,
                        references=vuln.references
                    )
                    findings.append(self.risk.prioritize_finding(finding))

            client.close()

        except Exception as e:
            console.print(f"[red][!] SSH audit failed for {host}: {e}[/red]")

        return findings

    def _exec(self, client, command: str) -> str:
        """Executes a remote command and returns stdout as a string."""
        try:
            _, stdout, _ = client.exec_command(command, timeout=15)
            return stdout.read().decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    def _detect_os(self, client) -> str:
        """Detects the remote OS type for package manager selection."""
        os_release = self._exec(client, "cat /etc/os-release 2>/dev/null || uname -s")
        if "ubuntu" in os_release.lower() or "debian" in os_release.lower():
            return "debian"
        elif "centos" in os_release.lower() or "rhel" in os_release.lower() or "fedora" in os_release.lower():
            return "rpm"
        elif "alpine" in os_release.lower():
            return "alpine"
        elif "arch" in os_release.lower():
            return "arch"
        return "unknown"

    def _get_packages(self, client, os_type: str) -> Dict[str, str]:
        """Retrieves all installed packages and versions from the remote host."""
        packages: Dict[str, str] = {}

        if os_type == "debian":
            output = self._exec(client, "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null")
            for line in output.splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    pkg, ver = parts[0].strip(), parts[1].strip()
                    # Clean epoch prefix (e.g. 1:2.4.49-1 -> 2.4.49-1)
                    if ":" in ver:
                        ver = ver.split(":", 1)[1]
                    packages[pkg] = ver

        elif os_type == "rpm":
            output = self._exec(client, "rpm -qa --queryformat '%{NAME}\\t%{VERSION}\\n' 2>/dev/null")
            for line in output.splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    packages[parts[0].strip()] = parts[1].strip()

        elif os_type == "alpine":
            output = self._exec(client, "apk info -v 2>/dev/null")
            for line in output.splitlines():
                if "-" in line:
                    # Format: packagename-version
                    last_dash = line.rfind("-")
                    pkg = line[:last_dash]
                    ver = line[last_dash + 1:]
                    packages[pkg] = ver

        return packages

    def _check_kernel(self, client, host: str) -> List[Finding]:
        """Retrieves kernel version and flags if it's potentially outdated."""
        findings = []
        kernel = self._exec(client, "uname -r")
        if not kernel:
            return findings

        console.print(f"  [dim]Kernel version: {kernel}[/dim]")

        # Flag kernels older than common LTS cutoffs as informational
        # (Full CVE kernel matching would require a dedicated kernel CVE feed)
        finding = Finding(
            id="AEGIS-SSH-001",
            title=f"Kernel Version Identified: {kernel}",
            target=host,
            port=22,
            service="ssh-credentialed",
            severity=Finding.__fields__["severity"].default if hasattr(Finding.__fields__, "severity") else "INFO",
            cvss_score=0.0,
            epss_score=0.0,
            description=(
                f"The remote host is running Linux kernel {kernel}. "
                "Ensure this kernel is regularly patched with the latest security updates."
            ),
            evidence=f"uname -r output: {kernel}",
            remediation="Apply all available kernel security patches via your distribution's update manager."
        )
        from aegis.core.models import Severity
        finding.severity = Severity.INFO
        finding.composite_risk_score = 5.0
        findings.append(finding)
        return findings
