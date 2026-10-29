"""
YAML Template Engine — Declarative, safe, sandboxed vulnerability check runner.
Allows community and enterprise teams to author lightweight detection checks
without writing Python code.

Template Format Example:
------------------------
id: AEGIS-TMPL-001
name: Redis Unauthenticated Access
description: Redis server is accessible without authentication.
severity: CRITICAL
cvss: 9.8
epss: 0.85
tags: [redis, database, auth]
checks:
  - type: tcp_banner
    port: 6379
    contains: "redis_version"
    evidence: "Redis INFO response received without authentication"
  - type: http_response
    path: /
    method: GET
    status: [200]
    contains: "NOAUTH"
remediation: "Enable requirepass in redis.conf and restrict bind address."
references:
  - https://redis.io/docs/manual/security/
"""

import asyncio
import yaml
import glob
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import httpx

from aegis.core.models import Finding, Severity
from aegis.core.config import ScanConfig
from aegis.scoring.risk_engine import RiskPrioritizationEngine


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class TemplateEngine:
    """Loads YAML detection templates and executes them safely against targets."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.risk = RiskPrioritizationEngine()
        self.templates: List[Dict[str, Any]] = []
        self._load_templates()

    def _load_templates(self):
        """Discovers and loads all YAML templates from the templates directory."""
        template_dir = Path(__file__).parent / "templates"
        template_dir.mkdir(exist_ok=True)
        for tmpl_file in glob.glob(str(template_dir / "*.yaml")):
            try:
                with open(tmpl_file) as f:
                    tmpl = yaml.safe_load(f)
                    if tmpl and "id" in tmpl and "checks" in tmpl:
                        self.templates.append(tmpl)
            except Exception:
                continue

    async def run_all(self, host: str, open_ports: List[int]) -> List[Finding]:
        """Runs all loaded templates against the target and returns findings."""
        all_findings: List[Finding] = []
        tasks = [self._run_template(tmpl, host, open_ports) for tmpl in self.templates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
        return [self.risk.prioritize_finding(f, detection_method="response_pattern_match") for f in all_findings]

    async def _run_template(self, tmpl: Dict, host: str, open_ports: List[int]) -> List[Finding]:
        """Executes a single template's checks against the host."""
        findings = []
        tmpl_id = tmpl.get("id", "AEGIS-TMPL-UNKNOWN")
        title = tmpl.get("name", tmpl_id)
        description = tmpl.get("description", "")
        severity = SEVERITY_MAP.get(str(tmpl.get("severity", "medium")).lower(), Severity.MEDIUM)
        cvss = float(tmpl.get("cvss", 5.0))
        epss = float(tmpl.get("epss", 0.0))
        remediation = tmpl.get("remediation", "")
        references = tmpl.get("references", [])

        for check in tmpl.get("checks", []):
            check_type = check.get("type")
            port = check.get("port")

            # Only run if port is open (or no specific port required)
            if port and port not in open_ports:
                continue

            evidence = None

            if check_type == "tcp_banner":
                evidence = await self._check_tcp_banner(host, port, check)
            elif check_type == "http_response":
                evidence = await self._check_http_response(host, port, check, open_ports)

            if evidence:
                findings.append(Finding(
                    id=tmpl_id,
                    title=title,
                    target=host,
                    port=port,
                    service=check_type,
                    severity=severity,
                    cvss_score=cvss,
                    epss_score=epss,
                    description=description,
                    evidence=evidence,
                    remediation=remediation,
                    references=references
                ))
                break  # One match per template is sufficient

        return findings

    async def _check_tcp_banner(self, host: str, port: int, check: Dict) -> Optional[str]:
        """Connects and checks if the banner contains the expected string."""
        contains = check.get("contains", "")
        not_contains = check.get("not_contains", "")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            probe = check.get("send", "")
            if probe:
                writer.write(probe.encode() + b"\r\n")
                await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(2048), timeout=2.0)
            except asyncio.TimeoutError:
                data = b""

            writer.close()
            await writer.wait_closed()

            banner = data.decode("utf-8", errors="ignore")
            match = (not contains or contains.lower() in banner.lower())
            mismatch = (not_contains and not_contains.lower() in banner.lower())

            if match and not mismatch:
                return check.get("evidence", f"Pattern '{contains}' found in banner on port {port}")
        except Exception:
            pass
        return None

    async def _check_http_response(self, host: str, port: int, check: Dict, open_ports: List[int]) -> Optional[str]:
        """Sends an HTTP request and validates status code and body content."""
        # Determine scheme
        use_tls = port in (443, 8443)
        scheme = "https" if use_tls else "http"
        target_port = port or (443 if use_tls else 80)
        path = check.get("path", "/")
        method = check.get("method", "GET").upper()
        expected_statuses = check.get("status", [200])
        contains = check.get("contains", "")
        not_contains = check.get("not_contains", "")
        url = f"{scheme}://{host}:{target_port}{path}"

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.config.read_timeout) as client:
                resp = await client.request(method, url)
                body = resp.text

                status_ok = not expected_statuses or resp.status_code in expected_statuses
                content_ok = not contains or contains.lower() in body.lower()
                content_neg_ok = not not_contains or not_contains.lower() not in body.lower()

                if status_ok and content_ok and content_neg_ok:
                    return check.get("evidence", f"HTTP {resp.status_code} with matching content at {path}")
        except Exception:
            pass
        return None
