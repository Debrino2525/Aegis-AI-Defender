"""
HTTP Security Misconfiguration Checker.
Performs safe, non-destructive checks for common web security misconfigurations.
"""

import httpx
from typing import List
from aegis.core.models import Finding, Severity
from aegis.core.config import ScanConfig
from aegis.scoring.risk_engine import RiskPrioritizationEngine


class HTTPMisconfigChecker:
    """Audits HTTP/HTTPS services for security header gaps, TLS weaknesses, and common misconfigurations."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.risk_engine = RiskPrioritizationEngine()

    async def check(self, host: str, port: int, use_tls: bool) -> List[Finding]:
        """Executes all HTTP security checks against the target endpoint."""
        findings: List[Finding] = []
        scheme = "https" if use_tls else "http"
        base_url = f"{scheme}://{host}:{port}"

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.config.read_timeout, follow_redirects=True) as client:
                resp = await client.get(f"{base_url}/")
                headers = {k.lower(): v for k, v in resp.headers.items()}

                # Run all passive header / TLS checks
                findings += self._check_security_headers(host, port, headers)
                findings += self._check_server_disclosure(host, port, headers)
                findings += self._check_tls(host, port, use_tls)

                # Check for sensitive exposed paths
                path_findings = await self._check_sensitive_paths(client, base_url, host, port)
                findings += path_findings

        except Exception:
            pass

        # Apply risk scoring to all findings with detection method
        return [self.risk_engine.prioritize_finding(f, detection_method="http_header_analysis") for f in findings]

    def _check_security_headers(self, host: str, port: int, headers: dict) -> List[Finding]:
        """Checks for missing critical HTTP security headers."""
        findings = []

        checks = [
            {
                "header": "strict-transport-security",
                "id": "AEGIS-HTTP-001",
                "title": "Missing HTTP Strict Transport Security (HSTS) Header",
                "description": "The server does not send a Strict-Transport-Security header, allowing potential protocol downgrade attacks (SSL stripping).",
                "severity": Severity.MEDIUM,
                "cvss_score": 5.9,
                "epss_score": 0.0,
                "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            },
            {
                "header": "x-content-type-options",
                "id": "AEGIS-HTTP-002",
                "title": "Missing X-Content-Type-Options Header",
                "description": "Missing X-Content-Type-Options header allows MIME-type sniffing attacks that can lead to XSS.",
                "severity": Severity.LOW,
                "cvss_score": 3.5,
                "epss_score": 0.0,
                "remediation": "Add: X-Content-Type-Options: nosniff"
            },
            {
                "header": "x-frame-options",
                "id": "AEGIS-HTTP-003",
                "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
                "description": "Without X-Frame-Options, the application is vulnerable to clickjacking attacks where the page can be embedded in an invisible iframe.",
                "severity": Severity.MEDIUM,
                "cvss_score": 4.3,
                "epss_score": 0.0,
                "remediation": "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN"
            },
            {
                "header": "content-security-policy",
                "id": "AEGIS-HTTP-004",
                "title": "Missing Content Security Policy (CSP) Header",
                "description": "No Content-Security-Policy header found. CSP is a critical defence against cross-site scripting (XSS) and data injection attacks.",
                "severity": Severity.MEDIUM,
                "cvss_score": 5.4,
                "epss_score": 0.0,
                "remediation": "Implement a strict Content-Security-Policy. Start with: Content-Security-Policy: default-src 'self'"
            },
            {
                "header": "permissions-policy",
                "id": "AEGIS-HTTP-005",
                "title": "Missing Permissions-Policy Header",
                "description": "No Permissions-Policy header found. This header controls access to browser features like camera, microphone, geolocation.",
                "severity": Severity.LOW,
                "cvss_score": 3.1,
                "epss_score": 0.0,
                "remediation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"
            }
        ]

        for check in checks:
            if check["header"] not in headers:
                findings.append(Finding(
                    id=check["id"],
                    title=check["title"],
                    target=host,
                    port=port,
                    service="http",
                    severity=check["severity"],
                    cvss_score=check["cvss_score"],
                    epss_score=check["epss_score"],
                    description=check["description"],
                    evidence=f"Header '{check['header']}' is absent from HTTP response on port {port}",
                    remediation=check["remediation"]
                ))

        return findings

    def _check_server_disclosure(self, host: str, port: int, headers: dict) -> List[Finding]:
        """Detects verbose server and technology version disclosure."""
        findings = []
        server_hdr = headers.get("server", "")
        powered_hdr = headers.get("x-powered-by", "")

        import re
        version_pattern = re.compile(r"[\d]+\.[\d]+\.[\d]+")

        if server_hdr and version_pattern.search(server_hdr):
            findings.append(Finding(
                id="AEGIS-HTTP-006",
                title="Web Server Version Disclosed in Server Header",
                target=host,
                port=port,
                service="http",
                severity=Severity.LOW,
                cvss_score=3.1,
                description="The Server header discloses the exact server software version, aiding attackers in targeting specific vulnerabilities.",
                evidence=f"Server: {server_hdr}",
                remediation="Configure the web server to use a generic or absent Server header."
            ))

        if powered_hdr:
            findings.append(Finding(
                id="AEGIS-HTTP-007",
                title="Technology Stack Disclosed via X-Powered-By Header",
                target=host,
                port=port,
                service="http",
                severity=Severity.LOW,
                cvss_score=3.1,
                description="The X-Powered-By header reveals backend technology (e.g. PHP/7.4, ASP.NET), aiding targeted exploitation.",
                evidence=f"X-Powered-By: {powered_hdr}",
                remediation="Remove the X-Powered-By header from all server responses."
            ))

        return findings

    def _check_tls(self, host: str, port: int, use_tls: bool) -> List[Finding]:
        """Flags HTTP services that should be using HTTPS."""
        findings = []
        if not use_tls and port in [80, 8080, 8000]:
            findings.append(Finding(
                id="AEGIS-HTTP-008",
                title="Service Running on Unencrypted HTTP",
                target=host,
                port=port,
                service="http",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description="Traffic to this service is transmitted in plaintext HTTP, exposing data to interception and man-in-the-middle attacks.",
                evidence=f"Port {port} is serving HTTP without TLS.",
                remediation="Enable HTTPS/TLS and redirect all HTTP traffic to HTTPS."
            ))
        return findings

    async def _check_sensitive_paths(self, client: httpx.AsyncClient, base_url: str, host: str, port: int) -> List[Finding]:
        """Probes for exposed administrative and sensitive endpoints."""
        findings = []
        sensitive_paths = [
            ("/.git/HEAD", "AEGIS-HTTP-009", "Exposed .git Repository", "The .git directory is publicly accessible, potentially leaking full source code and secrets.", Severity.CRITICAL, 9.0),
            ("/.env", "AEGIS-HTTP-010", "Exposed .env Configuration File", "The .env file is publicly accessible and may contain credentials, API keys, and database passwords.", Severity.CRITICAL, 9.0),
            ("/admin", "AEGIS-HTTP-011", "Exposed Admin Panel", "An administrative interface was found publicly accessible without IP restriction.", Severity.HIGH, 7.5),
            ("/phpmyadmin", "AEGIS-HTTP-012", "phpMyAdmin Exposed", "phpMyAdmin is accessible publicly. Direct database management should never be exposed to the internet.", Severity.HIGH, 7.5),
            ("/actuator", "AEGIS-HTTP-013", "Spring Boot Actuator Exposed", "Spring Boot Actuator endpoints are exposed, potentially leaking application internals, health data, and env variables.", Severity.HIGH, 7.3),
            ("/actuator/env", "AEGIS-HTTP-014", "Spring Boot Actuator /env Exposed", "The /actuator/env endpoint may expose all application environment variables including credentials.", Severity.CRITICAL, 9.1),
            ("/server-status", "AEGIS-HTTP-015", "Apache Server Status Exposed", "Apache mod_status is enabled and publicly accessible, revealing active connections and server internals.", Severity.MEDIUM, 5.3),
            ("/wp-login.php", "AEGIS-HTTP-016", "WordPress Login Page Exposed", "WordPress login page is publicly accessible and may be targeted by brute force attacks.", Severity.MEDIUM, 5.3),
            ("/robots.txt", "AEGIS-HTTP-017", "robots.txt Enumeration", "robots.txt is available and may enumerate hidden or sensitive application paths.", Severity.INFO, 2.0),
        ]

        for path, finding_id, title, desc, severity, cvss in sensitive_paths:
            try:
                resp = await client.get(f"{base_url}{path}", follow_redirects=False)
                # Only flag 200 OK responses as actual exposures
                # 401/403 indicate the path is protected (good security)
                # 301/302 redirects are often legitimate (e.g., to login)
                if resp.status_code == 200:
                    findings.append(Finding(
                        id=finding_id,
                        title=title,
                        target=host,
                        port=port,
                        service="http",
                        severity=severity,
                        cvss_score=cvss,
                        epss_score=0.5 if severity == Severity.CRITICAL else 0.1,
                        description=desc,
                        evidence=f"HTTP {resp.status_code} response received at {base_url}{path}",
                        remediation="Restrict access to this path via firewall rules or web server configuration."
                    ))
                # Optional: Add informational finding for protected paths that exist
                elif resp.status_code in (401, 403) and finding_id in ("AEGIS-HTTP-011", "AEGIS-HTTP-012", "AEGIS-HTTP-016"):
                    # These are admin/login pages that exist but are protected - this is normal
                    pass
            except Exception:
                continue

        return findings
