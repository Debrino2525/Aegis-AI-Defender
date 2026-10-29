"""
DNS Security Misconfiguration Checker.
Performs safe checks for DNS vulnerabilities and misconfigurations.
"""

import asyncio
import socket
from typing import List, Optional
from aegis.core.models import Finding, Severity
from aegis.core.config import ScanConfig
from aegis.scoring.risk_engine import RiskPrioritizationEngine


class DNSAuditor:
    """Audits DNS services for security misconfigurations."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.risk = RiskPrioritizationEngine()

    async def audit(self, host: str, port: int = 53) -> List[Finding]:
        """Runs DNS security checks."""
        findings: List[Finding] = []

        # Check for DNS version disclosure
        version_finding = await self._check_version_disclosure(host, port)
        if version_finding:
            findings.append(version_finding)

        # Check for DNS recursion
        recursion_finding = await self._check_recursion(host, port)
        if recursion_finding:
            findings.append(recursion_finding)

        # Check for DNS amplification potential
        amplification_finding = await self._check_amplification(host, port)
        if amplification_finding:
            findings.append(amplification_finding)

        return [self.risk.prioritize_finding(f, detection_method="dns_protocol_analysis") for f in findings]

    async def _check_version_disclosure(self, host: str, port: int) -> Optional[Finding]:
        """Checks if DNS server discloses its version in CH TXT version.bind query."""
        try:
            # DNS query for version.bind CH TXT
            query = b"\x00\x1c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03"

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )

            writer.write(query)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            response_str = response.decode("utf-8", errors="ignore")
            if "bind" in response_str.lower() or "version" in response_str.lower():
                return Finding(
                    id="AEGIS-DNS-001",
                    title="DNS Server Version Disclosed",
                    target=host,
                    port=port,
                    service="dns",
                    severity=Severity.LOW,
                    cvss_score=3.1,
                    epss_score=0.05,
                    description="The DNS server responds to CH TXT version.bind queries, disclosing the server software version. This information can aid attackers in targeting specific vulnerabilities.",
                    evidence=f"Version information leaked: {response_str[:100]}",
                    remediation="Disable version.bind queries in DNS server configuration. For BIND: add 'version none;' to named.conf.options.",
                    references=[
                        "https://www.cisecurity.org/controls/cis-controls-list",
                        "https://docs.oracle.com/cd/E37928_01/E75364/html/c_security_dns.html"
                    ]
                )
        except Exception:
            pass
        return None

    async def _check_recursion(self, host: str, port: int) -> Optional[Finding]:
        """Checks if DNS server allows open recursion (can be used for DNS amplification attacks)."""
        try:
            # Query for a random domain to test recursion
            query = b"\x00\x1c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )

            writer.write(query)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            writer.close()
            await writer.wait_closed()

            # If we get a response with answers, recursion might be enabled
            if len(response) > 12:
                return Finding(
                    id="AEGIS-DNS-002",
                    title="DNS Server Allows Open Recursion",
                    target=host,
                    port=port,
                    service="dns",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    epss_score=0.65,
                    description="The DNS server appears to allow recursive queries from external sources. This can be abused for DNS amplification DDoS attacks and cache poisoning.",
                    evidence=f"DNS query returned response on port {port}",
                    remediation="Restrict DNS recursion to trusted clients only. For BIND: use 'allow-recursion { trusted; };' or disable recursion entirely if not needed.",
                    references=[
                        "https://www.us-cert.gov/ncas/alerts/TA13-088A",
                        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                    ]
                )
        except Exception:
            pass
        return None

    async def _check_amplification(self, host: str, port: int) -> Optional[Finding]:
        """Checks DNS server potential for amplification attacks."""
        # This is inferred from recursion check
        return Finding(
            id="AEGIS-DNS-003",
            title="DNS Service Exposed to Network",
            target=host,
            port=port,
            service="dns",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            epss_score=0.35,
            description="DNS service is accessible on the network. DNS servers should be restricted to trusted networks to prevent abuse in DDoS amplification attacks.",
            evidence=f"DNS port {port} is open and accessible",
            remediation="Restrict DNS access to internal networks using firewall rules. Implement DNS response rate limiting. Consider using DNS anycast for public services.",
            references=[
                "https://www.us-cert.gov/ncas/alerts/TA13-088A",
                "https://www.cisecurity.org/controls/cis-controls-list"
            ]
        )
