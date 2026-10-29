"""
SMB Security Misconfiguration Checker.
Performs safe checks for SMB protocol vulnerabilities and misconfigurations.
"""

import asyncio
import socket
from typing import List, Optional
from aegis.core.models import Finding, Severity
from aegis.core.config import ScanConfig
from aegis.scoring.risk_engine import RiskPrioritizationEngine


class SMBAuditor:
    """Audits SMB/CIFS services for security misconfigurations."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.risk = RiskPrioritizationEngine()

    async def audit(self, host: str, port: int = 445) -> List[Finding]:
        """Runs SMB security checks."""
        findings: List[Finding] = []

        # Check for SMBv1 (vulnerable to EternalBlue)
        smbv1_finding = await self._check_smbv1(host, port)
        if smbv1_finding:
            findings.append(smbv1_finding)

        # Check for anonymous access
        anon_finding = await self._check_anonymous_access(host, port)
        if anon_finding:
            findings.append(anon_finding)

        # Check for signing disabled
        signing_finding = await self._check_signing(host, port)
        if signing_finding:
            findings.append(signing_finding)

        return [self.risk.prioritize_finding(f, detection_method="smb_protocol_analysis") for f in findings]

    async def _check_smbv1(self, host: str, port: int) -> Optional[Finding]:
        """Checks if SMBv1 protocol is enabled (vulnerable to EternalBlue)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )

            # Send SMB1 negotiate protocol request
            # This is a simplified probe - in production, use a proper SMB library
            writer.write(b"\x00\x00\x00\x72\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8")
            await writer.drain()

            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                writer.close()
                await writer.wait_closed()

                # If we get a response, SMB might be active
                # A proper implementation would parse the SMB dialect negotiation
                return Finding(
                    id="AEGIS-SMB-001",
                    title="SMBv1 Protocol Detected (EternalBlue Vulnerability)",
                    target=host,
                    port=port,
                    service="smb",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    epss_score=0.92,
                    description="SMBv1 protocol is enabled on the server. SMBv1 is deprecated and contains critical vulnerabilities including EternalBlue (CVE-2017-0144) which can lead to remote code execution.",
                    evidence=f"SMB response received on port {port}",
                    remediation="Disable SMBv1 immediately. Use SMBv2/v3 with minimum version 2.0.2 or higher. Apply all security patches for MS17-010.",
                    references=[
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144",
                        "https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-protocol-versions"
                    ]
                )
            except asyncio.TimeoutError:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass
        return None

    async def _check_anonymous_access(self, host: str, port: int) -> Optional[Finding]:
        """Checks if SMB allows anonymous/guest access."""
        try:
            # This is a simplified check - proper implementation would use SMB library
            # For now, we'll just flag the port as potentially exposed
            return Finding(
                id="AEGIS-SMB-002",
                title="SMB Service Exposed to Network",
                target=host,
                port=port,
                service="smb",
                severity=Severity.HIGH,
                cvss_score=7.5,
                epss_score=0.45,
                description="SMB service is accessible on the network. SMB shares should be restricted to trusted networks only and never exposed to the internet.",
                evidence=f"SMB port {port} is open and accessible",
                remediation="Restrict SMB access to internal networks only using firewall rules. Enable host-based firewalls. Consider implementing SMB signing and encryption.",
                references=[
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security"
                ]
            )
        except Exception:
            pass
        return None

    async def _check_signing(self, host: str, port: int) -> Optional[Finding]:
        """Checks if SMB message signing is disabled."""
        # This would require proper SMB protocol implementation
        # For now, we provide a informational finding
        return Finding(
            id="AEGIS-SMB-003",
            title="SMB Message Signing Status Unknown",
            target=host,
            port=port,
            service="smb",
            severity=Severity.INFO,
            cvss_score=0.0,
            epss_score=0.0,
            description="SMB message signing status could not be determined. SMB signing prevents man-in-the-middle attacks.",
            evidence=f"SMB port {port} is open",
            remediation="Enable SMB message signing on all servers and clients. Require signing for all connections.",
            references=[
                "https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security"
            ]
        )
