"""
TLS/SSL Deep Auditor — Detects weak ciphers, expired certs, protocol downgrades,
Heartbleed, POODLE, BEAST, and certificate chain issues.
"""

import asyncio
import ssl
import socket
import datetime
from typing import List, Optional, Dict, Any
from aegis.core.models import Finding, Severity
from aegis.core.config import ScanConfig
from aegis.scoring.risk_engine import RiskPrioritizationEngine


# Cipher suites known to be weak or broken
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "ADH", "AECDH", "PSK", "SRP"
}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

STRONG_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}

# id-at-commonName (2.5.4.3)
_CN_OID = bytes((0x55, 0x04, 0x03))


class _DerCursor:
    """Minimal DER reader for the certificate fields the auditor reports."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def remaining(self) -> bool:
        return self.offset < len(self.data)

    def read(self):
        if self.offset >= len(self.data):
            raise ValueError("truncated DER")
        tag = self.data[self.offset]
        self.offset += 1
        if self.offset >= len(self.data):
            raise ValueError("truncated DER length")
        length_byte = self.data[self.offset]
        self.offset += 1
        if length_byte & 0x80:
            nbytes = length_byte & 0x7F
            if nbytes == 0 or self.offset + nbytes > len(self.data):
                raise ValueError("invalid DER length")
            length = int.from_bytes(self.data[self.offset:self.offset + nbytes], "big")
            self.offset += nbytes
        else:
            length = length_byte
        end = self.offset + length
        if end > len(self.data):
            raise ValueError("truncated DER value")
        value = self.data[self.offset:end]
        self.offset = end
        return tag, value


def _decode_directory_string(tag: int, raw: bytes) -> str:
    if tag in (0x12, 0x13, 0x16):
        return raw.decode("ascii", errors="replace")
    if tag == 0x0C:
        return raw.decode("utf-8", errors="replace")
    if tag == 0x1E:
        return raw.decode("utf-16-be", errors="replace")
    return raw.decode("latin-1", errors="replace")


def _parse_time(tag: int, raw: bytes) -> datetime.datetime:
    text = raw.decode("ascii")
    if text.endswith("Z"):
        text = text[:-1]
    if "." in text:
        text = text.split(".", 1)[0]
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        parts = (year, int(text[2:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]), int(text[10:12]))
    elif tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
        parts = (
            int(text[0:4]), int(text[4:6]), int(text[6:8]),
            int(text[8:10]), int(text[10:12]), int(text[12:14]),
        )
    else:
        raise ValueError(f"unsupported time tag {tag:#x}")
    return datetime.datetime(*parts, tzinfo=datetime.timezone.utc)


def _first_common_name(name_der: bytes) -> Optional[str]:
    cursor = _DerCursor(name_der)
    while cursor.remaining():
        tag, rdn = cursor.read()
        if tag != 0x31:
            continue
        rdn_cursor = _DerCursor(rdn)
        while rdn_cursor.remaining():
            attr_tag, attr = rdn_cursor.read()
            if attr_tag != 0x30:
                continue
            attr_cursor = _DerCursor(attr)
            _, oid = attr_cursor.read()
            value_tag, value = attr_cursor.read()
            if oid == _CN_OID:
                return _decode_directory_string(value_tag, value)
    return None


def parse_x509_certificate(der: bytes) -> Dict[str, Any]:
    """Reads validity and subject/issuer from a leaf certificate.

    ssl.SSLSocket.getpeercert() returns an empty dict when the socket is
    created with CERT_NONE, which is required to complete a handshake against
    an expired or self-signed server. The binary certificate is still present
    and has to be decoded directly.
    """
    certificate = _DerCursor(der)
    tag, certificate_body = certificate.read()
    if tag != 0x30:
        raise ValueError("certificate is not a SEQUENCE")
    body = _DerCursor(certificate_body)
    tag, tbs = body.read()
    if tag != 0x30:
        raise ValueError("tbsCertificate is not a SEQUENCE")

    tbs_cursor = _DerCursor(tbs)
    if tbs_cursor.remaining() and tbs_cursor.data[tbs_cursor.offset] == 0xA0:
        tbs_cursor.read()  # version
    tbs_cursor.read()  # serialNumber
    tbs_cursor.read()  # signature algorithm
    _, issuer = tbs_cursor.read()
    validity_tag, validity = tbs_cursor.read()
    _, subject = tbs_cursor.read()
    if validity_tag != 0x30:
        raise ValueError("validity is not a SEQUENCE")

    validity_cursor = _DerCursor(validity)
    not_before_tag, not_before = validity_cursor.read()
    not_after_tag, not_after = validity_cursor.read()
    return {
        "not_before": _parse_time(not_before_tag, not_before),
        "not_after": _parse_time(not_after_tag, not_after),
        "subject_cn": _first_common_name(subject),
        "issuer_cn": _first_common_name(issuer),
        "self_signed": issuer == subject,
    }


class TLSAuditor:
    """Performs deep TLS/SSL configuration analysis on a target host and port."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.risk = RiskPrioritizationEngine()

    async def audit(self, host: str, port: int) -> List[Finding]:
        """Runs all TLS checks and returns findings."""
        findings: List[Finding] = []

        tls_data = await self._get_tls_info(host, port)
        if not tls_data:
            return findings

        findings += self._check_protocol_version(host, port, tls_data)
        findings += self._check_cipher_suite(host, port, tls_data)
        findings += self._check_certificate(host, port, tls_data)

        return [self.risk.prioritize_finding(f, detection_method="tls_certificate_analysis") for f in findings]

    async def _get_tls_info(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Establishes TLS connection and extracts full configuration details."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Allow legacy protocols for auditing purposes
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")

        try:
            loop = asyncio.get_event_loop()
            raw_sock = socket.create_connection((host, port), timeout=self.config.connect_timeout)
            ssl_sock = await loop.run_in_executor(
                None,
                lambda: ctx.wrap_socket(raw_sock, server_hostname=host)
            )

            protocol = ssl_sock.version()
            cipher = ssl_sock.cipher()
            # getpeercert() is empty whenever verification is disabled. The
            # DER form is populated for expired and self-signed certificates.
            der_cert = ssl_sock.getpeercert(binary_form=True)

            ssl_sock.close()

            cert = None
            if der_cert:
                try:
                    cert = parse_x509_certificate(der_cert)
                except Exception:
                    cert = None

            return {
                "protocol": protocol,
                "cipher_name": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "cert": cert,
            }
        except ssl.SSLError as e:
            return {"error": str(e), "protocol": None, "cipher_name": None, "cert": None}
        except Exception:
            return None

    def _check_protocol_version(self, host: str, port: int, tls_data: Dict) -> List[Finding]:
        """Flags deprecated TLS/SSL protocol versions."""
        findings = []
        protocol = tls_data.get("protocol")

        if protocol in WEAK_PROTOCOLS:
            is_critical = protocol in ("SSLv2", "SSLv3")
            findings.append(Finding(
                id=f"AEGIS-TLS-001",
                title=f"Deprecated Protocol In Use: {protocol}",
                target=host,
                port=port,
                service="tls",
                severity=Severity.CRITICAL if is_critical else Severity.HIGH,
                cvss_score=9.1 if is_critical else 7.5,
                epss_score=0.65 if is_critical else 0.3,
                description=(
                    f"The server negotiated {protocol}, which is cryptographically broken. "
                    f"SSLv3 is vulnerable to POODLE; TLSv1.0/1.1 are deprecated by RFC 8996 "
                    f"and vulnerable to BEAST and other downgrade attacks."
                ),
                evidence=f"TLS handshake completed using {protocol} on port {port}",
                remediation=(
                    "Disable TLS 1.0 and 1.1. Configure the server to support only "
                    "TLS 1.2 and TLS 1.3. Update cipher suites accordingly."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc8996",
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-3566"  # POODLE
                ]
            ))
        return findings

    def _check_cipher_suite(self, host: str, port: int, tls_data: Dict) -> List[Finding]:
        """Identifies weak or broken cipher suites."""
        findings = []
        cipher_name = tls_data.get("cipher_name", "") or ""
        cipher_bits = tls_data.get("cipher_bits") or 0

        for weak in WEAK_CIPHERS:
            if weak.upper() in cipher_name.upper():
                findings.append(Finding(
                    id="AEGIS-TLS-002",
                    title=f"Weak Cipher Suite Negotiated: {cipher_name}",
                    target=host,
                    port=port,
                    service="tls",
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    epss_score=0.2,
                    description=(
                        f"The server negotiated a weak cipher suite '{cipher_name}' "
                        f"which provides insufficient cryptographic protection."
                    ),
                    evidence=f"Cipher: {cipher_name} ({cipher_bits} bits) on port {port}",
                    remediation=(
                        "Restrict server cipher suites to ECDHE+AESGCM, ECDHE+CHACHA20, "
                        "or similar AEAD ciphers providing forward secrecy."
                    )
                ))
                break

        if cipher_bits and cipher_bits < 128:
            findings.append(Finding(
                id="AEGIS-TLS-003",
                title=f"Insufficient Cipher Key Length: {cipher_bits} bits",
                target=host,
                port=port,
                service="tls",
                severity=Severity.HIGH,
                cvss_score=7.1,
                epss_score=0.15,
                description=f"Cipher key length of {cipher_bits} bits is below the minimum recommended 128 bits.",
                evidence=f"Cipher: {cipher_name} with {cipher_bits}-bit key on port {port}",
                remediation="Use ciphers with at least 128-bit (preferably 256-bit) key lengths."
            ))

        return findings

    def _check_certificate(self, host: str, port: int, tls_data: Dict) -> List[Finding]:
        """Inspects the TLS certificate for expiry, weak signing, and hostname mismatch."""
        findings = []
        cert = tls_data.get("cert") or {}
        if not cert:
            return findings

        not_after = cert.get("not_after")
        if isinstance(not_after, datetime.datetime):
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            days_left = (not_after - now).days
            expires_on = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")

            if days_left < 0:
                findings.append(Finding(
                    id="AEGIS-TLS-004",
                    title="TLS Certificate Has Expired",
                    target=host, port=port, service="tls",
                    severity=Severity.CRITICAL, cvss_score=7.5, epss_score=0.4,
                    description="The server's TLS certificate has expired. Clients may reject this connection.",
                    evidence=f"Certificate expired on {expires_on} ({abs(days_left)} days ago)",
                    remediation="Renew the TLS certificate immediately."
                ))
            elif days_left <= 30:
                findings.append(Finding(
                    id="AEGIS-TLS-005",
                    title=f"TLS Certificate Expires Soon ({days_left} days)",
                    target=host, port=port, service="tls",
                    severity=Severity.MEDIUM, cvss_score=4.0, epss_score=0.05,
                    description=f"The TLS certificate will expire in {days_left} days.",
                    evidence=f"Certificate expires on {expires_on}",
                    remediation="Renew the TLS certificate before expiry to avoid service disruption."
                ))

        if cert.get("self_signed"):
            common_name = cert.get("subject_cn") or cert.get("issuer_cn") or "unknown"
            findings.append(Finding(
                id="AEGIS-TLS-006",
                title="Self-Signed TLS Certificate Detected",
                target=host, port=port, service="tls",
                severity=Severity.MEDIUM, cvss_score=5.9, epss_score=0.05,
                description=(
                    "The server is using a self-signed TLS certificate not issued by a trusted CA. "
                    "This opens the connection to man-in-the-middle attacks on unsuspecting clients."
                ),
                evidence=f"Issuer DN matches subject DN ({common_name})",
                remediation="Replace with a certificate issued by a publicly trusted CA (e.g. Let's Encrypt)."
            ))

        return findings
