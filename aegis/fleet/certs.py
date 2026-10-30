"""Site CA and agent client certificates under ~/.aegis/ca/."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aegis.runtime import aegis_data_dir

CA_YEARS = 10
CLIENT_DAYS = 365
SERVER_DAYS = 365
KEY_SIZE = 2048


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aegis"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)


def serialize_key(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def serialize_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def load_key(pem: str) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def load_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("utf-8"))


def cert_fingerprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return "sha256:" + hashlib.sha256(der).hexdigest()


def heartbeat_canonical(agent_id: str, timestamp: str, nonce: str) -> bytes:
    return f"AEGIS-HEARTBEAT\n{agent_id}\n{timestamp}\n{nonce}".encode("utf-8")


def sign_heartbeat(private_key: rsa.RSAPrivateKey, agent_id: str, timestamp: str, nonce: str) -> bytes:
    return private_key.sign(
        heartbeat_canonical(agent_id, timestamp, nonce),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def verify_heartbeat_signature(cert: x509.Certificate, agent_id: str, timestamp: str, nonce: str, signature: bytes) -> None:
    cert.public_key().verify(
        signature,
        heartbeat_canonical(agent_id, timestamp, nonce),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def _chmod600(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass


class SiteCA:
    """Create-or-load the site CA used to enroll host agents."""

    def __init__(self, ca_dir: Optional[Path] = None):
        self.ca_dir = Path(ca_dir) if ca_dir else aegis_data_dir() / "ca"
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.ca_dir / "ca.key"
        self.cert_path = self.ca_dir / "ca.crt"
        self.server_key_path = self.ca_dir / "server.key"
        self.server_cert_path = self.ca_dir / "server.crt"
        self._ca_key: Optional[rsa.RSAPrivateKey] = None
        self._ca_cert: Optional[x509.Certificate] = None

    def bootstrap(self) -> None:
        if self.key_path.is_file() and self.cert_path.is_file():
            self._ca_key = load_key(self.key_path.read_text(encoding="utf-8"))
            self._ca_cert = load_cert(self.cert_path.read_text(encoding="utf-8"))
        else:
            self._ca_key, self._ca_cert = self._create_ca()
        if not (self.server_key_path.is_file() and self.server_cert_path.is_file()):
            self._create_server_cert()

    @property
    def ca_key(self) -> rsa.RSAPrivateKey:
        if self._ca_key is None:
            self.bootstrap()
        return self._ca_key

    @property
    def ca_cert(self) -> x509.Certificate:
        if self._ca_cert is None:
            self.bootstrap()
        return self._ca_cert

    def ca_pem(self) -> str:
        return serialize_cert(self.ca_cert)

    def fingerprint(self) -> str:
        return cert_fingerprint(self.ca_cert)

    def issue_client(self, agent_id: str, hostname: str) -> Tuple[str, str, str]:
        """Return (certificate_pem, private_key_pem, fingerprint)."""
        key = generate_rsa_key()
        now = _now()
        san = [x509.DNSName(hostname[:253] or agent_id)]
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(agent_id))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=CLIENT_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        return serialize_cert(cert), serialize_key(key), cert_fingerprint(cert)

    def verify_client_pem(self, pem: str) -> x509.Certificate:
        cert = load_cert(pem)
        now = _now()
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
            raise ValueError("Client certificate is expired or not yet valid")
        self.ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        issuer = cert.issuer.rfc4514_string()
        expected = self.ca_cert.subject.rfc4514_string()
        if issuer != expected:
            raise ValueError("Client certificate was not issued by this site CA")
        return cert

    def _create_ca(self) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = generate_rsa_key()
        now = _now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name("Aegis Site CA"))
            .issuer_name(_name("Aegis Site CA"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365 * CA_YEARS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        self.key_path.write_text(serialize_key(key), encoding="utf-8")
        self.cert_path.write_text(serialize_cert(cert), encoding="utf-8")
        _chmod600(self.key_path)
        _chmod600(self.cert_path)
        return key, cert

    def _create_server_cert(self) -> None:
        key = generate_rsa_key()
        now = _now()
        host = socket.gethostname() or "localhost"
        names = [x509.DNSName("localhost"), x509.DNSName(host[:253])]
        ips = [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(host))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=SERVER_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName(names + ips), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        self.server_key_path.write_text(serialize_key(key), encoding="utf-8")
        self.server_cert_path.write_text(serialize_cert(cert), encoding="utf-8")
        _chmod600(self.server_key_path)
        _chmod600(self.server_cert_path)
