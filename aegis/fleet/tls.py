"""Console HTTPS and real mTLS for host-agent heartbeats.

When AEGIS_TLS is on, uvicorn serves the site CA server cert (or AEGIS_TLS_CERTFILE)
and loads the site CA so it can verify agent client certificates.

Handshake defaults to ssl.CERT_OPTIONAL so the operator browser and first enroll
still work without a client cert. /api/fleet/heartbeat then requires a verified
client certificate — that is CERT_REQUIRED for the agent. Set
AEGIS_TLS_CERT_REQS=required to demand a client cert on every connection
(agent-only port; the browser and first enroll cannot use that listener).

nginx equivalent for heartbeat-only CERT_REQUIRED is documented in README.
"""

from __future__ import annotations

import importlib
import os
import ssl
from typing import Any, Dict, Optional
from urllib.parse import unquote

from fastapi import Request

_TRUE = {"1", "true", "yes", "on", "https"}
_HOOKED = False
PEER_CERT_EXTENSION = "aegis.peer_cert_pem"


def _flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in _TRUE


def tls_enabled() -> bool:
    return _flag("AEGIS_TLS")


def tls_proxy() -> bool:
    """Honor nginx X-SSL-Client-Cert headers. Off unless the operator sets it."""
    return _flag("AEGIS_TLS_PROXY")


def heartbeat_requires_client_cert() -> bool:
    return tls_enabled() or tls_proxy()


def cert_reqs_from_env() -> int:
    raw = os.getenv("AEGIS_TLS_CERT_REQS", "optional").strip().lower()
    if raw in {"required", "require", "2", "cert_required"}:
        return ssl.CERT_REQUIRED
    if raw in {"none", "0", "cert_none"}:
        return ssl.CERT_NONE
    return ssl.CERT_OPTIONAL


def cert_reqs_name(value: Optional[int] = None) -> str:
    reqs = cert_reqs_from_env() if value is None else value
    if reqs == ssl.CERT_REQUIRED:
        return "required"
    if reqs == ssl.CERT_NONE:
        return "none"
    return "optional"


def build_server_ssl_context(
    certfile: str,
    keyfile: str,
    ca_certs: str,
    cert_reqs: int,
) -> ssl.SSLContext:
    """TLS context that actually asks for an agent client certificate.

    TLS 1.3 does not send CertificateRequest for CERT_OPTIONAL during the
    handshake. Cap OPTIONAL at TLS 1.2 so the browser and first enroll still
    connect without a client cert, while an agent that has one presents it.
    CERT_REQUIRED stays on TLS 1.3 (agent-only listener).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile)
    ctx.load_verify_locations(ca_certs)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.VerifyMode(cert_reqs)
    if cert_reqs == ssl.CERT_OPTIONAL:
        # TLS 1.3 skips CertificateRequest for OPTIONAL. Stay on 1.2 so the
        # server asks for a client cert without failing clients that have none.
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _ssl_context_factory(config: Any, default_factory: Any) -> ssl.SSLContext:
    del default_factory
    return build_server_ssl_context(
        str(config.ssl_certfile),
        str(config.ssl_keyfile),
        str(config.ssl_ca_certs),
        int(config.ssl_cert_reqs),
    )


def uvicorn_ssl_kwargs() -> Dict[str, Any]:
    """Keyword arguments for uvicorn.run / Config. Empty when TLS is off."""
    if not tls_enabled():
        return {}
    from aegis.fleet.certs import SiteCA

    ca = SiteCA()
    ca.bootstrap()
    certfile = os.getenv("AEGIS_TLS_CERTFILE", "").strip() or str(ca.server_cert_path)
    keyfile = os.getenv("AEGIS_TLS_KEYFILE", "").strip() or str(ca.server_key_path)
    ca_certs = os.getenv("AEGIS_TLS_CA_CERTS", "").strip() or str(ca.cert_path)
    if not os.path.isfile(certfile) or not os.path.isfile(keyfile):
        raise FileNotFoundError(
            "AEGIS_TLS is set but the server certificate is missing. "
            f"Expected {certfile} and {keyfile}."
        )
    if not os.path.isfile(ca_certs):
        raise FileNotFoundError(
            "AEGIS_TLS is set but the site CA is missing. "
            f"Expected {ca_certs}."
        )
    install_peer_cert_hook()
    return {
        "ssl_certfile": certfile,
        "ssl_keyfile": keyfile,
        "ssl_ca_certs": ca_certs,
        "ssl_cert_reqs": cert_reqs_from_env(),
        "ssl_context_factory": _ssl_context_factory,
    }


def pem_from_transport(transport: Any) -> str:
    if transport is None:
        return ""
    try:
        ssl_object = transport.get_extra_info("ssl_object")
    except Exception:
        return ""
    if ssl_object is None:
        return ""
    try:
        der = ssl_object.getpeercert(binary_form=True)
    except Exception:
        return ""
    if not der:
        return ""
    try:
        return ssl.DER_cert_to_PEM_cert(der)
    except Exception:
        return ""


def normalize_client_cert_pem(value: str) -> str:
    """Turn an nginx-forwarded or URL-encoded PEM into a parseable certificate."""
    text = (value or "").strip()
    if not text:
        return ""
    if "%" in text:
        text = unquote(text).strip()
    text = text.replace("\\n", "\n")
    if "BEGIN CERTIFICATE" in text and "\n" not in text:
        text = text.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
        text = text.replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----")
        parts = text.split("-----BEGIN CERTIFICATE-----\n", 1)
        if len(parts) == 2:
            body_and_tail = parts[1]
            body, _, tail = body_and_tail.partition("-----END CERTIFICATE-----")
            body = body.replace(" ", "\n").strip()
            text = "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----" + tail
    if "BEGIN CERTIFICATE" in text and not text.endswith("\n"):
        text += "\n"
    return text


def peer_cert_pem_from_request(request: Request) -> str:
    extensions = request.scope.get("extensions") or {}
    scoped = extensions.get(PEER_CERT_EXTENSION) or ""
    if scoped:
        return str(scoped)
    if tls_proxy():
        verify = (request.headers.get("x-ssl-client-verify") or request.headers.get("ssl-client-verify") or "").strip().upper()
        if verify and verify not in {"SUCCESS", "OK", "NONE"}:
            return ""
        forwarded = (
            request.headers.get("x-ssl-client-cert")
            or request.headers.get("ssl-client-cert")
            or request.headers.get("x-forwarded-tls-client-cert")
            or ""
        )
        pem = normalize_client_cert_pem(forwarded)
        if pem and (not verify or verify in {"SUCCESS", "OK"}):
            return pem
    return ""


def install_peer_cert_hook() -> None:
    """Copy the TLS peer certificate onto the ASGI scope (uvicorn does not)."""
    global _HOOKED
    if _HOOKED:
        return
    _HOOKED = True
    for mod_name in (
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.http.zttp_impl",
    ):
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            continue
        cycle = getattr(mod, "RequestResponseCycle", None)
        if cycle is None:
            continue
        _patch_cycle(cycle)


def _patch_cycle(cls: type) -> None:
    original = cls.__init__

    def wrapped(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        original(self, *args, **kwargs)
        transport = getattr(self, "transport", None)
        pem = pem_from_transport(transport)
        if not pem:
            return
        scope = getattr(self, "scope", None)
        if not isinstance(scope, dict):
            return
        extensions = dict(scope.get("extensions") or {})
        extensions[PEER_CERT_EXTENSION] = pem
        scope["extensions"] = extensions

    cls.__init__ = wrapped  # type: ignore[method-assign]
