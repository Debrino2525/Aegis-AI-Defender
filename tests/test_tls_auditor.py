"""TLS auditor must report expired and self-signed certificates.

ssl.getpeercert() is empty when verification is disabled, so the auditor has
to decode the peer certificate bytes. These fixtures are throwaway keys
generated for the test, not credentials for any real host.
"""

import socket
import ssl
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis.checks.tls_auditor import TLSAuditor, parse_x509_certificate
from aegis.core.config import ScanConfig


EXPIRED_CERT = """-----BEGIN CERTIFICATE-----
MIICxjCCAa6gAwIBAgIUKSLcNK83Zmgy6o8RGf5iUSTYAkgwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSZXhwaXJlZC5hZWdpcy50ZXN0MB4XDTI1MTAwNjExMDYz
MloXDTI2MTAxMTExMDYzMlowHTEbMBkGA1UEAwwSZXhwaXJlZC5hZWdpcy50ZXN0
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApaBnVIJcVEFa2/BozPSr
bIRLw1R6cf9uP14iSW4/wXB8996q5KOvbE/iPAvIYW3azbPOOv20EV0LPmc2CaX5
ourGRj2qnaXGY/7mMgHWImAsxk5qrWlQOOF0nXW+tb76Yt8bAAhU1/047ELOaSdo
oUcqM/LqSNUD2t2trMX6Aypufwv/H7uBksR9wwYcS+AFKaAo1fZHC3/B2uoawXCR
QfgQohIoqx/FHJeFcsyozCbXnxhS3iDrwX8ZzSAcPMPTKZTPrduhcx0XnQdKoPUa
Bi2shRQAHx9hSX9qHyerz8n8RE1HgaYG+GihjLRpZ4kSuhuBY0ACilMKNKcKK95d
xwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBkJHt5SdYn/6uilJAFAfKusysqO3Z0
LTbDvYqDiz5LOpSB13ZjXYreUq4cV0jeNn/COXNeChOexCNmRjMcU+t0WPIcN+sO
utHlnXuSiA6O84OtBcrHCMrhI/5WH5UPn9bhCG1Ey7OoF7NQWSrK1kbOCP1pPv84
T9YZT09SpbfiazyRLSXtnP/LkqQf2ujmae8jCsMC5Sd8UBv+nQqvz5r/AUQGAbzu
wOqRhfVw6HTYey8xpmYUvzasxmx8FZroUIkRax38s9fgJrvJLibtsjpaq25dXV/U
3XGkpBKAx4ah00V6DNnMv3u4zas4PlAFJf49e/Lo9OOngt/rSbD0s/Ey
-----END CERTIFICATE-----
"""

EXPIRED_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEApaBnVIJcVEFa2/BozPSrbIRLw1R6cf9uP14iSW4/wXB8996q
5KOvbE/iPAvIYW3azbPOOv20EV0LPmc2CaX5ourGRj2qnaXGY/7mMgHWImAsxk5q
rWlQOOF0nXW+tb76Yt8bAAhU1/047ELOaSdooUcqM/LqSNUD2t2trMX6Aypufwv/
H7uBksR9wwYcS+AFKaAo1fZHC3/B2uoawXCRQfgQohIoqx/FHJeFcsyozCbXnxhS
3iDrwX8ZzSAcPMPTKZTPrduhcx0XnQdKoPUaBi2shRQAHx9hSX9qHyerz8n8RE1H
gaYG+GihjLRpZ4kSuhuBY0ACilMKNKcKK95dxwIDAQABAoIBAAd23nXcsrscNlfs
CViEc3lVPZaUuV0eKJlhpD/wYHnEmHrtARODZY70y0PKXd2lEaYRDEcG5Xnm2kve
9XyjQiObpDg2dmZtTFN370J9aCBt6FIaeTEphbx18mvqQUTBCMbpXtttFvt/00+h
YWzq61PPHRrMP/Oje7aQbZjl5heXN4jhIDePnzQLVzgSMBkyohuCzVCB54BmvQvS
fQjyWMVoHwh/j5oVuMeojAc55kS84AwvSf5K2FKFDhL2e9lpprHqPwvO5mIreuaO
EJSGfHOVCWUPleK0Z60Bhx6ES2/OpciWIfdnZ/Lkz3WLxuEYdUAINpgtUQckkJ0+
85WsBAECgYEA09NO/RUT6hKSBWUyHgfxfQsJRUpfjhpQv+/rptBs6L3wUyK7Ucdq
F53aBsDZiHyxdz2vg6ZzwnJKcDAJ+dCfKXNwsKni4wT2MrLVq4S7XKQ7CQ6fNcBQ
1lBIb5GThq7q7xtI+57jF6XiVv6naYgQZd4cMHEvBKMqx9PlJYdOXgECgYEAyCqv
LmJiKTewnvmyJo95NaeRblvmEPCkjJYH+YgK+c0FCjmjbSol7ubLvJm8kJ9sC+3q
yAXKYR7+hqt2mE8dA4tKrrFWkjuFXRFWL8Gh4BJDiGY8xCEeZjM+kgtR+qYh8Bdt
19TS9sAaMIvdCz0Gri3NiQ1dP3BTCSbiSXppS8cCgYEAlRys/+80g5PrAq1H6GgD
ENkR/5rpRSk1KsgDhPw3jmcWpA9Q+bJ89n8CGbrr5u6QJrZftTcZSgoWaH8Ipri7
Mfy3mUUeGF1HykylqQXYttBNVoTagoYM4bDGLPO3fBnp+8OjTq18gwsdF8xPoTRN
Bsih41/pj0QlO2HobtCe1AECgYEAn52J/A7v/7Ys3Vh3u1AFc8efrMUTfMaoMIMi
8NSPDAt0zWaQ72gAv7TDGi3ts9WsrwaVhdM4QqIYjQMFmwbbOAxHDW7Ufd+AxWoh
tAtQLgHiYE5Gfo96Ujzi1Eq6oIkB3xaPvOA1Khady8B8D44mWZako3lItmG3lUCw
ia9Xb9kCgYAkXDRvOpJ/N2aP3oBw85u3yoOzE2hhZbZ6l0bh95zLEz5gS/JfFtiL
1DlAeA3FfHJ8Wvi9Y5HFoCekHkABtkh4ltB/N8I4qItMuX1nbEPNfN0XbQghqD3j
c1BkwkBvh7T2T+hBOzlqZ3/7O9IcsRgmDulbL0Cwtd2i/dQHDXzW2w==
-----END RSA PRIVATE KEY-----
"""

VALID_CERT = """-----BEGIN CERTIFICATE-----
MIICwjCCAaqgAwIBAgIUEgiu62juJ6f4K01jvptXpS7LeVswDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdmFsaWQuYWVnaXMudGVzdDAeFw0yNjExMDkxMTA2MzJa
Fw0yNzExMTAxMTA2MzJaMBsxGTAXBgNVBAMMEHZhbGlkLmFlZ2lzLnRlc3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDf/Anw9rxRWmZRP09MNswdWRq7
LwuOt+J8Fp63mRLM7YkViU1V3TrdJdceLQo7qxN8MmivKELuaH3j0mUP9IBkNh5N
D8tRF0V5WuZAKmDFQB81MkjjU2Cwci6D2vaeY9qUwR+eO/t1W2tLqT1DUzxQhYvu
BpVQfddixk7kt7hc6uoe1LL1arIF5CerKVe/9qM/NBr/M1tvMLPSzra8/RZ8anZd
CJbA1zeSQjlah/j0ZIHjed2PgROq8/900FpNbwmaGCw2v/b211UX622r6GF3tntH
MpCiiyzUyyIAy/0QxHZ0vQcvORIMZXXUA4xhQ7s/Pb79IzN6CnZB/Hs/ZYhjAgMB
AAEwDQYJKoZIhvcNAQELBQADggEBABPFhuImp1jUlDb3Ho2O93lwjCgD3P1E65uw
slbhA6QXCmORCnWiw546/WVVjNWsqH5ypRRFPX4cngPe247+kZ+FtSsie21gmxbj
x71jwQnxRR3n3yCS0GhbwXvOzXtzGePtlP0TkklrQ0GzZqfmYiNqkM78EhSivTKE
wCB1Q4IzKcpiLXTVU5RUEe/33tzNbCWnBQ5uVdp7TAPcfqmW3VQ1FOMb2yRwZ806
tRlg9xE7Uivpp0rm/ijuUvKcNGZWLxKFXNp5+4cS7PdQ55KYgb/fAt9j51QvaqH8
uTRl+idLAC7cz1Jaatt2aptW4WXBtCf74JLJeKt8P3Yq/rv8Dhg=
-----END CERTIFICATE-----
"""

VALID_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA3/wJ8Pa8UVpmUT9PTDbMHVkauy8LjrfifBaet5kSzO2JFYlN
Vd063SXXHi0KO6sTfDJoryhC7mh949JlD/SAZDYeTQ/LURdFeVrmQCpgxUAfNTJI
41NgsHIug9r2nmPalMEfnjv7dVtrS6k9Q1M8UIWL7gaVUH3XYsZO5Le4XOrqHtSy
9WqyBeQnqylXv/ajPzQa/zNbbzCz0s62vP0WfGp2XQiWwNc3kkI5Wof49GSB43nd
j4ETqvP/dNBaTW8JmhgsNr/29tdVF+ttq+hhd7Z7RzKQooss1MsiAMv9EMR2dL0H
LzkSDGV11AOMYUO7Pz2+/SMzegp2Qfx7P2WIYwIDAQABAoIBAEbe6ERaxbZWDLbb
edtLIWWN2pPsrFMBowORYrIEGLtH047BbXtkLypnPTw6kxjTJiyvhIkbi6YE4QRz
f2+/dNqAdzD59OKZIu3lkaIu5oSzJ8y8tuxa5uadklM9NrhiLvjPbJI0N3noLbh4
eb5yOUzfHKn5YkhgMQT7a14aNZcMU9fm35iZIioug9TbawT9dGkKXH37ltWqkb/d
ihkGnK0JRxp5Q34/ltiNWY8NBeO+mLOa1J5T9SIavbg+K/g5BuWahCmRdgm29py2
XiRgbHcip+a/DH3YD/4gR/1x8cVvhM/XMThdmuwczrLhc0SKymoBvSJ7Q8vswJ+m
igxiaDkCgYEA+LXsIiKUXwBJNp5bEit5PcS13S8ldqUz8W1gJ52V/xlRP48OXm3S
Pay+8dlWdj08KNFq1btp1OiWCKVQMTuy0i+FJrSsT+d1qGZrn+mjGiCzdbVQEa1p
8gdnqKlF2Vqg/Y/+QCY2moclRHm4zct4VKzTK2z+YK4v2JDFuMXzfdsCgYEA5oyY
pd3b2g7WXa25huNjtPbbbh9C4ExeO71iCpNfZDqmQI3ppyYM5QGjrBcCgAiAYi3P
jEFjwyZ9WSXbn+6RxxpDMvzJ0ERMzPlvnulLJp4jYn0TxQNCKCb7VtouoGhQ3PeI
64Vw3jmoOsnWOhg3cq9tExm41b6YLCvmeaZiGhkCgYBLEm6yZwmuG2H+EJKgy2qP
UH8swnxmcbtaFo+9pX2PQM8bhkzqB/A8GZaRXe8RRa6RC5VZ6nYphAM1nOC127VA
aIOiiUqx28XSDQhTfqxyyIgi8ZW3oEaofb+2U1H4J7kMkJhIOMCmqECBiNRVmiM6
O+iJ5R5rhGiA0EI+YdH7nQKBgFKKDXB8oGROIZMCSkSvjhfQtTiUupWg4a/TmpEc
t+8jTDgaVoeACOfIEXff+QYrhQMhUYfuNTA9zGypMBrvB4PXtC1B8WK9wR01RDAJ
Z91YimSNURGcnAfSBPPQQxcsoZ6qhHuFl6YH0GHTtv2vg9JsWcmX0OO9S6+su+Pb
nI2pAoGAFuh8fxF7qN/EJBafTQHkzV7Bx78TCQEwYhmgfZreqtA3eLd2B7zeeW34
3XqjLFR+eez5TGAzyvheF243mTBxurg1uP2KuPo/YVOibec9J9NULzNmY9lrpsoc
HJCiSfQKLDeecs3IwmXdvqnSRpJP7UDEg5HvDHZrfLYIw2iY5ko=
-----END RSA PRIVATE KEY-----
"""


def _serve(cert_pem: str, key_pem: str):
    cert_path = Path("/tmp/aegis-tls-test-cert.pem")
    key_path = Path("/tmp/aegis-tls-test-key.pem")
    cert_path.write_text(cert_pem)
    key_path.write_text(key_pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    sock.settimeout(5)
    port = sock.getsockname()[1]

    def _accept():
        try:
            conn, _ = sock.accept()
            try:
                tls_conn = ctx.wrap_socket(conn, server_side=True)
                tls_conn.settimeout(3)
                try:
                    tls_conn.recv(16)
                except Exception:
                    pass
                tls_conn.close()
            except Exception:
                conn.close()
        except Exception:
            pass
        finally:
            sock.close()

    threading.Thread(target=_accept, daemon=True).start()
    return port


def test_parser_reads_expired_self_signed_cert():
    parsed = parse_x509_certificate(ssl.PEM_cert_to_DER_cert(EXPIRED_CERT))
    assert parsed["subject_cn"] == "expired.aegis.test"
    assert parsed["issuer_cn"] == "expired.aegis.test"
    assert parsed["self_signed"] is True
    assert parsed["not_after"] < datetime.now(timezone.utc)
    print("[+] test_parser_reads_expired_self_signed_cert: PASSED")


def test_parser_reads_unexpired_self_signed_cert():
    parsed = parse_x509_certificate(ssl.PEM_cert_to_DER_cert(VALID_CERT))
    assert parsed["subject_cn"] == "valid.aegis.test"
    assert parsed["self_signed"] is True
    assert parsed["not_after"] > datetime.now(timezone.utc) + timedelta(days=300)
    print("[+] test_parser_reads_unexpired_self_signed_cert: PASSED")


def test_check_does_not_treat_different_issuer_as_self_signed():
    auditor = TLSAuditor(ScanConfig(target="127.0.0.1"))
    later = datetime.now(timezone.utc) + timedelta(days=90)
    findings = auditor._check_certificate("10.0.0.5", 443, {
        "cert": {
            "not_after": later,
            "subject_cn": "app.internal",
            "issuer_cn": "corp-ca",
            "self_signed": False,
        }
    })
    assert findings == []
    print("[+] test_check_does_not_treat_different_issuer_as_self_signed: PASSED")


async def _audit(port: int):
    auditor = TLSAuditor(ScanConfig(target="127.0.0.1", connect_timeout=3.0))
    return await auditor.audit("127.0.0.1", port)


def test_live_audit_reports_expired_and_self_signed():
    import asyncio
    port = _serve(EXPIRED_CERT, EXPIRED_KEY)
    findings = asyncio.run(_audit(port))
    ids = {f.id for f in findings}
    assert "AEGIS-TLS-004" in ids, ids
    assert "AEGIS-TLS-006" in ids, ids
    print("[+] test_live_audit_reports_expired_and_self_signed: PASSED")


def test_live_audit_does_not_flag_a_current_certificate_as_expired():
    import asyncio
    port = _serve(VALID_CERT, VALID_KEY)
    findings = asyncio.run(_audit(port))
    ids = {f.id for f in findings}
    assert "AEGIS-TLS-004" not in ids, ids
    assert "AEGIS-TLS-005" not in ids, ids
    assert "AEGIS-TLS-006" in ids, ids
    print("[+] test_live_audit_does_not_flag_a_current_certificate_as_expired: PASSED")


if __name__ == "__main__":
    test_parser_reads_expired_self_signed_cert()
    test_parser_reads_unexpired_self_signed_cert()
    test_check_does_not_treat_different_issuer_as_self_signed()
    test_live_audit_reports_expired_and_self_signed()
    test_live_audit_does_not_flag_a_current_certificate_as_expired()
    print("\n[=== TLS AUDITOR TESTS PASSED ===]")
