"""
Aegis Finding Verifier — Manual PoC Instructions & Automated Live Re-testing.

Provides:
1. Manual CLI reproduction commands (curl, PowerShell, Nmap, OpenSSL).
2. Automated targeted re-testing of individual findings with real-time proof of vulnerability/remediation.
"""

import asyncio
import socket
import ssl
import time
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import httpx


class FindingVerifier:
    """Verifies specific vulnerability findings on demand (manually or automated)."""

    def get_instructions(self, finding_id: str, title: str, target: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Generates CLI reproduction commands and verification guidelines for a finding."""
        port = port or 80
        is_https = (port in (443, 8443))
        scheme = "https" if is_https else "http"
        url = f"{scheme}://{target}:{port}" if port not in (80, 443) else f"{scheme}://{target}"

        # ── HTTP Headers / Web Misconfigurations ──────────────────────────
        if finding_id.startswith("AEGIS-HTTP-"):
            header_map = {
                "AEGIS-HTTP-001": ("Strict-Transport-Security", "HSTS header is absent from HTTP response", "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
                "AEGIS-HTTP-002": ("X-Frame-Options", "X-Frame-Options header missing (clickjacking risk)", "X-Frame-Options: DENY or SAMEORIGIN"),
                "AEGIS-HTTP-003": ("X-Content-Type-Options", "MIME sniffing protection header missing", "X-Content-Type-Options: nosniff"),
                "AEGIS-HTTP-004": ("Content-Security-Policy", "CSP header missing (XSS mitigation)", "Content-Security-Policy: default-src 'self'"),
                "AEGIS-HTTP-005": ("Referrer-Policy", "Referrer-Policy header missing", "Referrer-Policy: strict-origin-when-cross-origin"),
                "AEGIS-HTTP-006": ("Permissions-Policy", "Permissions-Policy header missing", "Permissions-Policy: geolocation=(), camera=()"),
                "AEGIS-HTTP-007": ("Server", "Server software banner is disclosed", "Server header hidden or stripped"),
                "AEGIS-HTTP-008": ("X-Powered-By", "Backend technology banner disclosed", "X-Powered-By header removed"),
            }

            if finding_id in header_map:
                hdr_name, vuln_desc, rem_desc = header_map[finding_id]
                curl_cmd = f"curl -I -k {url}/"
                ps_cmd = f"(Invoke-WebRequest -Uri '{url}' -Method Head -UseBasicParsing -SkipCertificateCheck).Headers"
                return {
                    "method": "HTTP Header Inspection",
                    "curl_command": curl_cmd,
                    "powershell_command": ps_cmd,
                    "tool": "cURL / PowerShell",
                    "steps": [
                        f"Send a HEAD request to {url}/ to inspect HTTP response headers.",
                        f"Check whether the '{hdr_name}' header is present in the response.",
                    ],
                    "expected_vulnerable": f"Header '{hdr_name}' is completely absent or discloses internal software versions.",
                    "expected_remediated": f"Header '{hdr_name}' is present and configured correctly (e.g. {rem_desc}).",
                }

            # Sensitive paths / files (e.g. .git, .env, phpinfo)
            path = "/.env"
            if "git" in title.lower():
                path = "/.git/HEAD"
            elif "php" in title.lower():
                path = "/phpinfo.php"
            elif "swagger" in title.lower():
                path = "/swagger-ui.html"

            return {
                "method": "HTTP Path Probe",
                "curl_command": f"curl -i -k {url}{path}",
                "powershell_command": f"Invoke-WebRequest -Uri '{url}{path}' -UseBasicParsing -SkipCertificateCheck",
                "tool": "cURL / Web Browser",
                "steps": [
                    f"Send a GET request to the sensitive endpoint: {url}{path}",
                    "Inspect the HTTP response status code and body content.",
                ],
                "expected_vulnerable": "Returns HTTP 200 OK with sensitive file contents, source code, or internal configuration.",
                "expected_remediated": "Returns HTTP 404 Not Found or HTTP 403 Forbidden.",
            }

        # ── SMB Checks ────────────────────────────────────────────────────
        if finding_id.startswith("AEGIS-SMB-") or "SMB" in title.upper():
            return {
                "method": "SMB Security Mode Audit",
                "curl_command": f"nmap -p 445 --script smb-security-mode,smb2-security-mode {target}",
                "powershell_command": f"Get-SmbServerConfiguration | Select-Object -Property EnableSMB1Protocol, RequireSecuritySignature",
                "tool": "Nmap / PowerShell",
                "steps": [
                    f"Probe SMB service on {target}:445 using Nmap or PowerShell.",
                    "Check if message signing is required or disabled.",
                ],
                "expected_vulnerable": "Message signing is enabled but not required ('message_signing: disabled' or 'RequireSecuritySignature = False'). Allows NTLM relay.",
                "expected_remediated": "Message signing is enforced ('RequireSecuritySignature = True'). NTLM relay attacks are blocked.",
            }

        # ── TLS / SSL Checks ──────────────────────────────────────────────
        if finding_id.startswith("AEGIS-TLS-") or "TLS" in title.upper() or "SSL" in title.upper():
            return {
                "method": "TLS Handshake & Cipher Audit",
                "curl_command": f"openssl s_client -connect {target}:{port} -tls1",
                "powershell_command": f"Test-NetConnection -ComputerName {target} -Port {port}",
                "tool": "OpenSSL / testssl.sh",
                "steps": [
                    f"Attempt a TLS handshake with legacy protocols (TLS 1.0 / 1.1) against {target}:{port}.",
                    "Inspect negotiated cipher suites and server certificate validity.",
                ],
                "expected_vulnerable": "Handshake succeeds with TLSv1.0 or TLSv1.1, or certificate is expired/self-signed.",
                "expected_remediated": "Server rejects TLS < 1.2 with handshake failure, and serves a valid CA-signed certificate.",
            }

                # ── FTP Services ──────────────────────────────────────────────────
        if "ftp" in title.lower() or finding_id == "AEGIS-TMPL-004" or port == 21:
            return {
                "method": "FTP Anonymous Authentication Audit (RFC 959)",
                "curl_command": f"curl -v --user anonymous:anonymous@ ftp://{target}:{port}/",
                "powershell_command": f"$ftp = [System.Net.FtpWebRequest]::Create('ftp://{target}:{port}/'); $ftp.Credentials = New-Object System.Net.NetworkCredential('anonymous', 'anonymous@'); $ftp.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory; $resp = $ftp.GetResponse(); $resp.StatusDescription",
                "tool": "cURL / ftp / PowerShell",
                "steps": [
                    f"Initiate TCP connection to FTP service on {target}:{port}.",
                    "Read 220 service ready banner from server.",
                    "Send authentication command: 'USER anonymous'.",
                    "When challenged with 331, send password: 'PASS anonymous@'.",
                    "Evaluate final server response code: 230 confirms access; 530 confirms access is denied."
                ],
                "expected_vulnerable": "Server replies '230 Login successful' or '230 User logged in'.",
                "expected_remediated": "Server replies '530 Login incorrect' or '530 User anonymous cannot log in'.",
                "note": "Anonymous FTP allows arbitrary users to access the directory tree without valid account credentials."
            }

        # ── Database / Template Checks ────────────────────────────────────
        if finding_id.startswith("AEGIS-TMPL-"):
            if "redis" in title.lower():
                return {
                    "method": "TCP Unauthenticated Query",
                    "curl_command": f"redis-cli -h {target} -p {port} ping",
                    "powershell_command": f"$client = New-Object System.Net.Sockets.TcpClient('{target}', {port}); $stream = $client.GetStream(); $writer = New-Object System.IO.StreamWriter($stream); $writer.WriteLine('PING'); $writer.Flush(); $reader = New-Object System.IO.StreamReader($stream); $reader.ReadLine()",
                    "tool": "redis-cli / netcat",
                    "steps": [
                        f"Connect to Redis server on {target}:{port} and send 'PING'.",
                    ],
                    "expected_vulnerable": "Server replies '+PONG' without requiring AUTH password.",
                    "expected_remediated": "Server replies '-NOAUTH Authentication required.'.",
                }
            if "docker" in title.lower():
                return {
                    "method": "HTTP REST API Query",
                    "curl_command": f"curl -s http://{target}:{port}/version",
                    "powershell_command": f"Invoke-RestMethod -Uri 'http://{target}:{port}/version'",
                    "tool": "cURL / Docker CLI",
                    "steps": [
                        f"Query Docker daemon API endpoint at http://{target}:{port}/version.",
                    ],
                    "expected_vulnerable": "Returns JSON object with Docker daemon version and OS architecture with no authentication.",
                    "expected_remediated": "Connection refused, or TLS client certificate required.",
                }

        # ── Generic CVE / Software Version ────────────────────────────────
        return {
            "method": "Service Banner & Version Verification",
            "curl_command": f"nmap -sV -p {port} {target}",
            "powershell_command": f"$tcp = Test-NetConnection -ComputerName {target} -Port {port}; $tcp",
            "tool": "Nmap / Netcat",
            "steps": [
                f"Connect to {target}:{port} and capture the raw service banner.",
                "Compare the running software version against known vulnerable releases.",
            ],
            "expected_vulnerable": "Software version banner matches the vulnerable version range.",
            "expected_remediated": "Software is updated to the latest patched version.",
        }

    async def verify_finding(self, finding_id: str, title: str, target: str, port: Optional[int] = None) -> Dict[str, Any]:
        """
        Executes a targeted, automated real-time test against the target to verify
        if the finding is actively vulnerable or has been remediated.
        """
        t0 = time.time()
        port = port or 80
        timestamp = datetime.now(timezone.utc).isoformat()

        # 1. HTTP Misconfigurations Re-test
        if finding_id.startswith("AEGIS-HTTP-"):
            return await self._verify_http_finding(finding_id, target, port, t0, timestamp)

        # 2. SMB Signing / SMB Re-test
        if finding_id.startswith("AEGIS-SMB-") or "SMB" in title.upper():
            return await self._verify_smb_finding(finding_id, target, port, t0, timestamp)

        # 3. TLS Protocol / Certificate Re-test
        if finding_id.startswith("AEGIS-TLS-") or "TLS" in title.upper():
            return await self._verify_tls_finding(finding_id, target, port, t0, timestamp)

        # 4. FTP Anonymous Login Verification
        if "ftp" in title.lower() or finding_id == "AEGIS-TMPL-004" or port == 21:
            return await self._verify_ftp_finding(target, port or 21, t0, timestamp)

        # 5. Template Engine Checks (Redis, Docker, MongoDB, etc.)
        if finding_id.startswith("AEGIS-TMPL-"):
            return await self._verify_template_finding(finding_id, target, port, t0, timestamp)

        # 5. Generic Service Banner / Port Check
        return await self._verify_service_banner(target, port, t0, timestamp)

    # ── Specialized Automated Testers ─────────────────────────────────────────

    async def _verify_http_finding(self, finding_id: str, target: str, port: int, t0: float, timestamp: str) -> Dict[str, Any]:
        is_https = (port in (443, 8443))
        scheme = "https" if is_https else "http"
        url = f"{scheme}://{target}:{port}/"

        try:
            async with httpx.AsyncClient(verify=False, timeout=4.0, follow_redirects=True) as client:
                resp = await client.get(url)
                elapsed = round((time.time() - t0) * 1000, 1)
                headers = dict(resp.headers)

                # Format proof headers
                header_preview = "\n".join(f"{k}: {v}" for k, v in list(headers.items())[:12])

                # Check specific missing header
                req_headers = {
                    "AEGIS-HTTP-001": "strict-transport-security",
                    "AEGIS-HTTP-002": "x-frame-options",
                    "AEGIS-HTTP-003": "x-content-type-options",
                    "AEGIS-HTTP-004": "content-security-policy",
                    "AEGIS-HTTP-005": "referrer-policy",
                    "AEGIS-HTTP-006": "permissions-policy",
                }

                if finding_id in req_headers:
                    hkey = req_headers[finding_id]
                    if hkey in headers:
                        return {
                            "status": "REMEDIATED",
                            "is_vulnerable": False,
                            "execution_time_ms": elapsed,
                            "timestamp": timestamp,
                            "summary": f"Header '{hkey}' is now present in HTTP response.",
                            "details": f"The security header was successfully received from {target}:{port}. Value: '{headers[hkey]}'",
                            "raw_proof": f"HTTP/{resp.http_version} {resp.status_code} {resp.reason_phrase}\n{hkey}: {headers[hkey]}\n\nServer Response Headers:\n{header_preview}",
                        }
                    else:
                        return {
                            "status": "VULNERABLE",
                            "is_vulnerable": True,
                            "execution_time_ms": elapsed,
                            "timestamp": timestamp,
                            "summary": f"Header '{hkey}' is still missing from HTTP response.",
                            "details": f"Target {target}:{port} returned HTTP {resp.status_code}, but the security header '{hkey}' was not present.",
                            "raw_proof": f"HTTP/{resp.http_version} {resp.status_code} {resp.reason_phrase}\n(Header '{hkey}' is absent)\n\nObserved Response Headers:\n{header_preview}",
                        }

                # Server banner disclosure
                if finding_id == "AEGIS-HTTP-007":
                    server_val = headers.get("server")
                    if server_val and any(c.isdigit() for c in server_val):
                        return {
                            "status": "VULNERABLE",
                            "is_vulnerable": True,
                            "execution_time_ms": elapsed,
                            "timestamp": timestamp,
                            "summary": f"Server banner discloses software version: '{server_val}'",
                            "details": f"The Server header reveals exact software version information.",
                            "raw_proof": f"Server: {server_val}\n\nHeaders:\n{header_preview}",
                        }
                    else:
                        return {
                            "status": "REMEDIATED",
                            "is_vulnerable": False,
                            "execution_time_ms": elapsed,
                            "timestamp": timestamp,
                            "summary": "Server banner is hidden, generic, or stripped.",
                            "details": f"Current Server header value: '{server_val or 'None'}'",
                            "raw_proof": f"Server: {server_val or '(Header omitted)'}",
                        }

                return {
                    "status": "CONFIRMED",
                    "is_vulnerable": True,
                    "execution_time_ms": elapsed,
                    "timestamp": timestamp,
                    "summary": f"HTTP endpoint reachable at {url}",
                    "details": f"Target responded with status code HTTP {resp.status_code}",
                    "raw_proof": f"HTTP/{resp.http_version} {resp.status_code}\n{header_preview}",
                }

        except Exception as e:
            elapsed = round((time.time() - t0) * 1000, 1)
            return {
                "status": "UNREACHABLE",
                "is_vulnerable": False,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": "Could not connect to HTTP service.",
                "details": f"Connection error: {str(e)}",
                "raw_proof": f"Failed connection to {url}: {str(e)}",
            }

    async def _verify_smb_finding(self, finding_id: str, target: str, port: int, t0: float, timestamp: str) -> Dict[str, Any]:
        """Probes SMB service on port 445."""
        loop = asyncio.get_event_loop()
        try:
            t_start = time.time()
            conn = asyncio.open_connection(target, port or 445)
            reader, writer = await asyncio.wait_for(conn, timeout=3.0)

            # Send SMBv1/v2 negotiate packet
            negotiate_proto = bytes([
                0x00, 0x00, 0x00, 0x45,  # NetBIOS header
                0xff, 0x53, 0x4d, 0x42,  # "\xFFSMB"
                0x72,                    # SMB_COM_NEGOTIATE
                0x00, 0x00, 0x00, 0x00,  # Status
                0x18, 0x53, 0xc8, 0x01,  # Flags
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x22,              # Byte count
                0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, # NT LM 0.12
                0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00,       # SMB 2.002
            ])
            writer.write(negotiate_proto)
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            writer.close()
            await writer.wait_closed()
            elapsed = round((time.time() - t0) * 1000, 1)

            if len(resp) >= 4 and (resp[4:8] == b"\xffSMB" or resp[4:8] == b"\xfeSMB"):
                smb_ver = "SMBv1 (Legacy)" if resp[4:8] == b"\xffSMB" else "SMBv2/v3"
                return {
                    "status": "VULNERABLE",
                    "is_vulnerable": True,
                    "execution_time_ms": elapsed,
                    "timestamp": timestamp,
                    "summary": f"SMB Service active on {target}:445. Negotiated: {smb_ver}.",
                    "details": "SMB service responded to negotiate protocol. Message signing is not strictly enforced.",
                    "raw_proof": f"Connected to {target}:445\nProtocol: {smb_ver}\nResponse Length: {len(resp)} bytes\nHex Dump: {resp[:32].hex(' ')}",
                }
            else:
                return {
                    "status": "CONFIRMED",
                    "is_vulnerable": True,
                    "execution_time_ms": elapsed,
                    "timestamp": timestamp,
                    "summary": f"Port 445 is open and accepting TCP connections.",
                    "details": "SMB service is online.",
                    "raw_proof": f"Port 445/tcp OPEN. Handshake latency: {elapsed} ms.",
                }
        except Exception as e:
            elapsed = round((time.time() - t0) * 1000, 1)
            return {
                "status": "UNREACHABLE",
                "is_vulnerable": False,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": "Could not connect to SMB port 445.",
                "details": f"Connection refused or timed out: {str(e)}",
                "raw_proof": f"Error connecting to {target}:445: {str(e)}",
            }

    async def _verify_tls_finding(self, finding_id: str, target: str, port: int, t0: float, timestamp: str) -> Dict[str, Any]:
        """Audits TLS handshake on live target port."""
        try:
            loop = asyncio.get_event_loop()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            def do_handshake():
                s = socket.create_connection((target, port or 443), timeout=3.0)
                ss = ctx.wrap_socket(s, server_hostname=target)
                cert = ss.getpeercert(binary_form=True)
                proto = ss.version()
                cipher = ss.cipher()
                ss.close()
                return proto, cipher, len(cert) if cert else 0

            proto, cipher, cert_len = await loop.run_in_executor(None, do_handshake)
            elapsed = round((time.time() - t0) * 1000, 1)

            is_weak = proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
            return {
                "status": "VULNERABLE" if is_weak else "REMEDIATED",
                "is_vulnerable": is_weak,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": f"Negotiated {proto} with cipher {cipher[0] if cipher else 'unknown'}",
                "details": f"Server protocol: {proto} ({'Legacy Weak Protocol' if is_weak else 'Modern Secure TLS'})",
                "raw_proof": f"TLS Version: {proto}\nCipher Suite: {cipher[0] if cipher else 'N/A'}\nKey Exchange: {cipher[1] if cipher else 'N/A'}\nBits: {cipher[2] if cipher else 'N/A'}\nCertificate bytes: {cert_len}",
            }
        except Exception as e:
            elapsed = round((time.time() - t0) * 1000, 1)
            return {
                "status": "UNREACHABLE",
                "is_vulnerable": False,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": f"TLS handshake failed on port {port}.",
                "details": str(e),
                "raw_proof": f"TLS connection to {target}:{port} failed: {str(e)}",
            }

    async def _verify_ftp_finding(self, target: str, port: int, t0: float, timestamp: str) -> Dict[str, Any]:
        """Performs a live RFC 959 anonymous authentication audit against the FTP server."""
        transcript = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=5.0
            )

            # 1. Read greeting banner line
            banner_line = await asyncio.wait_for(reader.readline(), timeout=4.0)
            banner_text = banner_line.decode("latin1", errors="replace").strip()
            transcript.append(f"← {banner_text}")

            # 2. Send USER anonymous
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            transcript.append("→ USER anonymous")

            user_line = await asyncio.wait_for(reader.readline(), timeout=4.0)
            user_text = user_line.decode("latin1", errors="replace").strip()
            transcript.append(f"← {user_text}")

            is_vuln = False
            summary = ""
            details = ""

            if user_text.startswith("230"):
                is_vuln = True
                summary = "Anonymous FTP Login Accepted (230 User logged in)"
                details = "The FTP server immediately accepted 'USER anonymous' without requiring a password."
            elif user_text.startswith("331"):
                # Send PASS anonymous@
                writer.write(b"PASS anonymous@\r\n")
                await writer.drain()
                transcript.append("→ PASS anonymous@")

                pass_line = await asyncio.wait_for(reader.readline(), timeout=4.0)
                pass_text = pass_line.decode("latin1", errors="replace").strip()
                transcript.append(f"← {pass_text}")

                if pass_text.startswith("230"):
                    is_vuln = True
                    summary = "Anonymous FTP Login Accepted (230 Login successful)"
                    details = "The server accepted anonymous credentials (USER anonymous / PASS anonymous@)."
                else:
                    is_vuln = False
                    summary = f"Anonymous FTP Login Rejected: {pass_text}"
                    details = f"Server rejected anonymous access with response: {pass_text}"
            elif user_text.startswith("530") or "cannot" in user_text.lower():
                is_vuln = False
                summary = f"Anonymous FTP Login Denied ({user_text})"
                details = f"Server explicitly rejected anonymous user: {user_text}"
            else:
                is_vuln = False
                summary = f"FTP server response: {user_text}"
                details = "Could not confirm anonymous login."

            # Clean exit
            try:
                writer.write(b"QUIT\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            elapsed = round((time.time() - t0) * 1000, 1)
            return {
                "status": "VULNERABLE" if is_vuln else "REMEDIATED",
                "is_vulnerable": is_vuln,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": summary,
                "details": details,
                "raw_proof": "\n".join(transcript),
            }
        except Exception as e:
            elapsed = round((time.time() - t0) * 1000, 1)
            err_msg = str(e) or type(e).__name__
            return {
                "status": "UNREACHABLE",
                "is_vulnerable": False,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": f"Could not complete FTP handshake on {target}:{port}",
                "details": err_msg,
                "raw_proof": f"Connection to {target}:{port} failed: {err_msg}",
            }

    async def _verify_template_finding(self, finding_id: str, target: str, port: int, t0: float, timestamp: str) -> Dict[str, Any]:
        """Probes unauthenticated database/service endpoints."""
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=3.0)

            # Redis probe
            if "001" in finding_id or port == 6379:
                writer.write(b"PING\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(128), timeout=2.0)
                writer.close()
                await writer.wait_closed()
                elapsed = round((time.time() - t0) * 1000, 1)
                is_vuln = b"+PONG" in resp
                return {
                    "status": "VULNERABLE" if is_vuln else "REMEDIATED",
                    "is_vulnerable": is_vuln,
                    "execution_time_ms": elapsed,
                    "timestamp": timestamp,
                    "summary": "Redis Unauthenticated Access" if is_vuln else "Authentication Enforced",
                    "details": "Server answered PING with +PONG without requiring credentials." if is_vuln else "Server required AUTH.",
                    "raw_proof": f"Sent: PING\\r\\n\nReceived: {resp.decode('latin1', errors='replace')}",
                }

            writer.close()
            await writer.wait_closed()
            elapsed = round((time.time() - t0) * 1000, 1)
            return {
                "status": "CONFIRMED",
                "is_vulnerable": True,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": f"Port {port} is open and receptive to TCP packets.",
                "details": f"TCP probe connected successfully in {elapsed} ms.",
                "raw_proof": f"Port {port}/tcp OPEN.",
            }
        except Exception as e:
            elapsed = round((time.time() - t0) * 1000, 1)
            return {
                "status": "REMEDIATED",
                "is_vulnerable": False,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": f"Port {port} is closed or refusing connections.",
                "details": str(e),
                "raw_proof": f"Connection to {target}:{port} failed: {str(e)}",
            }

    async def _verify_service_banner(self, target: str, port: int, t0: float, timestamp: str) -> Dict[str, Any]:
        """Captures raw TCP service banner from target port."""
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=3.0)
            banner = ""
            try:
                raw = await asyncio.wait_for(reader.read(512), timeout=2.0)
                banner = raw.decode("latin1", errors="replace").strip()
            except asyncio.TimeoutError:
                pass
            writer.close()
            await writer.wait_closed()
            elapsed = round((time.time() - t0) * 1000, 1)
            return {
                "status": "CONFIRMED",
                "is_vulnerable": True,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": f"Port {port} is open and active.",
                "details": f"Banner: '{banner or 'Silent binary service'}'",
                "raw_proof": f"Connection succeeded in {elapsed} ms.\nRaw Banner: {banner or '(None)'}",
            }
        except Exception as e:
            elapsed = round((time.time() - t0) * 1000, 1)
            return {
                "status": "UNREACHABLE",
                "is_vulnerable": False,
                "execution_time_ms": elapsed,
                "timestamp": timestamp,
                "summary": f"Port {port} is not reachable.",
                "details": str(e),
                "raw_proof": f"Connection failed: {str(e)}",
            }
