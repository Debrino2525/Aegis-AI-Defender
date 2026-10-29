"""
Multi-protocol banner grabber and service fingerprinting engine.
Enhanced with protocol-specific probes for accurate detection.
"""

import asyncio
import ssl
import re
from typing import Optional, Dict, Any, Tuple
import httpx

from aegis.core.models import ServiceInfo
from aegis.core.config import ScanConfig


class ServiceFingerprinter:
    """Probes open ports with multiple protocols to extract detailed service metadata."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def fingerprint(self, host: str, port: int) -> ServiceInfo:
        """Determines protocol, service name, banner, TLS status, and software versions."""
        tls_info = await self._check_tls(host, port)
        is_tls = tls_info.get("tls_enabled", False)

        # Check HTTP / HTTPS first for web ports or TLS listeners
        if port in [80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9000] or is_tls:
            http_info = await self._probe_http(host, port, use_tls=is_tls)
            if http_info:
                return ServiceInfo(
                    port=port,
                    protocol="tcp",
                    service_name="https" if is_tls else "http",
                    product=http_info.get("product"),
                    version=http_info.get("version"),
                    banner=http_info.get("server_banner"),
                    tls=is_tls,
                    metadata={**tls_info, **http_info}
                )

        # Protocol-specific probes for better accuracy
        protocol_result = await self._probe_protocol_specific(host, port)
        if protocol_result:
            return ServiceInfo(
                port=port,
                protocol="tcp",
                service_name=protocol_result["service_name"],
                product=protocol_result.get("product"),
                version=protocol_result.get("version"),
                banner=protocol_result.get("banner"),
                tls=is_tls,
                metadata={**tls_info, **protocol_result.get("metadata", {})}
            )

        # Fallback to raw banner grab
        banner = await self._grab_raw_banner(host, port)
        service_name, product, version = self._analyze_banner(port, banner)

        return ServiceInfo(
            port=port,
            protocol="tcp",
            service_name=service_name,
            product=product,
            version=version,
            banner=banner,
            tls=is_tls,
            metadata=tls_info
        )

    async def _probe_protocol_specific(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Sends protocol-specific probes for accurate service detection."""
        # SSH - specific version exchange
        if port == 22:
            return await self._probe_ssh(host, port)
        # FTP - SYST command
        elif port == 21:
            return await self._probe_ftp(host, port)
        # SMTP - EHLO/HELP
        elif port in [25, 587, 465]:
            return await self._probe_smtp(host, port)
        # DNS - version.bind query
        elif port == 53:
            return await self._probe_dns(host, port)
        # MySQL - handshake packet
        elif port == 3306:
            return await self._probe_mysql(host, port)
        # PostgreSQL - startup packet
        elif port == 5432:
            return await self._probe_postgresql(host, port)
        # Redis - PING/INFO
        elif port == 6379:
            return await self._probe_redis(host, port)
        # MongoDB - isMaster
        elif port == 27017:
            return await self._probe_mongodb(host, port)
        return None

    async def _probe_ssh(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Probes SSH service with version string detection."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            banner_str = banner.decode("utf-8", errors="ignore").strip()
            # SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
            ssh_match = re.search(r"SSH-[\d.]+-([^\s]+)", banner_str)
            if ssh_match:
                full_version = ssh_match.group(1)
                # Extract product and version
                if "OpenSSH" in full_version:
                    version_match = re.search(r"OpenSSH_([0-9a-zA-Z._-]+)", full_version)
                    version = version_match.group(1) if version_match else None
                    return {
                        "service_name": "ssh",
                        "product": "openssh",
                        "version": version,
                        "banner": banner_str,
                        "metadata": {"ssh_protocol": "2.0"}
                    }
        except Exception:
            pass
        return None

    async def _probe_ftp(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Probes FTP service with SYST command."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.write(b"SYST\r\n")
            await writer.drain()
            syst_response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            banner_str = banner.decode("utf-8", errors="ignore").strip()
            syst_str = syst_response.decode("utf-8", errors="ignore").strip()

            # Parse banner for product/version
            if "vsftpd" in banner_str.lower():
                match = re.search(r"vsftpd\s+([0-9.]+)", banner_str, re.I)
                return {
                    "service_name": "ftp",
                    "product": "vsftpd",
                    "version": match.group(1) if match else None,
                    "banner": banner_str,
                    "metadata": {"syst_response": syst_str}
                }
            elif "proftpd" in banner_str.lower():
                match = re.search(r"ProFTPD\s+([0-9.]+)", banner_str, re.I)
                return {
                    "service_name": "ftp",
                    "product": "proftpd",
                    "version": match.group(1) if match else None,
                    "banner": banner_str,
                    "metadata": {"syst_response": syst_str}
                }
            elif "pure-ftpd" in banner_str.lower():
                match = re.search(r"Pure-FTPd\s+([0-9.]+)", banner_str, re.I)
                return {
                    "service_name": "ftp",
                    "product": "pure-ftpd",
                    "version": match.group(1) if match else None,
                    "banner": banner_str,
                    "metadata": {"syst_response": syst_str}
                }
            elif "microsoft" in banner_str.lower() or "iis" in banner_str.lower():
                return {
                    "service_name": "ftp",
                    "product": "microsoft_ftp",
                    "version": None,
                    "banner": banner_str,
                    "metadata": {"syst_response": syst_str}
                }
        except Exception:
            pass
        return None

    async def _probe_smtp(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Probes SMTP service with EHLO/HELP commands."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.write(b"EHLO aegis-scanner\r\n")
            await writer.drain()
            ehlo_response = await asyncio.wait_for(reader.read(2048), timeout=2.0)
            writer.write(b"HELP\r\n")
            await writer.drain()
            help_response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            banner_str = banner.decode("utf-8", errors="ignore").strip()
            ehlo_str = ehlo_response.decode("utf-8", errors="ignore")

            # Detect SMTP server
            if "postfix" in banner_str.lower():
                match = re.search(r"Postfix\s+([0-9.]+)", banner_str, re.I)
                return {
                    "service_name": "smtp",
                    "product": "postfix",
                    "version": match.group(1) if match else None,
                    "banner": banner_str,
                    "metadata": {"ehlo_features": ehlo_str.count("250-")}
                }
            elif "exim" in banner_str.lower():
                match = re.search(r"Exim\s+([0-9.]+)", banner_str, re.I)
                return {
                    "service_name": "smtp",
                    "product": "exim",
                    "version": match.group(1) if match else None,
                    "banner": banner_str,
                    "metadata": {"ehlo_features": ehlo_str.count("250-")}
                }
            elif "sendmail" in banner_str.lower():
                match = re.search(r"Sendmail\s+([0-9.]+)", banner_str, re.I)
                return {
                    "service_name": "smtp",
                    "product": "sendmail",
                    "version": match.group(1) if match else None,
                    "banner": banner_str,
                    "metadata": {"ehlo_features": ehlo_str.count("250-")}
                }
            elif "microsoft" in banner_str.lower() or "exchange" in banner_str.lower():
                return {
                    "service_name": "smtp",
                    "product": "microsoft_smtp",
                    "version": None,
                    "banner": banner_str,
                    "metadata": {"ehlo_features": ehlo_str.count("250-")}
                }
        except Exception:
            pass
        return None

    async def _probe_dns(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Probes DNS service with version.bind query."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            # DNS query for version.bind CH TXT
            query = b"\x00\x1c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03"
            writer.write(query)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            response_str = response.decode("utf-8", errors="ignore")
            # BIND version usually in the response
            if "bind" in response_str.lower():
                match = re.search(r"([0-9.]+[a-zA-Z0-9.-]*)", response_str)
                return {
                    "service_name": "dns",
                    "product": "bind",
                    "version": match.group(1) if match else None,
                    "banner": response_str,
                    "metadata": {"dns_protocol": "tcp"}
                }
        except Exception:
            pass
        return None

    async def _probe_mysql(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Probes MySQL service via handshake analysis."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            handshake = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            if len(handshake) > 4:
                handshake_str = handshake.decode("utf-8", errors="ignore")
                # MySQL handshake contains version info
                if "mysql" in handshake_str.lower() or "mariadb" in handshake_str.lower():
                    is_mariadb = "mariadb" in handshake_str.lower()
                    match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9]+)?)", handshake_str)
                    version = match.group(1) if match else None
                    return {
                        "service_name": "mysql",
                        "product": "mariadb" if is_mariadb else "mysql",
                        "version": version,
                        "banner": handshake_str,
                        "metadata": {"mysql_protocol": "native"}
                    }
        except Exception:
            pass
        return None

    async def _probe_postgresql(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Probes PostgreSQL service via startup packet."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            # Send PostgreSQL startup packet
            startup = b"\x00\x00\x00\x08\x04\xd2\x16\x2fuser\x00aegis\x00database\x00postgres\x00"
            writer.write(startup)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            response_str = response.decode("utf-8", errors="ignore")
            if "postgresql" in response_str.lower() or "postgres" in response_str.lower():
                match = re.search(r"PostgreSQL\s+([0-9.]+)", response_str, re.I)
                return {
                    "service_name": "postgresql",
                    "product": "postgresql",
                    "version": match.group(1) if match else None,
                    "banner": response_str,
                    "metadata": {"postgresql_protocol": "3.0"}
                }
        except Exception:
            pass
        return None

    async def _probe_redis(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Probes Redis service with PING command."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            writer.write(b"PING\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            response_str = response.decode("utf-8", errors="ignore").strip()
            if "+PONG" in response_str or "redis" in response_str.lower():
                # Try to get version with INFO
                reader2, writer2 = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.config.connect_timeout
                )
                writer2.write(b"INFO server\r\n")
                await writer2.drain()
                info_response = await asyncio.wait_for(reader2.read(4096), timeout=2.0)
                writer2.close()
                await writer2.wait_closed()

                info_str = info_response.decode("utf-8", errors="ignore")
                match = re.search(r"redis_version:([0-9.]+)", info_str)
                version = match.group(1) if match else None
                return {
                    "service_name": "redis",
                    "product": "redis",
                    "version": version,
                    "banner": response_str,
                    "metadata": {"redis_info": "authenticated" if "NOAUTH" not in info_str else "unauthenticated"}
                }
        except Exception:
            pass
        return None

    async def _probe_mongodb(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Probes MongoDB service with isMaster command."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )
            # MongoDB isMaster command
            ismaster_cmd = b"\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00isMaster\x00\x01\x00\x00\x00\x00\x00\x00\x00\xf0\x03\x00\x00"
            writer.write(ismaster_cmd)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            response_str = response.decode("utf-8", errors="ignore")
            if "mongodb" in response_str.lower() or "version" in response_str.lower():
                match = re.search(r"version[:\s]+([0-9.]+)", response_str, re.I)
                version = match.group(1) if match else None
                return {
                    "service_name": "mongodb",
                    "product": "mongodb",
                    "version": version,
                    "banner": response_str,
                    "metadata": {"mongodb_protocol": "wire_protocol"}
                }
        except Exception:
            pass
        return None

    async def _check_tls(self, host: str, port: int) -> Dict[str, Any]:
        """Attempts a TLS handshake to determine TLS parameters and certificate info."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=self.config.connect_timeout
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            cipher = ssl_obj.cipher() if ssl_obj else None
            version = ssl_obj.version() if ssl_obj else None
            cert = ssl_obj.getpeercert(binary_form=False) if ssl_obj else {}
            
            writer.close()
            await writer.wait_closed()

            return {
                "tls_enabled": True,
                "tls_version": version,
                "cipher": cipher[0] if cipher else None,
                "cert_subject": cert.get("subject") if cert else None
            }
        except Exception:
            return {"tls_enabled": False}

    async def _probe_http(self, host: str, port: int, use_tls: bool) -> Optional[Dict[str, Any]]:
        """Sends an HTTP GET request to detect Web server banners and technologies."""
        protocol = "https" if use_tls else "http"
        url = f"{protocol}://{host}:{port}/"
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.config.read_timeout) as client:
                resp = await client.get(url, follow_redirects=True)
                server_hdr = resp.headers.get("server", "")
                powered_by = resp.headers.get("x-powered-by", "")

                title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                title = title_match.group(1).strip() if title_match else None

                product, version = self._parse_http_server(server_hdr)

                return {
                    "is_http": True,
                    "status_code": resp.status_code,
                    "server_banner": server_hdr or powered_by or None,
                    "product": product,
                    "version": version,
                    "title": title,
                    "powered_by": powered_by or None,
                    "headers": dict(resp.headers)
                }
        except Exception:
            return None

    async def _grab_raw_banner(self, host: str, port: int) -> Optional[str]:
        """Connects and listens for immediate greeting banner or sends a probe."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.connect_timeout
            )

            # Wait for greeting banner
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            except asyncio.TimeoutError:
                # If quiet, send a probe newline
                writer.write(b"\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.5)

            writer.close()
            await writer.wait_closed()
            return data.decode("utf-8", errors="ignore").strip() if data else None
        except Exception:
            return None

    def _parse_http_server(self, server_str: str) -> Tuple[Optional[str], Optional[str]]:
        """Parses Server header such as 'Apache/2.4.49 (Unix)' into ('apache', '2.4.49')."""
        if not server_str:
            return None, None

        # Matches format: Name/1.2.3
        match = re.search(r"([a-zA-Z0-9_-]+)/([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-zA-Z0-9._-]*)", server_str)
        if match:
            return match.group(1).lower(), match.group(2)
        
        return server_str.split()[0].lower(), None

    def _analyze_banner(self, port: int, banner: Optional[str]) -> Tuple[str, Optional[str], Optional[str]]:
        """Infers service name, product, and version from port and raw banner."""
        if not banner:
            default_map = {
                21: ("ftp", "ftp", None),
                22: ("ssh", "ssh", None),
                23: ("telnet", "telnet", None),
                25: ("smtp", "smtp", None),
                53: ("dns", "dns", None),
                80: ("http", "http", None),
                443: ("https", "https", None),
                445: ("smb", "smb", None),
                1433: ("mssql", "microsoft_sql_server", None),
                1521: ("oracle", "oracle_database", None),
                3306: ("mysql", "mysql", None),
                3389: ("rdp", "ms-wbt-server", None),
                5432: ("postgresql", "postgresql", None),
                6379: ("redis", "redis", None),
                27017: ("mongodb", "mongodb", None),
            }
            return default_map.get(port, ("unknown", None, None))

        # SSH banners e.g. SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
        ssh_match = re.search(r"SSH-[\d.]+-OpenSSH_([0-9a-zA-Z._-]+)", banner)
        if ssh_match:
            return "ssh", "openssh", ssh_match.group(1)

        # FTP banners e.g. 220 ProFTPD 1.3.5
        ftp_match = re.search(r"(?:ProFTPD|vsftpd|Pure-FTPd)\s+([0-9a-zA-Z._-]+)", banner, re.I)
        if ftp_match:
            prod = "vsftpd" if "vsftpd" in banner.lower() else "proftpd"
            return "ftp", prod, ftp_match.group(1)

        # Redis
        if "redis" in banner.lower() or "-ERR unknown command" in banner:
            return "redis", "redis", None

        # MySQL / MariaDB
        if "mysql" in banner.lower() or "mariadb" in banner.lower() or "\x00\x00\x00\x0a" in banner:
            ver_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9]+)?)", banner)
            ver = ver_match.group(1) if ver_match else None
            prod = "mariadb" if "mariadb" in banner.lower() else "mysql"
            return "mysql", prod, ver

        return "unknown", None, None
