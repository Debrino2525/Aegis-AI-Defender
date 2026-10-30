#!/usr/bin/env python3
"""Part 2H: ServiceFingerprinter on HTTP/SSH/FTP/SMTP/MySQL/Redis fake servers on NON-standard ports."""
import asyncio
import json
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "06_fingerprint.json"

from aegis.core.config import ScanConfig
from aegis.discovery.fingerprint import ServiceFingerprinter


class FakeServer:
    def __init__(self, name, port, banner: bytes, extra_handler=None):
        self.name = name
        self.port = port
        self.banner = banner
        self.extra_handler = extra_handler
        self.server = None

    async def handle(self, reader, writer):
        try:
            if self.banner:
                writer.write(self.banner)
                await writer.drain()
            if self.extra_handler:
                await self.extra_handler(reader, writer)
            else:
                try:
                    await asyncio.wait_for(reader.read(256), timeout=0.8)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", self.port)

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


async def redis_handler(reader, writer):
    data = await asyncio.wait_for(reader.read(256), timeout=1.0)
    if b"PING" in data:
        writer.write(b"+PONG\r\n")
        await writer.drain()
        try:
            data2 = await asyncio.wait_for(reader.read(256), timeout=0.5)
        except Exception:
            data2 = b""
    # INFO handled on a second connection by the probe


async def http_handler(reader, writer):
    try:
        await asyncio.wait_for(reader.read(1024), timeout=1.0)
    except Exception:
        pass
    body = b"<html><title>fake</title></html>"
    hdr = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    writer.write(hdr + body)
    await writer.drain()


async def ftp_handler(reader, writer):
    # banner already sent
    try:
        cmd = await asyncio.wait_for(reader.read(256), timeout=1.0)
        if b"SYST" in cmd:
            writer.write(b"215 UNIX Type: L8\r\n")
            await writer.drain()
    except Exception:
        pass


async def smtp_handler(reader, writer):
    try:
        cmd = await asyncio.wait_for(reader.read(512), timeout=1.0)
        if b"EHLO" in cmd or b"HELO" in cmd:
            writer.write(b"250-fake.local\r\n250-PIPELINING\r\n250 HELP\r\n")
            await writer.drain()
        cmd2 = await asyncio.wait_for(reader.read(256), timeout=1.0)
        if b"HELP" in cmd2:
            writer.write(b"214-Help\r\n214 End\r\n")
            await writer.drain()
    except Exception:
        pass


async def main():
    # Non-standard ports, well away from 22/21/25/80/443/3306/6379
    servers = [
        FakeServer("http", 18080, b"", extra_handler=http_handler),
        FakeServer("ssh", 18022, b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-0ubuntu0.1\r\n"),
        FakeServer("ftp", 18021, b"220 ProFTPD 1.3.8 Server (Debian) [::ffff:127.0.0.1]\r\n", extra_handler=ftp_handler),
        FakeServer("smtp", 18025, b"220 mail.example.com ESMTP Postfix 3.7.10\r\n", extra_handler=smtp_handler),
        FakeServer("mysql", 18036, b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00" + b"\x00" * 40),
        FakeServer("redis", 18079, b"", extra_handler=redis_handler),
    ]
    for s in servers:
        await s.start()

    cfg = ScanConfig(target="127.0.0.1", connect_timeout=2.0, read_timeout=2.0)
    fp = ServiceFingerprinter(cfg)
    results = []
    for s in servers:
        info = await fp.fingerprint("127.0.0.1", s.port)
        results.append({
            "intended": s.name,
            "port": s.port,
            "service_name": info.service_name,
            "product": info.product,
            "version": info.version,
            "banner": (info.banner or "")[:180],
            "tls": info.tls,
            "identified_as_intended": (
                (s.name == "http" and info.service_name in ("http", "https"))
                or (s.name == "ssh" and info.product == "openssh")
                or (s.name == "ftp" and info.product in ("proftpd", "vsftpd", "pure-ftpd"))
                or (s.name == "smtp" and info.product in ("postfix", "exim", "sendmail"))
                or (s.name == "mysql" and info.product in ("mysql", "mariadb"))
                or (s.name == "redis" and info.product == "redis")
            ),
        })

    # Control: same banners on STANDARD ports
    std = [
        FakeServer("ssh_std", 22, b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-0ubuntu0.1\r\n"),
        FakeServer("ftp_std", 21, b"220 ProFTPD 1.3.8 Server\r\n", extra_handler=ftp_handler),
        FakeServer("smtp_std", 25, b"220 mail ESMTP Postfix 3.7.10\r\n", extra_handler=smtp_handler),
        FakeServer("mysql_std", 3306, b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00" + b"\x00" * 40),
        FakeServer("redis_std", 6379, b"", extra_handler=redis_handler),
        FakeServer("http_std", 8080, b"", extra_handler=http_handler),
    ]
    std_results = []
    for s in std:
        try:
            await s.start()
            info = await fp.fingerprint("127.0.0.1", s.port)
            std_results.append({
                "intended": s.name,
                "port": s.port,
                "service_name": info.service_name,
                "product": info.product,
                "version": info.version,
                "banner": (info.banner or "")[:180],
                "tls": info.tls,
            })
            await s.stop()
        except OSError as e:
            std_results.append({"intended": s.name, "port": s.port, "error": str(e)})

    for s in servers:
        await s.stop()

    payload = {"nonstandard": results, "standard_controls": std_results}
    OUT.write_text(json.dumps(payload, indent=2, default=str))
    print(json.dumps(payload, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
