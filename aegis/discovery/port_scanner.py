"""
High-concurrency asynchronous TCP/UDP port scanner.
Enhanced with UDP scanning capability.
"""

import asyncio
import socket
from typing import List, Tuple, Set
from aegis.core.config import ScanConfig


class AsyncPortScanner:
    """Asynchronous port scanner capable of scanning hundreds of ports concurrently."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.concurrency)

    async def _probe_port(self, host: str, port: int) -> Tuple[int, bool]:
        """Probes a single TCP port using non-blocking connection."""
        async with self.semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.config.connect_timeout)
                writer.close()
                await writer.wait_closed()
                return port, True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return port, False

    async def _probe_udp_port(self, host: str, port: int) -> Tuple[int, bool]:
        """Probes a single UDP port with timeout."""
        async with self.semaphore:
            try:
                # Create UDP socket
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.config.connect_timeout)

                # Send empty probe packet
                await loop.sock_sendto(sock, b"\x00", (host, port))

                # Try to receive response
                try:
                    data, _ = await loop.sock_recvfrom(sock, 1024)
                    sock.close()
                    return port, True
                except socket.timeout:
                    # No response could mean filtered or no service
                    # For UDP, we mark as potentially open if no ICMP error
                    sock.close()
                    return port, False
            except Exception:
                return port, False

    async def scan_target(self, host: str, ports: List[int], scan_udp: bool = False) -> List[int]:
        """Scans the specified list of ports on the target host and returns open ports."""
        tasks = [self._probe_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports: List[int] = []
        for res in results:
            if isinstance(res, tuple):
                port, is_open = res
                if is_open:
                    open_ports.append(port)

        return sorted(open_ports)

    async def scan_udp(self, host: str, ports: List[int]) -> List[int]:
        """Scans UDP ports and returns potentially open ports."""
        # Common UDP ports to scan
        if not ports:
            ports = [53, 67, 68, 69, 123, 161, 162, 514, 520, 631, 1194, 1701, 4500]

        tasks = [self._probe_udp_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports: List[int] = []
        for res in results:
            if isinstance(res, tuple):
                port, is_open = res
                if is_open:
                    open_ports.append(port)

        return sorted(open_ports)
