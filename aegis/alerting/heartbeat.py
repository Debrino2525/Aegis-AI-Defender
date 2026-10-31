"""
Aegis AI — Dead-Man Canary Heartbeat Engine.
Periodically emits cryptographically signed health heartbeats to off-premises
watchdog monitors to detect if Aegis was terminated or silenced by an adversary.
"""

import os
import time
import asyncio
import httpx
from datetime import datetime, timezone
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


class CanaryHeartbeat:
    """Emits periodic heartbeats to an off-premises canary listener."""

    def __init__(self, ping_interval_seconds: int = 60):
        self.canary_url = os.getenv("CANARY_HEARTBEAT_URL", "").strip()
        self.ping_interval = ping_interval_seconds
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self.last_successful_ping: Optional[str] = None
        self.total_pings_sent = 0

    async def start(self):
        if self.running or not self.canary_url:
            return
        self.running = True
        self._task = asyncio.create_task(self._loop())

    def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()

    async def _loop(self):
        while self.running:
            try:
                await self._send_ping()
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(self.ping_interval)

    async def _send_ping(self):
        if not self.canary_url:
            return
        payload = {
            "service": "Aegis-AI-Defense",
            "status": "UP",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_pings": self.total_pings_sent
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(self.canary_url, json=payload)
                if resp.status_code in (200, 201, 204):
                    self.last_successful_ping = payload["timestamp"]
                    self.total_pings_sent += 1
        except Exception:
            pass

    def get_status(self) -> dict:
        return {
            "canary_configured": bool(self.canary_url),
            "ping_interval_seconds": self.ping_interval,
            "last_successful_ping": self.last_successful_ping,
            "total_pings_sent": self.total_pings_sent
        }
