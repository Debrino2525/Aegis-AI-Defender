"""
Session and bearer authentication for the local Aegis console.

There is no built-in password. Set AEGIS_ADMIN_TOKEN or AEGIS_ADMIN_PASSWORD.
If neither is set, the first start generates ~/.aegis/admin_token and prints it once.
"""

import hmac
import hashlib
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional

from aegis.runtime import aegis_data_dir


def _secret_equal(presented: str, expected: str) -> bool:
    if not expected or presented is None:
        return False
    return hmac.compare_digest(
        hashlib.sha256(presented.encode("utf-8")).digest(),
        hashlib.sha256(expected.encode("utf-8")).digest(),
    )


class ConsoleAuth:
    """Admin gate shared by HTTP routes and WebSockets."""

    COOKIE = "aegis_session"
    SESSION_TTL = 12 * 60 * 60

    def __init__(self):
        self.token = ""
        self.password = ""
        self.generated = False
        self.token_path: Optional[Path] = None
        self.sessions = {}
        self.ready = False

    def bootstrap(self, force: bool = False) -> None:
        if self.ready and not force:
            return
        data_dir = aegis_data_dir()
        self.token_path = data_dir / "admin_token"
        self.password = os.getenv("AEGIS_ADMIN_PASSWORD", "").strip()
        env_token = os.getenv("AEGIS_ADMIN_TOKEN", "").strip()
        self.generated = False
        self.token = ""

        if env_token:
            self.token = env_token
        elif self.token_path.is_file() and not self.password:
            stored = self.token_path.read_text(encoding="utf-8").strip()
            if stored:
                self.token = stored
            else:
                self._generate()
        elif self.password:
            self.token = ""
        else:
            self._generate()
        self.ready = True

    def _generate(self) -> None:
        self.token = secrets.token_urlsafe(32)
        self.token_path.parent.mkdir(parents=True, exist_ok=True)
        self.token_path.write_text(self.token + "\n", encoding="utf-8")
        try:
            os.chmod(self.token_path, 0o600)
        except OSError:
            pass
        self.generated = True
        print(
            "[AEGIS] WARNING: No AEGIS_ADMIN_TOKEN or AEGIS_ADMIN_PASSWORD is set.\n"
            f"[AEGIS] Generated an admin token at {self.token_path} (mode 600).\n"
            "[AEGIS] This token is shown once. Set AEGIS_ADMIN_TOKEN to choose your own.\n"
            f"[AEGIS] Admin token: {self.token}",
            file=sys.stderr,
        )

    def check_secret(self, presented: str) -> bool:
        if not self.ready:
            self.bootstrap()
        presented = (presented or "").strip()
        if not presented:
            return False
        if self.token and _secret_equal(presented, self.token):
            return True
        if self.password and _secret_equal(presented, self.password):
            return True
        return False

    def issue_session(self) -> str:
        sid = secrets.token_urlsafe(32)
        self.sessions[sid] = time.time() + self.SESSION_TTL
        return sid

    def session_valid(self, sid: str) -> bool:
        if not sid or sid not in self.sessions:
            return False
        if time.time() > self.sessions[sid]:
            self.sessions.pop(sid, None)
            return False
        return True

    def drop_session(self, sid: Optional[str]) -> None:
        if sid:
            self.sessions.pop(sid, None)

    def authorized(
        self,
        authorization: Optional[str] = None,
        cookie: Optional[str] = None,
        query_token: Optional[str] = None,
    ) -> bool:
        if not self.ready:
            self.bootstrap()
        if authorization:
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "bearer" and self.check_secret(value.strip()):
                return True
        if cookie and self.session_valid(cookie):
            return True
        # Query tokens are for WebSocket clients that cannot set headers.
        if query_token and self.check_secret(query_token):
            return True
        return False


console_auth = ConsoleAuth()
