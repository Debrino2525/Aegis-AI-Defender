"""
Aegis AI — Deduplication, Rate Limiting & Flap Damping Engine.
Prevents notification floods, denial-of-wallet, and analyst fatigue by enforcing
token-bucket rate limiting and sliding-window fingerprint deduplication.
"""

import time
from typing import Dict, Tuple, Optional
from collections import defaultdict


class FlapDamper:
    """
    Sliding-window deduplication and token-bucket rate limiter.
    Ensures security teams receive instant initial alerts, but suppresses subsequent
    identical events within a configurable dampening window (default 15 minutes).
    """

    def __init__(self, flap_window_seconds: int = 900, max_alerts_per_window: int = 3):
        self.flap_window = flap_window_seconds
        self.max_alerts = max_alerts_per_window
        # Key: fingerprint -> (first_seen, last_seen, count, last_dispatched_at)
        self._history: Dict[str, Dict[str, float]] = {}

    def should_dispatch(self, fingerprint: str) -> Tuple[bool, str, int]:
        """
        Determines whether a critical alert should trigger external dispatch.
        Returns: (allow_dispatch, reason, current_occurrence_count)
        """
        now = time.time()
        record = self._history.get(fingerprint)

        if not record:
            # First occurrence
            self._history[fingerprint] = {
                "first_seen": now,
                "last_seen": now,
                "count": 1,
                "last_dispatched": now,
                "dispatches_in_window": 1,
            }
            return True, "First occurrence; immediate dispatch allowed", 1

        # Check if previous window has expired
        time_since_first = now - record["first_seen"]
        if time_since_first > self.flap_window:
            # Reset window
            record["first_seen"] = now
            record["last_seen"] = now
            record["count"] = 1
            record["last_dispatched"] = now
            record["dispatches_in_window"] = 1
            return True, "Flap window reset; dispatch allowed", 1

        # Within existing window
        record["last_seen"] = now
        record["count"] += 1

        # Rate limit check: Cap dispatches per window
        if record["dispatches_in_window"] >= self.max_alerts:
            suppressed_count = int(record["count"])
            return False, f"Rate limited: exceeded {self.max_alerts} dispatches in {self.flap_window}s window ({suppressed_count} occurrences)", suppressed_count

        # Minimum interval between dispatches (at least 60s)
        time_since_last_dispatch = now - record["last_dispatched"]
        if time_since_last_dispatch < 60:
            suppressed_count = int(record["count"])
            return False, f"Throttled: minimum 60s inter-alert cooldown active ({suppressed_count} occurrences)", suppressed_count

        record["last_dispatched"] = now
        record["dispatches_in_window"] += 1
        return True, "Dispatch allowed within rate limit threshold", int(record["count"])

    def cleanup_expired(self):
        """Removes records older than 2x the flap window to prevent memory leaks."""
        now = time.time()
        expired_keys = [k for k, v in self._history.items() if (now - v["last_seen"]) > (self.flap_window * 2)]
        for k in expired_keys:
            del self._history[k]
