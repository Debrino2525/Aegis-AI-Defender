"""Observe / Recommend / Auto. New sites cannot silently Auto."""

from __future__ import annotations

from typing import Optional

OBSERVE = "observe"
RECOMMEND = "recommend"
AUTO = "auto"
MODES = (OBSERVE, RECOMMEND, AUTO)
SITE_DEFAULT_MODE = RECOMMEND
CONSOLE_ASSET = "console"

_RANK = {OBSERVE: 0, RECOMMEND: 1, AUTO: 2}


def normalize_mode(value: Optional[str], default: str = RECOMMEND) -> str:
    text = (value or "").strip().lower()
    if text in MODES:
        return text
    return default


def mode_rank(mode: str) -> int:
    return _RANK.get(normalize_mode(mode), 1)


def clamp_mode(requested: str, ceiling: str) -> str:
    req = normalize_mode(requested)
    cap = normalize_mode(ceiling, default=SITE_DEFAULT_MODE)
    if mode_rank(req) <= mode_rank(cap):
        return req
    return cap


def site_ceiling(site_mode: str, auto_allowed: bool) -> str:
    """Auto is only reachable when the operator armed this site."""
    mode = normalize_mode(site_mode, default=SITE_DEFAULT_MODE)
    if mode == AUTO and not auto_allowed:
        return RECOMMEND
    if mode == AUTO and auto_allowed:
        return AUTO
    return mode


def effective_mode(asset_mode: str, site_mode: str, auto_allowed: bool) -> str:
    return clamp_mode(asset_mode, site_ceiling(site_mode, auto_allowed))


def auto_is_silent_on_new_site(auto_allowed: bool, site_mode: str) -> bool:
    """True when Auto would fire without the site-level arming step."""
    return normalize_mode(site_mode) == AUTO and not auto_allowed
