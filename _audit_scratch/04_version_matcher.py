#!/usr/bin/env python3
"""Part 2G: VersionMatcher.normalize_version on 25+ real-world strings."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "04_version_matcher.json"

from packaging import version as pkg_version
from aegis.database.matcher import VersionMatcher

INPUTS = [
    "8.9p1",
    "9.3p2",
    "9.8p1",
    "OpenSSH_8.9p1",
    "2.4.49",
    "2.4.49-1",
    "2.4.52-1ubuntu4.8",
    "1.18.0-0ubuntu1.4",
    "1.1.1f-1ubuntu2.22",
    "1.1.1w",
    "8.0.36-log",
    "8.0.36",
    "10.11.6-MariaDB",
    "10.11.6",
    "1.3.5",
    "1.3.5a",
    "3.7.10",
    "2.4.49.el8",
    "2.4.57-1.el9",
    "1.21.6-1.el8",
    "9.2p1 Debian-2+deb12u3",
    "9.2p1",
    "1.18.0-2+deb12u3",
    "2.4.62-1~deb12u1",
    "10.0",  # IIS
    "10.0.17763",
    "8.0.36+",
    "1.20.1~",
    "1.24.0",
    "11.4.0",
    "*",
    "",
    "deb12u3",
    "1ubuntu2.22",
]


def parses(s: str) -> bool:
    if not s or s == "*":
        return False
    try:
        pkg_version.parse(s)
        return True
    except Exception:
        return False


rows = []
for raw in INPUTS:
    norm = VersionMatcher.normalize_version(raw)
    rows.append({
        "input": raw,
        "normalized": norm,
        "parses_input": parses(raw),
        "parses_normalized": parses(norm),
    })

# Explicit Debian-before-Ubuntu demonstration
ubuntu_in = "2.4.49-3ubuntu0.1"
debian_rule = r"([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)"
ubuntu_rule = r"([0-9]+\.[0-9]+\.[0-9]+)-[0-9]+ubuntu[0-9.]*"
import re
after_debian_first = re.sub(debian_rule, r"\1.\2", ubuntu_in)
after_ubuntu_on_original = re.sub(ubuntu_rule, r"\1", ubuntu_in)

payload = {
    "rule_order": list(VersionMatcher.VERSION_TRANSFORMS.keys()),
    "debian_before_ubuntu": True,
    "ubuntu_input": ubuntu_in,
    "after_debian_rule_alone": after_debian_first,
    "after_ubuntu_rule_alone": after_ubuntu_on_original,
    "actual_normalize": VersionMatcher.normalize_version(ubuntu_in),
    "table": rows,
}
OUT.write_text(json.dumps(payload, indent=2))
print(json.dumps(payload, indent=2))
