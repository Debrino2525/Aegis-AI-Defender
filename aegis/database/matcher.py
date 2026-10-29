"""
Software version evaluator and range comparison engine.
Enhanced with comprehensive version normalization for vendor-specific formats.
"""

from typing import Optional
from packaging import version
import re


class VersionMatcher:
    """Accurately checks whether a software version falls within vulnerable ranges."""

    # Vendor-specific version transformation rules
    VERSION_TRANSFORMS = {
        # OpenSSH: 8.9p1 -> 8.9.1, 9.3p2 -> 9.3.2
        r"([0-9]+\.[0-9]+)p([0-9]+)": r"\1.\2",
        # Debian: 2.4.49-1 -> 2.4.49.1
        r"([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)": r"\1.\2",
        # RPM: 2.4.49.el8 -> 2.4.49
        r"([0-9]+\.[0-9]+\.[0-9]+)\.[a-z]+[0-9]*": r"\1",
        # Ubuntu: 2.4.49-3ubuntu0.1 -> 2.4.49
        r"([0-9]+\.[0-9]+\.[0-9]+)-[0-9]+ubuntu[0-9.]*": r"\1",
        # Generic suffixes: 2.4.49a -> 2.4.49.1, 2.4.49beta -> 2.4.49b0
        r"([0-9]+\.[0-9]+\.[0-9]+)([a-z])([0-9]*)": r"\1.\2\3",
        # Remove + suffixes: 1.20.1+ -> 1.20.1
        r"\+": "",
        # Remove ~ suffixes: 1.20.1~ -> 1.20.1
        r"~": "",
    }

    @staticmethod
    def normalize_version(version_str: str) -> str:
        """Normalizes version string to PEP440-compatible format."""
        if not version_str or version_str == "*":
            return version_str

        normalized = version_str.strip().lower()

        # Apply transformation rules
        for pattern, replacement in VersionMatcher.VERSION_TRANSFORMS.items():
            normalized = re.sub(pattern, replacement, normalized)

        # Handle common special cases
        # Remove git hashes
        normalized = re.sub(r"\+[a-f0-9]{7,}", "", normalized)
        # Remove build metadata
        normalized = re.sub(r"\+[0-9]+", "", normalized)

        return normalized

    @staticmethod
    def is_version_vulnerable(
        target_version_str: Optional[str],
        min_ver_str: Optional[str] = None,
        max_ver_str: Optional[str] = None,
        min_inclusive: bool = True,
        max_inclusive: bool = False
    ) -> bool:
        """Determines if target_version is within [min_version, max_version)."""
        if not target_version_str or target_version_str == "*":
            return False

        # Normalize target version
        try:
            target_v = version.parse(VersionMatcher.normalize_version(target_version_str))
        except Exception:
            # If normalization fails, try direct parse
            try:
                target_v = version.parse(target_version_str)
            except Exception:
                return False

        # Check minimum version
        if min_ver_str and min_ver_str != "*":
            try:
                min_v = version.parse(VersionMatcher.normalize_version(min_ver_str))
                if min_inclusive:
                    if target_v < min_v:
                        return False
                else:
                    if target_v <= min_v:
                        return False
            except Exception:
                # If min version can't be parsed, assume it's a match
                pass

        # Check maximum version
        if max_ver_str and max_ver_str != "*":
            try:
                max_v = version.parse(VersionMatcher.normalize_version(max_ver_str))
                if max_inclusive:
                    if target_v > max_v:
                        return False
                else:
                    if target_v >= max_v:
                        return False
            except Exception:
                # If max version can't be parsed, assume it's a match
                pass

        return True
