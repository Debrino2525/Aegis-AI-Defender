"""
Target URL and Hostname Normalization Utility for Aegis.
Extracts clean hostnames and optional custom ports from arbitrary user inputs
including full URLs (http/https), paths, query strings, and host:port pairs.
"""

import urllib.parse
from typing import Tuple, Optional


def normalize_target(raw_target: str) -> Tuple[str, Optional[int]]:
    """
    Normalizes arbitrary target inputs (e.g. URLs, IPs, hostnames with ports/paths)
    into a clean hostname/IP string and an optional extracted port number.

    Examples:
      'http://testphp.vulnweb.com/' -> ('testphp.vulnweb.com', None)
      'https://testphp.vulnweb.com:8443/login?q=1' -> ('testphp.vulnweb.com', 8443)
      'testphp.vulnweb.com/some/path' -> ('testphp.vulnweb.com', None)
      '192.168.1.100:8080' -> ('192.168.1.100', 8080)
      'testphp.vulnweb.com' -> ('testphp.vulnweb.com', None)
    """
    if not raw_target:
        return "", None

    target = raw_target.strip()
    port = None

    if "://" in target:
        try:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or (parsed.netloc.split(":")[0] if parsed.netloc else "")
            if parsed.port:
                port = parsed.port
            return host.strip(), port
        except Exception:
            pass

    # Strip URL fragments, query strings, and path components
    for delim in ("/", "?", "#"):
        if delim in target:
            target = target.split(delim)[0]

    # Handle host:port notation (excluding IPv6 bracketed addresses)
    if ":" in target and not target.startswith("["):
        parts = target.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            target = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

    return target.strip(), port
