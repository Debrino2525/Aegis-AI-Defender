"""ProFTPD banner versions must keep the patch letter that distinguishes the KEV fix."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis.database.db import VulnerabilityDatabase
from aegis.discovery.fingerprint import parse_proftpd_version


def test_patched_proftpd_is_not_the_kev_release():
    patched_banner = "220 ProFTPD 1.3.5a Server (Debian) [::ffff:10.0.0.5]"
    vulnerable_banner = "220 ProFTPD 1.3.5 Server (Debian) [::ffff:10.0.0.5]"

    patched = parse_proftpd_version(patched_banner)
    vulnerable = parse_proftpd_version(vulnerable_banner)
    assert patched == "1.3.5a", patched
    assert vulnerable == "1.3.5", vulnerable

    with tempfile.TemporaryDirectory() as tmp:
        db = VulnerabilityDatabase(Path(tmp) / "vdb.sqlite3")
        patched_hits = db.query_vulnerabilities("proftpd", "proftpd", patched)
        vulnerable_hits = db.query_vulnerabilities("proftpd", "proftpd", vulnerable)

    assert [v.id for v in patched_hits] == []
    assert any(v.id == "CVE-2015-3306" and v.is_cisa_kev for v in vulnerable_hits)
    print("[+] test_patched_proftpd_is_not_the_kev_release: PASSED")


if __name__ == "__main__":
    test_patched_proftpd_is_not_the_kev_release()
