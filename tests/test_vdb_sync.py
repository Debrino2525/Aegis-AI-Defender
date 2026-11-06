"""
Regression tests for vulnerability-database feed ingestion.

Threat-feed sync used to erase curated version ranges. After a CISA KEV import,
patched Apache builds matched CVE-2021-41773. After an NVD import, OpenSSH
scans stopped reporting CVE-2024-6387 because the row was rewritten with an
empty range under the search keyword instead of openbsd/openssh.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis.database.db import VulnerabilityDatabase
from aegis.database.matcher import VersionMatcher
from aegis.database.sync import ThreatFeedSync


def _ids(db, vendor, product, version):
    return sorted(v.id for v in db.query_vulnerabilities(vendor, product, version))


def _feed_row(cve_id, vendor, product, min_version=None, max_version=None, **extra):
    row = {
        "id": cve_id,
        "title": cve_id,
        "description": "feed update",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "epss_score": 0.5,
        "is_cisa_kev": False,
        "vendor": vendor,
        "product": product,
        "min_version": min_version,
        "max_version": max_version,
        "remediation": "Apply the vendor patch.",
        "references": [],
    }
    row.update(extra)
    return row


def test_missing_bounds_do_not_match_every_version():
    assert VersionMatcher.is_version_vulnerable("2.4.62", None, None) is False
    assert VersionMatcher.is_version_vulnerable("2.4.62", "*", "*") is False
    # A one-sided upper bound still describes a real range.
    assert VersionMatcher.is_version_vulnerable(
        "1.0", None, "2.0", max_inclusive=False
    ) is True
    assert VersionMatcher.is_version_vulnerable(
        "2.0", None, "2.0", max_inclusive=False
    ) is False
    print("[+] test_missing_bounds_do_not_match_every_version: PASSED")


def test_kev_sync_does_not_flag_patched_apache():
    with tempfile.TemporaryDirectory() as tmp:
        db = VulnerabilityDatabase(Path(tmp) / "vdb.sqlite3")

        assert _ids(db, "apache", "http_server", "2.4.49") == ["CVE-2021-41773"]
        assert _ids(db, "apache", "http_server", "2.4.50") == ["CVE-2021-42013"]
        assert _ids(db, "apache", "http_server", "2.4.62") == []

        # CISA KEV records carry the right product name and no version range.
        for cve_id in ("CVE-2021-41773", "CVE-2021-42013", "CVE-2019-0211"):
            db.add_vulnerability(_feed_row(
                cve_id, "apache", "http_server", is_cisa_kev=True
            ))

        assert _ids(db, "apache", "http_server", "2.4.49") == ["CVE-2021-41773"]
        assert _ids(db, "apache", "http_server", "2.4.50") == ["CVE-2021-42013"]
        assert "CVE-2019-0211" not in _ids(db, "apache", "http_server", "2.4.17")
        assert _ids(db, "apache", "http_server", "2.4.62") == []
        print("[+] test_kev_sync_does_not_flag_patched_apache: PASSED")


def test_nvd_keyword_write_keeps_openssh_detection():
    with tempfile.TemporaryDirectory() as tmp:
        db = VulnerabilityDatabase(Path(tmp) / "vdb.sqlite3")

        db.add_vulnerability(_feed_row(
            "CVE-2024-6387", "openbsd", "openssh",
            min_version="8.5", max_version="9.8",
            min_inclusive=True, max_inclusive=False,
            is_cisa_kev=True, severity="CRITICAL", cvss_score=8.1,
        ))
        # What keyword sync stored when CPE parsing failed: the search word
        # as vendor and product, no range, and the KEV flag cleared.
        db.add_vulnerability(_feed_row(
            "CVE-2024-6387", "openssh", "openssh", is_cisa_kev=False
        ))

        assert "CVE-2024-6387" in _ids(db, "openbsd", "openssh", "9.2")
        assert "CVE-2024-6387" in _ids(db, "openbsd", "openssh", "8.5p1")
        assert "CVE-2024-6387" not in _ids(db, "openbsd", "openssh", "9.8")

        with db._get_connection() as conn:
            row = conn.execute(
                "SELECT vendor, product, is_cisa_kev FROM vulnerabilities WHERE id = ?",
                ("CVE-2024-6387",)
            ).fetchone()
        assert row["vendor"] == "openbsd"
        assert row["product"] == "openssh"
        assert row["is_cisa_kev"] == 1
        print("[+] test_nvd_keyword_write_keeps_openssh_detection: PASSED")


def test_narrower_nvd_slice_does_not_replace_curated_range():
    with tempfile.TemporaryDirectory() as tmp:
        db = VulnerabilityDatabase(Path(tmp) / "vdb.sqlite3")
        # First NVD slice for regreSSHion is OpenSSH < 4.4. The regression
        # window 8.5–9.7 is a later configuration entry.
        db.add_vulnerability(_feed_row(
            "CVE-2024-6387", "openbsd", "openssh",
            min_version=None, max_version="4.4",
            min_inclusive=True, max_inclusive=False,
        ))
        assert "CVE-2024-6387" in _ids(db, "openbsd", "openssh", "9.2")
        assert "CVE-2024-6387" in _ids(db, "openbsd", "openssh", "8.5p1")
        print("[+] test_narrower_nvd_slice_does_not_replace_curated_range: PASSED")


def test_nvd2_criteria_parse_picks_current_product_range():
    with tempfile.TemporaryDirectory() as tmp:
        db = VulnerabilityDatabase(Path(tmp) / "vdb.sqlite3")
        syncer = ThreatFeedSync(db)

        info = syncer._extract_cpe_info({
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "4.4",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "8.6",
                            "versionEndIncluding": "9.8",
                        },
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:a:openbsd:openssh:9.8:*:*:*:*:*:*:*",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*",
                        },
                    ]
                }]
            }]
        })
        assert info["vendor"] == "openbsd"
        assert info["product"] == "openssh"
        assert info["min_version"] == "8.6"
        assert info["max_version"] == "9.8"
        assert info["min_inclusive"] is True
        assert info["max_inclusive"] is True

        # API 1.0 name still works, and underscores are not turned into spaces.
        # A more frequent unrelated product must not steal the first product.
        legacy = syncer._extract_cpe_info({
            "configurations": [{
                "nodes": [
                    {"cpeMatch": [{
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                    }]},
                    {"cpeMatch": [
                        {"vulnerable": True, "criteria": "cpe:2.3:a:oracle:instantis_enterprisetrack:9.0:*:*:*:*:*:*:*"},
                        {"vulnerable": True, "criteria": "cpe:2.3:a:oracle:instantis_enterprisetrack:9.1:*:*:*:*:*:*:*"},
                        {"vulnerable": True, "criteria": "cpe:2.3:a:oracle:instantis_enterprisetrack:9.2:*:*:*:*:*:*:*"},
                    ]},
                ]
            }]
        })
        assert legacy == {
            "vendor": "apache",
            "product": "http_server",
            "min_version": "2.4.49",
            "max_version": "2.4.49",
            "min_inclusive": True,
            "max_inclusive": True,
        }

        # A previously corrupted empty row is filled from the parsed range.
        with db._get_connection() as conn:
            conn.execute(
                """
                UPDATE vulnerabilities
                SET vendor = 'openssh', product = 'openssh',
                    min_version = NULL, max_version = NULL
                WHERE id = 'CVE-2024-6387'
                """
            )
            conn.commit()
        db.add_vulnerability(_feed_row(
            "CVE-2024-6387",
            info["vendor"],
            info["product"],
            min_version=info["min_version"],
            max_version=info["max_version"],
            min_inclusive=info["min_inclusive"],
            max_inclusive=info["max_inclusive"],
        ))
        assert "CVE-2024-6387" in _ids(db, "openbsd", "openssh", "9.2")
        assert "CVE-2024-6387" not in _ids(db, "openbsd", "openssh", "4.3")
        assert "CVE-2024-6387" not in _ids(db, "openbsd", "openssh", "9.9")
        print("[+] test_nvd2_criteria_parse_picks_current_product_range: PASSED")


if __name__ == "__main__":
    test_missing_bounds_do_not_match_every_version()
    test_kev_sync_does_not_flag_patched_apache()
    test_nvd_keyword_write_keeps_openssh_detection()
    test_narrower_nvd_slice_does_not_replace_curated_range()
    test_nvd2_criteria_parse_picks_current_product_range()
    print("\n[=== VDB FEED SYNC TESTS PASSED ===]")
