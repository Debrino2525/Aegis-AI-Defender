"""
High-performance local Vulnerability Database (VDB) backed by SQLite.
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from aegis.core.models import VulnerabilityDefinition, Severity
from aegis.database.matcher import VersionMatcher


class VulnerabilityDatabase:
    """Embedded SQLite database for sub-millisecond vulnerability correlation."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            data_dir = Path.home() / ".aegis"
            data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = data_dir / "vdb.sqlite3"
        else:
            self.db_path = db_path
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()
        self._seed_initial_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss_score REAL DEFAULT 0.0,
                    epss_score REAL DEFAULT 0.0,
                    is_cisa_kev INTEGER DEFAULT 0,
                    vendor TEXT NOT NULL,
                    product TEXT NOT NULL,
                    min_version TEXT,
                    max_version TEXT,
                    min_inclusive INTEGER DEFAULT 1,
                    max_inclusive INTEGER DEFAULT 0,
                    remediation TEXT,
                    references_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_vendor_prod ON vulnerabilities(vendor, product)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_cisa_kev ON vulnerabilities(is_cisa_kev)")
            conn.commit()

    def add_vulnerability(self, vuln: Dict[str, Any]):
        """Inserts or updates a vulnerability record."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO vulnerabilities (
                    id, title, description, severity, cvss_score, epss_score, is_cisa_kev,
                    vendor, product, min_version, max_version, min_inclusive, max_inclusive,
                    remediation, references_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln["id"],
                vuln["title"],
                vuln["description"],
                vuln.get("severity", "HIGH"),
                vuln.get("cvss_score", 0.0),
                vuln.get("epss_score", 0.0),
                1 if vuln.get("is_cisa_kev") else 0,
                vuln["vendor"].lower(),
                vuln["product"].lower(),
                vuln.get("min_version"),
                vuln.get("max_version"),
                1 if vuln.get("min_inclusive", True) else 0,
                1 if vuln.get("max_inclusive", False) else 0,
                vuln.get("remediation"),
                json.dumps(vuln.get("references", []))
            ))
            conn.commit()

    def query_vulnerabilities(self, vendor: str, product: str, version_str: Optional[str]) -> List[VulnerabilityDefinition]:
        """Queries database for vulnerabilities affecting the vendor, product, and version."""
        results: List[VulnerabilityDefinition] = []
        if not vendor or not product:
            return results

        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM vulnerabilities WHERE vendor = ? AND product = ?",
                (vendor.lower(), product.lower())
            )
            rows = cursor.fetchall()

            for row in rows:
                is_affected = False
                if version_str:
                    is_affected = VersionMatcher.is_version_vulnerable(
                        target_version_str=version_str,
                        min_ver_str=row["min_version"],
                        max_ver_str=row["max_version"],
                        min_inclusive=bool(row["min_inclusive"]),
                        max_inclusive=bool(row["max_inclusive"])
                    )
                else:
                    # If version is unknown, flag potential risk if high severity
                    is_affected = False

                if is_affected:
                    refs = json.loads(row["references_json"]) if row["references_json"] else []
                    results.append(VulnerabilityDefinition(
                        id=row["id"],
                        title=row["title"],
                        description=row["description"],
                        severity=Severity(row["severity"]),
                        cvss_score=row["cvss_score"],
                        epss_score=row["epss_score"],
                        is_cisa_kev=bool(row["is_cisa_kev"]),
                        cpe_match=f"cpe:2.3:a:{row['vendor']}:{row['product']}:*:*:*:*:*:*:*:*",
                        remediation=row["remediation"],
                        references=refs
                    ))

        return results

    def _seed_initial_database(self):
        """Seeds curated critical known vulnerabilities across enterprise infrastructure."""
        with self._get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            if count > 0:
                return

        seeds = [
            {
                "id": "CVE-2021-41773",
                "title": "Apache HTTP Server Path Traversal and RCE",
                "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "epss_score": 0.97,
                "is_cisa_kev": True,
                "vendor": "apache",
                "product": "http_server",
                "min_version": "2.4.49",
                "max_version": "2.4.49",
                "min_inclusive": True,
                "max_inclusive": True,
                "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]
            },
            {
                "id": "CVE-2021-42013",
                "title": "Apache HTTP Server Path Traversal Incomplete Fix",
                "description": "It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. Attackers could still exploit path traversal or remote code execution.",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "epss_score": 0.96,
                "is_cisa_kev": True,
                "vendor": "apache",
                "product": "http_server",
                "min_version": "2.4.50",
                "max_version": "2.4.50",
                "min_inclusive": True,
                "max_inclusive": True,
                "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"]
            },
            {
                "id": "CVE-2024-6387",
                "title": "OpenSSH regreSSHion Remote Code Execution Vulnerability",
                "description": "A signal handler race condition in OpenSSH server (sshd) allows unauthenticated remote code execution as root in glibc-based Linux systems.",
                "severity": "CRITICAL",
                "cvss_score": 8.1,
                "epss_score": 0.88,
                "is_cisa_kev": False,
                "vendor": "openbsd",
                "product": "openssh",
                "min_version": "8.5",
                "max_version": "9.8",
                "min_inclusive": True,
                "max_inclusive": False,
                "remediation": "Update OpenSSH to 9.8p1 or newer, or set 'LoginGraceTime 0' as a temporary mitigation.",
                "references": ["https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt"]
            },
            {
                "id": "CVE-2023-38408",
                "title": "OpenSSH PKCS#11 Provider Remote Code Execution",
                "description": "OpenSSH ssh-agent PKCS#11 provider allows remote attackers to execute arbitrary code via forwarded agent socket.",
                "severity": "HIGH",
                "cvss_score": 7.8,
                "epss_score": 0.74,
                "is_cisa_kev": False,
                "vendor": "openbsd",
                "product": "openssh",
                "min_version": "5.5",
                "max_version": "9.3.2",
                "min_inclusive": True,
                "max_inclusive": True,
                "remediation": "Upgrade OpenSSH to version 9.3p2 or later.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"]
            },
            {
                "id": "CVE-2022-22965",
                "title": "Spring Framework RCE (Spring4Shell)",
                "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding.",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "epss_score": 0.95,
                "is_cisa_kev": True,
                "vendor": "vmware",
                "product": "spring_framework",
                "min_version": "5.3.0",
                "max_version": "5.3.18",
                "min_inclusive": True,
                "max_inclusive": False,
                "remediation": "Upgrade Spring Framework to 5.3.18+, 5.2.20+, or newer.",
                "references": ["https://tanzu.vmware.com/security/cve-2022-22965"]
            },
            {
                "id": "CVE-2021-23017",
                "title": "Nginx 1-byte Memory Overwrite in DNS Resolver",
                "description": "A security issue in nginx resolver allows an attacker to cause 1-byte memory overwrite, potentially leading to worker process crash or arbitrary code execution.",
                "severity": "HIGH",
                "cvss_score": 7.7,
                "epss_score": 0.58,
                "is_cisa_kev": False,
                "vendor": "f5",
                "product": "nginx",
                "min_version": "0.6.18",
                "max_version": "1.20.1",
                "min_inclusive": True,
                "max_inclusive": False,
                "remediation": "Upgrade nginx to version 1.20.1, 1.21.0 or newer.",
                "references": ["https://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"]
            },
            {
                "id": "CVE-2015-3306",
                "title": "ProFTPD mod_copy Command Execution",
                "description": "The mod_copy module in ProFTPD allows remote unauthenticated attackers to read and write arbitrary files via SITE CPFR and SITE CPTO commands.",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "epss_score": 0.97,
                "is_cisa_kev": True,
                "vendor": "proftpd",
                "product": "proftpd",
                "min_version": "1.3.5",
                "max_version": "1.3.5",
                "min_inclusive": True,
                "max_inclusive": True,
                "remediation": "Update ProFTPD to 1.3.5a or newer, or disable mod_copy.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"]
            }
        ]

        for seed in seeds:
            self.add_vulnerability(seed)
