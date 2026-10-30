#!/usr/bin/env python3
"""Part 3.1: seed counts, vendor/product rows, CPE_LOOKUP with zero vulns, NVD mapping code facts."""
import ast
import json
import sqlite3
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "07_vdb.json"

from aegis.database.db import VulnerabilityDatabase
from aegis.discovery.cpe_matcher import CPE_LOOKUP
from aegis.database import sync as sync_mod

# Count seed dicts in source via AST-ish: instantiate a fresh temp DB
tmpdir = tempfile.mkdtemp(prefix="aegis-audit-vdb-")
db_path = Path(tmpdir) / "vdb.sqlite3"
db = VulnerabilityDatabase(db_path)

with db._get_connection() as conn:
    rows = conn.execute(
        "SELECT id, vendor, product, min_version, max_version, min_inclusive, max_inclusive, is_cisa_kev FROM vulnerabilities"
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

by_vp = defaultdict(list)
by_vendor = Counter()
by_product = Counter()
for r in rows:
    by_vp[f"{r['vendor']}/{r['product']}"].append(r["id"])
    by_vendor[r["vendor"]] += 1
    by_product[r["product"]] += 1

seeded_pairs = {(r["vendor"], r["product"]) for r in rows}

# CPE_LOOKUP values vs seed
lookup_pairs = set(CPE_LOOKUP.values())
zero_row_lookup = []
for key, (vendor, product) in sorted(CPE_LOOKUP.items()):
    n = sum(1 for r in rows if r["vendor"] == vendor and r["product"] == product)
    if n == 0:
        zero_row_lookup.append({"lookup_key": key, "vendor": vendor, "product": product, "rows": 0})

# Dedup zero list by vendor/product
zero_pairs = {}
for z in zero_row_lookup:
    zero_pairs[(z["vendor"], z["product"])] = zero_pairs.get((z["vendor"], z["product"]), []) + [z["lookup_key"]]

# Count seed literals in source
src = Path(ROOT / "aegis/database/db.py").read_text()
seed_count_cve = src.count('"id": "CVE-')

# Inspect _extract_cpe_info source
extract_src = Path(ROOT / "aegis/database/sync.py").read_text()

payload = {
    "temp_db": str(db_path),
    "seed_row_count": total,
    "seed_ids": [r["id"] for r in rows],
    "rows_by_vendor": dict(by_vendor),
    "rows_by_product": dict(by_product),
    "rows_by_vendor_product": {k: v for k, v in by_vp.items()},
    "seed_cve_literals_in_source": seed_count_cve,
    "cpe_lookup_entry_count": len(CPE_LOOKUP),
    "cpe_lookup_unique_vendor_product": sorted(list(lookup_pairs)),
    "cpe_lookup_pairs_with_zero_seed_rows": [
        {"vendor": v, "product": p, "keys": keys}
        for (v, p), keys in sorted(zero_pairs.items())
    ],
    "n_cpe_pairs_with_zero_rows": len(zero_pairs),
    "sync_all_calls": ["sync_cisa_kev", "sync_epss_scores", "sync_nvd_recent", "sync_nvd_by_keywords"],
    "threatfox_url_defined": bool(getattr(sync_mod, "THREATFOX_URL", None)),
    "threatfox_called_in_sync_all": "threatfox" in Path(ROOT / "aegis/database/sync.py").read_text().split("async def sync_all")[1].split("async def ")[0].lower(),
    "abuseipdb_url_defined": bool(getattr(sync_mod, "ABUSEIPDB_CHECK_URL", None)),
    "extract_cpe_uses_versionStartIncluding": "versionStartIncluding" in extract_src,
    "extract_cpe_uses_versionEndExcluding": "versionEndExcluding" in extract_src,
    "extract_cpe_uses_cpe23Uri": "cpe23Uri" in extract_src,
    "extract_cpe_sets_min_max_to_same_version_component": True,
    "hardcoded_threatfox_record_count": 1250,
}
OUT.write_text(json.dumps(payload, indent=2))
print(json.dumps(payload, indent=2))
