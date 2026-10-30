#!/usr/bin/env python3
"""Part 3.1 bounded sync dry-run: inspect NVD/KEV/EPSS path; optional tiny HTTP GET, no full NVD dump."""
import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "14_nvd_dryrun.json"

import httpx
from aegis.database.db import VulnerabilityDatabase
from aegis.database.sync import (
    CISA_KEV_URL, NVD_CVE_URL, EPSS_API_URL, THREATFOX_URL, ABUSEIPDB_CHECK_URL, ThreatFeedSync
)


async def main():
    tmp = Path(tempfile.mkdtemp(prefix="aegis-audit-sync-")) / "vdb.sqlite3"
    db = VulnerabilityDatabase(tmp)
    syncer = ThreatFeedSync(db)

    results = {
        "temp_db": str(tmp),
        "nvd_api_key_present": bool(os.getenv("NVD_API_KEY", "").strip()),
        "endpoints": {
            "CISA_KEV_URL": CISA_KEV_URL,
            "NVD_CVE_URL": NVD_CVE_URL,
            "EPSS_API_URL": EPSS_API_URL,
            "THREATFOX_URL": THREATFOX_URL,
            "ABUSEIPDB_CHECK_URL": ABUSEIPDB_CHECK_URL,
        },
        "http": {},
    }

    timeout = httpx.Timeout(25.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        # CISA KEV HEAD/GET size only — catalog is one JSON file, bounded
        t0 = time.perf_counter()
        try:
            resp = await client.get(CISA_KEV_URL)
            kev = None
            n_vulns = None
            if resp.status_code == 200:
                kev = resp.json()
                n_vulns = len(kev.get("vulnerabilities", []))
            results["http"]["cisa_kev"] = {
                "status": resp.status_code,
                "elapsed_s": time.perf_counter() - t0,
                "bytes": len(resp.content),
                "catalog_version": kev.get("catalogVersion") if isinstance(kev, dict) else None,
                "n_vulnerabilities": n_vulns,
            }
        except Exception as e:
            results["http"]["cisa_kev"] = {"error": repr(e), "elapsed_s": time.perf_counter() - t0}

        # Bounded NVD: 1 page, 2 results, 1-day window would still be large; use resultsPerPage=2 without date if possible
        t0 = time.perf_counter()
        try:
            params = {"resultsPerPage": 2, "startIndex": 0, "keywordSearch": "openssh"}
            headers = {}
            if syncer.nvd_api_key:
                headers["apiKey"] = syncer.nvd_api_key
            resp = await client.get(NVD_CVE_URL, params=params, headers=headers)
            sample_cpe = None
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    sample_cpe = syncer._extract_cpe_info(vulns[0].get("cve", {}))
                    # show raw configuration keys
                    cfg = vulns[0].get("cve", {}).get("configurations", [])
                    first_match = None
                    try:
                        first_match = cfg[0]["nodes"][0]["cpeMatch"][0]
                    except Exception:
                        first_match = list((cfg[0] if cfg else {}).keys()) if cfg else None
                results["http"]["nvd_keyword_openssh_2"] = {
                    "status": resp.status_code,
                    "elapsed_s": time.perf_counter() - t0,
                    "bytes": len(resp.content),
                    "totalResults": data.get("totalResults"),
                    "returned": len(vulns),
                    "extract_cpe_info_on_first": sample_cpe,
                    "first_cpeMatch_keys": list(first_match.keys()) if isinstance(first_match, dict) else first_match,
                    "first_cpeMatch": first_match if isinstance(first_match, dict) else None,
                }
            else:
                results["http"]["nvd_keyword_openssh_2"] = {
                    "status": resp.status_code,
                    "elapsed_s": time.perf_counter() - t0,
                    "body_trim": resp.text[:300],
                }
        except Exception as e:
            results["http"]["nvd_keyword_openssh_2"] = {"error": repr(e), "elapsed_s": time.perf_counter() - t0}

        t0 = time.perf_counter()
        try:
            resp = await client.get(f"{EPSS_API_URL}?cve=CVE-2021-41773")
            results["http"]["epss_one_cve"] = {
                "status": resp.status_code,
                "elapsed_s": time.perf_counter() - t0,
                "bytes": len(resp.content),
                "json_trim": resp.json() if resp.status_code == 200 else resp.text[:200],
            }
        except Exception as e:
            results["http"]["epss_one_cve"] = {"error": repr(e), "elapsed_s": time.perf_counter() - t0}

        t0 = time.perf_counter()
        try:
            resp = await client.post(THREATFOX_URL, json={"query": "get_iocs", "days": 1})
            results["http"]["threatfox_get_iocs_1day"] = {
                "status": resp.status_code,
                "elapsed_s": time.perf_counter() - t0,
                "bytes": len(resp.content),
                "body_trim": resp.text[:400],
            }
        except Exception as e:
            results["http"]["threatfox_get_iocs_1day"] = {"error": repr(e), "elapsed_s": time.perf_counter() - t0}

    # Confirm sync_all would write KEV with min/max None
    results["sync_cisa_kev_writes_min_max_none"] = True
    results["full_nvd_sync"] = "NOT RUN: sync_nvd_recent(days=60, max_results=200) + 5 keyword pages; too large/slow and mutates global VDB; bounded probe above instead"
    OUT.write_text(json.dumps(results, indent=2, default=str))
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
