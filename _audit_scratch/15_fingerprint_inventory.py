#!/usr/bin/env python3
"""Part 3.2: inventory every product/service the fingerprinter can identify from probes + regex."""
import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "15_fp_inventory.json"

src = (ROOT / "aegis/discovery/fingerprint.py").read_text()

# products returned as string literals assigned to "product"
products = sorted(set(re.findall(r'"product":\s*"([^"]+)"', src)))
service_names = sorted(set(re.findall(r'"service_name":\s*"([^"]+)"', src)))

# _analyze_banner default_map
default_map = {
    21: ("ftp", "ftp"),
    22: ("ssh", "ssh"),
    23: ("telnet", "telnet"),
    25: ("smtp", "smtp"),
    53: ("dns", "dns"),
    80: ("http", "http"),
    443: ("https", "https"),
    445: ("smb", "smb"),
    1433: ("mssql", "microsoft_sql_server"),
    1521: ("oracle", "oracle_database"),
    3306: ("mysql", "mysql"),
    3389: ("rdp", "ms-wbt-server"),
    5432: ("postgresql", "postgresql"),
    6379: ("redis", "redis"),
    27017: ("mongodb", "mongodb"),
}

# HTTP parser: product = Server header name lowercased when Name/version matches
http_note = "_parse_http_server returns match.group(1).lower() from Name/version, else first token lowercased — open-ended, not a fixed catalog"

# port-gated probes
port_probes = {
    22: "ssh/_probe_ssh -> openssh",
    21: "ftp/_probe_ftp -> vsftpd|proftpd|pure-ftpd|microsoft_ftp",
    "25/587/465": "smtp/_probe_smtp -> postfix|exim|sendmail|microsoft_smtp",
    53: "dns/_probe_dns -> bind",
    3306: "mysql/_probe_mysql -> mysql|mariadb",
    5432: "postgresql/_probe_postgresql -> postgresql",
    6379: "redis/_probe_redis -> redis",
    27017: "mongodb/_probe_mongodb -> mongodb",
    "80,443,8000,8080,8443,8888,3000,5000,9000 or TLS": "http/_probe_http -> _parse_http_server",
}

banner_regex_products = [
    "openssh (SSH-...-OpenSSH_VER)",
    "vsftpd/proftpd (FTP banner; pure-ftpd banner is mislabeled proftpd)",
    "redis",
    "mysql/mariadb",
]

payload = {
    "literal_product_strings": products,
    "literal_service_name_strings": service_names,
    "default_port_map_without_banner": default_map,
    "port_gated_probes": port_probes,
    "banner_regex_products": banner_regex_products,
    "http_open_ended": http_note,
    "count_literal_products": len(products),
    "count_default_map_products": len({v[1] for v in default_map.values()}),
    "union_identifiable_closed_set": sorted(set(products) | {v[1] for v in default_map.values()} | {
        "http", "https", "unknown"
    }),
}
payload["count_union_closed_set"] = len(payload["union_identifiable_closed_set"])
OUT.write_text(json.dumps(payload, indent=2))
print(json.dumps(payload, indent=2))
