"""
MITRE ATT&CK CVE-to-Technique Mapper.
Maps CVEs to specific ATT&CK Tactics and Techniques for threat intelligence context.
"""

from typing import Dict, List, Optional

# Curated CVE → ATT&CK mapping (production would pull from MITRE API)
CVE_ATTACK_MAP: Dict[str, Dict] = {
    "CVE-2021-44228": {"tactic": "Execution", "technique": "T1203", "technique_name": "Exploitation for Client Execution", "group": "Multiple APTs"},
    "CVE-2021-41773": {"tactic": "Initial Access", "technique": "T1190", "technique_name": "Exploit Public-Facing Application", "group": "Multiple Threat Actors"},
    "CVE-2021-42013": {"tactic": "Initial Access", "technique": "T1190", "technique_name": "Exploit Public-Facing Application", "group": "Multiple Threat Actors"},
    "CVE-2024-6387":  {"tactic": "Initial Access", "technique": "T1190", "technique_name": "Exploit Public-Facing Application", "group": "Nation-State Actors"},
    "CVE-2023-38408": {"tactic": "Lateral Movement", "technique": "T1563.001", "technique_name": "SSH Hijacking", "group": "Multiple APTs"},
    "CVE-2022-22965": {"tactic": "Execution", "technique": "T1203", "technique_name": "Exploitation for Client Execution", "group": "APT41"},
    "CVE-2021-23017": {"tactic": "Defense Evasion", "technique": "T1071.001", "technique_name": "Web Protocols", "group": "Multiple Actors"},
    "CVE-2015-3306": {"tactic": "Initial Access", "technique": "T1190", "technique_name": "Exploit Public-Facing Application", "group": "Multiple Actors"},
}

# ATT&CK Tactic → color
TACTIC_COLORS = {
    "Initial Access": "#ff3b3b",
    "Execution": "#ff6b35",
    "Persistence": "#f5a623",
    "Privilege Escalation": "#e535ab",
    "Defense Evasion": "#a855f7",
    "Credential Access": "#3b9eff",
    "Discovery": "#10b981",
    "Lateral Movement": "#f59e0b",
    "Collection": "#06b6d4",
    "Exfiltration": "#ef4444",
    "Impact": "#dc2626",
    "Command and Control": "#8b5cf6",
}

# Ransomware groups and their known CVEs
RANSOMWARE_CVE_MAP: Dict[str, List[str]] = {
    "LockBit 3.0": ["CVE-2021-44228", "CVE-2022-22965", "CVE-2021-41773", "CVE-2024-6387"],
    "ALPHV/BlackCat": ["CVE-2021-44228", "CVE-2022-22965", "CVE-2023-38408"],
    "Cl0p": ["CVE-2021-35464", "CVE-2023-0669"],
    "Royal": ["CVE-2021-44228", "CVE-2022-22947"],
    "Play": ["CVE-2022-41082", "CVE-2022-41040"],
    "Hive": ["CVE-2021-44228", "CVE-2021-41773"],
    "Vice Society": ["CVE-2021-42278", "CVE-2021-42287"],
    "Black Basta": ["CVE-2024-6387", "CVE-2022-22965"],
}

def get_attack_info(cve_id: str) -> Optional[Dict]:
    return CVE_ATTACK_MAP.get(cve_id)

def get_ransomware_groups(cve_id: str) -> List[str]:
    return [grp for grp, cves in RANSOMWARE_CVE_MAP.items() if cve_id in cves]

def build_attack_summary(findings: List[Dict]) -> Dict:
    """Aggregates ATT&CK tactics and techniques from a list of findings."""
    tactic_counts: Dict[str, int] = {}
    technique_hits = []
    ransomware_cves = []

    for f in findings:
        cve = f.get("cve_id") or f.get("id", "")
        attack = get_attack_info(cve)
        if attack:
            tac = attack["tactic"]
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1
            technique_hits.append({
                "cve": cve,
                "tactic": tac,
                "technique": attack["technique"],
                "technique_name": attack["technique_name"],
                "finding_title": f.get("title", ""),
                "severity": f.get("severity", "MEDIUM"),
                "color": TACTIC_COLORS.get(tac, "#64748b"),
            })
        groups = get_ransomware_groups(cve)
        if groups:
            ransomware_cves.append({
                "cve": cve,
                "title": f.get("title", ""),
                "severity": f.get("severity", "HIGH"),
                "groups": groups,
                "cvss_score": f.get("cvss_score", 0),
                "composite_risk_score": f.get("composite_risk_score", 0),
            })

    return {
        "tactic_counts": tactic_counts,
        "technique_hits": technique_hits[:10],
        "ransomware_cves": ransomware_cves,
        "tactic_colors": TACTIC_COLORS,
    }
