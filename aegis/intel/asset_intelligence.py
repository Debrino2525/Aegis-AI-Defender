"""
Asset Intelligence Engine — tracks all discovered assets, technologies, and risk posture.
"""
from typing import Dict, List, Any

# Map service/product names to technology categories
TECH_CATEGORY_MAP = {
    # Web Servers
    "apache": "Web Servers", "nginx": "Web Servers", "iis": "Web Servers",
    "http_server": "Web Servers", "lighttpd": "Web Servers", "caddy": "Web Servers",
    # Databases
    "mysql": "Databases", "postgresql": "Databases", "mssql": "Databases",
    "mongodb": "Databases", "redis": "Databases", "elasticsearch": "Databases",
    "cassandra": "Databases", "oracle": "Databases", "mariadb": "Databases",
    # Remote Access
    "openssh": "Remote Access", "ssh": "Remote Access", "rdp": "Remote Access",
    "ms-wbt-server": "Remote Access", "vnc": "Remote Access", "telnet": "Remote Access",
    # File Transfer
    "ftp": "File Transfer", "vsftpd": "File Transfer", "proftpd": "File Transfer",
    # Mail
    "smtp": "Mail", "imap": "Mail", "pop3": "Mail",
    # Container / Cloud
    "docker": "Container/Cloud", "kubernetes": "Container/Cloud",
    # DNS
    "dns": "DNS",
}

CATEGORY_ICONS = {
    "Web Servers": "🌐",
    "Databases": "🗄",
    "Remote Access": "🔑",
    "File Transfer": "📁",
    "Mail": "✉",
    "Container/Cloud": "☁",
    "DNS": "📡",
    "Other": "⚙",
}

def categorize_services(services: List[Dict]) -> Dict[str, List[Dict]]:
    """Groups services by technology category."""
    categories: Dict[str, List] = {}
    for svc in services:
        product = (svc.get("product") or svc.get("service_name") or "").lower()
        cat = TECH_CATEGORY_MAP.get(product, "Other")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(svc)
    return categories

def compute_aegis_risk_score(findings: List[Dict]) -> int:
    """
    Computes the overall Aegis TruRisk-style score (0–1000).
    Higher = more risk.
    """
    if not findings:
        return 0

    severity_weights = {"CRITICAL": 100, "HIGH": 60, "MEDIUM": 25, "LOW": 8, "INFO": 1}
    kev_bonus = 40
    raw = 0

    for f in findings:
        sev = f.get("severity", "INFO")
        raw += severity_weights.get(sev, 1)
        if f.get("is_cisa_kev"):
            raw += kev_bonus
        raw += f.get("epss_score", 0) * 20

    # Normalize to 0–1000
    score = min(1000, int(raw))
    return score

def compute_risk_label(score: int) -> str:
    if score >= 750: return "Critical"
    if score >= 500: return "High"
    if score >= 250: return "Medium"
    if score > 0:    return "Low"
    return "Minimal"

def compute_business_risk(findings: List[Dict]) -> Dict[str, Any]:
    """
    Estimates financial exposure based on finding severity.
    Uses industry-average breach cost data (IBM Cost of Data Breach Report 2024).
    """
    # Average cost per severity tier (USD, based on industry data)
    cost_map = {"CRITICAL": 850_000, "HIGH": 320_000, "MEDIUM": 85_000, "LOW": 12_000, "INFO": 0}
    total = sum(cost_map.get(f.get("severity", "INFO"), 0) for f in findings)
    kev_multiplier = 1.0 + (0.15 * sum(1 for f in findings if f.get("is_cisa_kev")))
    total_adjusted = int(total * kev_multiplier)
    return {
        "estimated_breach_cost": total_adjusted,
        "formatted": f"${total_adjusted:,.0f}",
        "kev_count": sum(1 for f in findings if f.get("is_cisa_kev")),
        "critical_count": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
    }

def build_contributing_factors(findings: List[Dict]) -> List[Dict]:
    """Breaks findings into Qualys-style contributing factor categories."""
    vuln_cves    = [f for f in findings if (f.get("id") or "").startswith("CVE-")]
    misconfigs   = [f for f in findings if (f.get("id") or "").startswith("AEGIS-HTTP") or (f.get("id") or "").startswith("AEGIS-TLS")]
    templates    = [f for f in findings if (f.get("id") or "").startswith("AEGIS-TMPL")]
    ssh_findings = [f for f in findings if "ssh" in (f.get("service") or "").lower()]
    ransomware   = [f for f in findings if f.get("is_cisa_kev")]

    factors = [
        {"name": "CVE Vulnerabilities",    "count": len(vuln_cves),  "color": "#ff3b3b", "pct": 0},
        {"name": "Misconfigurations",      "count": len(misconfigs), "color": "#ff6b35", "pct": 0},
        {"name": "Template Detections",    "count": len(templates),  "color": "#f5a623", "pct": 0},
        {"name": "Active Exploitation (KEV)", "count": len(ransomware), "color": "#a855f7", "pct": 0},
        {"name": "Remote Access Risk",     "count": len(ssh_findings),"color": "#3b9eff", "pct": 0},
    ]
    total = sum(f["count"] for f in factors) or 1
    for f in factors:
        f["pct"] = round(f["count"] / total * 100, 1)
    return factors

def generate_top_insights(findings: List[Dict]) -> List[Dict]:
    """Auto-generates prioritized actionable insights from findings."""
    insights = []
    sorted_findings = sorted(findings, key=lambda f: f.get("composite_risk_score", 0), reverse=True)

    for f in sorted_findings[:8]:
        criticality = "Critical" if f.get("composite_risk_score", 0) >= 70 else "High" if f.get("composite_risk_score", 0) >= 50 else "Medium"
        prefix = ""
        if f.get("is_cisa_kev"):
            prefix = "KEV-Confirmed: "
        elif (f.get("id") or "").startswith("CVE-"):
            prefix = "Actively Exploitable: "
        elif "Exposed" in f.get("title", ""):
            prefix = "Exposure Risk: "

        insights.append({
            "title": prefix + f.get("title", ""),
            "criticality": criticality,
            "score": f.get("composite_risk_score", 0),
            "port": f.get("port"),
            "cve": f.get("cve_id"),
            "is_kev": f.get("is_cisa_kev", False),
        })

    return insights
