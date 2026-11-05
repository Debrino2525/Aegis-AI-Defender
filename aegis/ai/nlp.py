"""Natural language processing for incident summarization, query interpretation, and report generation.

No external LLM or ML library required. Uses:
- Structured f-string templates for summarization and reports
- Keyword/pattern matching for query interpretation
- Regex for entity extraction
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Query intent patterns (order matters — more specific first)
# ---------------------------------------------------------------------------

_QUERY_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # Critical / high findings
    (re.compile(r"\b(crit(ical)?)\b", re.I),                         "findings_by_severity", "critical"),
    (re.compile(r"\bhigh(\b|[\s_-]?(severit|finding))", re.I),       "findings_by_severity", "high"),
    # Specific CVE
    (re.compile(r"CVE-\d{4}-\d+", re.I),                             "finding_by_cve",       "cve"),
    # KEV / known-exploited
    (re.compile(r"\b(kev|known[\s_-]?exploit(ed)?)\b", re.I),        "findings_kev",         "kev"),
    # Asset / host counts
    (re.compile(r"\b(how many|count)\b.*\b(assets?|hosts?|devices?)\b", re.I), "asset_count", ""),
    # Open ports on a host
    (re.compile(r"\b(open[\s_-]?ports?|ports?|listen(?:ing)?)\b.*\bon\b\s+(\S+)", re.I), "open_ports", "host"),
    # Lateral movement / alerts
    (re.compile(r"\b(lateral[\s_-]?mov(?:ement)?|pivot)\b", re.I),   "alerts_by_tactic", "Lateral Movement"),
    (re.compile(r"\b(c2|command[\s._-]?and[\s._-]?control|beaconing)\b", re.I), "alerts_by_tactic", "Command and Control"),
    (re.compile(r"\b(exfil(tration)?)\b", re.I),                     "alerts_by_tactic", "Exfiltration"),
    # Recent incidents / alerts
    (re.compile(r"\b(recent|last|today|yesterday)\b.*\b(incidents?|alerts?|events?)\b", re.I), "recent_incidents", ""),
    # Agent / fleet status
    (re.compile(r"\b(agents?|fleet|endpoints?)\b.*\b(status|online|offline|health)\b", re.I), "agent_status", ""),
    # Response history
    (re.compile(r"\b(responses?|actions?|block|quarantine)\b.*\b(histor|log|audit)\b", re.I), "response_history", ""),
    # Trend / risk score
    (re.compile(r"\b(trends?|scores?|risks?|postures?)\b", re.I),    "risk_trend", ""),
    # Catch-all — asset summary
    (re.compile(r".", re.I),                                         "summary",            ""),
]

# ---------------------------------------------------------------------------
# Severity colour words for prose
# ---------------------------------------------------------------------------

_SEV_ADJECTIVE = {
    "critical": "critically severe",
    "high":     "high-severity",
    "medium":   "medium-severity",
    "low":      "low-severity",
    "info":     "informational",
}

_PHASE_PROSE = {
    "initial":  "initial access",
    "lateral":  "lateral movement",
    "impact":   "impact / exfiltration",
}

# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def _fmt_host_list(hosts: List[str], limit: int = 5) -> str:
    if not hosts:
        return "unknown hosts"
    shown = hosts[:limit]
    suffix = f" and {len(hosts) - limit} more" if len(hosts) > limit else ""
    return ", ".join(shown) + suffix


def _fmt_ts(ts: Optional[float]) -> str:
    if ts is None:
        return "unknown time"
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (OSError, OverflowError, ValueError):
        return str(ts)


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class NaturalLanguageProcessing:
    """NLP for incident summarization, natural-language query, and report generation.

    All output is template-driven — no external LLM required.
    """

    def __init__(self):
        # Optional: attach a live data-fetch callback for query resolution
        # Signature: callback(query_type: str, params: dict) -> Any
        self._data_callback: Optional[Any] = None

    def set_data_callback(self, callback) -> None:
        """Register a callable that the NLP engine uses to resolve live queries.

        The callback receives (query_type: str, params: dict) and should return
        the matching data (list / dict / int) or None.
        """
        self._data_callback = callback

    # ------------------------------------------------------------------
    # Incident summarization
    # ------------------------------------------------------------------

    def summarize_incident(self, incident: Dict[str, Any]) -> str:
        """Generate an executive-readable narrative paragraph from an incident dict.

        Consumes keys: id, host, hosts, severity, tactics, cvss_score,
        cves, description, first_seen, last_seen, alert_count, phase, status.

        Returns:
            Non-empty English prose string.
        """
        inc_id      = incident.get("id", incident.get("incident_id", "UNKNOWN"))
        severity    = str(incident.get("severity", "medium")).lower()
        sev_word    = _SEV_ADJECTIVE.get(severity, f"{severity}-severity")

        # Host(s)
        hosts: List[str] = []
        if "hosts" in incident and isinstance(incident["hosts"], list):
            hosts = [str(h) for h in incident["hosts"] if h]
        elif "host" in incident:
            hosts = [str(incident["host"])]
        host_str = _fmt_host_list(hosts) if hosts else "one or more hosts"

        # Tactics
        tactics: List[str] = []
        if "tactics" in incident and isinstance(incident["tactics"], list):
            tactics = [str(t) for t in incident["tactics"]]
        elif "tactic" in incident:
            tactics = [str(incident["tactic"])]
        tactic_str = (
            ", ".join(tactics) if tactics else "unclassified activity"
        )

        # CVEs
        cves: List[str] = []
        if "cves" in incident and isinstance(incident["cves"], list):
            cves = [str(c) for c in incident["cves"]]
        cve_clause = (
            f", exploiting {', '.join(cves[:3])}"
            + (" and others" if len(cves) > 3 else "")
            if cves else ""
        )

        # Timestamps
        first_seen = _fmt_ts(incident.get("first_seen"))
        last_seen  = _fmt_ts(incident.get("last_seen"))

        # Alert count
        alert_count = incident.get("alert_count", incident.get("alerts", ""))
        alert_clause = (
            f" A total of {alert_count} alerts were raised."
            if alert_count else ""
        )

        # Phase
        phase = str(incident.get("phase", "")).lower()
        phase_word = _PHASE_PROSE.get(phase, phase) if phase else None

        # Status
        status = str(incident.get("status", "open")).lower()

        # CVSS
        cvss = incident.get("cvss_score")
        cvss_clause = f" (CVSS {cvss:.1f})" if isinstance(cvss, (int, float)) else ""

        # Build narrative
        lines = [
            f"Incident {inc_id}: A {sev_word} event{cvss_clause} was detected "
            f"on {host_str}, first observed at {first_seen} and most recently "
            f"active at {last_seen}."
        ]

        lines.append(
            f"The activity involves {tactic_str}{cve_clause}."
            + (f" Kill-chain phase: {phase_word}." if phase_word else "")
        )

        lines.append(alert_clause.strip() if alert_clause else "")

        description = str(incident.get("description", "")).strip()
        if description:
            lines.append(description)

        lines.append(
            f"Current status: {status}. "
            f"This summary was generated by Aegis Analyst Assist at {_now_str()}."
        )

        return " ".join(line for line in lines if line)

    # ------------------------------------------------------------------
    # Natural-language query
    # ------------------------------------------------------------------

    def query_natural_language(self, query: str) -> Dict[str, Any]:
        """Interpret a natural-language threat-hunting query.

        Matches the query against known intent patterns and returns a
        structured response.  If a data callback is registered, the live
        result is embedded; otherwise a template result is returned.

        Returns:
            Dict with keys: type, params, interpreted_query, result, filters.
        """
        query = query.strip()
        query_type = "summary"
        params: Dict[str, Any] = {}

        for pattern, intent, default_param in _QUERY_PATTERNS:
            m = pattern.search(query)
            if m:
                query_type = intent
                if default_param == "cve":
                    # Extract the CVE number from the match
                    cve_match = re.search(r"CVE-\d{4}-\d+", query, re.I)
                    params["cve"] = cve_match.group(0).upper() if cve_match else ""
                elif default_param == "host":
                    # Extract the hostname/IP after "on"
                    host_match = re.search(r"\bon\b\s+(\S+)", query, re.I)
                    params["host"] = host_match.group(1) if host_match else ""
                elif default_param:
                    params["value"] = default_param
                break

        # Try live data callback
        result: Any = None
        if self._data_callback is not None:
            try:
                result = self._data_callback(query_type, params)
            except Exception as exc:  # noqa: BLE001
                result = {"error": str(exc)}

        # Template result when no callback or empty result
        if result is None:
            result = _template_result(query_type, params)

        return {
            "type":               query_type,
            "params":             params,
            "interpreted_query":  query,
            "result":             result,
            "filters":            params,
        }

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(
        self,
        data: Dict[str, Any],
        report_type: str = "weekly",
    ) -> str:
        """Generate a structured plain-text / markdown report.

        Args:
            data: Dict with optional keys:
                  period_start, period_end, total_scans, critical_count,
                  high_count, kev_count, resolved_count, new_count,
                  top_tactics (list), top_hosts (list), incidents (list),
                  risk_score, risk_grade, recommendations (list).
            report_type: "weekly", "monthly", or "executive".

        Returns:
            Markdown-formatted report string.
        """
        period_start = _fmt_ts(data.get("period_start"))
        period_end   = _fmt_ts(data.get("period_end", time.time()))
        title_prefix = {"weekly": "Weekly", "monthly": "Monthly",
                        "executive": "Executive"}.get(report_type, "Security")

        lines = [
            f"# Aegis AI — {title_prefix} Security Report",
            f"**Period:** {period_start} → {period_end}  ",
            f"**Generated:** {_now_str()}",
            "",
            "---",
            "",
            "## Executive Summary",
        ]

        # Risk posture
        risk_score = data.get("risk_score", "N/A")
        risk_grade = data.get("risk_grade", "N/A")
        lines.append(
            f"Overall risk score: **{risk_score}/100** (grade **{risk_grade}**)."
        )

        # Counts
        total_scans   = data.get("total_scans",    0)
        critical      = data.get("critical_count", 0)
        high          = data.get("high_count",     0)
        kev           = data.get("kev_count",      0)
        resolved      = data.get("resolved_count", 0)
        new_findings  = data.get("new_count",      0)

        lines += [
            "",
            f"- **Scans completed:** {total_scans}",
            f"- **Critical findings:** {critical}",
            f"- **High findings:** {high}",
            f"- **Known-Exploited (KEV) vulnerabilities:** {kev}",
            f"- **New findings this period:** {new_findings}",
            f"- **Resolved this period:** {resolved}",
        ]

        # Top tactics
        top_tactics: List[str] = data.get("top_tactics", [])
        if top_tactics:
            lines += [
                "",
                "## Top ATT&CK Tactics Observed",
            ] + [f"- {t}" for t in top_tactics[:5]]

        # Top affected hosts
        top_hosts: List[str] = data.get("top_hosts", [])
        if top_hosts:
            lines += [
                "",
                "## Most Affected Assets",
            ] + [f"- {h}" for h in top_hosts[:5]]

        # Incident summaries
        incidents: List[Dict[str, Any]] = data.get("incidents", [])
        if incidents:
            lines += ["", "## Incident Highlights"]
            for inc in incidents[:5]:
                inc_id  = inc.get("id", "?")
                sev     = inc.get("severity", "medium")
                host    = inc.get("host", "unknown")
                tactic  = inc.get("tactic", "unknown")
                lines.append(f"- **{inc_id}** [{sev.upper()}] — {host} — {tactic}")

        # Recommendations
        recs: List[str] = data.get("recommendations", [])
        if not recs:
            recs = _default_recommendations(critical, kev, high)
        if recs:
            lines += ["", "## Recommendations"]
            for i, rec in enumerate(recs[:7], 1):
                lines.append(f"{i}. {rec}")

        lines += [
            "",
            "---",
            "",
            "_This report was auto-generated by Aegis AI Analyst Assist. "
            "Findings should be validated before remediation actions are taken._",
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Entity extraction
    # ------------------------------------------------------------------

    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract IP addresses, CVEs, hostnames, and tactic names from free text.

        Returns:
            Dict with keys: ips, cves, hostnames, tactics.
        """
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        cves = re.findall(r"CVE-\d{4}-\d+", text, re.I)
        # Simple hostname: word.word or word (not a CVE or pure number)
        potential_hosts = re.findall(r"\b(?:[a-zA-Z][a-zA-Z0-9\-]*\.){1,3}[a-zA-Z]{2,}\b", text)
        tactics_found = [t for t in _FOLLOWON_KEYS if t.lower() in text.lower()]
        return {
            "ips":      sorted(set(ips)),
            "cves":     sorted(set(c.upper() for c in cves)),
            "hostnames": sorted(set(potential_hosts)),
            "tactics":  tactics_found,
        }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

_FOLLOWON_KEYS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def _template_result(query_type: str, params: Dict[str, Any]) -> Any:
    """Return a descriptive template response when no live callback is attached."""
    if query_type == "findings_by_severity":
        sev = params.get("value", "critical")
        return {
            "message":  f"Query for {sev} findings. Connect a data source to retrieve live results.",
            "severity": sev,
            "count":    None,
        }
    if query_type == "finding_by_cve":
        return {
            "cve":     params.get("cve", ""),
            "message": "Query for specific CVE. Connect a data source to retrieve live results.",
        }
    if query_type == "findings_kev":
        return {"message": "Query for KEV findings. Connect a data source for live results."}
    if query_type == "asset_count":
        return {"message": "Asset count query. Connect a data source to retrieve live results.", "count": None}
    if query_type == "open_ports":
        return {"host": params.get("host", ""), "ports": None,
                "message": "Port query. Connect a data source for live results."}
    if query_type == "alerts_by_tactic":
        return {"tactic": params.get("value", ""), "alerts": None,
                "message": "Tactic alert query. Connect a data source for live results."}
    if query_type == "recent_incidents":
        return {"incidents": None, "message": "Recent incidents query. Connect a data source for live results."}
    if query_type == "agent_status":
        return {"agents": None, "message": "Agent status query. Connect a data source for live results."}
    if query_type == "response_history":
        return {"history": None, "message": "Response history query. Connect a data source for live results."}
    if query_type == "risk_trend":
        return {"trend": None, "message": "Risk trend query. Connect a data source for live results."}
    return {"message": "General summary query. Connect a data source for live results."}


def _default_recommendations(critical: int, kev: int, high: int) -> List[str]:
    recs = []
    if critical > 0:
        recs.append(f"Remediate {critical} critical finding(s) within 24 hours per SLA.")
    if kev > 0:
        recs.append(
            f"Prioritize {kev} CISA KEV finding(s) — these are actively exploited in the wild."
        )
    if high > 0:
        recs.append(f"Schedule patching for {high} high-severity finding(s) within 7 days.")
    recs.append("Review behavioral anomalies flagged by Analyst Assist before closing incidents.")
    recs.append("Validate response actions in Recommend mode before enabling Auto on new hosts.")
    return recs
