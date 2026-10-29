"""
Aegis AI — Executive & Technical HTML Security Assessment Report Generator.
Produces executive-grade, beautifully styled, print/PDF-optimized audit reports
aligned with the Aegis AI design system (Globitech Ghana branding, Palantir/Stripe aesthetic).
"""

import html as htmllib
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from aegis.core.models import ScanReport, Severity, Finding


def esc(val: Any) -> str:
    """Safe HTML escaping for all user- and network-controlled strings."""
    if val is None:
        return ""
    return htmllib.escape(str(val))


class HTMLReporter:
    """Generates executive and technical vulnerability assessment reports."""

    @classmethod
    def generate(cls, report: ScanReport) -> str:
        all_findings: List[Finding] = []
        all_services: List[Dict[str, Any]] = []
        open_ports: List[int] = []

        for host in report.hosts:
            all_findings.extend(host.findings)
            open_ports.extend(host.open_ports)
            for svc in host.services:
                if isinstance(svc, dict):
                    all_services.append(svc)
                elif hasattr(svc, "model_dump"):
                    all_services.append(svc.model_dump())
                elif hasattr(svc, "__dict__"):
                    all_services.append(svc.__dict__)

        # Sort findings by composite risk score (descending)
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        all_findings.sort(
            key=lambda f: (
                sev_order.get(f.severity.value, 0),
                f.composite_risk_score,
                f.cvss_score
            ),
            reverse=True
        )

        # Calculate metrics
        crit_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in all_findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in all_findings if f.severity == Severity.INFO)
        kev_count = sum(1 for f in all_findings if getattr(f, "is_cisa_kev", False))

        # Overall composite posture calculation (0 - 100)
        # 100 = perfectly secure, 0 = severe critical exposure
        if not all_findings:
            posture_score = 100
            posture_grade = "A+"
            posture_label = "SECURE / HARDENED"
            posture_color = "#3ddc97"
        else:
            penalty = (crit_count * 25) + (high_count * 12) + (med_count * 4) + (low_count * 1)
            posture_score = max(0, min(100, round(100 - penalty)))
            if posture_score >= 90:
                posture_grade = "A"
                posture_label = "LOW RISK"
                posture_color = "#3ddc97"
            elif posture_score >= 70:
                posture_grade = "B"
                posture_label = "MODERATE RISK"
                posture_color = "#f2c14e"
            elif posture_score >= 50:
                posture_grade = "C"
                posture_label = "ELEVATED RISK"
                posture_color = "#ff8a4c"
            else:
                posture_grade = "F"
                posture_label = "CRITICAL RISK"
                posture_color = "#ff4d5e"

        # Unique ports and services
        unique_ports = sorted(list(set(open_ports)))
        services_count = len(all_services)

        # Dates
        started_str = report.started_at.strftime("%B %d, %Y · %H:%M:%S UTC") if report.started_at else "N/A"
        duration_str = f"{report.duration_seconds:.1f}s" if report.duration_seconds else "N/A"
        generated_at = datetime.utcnow().strftime("%B %d, %Y · %H:%M:%S UTC")

        # Render Finding Cards
        findings_cards_html = []
        for i, f in enumerate(all_findings, 1):
            sev_val = f.severity.value
            sev_class = sev_val.lower()

            # Badges
            kev_badge = '<span class="badge badge-kev">CISA KEV EXPLOITABLE</span>' if getattr(f, "is_cisa_kev", False) else ''
            cve_badge = f'<span class="badge badge-cve">{esc(f.cve_id)}</span>' if getattr(f, "cve_id", None) else ''
            cvss_val = f"{f.cvss_score:.1f}" if f.cvss_score else "0.0"
            epss_pct = f"{f.epss_score * 100:.1f}%" if getattr(f, "epss_score", 0.0) else "0.0%"
            risk_score_val = f"{f.composite_risk_score:.1f}" if getattr(f, "composite_risk_score", 0.0) else cvss_val

            # References list
            refs_html = ""
            if f.references:
                ref_items = "".join(f'<li><a href="{esc(r)}" target="_blank" rel="noopener noreferrer">{esc(r)}</a></li>' for r in f.references[:5])
                refs_html = f"""
                <div class="fcard-section">
                    <div class="fcard-subtitle">Official References &amp; Advisories</div>
                    <ul class="ref-list">{ref_items}</ul>
                </div>
                """

            # Remediation
            remediation_html = ""
            if f.remediation:
                remediation_html = f"""
                <div class="fcard-section remediation-box">
                    <div class="fcard-subtitle rem-title">Remediation &amp; Hardening Guidance</div>
                    <div class="rem-text">{esc(f.remediation)}</div>
                </div>
                """

            # Attack mapping tactic heuristic if known
            tactic_badge = ""
            if "SQL" in f.title or "Injection" in f.title:
                tactic_badge = '<span class="badge badge-mitre">ATT&amp;CK T1190 · Exploit Public-Facing App</span>'
            elif "SMB" in f.title:
                tactic_badge = '<span class="badge badge-mitre">ATT&amp;CK T1021.002 · SMB Shares</span>'
            elif "TLS" in f.title or "SSL" in f.title or "Certificate" in f.title:
                tactic_badge = '<span class="badge badge-mitre">ATT&amp;CK T1557 · Adversary-in-the-Middle</span>'
            elif "Header" in f.title or "HSTS" in f.title or "Clickjacking" in f.title:
                tactic_badge = '<span class="badge badge-mitre">ATT&amp;CK T1189 · Drive-by Compromise</span>'
            elif "Port" in f.title or "Scan" in f.title:
                tactic_badge = '<span class="badge badge-mitre">ATT&amp;CK T1046 · Network Service Discovery</span>'

            card = f"""
            <div class="finding-card {sev_class}" data-severity="{sev_val}" data-title="{esc(f.title.lower())}" data-id="{esc(f.id.lower())}">
                <div class="fcard-header">
                    <div class="fcard-meta-top">
                        <span class="sev-pill sev-{sev_class}">{sev_val}</span>
                        <span class="fid-tag">{esc(f.id)}</span>
                        {cve_badge}
                        {kev_badge}
                        {tactic_badge}
                        <span class="score-pill">CVSS {cvss_val}</span>
                        <span class="score-pill">EPSS {epss_pct}</span>
                        <span class="score-pill score-risk">Risk Score {risk_score_val}/100</span>
                    </div>
                    <h3 class="fcard-title">{esc(f.title)}</h3>
                    <div class="fcard-asset-row">
                        <span><b>Target:</b> <code>{esc(f.target)}</code></span>
                        {f'<span><b>Port:</b> <code>{f.port}</code></span>' if f.port else ''}
                        {f'<span><b>Service:</b> <code>{esc(f.service)}</code></span>' if f.service else ''}
                        <span><b>Confidence:</b> {esc(getattr(f, "confidence", "HIGH"))}</span>
                    </div>
                </div>

                <div class="fcard-body">
                    <div class="fcard-section">
                        <div class="fcard-subtitle">Vulnerability Overview</div>
                        <p class="fcard-desc">{esc(f.description)}</p>
                    </div>

                    <div class="fcard-section">
                        <div class="fcard-subtitle">Technical Evidence &amp; Proof of Vulnerability</div>
                        <pre class="evidence-block"><code>{esc(f.evidence)}</code></pre>
                    </div>

                    {remediation_html}
                    {refs_html}
                </div>
            </div>
            """
            findings_cards_html.append(card)

        # Render Services Table
        services_rows_html = []
        for s in all_services:
            p = s.get("port", "—")
            proto = s.get("protocol", "tcp").upper()
            svc_name = s.get("service_name") or "unknown"
            product = s.get("product") or "—"
            ver = s.get("version") or "—"
            tls_badge = '<span class="badge badge-ok">TLS Enabled</span>' if s.get("tls") else '<span class="badge badge-dim">Plaintext</span>'
            banner = s.get("banner") or "—"

            services_rows_html.append(f"""
            <tr>
                <td class="mono font-bold">{p}/{proto}</td>
                <td class="mono">{esc(svc_name)}</td>
                <td>{esc(product)}</td>
                <td class="mono">{esc(ver)}</td>
                <td>{tls_badge}</td>
                <td class="mono truncate-cell" title="{esc(banner)}">{esc(banner[:70])}{'…' if len(banner) > 70 else ''}</td>
            </tr>
            """)

        # Assemble full HTML
        findings_joined = "\n".join(findings_cards_html) if findings_cards_html else """
        <div class="empty-dossier">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#3ddc97" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><polyline points="9 12 11 14 15 10"/></svg>
            <h3>Zero Vulnerabilities Detected</h3>
            <p>Target host demonstrates hardened security posture with no high, medium, or low findings.</p>
        </div>
        """

        services_table_html = "\n".join(services_rows_html) if services_rows_html else """
        <tr><td colspan="6" style="text-align:center;color:#6b7280;padding:24px;">No open ports or services discovered on target.</td></tr>
        """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aegis AI Security Assessment Report — {esc(report.target)}</title>
<style>
/* ═══════════════════════════════════════════════════════════════════════
   AEGIS AI ENTERPRISE SECURITY REPORT DESIGN SYSTEM
   Palantir / Stripe / Vercel restraint, dark command-center + print mode.
   ═══════════════════════════════════════════════════════════════════════ */
:root {{
  --bg: #06070a;
  --surface: #0c0e14;
  --surface-raised: #121620;
  --surface-sunken: #08090d;
  --border: rgba(255,255,255,.08);
  --border-strong: rgba(255,255,255,.14);
  --accent: #9ab8ff;
  --accent-soft: rgba(154,184,255,.10);
  --text: #eceef3;
  --text-muted: #8a92a5;
  --text-dim: #545c70;
  --critical: #ff4d5e;
  --high: #ff8a4c;
  --medium: #f2c14e;
  --low: #6ea8ff;
  --info: #7b8497;
  --success: #3ddc97;
  --font: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --mono: 'JetBrains Mono', 'Cascadia Code', Consolas, monospace;
  --radius: 12px;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  font-size: 13.5px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  padding: 32px 24px 80px;
}}

.report-container {{
  max-width: 1240px;
  margin: 0 auto;
}}

/* Header Banner */
.report-header {{
  background: linear-gradient(180deg, rgba(255,255,255,.03) 0%, rgba(255,255,255,.01) 100%);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 32px 36px;
  position: relative;
  overflow: hidden;
  box-shadow: 0 20px 40px rgba(0,0,0,.45);
}}

.report-header::before {{
  content: '';
  position: absolute;
  top: -120px;
  right: -80px;
  width: 440px;
  height: 440px;
  background: radial-gradient(circle, rgba(154,184,255,.12) 0%, transparent 70%);
  pointer-events: none;
}}

.header-top {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 20px;
  margin-bottom: 24px;
}}

.brand-row {{
  display: flex;
  align-items: center;
  gap: 14px;
}}

.brand-logo {{
  width: 42px;
  height: 42px;
  border-radius: 10px;
  background: linear-gradient(135deg, #182032 0%, #0c0e14 100%);
  border: 1px solid rgba(154,184,255,.25);
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 4px 14px rgba(0,0,0,.4);
}}

.brand-text h1 {{
  font-size: 20px;
  font-weight: 700;
  letter-spacing: -.02em;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 8px;
}}

.brand-text p {{
  font-size: 11.5px;
  color: var(--text-muted);
  letter-spacing: .02em;
}}

.badge-classified {{
  font-family: var(--mono);
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: .1em;
  text-transform: uppercase;
  background: rgba(255,77,94,.12);
  color: var(--critical);
  border: 1px solid rgba(255,77,94,.25);
  padding: 6px 14px;
  border-radius: 20px;
}}

.target-hero {{
  margin-top: 10px;
}}

.target-hero-label {{
  font-size: 11px;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: .08em;
  text-transform: uppercase;
  margin-bottom: 4px;
}}

.target-hero-title {{
  font-size: 30px;
  font-weight: 700;
  letter-spacing: -.03em;
  color: #ffffff;
  word-break: break-all;
}}

.meta-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
}}

.meta-item {{
  display: flex;
  flex-direction: column;
  gap: 3px;
}}

.meta-item .lbl {{
  font-size: 10.5px;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--text-dim);
  font-weight: 600;
}}

.meta-item .val {{
  font-size: 13px;
  font-family: var(--mono);
  color: var(--text);
  font-weight: 500;
}}

/* Executive Summary Strip */
.section-title {{
  font-size: 15px;
  font-weight: 700;
  letter-spacing: -.01em;
  color: #fff;
  margin: 40px 0 16px;
  display: flex;
  align-items: center;
  gap: 10px;
}}

.section-title::before {{
  content: '';
  width: 4px;
  height: 16px;
  background: var(--accent);
  border-radius: 2px;
}}

.posture-grid {{
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 20px;
}}

@media (max-width: 900px) {{
  .posture-grid {{ grid-template-columns: 1fr; }}
}}

.posture-gauge-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 28px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  position: relative;
}}

.gauge-circle {{
  width: 130px;
  height: 130px;
  border-radius: 50%;
  border: 6px solid var(--surface-raised);
  border-top-color: {posture_color};
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  margin-bottom: 16px;
}}

.gauge-score {{
  font-size: 38px;
  font-weight: 300;
  font-family: var(--mono);
  color: #fff;
  line-height: 1;
}}

.gauge-grade {{
  font-size: 12px;
  font-weight: 700;
  color: {posture_color};
  letter-spacing: .08em;
  text-transform: uppercase;
  margin-top: 4px;
}}

.gauge-label {{
  font-size: 13px;
  font-weight: 700;
  color: #fff;
  letter-spacing: .02em;
}}

.gauge-sub {{
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 4px;
}}

.metrics-matrix {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px;
}}

.metric-box {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}}

.metric-box.crit {{ border-color: rgba(255,77,94,.3); background: rgba(255,77,94,.03); }}
.metric-box.high {{ border-color: rgba(255,138,76,.3); background: rgba(255,138,76,.03); }}
.metric-box.med {{ border-color: rgba(242,193,78,.3); background: rgba(242,193,78,.03); }}
.metric-box.low {{ border-color: rgba(110,168,255,.3); background: rgba(110,168,255,.03); }}

.metric-box .m-count {{
  font-size: 30px;
  font-weight: 300;
  font-family: var(--mono);
  color: #fff;
  line-height: 1;
}}

.metric-box.crit .m-count {{ color: var(--critical); }}
.metric-box.high .m-count {{ color: var(--high); }}
.metric-box.med .m-count {{ color: var(--medium); }}
.metric-box.low .m-count {{ color: var(--low); }}

.metric-box .m-label {{
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--text-muted);
}}

/* Attack Surface Services Table */
.data-table-wrap {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  overflow: hidden;
}}

table.data-table {{
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 12.5px;
}}

table.data-table th {{
  background: var(--surface-raised);
  padding: 12px 16px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}}

table.data-table td {{
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  color: var(--text);
}}

table.data-table tr:last-child td {{ border-bottom: none; }}
table.data-table tr:hover td {{ background: rgba(255,255,255,.015); }}

.mono {{ font-family: var(--mono); }}
.font-bold {{ font-weight: 700; }}
.truncate-cell {{ max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

/* Filter Toolbar */
.toolbar-wrap {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 16px;
}}

.filter-pills {{
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}}

.fpill {{
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text-muted);
  padding: 6px 14px;
  border-radius: 20px;
  font-size: 11.5px;
  font-weight: 600;
  cursor: pointer;
  transition: all .15s;
}}

.fpill:hover, .fpill.active {{
  background: var(--surface-raised);
  color: #fff;
  border-color: var(--accent);
}}

.search-input-wrap input {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 7px 16px;
  font-size: 12px;
  color: #fff;
  outline: none;
  width: 240px;
}}

.search-input-wrap input:focus {{
  border-color: var(--accent);
}}

.btn-ctrl {{
  background: rgba(255,255,255,.05);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 6px 14px;
  border-radius: 8px;
  font-size: 11.5px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}}

.btn-ctrl:hover {{
  background: rgba(255,255,255,.1);
}}

/* Finding Cards */
.finding-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  margin-bottom: 16px;
  overflow: hidden;
  transition: transform .15s, border-color .15s;
}}

.finding-card.critical {{ border-left: 4px solid var(--critical); }}
.finding-card.high {{ border-left: 4px solid var(--high); }}
.finding-card.medium {{ border-left: 4px solid var(--medium); }}
.finding-card.low {{ border-left: 4px solid var(--low); }}
.finding-card.info {{ border-left: 4px solid var(--info); }}

.fcard-header {{
  padding: 22px 26px 18px;
  background: linear-gradient(180deg, rgba(255,255,255,.015) 0%, transparent 100%);
  border-bottom: 1px solid var(--border);
}}

.fcard-meta-top {{
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}}

.sev-pill {{
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 4px;
  letter-spacing: .04em;
}}

.sev-critical {{ background: rgba(255,77,94,.15); color: var(--critical); border: 1px solid rgba(255,77,94,.3); }}
.sev-high {{ background: rgba(255,138,76,.15); color: var(--high); border: 1px solid rgba(255,138,76,.3); }}
.sev-medium {{ background: rgba(242,193,78,.15); color: var(--medium); border: 1px solid rgba(242,193,78,.3); }}
.sev-low {{ background: rgba(110,168,255,.15); color: var(--low); border: 1px solid rgba(110,168,255,.3); }}
.sev-info {{ background: rgba(123,132,151,.15); color: var(--info); border: 1px solid rgba(123,132,151,.3); }}

.fid-tag {{
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text-muted);
}}

.score-pill {{
  font-family: var(--mono);
  font-size: 10.5px;
  background: rgba(255,255,255,.05);
  border: 1px solid var(--border);
  padding: 2px 8px;
  border-radius: 12px;
  color: var(--text);
}}

.score-risk {{
  background: rgba(154,184,255,.10);
  border-color: rgba(154,184,255,.25);
  color: var(--accent);
  font-weight: 600;
}}

.badge {{
  font-size: 10px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 12px;
}}

.badge-kev {{ background: rgba(255,77,94,.2); color: #ff6b7a; border: 1px solid var(--critical); }}
.badge-cve {{ background: rgba(183,156,255,.15); color: #c4b5fd; font-family: var(--mono); }}
.badge-mitre {{ background: rgba(61,220,151,.12); color: #3ddc97; }}
.badge-ok {{ background: rgba(61,220,151,.15); color: #3ddc97; }}
.badge-dim {{ background: rgba(255,255,255,.05); color: var(--text-dim); }}

.fcard-title {{
  font-size: 17px;
  font-weight: 600;
  color: #ffffff;
  letter-spacing: -.01em;
  margin-bottom: 8px;
}}

.fcard-asset-row {{
  display: flex;
  align-items: center;
  gap: 16px;
  font-size: 11.5px;
  color: var(--text-muted);
  flex-wrap: wrap;
}}

.fcard-asset-row code {{
  background: rgba(255,255,255,.05);
  padding: 1px 6px;
  border-radius: 4px;
  color: var(--text);
}}

.fcard-body {{
  padding: 22px 26px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}}

.fcard-section {{
  display: flex;
  flex-direction: column;
  gap: 6px;
}}

.fcard-subtitle {{
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--text-dim);
}}

.fcard-desc {{
  font-size: 13px;
  color: var(--text);
  line-height: 1.6;
}}

.evidence-block {{
  background: var(--surface-sunken);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
  font-family: var(--mono);
  font-size: 11.5px;
  color: #9ab8ff;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 240px;
  overflow-y: auto;
}}

.remediation-box {{
  background: rgba(61,220,151,.03);
  border: 1px solid rgba(61,220,151,.25);
  border-radius: 10px;
  padding: 14px 18px;
}}

.rem-title {{
  color: #3ddc97 !important;
}}

.rem-text {{
  font-size: 12.5px;
  color: var(--text);
}}

.ref-list {{
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 4px;
}}

.ref-list li a {{
  color: var(--accent);
  text-decoration: none;
  font-family: var(--mono);
  font-size: 11px;
}}

.ref-list li a:hover {{
  text-decoration: underline;
}}

.empty-dossier {{
  text-align: center;
  padding: 48px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  color: var(--text-muted);
}}

.empty-dossier svg {{ margin-bottom: 12px; }}

/* Footer */
.report-footer {{
  margin-top: 60px;
  padding-top: 24px;
  border-top: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  font-size: 11.5px;
  color: var(--text-dim);
}}

/* ═══════════════════════════════════════════════════════════════════════
   PRINT / PDF EXPORT HIGH-CONTRAST STYLESHEET
   Triggered via Browser Print (Ctrl+P -> Save as PDF)
   ═══════════════════════════════════════════════════════════════════════ */
@media print {{
  body {{
    background: #ffffff !important;
    color: #111827 !important;
    font-size: 11pt !important;
    padding: 0 !important;
  }}
  .toolbar-wrap, .btn-ctrl {{ display: none !important; }}
  .report-header {{
    background: #ffffff !important;
    color: #111827 !important;
    border: 1px solid #d1d5db !important;
    box-shadow: none !important;
  }}
  .report-header::before {{ display: none !important; }}
  .brand-text h1, .target-hero-title, .fcard-title {{ color: #111827 !important; }}
  .posture-gauge-card, .metric-box, .finding-card, .data-table-wrap {{
    background: #ffffff !important;
    border: 1px solid #e5e7eb !important;
    box-shadow: none !important;
    page-break-inside: avoid !important;
  }}
  table.data-table th {{
    background: #f3f4f6 !important;
    color: #374151 !important;
    border-bottom: 1px solid #d1d5db !important;
  }}
  table.data-table td {{
    color: #111827 !important;
    border-bottom: 1px solid #e5e7eb !important;
  }}
  .evidence-block {{
    background: #f9fafb !important;
    color: #1f2937 !important;
    border: 1px solid #e5e7eb !important;
  }}
  .remediation-box {{
    background: #f0fdf4 !important;
    border: 1px solid #86efac !important;
  }}
  .rem-text {{ color: #15803d !important; }}
}}
</style>
</head>
<body>

<div class="report-container">
  <!-- Top Assessment Banner -->
  <header class="report-header">
    <div class="header-top">
      <div class="brand-row">
        <div class="brand-logo">
          <!-- Globitech Ghana Vector Mark -->
          <svg width="24" height="24" viewBox="0 0 32 32" fill="none">
            <path d="M16 2L29 9.5V22.5L16 30L3 22.5V9.5L16 2Z" stroke="#9ab8ff" stroke-width="2.2" stroke-linejoin="round"/>
            <path d="M16 8L23 12V20L16 24L9 20V12L16 8Z" fill="url(#brand-grad)"/>
            <defs>
              <linearGradient id="brand-grad" x1="9" y1="8" x2="23" y2="24" gradientUnits="userSpaceOnUse">
                <stop stop-color="#9ab8ff"/>
                <stop offset="1" stop-color="#b79cff"/>
              </linearGradient>
            </defs>
          </svg>
        </div>
        <div class="brand-text">
          <h1>Aegis AI Enterprise <span style="font-size:12px;color:var(--accent);font-weight:400;margin-left:4px;">by Globitech Ghana</span></h1>
          <p>Cybersecurity Threat Exposure &amp; Vulnerability Assessment Dossier</p>
        </div>
      </div>
      <div style="display:flex;gap:10px;align-items:center;">
        <span class="badge-classified">CONFIDENTIAL AUDIT REPORT</span>
        <button class="btn-ctrl" onclick="window.print()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
          Print / Export PDF
        </button>
      </div>
    </div>

    <div class="target-hero">
      <div class="target-hero-label">Target Assessment Subject</div>
      <div class="target-hero-title">{esc(report.target)}</div>
    </div>

    <div class="meta-grid">
      <div class="meta-item">
        <span class="lbl">Assessment ID</span>
        <span class="val">{esc(report.scan_id)}</span>
      </div>
      <div class="meta-item">
        <span class="lbl">Execution Date</span>
        <span class="val">{started_str}</span>
      </div>
      <div class="meta-item">
        <span class="lbl">Duration</span>
        <span class="val">{duration_str}</span>
      </div>
      <div class="meta-item">
        <span class="lbl">Report Generated</span>
        <span class="val">{generated_at}</span>
      </div>
    </div>
  </header>

  <!-- Executive Summary -->
  <div class="section-title">Executive Summary &amp; Posture Scorecard</div>
  <div class="posture-grid">
    <div class="posture-gauge-card">
      <div class="gauge-circle">
        <div class="gauge-score">{posture_score}</div>
        <div class="gauge-grade">{posture_grade}</div>
      </div>
      <div class="gauge-label">{posture_label}</div>
      <div class="gauge-sub">Composite Security Posture Index</div>
    </div>

    <div class="metrics-matrix">
      <div class="metric-box crit">
        <div class="m-count">{crit_count}</div>
        <div class="m-label">Critical Severity</div>
      </div>
      <div class="metric-box high">
        <div class="m-count">{high_count}</div>
        <div class="m-label">High Severity</div>
      </div>
      <div class="metric-box med">
        <div class="m-count">{med_count}</div>
        <div class="m-label">Medium Severity</div>
      </div>
      <div class="metric-box low">
        <div class="m-count">{low_count}</div>
        <div class="m-label">Low / Informational</div>
      </div>
      <div class="metric-box" style="border-color:rgba(154,184,255,.3);background:rgba(154,184,255,.04)">
        <div class="m-count" style="color:var(--accent)">{len(unique_ports)}</div>
        <div class="m-label">Open Ports</div>
      </div>
      <div class="metric-box" style="border-color:rgba(255,77,94,.4);background:rgba(255,77,94,.05)">
        <div class="m-count" style="color:var(--critical)">{kev_count}</div>
        <div class="m-label">CISA KEV Weaponized</div>
      </div>
    </div>
  </div>

  <!-- Attack Surface Inventory -->
  <div class="section-title">Attack Surface &amp; Enumerated Network Services ({len(all_services)})</div>
  <div class="data-table-wrap">
    <table class="data-table">
      <thead>
        <tr>
          <th>Port / Proto</th>
          <th>Service Name</th>
          <th>Product</th>
          <th>Version</th>
          <th>Transport Security</th>
          <th>Captured Banner Evidence</th>
        </tr>
      </thead>
      <tbody>
        {services_table_html}
      </tbody>
    </table>
  </div>

  <!-- Vulnerability Dossier -->
  <div class="section-title">Vulnerability &amp; Threat Dossier ({len(all_findings)} Findings)</div>
  
  <div class="toolbar-wrap">
    <div class="filter-pills">
      <button class="fpill active" onclick="filterFindings('ALL', this)">All ({len(all_findings)})</button>
      <button class="fpill" onclick="filterFindings('CRITICAL', this)">Critical ({crit_count})</button>
      <button class="fpill" onclick="filterFindings('HIGH', this)">High ({high_count})</button>
      <button class="fpill" onclick="filterFindings('MEDIUM', this)">Medium ({med_count})</button>
      <button class="fpill" onclick="filterFindings('LOW', this)">Low ({low_count})</button>
    </div>
    <div class="search-input-wrap">
      <input type="text" id="finding-search" placeholder="Search CVE, port, or keyword..." oninput="searchFindings(this.value)">
    </div>
  </div>

  <div id="findings-container">
    {findings_joined}
  </div>

  <!-- Footer -->
  <footer class="report-footer">
    <div>
      <b>Aegis AI Security Platform</b> &bull; Developed by Globitech Ghana Security Research
    </div>
    <div>
      Confidential Assessment &bull; Not for unauthorized distribution
    </div>
  </footer>
</div>

<script>
function filterFindings(sev, btn) {{
  document.querySelectorAll('.fpill').forEach(p => p.classList.remove('active'));
  if(btn) btn.classList.add('active');

  const cards = document.querySelectorAll('.finding-card');
  cards.forEach(c => {{
    if(sev === 'ALL' || c.dataset.severity === sev) {{
      c.style.display = 'block';
    }} else {{
      c.style.display = 'none';
    }}
  }});
}}

function searchFindings(q) {{
  const term = q.trim().toLowerCase();
  const cards = document.querySelectorAll('.finding-card');
  cards.forEach(c => {{
    const title = c.dataset.title || '';
    const id = c.dataset.id || '';
    if(!term || title.includes(term) || id.includes(term)) {{
      c.style.display = 'block';
    }} else {{
      c.style.display = 'none';
    }}
  }});
}}
</script>

</body>
</html>"""
