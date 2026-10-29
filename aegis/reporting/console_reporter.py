"""
Enterprise-grade terminal console reporter with Rich-powered output.
"""

import sys
import os

# Force UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from aegis.core.models import ScanReport, Finding, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim white",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED] ",
    Severity.LOW: "[LOW] ",
    Severity.INFO: "[INFO]",
}


class ConsoleReporter:
    """Renders a professional, color-coded vulnerability report to the terminal."""

    @staticmethod
    def print_report(report: ScanReport):
        """Renders the full scan report to the console."""

        # ─── Header ────────────────────────────────────────────────────────────
        console.print()
        console.print(Panel.fit(
            f"[bold cyan]AEGIS SCAN REPORT[/bold cyan]\n"
            f"[white]Scan ID:[/white] [yellow]{report.scan_id}[/yellow]  "
            f"[white]Target:[/white] [green]{report.target}[/green]  "
            f"[white]Duration:[/white] [dim]{report.duration_seconds:.1f}s[/dim]",
            border_style="cyan"
        ))

        # ─── Summary ───────────────────────────────────────────────────────────
        summary = Table(box=box.SIMPLE_HEAVY, show_header=True)
        summary.add_column("Severity", style="bold")
        summary.add_column("Count", justify="right")
        summary.add_column("Risk Level")

        severity_map = {
            Severity.CRITICAL: ("[CRIT] CRITICAL", "bold red", "Immediate action required"),
            Severity.HIGH: ("[HIGH] HIGH", "red", "Address within 24-72 hours"),
            Severity.MEDIUM: ("[MED]  MEDIUM", "yellow", "Address within 30 days"),
            Severity.LOW: ("[LOW]  LOW", "cyan", "Informational / best practice"),
            Severity.INFO: ("[INFO] INFO", "dim", "Monitoring recommended"),
        }

        for severity, (label, color, guidance) in severity_map.items():
            count = report.severity_breakdown.get(severity.value, 0)
            if count > 0:
                summary.add_row(
                    f"[{color}]{label}[/{color}]",
                    f"[{color}]{count}[/{color}]",
                    f"[dim]{guidance}[/dim]"
                )

        console.print(summary)

        if report.total_findings == 0:
            console.print("\n[bold green]✅ No vulnerabilities detected! Host appears secure based on current checks.[/bold green]\n")
            return

        # ─── Findings Table ────────────────────────────────────────────────────
        for host_result in report.hosts:
            console.print(f"\n[bold white]Host: [green]{host_result.host}[/green] ({host_result.ip})[/bold white]")
            console.print(f"[dim]Open ports: {host_result.open_ports}[/dim]\n")

            if not host_result.findings:
                continue

            table = Table(
                title=f"Vulnerability Findings — {host_result.host}",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan",
                border_style="dim cyan",
                expand=True
            )
            table.add_column("Risk", justify="center", width=6)
            table.add_column("ID", width=22)
            table.add_column("Title", width=42)
            table.add_column("Port", justify="center", width=6)
            table.add_column("CVSS", justify="center", width=5)
            table.add_column("EPSS%", justify="center", width=6)
            table.add_column("KEV", justify="center", width=4)
            table.add_column("Conf", justify="center", width=4)
            table.add_column("Score", justify="center", width=7)

            for finding in host_result.findings:
                color = SEVERITY_COLORS.get(finding.severity, "white")
                icon = SEVERITY_ICONS.get(finding.severity, " ")
                kev_badge = "[bold red]YES[/bold red]" if finding.is_cisa_kev else "[dim]no[/dim]"
                conf_color = "bold green" if finding.confidence == "HIGH" else "yellow" if finding.confidence == "MEDIUM" else "dim"

                table.add_row(
                    f"{icon}",
                    f"[{color}]{finding.id}[/{color}]",
                    f"[{color}]{finding.title[:40]}[/{color}]",
                    str(finding.port) if finding.port else "-",
                    f"[{color}]{finding.cvss_score:.1f}[/{color}]",
                    f"{finding.epss_score * 100:.0f}%",
                    kev_badge,
                    f"[{conf_color}]{finding.confidence[0]}[/{conf_color}]",
                    f"[bold {color}]{finding.composite_risk_score:.1f}[/bold {color}]",
                )

            console.print(table)

            # ─── Detailed Finding Panels ────────────────────────────────────────
            console.print("\n[bold cyan]── Detailed Findings ─────────────────────────────────────────[/bold cyan]\n")
            for i, finding in enumerate(host_result.findings, 1):
                color = SEVERITY_COLORS.get(finding.severity, "white")
                icon = SEVERITY_ICONS.get(finding.severity, " ")

                detail_text = Text()
                detail_text.append(f"Description\n", style="bold white")
                detail_text.append(f"{finding.description}\n\n", style="white")
                detail_text.append(f"Evidence\n", style="bold white")
                detail_text.append(f"{finding.evidence}\n\n", style="yellow")
                if finding.remediation:
                    detail_text.append(f"Remediation\n", style="bold green")
                    detail_text.append(f"{finding.remediation}\n", style="green")
                if finding.references:
                    detail_text.append(f"\nReferences\n", style="bold dim")
                    for ref in finding.references:
                        detail_text.append(f"  {ref}\n", style="dim")

                console.print(Panel(
                    detail_text,
                    title=f"[{color}]{icon} [{i}] {finding.id} — {finding.title}[/{color}]",
                    border_style=color.replace("bold ", ""),
                    subtitle=f"[dim]Score: {finding.composite_risk_score}/100 | CVSS: {finding.cvss_score} | EPSS: {finding.epss_score*100:.0f}%[/dim]"
                ))

        # ─── Footer ────────────────────────────────────────────────────────────
        console.print(f"\n[dim]Aegis scan completed in {report.duration_seconds:.1f}s. "
                      f"Total findings: {report.total_findings}. "
                      f"This report is for authorized security assessment only.[/dim]\n")
