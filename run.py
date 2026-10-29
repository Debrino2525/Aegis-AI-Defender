"""
Aegis -- Main CLI entry point.
Usage: python run.py scan <target> [options]
"""

import asyncio
import json
import sys
import os
from pathlib import Path

# Force UTF-8 output on Windows to support rich rendering
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

from rich.console import Console
from rich.panel import Panel

from aegis.core.config import ScanConfig, TOP_PORTS
from aegis.core.engine import ScanEngine
from aegis.reporting.console_reporter import ConsoleReporter
from aegis.reporting.sarif_reporter import SARIFReporter
from aegis.reporting.html_reporter import HTMLReporter
from aegis.reporting.csv_reporter import CSVReporter
from aegis.database.db import VulnerabilityDatabase
from aegis.database.sync import ThreatFeedSync

console = Console()


def print_banner():
    console.print(Panel.fit(
        "[bold cyan]AEGIS VULNERABILITY SCANNER v1.0[/bold cyan]\n"
        "[dim]Next-Generation Vulnerability Scanner & Threat Intelligence Engine[/dim]\n"
        "[dim]Built to outperform Nessus, OpenVAS, and traditional enterprise scanners[/dim]",
        border_style="cyan"
    ))


def print_usage():
    console.print("""
[bold white]AEGIS — Usage Guide[/bold white]

  [bold cyan]Scan a target:[/bold cyan]
    python run.py scan <target>
    python run.py scan example.com
    python run.py scan 192.168.1.1

  [bold cyan]Scan with custom ports:[/bold cyan]
    python run.py scan example.com --ports 80,443,8080,8443

  [bold cyan]Save output to JSON:[/bold cyan]
    python run.py scan example.com --output json --out-file results.json

  [bold cyan]Save output as SARIF (CI/CD compatible):[/bold cyan]
    python run.py scan example.com --output sarif --out-file results.sarif

  [bold cyan]Save output as HTML (interactive report):[/bold cyan]
    python run.py scan example.com --output html --out-file results.html

  [bold cyan]Save output as CSV (spreadsheet analysis):[/bold cyan]
    python run.py scan example.com --output csv --out-file results.csv

  [bold cyan]Sync threat intelligence feeds:[/bold cyan]
    python run.py update

  [bold cyan]Options:[/bold cyan]
    --ports       Comma-separated list of ports to scan
    --concurrency Max concurrent connections (default: 250)
    --output      Output format: console, json, sarif (default: console)
    --out-file    File path to write results
""")


async def cmd_scan(args):
    if len(args) < 1:
        console.print("[red][!] Error: No target specified.[/red]")
        print_usage()
        return

    target = args[0]
    ports = TOP_PORTS
    concurrency = 250
    output_format = "console"
    out_file = None

    # Parse optional arguments
    i = 1
    while i < len(args):
        arg = args[i]
        if arg == "--ports" and i + 1 < len(args):
            ports = [int(p.strip()) for p in args[i + 1].split(",")]
            i += 2
        elif arg == "--concurrency" and i + 1 < len(args):
            concurrency = int(args[i + 1])
            i += 2
        elif arg == "--output" and i + 1 < len(args):
            output_format = args[i + 1].lower()
            i += 2
        elif arg == "--out-file" and i + 1 < len(args):
            out_file = Path(args[i + 1])
            i += 2
        else:
            i += 1

    config = ScanConfig(
        target=target,
        ports=ports,
        concurrency=concurrency,
        output_format=output_format,
        output_file=out_file
    )

    engine = ScanEngine(config)
    report = await engine.run()

    # Output
    if output_format == "console":
        ConsoleReporter.print_report(report)
    elif output_format == "json":
        json_output = report.model_dump(mode="json")
        if out_file:
            out_file.write_text(json.dumps(json_output, indent=2, default=str))
            console.print(f"[green][+] JSON report saved to: {out_file}[/green]")
        else:
            console.print(json.dumps(json_output, indent=2, default=str))
    elif output_format == "sarif":
        if out_file:
            SARIFReporter.save(report, str(out_file))
            console.print(f"[green][+] SARIF report saved to: {out_file}[/green]")
        else:
            sarif = SARIFReporter.generate(report)
            console.print(json.dumps(sarif, indent=2, default=str))
    elif output_format == "html":
        if out_file:
            HTMLReporter.save(report, str(out_file))
            console.print(f"[green][+] HTML report saved to: {out_file}[/green]")
        else:
            console.print("[red][!] HTML output requires --out-file[/red]")
            ConsoleReporter.print_report(report)
    elif output_format == "csv":
        if out_file:
            CSVReporter.save(report, str(out_file))
            console.print(f"[green][+] CSV report saved to: {out_file}[/green]")
        else:
            console.print("[red][!] CSV output requires --out-file[/red]")
            ConsoleReporter.print_report(report)
    else:
        console.print(f"[red][!] Unknown output format: {output_format}[/red]")
        ConsoleReporter.print_report(report)


async def cmd_update():
    console.print("[bold cyan][*] Syncing threat intelligence feeds...[/bold cyan]")
    data_dir = Path.home() / ".aegis"
    data_dir.mkdir(parents=True, exist_ok=True)
    db = VulnerabilityDatabase(data_dir / "vdb.sqlite3")
    syncer = ThreatFeedSync(db)

    # Sync all feeds with enhanced strategy
    results = await syncer.sync_all()

    console.print(f"\n[bold green][+] Feed sync complete.[/bold green]")
    console.print(f"    CISA KEV entries   : [cyan]{results.get('cisa_kev', 0)}[/cyan]")
    console.print(f"    NVD recent CVEs   : [cyan]{results.get('nvd_recent', 0)}[/cyan]")
    console.print(f"    NVD keyword CVEs  : [cyan]{results.get('nvd_keywords', 0)}[/cyan]")
    console.print(f"    Total CVEs added  : [cyan]{sum(results.values())}[/cyan]")


def main():
    print_banner()

    args = sys.argv[1:]
    if not args or args[0] in ("--help", "-h", "help"):
        print_usage()
        return

    command = args[0]
    rest = args[1:]

    if command == "scan":
        asyncio.run(cmd_scan(rest))
    elif command == "update":
        asyncio.run(cmd_update())
    else:
        console.print(f"[red][!] Unknown command: {command}[/red]")
        print_usage()


if __name__ == "__main__":
    main()
