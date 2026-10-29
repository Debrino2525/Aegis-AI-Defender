"""
CSV Report Generator.
Generates CSV reports for spreadsheet analysis and data processing.
"""

import csv
from pathlib import Path
from aegis.core.models import ScanReport


class CSVReporter:
    """Generates CSV vulnerability reports."""

    @staticmethod
    def generate(report: ScanReport) -> str:
        """Generates CSV content from ScanReport."""
        import io
        output = io.StringIO()

        fieldnames = [
            "ID", "Title", "Severity", "CVSS Score", "EPSS Score",
            "Composite Risk Score", "Confidence", "CISA KEV",
            "Target", "Port", "Service", "Description",
            "Evidence", "Remediation", "CVE ID", "Timestamp"
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for host_result in report.hosts:
            for finding in host_result.findings:
                writer.writerow({
                    "ID": finding.id,
                    "Title": finding.title,
                    "Severity": finding.severity.value,
                    "CVSS Score": finding.cvss_score,
                    "EPSS Score": finding.epss_score,
                    "Composite Risk Score": finding.composite_risk_score,
                    "Confidence": finding.confidence,
                    "CISA KEV": "Yes" if finding.is_cisa_kev else "No",
                    "Target": finding.target,
                    "Port": finding.port if finding.port else "",
                    "Service": finding.service if finding.service else "",
                    "Description": finding.description,
                    "Evidence": finding.evidence,
                    "Remediation": finding.remediation if finding.remediation else "",
                    "CVE ID": finding.cve_id if finding.cve_id else "",
                    "Timestamp": finding.timestamp.isoformat()
                })

        return output.getvalue()

    @staticmethod
    def save(report: ScanReport, output_path: str):
        """Saves CSV report to a file."""
        csv_content = CSVReporter.generate(report)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            f.write(csv_content)
