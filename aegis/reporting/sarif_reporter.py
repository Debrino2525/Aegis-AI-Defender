"""
SARIF (Static Analysis Results Interchange Format) reporter.
Standard output format compatible with GitHub Security, Azure DevOps, CI/CD pipelines.
"""

import json
from datetime import datetime
from typing import Dict, Any
from aegis.core.models import ScanReport, Severity


SARIF_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


class SARIFReporter:
    """Generates SARIF 2.1.0 compliant vulnerability reports."""

    AEGIS_VERSION = "1.0.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    @classmethod
    def generate(cls, report: ScanReport) -> Dict[str, Any]:
        """Converts an Aegis ScanReport into a SARIF 2.1.0 document."""
        rules = {}
        results = []

        for host_result in report.hosts:
            for finding in host_result.findings:
                # Collect unique rules
                if finding.id not in rules:
                    rules[finding.id] = {
                        "id": finding.id,
                        "name": finding.id.replace("-", "_"),
                        "shortDescription": {"text": finding.title},
                        "fullDescription": {"text": finding.description},
                        "help": {"text": finding.remediation or "Refer to security documentation."},
                        "properties": {
                            "tags": ["security", "vulnerability"],
                            "cvssScore": finding.cvss_score,
                            "epssScore": finding.epss_score,
                            "isCisaKev": finding.is_cisa_kev,
                            "compositeRiskScore": finding.composite_risk_score,
                        },
                        "defaultConfiguration": {
                            "level": SARIF_LEVEL_MAP.get(finding.severity, "warning")
                        },
                        "helpUri": finding.references[0] if finding.references else "https://aegisscan.io",
                    }

                results.append({
                    "ruleId": finding.id,
                    "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
                    "message": {
                        "text": (
                            f"{finding.description}\n\n"
                            f"Evidence: {finding.evidence}\n"
                            f"Remediation: {finding.remediation or 'N/A'}"
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f"network://{host_result.host}:{finding.port or 0}"
                                }
                            },
                            "logicalLocations": [
                                {
                                    "name": f"{host_result.host}:{finding.port}",
                                    "kind": "networkHost"
                                }
                            ]
                        }
                    ],
                    "properties": {
                        "target": host_result.host,
                        "port": finding.port,
                        "service": finding.service,
                        "cvssScore": finding.cvss_score,
                        "epssScore": finding.epss_score,
                        "isCisaKev": finding.is_cisa_kev,
                        "compositeRiskScore": finding.composite_risk_score,
                        "severity": finding.severity.value,
                        "detectedAt": finding.timestamp.isoformat()
                    }
                })

        sarif_doc = {
            "$schema": cls.SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Aegis",
                            "version": cls.AEGIS_VERSION,
                            "informationUri": "https://aegisscan.io",
                            "rules": list(rules.values())
                        }
                    },
                    "results": results,
                    "properties": {
                        "scanId": report.scan_id,
                        "target": report.target,
                        "startedAt": report.started_at.isoformat(),
                        "completedAt": report.completed_at.isoformat(),
                        "durationSeconds": report.duration_seconds,
                        "totalFindings": report.total_findings,
                    }
                }
            ]
        }

        return sarif_doc

    @classmethod
    def save(cls, report: ScanReport, output_path: str):
        """Saves SARIF report to a file."""
        sarif = cls.generate(report)
        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2, default=str)
