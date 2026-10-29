"""
Contextual Dynamic Risk Prioritization Engine.
Replaces raw CVSS with real-world threat-informed scoring (CVSS + EPSS + CISA KEV + Exposure).
Enhanced with confidence scoring to reduce false positives.
"""

from aegis.core.models import Finding, Severity


class RiskPrioritizationEngine:
    """Calculates prioritized risk scores to highlight immediately actionable vulnerabilities."""

    @staticmethod
    def calculate_composite_risk(
        cvss_score: float,
        epss_score: float,
        is_cisa_kev: bool,
        is_public_exposure: bool = True
    ) -> float:
        """Computes a normalized risk score from 0.0 to 100.0.

        Formula:
        - CVSS base contribution: up to 35 points (CVSS * 3.5)
        - CISA KEV contribution: 35 points if active in wild, else 0
        - EPSS score contribution: up to 20 points (EPSS * 20.0)
        - Network exposure factor: 10 points if directly accessible
        """
        cvss_component = min(10.0, max(0.0, cvss_score)) * 3.5
        kev_component = 35.0 if is_cisa_kev else 0.0
        epss_component = min(1.0, max(0.0, epss_score)) * 20.0
        exposure_component = 10.0 if is_public_exposure else 5.0

        total = cvss_component + kev_component + epss_component + exposure_component
        return round(min(100.0, max(0.0, total)), 1)

    @staticmethod
    def assign_confidence(
        detection_method: str,
        has_version: bool = False,
        is_cisa_kev: bool = False,
        is_banner_match: bool = False
    ) -> str:
        """Assigns confidence level based on detection method and evidence quality."""
        # HIGH confidence: CVE with exact version match or CISA KEV
        if is_cisa_kev and has_version:
            return "HIGH"
        if detection_method == "cve_exact_match" and has_version:
            return "HIGH"
        if detection_method == "banner_version_match" and is_banner_match:
            return "HIGH"

        # MEDIUM confidence: CVE with partial version or generic detection
        if detection_method == "cve_partial_match":
            return "MEDIUM"
        if detection_method == "service_detection" and has_version:
            return "MEDIUM"
        if detection_method == "http_header_analysis":
            return "MEDIUM"
        if detection_method == "tls_certificate_analysis":
            return "MEDIUM"

        # LOW confidence: Generic detection without version
        if detection_method == "service_detection" and not has_version:
            return "LOW"
        if detection_method == "default_port_detection":
            return "LOW"
        if detection_method == "response_pattern_match":
            return "LOW"

        return "MEDIUM"  # Default

    @classmethod
    def prioritize_finding(cls, finding: Finding, is_public: bool = True, detection_method: str = "generic") -> Finding:
        """Enriches finding with composite risk score, confidence, and adjusts severity accordingly."""
        # Assign confidence if not already set
        if not finding.confidence or finding.confidence == "MEDIUM":
            has_version = bool(finding.evidence and any(char.isdigit() for char in finding.evidence))
            finding.confidence = cls.assign_confidence(
                detection_method=detection_method,
                has_version=has_version,
                is_cisa_kev=finding.is_cisa_kev,
                is_banner_match="version" in finding.evidence.lower() if finding.evidence else False
            )

        # Calculate composite risk score
        score = cls.calculate_composite_risk(
            cvss_score=finding.cvss_score,
            epss_score=finding.epss_score,
            is_cisa_kev=finding.is_cisa_kev,
            is_public_exposure=is_public
        )
        finding.composite_risk_score = score

        # Adjust severity based on composite score and confidence
        # Low confidence findings are downgraded by one severity level
        base_severity = score
        if finding.confidence == "LOW":
            base_severity = score - 10

        if base_severity >= 80.0:
            finding.severity = Severity.CRITICAL
        elif base_severity >= 60.0:
            finding.severity = Severity.HIGH
        elif base_severity >= 40.0:
            finding.severity = Severity.MEDIUM
        elif base_severity >= 20.0:
            finding.severity = Severity.LOW
        else:
            finding.severity = Severity.INFO

        return finding
