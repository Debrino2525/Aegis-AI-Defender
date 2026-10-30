"""
Aegis AI — Alert Classifier & DoD Zero Trust Pillar Tagging Engine.
Evaluates incoming behavioral telemetry and vulnerability scan findings against
strict threshold rules to qualify CRITICAL incidents and assign DoD Zero Trust pillars.
"""

import hashlib
import uuid
from typing import Dict, Any, Optional, Tuple, List
from aegis.alerting.models import CriticalAlert, SeverityLevel, DoDZTPillar
from aegis.monitor.threat_patterns import suppress_web_beacon


class AlertClassifier:
    """Classifies alerts, enforces critical thresholds, and tags with DoD Zero Trust pillars."""

    @staticmethod
    def generate_fingerprint(pattern_id: str, source_ip: str, dest_ip: Optional[str] = None, cve_id: Optional[str] = None) -> str:
        """Generates a stable SHA-256 fingerprint for deduplication and correlation."""
        key = f"{pattern_id or 'GENERIC'}:{source_ip or 'UNKNOWN'}:{dest_ip or '*'}:{cve_id or '*'}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def classify_behavioral_alert(cls, alert_dict: Dict[str, Any]) -> Optional[CriticalAlert]:
        """
        Evaluates a raw behavioral monitor alert.
        Returns a CriticalAlert if it qualifies for emergency routing, else None.
        """
        pattern_id = alert_dict.get("pattern_id", "")
        severity_str = alert_dict.get("severity", "LOW").upper()
        title = alert_dict.get("title", "Network Anomaly Detected")
        source_ip = alert_dict.get("source_ip", "127.0.0.1")
        dest_ip = alert_dict.get("dest_ip")
        dest_port = alert_dict.get("dest_port")
        process = alert_dict.get("process")
        tactic = alert_dict.get("tactic")
        technique = alert_dict.get("technique")
        evidence = alert_dict.get("evidence", "")

        is_critical = False
        zt_pillars: List[DoDZTPillar] = [DoDZTPillar.VISIBILITY_ANALYTICS]

        # Rule 1: Command and Control Beaconing. Routine web traffic is not C2.
        if pattern_id == "AEGIS-BEH-002" or "Beaconing" in title:
            if suppress_web_beacon(dest_ip or "", dest_port, 1):
                return None
            is_critical = True
            zt_pillars.extend([DoDZTPillar.NETWORK_ENVIRONMENT, DoDZTPillar.DEVICE])

        # Rule 2: Active Data Exfiltration
        elif pattern_id == "AEGIS-BEH-003" or "Exfiltration" in title:
            is_critical = True
            zt_pillars.extend([DoDZTPillar.DATA, DoDZTPillar.NETWORK_ENVIRONMENT])

        # Rule 3: SMB Lateral Movement / Worm propagation
        elif pattern_id == "AEGIS-BEH-010" or "SMB Lateral" in title:
            is_critical = True
            zt_pillars.extend([DoDZTPillar.NETWORK_ENVIRONMENT, DoDZTPillar.DEVICE])

        # Rule 4: Connection to verified Malicious Port / C2 infrastructure
        elif pattern_id == "AEGIS-BEH-004":
            is_critical = True
            zt_pillars.extend([DoDZTPillar.NETWORK_ENVIRONMENT])

        # Rule 5: Explicit CRITICAL severity with high-impact tactics
        elif severity_str == "CRITICAL" and tactic in ("Impact", "Command and Control", "Exfiltration", "Lateral Movement"):
            is_critical = True
            zt_pillars.extend([DoDZTPillar.NETWORK_ENVIRONMENT, DoDZTPillar.DEVICE])

        # Deduplicate pillar list
        zt_pillars = list(dict.fromkeys(zt_pillars))

        if not is_critical:
            return None

        alert_id = f"CALT-{uuid.uuid4().hex[:8].upper()}"
        fingerprint = cls.generate_fingerprint(pattern_id, source_ip, dest_ip)

        summary = f"{title}. Source: {source_ip} -> Dest: {dest_ip or 'N/A'}:{dest_port or 'N/A'}. Process: {process or 'Unknown'}. Evidence: {evidence}"

        return CriticalAlert(
            alert_id=alert_id,
            fingerprint=fingerprint,
            title=title,
            severity=SeverityLevel.CRITICAL,
            summary=summary,
            source_ip=source_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
            process=process,
            tactic=tactic,
            technique=technique,
            zt_pillars=zt_pillars,
            metadata={"raw_pattern_id": pattern_id, "evidence": evidence}
        )

    @classmethod
    def classify_scan_finding(cls, target: str, finding_dict: Dict[str, Any]) -> Optional[CriticalAlert]:
        """
        Evaluates a vulnerability scanner finding.
        Returns a CriticalAlert if it is weaponized (CISA KEV) with high exploit probability.
        """
        is_kev = finding_dict.get("is_cisa_kev", False)
        cvss = finding_dict.get("cvss_score", 0.0)
        epss = finding_dict.get("epss_score", 0.0)
        cve_id = finding_dict.get("cve_id") or finding_dict.get("id", "")
        title = finding_dict.get("title", f"Vulnerability {cve_id}")
        port = finding_dict.get("port")

        # Threshold: CISA KEV weaponized vulnerability with CVSS >= 8.5 OR EPSS >= 0.40
        is_critical = is_kev and (cvss >= 8.5 or epss >= 0.40)

        if not is_critical:
            return None

        alert_id = f"CALT-{uuid.uuid4().hex[:8].upper()}"
        fingerprint = cls.generate_fingerprint("SCAN_VULN", target, cve_id=cve_id)
        
        zt_pillars = [
            DoDZTPillar.APPLICATION_WORKLOAD,
            DoDZTPillar.DEVICE,
            DoDZTPillar.VISIBILITY_ANALYTICS
        ]

        summary = (
            f"Active weaponized CVE detected on {target}:{port or 'host'}. "
            f"CVE: {cve_id} (CVSS: {cvss}, EPSS: {round(epss * 100, 1)}%, CISA KEV: YES). "
            f"Adversaries are actively exploiting this in the wild."
        )

        return CriticalAlert(
            alert_id=alert_id,
            fingerprint=fingerprint,
            title=f"Weaponized Exploit Exposure: {cve_id}",
            severity=SeverityLevel.CRITICAL,
            summary=summary,
            source_ip=target,
            dest_port=port,
            cve_id=cve_id,
            cvss_score=cvss,
            epss_score=epss,
            is_cisa_kev=True,
            zt_pillars=zt_pillars,
            metadata=finding_dict
        )
