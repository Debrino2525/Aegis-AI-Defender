"""
Unit & Integration Tests for Aegis AI Critical Alert Routing Engine.
"""

import sys
import time
import tempfile
from pathlib import Path
from datetime import datetime, timezone

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis.alerting.models import (
    CriticalAlert, SeverityLevel, DoDZTPillar, OnCallContact, AssetOwnerMapping
)
from aegis.alerting.classifier import AlertClassifier
from aegis.alerting.dedup import FlapDamper
from aegis.alerting.queue import AlertQueue
from aegis.alerting.escalation import EscalationManager
from aegis.alerting.security import generate_triage_token, verify_triage_token, sanitize_for_public_channel


def test_classifier_behavioral():
    # Test 1: C2 Beaconing must be CRITICAL with Network & Device pillars
    alert_dict = {
        "pattern_id": "AEGIS-BEH-002",
        "title": "C2 Beaconing Pattern",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.100",
        "dest_ip": "185.220.101.5",
        "dest_port": 443,
        "process": "svchost.exe",
        "tactic": "Command and Control",
        "evidence": "Regular 30s beaconing with 0.02 jitter"
    }
    res = AlertClassifier.classify_behavioral_alert(alert_dict)
    assert res is not None, "C2 Beaconing must qualify as CriticalAlert"
    assert res.severity == SeverityLevel.CRITICAL
    assert DoDZTPillar.NETWORK_ENVIRONMENT in res.zt_pillars
    assert DoDZTPillar.DEVICE in res.zt_pillars
    print("[+] test_classifier_behavioral (C2): PASSED")

    # Test 2: Low-severity scan port probe should NOT qualify as CriticalAlert
    benign_dict = {
        "pattern_id": "AEGIS-BEH-009",
        "title": "Minor Outbound Spike",
        "severity": "MEDIUM",
        "source_ip": "192.168.1.100",
        "tactic": "Discovery"
    }
    assert AlertClassifier.classify_behavioral_alert(benign_dict) is None
    print("[+] test_classifier_behavioral (Benign): PASSED")


def test_classifier_scan_finding():
    # Weaponized CISA KEV finding with high CVSS must qualify as CriticalAlert
    finding = {
        "id": "CVE-2024-38475",
        "title": "Apache HTTP Server Output Escaping Vulnerability",
        "port": 80,
        "cvss_score": 9.8,
        "epss_score": 0.85,
        "is_cisa_kev": True
    }
    res = AlertClassifier.classify_scan_finding("10.0.0.5", finding)
    assert res is not None
    assert res.severity == SeverityLevel.CRITICAL
    assert DoDZTPillar.APPLICATION_WORKLOAD in res.zt_pillars
    print("[+] test_classifier_scan_finding: PASSED")


def test_flap_damper_rate_limiting():
    damper = FlapDamper(flap_window_seconds=60, max_alerts_per_window=2)
    fp = "TEST-FINGERPRINT-001"

    # 1st: allowed
    allow, reason, count = damper.should_dispatch(fp)
    assert allow is True
    assert count == 1

    # Immediate 2nd: throttled by 60s inter-alert cooldown
    allow, reason, count = damper.should_dispatch(fp)
    assert allow is False
    assert "Throttled" in reason
    assert count == 2
    print("[+] test_flap_damper_rate_limiting: PASSED")


def test_sqlite_alert_queue():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / "test_queue.sqlite3"
        queue = AlertQueue(db_path)

        alert = CriticalAlert(
            alert_id="CALT-TEST01",
            fingerprint="FP-001",
            title="SMB Lateral Movement",
            severity=SeverityLevel.CRITICAL,
            summary="Host propagating over port 445",
            source_ip="192.168.1.50",
            zt_pillars=[DoDZTPillar.NETWORK_ENVIRONMENT]
        )

        # Enqueue
        is_new = queue.enqueue_alert(alert)
        assert is_new is True

        # Retrieve pending
        pending = queue.get_pending_alerts()
        assert len(pending) == 1
        assert pending[0]["alert_id"] == "CALT-TEST01"

        # Acknowledge
        acked = queue.acknowledge_alert("CALT-TEST01", "Analyst-Alice")
        assert acked is True

        # Now pending should be empty
        assert len(queue.get_pending_alerts()) == 0
        print("[+] test_sqlite_alert_queue: PASSED")


def test_security_tokens():
    # Valid token creation & verification
    token = generate_triage_token("CALT-ABC123", "ONCALL-PRIMARY", ttl_seconds=60)
    is_valid, payload, reason = verify_triage_token(token)
    assert is_valid is True
    assert payload["aid"] == "CALT-ABC123"
    assert payload["cid"] == "ONCALL-PRIMARY"

    # Expired token
    expired_token = generate_triage_token("CALT-ABC123", "ONCALL-PRIMARY", ttl_seconds=-10)
    is_valid, _, reason = verify_triage_token(expired_token)
    assert is_valid is False
    assert "expired" in reason.lower()

    # Public sanitization check: NO raw IPs or CVE exploit payloads leaked
    msg = sanitize_for_public_channel(
        "CALT-001", "C2 Beaconing Detected", "Production-Banking",
        [DoDZTPillar.NETWORK_ENVIRONMENT], "https://aegis.corp/triage"
    )
    assert "192.168" not in msg
    assert "https://aegis.corp/triage" in msg
    print("[+] test_security_tokens: PASSED")


def test_escalation_manager():
    mgr = EscalationManager()
    
    # Custom mapping for core banking subnet
    mgr.add_owner_mapping(AssetOwnerMapping(
        cidr_or_host="10.20.0.0/16",
        environment="Core-Banking-VLAN",
        owner_team="FinTech-Sec",
        primary_contact_id="ONCALL-PRIMARY",
        escalation_contact_id="ONCALL-LEAD",
        escalation_timeout_mins=5
    ))

    p, lead, env, timeout = mgr.resolve_contacts_for_target("10.20.5.12")
    assert env == "Core-Banking-VLAN"
    assert timeout == 5
    print("[+] test_escalation_manager: PASSED")


def test_longest_prefix_beats_default_route_order():
    """Default route must not steal alerts from a more specific subnet.

    SQLite reloads mappings ordered by cidr string, which places 0.0.0.0/0
    ahead of every other IPv4 network. First-match routing then pages the
    enterprise default for every address and never the asset owner.
    """
    mgr = EscalationManager()
    mgr.ownership_mappings = [
        AssetOwnerMapping(
            cidr_or_host="0.0.0.0/0",
            environment="Enterprise Network",
            owner_team="Security Operations",
            primary_contact_id="ONCALL-PRIMARY",
            escalation_contact_id="ONCALL-LEAD",
            escalation_timeout_mins=5,
        ),
        AssetOwnerMapping(
            cidr_or_host="10.20.0.0/16",
            environment="Core-Banking-VLAN",
            owner_team="FinTech-Sec",
            primary_contact_id="ONCALL-PRIMARY",
            escalation_contact_id="ONCALL-LEAD",
            escalation_timeout_mins=5,
        ),
        AssetOwnerMapping(
            cidr_or_host="10.20.5.0/24",
            environment="Core-Banking-App",
            owner_team="FinTech-App",
            primary_contact_id="ONCALL-LEAD",
            escalation_contact_id="ONCALL-PRIMARY",
            escalation_timeout_mins=2,
        ),
    ]

    _, lead, env, timeout = mgr.resolve_contacts_for_target("10.20.5.12")
    assert env == "Core-Banking-App"
    assert timeout == 2
    assert lead.contact_id == "ONCALL-PRIMARY"

    _, _, env, timeout = mgr.resolve_contacts_for_target("10.20.9.4")
    assert env == "Core-Banking-VLAN"
    assert timeout == 5

    _, _, env, timeout = mgr.resolve_contacts_for_target("192.168.1.20")
    assert env == "Enterprise Network"
    assert timeout == 5

    # Hostnames are not inside a subnet; they must use the default route,
    # not whichever specific mapping happens to sit last in the list.
    _, _, env, _ = mgr.resolve_contacts_for_target("payments.example.com")
    assert env == "Enterprise Network"

    # Re-saving a rule replaces the previous one instead of stacking a stale copy.
    mgr.add_owner_mapping(AssetOwnerMapping(
        cidr_or_host="10.20.0.0/16",
        environment="Core-Banking-Updated",
        owner_team="FinTech-Sec",
        primary_contact_id="ONCALL-LEAD",
        escalation_contact_id="ONCALL-PRIMARY",
        escalation_timeout_mins=9,
    ))
    assert sum(1 for m in mgr.ownership_mappings if m.cidr_or_host == "10.20.0.0/16") == 1
    _, _, env, timeout = mgr.resolve_contacts_for_target("10.20.9.4")
    assert env == "Core-Banking-Updated"
    assert timeout == 9
    print("[+] test_longest_prefix_beats_default_route_order: PASSED")


if __name__ == "__main__":
    test_classifier_behavioral()
    test_classifier_scan_finding()
    test_flap_damper_rate_limiting()
    test_sqlite_alert_queue()
    test_security_tokens()
    test_escalation_manager()
    test_longest_prefix_beats_default_route_order()
    print("\n[=== ALL CRITICAL ALERT ROUTING TESTS PASSED ===]")
