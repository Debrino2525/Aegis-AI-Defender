"""Unified asset posture: Prevent findings join enrolled hosts. No invented CVEs or hosts."""

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.assets.posture import NO_MATCH, NO_SCANS, matching_scans, posture_for_keys
from aegis.assets.identity import host_keys
from aegis.fleet.certs import load_key, sign_heartbeat
from aegis.fleet.service import reset_fleet_service
from aegis.monitor.network_monitor import NetworkMonitor
from server import analyst, app, monitor, scans

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(monkeypatch):
    reset_fleet_service(clear=True)

    async def _noop(self):
        return None

    monkeypatch.setattr(NetworkMonitor, "_sample_connections", _noop)
    with TestClient(app) as test_client:
        monitor.current_connections = []
        monitor.alerts = []
        analyst.clear()
        scans.clear()
        yield test_client
    monitor.current_connections = []
    monitor.alerts = []
    analyst.clear()
    scans.clear()
    reset_fleet_service(clear=True)


def _auth():
    return {"Authorization": f"Bearer {os.environ['AEGIS_ADMIN_TOKEN']}"}


def _sign(private_key_pem, agent_id, timestamp, nonce):
    import base64
    signature = sign_heartbeat(load_key(private_key_pem), agent_id, timestamp, nonce)
    return base64.b64encode(signature).decode("ascii")


def _enroll_heartbeat(client, hostname="app-01.corp.example", ipv4="10.20.0.14"):
    minted = client.post("/api/fleet/tokens", headers=_auth(), json={"label": "lab"})
    token = minted.json()["token"]
    enroll = client.post(
        "/api/fleet/enroll",
        json={
            "token": token,
            "hostname": hostname,
            "os_name": "Linux",
            "os_version": "6.8.0",
            "arch": "x86_64",
            "agent_version": "1.0.0",
        },
    )
    payload = enroll.json()
    agent_id = payload["agent_id"]
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = "nonce-posture-" + agent_id[-8:]
    beat = client.post(
        "/api/fleet/heartbeat",
        json={
            "agent_id": agent_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "certificate_pem": payload["certificate_pem"],
            "signature_b64": _sign(payload["private_key_pem"], agent_id, timestamp, nonce),
            "telemetry": {
                "hostname": hostname,
                "os_name": "Linux",
                "arch": "x86_64",
                "ipv4": [ipv4],
                "listen_count": 1,
                "listening_tcp": [{"ip": "0.0.0.0", "port": 443}],
            },
        },
    )
    assert beat.status_code == 200, beat.text
    return agent_id


def _scan(scan_id, target, findings, started_at="2026-10-30T20:00:00+00:00", status="done", **extra):
    payload = {
        "id": scan_id,
        "target": target,
        "status": status,
        "started_at": started_at,
        "duration": 1.2,
        "total_findings": len(findings),
        "severity_breakdown": {},
        "open_ports": extra.pop("open_ports", [443]),
        "findings": findings,
    }
    payload.update(extra)
    scans[scan_id] = payload
    return payload


def test_assets_and_fleet_empty_without_agents_or_scans(client):
    assert client.get("/api/assets").status_code == 401
    empty = client.get("/api/assets", headers=_auth())
    assert empty.status_code == 200
    assert empty.json() == {"assets": [], "unmatched_scans": []}
    fleet = client.get("/api/fleet/hosts", headers=_auth())
    assert fleet.json() == {"hosts": []}
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert "No hosts have enrolled a heartbeat" in html
    assert "/api/assets" in html
    assert "Prevent findings on the same record" in html
    assert "Scan inventory stays separate" not in html
    assert "Scan inventory (Prevent)" not in html
    assert "sample-dc01" not in html
    assert "demo-host" not in html
    script = (ROOT / "static" / "investigate.js").read_text(encoding="utf-8")
    assert "Prevent posture" in script
    assert "device.posture" in script


def test_scan_without_agent_is_unmatched_not_a_fake_host(client):
    _scan(
        "SCANONLY1",
        "198.51.100.40",
        [
            {
                "id": "AEGIS-HTTP-001",
                "title": "Missing security headers",
                "target": "198.51.100.40",
                "port": 443,
                "severity": "LOW",
                "cve_id": None,
                "evidence": "Server did not send Content-Security-Policy",
            }
        ],
    )
    catalog = client.get("/api/assets", headers=_auth()).json()
    assert catalog["assets"] == []
    assert len(catalog["unmatched_scans"]) == 1
    row = catalog["unmatched_scans"][0]
    assert row["scan_id"] == "SCANONLY1"
    assert row["target"] == "198.51.100.40"
    assert row["finding_count"] == 1
    assert "agent_id" not in row
    assert "hostname" not in row
    blob = str(catalog)
    assert "CVE-" not in blob
    assert "sample-dc01" not in blob


def test_enrolled_host_without_scans_has_empty_posture(client):
    agent_id = _enroll_heartbeat(client)
    catalog = client.get("/api/assets", headers=_auth()).json()
    assert catalog["unmatched_scans"] == []
    assert len(catalog["assets"]) == 1
    host = catalog["assets"][0]
    assert host["agent_id"] == agent_id
    posture = host["posture"]
    assert posture["finding_count"] == 0
    assert posture["cves"] == []
    assert posture["findings"] == []
    assert posture["empty_reason"] == NO_SCANS
    assert "CVE-" not in str(posture)
    fleet = client.get("/api/fleet/hosts", headers=_auth()).json()["hosts"][0]["posture"]
    inv = client.get(f"/api/investigations?host={agent_id}", headers=_auth()).json()
    assert inv["device"]["posture"] == posture == fleet


def test_scan_of_agent_address_joins_the_same_posture(client):
    agent_id = _enroll_heartbeat(client, ipv4="10.20.0.14")
    _scan(
        "SCANJOIN1",
        "10.20.0.14",
        [
            {
                "id": "CVE-2021-44228",
                "title": "Apache Log4j2 JNDI injection",
                "target": "10.20.0.14",
                "port": 443,
                "severity": "CRITICAL",
                "cve_id": "CVE-2021-44228",
                "is_cisa_kev": True,
                "evidence": "Product matched nvd CPE on 10.20.0.14:443",
            },
            {
                "id": "AEGIS-TLS-001",
                "title": "TLS 1.0 offered",
                "target": "10.20.0.14",
                "port": 443,
                "severity": "HIGH",
                "cve_id": None,
                "evidence": "Server hello included TLS 1.0",
            },
        ],
        open_ports=[443],
    )
    _scan(
        "SCANOTHER2",
        "203.0.113.90",
        [
            {
                "id": "AEGIS-HTTP-002",
                "title": "Directory listing",
                "target": "203.0.113.90",
                "port": 80,
                "severity": "MEDIUM",
                "cve_id": None,
                "evidence": "Index of / on 203.0.113.90",
            }
        ],
        open_ports=[80],
    )

    catalog = client.get("/api/assets", headers=_auth()).json()
    assert len(catalog["assets"]) == 1
    posture = catalog["assets"][0]["posture"]
    assert posture["empty_reason"] is None
    assert posture["finding_count"] == 2
    assert posture["severity_breakdown"]["CRITICAL"] == 1
    assert posture["severity_breakdown"]["HIGH"] == 1
    assert posture["kev_count"] == 1
    assert posture["scan_ids"] == ["SCANJOIN1"]
    assert posture["open_ports"] == [443]
    assert [cve["cve_id"] for cve in posture["cves"]] == ["CVE-2021-44228"]
    assert all(row["scan_id"] == "SCANJOIN1" for row in posture["findings"])
    assert catalog["unmatched_scans"][0]["scan_id"] == "SCANOTHER2"
    assert catalog["unmatched_scans"][0]["target"] == "203.0.113.90"

    fleet_posture = client.get("/api/fleet/hosts", headers=_auth()).json()["hosts"][0]["posture"]
    inv = client.get(f"/api/investigations?host={agent_id}", headers=_auth()).json()
    assert inv["device"]["posture"] == posture == fleet_posture
    assert inv["counts"]["findings"] == 2
    kinds = {item["kind"] for item in inv["timeline"]}
    assert "finding" in kinds
    assert "scan" in kinds
    assert "CVE-2021-44228" in str(inv["device"]["posture"])
    assert "203.0.113.90" not in str(inv["device"]["posture"]["findings"])
    assert "demo-host" not in str(catalog)
    assert "sample-dc01" not in str(catalog)


def test_hostname_scan_matches_and_older_scan_does_not(client):
    agent_id = _enroll_heartbeat(client, hostname="app-01.corp.example", ipv4="10.20.0.14")
    _scan(
        "SCANOLD",
        "app-01.corp.example",
        [
            {
                "id": "AEGIS-OLD-001",
                "title": "Stale finding",
                "target": "app-01.corp.example",
                "severity": "LOW",
                "cve_id": None,
                "evidence": "from an older completed scan",
            }
        ],
        started_at="2026-10-01T00:00:00+00:00",
    )
    _scan(
        "SCANNEW",
        "app-01.corp.example",
        [
            {
                "id": "AEGIS-NEW-001",
                "title": "Current finding",
                "target": "app-01.corp.example",
                "severity": "MEDIUM",
                "cve_id": None,
                "evidence": "from the latest completed scan",
            }
        ],
        started_at="2026-10-30T12:00:00+00:00",
    )
    _scan(
        "SCANRUN",
        "app-01.corp.example",
        [
            {
                "id": "AEGIS-RUN-001",
                "title": "Should not join",
                "target": "app-01.corp.example",
                "severity": "CRITICAL",
                "cve_id": "CVE-2099-0001",
                "evidence": "running scans are not posture",
            }
        ],
        started_at="2026-10-30T18:00:00+00:00",
        status="running",
    )
    posture = client.get("/api/assets", headers=_auth()).json()["assets"][0]["posture"]
    assert posture["scan_ids"] == ["SCANNEW"]
    assert [row["id"] for row in posture["findings"]] == ["AEGIS-NEW-001"]
    assert posture["cves"] == []
    inv = client.get(f"/api/investigations?host={agent_id}", headers=_auth()).json()
    assert inv["device"]["posture"] == posture
    assert "AEGIS-OLD-001" not in str(inv["device"]["posture"])
    assert "CVE-2099-0001" not in str(inv["device"]["posture"])


def test_clean_scan_joins_without_inventing_cves(client):
    agent_id = _enroll_heartbeat(client, ipv4="10.20.0.14")
    _scan("SCANCLEAN", "10.20.0.14", [], open_ports=[22, 443])
    posture = client.get("/api/assets", headers=_auth()).json()["assets"][0]["posture"]
    assert posture["empty_reason"] is None
    assert posture["finding_count"] == 0
    assert posture["cves"] == []
    assert posture["scan_ids"] == ["SCANCLEAN"]
    assert posture["open_ports"] == [22, 443]
    inv = client.get(f"/api/investigations?host={agent_id}", headers=_auth()).json()
    assert inv["device"]["posture"] == posture


def test_unrelated_finding_does_not_join(client):
    keys = host_keys({"hostname": "app-01.corp.example", "ipv4": ["10.20.0.14"], "agent_id": "agt_x"})
    scans_in = [
        {
            "id": "SCANX",
            "target": "203.0.113.7",
            "status": "done",
            "started_at": "2026-10-30T00:00:00+00:00",
            "findings": [
                {
                    "id": "F1",
                    "title": "Other host",
                    "target": "203.0.113.7",
                    "severity": "HIGH",
                    "cve_id": "CVE-2024-0001",
                }
            ],
        }
    ]
    matched = matching_scans(scans_in, keys)
    assert matched == []
    posture = posture_for_keys(keys, scans_in)
    assert posture["empty_reason"] == NO_MATCH
    assert posture["cves"] == []
    assert posture["finding_count"] == 0
