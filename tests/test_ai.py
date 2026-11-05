"""Comprehensive tests for advanced AI module (Phase 8)."""

import time
import pytest
from fastapi.testclient import TestClient
from aegis.ai.unsupervised import UnsupervisedLearning
from aegis.ai.predictive import PredictiveAnalytics
from aegis.ai.nlp import NaturalLanguageProcessing
from aegis.ai.api import router
from fastapi import FastAPI

app = FastAPI()
app.include_router(router)
client = TestClient(app)


# ---------------------------------------------------------------------------
# Unsupervised Learning Tests
# ---------------------------------------------------------------------------

def test_anomaly_detector_training_and_detection():
    ai = UnsupervisedLearning()
    # Baseline normal data
    training_data = [
        {"connections": 50 + (i % 5), "bytes": 1000 + (i * 10), "ports": 2}
        for i in range(50)
    ]
    model_id = ai.train_anomaly_detector(training_data, threshold_z=2.5)
    assert model_id.startswith("zscore-")

    # Normal sample
    normal_sample = {"connections": 52, "bytes": 1100, "ports": 2}
    assert not ai.detect_anomaly(model_id, normal_sample)

    # Extreme anomaly
    spike_sample = {"connections": 5000, "bytes": 9000000, "ports": 500}
    assert ai.detect_anomaly(model_id, spike_sample)

    # Anomaly detail breakdown
    detail = ai.anomaly_detail(model_id, spike_sample)
    assert detail["anomalous"] is True
    assert "connections" in detail["z_scores"]
    assert detail["z_scores"]["connections"] > 2.5
    assert detail["top_feature"] is not None


def test_reinforcement_learning_qtable():
    ai = UnsupervisedLearning()
    state = {
        "severity": "critical",
        "confidence": 0.9,
        "is_kev": True,
        "host_risk": 0.8,
    }
    decision = ai.reinforcement_learning(state)
    assert "action" in decision
    assert decision["action"] in ("observe", "recommend", "auto")
    assert "q_values" in decision

    # Record feedback reward
    ai.record_outcome(state, decision["action"], reward=10.0)
    post_decision = ai.reinforcement_learning(state)
    assert post_decision["q_values"][decision["action"]] > 0.0


def test_federated_learning():
    ai = UnsupervisedLearning()
    client_data = [
        {
            "sample_count": 100,
            "conn_rate_mean": 25.0,
            "conn_rate_std": 3.0,
            "bytes_mean": 500.0,
            "bytes_std": 50.0,
        },
        {
            "sample_count": 200,
            "conn_rate_mean": 35.0,
            "conn_rate_std": 4.0,
            "bytes_mean": 800.0,
            "bytes_std": 60.0,
        },
    ]
    result = ai.federated_learning(client_data)
    assert result["round"] == 1
    assert result["clients"] == 2
    assert "conn_rate" in result["global_baseline"]
    # Weighted mean: (25*100 + 35*200) / 300 = 9500 / 300 = 31.666667
    assert pytest.approx(result["global_baseline"]["conn_rate"]["mean"], 0.01) == 31.67


# ---------------------------------------------------------------------------
# Predictive Analytics Tests
# ---------------------------------------------------------------------------

def test_predict_next_attack():
    pred = PredictiveAnalytics()
    incident = {
        "id": "INC-101",
        "host": "srv-prod-01",
        "tactics": ["Initial Access", "Execution", "Lateral Movement"],
    }
    res = pred.predict_next_attack(incident)
    assert res["current_tactic"] == "Lateral Movement"
    assert res["predicted_tactic"] in ("Collection", "Command and Control", "Exfiltration")
    assert res["confidence"] > 0.0
    assert "preemptive_response" in res
    assert "quarantine" in res["preemptive_response"].lower() or "isolate" in res["preemptive_response"].lower() or len(res["preemptive_response"]) > 0
    assert len(res["projected_chain"]) >= 2


def test_vulnerability_forecasting():
    pred = PredictiveAnalytics()
    now = time.time()
    # Ingest historical scan trends (increasing criticals)
    for i in range(5):
        pred.ingest_scan_result({
            "timestamp": now - (5 - i) * 86400,
            "critical": 5 + i * 2,
            "high": 10 + i * 3,
            "kev_count": 1 + i,
            "total_assets": 20,
        })

    forecast = pred.forecast_vulnerabilities(time_horizon=7)
    assert len(forecast) == 7
    assert forecast[0]["day"] == 1
    assert forecast[0]["trend"] == "up"
    assert forecast[-1]["critical_forecast"] >= forecast[0]["critical_forecast"]


def test_resource_optimization():
    pred = PredictiveAnalytics()
    high_load = {
        "cpu_percent": 92.0,
        "memory_percent": 88.0,
        "active_scans": 10,
        "active_agents": 60,
    }
    opt_high = pred.optimize_resources(high_load)
    assert opt_high["throttle_monitors"] is True
    assert opt_high["pause_non_critical"] is True
    assert opt_high["recommended_concurrency"] < 10

    low_load = {
        "cpu_percent": 25.0,
        "memory_percent": 30.0,
        "active_scans": 2,
        "active_agents": 10,
    }
    opt_low = pred.optimize_resources(low_load)
    assert opt_low["throttle_monitors"] is False
    assert opt_low["pause_non_critical"] is False


def test_risk_scoring():
    pred = PredictiveAnalytics()
    findings = [
        {"severity": "critical", "is_kev": True, "epss_score": 0.8},
        {"severity": "high", "is_kev": False, "epss_score": 0.2},
    ]
    risk = pred.risk_score(findings)
    assert risk["score"] > 0
    assert risk["grade"] in ("A", "B", "C", "D", "F")
    assert risk["finding_count"] == 2


# ---------------------------------------------------------------------------
# Natural Language Processing Tests
# ---------------------------------------------------------------------------

def test_nlp_summarize_incident():
    nlp = NaturalLanguageProcessing()
    incident = {
        "id": "INC-889",
        "host": "db-primary.internal",
        "severity": "critical",
        "tactics": ["Credential Access", "Lateral Movement"],
        "cves": ["CVE-2024-21413"],
        "cvss_score": 9.8,
        "alert_count": 14,
        "status": "investigating",
    }
    summary = nlp.summarize_incident(incident)
    assert "INC-889" in summary
    assert "db-primary.internal" in summary
    assert "critical" in summary.lower()
    assert "CVE-2024-21413" in summary
    assert "Lateral Movement" in summary


def test_nlp_query_natural_language():
    nlp = NaturalLanguageProcessing()
    # Query for critical findings
    q1 = nlp.query_natural_language("show me all critical findings")
    assert q1["type"] == "findings_by_severity"
    assert q1["params"]["value"] == "critical"

    # Query with specific CVE
    q2 = nlp.query_natural_language("what is the status of CVE-2023-38606?")
    assert q2["type"] == "finding_by_cve"
    assert q2["params"]["cve"] == "CVE-2023-38606"

    # Query for open ports on host
    q3 = nlp.query_natural_language("list open ports on 192.168.1.100")
    assert q3["type"] == "open_ports"
    assert q3["params"]["host"] == "192.168.1.100"

    # Test live callback integration
    nlp.set_data_callback(lambda qtype, params: {"mock_count": 42})
    q4 = nlp.query_natural_language("how many assets do we have?")
    assert q4["result"]["mock_count"] == 42


def test_nlp_generate_report():
    nlp = NaturalLanguageProcessing()
    report_data = {
        "period_start": time.time() - 7 * 86400,
        "period_end": time.time(),
        "total_scans": 15,
        "critical_count": 3,
        "high_count": 8,
        "kev_count": 2,
        "resolved_count": 5,
        "new_count": 6,
        "risk_score": 74,
        "risk_grade": "C",
        "top_tactics": ["Initial Access", "Privilege Escalation"],
        "top_hosts": ["10.0.0.5", "10.0.0.12"],
    }
    report = nlp.generate_report(report_data, report_type="weekly")
    assert "# Aegis AI — Weekly Security Report" in report
    assert "74/100" in report
    assert "Critical findings:** 3" in report
    assert "Initial Access" in report
    assert "10.0.0.5" in report


def test_nlp_entity_extraction():
    nlp = NaturalLanguageProcessing()
    text = (
        "Host db01.corp was targeted with CVE-2021-44228 from IP 198.51.100.42 "
        "initiating Lateral Movement and Command and Control."
    )
    entities = nlp.extract_entities(text)
    assert "198.51.100.42" in entities["ips"]
    assert "CVE-2021-44228" in entities["cves"]
    assert "db01.corp" in entities["hostnames"]
    assert "Lateral Movement" in entities["tactics"]
    assert "Command and Control" in entities["tactics"]


# ---------------------------------------------------------------------------
# API Endpoints End-to-End Tests
# ---------------------------------------------------------------------------

def test_ai_api_routes():
    # 1. Train anomaly detector
    train_resp = client.post(
        "/api/ai/unsupervised/train",
        json={"data": [{"metric": 10.0 + i} for i in range(20)]},
    )
    assert train_resp.status_code == 200
    model_id = train_resp.json()["model_id"]

    # 2. Detect anomaly
    detect_resp = client.post(
        "/api/ai/unsupervised/detect",
        json={"model_id": model_id, "sample": {"metric": 500.0}},
    )
    assert detect_resp.status_code == 200
    assert detect_resp.json()["anomalous"] is True

    # 3. RL action selection & feedback
    rl_resp = client.post(
        "/api/ai/rl/select-action",
        json={"state": {"severity": "high", "confidence": 0.85, "is_kev": False}},
    )
    assert rl_resp.status_code == 200
    assert "action" in rl_resp.json()

    fb_resp = client.post(
        "/api/ai/rl/feedback",
        json={
            "state": {"severity": "high", "confidence": 0.85, "is_kev": False},
            "action": rl_resp.json()["action"],
            "reward": 5.0,
        },
    )
    assert fb_resp.status_code == 200
    assert fb_resp.json()["status"] == "recorded"

    # 4. Federated aggregation
    fed_resp = client.post(
        "/api/ai/federated/aggregate",
        json={
            "client_data": [
                {"sample_count": 50, "rate_mean": 12.0, "rate_std": 1.5},
                {"sample_count": 50, "rate_mean": 14.0, "rate_std": 2.0},
            ]
        },
    )
    assert fed_resp.status_code == 200
    assert fed_resp.json()["clients"] == 2

    # 5. Attack prediction
    pred_resp = client.post(
        "/api/ai/predict/next-attack",
        json={"incident": {"tactics": ["Initial Access"]}},
    )
    assert pred_resp.status_code == 200
    assert "predicted_tactic" in pred_resp.json()

    # 6. Optimize resources
    opt_resp = client.post(
        "/api/ai/predict/optimize-resources",
        json={"current_load": {"cpu_percent": 90, "memory_percent": 75, "active_scans": 4}},
    )
    assert opt_resp.status_code == 200
    assert opt_resp.json()["throttle_monitors"] is True

    # 7. NLP summarize & query & report
    sum_resp = client.post(
        "/api/ai/nlp/summarize",
        json={"incident": {"id": "INC-01", "host": "10.0.0.1", "severity": "critical"}},
    )
    assert sum_resp.status_code == 200
    assert "INC-01" in sum_resp.json()["summary"]

    query_resp = client.post(
        "/api/ai/nlp/query",
        json={"query": "find critical findings"},
    )
    assert query_resp.status_code == 200
    assert query_resp.json()["type"] == "findings_by_severity"

    report_resp = client.post(
        "/api/ai/nlp/generate-report",
        json={"data": {"risk_score": 85, "critical_count": 2}, "report_type": "executive"},
    )
    assert report_resp.status_code == 200
    assert "Executive Security Report" in report_resp.json()["report"]
