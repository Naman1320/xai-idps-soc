"""
Tests for Alert Ingestion, Filtering, Sorting, and SHAP Explainability endpoints.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../soc-backend")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_list_alerts_endpoint():
    """Verify alert listing returns seeded telemetry."""
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert data["total"] >= 1
    assert "page" in data


def test_filter_alerts_by_attack_class():
    """Verify filtering by attack class."""
    response = client.get("/api/v1/alerts?attack_class=DDoS")
    assert response.status_code == 200
    data = response.json()
    for alert in data["alerts"]:
        assert alert["attack_class"] == "DDoS"


def test_alert_explanation_endpoint():
    """Verify SHAP explanation endpoint returns feature contributions and narrative."""
    # First get an alert
    res = client.get("/api/v1/alerts")
    alerts = res.json()["alerts"]
    alert_id = alerts[0]["id"]

    exp_res = client.get(f"/api/v1/alerts/{alert_id}/explanation")
    assert exp_res.status_code == 200
    exp_data = exp_res.json()
    assert "features" in exp_data
    assert "plain_language" in exp_data
    assert "summary" in exp_data["plain_language"]
    assert "recommended_action" in exp_data["plain_language"]


def test_ingest_new_alert():
    """Verify POST /api/v1/alerts ingests an alert with SHAP values."""
    payload = {
        "source_ip": "192.168.100.55",
        "dest_ip": "10.0.0.10",
        "dest_port": 80,
        "protocol": "TCP",
        "flow_features": {"flow_duration": 0.005, "fwd_pkt_len_mean": 950.0},
        "classification": {
            "attack_class": "DDoS",
            "confidence": 0.95,
            "probabilities": {"Benign": 0.05, "DDoS": 0.95}
        },
        "shap_explanation": {
            "base_value": 0.10,
            "feature_contributions": [
                {"feature": "Fwd Packet Length Mean", "shap_value": 0.35, "feature_value": 950.0, "rank": 1},
                {"feature": "Flow Duration", "shap_value": 0.18, "feature_value": 0.005, "rank": 2}
            ]
        },
        "mitre_mapping": {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "severity": "High",
            "description": "Network Denial of Service"
        },
        "risk_score": {
            "composite": 0.89,
            "components": {
                "ml_confidence": 0.95,
                "asset_criticality": 0.9,
                "attack_severity": 0.9
            }
        }
    }

    response = client.post("/api/v1/alerts", json=payload)
    assert response.status_code == 201
    res_data = response.json()
    assert "alert_id" in res_data

    # Verify retrieval
    alert_id = res_data["alert_id"]
    get_res = client.get(f"/api/v1/alerts/{alert_id}")
    assert get_res.status_code == 200
    alert_obj = get_res.json()
    assert alert_obj["attack_class"] == "DDoS"
    assert len(alert_obj["shap_features"]) == 2
