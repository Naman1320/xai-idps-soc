"""
End-to-End Integration Test:
From detection alert JSON -> REST API Ingestion -> Database Persistence
-> SHAP Waterfall Explanation Retrieval -> Incident Case Management -> Analyst Feedback.
"""

import sys
import os
import uuid
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../soc-backend")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_full_detection_to_soc_triage_lifecycle():
    """
    Validates the entire core integration that addresses the research gap:
    Carrying ML detection + per-alert SHAP explainability through to the cloud SOC.
    """
    unique_src_ip = f"192.168.99.{uuid.uuid4().hex[:2]}"
    
    # 1. Detection Pipeline output payload
    alert_payload = {
        "source_ip": unique_src_ip,
        "dest_ip": "10.0.0.10",
        "dest_port": 80,
        "protocol": "TCP",
        "flow_features": {
            "flow_duration": 0.0035,
            "fwd_pkt_len_mean": 1380.0,
            "flow_pkts_per_sec": 28571.4,
            "syn_flag_count": 1
        },
        "classification": {
            "attack_class": "DDoS",
            "confidence": 0.965,
            "probabilities": {"Benign": 0.035, "DDoS": 0.965}
        },
        "shap_explanation": {
            "base_value": 0.10,
            "feature_contributions": [
                {"feature": "Flow Packets/s", "shap_value": 0.41, "feature_value": 28571.4, "rank": 1},
                {"feature": "Fwd Packet Length Mean", "shap_value": 0.32, "feature_value": 1380.0, "rank": 2},
                {"feature": "Flow Duration", "shap_value": 0.15, "feature_value": 0.0035, "rank": 3}
            ]
        },
        "mitre_mapping": {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "severity": "High",
            "description": "Adversaries may perform DoS attacks to degrade resource availability."
        },
        "risk_score": {
            "composite": 0.92,
            "components": {
                "ml_confidence": 0.965,
                "asset_criticality": 0.90,
                "attack_severity": 0.90
            },
            "weights": {"w1": 0.5, "w2": 0.3, "w3": 0.2}
        }
    }

    # 2. Ingest alert via API
    ingest_res = client.post(
        "/api/v1/alerts",
        json=alert_payload,
        headers={"X-API-Key": "xai-soc-pipeline-key-cicids2017"}
    )
    assert ingest_res.status_code == 201
    alert_id = ingest_res.json()["alert_id"]

    # 3. Retrieve Alert from SOC Queue
    get_res = client.get(f"/api/v1/alerts/{alert_id}")
    assert get_res.status_code == 200
    alert_data = get_res.json()
    assert alert_data["source_ip"] == unique_src_ip
    assert alert_data["risk_score"] == 0.92
    assert alert_data["attack_class"] == "DDoS"

    # 4. Retrieve SHAP Explanation & Plain Language Narrative
    exp_res = client.get(f"/api/v1/alerts/{alert_id}/explanation")
    assert exp_res.status_code == 200
    exp_data = exp_res.json()
    assert len(exp_data["features"]) == 3
    assert exp_data["features"][0]["feature_name"] == "Flow Packets/s"
    assert "DDoS" in exp_data["plain_language"]["summary"]

    # 5. Create Incident Case linking this alert
    case_payload = {
        "title": f"INC-AUTO: Ingress Flood from {unique_src_ip}",
        "severity": "critical",
        "assigned_to": "analyst",
        "notes": "Correlated high-risk volumetric spike.",
        "alert_ids": [alert_id]
    }
    case_res = client.post("/api/v1/cases", json=case_payload)
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # 6. Verify case detail has linked alert
    case_get_res = client.get(f"/api/v1/cases/{case_id}")
    assert case_get_res.status_code == 200
    assert len(case_get_res.json()["alerts"]) == 1
    assert case_get_res.json()["alerts"][0]["id"] == alert_id

    # 7. Analyst submits Ground-Truth Feedback
    fb_res = client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={
            "disposition": "true_positive",
            "notes": "Confirmed malicious volumetric attack against Web DMZ."
        }
    )
    assert fb_res.status_code == 201
    assert fb_res.json()["disposition"] == "true_positive"
