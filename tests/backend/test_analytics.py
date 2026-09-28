"""
Tests for Analytics and Metrics endpoints.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../soc-backend")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_analytics_summary():
    """Verify summary stats endpoint."""
    res = client.get("/api/v1/analytics/summary")
    assert res.status_code == 200
    data = res.json()
    assert "total_alerts" in data
    assert "attack_classes" in data
    assert "status_breakdown" in data


def test_analytics_timeline():
    """Verify time series timeline."""
    res = client.get("/api/v1/analytics/timeline?hours=48")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_analytics_metrics():
    """Verify ML model benchmark evaluation metrics."""
    res = client.get("/api/v1/analytics/metrics")
    assert res.status_code == 200
    data = res.json()
    assert data["macro_f1"] >= 0.90
    assert "evaluation_metrics" in data
