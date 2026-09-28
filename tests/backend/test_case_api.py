"""
Tests for Incident Case management endpoints.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../soc-backend")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_list_and_create_cases():
    """Verify case listing and creation workflows."""
    # List cases
    res = client.get("/api/v1/cases")
    assert res.status_code == 200
    cases_data = res.json()
    assert "cases" in cases_data

    # Create new case
    new_case = {
        "title": "TEST-INC-999: Investigation of Reconnaissance Spike",
        "severity": "medium",
        "assigned_to": "analyst",
        "notes": "Testing case creation from integration test suite."
    }
    create_res = client.post("/api/v1/cases", json=new_case)
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["title"] == new_case["title"]
    case_id = created["id"]

    # Update case
    update_res = client.patch(
        f"/api/v1/cases/{case_id}",
        json={"status": "resolved", "disposition": "true_positive"}
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "resolved"
