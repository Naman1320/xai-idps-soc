"""
Tests for Authentication and User management.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../soc-backend")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_auth_login_successful():
    """Verify admin login returns JWT."""
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["role"] == "admin"


def test_auth_login_invalid():
    """Verify bad password rejected."""
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert res.status_code == 401
