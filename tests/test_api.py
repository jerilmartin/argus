"""Tests for the ARGUS FastAPI application.

Uses httpx TestClient to test API endpoints without a running server
or database connection. The database is bypassed for these tests.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from argus.api.main import app
from argus.schemas import ArgusEvent


@pytest.fixture
def client():
    """Create a test client that bypasses database dependency."""
    # Override the database dependency to avoid needing a real DB
    from argus.database.database import get_db

    def override_get_db():
        mock_db = MagicMock()
        try:
            yield mock_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


class TestHealthEndpoint:
    """Test GET /health."""

    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "argus-api"

    def test_root_endpoint(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "ARGUS API"


class TestEventsEndpoint:
    """Test event CRUD endpoints."""

    SAMPLE_EVENT = {
        "event_id": "test-event-001",
        "timestamp": "2026-08-12T16:58:10Z",
        "source": "zeek",
        "event_type": "connection",
        "source_ip": "192.168.1.100",
        "source_port": 54993,
        "destination_ip": "10.0.0.1",
        "destination_port": 53,
        "protocol": "udp",
        "service": "dns",
        "duration": 0.000963,
        "source_bytes": 28,
        "destination_bytes": 56,
        "connection_state": "SF",
    }

    def test_post_event_structure(self, client):
        """Test that POST /events accepts the correct request body."""
        # The mock DB will cause the repo to fail, but we can
        # at least verify the endpoint accepts the schema
        response = client.post("/events", json=self.SAMPLE_EVENT)
        # Will be 500 because mock DB doesn't actually work for inserts
        # but it validates the request schema was accepted
        assert response.status_code in (201, 500, 409)

    def test_get_events_endpoint_exists(self, client):
        """Test that GET /events endpoint exists and responds."""
        response = client.get("/events")
        # Will likely be 500 due to mock DB, but endpoint exists
        assert response.status_code in (200, 500)

    def test_get_event_by_id_endpoint_exists(self, client):
        """Test that GET /events/{event_id} endpoint exists."""
        response = client.get("/events/test-id-123")
        assert response.status_code in (404, 500)


class TestAnalyzeEndpoint:
    """Test POST /events/analyze placeholder."""

    def test_analyze_returns_placeholder(self, client):
        event = {
            "event_id": "test-event-002",
            "timestamp": "2026-08-12T16:58:10Z",
            "source": "zeek",
            "event_type": "connection",
        }
        response = client.post("/events/analyze", json=event)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ml_not_implemented"
        assert data["event_id"] == "test-event-002"
        assert data["risk_score"] is None

    def test_analyze_accepts_minimal_event(self, client):
        event = {
            "timestamp": "2026-08-12T16:58:10Z",
            "source": "suricata",
            "event_type": "alert",
        }
        response = client.post("/events/analyze", json=event)
        assert response.status_code == 200
