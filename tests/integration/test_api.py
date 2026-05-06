"""Agent 10 integration TDD contract: FastAPI routes + auth enforcement."""

from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from specter.api.main import app
from specter.api.auth import create_access_token, Role
from specter.api.state import _targets, _jobs, _alerts, _profiles
from specter.models.alert import AlertSeverity, MonitoringAlert
from specter.models.person import PersonProfile
from specter.models.target import SeedInput, TargetEntity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def clear_state():
    """Reset in-memory state between tests."""
    _targets.clear()
    _jobs.clear()
    _alerts.clear()
    _profiles.clear()
    yield
    _targets.clear()
    _jobs.clear()
    _alerts.clear()
    _profiles.clear()


@pytest.fixture
def admin_token() -> str:
    return create_access_token("admin", Role.ADMIN)


@pytest.fixture
def analyst_token() -> str:
    return create_access_token("analyst", Role.ANALYST)


@pytest.fixture
def reviewer_token() -> str:
    return create_access_token("reviewer", Role.REVIEWER)


@pytest.fixture
def auditor_token() -> str:
    return create_access_token("auditor", Role.AUDITOR)


@pytest.fixture
async def client() -> AsyncClient:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


async def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# Auth
# ===========================================================================


class TestAuth:
    async def test_unauthenticated_request_rejected(self, client: AsyncClient):
        resp = await client.get("/api/targets")
        assert resp.status_code == 401

    async def test_login_valid_credentials(self, client: AsyncClient):
        resp = await client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "admin"},
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    async def test_login_invalid_credentials(self, client: AsyncClient):
        resp = await client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "wrong"},
        )
        assert resp.status_code == 401

    async def test_me_returns_operator_info(self, client: AsyncClient, admin_token: str):
        resp = await client.get("/api/auth/me", headers=await auth_headers(admin_token))
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"


# ===========================================================================
# Role enforcement
# ===========================================================================


class TestRoleEnforcement:
    async def test_analyst_cannot_manage_credentials(
        self, client: AsyncClient, analyst_token: str
    ):
        """Analysts cannot list credential configuration (admin-only)."""
        resp = await client.get(
            "/api/credentials",
            headers=await auth_headers(analyst_token),
        )
        assert resp.status_code == 403

    async def test_reviewer_cannot_trigger_collection(
        self, client: AsyncClient, reviewer_token: str, admin_token: str
    ):
        """Reviewers cannot trigger collection jobs."""
        # First create a target as admin
        target_resp = await client.post(
            "/api/targets",
            headers=await auth_headers(admin_token),
            json={"display_name": "Jane Doe",
                  "seeds": [{"seed_type": "email", "value": "jane@example.com"}]},
        )
        target_id = target_resp.json()["id"]

        # Reviewer attempts to trigger collection
        resp = await client.post(
            f"/api/targets/{target_id}/collect",
            headers=await auth_headers(reviewer_token),
        )
        assert resp.status_code == 403

    async def test_auditor_cannot_create_target(
        self, client: AsyncClient, auditor_token: str
    ):
        resp = await client.post(
            "/api/targets",
            headers=await auth_headers(auditor_token),
            json={"display_name": "Test",
                  "seeds": [{"seed_type": "email", "value": "t@x.com"}]},
        )
        assert resp.status_code == 403

    async def test_reviewer_can_read_targets(
        self, client: AsyncClient, reviewer_token: str, admin_token: str
    ):
        """Reviewers have read access to targets."""
        await client.post(
            "/api/targets",
            headers=await auth_headers(admin_token),
            json={"display_name": "Jane",
                  "seeds": [{"seed_type": "name", "value": "Jane Doe"}]},
        )
        resp = await client.get("/api/targets", headers=await auth_headers(reviewer_token))
        assert resp.status_code == 200


# ===========================================================================
# Targets
# ===========================================================================


class TestTargetRoutes:
    async def test_create_and_list_target(
        self, client: AsyncClient, admin_token: str
    ):
        resp = await client.post(
            "/api/targets",
            headers=await auth_headers(admin_token),
            json={"display_name": "Jane Doe",
                  "seeds": [{"seed_type": "email", "value": "jane@example.com"}]},
        )
        assert resp.status_code == 201
        target_id = resp.json()["id"]

        list_resp = await client.get("/api/targets", headers=await auth_headers(admin_token))
        assert list_resp.status_code == 200
        ids = [t["id"] for t in list_resp.json()]
        assert target_id in ids

    async def test_collect_endpoint_creates_job(
        self, client: AsyncClient, analyst_token: str, admin_token: str
    ):
        """POST /api/targets/{id}/collect creates a CollectionJob."""
        target_resp = await client.post(
            "/api/targets",
            headers=await auth_headers(admin_token),
            json={"display_name": "Jane Doe",
                  "seeds": [{"seed_type": "email", "value": "jane@example.com"}]},
        )
        target_id = target_resp.json()["id"]

        collect_resp = await client.post(
            f"/api/targets/{target_id}/collect",
            headers=await auth_headers(analyst_token),
        )
        assert collect_resp.status_code == 200
        job = collect_resp.json()
        assert job["target_id"] == target_id
        assert job["status"] == "pending"

    async def test_get_nonexistent_target_returns_404(
        self, client: AsyncClient, admin_token: str
    ):
        resp = await client.get(
            "/api/targets/nonexistent",
            headers=await auth_headers(admin_token),
        )
        assert resp.status_code == 404

    async def test_delete_target(
        self, client: AsyncClient, admin_token: str
    ):
        target_resp = await client.post(
            "/api/targets",
            headers=await auth_headers(admin_token),
            json={"display_name": "To Delete",
                  "seeds": [{"seed_type": "name", "value": "Delete Me"}]},
        )
        target_id = target_resp.json()["id"]
        del_resp = await client.delete(
            f"/api/targets/{target_id}",
            headers=await auth_headers(admin_token),
        )
        assert del_resp.status_code == 204


# ===========================================================================
# Graph export
# ===========================================================================


class TestGraphExport:
    async def test_graph_export_returns_graphml(
        self, client: AsyncClient, admin_token: str
    ):
        """Export returns GraphML when profile exists."""
        profile = PersonProfile(emails=["jane@example.com"], full_name="Jane Doe")
        _profiles["target-export-test"] = profile

        resp = await client.get(
            "/api/graph/export/target-export-test",
            headers=await auth_headers(admin_token),
        )
        assert resp.status_code == 200
        body = resp.text
        assert "graphml" in body.lower() or "node" in body.lower()

    async def test_graph_export_missing_profile_returns_404(
        self, client: AsyncClient, admin_token: str
    ):
        resp = await client.get(
            "/api/graph/export/no-profile-here",
            headers=await auth_headers(admin_token),
        )
        assert resp.status_code == 404


# ===========================================================================
# Alerts
# ===========================================================================


class TestAlertRoutes:
    async def test_alert_dismiss_writes_audit_log(
        self, client: AsyncClient, analyst_token: str
    ):
        """Dismissing an alert creates an audit event."""
        alert = MonitoringAlert(
            target_id="t1",
            severity=AlertSeverity.MEDIUM,
            title="Test alert",
            summary="Test",
        )
        _alerts[alert.id] = alert

        resp = await client.patch(
            f"/api/alerts/{alert.id}/dismiss",
            headers=await auth_headers(analyst_token),
        )
        assert resp.status_code == 200
        assert resp.json()["dismissed"] is True

        # Verify audit log was written
        from specter.api.routes.alerts import _audit
        from specter.models.audit import AuditAction
        events = _audit.list(action=AuditAction.ALERT_DISMISSED, resource_id=alert.id)
        assert len(events) >= 1

    async def test_list_alerts_undismissed(
        self, client: AsyncClient, admin_token: str
    ):
        alert = MonitoringAlert(
            target_id="t1", severity=AlertSeverity.HIGH,
            title="High severity alert", summary="Test",
        )
        _alerts[alert.id] = alert
        resp = await client.get("/api/alerts", headers=await auth_headers(admin_token))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1


# ===========================================================================
# Cases
# ===========================================================================


class TestCaseRoutes:
    async def test_create_case_and_add_note(
        self, client: AsyncClient, analyst_token: str
    ):
        case_resp = await client.post(
            "/api/cases",
            headers=await auth_headers(analyst_token),
            json={"name": "Op Test", "description": "Integration test case"},
        )
        assert case_resp.status_code == 201
        case_id = case_resp.json()["id"]

        note_resp = await client.post(
            f"/api/cases/{case_id}/notes",
            headers=await auth_headers(analyst_token),
            json={"content": "Initial intake complete."},
        )
        assert note_resp.status_code == 201
        assert note_resp.json()["content"] == "Initial intake complete."
