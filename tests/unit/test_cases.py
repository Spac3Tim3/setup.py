"""Agent 9 TDD contract: case management, audit log, legal export."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from specter.cases.audit import AuditLogger, audit_log
from specter.cases.export import LegalExporter
from specter.cases.manager import CaseManager
from specter.models.audit import AuditAction, AuditEvent
from specter.models.case import AnalystNote, Case, CaseMember, CaseStatus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def manager() -> CaseManager:
    return CaseManager()


@pytest.fixture
def audit() -> AuditLogger:
    return AuditLogger()


@pytest.fixture
def exporter() -> LegalExporter:
    return LegalExporter()


# ===========================================================================
# CaseManager
# ===========================================================================


class TestCaseManager:
    def test_case_created_with_members(self, manager: CaseManager):
        """Case can be created and members added immediately."""
        case = manager.create(name="Operation Shield", created_by="admin")
        manager.add_member(case.id, target_id="t1", role="subject", added_by="admin")
        manager.add_member(case.id, target_id="t2", role="associate", added_by="admin")
        loaded = manager.get(case.id)
        assert loaded is not None
        assert len(loaded.members) == 2
        assert loaded.members[0].role == "subject"

    def test_analyst_note_timestamped(self, manager: CaseManager):
        """Notes receive a UTC timestamp at creation time."""
        case = manager.create(name="Op Test")
        before = datetime.utcnow()
        note = manager.add_note(case.id, content="Initial intake.", author_id="analyst1")
        after = datetime.utcnow()
        assert before <= note.created_at <= after

    def test_note_content_preserved(self, manager: CaseManager):
        case = manager.create(name="Op Note")
        note = manager.add_note(case.id, content="Reviewed breach data.", author_id="analyst1")
        assert note.content == "Reviewed breach data."

    def test_case_status_update(self, manager: CaseManager):
        case = manager.create(name="Op Status")
        assert case.status == CaseStatus.ACTIVE
        updated = manager.update_status(case.id, CaseStatus.CLOSED)
        assert updated.status == CaseStatus.CLOSED

    def test_list_by_status(self, manager: CaseManager):
        manager.create(name="Active Case")
        closed = manager.create(name="Closed Case")
        manager.update_status(closed.id, CaseStatus.CLOSED)
        active_cases = manager.list(status=CaseStatus.ACTIVE)
        assert len(active_cases) == 1
        assert active_cases[0].name == "Active Case"

    def test_deconfliction_detects_shared_circle(self, manager: CaseManager):
        """A target appearing in multiple cases triggers deconfliction."""
        case_a = manager.create(name="Case A")
        case_b = manager.create(name="Case B")
        manager.add_member(case_a.id, target_id="shared-target", role="associate")
        manager.add_member(case_b.id, target_id="shared-target", role="associate")
        manager.add_member(case_b.id, target_id="unique-target", role="subject")

        # shared-target appears in both cases for different principals
        shared = manager.find_shared_circle(["unique-target"])
        assert "shared-target" in shared

    def test_deconflict_finds_cases_for_target(self, manager: CaseManager):
        case_a = manager.create(name="Case A")
        case_b = manager.create(name="Case B")
        manager.add_member(case_a.id, "t1")
        manager.add_member(case_b.id, "t1")
        manager.add_member(case_b.id, "t2")
        cases_for_t1 = manager.deconflict("t1")
        assert case_a.id in cases_for_t1
        assert case_b.id in cases_for_t1

    def test_get_nonexistent_returns_none(self, manager: CaseManager):
        assert manager.get("nonexistent") is None

    def test_add_member_to_nonexistent_case_raises(self, manager: CaseManager):
        with pytest.raises(KeyError):
            manager.add_member("bad-id", "t1")


# ===========================================================================
# AuditLogger
# ===========================================================================


class TestAuditLogger:
    def test_audit_log_writes_on_access(self, audit: AuditLogger):
        """Logging a PROFILE_VIEWED event stores an AuditEvent."""
        event = audit.log(
            action=AuditAction.PROFILE_VIEWED,
            operator_id="analyst1",
            resource_type="target",
            resource_id="t1",
        )
        assert event.action == AuditAction.PROFILE_VIEWED
        assert event.operator_id == "analyst1"
        assert audit.count() == 1

    def test_audit_log_writes_on_job_run(self, audit: AuditLogger):
        """Logging a JOB_CREATED event stores an AuditEvent."""
        event = audit.log(
            action=AuditAction.JOB_CREATED,
            operator_id="analyst2",
            resource_type="job",
            resource_id="job-001",
        )
        assert event.action == AuditAction.JOB_CREATED
        assert audit.count() == 1

    def test_multiple_events_accumulate(self, audit: AuditLogger):
        for _ in range(5):
            audit.log(AuditAction.PROFILE_VIEWED, operator_id="op1")
        assert audit.count() == 5

    def test_filter_by_operator(self, audit: AuditLogger):
        audit.log(AuditAction.LOGIN, operator_id="op1")
        audit.log(AuditAction.LOGIN, operator_id="op2")
        audit.log(AuditAction.PROFILE_VIEWED, operator_id="op1")
        filtered = audit.list(operator_id="op1")
        assert len(filtered) == 2

    def test_filter_by_action(self, audit: AuditLogger):
        audit.log(AuditAction.LOGIN, operator_id="op1")
        audit.log(AuditAction.LOGOUT, operator_id="op1")
        audit.log(AuditAction.LOGIN, operator_id="op2")
        logins = audit.list(action=AuditAction.LOGIN)
        assert len(logins) == 2

    def test_event_has_timestamp(self, audit: AuditLogger):
        before = datetime.utcnow()
        event = audit.log(AuditAction.LOGIN, operator_id="op1")
        after = datetime.utcnow()
        assert before <= event.timestamp <= after


# ===========================================================================
# LegalExporter
# ===========================================================================


class TestLegalExporter:
    def _make_case(self, manager: CaseManager) -> Case:
        case = manager.create(name="Op Legal Test", created_by="admin")
        manager.add_member(case.id, "target-001", role="subject", added_by="admin")
        manager.add_note(case.id, "Initial intake complete.", author_id="analyst1")
        return manager.get(case.id)  # type: ignore[return-value]

    def _make_audit_trail(self, audit: AuditLogger) -> list[AuditEvent]:
        audit.log(AuditAction.CASE_CREATED, operator_id="admin", resource_type="case")
        audit.log(AuditAction.PROFILE_VIEWED, operator_id="analyst1", resource_type="target",
                  resource_id="target-001")
        return audit.list()

    def test_legal_export_contains_timestamps(self, manager: CaseManager, audit: AuditLogger,
                                               exporter: LegalExporter):
        case = self._make_case(manager)
        trail = self._make_audit_trail(audit)
        output = exporter.generate_text(case, trail, generated_by="analyst1")
        # Should contain ISO timestamps
        assert "Z" in output  # UTC marker
        assert case.created_at.isoformat()[:10] in output  # date portion

    def test_legal_export_contains_citations(self, manager: CaseManager, audit: AuditLogger,
                                              exporter: LegalExporter):
        """Export includes case ID, member IDs, and analyst note authors (citations)."""
        case = self._make_case(manager)
        trail = self._make_audit_trail(audit)
        output = exporter.generate_text(case, trail)
        assert case.id in output
        assert "target-001" in output
        assert "analyst1" in output

    def test_legal_export_has_chain_of_custody(self, manager: CaseManager,
                                                audit: AuditLogger, exporter: LegalExporter):
        case = self._make_case(manager)
        trail = self._make_audit_trail(audit)
        output = exporter.generate_text(case, trail)
        assert "CHAIN OF CUSTODY" in output
        assert "AUDIT LOG" in output

    def test_legal_export_contains_all_notes(self, manager: CaseManager,
                                              exporter: LegalExporter):
        case = manager.create(name="Op Notes Test")
        manager.add_note(case.id, "First observation.", author_id="analyst1")
        manager.add_note(case.id, "Second observation.", author_id="analyst2")
        case = manager.get(case.id)  # type: ignore[assignment]
        output = exporter.generate_text(case, [])
        assert "First observation" in output
        assert "Second observation" in output

    def test_legal_export_header_and_footer(self, manager: CaseManager,
                                             exporter: LegalExporter):
        case = manager.create(name="Header Test")
        output = exporter.generate_text(case, [])
        assert "SPECTER" in output
        assert "LEGAL EXPORT" in output
        assert "END OF LEGAL EXPORT" in output
