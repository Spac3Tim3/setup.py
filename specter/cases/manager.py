"""In-memory case management with deconfliction."""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import uuid4

from specter.models.case import AnalystNote, Case, CaseMember, CaseStatus

logger = logging.getLogger(__name__)


class CaseManager:
    """CRUD for investigation cases with deconfliction support.

    All state is in-memory in this base implementation.
    Agent 10 (API) layers SQLite persistence on top.
    """

    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}

    def create(
        self,
        name: str,
        description: str | None = None,
        created_by: str | None = None,
        tags: list[str] | None = None,
    ) -> Case:
        """Create and register a new case."""
        case = Case(
            name=name,
            description=description,
            created_by=created_by,
            tags=tags or [],
        )
        self._cases[case.id] = case
        logger.info("Case created: %s (%s)", case.id, name)
        return case

    def get(self, case_id: str) -> Case | None:
        return self._cases.get(case_id)

    def list(self, status: CaseStatus | None = None) -> list[Case]:
        cases = list(self._cases.values())
        if status:
            cases = [c for c in cases if c.status == status]
        return cases

    def add_member(self, case_id: str, target_id: str, role: str = "subject",
                   added_by: str | None = None) -> Case:
        """Add a target to a case."""
        case = self._get_or_raise(case_id)
        member = CaseMember(target_id=target_id, role=role, added_by=added_by)
        case.members.append(member)
        case.updated_at = datetime.utcnow()
        return case

    def add_note(
        self,
        case_id: str,
        content: str,
        author_id: str,
        tags: list[str] | None = None,
    ) -> AnalystNote:
        """Append a timestamped analyst note to a case."""
        case = self._get_or_raise(case_id)
        note = AnalystNote(
            case_id=case_id,
            content=content,
            author_id=author_id,
            tags=tags or [],
        )
        case.notes.append(note)
        case.updated_at = datetime.utcnow()
        return note

    def update_status(self, case_id: str, status: CaseStatus) -> Case:
        case = self._get_or_raise(case_id)
        case.status = status
        case.updated_at = datetime.utcnow()
        return case

    def deconflict(self, target_id: str) -> list[str]:
        """Return case IDs where the given target appears as a member."""
        return [
            cid for cid, case in self._cases.items()
            if any(m.target_id == target_id for m in case.members)
        ]

    def find_shared_circle(self, target_ids: list[str]) -> list[str]:
        """Return target IDs that appear as members across multiple cases
        for different principals — deconfliction check."""
        seen: dict[str, int] = {}
        for case in self._cases.values():
            for member in case.members:
                if member.target_id not in target_ids:
                    seen[member.target_id] = seen.get(member.target_id, 0) + 1
        return [tid for tid, count in seen.items() if count > 1]

    def _get_or_raise(self, case_id: str) -> Case:
        case = self._cases.get(case_id)
        if case is None:
            raise KeyError(f"Case not found: {case_id}")
        return case
