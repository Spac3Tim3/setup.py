"""Legal export package generator."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from specter.models.case import AnalystNote, Case
from specter.models.audit import AuditEvent

logger = logging.getLogger(__name__)


class LegalExporter:
    """Generates a timestamped legal export package for a case.

    Output is a plain-text representation for the base implementation.
    Agents with WeasyPrint available can render to PDF via the API layer.
    """

    def generate_text(
        self,
        case: Case,
        audit_trail: list[AuditEvent],
        generated_by: str = "system",
    ) -> str:
        """Generate a plain-text legal export."""
        now = datetime.utcnow().isoformat() + "Z"
        sections: list[str] = [
            "=" * 72,
            "SPECTER PROTECTIVE INTELLIGENCE — LEGAL EXPORT PACKAGE",
            "=" * 72,
            f"Generated: {now}  |  By: {generated_by}",
            f"Case: {case.name} (ID: {case.id})",
            f"Status: {case.status.upper()}",
            f"Created: {case.created_at.isoformat()}Z",
            "",
            "-" * 72,
            "CASE DESCRIPTION",
            "-" * 72,
            case.description or "(No description provided)",
            "",
            "-" * 72,
            "CASE MEMBERS",
            "-" * 72,
        ]
        for member in case.members:
            sections.append(
                f"  Target: {member.target_id}  |  Role: {member.role}"
                f"  |  Added: {member.added_at.isoformat()}Z"
            )

        sections += [
            "",
            "-" * 72,
            "ANALYST NOTES",
            "-" * 72,
        ]
        for note in case.notes:
            sections.append(f"[{note.created_at.isoformat()}Z] {note.author_id}:")
            sections.append(f"  {note.content}")
            if note.tags:
                sections.append(f"  Tags: {', '.join(note.tags)}")
            sections.append("")

        sections += [
            "-" * 72,
            "CHAIN OF CUSTODY — AUDIT LOG",
            "-" * 72,
        ]
        for event in sorted(audit_trail, key=lambda e: e.timestamp):
            sections.append(
                f"[{event.timestamp.isoformat()}Z] "
                f"{event.action}  operator={event.operator_id}  "
                f"resource={event.resource_type}/{event.resource_id}"
            )

        sections += [
            "",
            "=" * 72,
            "END OF LEGAL EXPORT PACKAGE",
            f"Exported at: {now}",
            "=" * 72,
        ]
        return "\n".join(sections)

    def generate_pdf(self, case: Case, audit_trail: list[AuditEvent],
                     output_path: Path, generated_by: str = "system") -> Path:
        """Generate a PDF legal export using WeasyPrint."""
        text = self.generate_text(case, audit_trail, generated_by)
        html = self._wrap_html(case, text)
        try:
            from weasyprint import HTML  # type: ignore
            HTML(string=html).write_pdf(str(output_path))
        except ImportError:
            # Fallback: write plain text
            output_path.with_suffix(".txt").write_text(text)
        return output_path

    @staticmethod
    def _wrap_html(case: Case, text: str) -> str:
        escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"""
        <!DOCTYPE html><html><head>
        <meta charset="utf-8">
        <title>Specter Legal Export — {case.name}</title>
        <style>body{{font-family:monospace;font-size:11px;white-space:pre-wrap;}}</style>
        </head><body>{escaped}</body></html>
        """
