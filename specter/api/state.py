"""Shared in-memory state stores for the API layer."""

from __future__ import annotations

from specter.models.alert import MonitoringAlert
from specter.models.job import CollectionJob, JobResult
from specter.models.person import PersonProfile
from specter.models.target import TargetEntity

# These are replaced by SQLAlchemy models in production.
_targets: dict[str, TargetEntity] = {}
_jobs: dict[str, CollectionJob] = {}
_job_results: dict[str, list[JobResult]] = {}
_profiles: dict[str, PersonProfile] = {}
_alerts: dict[str, MonitoringAlert] = {}
