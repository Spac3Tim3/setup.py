"""Agent 0 TDD contract: every model instantiates with valid data and rejects invalid data."""

import pytest
from pydantic import ValidationError

from specter.models.alert import AlertChannel, AlertSeverity, AlertThreshold, MonitoringAlert
from specter.models.audit import AuditAction, AuditEvent
from specter.models.breach import BreachRecord, DarkWebSignal
from specter.models.case import AnalystNote, Case, CaseMember, CaseStatus
from specter.models.credential import APICredential, CollectorHealth, ServiceConfig
from specter.models.job import CollectionJob, JobResult, JobStatus
from specter.models.person import (
    CircleFinding,
    CircleMember,
    IdentityConfidence,
    ImageIntel,
    PersonProfile,
    PhoneIntel,
    SocialPresence,
)
from specter.models.records import IdentityValidation, PublicRecordResult, ShieldStatus
from specter.models.target import ProtectedIndividual, SeedInput, TargetEntity
from specter.models.threat import SockpuppetSignal, ThreatActor, ThreatSignal


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_seed(seed_type: str = "email", value: str = "test@example.com") -> SeedInput:
    return SeedInput(seed_type=seed_type, value=value)


def make_profile(name: str = "Jane Doe") -> PersonProfile:
    return PersonProfile(full_name=name, emails=["jane@example.com"])


def make_target() -> TargetEntity:
    return TargetEntity(display_name="Jane Doe", seeds=[make_seed()])


# ===========================================================================
# person.py
# ===========================================================================


class TestPhoneIntel:
    def test_valid(self):
        p = PhoneIntel(number="+15551234567", carrier="Verizon", line_type="mobile")
        assert p.number == "+15551234567"
        assert p.carrier == "Verizon"

    def test_empty_number_rejected(self):
        with pytest.raises(ValidationError):
            PhoneIntel(number="   ")

    def test_optional_fields_default_none(self):
        p = PhoneIntel(number="+15550000000")
        assert p.carrier is None
        assert p.linked_accounts == []


class TestSocialPresence:
    def test_valid(self):
        s = SocialPresence(platform="twitter", username="jdoe", url="https://twitter.com/jdoe")
        assert s.platform == "twitter"

    def test_minimal(self):
        s = SocialPresence(platform="linkedin", username="janedoe")
        assert s.url is None
        assert s.verified is False


class TestImageIntel:
    def test_valid_with_gps(self):
        img = ImageIntel(url="https://example.com/img.jpg", gps_lat=25.7617, gps_lon=-80.1918)
        assert img.gps_lat == pytest.approx(25.7617)

    def test_all_optional(self):
        img = ImageIntel()
        assert img.url is None
        assert img.face_matches == []


class TestCircleFinding:
    def test_valid(self):
        f = CircleFinding(
            member_id="abc",
            relationship="spouse",
            exposure_summary="Home address visible on voter rolls",
            risk_contribution=0.7,
        )
        assert f.risk_contribution == pytest.approx(0.7)

    def test_contribution_out_of_range(self):
        with pytest.raises(ValidationError):
            CircleFinding(
                member_id="abc",
                relationship="spouse",
                exposure_summary="test",
                risk_contribution=1.5,
            )

    def test_negative_contribution_rejected(self):
        with pytest.raises(ValidationError):
            CircleFinding(
                member_id="abc",
                relationship="spouse",
                exposure_summary="test",
                risk_contribution=-0.1,
            )


class TestIdentityConfidence:
    def test_valid(self):
        ic = IdentityConfidence(score=0.85, factors=["email+username match"])
        assert ic.score == pytest.approx(0.85)
        assert ic.requires_review is False

    def test_score_above_one_rejected(self):
        with pytest.raises(ValidationError):
            IdentityConfidence(score=1.1)

    def test_score_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            IdentityConfidence(score=-0.01)

    def test_score_boundary_values(self):
        assert IdentityConfidence(score=0.0).score == 0.0
        assert IdentityConfidence(score=1.0).score == 1.0


class TestPersonProfile:
    def test_valid_minimal(self):
        p = PersonProfile()
        assert p.id
        assert p.emails == []

    def test_valid_full(self):
        p = PersonProfile(
            full_name="Jane Doe",
            emails=["jane@example.com"],
            aliases=["J. Doe"],
            locations=["Miami, FL"],
        )
        assert p.full_name == "Jane Doe"
        assert len(p.emails) == 1

    def test_unique_id_per_instance(self):
        assert PersonProfile().id != PersonProfile().id

    def test_nested_phone_intel(self):
        p = PersonProfile(phone_intel=[PhoneIntel(number="+15550001111")])
        assert len(p.phone_intel) == 1


class TestCircleMember:
    def test_valid(self):
        member = CircleMember(relationship="spouse", profile=make_profile())
        assert member.relationship == "spouse"
        assert member.risk_score == 0.0

    def test_risk_score_out_of_range(self):
        with pytest.raises(ValidationError):
            CircleMember(relationship="spouse", profile=make_profile(), risk_score=2.0)


# ===========================================================================
# target.py
# ===========================================================================


class TestSeedInput:
    def test_valid_email_seed(self):
        s = SeedInput(seed_type="email", value="test@example.com")
        assert s.seed_type == "email"

    def test_valid_username_seed(self):
        s = SeedInput(seed_type="username", value="jdoe")
        assert s.value == "jdoe"

    def test_invalid_seed_type_rejected(self):
        with pytest.raises(ValidationError):
            SeedInput(seed_type="ssn", value="123-45-6789")

    def test_empty_value_rejected(self):
        with pytest.raises(ValidationError):
            SeedInput(seed_type="email", value="")

    def test_all_valid_seed_types(self):
        for st in ("email", "username", "phone", "name", "image", "platform_url"):
            assert SeedInput(seed_type=st, value="x").seed_type == st


class TestTargetEntity:
    def test_valid(self):
        t = make_target()
        assert t.display_name == "Jane Doe"
        assert t.active is True

    def test_no_seeds_rejected(self):
        with pytest.raises(ValidationError):
            TargetEntity(display_name="Jane Doe", seeds=[])

    def test_unique_ids(self):
        assert make_target().id != make_target().id


class TestProtectedIndividual:
    def test_valid(self):
        pi = ProtectedIndividual(
            target=make_target(),
            protection_class="judge",
            jurisdiction="FL",
        )
        assert pi.shield_active is True

    def test_invalid_protection_class_rejected(self):
        with pytest.raises(ValidationError):
            ProtectedIndividual(target=make_target(), protection_class="celebrity")

    def test_all_valid_protection_classes(self):
        for pc in ("judge", "law_enforcement", "executive", "public_official", "domestic_violence_survivor"):
            pi = ProtectedIndividual(target=make_target(), protection_class=pc)
            assert pi.protection_class == pc


# ===========================================================================
# threat.py
# ===========================================================================


class TestThreatSignal:
    def test_valid(self):
        ts = ThreatSignal(
            target_id="t1",
            signal_type="doxxing",
            source="twitter",
            raw_content="address posted",
            summary="Home address publicly posted",
            severity="high",
            confidence=0.9,
        )
        assert ts.severity == "high"

    def test_invalid_signal_type_rejected(self):
        with pytest.raises(ValidationError):
            ThreatSignal(
                target_id="t1",
                signal_type="murder",
                source="x",
                raw_content="x",
                summary="x",
                severity="high",
            )

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            ThreatSignal(
                target_id="t1",
                signal_type="doxxing",
                source="x",
                raw_content="x",
                summary="x",
                severity="extreme",
            )

    def test_confidence_out_of_range(self):
        with pytest.raises(ValidationError):
            ThreatSignal(
                target_id="t1",
                signal_type="doxxing",
                source="x",
                raw_content="x",
                summary="x",
                severity="low",
                confidence=1.5,
            )


class TestSockpuppetSignal:
    def test_valid(self):
        ss = SockpuppetSignal(
            platforms=["twitter", "reddit"],
            indicators=["creation_date_cluster", "profile_photo_reuse"],
            confidence=0.75,
        )
        assert ss.confidence == pytest.approx(0.75)

    def test_confidence_out_of_range(self):
        with pytest.raises(ValidationError):
            SockpuppetSignal(confidence=-0.1)


class TestThreatActor:
    def test_valid(self):
        actor = ThreatActor(alias="ShadowUser99", platforms=["telegram"])
        assert actor.alias == "ShadowUser99"
        assert actor.signals == []


# ===========================================================================
# breach.py
# ===========================================================================


class TestBreachRecord:
    def test_valid(self):
        br = BreachRecord(
            breach_name="ExampleBreach2023",
            data_classes=["email", "password_hash", "phone"],
            source="hibp",
        )
        assert br.breach_name == "ExampleBreach2023"
        assert "password_hash" in br.data_classes

    def test_empty_name_rejected(self):
        with pytest.raises(ValidationError):
            BreachRecord(breach_name="  ", data_classes=["email"], source="hibp")

    def test_no_raw_credentials_enforced_by_model_structure(self):
        # The model has no field for raw credentials — only data_classes labels
        br = BreachRecord(breach_name="Test", source="hibp")
        assert not hasattr(br, "plaintext_password")
        assert not hasattr(br, "password")


class TestDarkWebSignal:
    def test_valid(self):
        dws = DarkWebSignal(
            source="intelx",
            query="jane@example.com",
            result_type="paste",
            context_summary="Email found in credential paste, data class: email address",
        )
        assert dws.severity == "medium"

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            DarkWebSignal(
                source="intelx",
                query="q",
                result_type="paste",
                context_summary="test",
                severity="extreme",
            )


# ===========================================================================
# records.py
# ===========================================================================


class TestPublicRecordResult:
    def test_valid(self):
        r = PublicRecordResult(
            source="sunbiz",
            record_type="business_filing",
            subject_name="Jane Doe",
            address="123 Main St, Miami FL",
        )
        assert r.record_type == "business_filing"

    def test_minimal(self):
        r = PublicRecordResult(source="fl_elections", record_type="voter")
        assert r.subject_name is None


class TestShieldStatus:
    def test_no_violations(self):
        ss = ShieldStatus(
            individual_id="pi-1",
            protected=True,
            protection_class="judge",
        )
        assert ss.violations == []
        assert ss.protected is True

    def test_with_violations(self):
        ss = ShieldStatus(
            individual_id="pi-1",
            protected=False,
            protection_class="law_enforcement",
            violations=["Home address exposed via FL property appraiser"],
            recommendations=["File for address confidentiality program"],
        )
        assert len(ss.violations) == 1


class TestIdentityValidation:
    def test_valid(self):
        iv = IdentityValidation(target_id="t1", confidence_boost=0.3)
        assert iv.confidence_boost == pytest.approx(0.3)

    def test_boost_out_of_range(self):
        with pytest.raises(ValidationError):
            IdentityValidation(target_id="t1", confidence_boost=1.5)


# ===========================================================================
# job.py
# ===========================================================================


class TestJobStatus:
    def test_all_values(self):
        assert JobStatus.PENDING == "pending"
        assert JobStatus.RUNNING == "running"
        assert JobStatus.COMPLETED == "completed"
        assert JobStatus.FAILED == "failed"
        assert JobStatus.CANCELLED == "cancelled"


class TestCollectionJob:
    def test_valid(self):
        job = CollectionJob(target_id="t1", seeds=[make_seed()])
        assert job.status == JobStatus.PENDING
        assert job.max_depth == 4

    def test_no_seeds_rejected(self):
        with pytest.raises(ValidationError):
            CollectionJob(target_id="t1", seeds=[])

    def test_invalid_depth_rejected(self):
        with pytest.raises(ValidationError):
            CollectionJob(target_id="t1", seeds=[make_seed()], max_depth=0)


class TestJobResult:
    def test_valid(self):
        jr = JobResult(
            job_id="j1",
            collector="email",
            seed=make_seed(),
            status=JobStatus.COMPLETED,
        )
        assert jr.error is None
        assert jr.new_seeds == []

    def test_failed_with_error(self):
        jr = JobResult(
            job_id="j1",
            collector="email",
            seed=make_seed(),
            status=JobStatus.FAILED,
            error="Connection timeout",
        )
        assert jr.error == "Connection timeout"


# ===========================================================================
# credential.py
# ===========================================================================


class TestServiceConfig:
    def test_valid_paid_service(self):
        sc = ServiceConfig(
            name="Have I Been Pwned",
            api_key_required=True,
            free_tier=False,
            signup_url="https://haveibeenpwned.com/API/Key",
            docs_url="https://haveibeenpwned.com/API/v3",
            rate_limit_per_minute=10,
        )
        assert sc.api_key_required is True
        assert sc.signup_url is not None

    def test_kali_native_tool(self):
        sc = ServiceConfig(
            name="PhoneInfoga",
            api_key_required=False,
            kali_native=True,
            install_cmd="pip install phoneinfoga",
        )
        assert sc.kali_native is True
        assert sc.signup_url is None


class TestAPICredential:
    def test_valid(self):
        cred = APICredential(
            service_id="hibp",
            encrypted_key="gAAAAA...",
        )
        assert cred.valid is None  # not yet validated


class TestCollectorHealth:
    def test_available(self):
        h = CollectorHealth(service_id="hibp", available=True, configured=True, key_valid=True)
        assert h.available is True
        assert h.error is None

    def test_unavailable_with_error(self):
        h = CollectorHealth(
            service_id="intelx",
            available=False,
            configured=False,
            error="API key not configured",
        )
        assert h.available is False


# ===========================================================================
# case.py
# ===========================================================================


class TestCaseStatus:
    def test_all_values(self):
        assert CaseStatus.ACTIVE == "active"
        assert CaseStatus.CLOSED == "closed"
        assert CaseStatus.SUSPENDED == "suspended"
        assert CaseStatus.ARCHIVED == "archived"


class TestCaseMember:
    def test_valid_subject(self):
        cm = CaseMember(target_id="t1")
        assert cm.role == "subject"

    def test_valid_roles(self):
        for role in ("subject", "associate", "threat_actor"):
            assert CaseMember(target_id="t1", role=role).role == role

    def test_invalid_role_rejected(self):
        with pytest.raises(ValidationError):
            CaseMember(target_id="t1", role="spy")


class TestAnalystNote:
    def test_valid(self):
        note = AnalystNote(case_id="c1", content="Subject has new breach exposure.", author_id="op1")
        assert note.content.startswith("Subject")

    def test_empty_content_rejected(self):
        with pytest.raises(ValidationError):
            AnalystNote(case_id="c1", content="   ", author_id="op1")


class TestCase:
    def test_valid(self):
        case = Case(name="Operation Shield", created_by="admin")
        assert case.status == CaseStatus.ACTIVE
        assert case.members == []

    def test_empty_name_rejected(self):
        with pytest.raises(ValidationError):
            Case(name="")

    def test_with_members_and_notes(self):
        case = Case(
            name="Op Sunrise",
            members=[CaseMember(target_id="t1")],
            notes=[
                AnalystNote(case_id="c1", content="Initial intake complete.", author_id="op1")
            ],
        )
        assert len(case.members) == 1
        assert len(case.notes) == 1


# ===========================================================================
# audit.py
# ===========================================================================


class TestAuditAction:
    def test_all_actions_defined(self):
        actions = [
            "profile_viewed", "job_created", "job_cancelled",
            "target_created", "target_deleted", "case_created",
            "case_updated", "note_added", "credential_added",
            "credential_removed", "alert_dismissed", "export_generated",
            "login", "logout",
        ]
        for action in actions:
            assert action in AuditAction.__members__.values() or action in [a.value for a in AuditAction]


class TestAuditEvent:
    def test_valid(self):
        ev = AuditEvent(
            action=AuditAction.PROFILE_VIEWED,
            operator_id="op1",
            resource_type="target",
            resource_id="t1",
        )
        assert ev.action == AuditAction.PROFILE_VIEWED
        assert ev.id
        assert ev.timestamp

    def test_minimal(self):
        ev = AuditEvent(action=AuditAction.LOGIN, operator_id="op1")
        assert ev.resource_type is None


# ===========================================================================
# alert.py
# ===========================================================================


class TestAlertSeverity:
    def test_ordering_values(self):
        assert AlertSeverity.INFO == "info"
        assert AlertSeverity.CRITICAL == "critical"


class TestAlertChannel:
    def test_all_channels(self):
        assert AlertChannel.IN_APP == "in_app"
        assert AlertChannel.SLACK == "slack"
        assert AlertChannel.EMAIL == "email"
        assert AlertChannel.WEBHOOK == "webhook"


class TestAlertThreshold:
    def test_defaults(self):
        at = AlertThreshold()
        assert at.min_severity == AlertSeverity.MEDIUM
        assert AlertChannel.IN_APP in at.channels
        assert at.breach_count_threshold == 1

    def test_invalid_threshold_rejected(self):
        with pytest.raises(ValidationError):
            AlertThreshold(breach_count_threshold=0)

    def test_per_target_threshold(self):
        at = AlertThreshold(
            target_id="t1",
            min_severity=AlertSeverity.HIGH,
            channels=[AlertChannel.SLACK, AlertChannel.EMAIL],
        )
        assert at.target_id == "t1"


class TestMonitoringAlert:
    def test_valid(self):
        alert = MonitoringAlert(
            target_id="t1",
            severity=AlertSeverity.HIGH,
            title="New breach detected",
            summary="Target email found in BreachCo2024 breach",
            findings=["email exposed", "password_hash exposed"],
        )
        assert alert.dismissed is False
        assert alert.dismissed_by is None

    def test_empty_title_rejected(self):
        with pytest.raises(ValidationError):
            MonitoringAlert(
                target_id="t1",
                severity=AlertSeverity.LOW,
                title="",
                summary="test",
            )

    def test_dismissed_state(self):
        from datetime import datetime

        alert = MonitoringAlert(
            target_id="t1",
            severity=AlertSeverity.MEDIUM,
            title="Test alert",
            summary="Test",
            dismissed=True,
            dismissed_by="analyst1",
            dismissed_at=datetime.utcnow(),
        )
        assert alert.dismissed is True
        assert alert.dismissed_by == "analyst1"
