"""Deterministic identity confidence scorer."""

from __future__ import annotations

from specter.models.person import IdentityConfidence, PersonProfile

# Score deltas (additive; clamped to [0.0, 1.0])
_FACTOR_USERNAME_EMAIL = 0.40
_FACTOR_PHONE_EMAIL = 0.30
_FACTOR_NAME_LOCATION = 0.20
_FACTOR_SINGLE_PLATFORM = 0.10
_PENALTY_CONFLICT_LOCATION = -0.20
_PENALTY_CONFLICT_NAME = -0.30


class IdentityConfidenceScorer:
    """Computes an IdentityConfidence score from two PersonProfiles.

    Typical use case: compare a new collected profile against a known baseline
    to decide whether they represent the same individual.
    """

    def score(
        self,
        candidate: PersonProfile,
        baseline: PersonProfile,
    ) -> IdentityConfidence:
        """Score the identity overlap between candidate and baseline."""
        factors: list[str] = []
        conflicts: list[str] = []
        raw = 0.0

        cand_emails = {e.lower() for e in candidate.emails}
        base_emails = {e.lower() for e in baseline.emails}
        cand_usernames = {
            s.username.lower() for s in candidate.social_presence
        }
        base_usernames = {
            s.username.lower() for s in baseline.social_presence
        }
        cand_phones = {p.number for p in candidate.phone_intel}
        base_phones = {p.number for p in baseline.phone_intel}
        cand_locations = {loc.lower() for loc in candidate.locations}
        base_locations = {loc.lower() for loc in baseline.locations}

        # Positive signals
        if cand_usernames & base_usernames and cand_emails & base_emails:
            raw += _FACTOR_USERNAME_EMAIL
            factors.append("username+email match")

        if cand_phones & base_phones and cand_emails & base_emails:
            raw += _FACTOR_PHONE_EMAIL
            factors.append("phone+email match")

        cand_name = (candidate.full_name or "").lower()
        base_name = (baseline.full_name or "").lower()
        if cand_name and base_name and cand_name == base_name and cand_locations & base_locations:
            raw += _FACTOR_NAME_LOCATION
            factors.append("name+location match")

        if cand_usernames & base_usernames and not (cand_emails & base_emails):
            raw += _FACTOR_SINGLE_PLATFORM
            factors.append("single platform match")

        # Conflict penalties
        if (
            cand_locations
            and base_locations
            and not (cand_locations & base_locations)
        ):
            raw += _PENALTY_CONFLICT_LOCATION
            conflicts.append("conflicting location signals")

        if cand_name and base_name and cand_name != base_name:
            raw += _PENALTY_CONFLICT_NAME
            conflicts.append("conflicting name signals")

        score = max(0.0, min(1.0, raw))
        return IdentityConfidence(
            score=score,
            factors=factors,
            conflicts=conflicts,
            requires_review=bool(conflicts) or score < 0.3,
        )

    def score_single(self, profile: PersonProfile) -> IdentityConfidence:
        """Score confidence that a single profile represents one person."""
        factors: list[str] = []
        raw = 0.0

        has_email = bool(profile.emails)
        has_username = bool(profile.social_presence)
        has_phone = bool(profile.phone_intel)
        has_name = bool(profile.full_name)

        if has_username and has_email:
            raw += _FACTOR_USERNAME_EMAIL
            factors.append("username+email present")
        if has_phone and has_email:
            raw += _FACTOR_PHONE_EMAIL
            factors.append("phone+email present")
        if has_name and profile.locations:
            raw += _FACTOR_NAME_LOCATION
            factors.append("name+location present")
        if has_username and not has_email:
            raw += _FACTOR_SINGLE_PLATFORM
            factors.append("single platform match")

        score = max(0.0, min(1.0, raw))
        return IdentityConfidence(
            score=score,
            factors=factors,
            requires_review=score < 0.3,
        )
