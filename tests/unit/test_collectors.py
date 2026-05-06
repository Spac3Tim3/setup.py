"""Agent 2 TDD contract: all collectors, mocked — no live API calls."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from specter.collectors.base import BaseCollector, EthicsConstraintError
from specter.collectors.breach import BreachCollector
from specter.collectors.email import EmailCollector
from specter.collectors.image import ImageCollector
from specter.collectors.phone import PhoneCollector
from specter.collectors.registry import CollectorRegistry
from specter.collectors.social import SocialCollector
from specter.collectors.username import UsernameCollector
from specter.credentials.store import CredentialStore
from specter.models.job import JobStatus
from specter.models.target import SeedInput


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> CredentialStore:
    key = Fernet.generate_key()
    return CredentialStore(fernet_key=key, store_path=tmp_path / "creds.json")


@pytest.fixture
def store_with_keys(store: CredentialStore) -> CredentialStore:
    store.set("hibp", "hibp-test-key")
    store.set("intelx", "intelx-test-key")
    store.set("emailrep", "emailrep-test-key")
    store.set("facecheck", "facecheck-test-key")
    return store


@pytest.fixture
def phone_collector() -> PhoneCollector:
    return PhoneCollector()


@pytest.fixture
def email_collector(store_with_keys: CredentialStore) -> EmailCollector:
    return EmailCollector(store=store_with_keys)


@pytest.fixture
def username_collector() -> UsernameCollector:
    return UsernameCollector()


@pytest.fixture
def image_collector(store_with_keys: CredentialStore) -> ImageCollector:
    return ImageCollector(store=store_with_keys)


@pytest.fixture
def breach_collector(store_with_keys: CredentialStore) -> BreachCollector:
    return BreachCollector(store=store_with_keys)


@pytest.fixture
def registry(store_with_keys: CredentialStore) -> CollectorRegistry:
    return CollectorRegistry(store=store_with_keys)


def make_seed(seed_type: str, value: str) -> SeedInput:
    return SeedInput(seed_type=seed_type, value=value)


# ---------------------------------------------------------------------------
# BaseCollector / ethics
# ---------------------------------------------------------------------------


class TestBaseCollectorEthics:
    def test_ethics_flags_hardcoded(self, phone_collector: PhoneCollector):
        assert phone_collector.passive_only is True
        assert phone_collector.no_credential_extraction is True
        assert phone_collector.public_sources_only is True

    def test_ethics_check_passes_for_valid_seed(self, phone_collector: PhoneCollector):
        seed = make_seed("phone", "+15550001111")
        phone_collector._check_ethics(seed)  # must not raise


# ---------------------------------------------------------------------------
# PhoneCollector
# ---------------------------------------------------------------------------


class TestPhoneCollector:
    def test_seed_types(self, phone_collector: PhoneCollector):
        assert "phone" in phone_collector.seed_types

    def test_unavailable_when_tool_missing(self, phone_collector: PhoneCollector):
        with patch("shutil.which", return_value=None):
            assert phone_collector.is_available() is False

    def test_available_when_tool_present(self, phone_collector: PhoneCollector):
        with patch("shutil.which", return_value="/usr/bin/phoneinfoga"):
            assert phone_collector.is_available() is True

    async def test_parses_phoneinfoga_output(self, phone_collector: PhoneCollector):
        """Collector correctly parses JSON output from phoneinfoga subprocess."""
        fake_output = json.dumps({
            "carrier": "T-Mobile",
            "country": "United States",
            "found_accounts": ["whatsapp", "viber"],
        }).encode()

        with patch("shutil.which", return_value="/usr/bin/phoneinfoga"):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = AsyncMock()
                mock_proc.communicate = AsyncMock(return_value=(fake_output, b""))
                mock_exec.return_value = mock_proc

                result = await phone_collector.collect(make_seed("phone", "+15550001111"))

        assert result.status == JobStatus.COMPLETED
        types = [a["type"] for a in result.artifacts]
        assert "carrier" in types
        assert "region" in types
        assert "linked_account" in types

    async def test_wrong_seed_type_returns_error(self, phone_collector: PhoneCollector):
        result = await phone_collector.collect(make_seed("email", "test@example.com"))
        assert result.status == JobStatus.FAILED
        assert result.error

    async def test_tool_missing_returns_error(self, phone_collector: PhoneCollector):
        with patch("shutil.which", return_value=None):
            result = await phone_collector.collect(make_seed("phone", "+15550001111"))
        assert result.status == JobStatus.FAILED


# ---------------------------------------------------------------------------
# EmailCollector
# ---------------------------------------------------------------------------


class TestEmailCollector:
    async def test_holehe_discovers_services(self, email_collector: EmailCollector):
        holehe_output = b"[+] twitter\n[+] instagram\n[-] facebook"

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(holehe_output, b""))
            mock_exec.return_value = mock_proc

            with patch.object(email_collector, "_run_hibp", return_value=[]):
                with patch.object(email_collector, "_run_emailrep", return_value=[]):
                    result = await email_collector.collect(make_seed("email", "test@example.com"))

        services = [a["value"] for a in result.artifacts if a["type"] == "registered_service"]
        assert "twitter" in services
        assert "instagram" in services

    async def test_hibp_returns_breach_list(self, email_collector: EmailCollector):
        hibp_response = [
            {"Name": "TestBreach", "DataClasses": ["email", "password_hash"], "BreachDate": "2023-01-01"}
        ]

        with patch.object(email_collector, "_run_holehe", return_value=[]):
            with patch.object(email_collector, "_run_emailrep", return_value=[]):
                with patch("httpx.AsyncClient") as mock_client:
                    mock_resp = MagicMock()
                    mock_resp.status_code = 200
                    mock_resp.json.return_value = hibp_response
                    mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                        return_value=mock_resp
                    )

                    result = await email_collector.collect(make_seed("email", "test@example.com"))

        breaches = [a for a in result.artifacts if a["type"] == "breach"]
        assert len(breaches) == 1
        assert breaches[0]["breach_name"] == "TestBreach"
        assert "password" not in str(breaches[0])  # no raw creds
        assert "password_hash" in breaches[0]["data_classes"]

    async def test_wrong_seed_type_returns_error(self, email_collector: EmailCollector):
        result = await email_collector.collect(make_seed("phone", "+15550001111"))
        assert result.status == JobStatus.FAILED


# ---------------------------------------------------------------------------
# UsernameCollector
# ---------------------------------------------------------------------------


class TestUsernameCollector:
    def test_seed_types(self, username_collector: UsernameCollector):
        assert "username" in username_collector.seed_types

    def test_unavailable_when_maigret_missing(self, username_collector: UsernameCollector):
        with patch("shutil.which", return_value=None):
            assert username_collector.is_available() is False

    async def test_maigret_subprocess_parses_results(self, username_collector: UsernameCollector):
        maigret_json = json.dumps({
            "twitter": {"status": "Claimed", "url_user": "https://twitter.com/jdoe"},
            "github": {"status": "Claimed", "url_user": "https://github.com/jdoe"},
            "facebook": {"status": "Available"},
        }).encode()

        with patch("shutil.which", return_value="/usr/bin/maigret"):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = AsyncMock()
                mock_proc.communicate = AsyncMock(return_value=(maigret_json, b""))
                mock_exec.return_value = mock_proc

                with patch.object(username_collector, "_run_whatsmyname", return_value=[]):
                    result = await username_collector.collect(make_seed("username", "jdoe"))

        platforms = [a["platform"] for a in result.artifacts if a["type"] == "platform_presence"]
        assert "twitter" in platforms
        assert "github" in platforms
        assert "facebook" not in platforms  # Available = not claimed

    async def test_tool_missing_returns_error(self, username_collector: UsernameCollector):
        with patch("shutil.which", return_value=None):
            result = await username_collector.collect(make_seed("username", "jdoe"))
        assert result.status == JobStatus.FAILED


# ---------------------------------------------------------------------------
# ImageCollector
# ---------------------------------------------------------------------------


class TestImageCollector:
    def test_seed_types(self, image_collector: ImageCollector):
        assert "image" in image_collector.seed_types

    async def test_exiftool_extracts_gps(self, image_collector: ImageCollector):
        exif_json = json.dumps([{
            "GPSLatitude": 25.7617,
            "GPSLongitude": -80.1918,
            "Make": "Apple",
            "Model": "iPhone 15",
        }]).encode()

        with patch("shutil.which", return_value="/usr/bin/exiftool"):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = AsyncMock()
                mock_proc.communicate = AsyncMock(return_value=(exif_json, b""))
                mock_exec.return_value = mock_proc

                with patch.object(image_collector, "_run_facecheck", return_value=[]):
                    result = await image_collector.collect(
                        make_seed("image", "https://example.com/photo.jpg")
                    )

        exif = [a for a in result.artifacts if a["type"] == "exif"]
        assert exif
        assert exif[0]["gps_lat"] == pytest.approx(25.7617)
        assert exif[0]["device_make"] == "Apple"

    async def test_wrong_seed_type_returns_error(self, image_collector: ImageCollector):
        result = await image_collector.collect(make_seed("email", "test@example.com"))
        assert result.status == JobStatus.FAILED


# ---------------------------------------------------------------------------
# BreachCollector
# ---------------------------------------------------------------------------


class TestBreachCollector:
    def test_seed_types(self, breach_collector: BreachCollector):
        assert "email" in breach_collector.seed_types
        assert "phone" in breach_collector.seed_types

    def test_available_with_keys(self, breach_collector: BreachCollector):
        assert breach_collector.is_available() is True

    def test_unavailable_without_keys(self, store: CredentialStore):
        bc = BreachCollector(store=store)
        assert bc.is_available() is False

    async def test_hibp_breach_data_classes_only(self, breach_collector: BreachCollector):
        """Ensures only data class labels are stored, not raw credential content."""
        hibp_data = [
            {"Name": "TestBreach", "DataClasses": ["email", "password_hash"], "BreachDate": "2023-01-01"}
        ]
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = hibp_data
            mock_resp.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_resp)

            with patch.object(breach_collector, "_query_intelx", return_value=[]):
                result = await breach_collector.collect(make_seed("email", "target@example.com"))

        breaches = [a for a in result.artifacts if a["type"] == "breach_record"]
        assert breaches[0]["data_classes"] == ["email", "password_hash"]
        # No raw credential fields should exist
        for breach in breaches:
            assert "password" not in breach
            assert "hash" not in breach
            assert "plaintext" not in breach

    async def test_graceful_failure_on_network_error(self, breach_collector: BreachCollector):
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=Exception("Network error")
            )
            with patch.object(breach_collector, "_query_intelx", return_value=[]):
                result = await breach_collector.collect(make_seed("email", "x@example.com"))
        # Should not raise, just return with error or empty artifacts
        assert result.status in (JobStatus.COMPLETED, JobStatus.FAILED)


# ---------------------------------------------------------------------------
# CollectorRegistry
# ---------------------------------------------------------------------------


class TestCollectorRegistry:
    def test_registry_discovers_all_collectors(self, registry: CollectorRegistry):
        names = {c.name for c in registry.all()}
        assert "phoneinfoga" in names
        assert "email" in names
        assert "username" in names
        assert "image" in names
        assert "breach" in names
        assert "social" in names

    def test_for_seed_type_filters_correctly(self, registry: CollectorRegistry):
        with patch("shutil.which", return_value="/usr/bin/holehe"):
            email_collectors = registry.for_seed_type("email")
        assert all("email" in c.seed_types for c in email_collectors)

    def test_get_by_name(self, registry: CollectorRegistry):
        c = registry.get("breach")
        assert c is not None
        assert c.name == "breach"

    def test_get_unknown_returns_none(self, registry: CollectorRegistry):
        assert registry.get("nonexistent_collector_xyz") is None

    def test_available_excludes_missing_tools(self, registry: CollectorRegistry):
        with patch("shutil.which", return_value=None):
            available = registry.available()
        # breach collector is available because it has API keys in store_with_keys
        assert all(c.is_available() for c in available)

    def test_collector_unavailable_when_key_missing(self, store: CredentialStore):
        """BreachCollector with empty store reports unavailable."""
        bc = BreachCollector(store=store)
        assert bc.is_available() is False
