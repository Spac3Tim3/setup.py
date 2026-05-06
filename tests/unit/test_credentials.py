"""Agent 1 TDD contract: credential store + health validator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from specter.credentials.registry import SERVICES
from specter.credentials.store import CredentialStore, CredentialStoreError
from specter.credentials.validator import HealthValidator
from specter.models.credential import CollectorHealth


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fernet_key() -> bytes:
    return Fernet.generate_key()


@pytest.fixture
def store(tmp_path: Path, fernet_key: bytes) -> CredentialStore:
    return CredentialStore(fernet_key=fernet_key, store_path=tmp_path / "creds.json")


@pytest.fixture
def validator(store: CredentialStore) -> HealthValidator:
    return HealthValidator(store=store)


# ---------------------------------------------------------------------------
# CredentialStore
# ---------------------------------------------------------------------------


class TestCredentialStore:
    def test_store_and_retrieve_credential(self, store: CredentialStore):
        """Round-trip: stored key can be retrieved as plaintext."""
        store.set("hibp", "my-secret-key")
        assert store.get("hibp") == "my-secret-key"

    def test_credential_encryption_at_rest(self, store: CredentialStore, tmp_path: Path):
        """The on-disk value must not be the plaintext key."""
        store.set("hibp", "super-secret-key")
        raw = (tmp_path / "creds.json").read_text()
        assert "super-secret-key" not in raw

    def test_missing_service_returns_none(self, store: CredentialStore):
        assert store.get("nonexistent") is None

    def test_overwrite_credential(self, store: CredentialStore):
        store.set("hibp", "old-key")
        store.set("hibp", "new-key")
        assert store.get("hibp") == "new-key"

    def test_delete_removes_credential(self, store: CredentialStore):
        store.set("hibp", "key")
        assert store.delete("hibp") is True
        assert store.get("hibp") is None

    def test_delete_nonexistent_returns_false(self, store: CredentialStore):
        assert store.delete("missing") is False

    def test_list_configured_returns_service_ids(self, store: CredentialStore):
        store.set("hibp", "key1")
        store.set("intelx", "key2")
        configured = store.list_configured()
        assert "hibp" in configured
        assert "intelx" in configured

    def test_get_credential_returns_model(self, store: CredentialStore):
        store.set("hibp", "my-key")
        cred = store.get_credential("hibp")
        assert cred is not None
        assert cred.service_id == "hibp"
        assert cred.encrypted_key  # non-empty
        assert cred.encrypted_key != "my-key"  # not plaintext

    def test_get_credential_missing_returns_none(self, store: CredentialStore):
        assert store.get_credential("missing") is None

    def test_file_permissions_restrictive(self, store: CredentialStore, tmp_path: Path):
        """Credential file should be owner-read-only (0o600)."""
        store.set("hibp", "key")
        mode = (tmp_path / "creds.json").stat().st_mode & 0o777
        assert mode == 0o600

    def test_empty_key_rejected(self, store: CredentialStore):
        with pytest.raises(CredentialStoreError):
            store.set("hibp", "   ")


class TestCredentialStoreErrors:
    def test_invalid_fernet_key_rejected(self, tmp_path: Path):
        with pytest.raises(CredentialStoreError):
            CredentialStore(fernet_key="not-a-valid-fernet-key", store_path=tmp_path / "c.json")

    def test_missing_key_raises(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("CREDENTIAL_FERNET_KEY", raising=False)
        with pytest.raises(CredentialStoreError):
            CredentialStore(store_path=tmp_path / "c.json")

    def test_wrong_key_raises_on_decrypt(self, tmp_path: Path):
        """Decrypting with a different Fernet key raises CredentialStoreError."""
        path = tmp_path / "creds.json"
        store1 = CredentialStore(fernet_key=Fernet.generate_key(), store_path=path)
        store1.set("hibp", "secret")

        store2 = CredentialStore(fernet_key=Fernet.generate_key(), store_path=path)
        with pytest.raises(CredentialStoreError):
            store2.get("hibp")


# ---------------------------------------------------------------------------
# Service Registry
# ---------------------------------------------------------------------------


class TestServiceRegistry:
    def test_registry_not_empty(self):
        assert len(SERVICES) > 0

    def test_all_api_key_services_have_signup_url(self):
        """Every service requiring an API key must expose a signup URL."""
        for svc_id, config in SERVICES.items():
            if config.api_key_required:
                assert config.signup_url, (
                    f"Service '{svc_id}' requires an API key but has no signup_url"
                )

    def test_all_kali_native_services_have_install_cmd(self):
        for svc_id, config in SERVICES.items():
            if config.kali_native:
                assert config.install_cmd, (
                    f"Kali-native service '{svc_id}' has no install_cmd"
                )

    def test_known_services_present(self):
        required = {"hibp", "intelx", "emailrep", "shodan", "facecheck",
                    "phoneinfoga", "holehe", "ghunt", "maigret", "whatsmyname",
                    "ahmia", "ransomware_live"}
        missing = required - set(SERVICES.keys())
        assert not missing, f"Missing services from registry: {missing}"

    def test_service_config_fields_valid(self):
        for svc_id, config in SERVICES.items():
            assert config.name, f"Service '{svc_id}' has no name"
            assert config.rate_limit_per_minute >= 0


# ---------------------------------------------------------------------------
# HealthValidator
# ---------------------------------------------------------------------------


class TestHealthValidatorUnconfigured:
    async def test_unconfigured_api_service_not_available(
        self, validator: HealthValidator
    ):
        """Service with no stored key is reported as unavailable and not configured."""
        health = await validator.check("hibp")
        assert health.available is False
        assert health.configured is False
        assert health.key_valid is False
        assert "not configured" in (health.error or "")

    async def test_unknown_service_returns_error(self, validator: HealthValidator):
        health = await validator.check("totally_unknown_service_xyz")
        assert health.available is False
        assert "Unknown service" in (health.error or "")


class TestHealthValidatorConfigured:
    async def test_configured_service_with_valid_key(
        self, store: CredentialStore, validator: HealthValidator
    ):
        """Mocked successful ping reports available + key_valid."""
        store.set("hibp", "test-api-key")

        async def mock_ping(api_key: str) -> tuple[bool, str | None]:
            assert api_key == "test-api-key"
            return True, None

        with patch("specter.credentials.validator._SERVICE_PINGS", {"hibp": mock_ping}):
            health = await validator.check("hibp")

        assert health.available is True
        assert health.configured is True
        assert health.key_valid is True
        assert health.error is None

    async def test_configured_service_with_invalid_key(
        self, store: CredentialStore, validator: HealthValidator
    ):
        """Mocked failed ping reports unavailable with error message."""
        store.set("hibp", "bad-key")

        async def mock_ping(api_key: str) -> tuple[bool, str | None]:
            return False, "Invalid API key"

        with patch("specter.credentials.validator._SERVICE_PINGS", {"hibp": mock_ping}):
            health = await validator.check("hibp")

        assert health.available is False
        assert health.key_valid is False
        assert health.error == "Invalid API key"

    async def test_ping_exception_returns_graceful_error(
        self, store: CredentialStore, validator: HealthValidator
    ):
        """Network exceptions during ping are caught; service marked unavailable."""
        store.set("hibp", "key")

        async def failing_ping(api_key: str) -> tuple[bool, str | None]:
            raise ConnectionError("Network unreachable")

        with patch("specter.credentials.validator._SERVICE_PINGS", {"hibp": failing_ping}):
            health = await validator.check("hibp")

        assert health.available is False
        assert health.key_valid is None  # unknown — could not determine
        assert health.error

    async def test_service_without_ping_fn_returns_available(
        self, store: CredentialStore, validator: HealthValidator
    ):
        """A configured service with no registered ping is assumed available."""
        store.set("darkowl", "some-key")
        with patch("specter.credentials.validator._SERVICE_PINGS", {}):
            health = await validator.check("darkowl")
        assert health.available is True
        assert health.configured is True
        assert health.key_valid is None


class TestHealthValidatorNativeTool:
    async def test_native_tool_found_on_path(
        self, validator: HealthValidator
    ):
        with patch("shutil.which", return_value="/usr/bin/maigret"):
            health = await validator.check("maigret")
        assert health.available is True
        assert health.configured is True
        assert health.key_valid is None

    async def test_native_tool_not_found(
        self, validator: HealthValidator
    ):
        with patch("shutil.which", return_value=None):
            health = await validator.check("holehe")
        assert health.available is False
        assert health.error
        assert "PATH" in (health.error or "")


class TestCheckAll:
    async def test_check_all_returns_one_result_per_service(
        self, validator: HealthValidator
    ):
        with patch("shutil.which", return_value=None):
            results = await validator.check_all()
        assert len(results) == len(SERVICES)
        service_ids = {h.service_id for h in results}
        assert service_ids == set(SERVICES.keys())
