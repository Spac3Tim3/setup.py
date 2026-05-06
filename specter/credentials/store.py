"""Encrypted local API credential store using Fernet symmetric encryption."""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from specter.models.credential import APICredential


class CredentialStoreError(Exception):
    """Raised on store read/write or decryption failures."""


class CredentialStore:
    """Stores API credentials encrypted at rest using Fernet symmetric encryption.

    All values are encrypted before writing to disk. The store file is chmod
    0o600. The Fernet key must be supplied via the ``fernet_key`` constructor
    argument or the ``CREDENTIAL_FERNET_KEY`` environment variable.
    """

    DEFAULT_PATH = Path.home() / ".specter" / "credentials.json"

    def __init__(
        self,
        fernet_key: str | bytes | None = None,
        store_path: Path | None = None,
    ) -> None:
        raw_key = fernet_key or os.environ.get("CREDENTIAL_FERNET_KEY", "")
        if not raw_key:
            raise CredentialStoreError(
                "Fernet key required. Set CREDENTIAL_FERNET_KEY or pass fernet_key."
            )
        if isinstance(raw_key, str):
            raw_key = raw_key.encode()
        try:
            self._fernet = Fernet(raw_key)
        except Exception as exc:
            raise CredentialStoreError(f"Invalid Fernet key: {exc}") from exc
        self._path = store_path or self.DEFAULT_PATH

    # ------------------------------------------------------------------
    # Internal I/O
    # ------------------------------------------------------------------

    def _load_raw(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            raise CredentialStoreError(f"Failed to read credential store: {exc}") from exc

    def _save_raw(self, data: dict[str, str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._path.write_text(json.dumps(data, indent=2))
            self._path.chmod(0o600)
        except OSError as exc:
            raise CredentialStoreError(f"Failed to write credential store: {exc}") from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set(self, service_id: str, api_key: str, operator_id: str | None = None) -> APICredential:
        """Encrypt and persist an API key for a service."""
        if not api_key.strip():
            raise CredentialStoreError("API key must not be empty")
        encrypted = self._fernet.encrypt(api_key.encode()).decode()
        data = self._load_raw()
        data[service_id] = encrypted
        self._save_raw(data)
        return APICredential(
            service_id=service_id,
            encrypted_key=encrypted,
            added_by=operator_id,
        )

    def get(self, service_id: str) -> str | None:
        """Return the plaintext API key for a service, or None if not stored."""
        data = self._load_raw()
        encrypted = data.get(service_id)
        if encrypted is None:
            return None
        try:
            return self._fernet.decrypt(encrypted.encode()).decode()
        except InvalidToken as exc:
            raise CredentialStoreError(
                f"Failed to decrypt credential for '{service_id}': "
                "key mismatch or corrupted data"
            ) from exc

    def delete(self, service_id: str) -> bool:
        """Remove a stored credential. Returns True if it existed."""
        data = self._load_raw()
        if service_id not in data:
            return False
        del data[service_id]
        self._save_raw(data)
        return True

    def list_configured(self) -> list[str]:
        """Return service IDs that have stored credentials."""
        return list(self._load_raw().keys())

    def get_credential(self, service_id: str) -> APICredential | None:
        """Return an APICredential (with encrypted key) or None."""
        data = self._load_raw()
        encrypted = data.get(service_id)
        if encrypted is None:
            return None
        return APICredential(service_id=service_id, encrypted_key=encrypted)
