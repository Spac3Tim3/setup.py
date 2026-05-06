"""Service registry — all known data services with configuration metadata."""

from __future__ import annotations

from specter.models.credential import ServiceConfig

SERVICES: dict[str, ServiceConfig] = {
    # ── API services (key required) ────────────────────────────────────────────────────────
    "hibp": ServiceConfig(
        name="Have I Been Pwned",
        api_key_required=True,
        free_tier=False,
        signup_url="https://haveibeenpwned.com/API/Key",
        docs_url="https://haveibeenpwned.com/API/v3",
        rate_limit_per_minute=10,
    ),
    "intelx": ServiceConfig(
        name="IntelX",
        api_key_required=True,
        free_tier=True,
        signup_url="https://intelx.io/signup",
        docs_url="https://intelx.io/API",
        rate_limit_per_minute=5,
    ),
    "emailrep": ServiceConfig(
        name="EmailRep",
        api_key_required=True,
        free_tier=True,
        signup_url="https://emailrep.io/key",
        docs_url="https://docs.emailrep.io",
        rate_limit_per_minute=20,
    ),
    "shodan": ServiceConfig(
        name="Shodan",
        api_key_required=True,
        free_tier=True,
        signup_url="https://account.shodan.io/register",
        docs_url="https://developer.shodan.io/api",
        rate_limit_per_minute=60,
    ),
    "facecheck": ServiceConfig(
        name="FaceCheck.ID",
        api_key_required=True,
        free_tier=False,
        signup_url="https://facecheck.id/api",
        docs_url="https://facecheck.id/api",
        rate_limit_per_minute=10,
    ),
    "darkowl": ServiceConfig(
        name="DarkOwl",
        api_key_required=True,
        free_tier=False,
        signup_url="https://www.darkowl.com/contact",
        docs_url="https://docs.darkowl.com",
        rate_limit_per_minute=60,
    ),
    # ── Kali-native / CLI tools (no API key) ──────────────────────────────────────────
    "phoneinfoga": ServiceConfig(
        name="PhoneInfoga",
        api_key_required=False,
        kali_native=True,
        install_cmd="pip install phoneinfoga",
    ),
    "holehe": ServiceConfig(
        name="Holehe",
        api_key_required=False,
        kali_native=True,
        install_cmd="pip install holehe",
    ),
    "ghunt": ServiceConfig(
        name="GHunt",
        api_key_required=False,
        kali_native=True,
        install_cmd="pip install ghunt",
    ),
    "maigret": ServiceConfig(
        name="Maigret",
        api_key_required=False,
        kali_native=True,
        install_cmd="pip install maigret",
    ),
    "whatsmyname": ServiceConfig(
        name="WhatsMyName",
        api_key_required=False,
        kali_native=True,
        install_cmd="pip install whatsmyname",
    ),
    # ── Free clearnet APIs (no key) ───────────────────────────────────────────────────
    "ahmia": ServiceConfig(
        name="Ahmia",
        api_key_required=False,
        signup_url="https://ahmia.fi",
        docs_url="https://ahmia.fi",
        rate_limit_per_minute=10,
    ),
    "ransomware_live": ServiceConfig(
        name="ransomware.live",
        api_key_required=False,
        signup_url="https://api.ransomware.live",
        docs_url="https://api.ransomware.live",
        rate_limit_per_minute=60,
    ),
}
