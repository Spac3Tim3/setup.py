# SPECTER — Protective Intelligence Platform

## Project Overview

Specter is a passive, read-only protective intelligence platform for security operators.
It monitors high-value individuals (executives, LEO, judges) and their close circles
for digital exposure across social media, public records, breach databases, and dark web
sources. All data collection uses publicly accessible sources only.

**Stack:** Python 3.12 · FastAPI · React + Tailwind · SQLite → PostgreSQL · NetworkX ·
Playwright · Claude Sonnet (normalization) · Claude Opus (triage)

**Base OS:** Kali Linux (tools pre-installed where available)

## Design Principles

- TDD first — no implementation without a failing test
- Pydantic models are the contract layer — defined before any collector
- Passive only — no writes, no auth bypass, no restricted databases
- Audit everything — every operator action logged
- Graceful degradation — missing tools/API keys reduce capability, never crash

## Ethics Constraints (Non-Negotiable)

1. `passive_only = True` — no writes to any external system
2. `no_credential_extraction = True` — breach data surfaces data classes only
3. `no_dppa_queries = True` — no DMV API calls
4. `no_fcra_queries = True` — no credit/financial record access
5. `public_sources_only = True` — all sources must be publicly accessible
6. `audit_all_actions = True` — every operator action logged

## Agent Status

| Agent | Responsibility | Status |
|-------|---------------|--------|
| 0 — Architect | Models + pyproject.toml + Makefile | Complete |
| 1 — Credentials | Credential store + health system | Pending |
| 2 — Collectors | Data collection wrappers | Pending |
| 3 — Engine | Enrichment loop + scheduler | Pending |
| 4 — AI Layer | Sonnet normalization + Opus triage | Pending |
| 5 — Graph | NetworkX store + GraphML export | Pending |
| 6 — Records | FL public records + shield verification | Pending |
| 7 — Dark Web | IntelX + Ahmia + ransomware.live | Pending |
| 8 — Alerts | Alert dispatch + diff engine | Pending |
| 9 — Cases | Case management + audit log | Pending |
| 10 — API | FastAPI backend | Pending |
| 11 — UI | React operator dashboard | Pending |

## Design Decisions

- All models use `uuid4` for IDs to avoid sequential enumeration
- `BreachRecord.data_classes` contains data type labels only — never raw credential data
- `DarkWebSignal.context_summary` is sanitized — no plaintext passwords stored
- `IdentityConfidence.score` is float 0.0–1.0; `exposure_score` in triage is int 0–100
- `SeedInput.seed_type` enum: `email | username | phone | name | image | platform_url`
- Circle member profiles are stored as full `PersonProfile` objects for graph traversal
- All timestamps are UTC; consumers must localize for display
