# Production Readiness Audit

Audit date: 2026-11-24

## Implemented controls

- JWT-protected account, report, history, alert, and team operations with owner filters for private records.
- API keys are SHA-256 hashed at rest, masked in API responses, authenticated for scans, and revocable by their owner.
- WebSockets require an authenticated JWT and approved origin; alert payloads are owner-filtered. Redis pub/sub supports multi-instance fan-out.
- Security response headers and Redis-backed production rate limiting; production refuses requests when rate-limit infrastructure fails.
- Structured JSON application logs in production; URL scanner exception logs no longer contain submitted URLs.
- Refresh-token rotation and reuse revocation, access/refresh logout revocation, password-reset and email-verification tokens, login lockout, and optional TOTP MFA.
- PostgreSQL settings, additive Alembic migrations, SQLite development support, production Compose services, and manual PostgreSQL backup/restore scripts.
- CI workflow for backend tests, frontend build, dependency audits, and Docker builds.

## Verification evidence

As of 2026-11-24 on the local Windows/Python 3.12 environment:

- Backend: `python -m unittest discover -s tests -v` — **26 tests passed**.
- Database: fresh and legacy SQLite migration tests passed; the generated PostgreSQL Alembic SQL completed offline.
- Dependencies: `pip check` passed; `pip-audit -r requirements.txt` reported no known vulnerabilities; `npm audit` reported zero vulnerabilities.
- Frontend: Vite production build passed. It reports a non-blocking JavaScript chunk-size warning (710.06 kB minified).
- Python compilation passed.

No live PostgreSQL server, Redis server, Docker/Docker Compose, `psql`, or `pg_dump` was available. Therefore clean/live PostgreSQL upgrades, PostgreSQL recovery, Redis operation, container builds, and CI execution are **not verified**.

## Open production blockers

- URL scanner model accuracy, calibration, false-positive rate, and domain-grouped holdout performance remain unverified.

- Live PostgreSQL migration/upgrade/recovery verification and production deployment have not occurred.
- Company/team-wide resource access, organization roles, scoped API keys, and quotas need implementation and cross-tenant testing. Existing records are owner-scoped; this is not a complete organizational multi-tenancy model.
- Login lockout has not been tested under concurrent attempts.
- WebSocket credentials currently use a query parameter and may be exposed by access logs.
- Background-job processing, monitoring/alerting, scheduled/off-site/encrypted backups, and tested recovery operations are incomplete.
- Subscription lifecycle, plans, usage enforcement, invoices, payment transactions, Stripe/M-Pesa integrations, and secure/idempotent payment callbacks are absent.
- SMTP, production TLS/domain, external OAuth, and provider credentials are not configured here.
- Automated frontend behavior tests are not present; only the production build was verified.

## Readiness decision

**Not production-ready.** Local tests, static migration generation, frontend build, and dependency checks pass, but production services and several required product/security capabilities remain unimplemented or unverified. This audit is not a penetration test or deployment certification.
