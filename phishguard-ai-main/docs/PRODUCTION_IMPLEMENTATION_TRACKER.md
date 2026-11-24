# Production Implementation Tracker

Updated: 2026-11-24

## Completed and verified locally

- [x] Enforced owner filters on scan history, reports, and alerts; prevented cross-owner alert updates.
- [x] Restricted team invitations to team administrators.
- [x] Hashed API keys at rest, masked them in listings, and implemented owner-only revocation.
- [x] Authenticated WebSocket connections and scoped alert delivery to the authenticated owner.
- [x] Added security response headers and rate limiting; production requires Redis and fails closed if it is unavailable.
- [x] Added shared Redis-backed rate limiting and Redis pub/sub for WebSocket alert fan-out.
- [x] Added structured JSON application logs in production and removed scanned URLs from error log messages.
- [x] Added refresh-token rotation and reuse-family revocation, access/refresh logout revocation, reset and verification tokens, account lockout, and optional TOTP MFA.
- [x] Added regression tests for authentication/session controls, MFA, API keys, WebSockets, ownership, headers, rate limiting, and legacy data migrations.
- [x] Added Alembic migration revisions; fresh and legacy SQLite upgrades pass, and legacy user/scan/key records are preserved during tested upgrades.
- [x] Added production PostgreSQL/Redis Compose configuration and production environment validation; kept SQLite for development.
- [x] Added PostgreSQL backup and empty-database restore scripts.
- [x] Added GitHub Actions CI for backend tests, frontend build, dependency audits, and Docker image builds.
- [x] Replaced vulnerable JWT/multipart/dotenv/FastAPI dependency versions and vulnerable frontend dependencies after auditing.
- [x] Backend suite passes: 26 tests. `pip check`, `pip-audit -r requirements.txt`, `npm audit`, frontend production build, and PostgreSQL offline migration SQL generation pass.

## Not verified or still open

- [ ] Run migrations against a live clean PostgreSQL server and test an upgrade/restore on an isolated recovery database.
- [ ] Build and start the production Docker Compose stack; Docker is unavailable in the current environment.
- [ ] Schedule, encrypt, off-site replicate, and regularly restore backups. The supplied scripts are manual building blocks, not a backup service.
- [ ] Complete an endpoint-by-endpoint organizational authorization audit. Current resource access is owner-scoped; team/organization-wide resource roles are not implemented.
- [ ] Add scoped API-key permissions and quotas.
- [ ] Make failed-login lockout updates concurrency-safe and verify behavior under parallel attempts.
- [ ] Replace query-string WebSocket tokens with a transport that avoids URL/access-log exposure.
- [ ] Implement background jobs and production monitoring/alerting.
- [ ] Implement subscription plans, server-enforced quotas, invoice and transaction records, M-Pesa Daraja and Stripe payments, and signed/idempotent callbacks.
- [ ] Add UI-level frontend tests and exercise CI on the hosting provider.
- [ ] Obtain production domain/TLS, SMTP, Google OAuth, and payment-provider credentials as applicable; provider-dependent flows have not been verified.

## Production environment configuration

Copy `.env.example` to `.env` and set at least:

- `APP_ENV=production`, `DEBUG=false`, and a stable cryptographically random `SECRET_KEY` of at least 32 characters.
- `POSTGRES_DB`, `POSTGRES_USER`, and a unique strong `POSTGRES_PASSWORD`.
- `DATABASE_URL=postgresql+asyncpg://<user>:<URL-encoded-password>@postgres:5432/<database>`; its user, password, and database must match the `POSTGRES_*` values.
- `REDIS_PASSWORD` as a random hexadecimal string (the Compose file uses it to form `REDIS_URL`).
- `FRONTEND_URL=https://<public-frontend-host>` and `CORS_ORIGINS` as a comma-separated list of exact HTTPS origins.
- For reset/verification email, configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM_EMAIL`; set `EMAIL_VERIFICATION_REQUIRED=true` only when SMTP delivery is ready.

The production Compose command runs `alembic upgrade head` before starting the API. Review and back up any existing database before deployment; test migration and restore procedures on a separate copy first. MFA encryption is derived from `SECRET_KEY`; changing that key makes enrolled secrets undecryptable, so plan user MFA re-enrollment before rotating it.

Stripe and M-Pesa configuration keys are intentionally not listed: these integrations and verified payment activation are not implemented, and payment must not be simulated.
