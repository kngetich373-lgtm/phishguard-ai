# Known Limitations

- Detection is primarily heuristic; a verdict is not a guarantee of maliciousness or safety.
- The bundled URL classifier is a HistGradientBoostingClassifier. Its 96.9% statistic is not reproducible from repository artifacts and must not be presented as independently verified accuracy.
- Authorized external datasets and independent model evaluation are not included. Separate online, offline, and network-degraded benchmark metrics are therefore unavailable.
- Gmail synchronization and live threat-intelligence lookups are not implemented. No provider result is fabricated.
- Authentication includes refresh rotation/reuse revocation, logout, reset/verification tokens, account lockout, and optional TOTP MFA, but lockout concurrency has not been validated.
- MFA secrets are encrypted using key material derived from `SECRET_KEY`; changing that key requires MFA re-enrollment.
- Account records and scans are owner-scoped. Team-wide record sharing, organization roles, and a complete cross-tenant organizational policy are not implemented.
- API keys are hashed, masked, and revocable, but do not yet have permission scopes or usage quotas.
- Redis-backed production request limiting and WebSocket fan-out are implemented, but no live Redis server was available for integration testing.
- SQLite is supported for local development. Production settings require PostgreSQL and the Compose deployment runs Alembic, but only SQLite migrations and offline PostgreSQL SQL generation have been verified.
- Backup/restore PowerShell scripts are manual tools. Backup scheduling, encryption, off-site retention, and recurring restore drills remain operational work.
- Monitoring, background jobs, payment integration, subscription enforcement, billing records, and provider-verified payment activation are not implemented.
- WebSocket tokens are currently passed as query parameters; ensure access logs redact query strings until the transport is changed.
- The frontend bundle is larger than Vite's 500 kB advisory threshold; current build succeeds with that warning.
