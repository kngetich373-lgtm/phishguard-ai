# Environment configuration

PhishGuard has one authoritative configuration file: `.env` at the project
root. The backend reads that file by an absolute path, regardless of its
working directory. Docker Compose reads the same file and passes its values to
the backend container. Environment variables supplied by the process/container
override values in `.env`. Never commit `.env`.

The root `.env.example` is the canonical template. `backend/.env.example` is
kept only as a pointer for older checkouts; do not make a second backend
configuration file. Vite has its own optional `frontend/.env` because Vite
loads frontend build-time variables from the frontend directory. Only public
`VITE_*` values belong there.

## Create a local development configuration

From the project root:

**Linux/macOS**

```sh
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"
# Put the generated value in SECRET_KEY in .env.
```

Or generate directly into the file (preserving the other settings):

```sh
python3 -c "from pathlib import Path; import secrets; p=Path('.env'); s=p.read_text(); p.write_text(s.replace('REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_CHARACTERS', secrets.token_hex(32)))"
```

**Windows PowerShell**

```powershell
Copy-Item .env.example .env
$secret = python -c "import secrets; print(secrets.token_hex(32))"
# Paste $secret into the SECRET_KEY value in .env; do not share or log it.
```

**Windows Command Prompt**

```bat
copy .env.example .env
py -c "import secrets; print(secrets.token_hex(32))"
```

The example's `SECRET_KEY` is intentionally invalid. Replace it with at least
32 randomly generated characters before startup. Do not reuse a production
secret in development. On a machine without Python, `openssl rand -hex 32`
works on Linux/macOS and on Windows installations that include OpenSSL.

## Environment variable inventory

Variable names are case-insensitive in the backend. `APP_ENV` is preferred;
the legacy `ENVIRONMENT` name remains supported.

| Variable | Required | Default / purpose |
|---|---|---|
| `APP_NAME` | No | API display name (`PhishGuard AI`). |
| `APP_ENV` | No | `development` by default; `production`/`prod` enables production checks. Legacy alias: `ENVIRONMENT`. |
| `DEBUG` | No | `false`. Controls Uvicorn reload in `python -m app.run`; production rejects `true`. |
| `HOST` | No | `127.0.0.1` locally. Docker overrides it to `0.0.0.0`. |
| `PORT` | No | `8000`; must be 1–65535. |
| `LOG_LEVEL` | No | `INFO`; supported: `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`. |
| `SECRET_KEY` | **Yes** | JWT signing secret; at least 32 characters, non-placeholder, never logged. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | `60`; must be positive. |
| `JWT_ALGORITHM` | No | `HS256`; supported: `HS256`, `HS384`, `HS512`. Legacy alias: `ALGORITHM`. |
| `DATABASE_URL` | No | `sqlite+aiosqlite:///./phishguard.db`. Supports async SQLite and `postgresql+asyncpg` only. Production requires PostgreSQL. |
| `FRONTEND_URL` | No | `http://localhost:5173`; included among CORS origins. |
| `CORS_ORIGINS` | No | Comma-separated origins; default includes localhost dev origins. Production must list explicit non-local origins. |
| `GOOGLE_CLIENT_ID` | No | Optional; paired with `GOOGLE_CLIENT_SECRET`. These only control a Gmail OAuth scaffold/status; the OAuth flow is not implemented. |
| `GOOGLE_CLIENT_SECRET` | No | Optional Google OAuth client secret. Never expose it to Vite. |
| `GOOGLE_REDIRECT_URI` | No | Optional Google OAuth callback setting (default `http://localhost:8000/api/email/oauth/callback`). |
| `ANTHROPIC_API_KEY` | No | Optional key used only by the standalone server-side reputation search helper; no HTTP scan endpoint calls it currently. Keep it backend-only. |
| `VITE_API_BASE_URL` | No | Public frontend API URL; defaults to `/api` for the Vite proxy and Docker nginx proxy. Safe for browser exposure; **never place secrets in `VITE_*`**. |

VirusTotal and Google Safe Browsing API keys are not supported by the current
code and are intentionally not configured as active integrations. Gmail OAuth
is a scaffold, not a working mailbox integration. The heuristic scanners work
without any third-party credentials. The optional reputation helper requires
the `anthropic` package to be installed separately as well as an API key if you
call it directly.

## Database configuration

**SQLite development default**

```dotenv
DATABASE_URL=sqlite+aiosqlite:///./phishguard.db
```

The database file is relative to the backend process working directory and is
ignored by Git. Run `python -m app.run` from `backend/` for the conventional
local path. In Compose, the backend data volume preserves its working directory
and database across container recreation.

**PostgreSQL**

The async PostgreSQL driver is installed from `backend/requirements.txt`.
Create a database and an account with only the permissions the app requires.
Then set a SQLAlchemy async URL, for example:

```dotenv
DATABASE_URL=postgresql+asyncpg://phishguard:URL_ENCODED_PASSWORD@db.example.net:5432/phishguard
```

URL-encode special characters in the username/password. The backend rejects
malformed URLs and unsupported synchronous drivers before serving requests.
Production mode rejects SQLite.

## Google OAuth and threat-intelligence credentials

Google credentials are optional and can be created in the [Google Cloud
Console](https://console.cloud.google.com/) under APIs & Services → Credentials.
Configure an OAuth client and authorized redirect URI to match
`GOOGLE_REDIRECT_URI`. The repository currently exposes a configuration status
and scaffold only; it does not complete OAuth or read Gmail messages.

VirusTotal and Google Safe Browsing are not integrated. No credentials are
needed for URL, SMS, or pasted-email heuristic scanning. `ANTHROPIC_API_KEY`
can be obtained from the [Anthropic Console](https://console.anthropic.com/)
for direct use of the optional server-side reputation helper. Do not put
provider credentials in the frontend or browser build.

## Start the application

**Backend**, after installing `backend/requirements.txt`:

```sh
cd backend
python -m app.run
```

The backend validates settings before startup. It binds to `HOST:PORT`, and
automatically enables reload only if `DEBUG=true`.

**Frontend** (separate terminal):

```sh
cd frontend
npm ci
npm run dev
```

Vite serves `http://localhost:5173` and proxies `/api` to
`http://localhost:8000`. Set `VITE_API_BASE_URL` only when intentionally using
a different public API base URL. The frontend build embeds this value, so
changing it requires rebuilding.

**Docker Compose**, from the project root after creating `.env`:

```sh
docker compose config
docker compose up --build
```

The backend receives the root `.env`; there are no Compose fallback secrets.
The backend is available at `http://localhost:8000`, and the frontend at
`http://localhost` (nginx proxies API/WebSocket requests to the backend).
The `backend_data` named volume persists the SQLite database. To use an
external PostgreSQL database, set its URL and production security/CORS values
in the root `.env` before starting.

## Production setup

Set at least:

```dotenv
APP_ENV=production
DEBUG=false
SECRET_KEY=<unique random secret of at least 32 characters>
DATABASE_URL=postgresql+asyncpg://...
FRONTEND_URL=https://app.example.com
CORS_ORIGINS=https://app.example.com
```

Choose a strong, unique secret with `python -c "import secrets; print(secrets.token_hex(32))"` or `openssl rand -hex 32`, then deliver it using your deployment secret manager. Production startup refuses an absent, weak, or placeholder secret; SQLite; debug mode; wildcard or localhost CORS; an unsupported database URL; and incomplete Google credential pairs. Do not enable reload or expose debug logs in production.

The included Compose file is a local deployment setup; production hosting,
TLS termination, database provisioning/backups, secret-manager integration,
rate limiting, and multi-worker WebSocket coordination must be configured by
the operator.

## Troubleshooting and Git safety

- **`SECRET_KEY` validation failed:** replace the example marker with a random value of 32+ characters. Do not paste the value into logs or issue reports.
- **`DATABASE_URL` rejected:** use `sqlite+aiosqlite:///...` or `postgresql+asyncpg://...`; ensure the PostgreSQL driver is installed and URL-encode credentials.
- **Production CORS rejected:** use exact `https://` frontend origins in both `FRONTEND_URL` and `CORS_ORIGINS`; do not use `*` or localhost.
- **Compose cannot read `.env`:** run `docker compose` from the project root and create `.env` from `.env.example` first.
- **Frontend cannot reach API:** preserve `/api` when using the included Vite/nginx proxy, or set a reachable public `VITE_API_BASE_URL` and configure backend CORS accordingly.
- **Environment changes appear ignored:** process environment variables override the file; restart the backend, and rebuild the frontend after changing `VITE_API_BASE_URL`.

Verify ignore rules from a Git checkout:

```sh
git check-ignore -v .env backend/.env frontend/.env
git check-ignore -v --no-index .env.example frontend/.env.example
git ls-files -- .env backend/.env frontend/.env
```

The first command should report ignore rules. The template checks should not
report ignored files, and `git ls-files` should list no actual `.env` files.
Templates should remain tracked. `.gitignore` also protects local databases,
private keys/certificates, credentials exports, uploads, virtual environments,
dependency folders, build artifacts, and logs.
