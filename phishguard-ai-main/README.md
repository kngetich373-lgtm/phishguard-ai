# PhishGuard AI

AI-assisted phishing detection platform: URL scanning, SMS ("smishing")
analysis, email/Gmail scanning, real-time alerts, team dashboards, and a
public API — built as a full working product, not a mockup.

Every scan runs through a transparent, explainable heuristic engine and
returns **why** it made its call, not just a score.

---

## 1. Project structure

```
phishguard-ai/
├── backend/                     Python / FastAPI API server
│   ├── app/
│   │   ├── main.py              FastAPI app entrypoint, router wiring, CORS
│   │   ├── config.py            Env-var driven settings (pydantic-settings)
│   │   ├── database.py          Async SQLAlchemy engine/session (SQLite or Postgres)
│   │   ├── models.py            ORM tables: users, teams, scans, alerts, api_keys
│   │   ├── schemas.py           Pydantic request/response models
│   │   ├── auth.py              Password hashing + JWT issuance/verification
│   │   ├── routers/             One file per feature area
│   │   │   ├── auth.py              /api/auth/*        register, login, me
│   │   │   ├── url_scanner.py       /api/scan/url       URL phishing scan
│   │   │   ├── sms_analyzer.py      /api/scan/sms       SMS smishing scan
│   │   │   ├── email_scanner.py     /api/scan/email     Email scan + Gmail OAuth scaffold
│   │   │   ├── alerts.py            /api/alerts/*       alert feed + WebSocket
│   │   │   ├── reports.py           /api/reports/*      dashboard summary, history, API keys
│   │   │   └── team.py              /api/team/*         team roster, invites
│   │   ├── services/             The actual detection logic (the "AI")
│   │   │   ├── url_detection.py     Heuristic URL risk scoring engine
│   │   │   ├── sms_detection.py     Heuristic SMS risk scoring engine
│   │   │   ├── email_detection.py   Heuristic email risk scoring engine
│   │   │   ├── scoring.py           Shared score → verdict classification
│   │   │   └── websocket_manager.py In-memory pub/sub for live alerts
│   │   └── ml/                   Bundled ML model plus named-feature inference
│   ├── requirements.txt
│   ├── .env.example              Copy to .env and fill in real secrets
│   └── Dockerfile
│
├── frontend/                    React / Vite / Tailwind single-page app
│   ├── src/
│   │   ├── main.jsx              React root, router, auth context wiring
│   │   ├── App.jsx                Route table
│   │   ├── api/client.js          Axios client + every backend call, in one place
│   │   ├── context/AuthContext.jsx  Login state, JWT storage, current user
│   │   ├── components/            Sidebar, RiskGauge, Card/Button/Badge, ProtectedRoute
│   │   └── pages/                 Landing, Login, Register, UrlScanner, SmsAnalyzer,
│   │                               EmailScanner, Alerts, Dashboard, Reports, Team, ApiAccess
│   ├── package.json
│   ├── vite.config.js             Dev server + /api proxy to backend on :8000
│   ├── tailwind.config.js         Design tokens (colors, type, shadows)
│   └── Dockerfile / nginx.conf
│
├── docker-compose.yml            Runs backend + frontend together
├── .env.example                  Canonical environment template
├── ENVIRONMENT_SETUP.md          Environment setup and validation guide
└── README.md                     You are here
```

---

## 2. Language / framework choices, and why

| Layer | Choice | Why |
|---|---|---|
| Backend language | **Python 3.12** | Best ecosystem for text/NLP heuristics and for later swapping in a real ML model (scikit-learn / PyTorch) without a rewrite. |
| Backend framework | **FastAPI** | Async by default (matters for the WebSocket alert feed), automatic OpenAPI docs at `/docs` for the "API Access" page, and Pydantic gives you request validation for free. |
| Database | **SQLite by default, Postgres-ready** | SQLite needs zero setup for local dev/demo. Swapping to Postgres is a one-line `DATABASE_URL` change (SQLAlchemy async engine already supports both) — do this before real production traffic. |
| Auth | **JWT (python-jose) + bcrypt (passlib)** | Stateless tokens scale horizontally; industry-standard password hashing. |
| Frontend language | **JavaScript (React 18)** | Fastest path to a polished, componentized dashboard; huge ecosystem for charts (Recharts) and icons (lucide-react) used here. |
| Frontend build tool | **Vite** | Near-instant dev server reloads, small production bundles. |
| Styling | **Tailwind CSS** | Consistent design tokens (see `tailwind.config.js`) without hand-rolled CSS files scattered across 10+ pages. |
| Real-time alerts | **Native WebSockets** | No extra infra needed for a single-instance deployment. Documented upgrade path to Redis pub/sub for multi-instance scaling (see comment in `websocket_manager.py`). |
| Packaging | **Docker + docker-compose** | One command (`docker compose up`) runs the whole stack identically on any machine. |

**On the "AI" in the detection engines:** the scanners use a transparent,
rule-based scoring model (documented signal-by-signal in
`services/url_detection.py`, `sms_detection.py`, `email_detection.py`)
rather than an opaque black-box classifier. That was a deliberate choice:
every verdict comes with plain-English reasons ("uses a raw IP address",
"domain closely mimics paypal.com"), which is what makes the product
trustworthy and debuggable. The `app/ml/` folder is a marked extension
point — swap `score_url()` for a trained gradient-boosted or transformer
classifier later without touching any router or frontend code, as long as
you keep the `(score: float, reasons: list[str])` return shape.

---

## 3. Running it locally (no Docker)

**Backend:**
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate      # optional but recommended
pip install -r requirements.txt
cd ..
cp .env.example .env                                     # replace the SECRET_KEY placeholder
cd backend
python -m app.run
```
Backend runs at `http://localhost:8000`. Interactive API docs: `http://localhost:8000/docs`.

**Frontend** (in a second terminal):
```bash
cd frontend
npm install
npm run dev
```
Frontend runs at `http://localhost:5173` and proxies `/api` calls to the backend automatically.

Open `http://localhost:5173` — the app works immediately with no signup
required for the detection tools (URL Scanner, SMS Analyzer, Email
Scanner, Alerts). Create an account to unlock Team Dashboard, Reporting
Suite, Team management, and API Access.

---

## 4. Running it with Docker (recommended for a real deployment)

```bash
cd phishguard-ai
cp .env.example .env                    # replace the SECRET_KEY placeholder
docker compose up --build
```
- Frontend: `http://localhost`
- Backend API: `http://localhost:8000`

`docker-compose.yml` wires the two containers together and proxies
`/api` and the WebSocket upgrade from nginx to the backend container.

---

## 5. Before you take this to production

This is a real, working full-stack app, not a demo shell — but a few
things are intentionally left as documented next steps rather than guessed at:

1. **Generate a real `SECRET_KEY`**: `openssl rand -hex 32`, put it in the root `.env`. Never ship the placeholder.
2. **Switch to Postgres**: set `APP_ENV=production` and `DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/phishguard` in the root `.env`.
3. **Gmail integration**: the OAuth flow is scaffolded but not wired to live credentials (that requires *your own* Google Cloud OAuth client — a security/consent-screen decision only you should make). See the detailed inline comment in `backend/app/routers/email_scanner.py`.
4. **Multi-instance alerts**: the WebSocket manager is in-memory and works great for a single backend process. If you scale to multiple API workers/containers, back it with Redis pub/sub instead (noted in `websocket_manager.py`).
5. **Threat-intel enrichment**: VirusTotal and Google Safe Browsing are not integrated; the scanners currently use heuristics.
6. **Rate limiting** on the public API endpoints before opening `API Access` to the internet.

---

## 6. Detection engine reference

| Signal category | URL | SMS | Email |
|---|:---:|:---:|:---:|
| Urgency / pressure language | | ✅ | ✅ |
| Credential/OTP harvesting keywords | ✅ (path/query) | ✅ | ✅ |
| Typosquatting / brand impersonation | ✅ | | ✅ (sender domain mismatch) |
| Punycode / homograph domains | ✅ | | |
| IP-address hosts | ✅ | | |
| URL shorteners | ✅ | (via embedded link) | (via embedded link) |
| Suspicious TLDs | ✅ | | |
| Prize/lottery bait | | ✅ | ✅ |
| Delivery/shipping spoof | | ✅ | |
| Attachment lures | | | ✅ |

Every scan is scored 0–100 and classified: **0–29 safe · 30–64 suspicious
· 65–100 malicious.**
