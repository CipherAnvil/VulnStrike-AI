# VulnStrike AI — Flagship Cybersecurity Platform

VulnStrike AI is a cybersecurity assessment and attack-path orchestration platform built for controlled, authorized college demonstration environments. It integrates web security assessments, CVE intelligence, evidence-backed vulnerability findings, interactive attack-chain graph relationships, ML-assisted verification boundaries, and automated remediation reporting.

---

## 1. Architecture & Project Boundaries

```
vulnstrike/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application & CORS configuration
│   │   ├── api/
│   │   │   ├── scans.py                # Scan creation, listing, lifecycle management
│   │   │   ├── findings.py             # Filtered finding inventory endpoints
│   │   │   ├── reports.py              # JSON/HTML report & attack graph endpoints
│   │   │   └── health.py               # Module registry & backend health
│   │   ├── schemas/
│   │   │   ├── scan.py                 # Pydantic schemas for scans & profiles
│   │   │   ├── finding.py              # Pydantic schemas for findings & severity
│   │   │   ├── evidence.py             # Structured evidence models
│   │   │   └── report.py               # Attack graph & report schemas
│   │   ├── orchestrator/
│   │   │   ├── engine.py               # Async execution, timeout isolation, lifecycle
│   │   │   ├── registry.py             # Scanner adapter registry
│   │   │   ├── scope.py                # Strict target scope & SSRF protection
│   │   │   └── attack_graph.py         # Evidence-backed graph relationship generator
│   │   ├── storage/
│   │   │   ├── database.py             # SQLite database engine & ORM models
│   │   │   ├── repositories.py         # Repositories for scans, findings, evidence
│   │   │   └── evidence.py             # Secret redaction & payload sanitization
│   │   ├── reporting/
│   │   │   └── generator.py            # JSON and self-contained HTML audit generators
│   │   └── integrations/
│   │       └── clients.py              # Future scanner worker & ML service adapters
│   ├── tests/
│   │   ├── test_orchestrator.py        # Scope boundaries, redaction, registry tests
│   │   └── test_api.py                 # Repository, attack graph, and reporting tests
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx                # Overview dashboard & metric distribution
│   │   │   ├── scans/page.tsx          # Scan workspace, module selector & live logs
│   │   │   ├── findings/page.tsx       # Search, filter, and finding drawer
│   │   │   ├── graph/page.tsx          # Interactive attack-chain graph visualization
│   │   │   ├── reports/page.tsx        # JSON/HTML export & executive audit summaries
│   │   │   ├── model-intelligence/page.tsx # ML precision, recall, and boundaries
│   │   │   ├── settings/page.tsx       # System health & scanner module registry
│   │   │   └── layout.tsx              # Operations-grade charcoal layout & sidebar
│   │   ├── components/                 # Badges, navigation, alert banners
│   │   └── lib/                        # Typed API client, types, synthetic fixtures
│   └── Dockerfile
├── demo_target/
│   ├── server.py                       # Harmless HTTP server with seeded test vulnerabilities
│   └── Dockerfile
├── docker-compose.yml                  # Full demonstration lab orchestrator
└── README.md
```

---

## 2. Team Member Division & Responsibilities

- **Member 1**: CVE Intelligence pipeline, component fingerprinting, and NVD/MITRE sync.
- **Member 2**: Web application crawler, HTTP header analyzer, and TLS/cipher evaluator.
- **Member 3**: ML-assisted verification service and embedding similarity scoring.
- **Member 4 (Current Project Milestone)**:
  - Master scan orchestrator and module integration pipeline.
  - Attack-chain graph builder and evidence relationship modeling.
  - Sanitized evidence store and automated JSON/HTML reporting.
  - Next.js operations dashboard.
  - Docker-based isolated demonstration lab.
  - End-to-end integration and verification tests.

---

## 3. Authorization & Strict Safety Boundaries

1. **Target Allowlist**: The orchestrator enforces an allowlist (`localhost`, `127.0.0.1`, `demo-target`, `test-lab.local`). Scans to unauthorized external endpoints are blocked with HTTP 400.
2. **SSRF & Metadata Shield**: Hostnames matching `169.254.*` or cloud metadata services (`metadata.google.internal`) are rejected at request validation time.
3. **Explicit Authorization Check**: The user must explicitly toggle the authorization confirmation checkbox before initiating any scan.
4. **Secret Redaction**: Passwords, API tokens, Authorization bearer headers, and JWT tokens are sanitized and replaced with `[REDACTED_SECRET]` before persistence or report rendering.
5. **No Blind Code Execution**: The platform strictly prevents execution of arbitrary untrusted proof-of-concept scripts.
6. **ML Demarcation**: Machine learning confidence scores (`ml_confidence`) are clearly distinguished from empirical proof of exploitation (`verification_status`).

---

## 4. Quick Start: Launching the Application

### Option A: Local Development Run (Fastest)

#### 1. Backend (FastAPI)
```powershell
cd backend
# With virtual environment activated:
$env:PYTHONPATH = "C:\Users\DELL\.gemini\antigravity\scratch\vulnstrike\backend"
..\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### 2. Demo Target Service
```powershell
cd demo_target
python server.py
# Running on http://127.0.0.1:8088
```

#### 3. Frontend Dashboard (Next.js)
```powershell
cd frontend
npm run dev
# Running on http://localhost:3000
```

---

### Option B: Docker Demonstration Lab

```bash
docker-compose up --build -d
```
Services will launch in an isolated bridge network:
- Frontend Dashboard: `http://localhost:3000`
- Backend API & Swagger: `http://localhost:8000/docs`
- Seeded Demonstration Target: `http://localhost:8088`

To tear down and reset demo data:
```bash
docker-compose down -v
```

---

## 5. Running Verification Tests

Run the full pytest suite for scope validation, safe HTTP execution, contracts/adapters, evidence redaction, module registry, repositories, reports, and attack graph generation:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -v
```

Tests use an isolated temporary database and do not modify `vulnstrike.db`.

Run TypeScript compilation and static verification:
```powershell
cd frontend
npm run typecheck
npm run build
```

Run the frontend API fallback and demo-labeling tests:
```powershell
cd frontend
npm run test:api
```

### Environment notes
- Docker/Compose may be unavailable in some environments; see `docker-compose.yml` for the isolated lab configuration.
- Only the authorized local demo target and explicitly allowed lab hosts are testable.
- Simulated ML metrics and mock modules are labeled and must not be presented as verified live results.
