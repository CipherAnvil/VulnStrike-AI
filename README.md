# VulnStrike AI — Browser Crawler, Auth Exploits & CVE Fingerprinting Suite

Standalone Python 3.11+ security testing modules for **VulnStrike AI** (authorized Docker lab testing). Designed specifically for **hybrid server-rendered + JavaScript API applications** using **both session cookies and Bearer JWTs**, with structured JSON outputs ready for an upstream orchestrator to execute and merge.

---

## Strict Dependency Footprint

Only three third-party packages are used across the entire codebase (everything else uses the Python 3.11+ standard library):

```bash
pip install -r requirements.txt
playwright install chromium
```

`requirements.txt`:
- `playwright`
- `requests`
- `PyJWT`

---

## Directory Layout

```text
vulnstrike/
├── crawler.py                 # Subsystem 1: Playwright Web & API Crawler
├── cve_fingerprinter.py       # Subsystem 2: Tech Version Fingerprinter + NVD v2.0 Client
├── idor_tester.py             # Subsystem 3.1: Dual-Context Hybrid IDOR Verifier
├── jwt_inspector.py           # Subsystem 3.2: JWT Decoder, alg:none Tester & Secret Guesser
├── xss_verifier.py            # Subsystem 3.3: Reflected/Stored XSS & Screenshot Verifier
├── requirements.txt           # Strictly playwright, requests, PyJWT
├── examples/
│   ├── idor_config.example.json
│   ├── xss_config.example.json
│   ├── sample_wordlist.txt
│   └── merge_reports.py       # Reference orchestrator merger
├── tests/
│   ├── mock_lab_app.py        # Local hybrid vulnerable lab server for testing
│   └── run_e2e_verification.py
└── sample_outputs/            # Sample JSON outputs & XSS proof screenshots
```

Every standalone `.py` script is organized into modular, documented functions with type annotations—so teammates' orchestrator scripts can **either** invoke them via `subprocess.run(...)` CLI flags **or** import their core functions directly.

---

## Subsystem 1 — Playwright Crawler (`crawler.py`)

Crawls internal links up to `--max-depth`, extracts `<form>` elements (`action`, `method`, and all `input`/`textarea`/`select`/`button` controls), captures browser session cookies, logs JavaScript `XHR`/`fetch` API calls via `page.on("request")`, and isolates navigation/timeout errors without aborting the crawl.

### CLI Usage

```bash
python crawler.py \
  --url http://localhost:8080 \
  --max-depth 2 \
  --max-pages 50 \
  --output output/crawl_report.json
```

Optional authenticated hybrid crawl flags:
- `--cookie "session_id=abc123"` (repeatable)
- `--auth-token "<jwt>"` (injects `Authorization: Bearer` header and seeds `localStorage`)

### Output JSON Schema

```json
{
  "pages": [
    {
      "url": "http://localhost:8080/",
      "status_code": 200,
      "depth": 0,
      "forms": [
        {
          "action": "http://localhost:8080/api/login",
          "method": "POST",
          "inputs": [
            { "name": "username", "type": "text", "id": "username-input" },
            { "name": "password", "type": "password", "id": "password-input" }
          ]
        }
      ],
      "cookies": [
        {
          "name": "visitor_track",
          "value": "lab_vis_01",
          "domain": "localhost",
          "path": "/",
          "httpOnly": false,
          "secure": false,
          "sameSite": "Lax",
          "expires": -1
        }
      ],
      "api_calls": [
        {
          "method": "GET",
          "url": "http://localhost:8080/api/stats",
          "resource_type": "fetch"
        }
      ],
      "error": null
    }
  ]
}
```

---

## Subsystem 2 — CVE Tech Fingerprinter (`cve_fingerprinter.py`)

Fetches a target URL using `requests`, parses HTML via stdlib `html.parser`, extracts technologies + versions from `Server` / `X-Powered-By` headers (stripping OS suffixes like `-1ubuntu2`), `<meta name="generator|framework|...">` tags, and `<script src="...">` filenames/CDN paths, then queries `https://services.nvd.nist.gov/rest/json/cves/2.0` using CPE range matching (`virtualMatchString` + `versionStart`/`versionEnd`) with keyword fallback, automatic sliding rate-limit pacing, exponential-backoff retries on `429`/`403`/`5xx`, and a **fast-fail circuit breaker** (`--connect-timeout 3.5`) so air-gapped or firewalled lab environments never hang.

### CLI Usage

```bash
# Optional: export NVD_API_KEY="your-key" for 50 req/30s (vs 5 req/30s unauthenticated)
python cve_fingerprinter.py \
  --url http://localhost:8080 \
  --max-cves 25 \
  --output output/cve_report.json

# Air-gapped / offline Docker lab mode (fingerprints versions locally without external NVD calls)
python cve_fingerprinter.py \
  --url http://localhost:8080 \
  --offline \
  --output output/cve_report.json
```

### Output JSON Schema

```json
[
  {
    "technology": "nginx",
    "version": "1.18.0",
    "source": "header:Server",
    "cves": [
      {
        "id": "CVE-2021-23017",
        "cvss": 7.7,
        "has_public_exploit": true
      }
    ]
  }
]
```

---

## Subsystem 3 — Auth Exploit Modules

### 3.1 IDOR Tester (`idor_tester.py`)

Logs in User A and User B inside two isolated Playwright `BrowserContext` instances, automatically harvesting **both** session cookies and Bearer JWTs (from JSON login responses, `localStorage`/`sessionStorage`, or outgoing headers). Expands `{id}` patterns across explicit IDs (`--ids`), ID ranges (`--id-range`), and/or User A's listing endpoint (`--discover-endpoint`), and compares User A vs. User B access while filtering out `401`/`403` denials, soft login redirects, and session-scoped self-profile endpoints (such as `/api/me`).

```bash
python idor_tester.py \
  --base-url http://localhost:8080 \
  --user-a "alice:alice_password_123" \
  --user-b "bob:bob_password_123" \
  --pattern "/api/orders/{id}" \
  --ids "101,102" \
  --id-range "100-110" \
  --discover-endpoint "/api/orders" \
  --output output/idor_report.json
```

Or run from a JSON config file:
```bash
python idor_tester.py --config examples/idor_config.example.json --output output/idor_report.json
```

### 3.2 JWT Inspector (`jwt_inspector.py`)

1. Decodes JWT headers and claims without signature verification (`PyJWT`) and flags missing/expired `exp` claims.
2. Forges `"alg": "none"` (`none`, `None`, `NONE`, with/without trailing dot) variants and probes `--endpoint` after confirming baseline rejection of a corrupted signature.
3. Streams `--wordlist` line-by-line to perform offline HMAC (`HS256`/`HS384`/`HS512`) secret guessing via `PyJWT`.

```bash
python jwt_inspector.py \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --endpoint http://localhost:8080/api/jwt-protected \
  --tamper-claims '{"role": "admin"}' \
  --wordlist examples/sample_wordlist.txt \
  --output output/jwt_report.json
```

### 3.3 XSS Verification Helper (`xss_verifier.py`)

Injects candidate XSS payloads into target CSS selectors via Playwright, supporting both **same-page Reflected/DOM XSS** and **separate post-submit feed routes (`--verify-url`) for Stored XSS**. Confirms execution via:
- Browser `dialog` events (`alert`, `confirm`, `prompt`) — auto-dismissed cleanly with a visual proof banner rendered into the screenshot
- Live `MutationObserver` watching for dynamically injected `<script>`, `<svg>`, `<iframe>`, inline `on*` event attributes, `javascript:` URIs, or custom `--mutation-selector` matches
- Baseline-subtracted DOM & dialog tracking so persistent Stored XSS payloads do not pollute subsequent payload test cases, and HTML-escaped text never triggers false positives

```bash
# Reflected XSS check
python xss_verifier.py \
  --url http://localhost:8080/search \
  --selector "#search-box" \
  --payload "<script>alert('XSS')</script>" \
  --screenshot-dir output/screenshots \
  --output output/xss_reflected.json

# Stored XSS check (inject on /feedback, verify on /comments)
python xss_verifier.py \
  --url http://localhost:8080/feedback \
  --verify-url http://localhost:8080/comments \
  --selector "#comment-input" \
  --submit-selector "#submit-comment" \
  --extra-field "#author-input=Auditor" \
  --payload '<img src=x onerror="alert(1)">' \
  --screenshot-dir output/screenshots \
  --output output/xss_stored.json
```

---

## Merging Reports & Running Verification Tests

To merge all subsystem JSON files into one consolidated report:

```bash
python examples/merge_reports.py --input-dir output --output output/merged_vulnstrike_report.json
```

To run the full local end-to-end test suite against the self-contained mock hybrid lab server + local mock NVD v2.0 server (zero outbound internet access required):

```bash
python tests/run_e2e_verification.py

# Optional: test against live services.nvd.nist.gov when online
python tests/run_e2e_verification.py --live-nvd
```
