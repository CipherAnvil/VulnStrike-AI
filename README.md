# VulnStrike AI — Server-Side Exploit Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **VulnStrike AI (Subsystem: Member 2 - Server-Side Exploit Engine Lead)**  
> An automated, asynchronous multi-vector web vulnerability exploitation engine with AI-assisted WAF evasion capabilities.

---

## 📌 Architecture Overview

```
                        ┌─────────────────────────────────────┐
                        │      Member 3: Crawler Engine       │
                        │ (Discovered URLs, Forms, Endpoints) │
                        └──────────────────┬──────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      MEMBER 2: SERVER-SIDE EXPLOIT ENGINE                       │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │               Async Requester & Concurrency Controller (httpx)          │   │
│   └──────┬──────────────────┬──────────────────┬──────────────────┬─────────┘   │
│          │                  │                  │                  │             │
│          ▼                  ▼                  ▼                  ▼             │
│    ┌───────────┐      ┌───────────┐      ┌───────────┐      ┌───────────┐       │
│    │ SQLi Core │      │ RCE Core  │      │ LFI Core  │      │ SSRF/Upld │       │
│    └─────┬─────┘      └─────┬─────┘      └─────┬─────┘      └─────┬─────┘       │
│          │                  │                  │                  │             │
│          └──────────────────┼──────────────────┴──────────────────┘             │
│                             ▼                                                   │
│             ┌───────────────────────────────┐                                   │
│             │  Response & Anomaly Analyzer  │◄────────► Member 1: AI Mutator    │
│             └───────────────┬───────────────┘           (WAF Bypass Bridge)     │
└─────────────────────────────┼───────────────────────────────────────────────────┘
                              │
                              ▼
        ┌───────────────────────────────────────────┐
        │        Member 4: Orchestrator & UI        │
        │  (Standardized JSON, PoC Scripts, Chaining)│
        └───────────────────────────────────────────┘
```

---

## ⚡ Key Modules

| Module | Location | Capabilities | Evidence Produced |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | [`modules/sqli.py`](modules/sqli.py) | • Auth Bypass (`' OR 1=1--`)<br>• Error Fingerprinting (MySQL, Postgres, SQLite, MSSQL, Oracle)<br>• Time-Based Blind (`SLEEP(5)`) with statistical timing confirmation | Dumped DB data & SQL signatures |
| **Command Injection (RCE)** | [`modules/rce.py`](modules/rce.py) | • Command separator fuzzing (`;`, `\|`, `&&`, `$()`)<br>• Linux/Unix & Windows output regex detection | Shell execution output (e.g. `uid=33(www-data)`) |
| **Path Traversal (LFI)** | [`modules/lfi.py`](modules/lfi.py) | • Depth traversal (`../../../../etc/passwd`)<br>• URL encoding & null-byte bypasses | Leaked system / config file contents |
| **File Upload Bypass** | [`modules/file_upload.py`](modules/file_upload.py) | • Extension spoofing (`.phtml`, `.php.jpg`)<br>• MIME type forgery & Magic Byte injection (`GIF89a;`) | Uploaded shell path & execution canary |
| **SSRF** | [`modules/ssrf.py`](modules/ssrf.py) | • Localhost loopback probe (`127.0.0.1`, `localhost`)<br>• Cloud metadata access (`169.254.169.254`) | Internal service responses & cloud metadata |
| **AI Mutation Bridge** | [`core/ai_client.py`](core/ai_client.py) | • Bridges to Member 1's fine-tuned Hugging Face model on HTTP 403 / WAF triggers | Obfuscated payloads with WAF bypass flag |

---

## 🚀 Installation & Usage

### 1. Clone & Set Up
```bash
git clone https://github.com/your-username/vulnstrike-exploit-engine.git
cd vulnstrike-exploit-engine

python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Run Test Suite
```bash
pytest tests/
```

### 3. Run Exploitation CLI
```bash
# Scan a specific parameter for SQL Injection
python exploit_engine.py --url "http://target.local/login" --param "username" --type sqli

# Scan for Remote Command Execution
python exploit_engine.py --url "http://target.local/ping" --param "ip" --type rce

# Run all 5 exploit vectors and export JSON report
python exploit_engine.py --url "http://target.local/search" --param "q,file,id" --type all --out report.json
```

---

## 📄 Output Schema
All findings are saved in standardized JSON compliant with Member 4's Orchestrator and UI:
```json
[
  {
    "vulnerability_type": "SQL Injection (SQLi)",
    "severity": "CRITICAL",
    "target_url": "http://target.local/search",
    "parameter": "id",
    "description": "Error-Based SQL Injection detected (MySQL error signature identified)",
    "proof": {
      "payload": "'",
      "target_param": "id",
      "http_method": "GET",
      "status_code": 500,
      "response_snippet": "You have an error in your SQL syntax...",
      "curl_command": "curl -k -X GET \"http://target.local/search?id='\"",
      "time_taken_seconds": 0.084
    },
    "is_waf_bypassed": false
  }
]
```

---

## 👥 VulnStrike Team Split
* **Member 1:** Hugging Face ML & Training Lead (Fine-tuning & LoRA).
* **Member 2 (This Repository):** Server-Side Exploit Engine Lead.
* **Member 3:** Headless Browser Crawler, Auth Hacks & CVE Lead.
* **Member 4:** Attack-Chain Orchestrator, UI & Demo Lab Lead.
