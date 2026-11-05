# 🛡️ VulnStrike AI — Automated Vulnerability Scanner ML Pipeline

**Capstone Project:** Automated Vulnerability Verification & Static Analysis Pipeline  
**Role:** Member 1 — Machine Learning & Model Training Lead  
**Authorized Scope:** Educational & authorized security research against our own local Dockerized target apps only (e.g., OWASP Juice Shop, DVWA).

---

## 📌 Deliverable Summary

| Deliverable | Task | Base Model | Dataset | FastAPI Endpoint | Output Schema |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Deliverable 1** | Exploit Response & Anomaly Verifier | `distilbert-base-uncased` | Synthetic HTTP Leaks & HF Payloads | `POST /verify` (Port 8000) | `{label, confidence, is_vulnerable_leak, severity, all_scores}` |
| **Deliverable 2** | Vulnerable Code / CVE Severity Classifier | `microsoft/codebert-base` | `claudios/DiverseVul` & Curated AST Corpus | `POST /classify-code` (Port 8001) | `{vulnerable, severity_score, severity_level, confidence, cwe_hint}` |

---

## 📂 Directory Layout

```text
cyber/
├── requirements.txt                         # Lightweight Vercel serverless & API runtime dependencies
├── requirements-ml.txt                      # Full deep learning dependencies (PyTorch, Transformers, Datasets)
├── README.md                                # Complete capstone documentation
├── vercel.json                              # Vercel deployment & routing configuration
├── api/
│   └── index.py                            # Vercel serverless FastAPI handler & unified local API
├── public/
│   └── index.html                          # Cyber security telemetry & live inference dashboard
├── deliverable1/                            # Deliverable 1: Exploit Response Verifier
│   ├── __init__.py
│   ├── data_loader.py                      # Multi-class 4-category HTTP response dataset
│   ├── train.py                            # DistilBERT fine-tuning script (T4 GPU optimized)
│   ├── evaluate.py                         # Evaluation & confusion matrix heatmap generator
│   ├── app.py                              # FastAPI microservice on port 8000
│   ├── test_client.py                      # Test client sending sample HTTP responses
│   └── vulnstrike_d1_colab.ipynb           # Google Colab notebook for Deliverable 1
└── deliverable2/                            # Deliverable 2: Vulnerable Code / CVE Classifier
    ├── __init__.py
    ├── data_loader.py                      # Code dataset loader (DiverseVul + AST patterns)
    ├── train.py                            # CodeBERT fine-tuning script (T4 GPU optimized)
    ├── evaluate.py                         # CodeBERT evaluation & ROC-AUC confusion matrix
    ├── app.py                              # FastAPI microservice on port 8001
    ├── test_client.py                      # Test client sending vulnerable/secure code snippets
    └── vulnstrike_d2_colab.ipynb           # Google Colab notebook for Deliverable 2
```

---

## 🚀 Google Colab (Free T4 GPU) Quickstart

Both deliverables include dedicated, self-contained notebooks optimized for Colab's free T4 GPU:

1. **Deliverable 1:** Open [vulnstrike_d1_colab.ipynb](file:///c:/Users/Sarvesh/OneDrive/Desktop/cyber/deliverable1/vulnstrike_d1_colab.ipynb)
   - Fine-tunes `distilbert-base-uncased` on HTTP responses (NORMAL, SQL_ERROR_LEAK, XSS_REFLECTED, STACK_TRACE_LEAK).
   - Serves in-notebook `POST /verify` on port 8000.
2. **Deliverable 2:** Open [vulnstrike_d2_colab.ipynb](file:///c:/Users/Sarvesh/OneDrive/Desktop/cyber/deliverable2/vulnstrike_d2_colab.ipynb)
   - Fine-tunes `microsoft/codebert-base` on source functions (CWE-120 Buffer Overflow, CWE-89 SQLi, CWE-78 Command Injection, CWE-22 Path Traversal).
   - Serves in-notebook `POST /classify-code` on port 8001.

### Colab Execution Steps:
* Ensure GPU is active: **Runtime** → **Change runtime type** → **T4 GPU** → **Save**.
* Click **Runtime** → **Run all** (`Ctrl + F9`).
* Training completes in ~3-4 minutes per model with mixed precision (`fp16=True`).

---

## 💻 Local CLI Execution

### 1. Environment Installation
```bash
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Option A: Lightweight Web Dashboard & Serverless API (Vercel compatible)
pip install -r requirements.txt

# Option B: Full Deep Learning & Model Training (PyTorch, Transformers, Datasets)
pip install -r requirements-ml.txt
```

### 🌟 Unified Live Dashboard (Deliverable 1 + Deliverable 2)
```bash
# Launch unified API & interactive web UI on port 8000
python -m uvicorn api.index:app --port 8000 --reload
# Open http://localhost:8000 in your browser
```

### 2. Deliverable 1: Exploit Response Verifier
```bash
# Train DistilBERT
python deliverable1/train.py --num_train_epochs 4 --samples_per_class 600

# Evaluate & generate confusion matrix
python deliverable1/evaluate.py --model_path ./results_distilbert_response_verifier/final_model

# Launch FastAPI server (Port 8000)
python -m uvicorn deliverable1.app:app --port 8000 --reload

# Run Automated Test Suite
python deliverable1/test_client.py
```

### 3. Deliverable 2: CodeBERT Vulnerability Classifier
```bash
# Train CodeBERT
python deliverable2/train.py --num_train_epochs 4 --max_samples 1200

# Evaluate & generate confusion matrix
python deliverable2/evaluate.py --model_path ./results_codebert_vuln_classifier/final_model

# Launch FastAPI server (Port 8001)
python -m uvicorn deliverable2.app:app --port 8001 --reload

# Run Automated Test Suite
python deliverable2/test_client.py
```

---

## 🌐 FastAPI REST API Endpoints

### 1. `POST /verify` (Port 8000 - Exploit Response Verifier)
**Request Body:**
```json
{
  "response_text": "<html><body><h1>Database Error</h1><p>You have an error in your SQL syntax near '' OR 1=1' at line 1</p></body></html>"
}
```
**Response Body:**
```json
{
  "label": "SQL_ERROR_LEAK",
  "confidence": 0.9982,
  "is_vulnerable_leak": true,
  "severity": "HIGH",
  "all_scores": {
    "NORMAL": 0.0003,
    "SQL_ERROR_LEAK": 0.9982,
    "XSS_REFLECTED": 0.0009,
    "STACK_TRACE_LEAK": 0.0006
  },
  "inference_latency_ms": 11.2,
  "model_source": "./results_distilbert_response_verifier/final_model"
}
```

### 2. `POST /classify-code` (Port 8001 - CodeBERT CVE Classifier)
**Request Body:**
```json
{
  "code_snippet": "void copy_user_name(const char *src) {\n    char dest[32];\n    strcpy(dest, src);\n}",
  "language": "c"
}
```
**Response Body:**
```json
{
  "vulnerable": true,
  "severity_score": 0.91,
  "severity_level": "CRITICAL",
  "confidence": 0.95,
  "cwe_hint": "CWE-120: Buffer Copy without Checking Size of Input",
  "inference_latency_ms": 13.8,
  "model_source": "microsoft/codebert-base"
}
```

---

## 🔒 Scope & Compliance Note

VulnStrike AI is developed strictly for defensive verification, vulnerability auditing, and security education against our team's designated Docker lab targets. No live, unauthorized, or external systems should ever be targeted.
