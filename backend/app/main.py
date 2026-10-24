import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.storage.database import init_db
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.reports import router as reports_router
from app.api.health import router as health_router

app = FastAPI(
    title="VulnStrike AI Orchestrator API",
    version="1.0.0",
    description="Authorized Cybersecurity Assessment & Attack Graph Orchestrator"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(reports_router)

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/")
def root():
    return {
        "platform": "VulnStrike AI",
        "description": "Authorized Security Assessment & Evidence Pipeline",
        "docs_url": "/docs",
        "health_check": "/api/health"
    }
