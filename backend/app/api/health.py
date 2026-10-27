from fastapi import APIRouter
from app.orchestrator.registry import registry

router = APIRouter(prefix="/api/health", tags=["System Health & Modules"])

@router.get("")
def health_check():
    return {
        "status": "healthy",
        "service": "VulnStrike AI Orchestrator Core",
        "version": "1.0.0",
        "database": "sqlite_connected",
        "is_demo": True,
        "ml_engine": {
            "status": "online_simulated",
            "model": "VulnVerifier-DeBERTa-v3",
            "version": "2.1.0",
            "precision": 0.942,
            "recall": 0.918,
            "f1": 0.930,
            "evaluation_split": "CVE-Bench-Synthetic-2026",
            "evaluated_at": "2026-10-20T18:00:00Z",
            "is_demo": True
        },
        "registered_modules": registry.list_modules()
    }
