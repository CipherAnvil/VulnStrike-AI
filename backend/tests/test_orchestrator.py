import pytest
from app.orchestrator.scope import validate_scope
from app.schemas.scan import ScanCreateRequest, ScanProfile
from app.orchestrator.registry import registry
from app.storage.evidence import sanitize_and_redact

def test_scope_validation_authorized():
    valid, msg = validate_scope("http://localhost:8080/api", authorized_confirmation=True)
    assert valid is True
    assert "authorized lab demonstration scope" in msg

def test_scope_validation_unauthorized_external():
    valid, msg = validate_scope("https://google.com", authorized_confirmation=True)
    assert valid is False
    assert "out of scope" in msg

def test_scope_validation_cloud_metadata():
    valid, msg = validate_scope("http://169.254.169.254/latest/meta-data", authorized_confirmation=True)
    assert valid is False
    assert "Forbidden target" in msg

def test_scope_validation_missing_confirmation():
    valid, msg = validate_scope("http://localhost:8080", authorized_confirmation=False)
    assert valid is False
    assert "confirmation checkbox is required" in msg

def test_scan_create_schema():
    req = ScanCreateRequest(
        target_url="http://localhost:8080",
        authorized_confirmation=True,
        profile=ScanProfile.QUICK
    )
    assert req.profile == ScanProfile.QUICK
    assert len(req.enabled_modules) > 0

def test_evidence_sanitization_and_redaction():
    secret_text = "User logged in with password='SuperSecretPassword123!' and token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.xyz"
    sanitized = sanitize_and_redact(secret_text)
    assert "SuperSecretPassword123!" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized or "[REDACTED_JWT_TOKEN]" in sanitized

def test_module_registry():
    modules = registry.list_modules()
    assert len(modules) >= 4
    names = [m["name"] for m in modules]
    assert "cve_intel" in names
    assert "auth_tester" in names
