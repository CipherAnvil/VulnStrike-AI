import uuid
import pytest
from app.storage.database import SessionLocal, init_db
from app.storage.repositories import ScanRepository, FindingRepository, EvidenceRepository
from app.schemas.scan import ScanStatus
from app.schemas.finding import FindingSchema, Severity, VerificationStatus, FindingCategory
from app.reporting.generator import generate_json_report, generate_html_report
from app.orchestrator.attack_graph import build_attack_graph

def test_repositories_and_reports():
    init_db()
    db = SessionLocal()
    try:
        scan_repo = ScanRepository(db)
        finding_repo = FindingRepository(db)
        evidence_repo = EvidenceRepository(db)

        scan_id = f"SCAN-TEST-{uuid.uuid4().hex[:8]}"
        finding_id = f"F-{uuid.uuid4().hex[:8]}"
        evidence_id = f"EV-{uuid.uuid4().hex[:8]}"
        scan = scan_repo.create(scan_id, "http://localhost:8080", "standard", ["cve_intel"])
        assert scan.id == scan_id
        assert scan.status == ScanStatus.QUEUED

        finding = FindingSchema(
            id=finding_id,
            scan_id=scan_id,
            module="cve_intel",
            category=FindingCategory.ACCESS_CONTROL,
            title="Unauthorized Admin Access",
            severity=Severity.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
            endpoint="http://localhost:8080/admin",
            summary="Admin accessible without token",
            description="Detailed test description",
            evidence_references=[evidence_id],
            remediation_guidance="Enforce RBAC",
            ml_confidence=0.91,
            created_at="2026-10-24T12:00:00Z",
            is_demo=True
        )
        finding_repo.create(finding)

        findings = finding_repo.list_by_scan(scan_id)
        assert len(findings) >= 1
        assert findings[0].title == "Unauthorized Admin Access"

        # Test reports
        json_rep = generate_json_report(scan, findings, [])
        assert json_rep["scan_id"] == scan_id
        assert len(json_rep["findings"]) >= 1

        html_rep = generate_html_report(scan, findings, [])
        assert "VulnStrike AI Security Assessment Report" in html_rep
        assert "Unauthorized Admin Access" in html_rep

        # Test attack graph
        graph = build_attack_graph(scan_id, "http://localhost:8080", findings, [])
        assert len(graph.nodes) >= 2
        assert len(graph.edges) >= 1

    finally:
        db.close()
