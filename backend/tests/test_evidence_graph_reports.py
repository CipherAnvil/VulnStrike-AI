import uuid

from app.orchestrator.attack_graph import build_attack_graph
from app.reporting.generator import generate_html_report, generate_json_report
from app.schemas.evidence import EvidenceSchema
from app.schemas.finding import FindingCategory, FindingSchema, Severity, VerificationStatus
from app.schemas.scan import ScanProfile, ScanResponse, ScanStatus


def _make_scan(scan_id: str) -> ScanResponse:
    return ScanResponse(
        id=scan_id,
        target_url="http://127.0.0.1:8088",
        status=ScanStatus.COMPLETED,
        profile=ScanProfile.STANDARD,
        enabled_modules=["cve_intel", "auth_tester", "api_inspector"],
        is_demo=True,
        created_at="2026-10-24T12:00:00Z",
        started_at="2026-10-24T12:00:00Z",
        completed_at="2026-10-24T12:00:01Z",
        findings_count=2,
        critical_count=0,
        high_count=1,
        medium_count=1,
        low_count=0,
        info_count=0,
        error_message=None,
        log_messages=[],
    )


def test_graph_uses_valid_relationships_and_marks_inferred():
    scan_id = f"SCAN-TEST-{uuid.uuid4().hex[:8]}"
    findings = [
        FindingSchema(
            id="F-AUTH",
            scan_id=scan_id,
            module="auth_tester",
            category=FindingCategory.ACCESS_CONTROL,
            title="BOLA",
            severity=Severity.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
            endpoint="http://127.0.0.1:8088/internal/admin/metrics",
            summary="Auth bypass",
            description="Missing authz",
            evidence_references=["EV-1"],
            remediation_guidance="Add RBAC",
            created_at="2026-10-24T12:00:00Z",
            is_demo=True,
        ),
        FindingSchema(
            id="F-DATA",
            scan_id=scan_id,
            module="api_inspector",
            category=FindingCategory.INFO_DISCLOSURE,
            title="Data exposure",
            severity=Severity.MEDIUM,
            verification_status=VerificationStatus.SUSPECTED,
            endpoint="http://127.0.0.1:8088/api/v1/users",
            summary="Excessive fields",
            description="Fields exposed",
            evidence_references=["EV-2"],
            remediation_guidance="Filter fields",
            created_at="2026-10-24T12:00:00Z",
            is_demo=True,
        ),
    ]

    graph = build_attack_graph(scan_id, "http://127.0.0.1:8088", findings, [])
    node_ids = {node.id for node in graph.nodes}
    edge_targets = {(edge.source, edge.target, edge.relationship) for edge in graph.edges}
    assert "target-root" in node_ids
    assert ("finding-F-AUTH", "finding-F-DATA", "exploit_pivot") in edge_targets
    assert ("finding-F-DATA", "impact-data-exfil", "consequence") in edge_targets


def test_html_report_escapes_untrusted_content():
    scan_id = f"SCAN-TEST-{uuid.uuid4().hex[:8]}"
    scan = _make_scan(scan_id)
    findings = [
        FindingSchema(
            id="F-XSS",
            scan_id=scan_id,
            module="web_analyzer",
            category=FindingCategory.MISCONFIGURATION,
            title="<script>alert(1)</script>",
            severity=Severity.MEDIUM,
            verification_status=VerificationStatus.CONFIRMED,
            endpoint="http://127.0.0.1:8088/</script>",
            summary="bad",
            description="<img src=x onerror=alert(1)>",
            evidence_references=["EV-1"],
            remediation_guidance="<b>fix</b>",
            created_at="2026-10-24T12:00:00Z",
            is_demo=True,
        )
    ]
    html = generate_html_report(scan, findings, [])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img" in html


def test_json_report_redacts_sensitive_strings():
    scan_id = f"SCAN-TEST-{uuid.uuid4().hex[:8]}"
    scan = _make_scan(scan_id)
    findings = [
        FindingSchema(
            id="F-SEC",
            scan_id=scan_id,
            module="api_inspector",
            category=FindingCategory.INFO_DISCLOSURE,
            title="Leaky endpoint",
            severity=Severity.MEDIUM,
            verification_status=VerificationStatus.SUSPECTED,
            endpoint="http://127.0.0.1:8088/api/v1/users",
            summary="token=abc123456789 and password=SuperSecret",
            description="Authorization: Bearer abc.def.ghi",
            evidence_references=["EV-1"],
            remediation_guidance="Remove secrets",
            created_at="2026-10-24T12:00:00Z",
            is_demo=True,
        )
    ]
    evidence = [
        EvidenceSchema(
            id="EV-1",
            scan_id=scan_id,
            finding_id="F-SEC",
            module="api_inspector",
            evidence_type="data_leak_probe",
            title="response",
            sanitized_summary="password=SuperSecret and Authorization: Bearer abc.def.ghi",
            request_data={"Authorization": "Bearer abc.def.ghi"},
            response_data={"token": "abc123456789"},
            collected_at="2026-10-24T12:00:00Z",
            is_demo=True,
        )
    ]
    report = generate_json_report(scan, findings, evidence)
    text = str(report)
    assert "SuperSecret" not in text
    assert "abc.def.ghi" not in text
    assert "[REDACTED" in text


def test_empty_scan_generates_valid_empty_graph():
    scan_id = f"SCAN-TEST-{uuid.uuid4().hex[:8]}"
    graph = build_attack_graph(scan_id, "http://127.0.0.1:8088", [], [])
    assert len(graph.nodes) == 1
    assert graph.nodes[0].id == "target-root"
    assert graph.edges == []
