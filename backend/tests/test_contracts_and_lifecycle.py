import uuid

from app.orchestrator.registry import registry
from app.schemas.contracts import CONTRACT_VERSION, ContractStatus, ScannerInputContract, ScannerOutputContract
from app.schemas.evidence import EvidenceSchema
from app.schemas.finding import FindingCategory, FindingSchema, Severity, VerificationStatus


def test_scanner_input_output_contracts():
    module = registry.get("cve_intel")
    assert module is not None

    contract = module.build_input_contract(
        scan_id="SCAN-TEST-CONTRACT",
        target_url="http://127.0.0.1:8088",
        scope_metadata={"allowed": True},
    )
    assert isinstance(contract, ScannerInputContract)
    assert contract.contract_version == CONTRACT_VERSION

    findings, evidence = __import__("asyncio").run(module.run("SCAN-TEST-CONTRACT", "http://127.0.0.1:8088"))
    output = module.to_output_contract("SCAN-TEST-CONTRACT", findings, evidence)
    assert isinstance(output, ScannerOutputContract)
    assert output.status == ContractStatus.OK
    assert output.contract_version == CONTRACT_VERSION
    assert len(output.findings) >= 1


def test_registry_capabilities():
    caps = registry.capabilities()
    assert len(caps) >= 4
    names = {c["name"] for c in caps}
    assert {"cve_intel", "web_analyzer", "auth_tester", "api_inspector"}.issubset(names)
    assert registry.has_module("cve_intel")
    assert "cve_intel" in registry.available_modules()


def test_malformed_module_output_cannot_corrupt_normalization():
    module = registry.get("web_analyzer")
    assert module is not None

    scan_id = f"SCAN-TEST-{uuid.uuid4().hex[:8]}"
    finding = FindingSchema(
        id=f"F-{uuid.uuid4().hex[:8]}",
        scan_id=scan_id,
        module=module.name,
        category=FindingCategory.MISCONFIGURATION,
        title="Test header issue",
        severity=Severity.MEDIUM,
        verification_status=VerificationStatus.CONFIRMED,
        endpoint="http://127.0.0.1:8088/",
        summary="Missing headers",
        description="Headers missing",
        evidence_references=[],
        remediation_guidance="Add headers",
        ml_confidence=None,
        created_at="2026-10-24T12:00:00Z",
        is_demo=True,
    )
    evidence = EvidenceSchema(
        id=f"EV-{uuid.uuid4().hex[:8]}",
        scan_id=scan_id,
        finding_id=finding.id,
        module=module.name,
        evidence_type="header_analysis",
        title="Headers",
        sanitized_summary="Headers observed",
        request_data=None,
        response_data=None,
        collected_at="2026-10-24T12:00:00Z",
        is_demo=True,
    )

    output = module.to_output_contract(scan_id, [finding], [evidence])
    assert output.findings[0].severity.value == "medium"
    assert output.evidence[0].id == evidence.id
