import abc
import asyncio
import time
from typing import List, Dict, Any, Tuple, Optional

from app.schemas.contracts import (
    AdapterCapability,
    ContractStatus,
    EvidenceContractItem,
    FindingContractItem,
    FindingSeverity,
    ScannerInputContract,
    ScannerOutputContract,
    VerificationState,
)
from app.schemas.evidence import EvidenceSchema
from app.schemas.finding import FindingCategory, FindingSchema, Severity, VerificationStatus
from app.storage.evidence import sanitize_and_redact


class BaseScannerModule(abc.ABC):
    """
    Standard interface contract for VulnStrike scanner modules.
    Ensures safe error isolation, timeout compliance, and normalized results.
    """
    name: str = "base_module"
    display_name: str = "Base Security Module"
    description: str = "Standard scanner interface"
    version: str = "1.0.0"
    timeout_seconds: int = 15
    capabilities: List[str] = []

    @abc.abstractmethod
    async def run(self, scan_id: str, target_url: str) -> Tuple[List[FindingSchema], List[EvidenceSchema]]:
        pass

    def build_input_contract(
        self,
        scan_id: str,
        target_url: str,
        scope_metadata: Optional[Dict[str, Any]] = None,
        limits: Optional[Dict[str, Any]] = None,
    ) -> ScannerInputContract:
        return ScannerInputContract(
            scan_id=scan_id,
            module_name=self.name,
            target_url=target_url,
            authorized_confirmation=True,
            scope_metadata=scope_metadata or {},
            limits=limits or {"timeout_seconds": self.timeout_seconds},
        )

    def build_capability(self) -> AdapterCapability:
        return AdapterCapability(
            name=self.name,
            display_name=self.display_name,
            version=self.version,
            description=self.description,
            timeout_seconds=self.timeout_seconds,
            supported=True,
            status="ready",
            capabilities=self.capabilities,
        )

    def to_output_contract(
        self,
        scan_id: str,
        findings: List[FindingSchema],
        evidence: List[EvidenceSchema],
        status: ContractStatus = ContractStatus.OK,
        warnings: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
        duration_ms: Optional[int] = None,
    ) -> ScannerOutputContract:
        finding_items: List[FindingContractItem] = []
        for finding in findings:
            sev = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
            ver = finding.verification_status.value if hasattr(finding.verification_status, "value") else finding.verification_status
            try:
                severity = FindingSeverity(sev)
            except Exception:
                severity = FindingSeverity.INFO
            try:
                verification = VerificationState(ver)
            except Exception:
                verification = VerificationState.INCONCLUSIVE
            finding_items.append(
                FindingContractItem(
                    id=finding.id,
                    category=finding.category.value if hasattr(finding.category, "value") else str(finding.category),
                    title=sanitize_and_redact(finding.title),
                    severity=severity,
                    verification_status=verification,
                    endpoint=finding.endpoint,
                    summary=sanitize_and_redact(finding.summary),
                    description=sanitize_and_redact(finding.description),
                    evidence_references=list(finding.evidence_references or []),
                    remediation_guidance=sanitize_and_redact(finding.remediation_guidance),
                    ml_confidence=finding.ml_confidence,
                    cve_id=finding.cve_id,
                    cvss_score=finding.cvss_score,
                    tags=[finding.module],
                    is_demo=finding.is_demo,
                )
            )

        evidence_items: List[EvidenceContractItem] = []
        for ev in evidence:
            evidence_items.append(
                EvidenceContractItem(
                    id=ev.id,
                    finding_id=ev.finding_id,
                    evidence_type=ev.evidence_type,
                    title=sanitize_and_redact(ev.title),
                    sanitized_summary=sanitize_and_redact(ev.sanitized_summary),
                    request_data=sanitize_and_redact(ev.request_data) if ev.request_data else None,
                    response_data=sanitize_and_redact(ev.response_data) if ev.response_data else None,
                    collected_at=ev.collected_at,
                    is_demo=ev.is_demo,
                )
            )

        return ScannerOutputContract(
            scan_id=scan_id,
            module_name=self.name,
            module_version=self.version,
            status=status,
            findings=finding_items,
            evidence=evidence_items,
            warnings=warnings or [],
            errors=errors or [],
            metrics={"finding_count": len(finding_items), "evidence_count": len(evidence_items)},
            duration_ms=duration_ms,
        )

class MockCVEIntelModule(BaseScannerModule):
    name = "cve_intel"
    display_name = "CVE Intelligence & Component Fingerprinting"
    description = "Checks service headers and exposed components against synthetic CVE database"
    version = "1.2.0"

    async def run(self, scan_id: str, target_url: str) -> Tuple[List[FindingSchema], List[EvidenceSchema]]:
        await asyncio.sleep(0.5) # Simulate async inspection
        
        ev_id = f"EV-{scan_id[:8]}-01"
        evidence = EvidenceSchema(
            id=ev_id,
            scan_id=scan_id,
            finding_id=f"VS-{scan_id[:8]}-01",
            module=self.name,
            evidence_type="http_headers",
            title="Outdated Web Framework Banner",
            sanitized_summary="Server banner exposed: Apache/2.4.49 (Unix) with known path traversal vulnerability (simulated).",
            request_data={"method": "GET", "url": f"{target_url}/", "headers": {"User-Agent": "VulnStrike-Scanner/1.0"}},
            response_data={"status_code": 200, "headers": {"Server": "Apache/2.4.49 (Lab-Seed)"}},
            collected_at="2026-10-24T12:00:00Z",
            is_demo=True
        )

        finding = FindingSchema(
            id=f"VS-{scan_id[:8]}-01",
            scan_id=scan_id,
            module=self.name,
            category=FindingCategory.CVE,
            title="Apache 2.4.49 Path Traversal & Remote Code Execution (Simulated)",
            severity=Severity.CRITICAL,
            verification_status=VerificationStatus.CONFIRMED,
            endpoint=f"{target_url}/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
            summary="Server banner and response indicate vulnerable Apache 2.4.49 build in demonstration environment.",
            description="The remote server exposes Apache 2.4.49, which contains a flaw in path normalization leading to unauthorized file read and potential execution in CGI configurations (CVE-2021-41773). Observed in synthetic lab container.",
            evidence_references=[ev_id],
            remediation_guidance="Upgrade Apache HTTP Server to version 2.4.51 or later. Disable cgi-bin modules if not strictly required.",
            ml_confidence=0.98,
            cve_id="CVE-2021-41773",
            cvss_score=9.8,
            created_at="2026-10-24T12:00:00Z",
            is_demo=True
        )
        return [finding], [evidence]

class MockWebAnalyzerModule(BaseScannerModule):
    name = "web_analyzer"
    display_name = "Web Application Security Analyzer"
    description = "Analyzes HTTP headers, TLS attributes, and client-side protection policies"
    version = "1.1.0"

    async def run(self, scan_id: str, target_url: str) -> Tuple[List[FindingSchema], List[EvidenceSchema]]:
        await asyncio.sleep(0.4)
        
        ev_id = f"EV-{scan_id[:8]}-02"
        evidence = EvidenceSchema(
            id=ev_id,
            scan_id=scan_id,
            finding_id=f"VS-{scan_id[:8]}-02",
            module=self.name,
            evidence_type="header_analysis",
            title="Missing Content-Security-Policy & HSTS",
            sanitized_summary="HTTP response headers lack Content-Security-Policy and Strict-Transport-Security directives.",
            request_data={"method": "HEAD", "url": f"{target_url}/api/v1/health"},
            response_data={"status_code": 200, "headers": {"X-Powered-By": "Express-Simulated"}},
            collected_at="2026-10-24T12:00:01Z",
            is_demo=True
        )

        finding = FindingSchema(
            id=f"VS-{scan_id[:8]}-02",
            scan_id=scan_id,
            module=self.name,
            category=FindingCategory.MISCONFIGURATION,
            title="Missing Strict Content-Security-Policy & Transport Headers",
            severity=Severity.MEDIUM,
            verification_status=VerificationStatus.CONFIRMED,
            endpoint=f"{target_url}/api/v1/health",
            summary="Defensive headers CSP and HSTS are absent, increasing exposure to cross-site scripting and downgrade vectors.",
            description="Inspection of root and API endpoints revealed that neither 'Content-Security-Policy' nor 'Strict-Transport-Security' were returned by the target host.",
            evidence_references=[ev_id],
            remediation_guidance="Configure Content-Security-Policy with strict script-src and default-src directives. Add Strict-Transport-Security with max-age=31536000.",
            ml_confidence=0.82,
            created_at="2026-10-24T12:00:01Z",
            is_demo=True
        )
        return [finding], [evidence]

class MockAuthTesterModule(BaseScannerModule):
    name = "auth_tester"
    display_name = "Authentication & Access Control Inspector"
    description = "Identifies broken object level authorization (BOLA) and exposed management endpoints"
    version = "1.0.4"

    async def run(self, scan_id: str, target_url: str) -> Tuple[List[FindingSchema], List[EvidenceSchema]]:
        await asyncio.sleep(0.6)
        
        ev_id = f"EV-{scan_id[:8]}-03"
        evidence = EvidenceSchema(
            id=ev_id,
            scan_id=scan_id,
            finding_id=f"VS-{scan_id[:8]}-03",
            module=self.name,
            evidence_type="access_bypass_probe",
            title="Unauthenticated Internal Admin Metrics Endpoint",
            sanitized_summary="Direct unauthenticated GET request to /internal/admin/metrics returned 200 OK with server telemetry.",
            request_data={"method": "GET", "url": f"{target_url}/internal/admin/metrics"},
            response_data={"status_code": 200, "body_snippet": '{"system":"demo_target","role":"admin_unrestricted","db_records":142}'},
            collected_at="2026-10-24T12:00:02Z",
            is_demo=True
        )

        finding = FindingSchema(
            id=f"VS-{scan_id[:8]}-03",
            scan_id=scan_id,
            module=self.name,
            category=FindingCategory.ACCESS_CONTROL,
            title="Broken Object Level Authorization on Internal Admin Telemetry",
            severity=Severity.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
            endpoint=f"{target_url}/internal/admin/metrics",
            summary="Administrative metrics endpoint responds to unauthenticated client requests without role verification.",
            description="The endpoint /internal/admin/metrics does not enforce token or session validation, allowing any network caller to inspect tenant counts, active processes, and internal configuration keys.",
            evidence_references=[ev_id],
            remediation_guidance="Implement RBAC middleware to enforce valid admin bearer tokens and restrict route access at the ingress reverse proxy.",
            ml_confidence=0.95,
            created_at="2026-10-24T12:00:02Z",
            is_demo=True
        )
        return [finding], [evidence]

class MockAPIInspectorModule(BaseScannerModule):
    name = "api_inspector"
    display_name = "API Schema & Endpoint Probe"
    description = "Scans OpenAPI definitions and probes sensitive data disclosure in JSON payloads"
    version = "1.3.1"

    async def run(self, scan_id: str, target_url: str) -> Tuple[List[FindingSchema], List[EvidenceSchema]]:
        await asyncio.sleep(0.3)
        
        ev_id = f"EV-{scan_id[:8]}-04"
        evidence = EvidenceSchema(
            id=ev_id,
            scan_id=scan_id,
            finding_id=f"VS-{scan_id[:8]}-04",
            module=self.name,
            evidence_type="data_leak_probe",
            title="Exposed Test Customer Records via Unfiltered Query",
            sanitized_summary="GET /api/v1/users returned synthetic customer test records with simulated credit token references.",
            request_data={"method": "GET", "url": f"{target_url}/api/v1/users?limit=5"},
            response_data={"status_code": 200, "sample": '[{"id":1,"email":"test_alice@lab.local","token":"[REDACTED_SECRET]"}]'},
            collected_at="2026-10-24T12:00:03Z",
            is_demo=True
        )

        finding = FindingSchema(
            id=f"VS-{scan_id[:8]}-04",
            scan_id=scan_id,
            module=self.name,
            category=FindingCategory.INFO_DISCLOSURE,
            title="Excessive Data Exposure in User Listing API",
            severity=Severity.MEDIUM,
            verification_status=VerificationStatus.SUSPECTED,
            endpoint=f"{target_url}/api/v1/users",
            summary="User enumeration route returns extensive internal profile fields without field filtering.",
            description="API responses from /api/v1/users include debug flags, synthetic authentication tokens, and internal role assignments not intended for client consumption.",
            evidence_references=[ev_id],
            remediation_guidance="Apply response DTO serialization to filter internal fields before sending JSON responses.",
            ml_confidence=0.74,
            created_at="2026-10-24T12:00:03Z",
            is_demo=True
        )
        return [finding], [evidence]

class ModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, BaseScannerModule] = {}
        # Register default initial mock scanner adapters
        self.register(MockCVEIntelModule())
        self.register(MockWebAnalyzerModule())
        self.register(MockAuthTesterModule())
        self.register(MockAPIInspectorModule())

    def register(self, module: BaseScannerModule):
        self._modules[module.name] = module

    def get(self, name: str) -> Optional[BaseScannerModule]:
        return self._modules.get(name)

    def list_modules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": mod.name,
                "display_name": mod.display_name,
                "description": mod.description,
                "version": mod.version,
                "timeout_seconds": mod.timeout_seconds,
                "status": "ready"
            }
            for mod in self._modules.values()
        ]

    def capabilities(self) -> List[Dict[str, Any]]:
        return [mod.build_capability().model_dump() for mod in self._modules.values()]

    def has_module(self, name: str) -> bool:
        return name in self._modules

    def available_modules(self) -> List[str]:
        return sorted(self._modules.keys())

registry = ModuleRegistry()
