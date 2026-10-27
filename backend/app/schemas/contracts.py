from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


CONTRACT_VERSION = "1.0.0"


class ContractStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"
    UNSUPPORTED = "unsupported"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerificationState(str, Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    INCONCLUSIVE = "inconclusive"


class ScannerInputContract(BaseModel):
    contract_version: str = CONTRACT_VERSION
    scan_id: str
    module_name: str
    target_url: str
    authorized_confirmation: bool = True
    scope_metadata: Dict[str, Any] = Field(default_factory=dict)
    limits: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)


class EvidenceContractItem(BaseModel):
    id: str
    finding_id: Optional[str] = None
    evidence_type: str
    title: str
    sanitized_summary: str
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None
    collected_at: str
    is_demo: bool = True


class FindingContractItem(BaseModel):
    id: str
    category: str
    title: str
    severity: FindingSeverity
    verification_status: VerificationState
    endpoint: str
    summary: str
    description: str
    evidence_references: List[str] = Field(default_factory=list)
    remediation_guidance: str
    ml_confidence: Optional[float] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    tags: List[str] = Field(default_factory=list)
    is_demo: bool = True


class ScannerOutputContract(BaseModel):
    contract_version: str = CONTRACT_VERSION
    scan_id: str
    module_name: str
    module_version: str
    status: ContractStatus
    findings: List[FindingContractItem] = Field(default_factory=list)
    evidence: List[EvidenceContractItem] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: Optional[int] = None


class AdapterCapability(BaseModel):
    name: str
    display_name: str
    version: str
    description: str
    timeout_seconds: int
    supported: bool = True
    status: str = "ready"
    capabilities: List[str] = Field(default_factory=list)
