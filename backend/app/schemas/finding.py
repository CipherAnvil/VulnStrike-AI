import enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VerificationStatus(str, enum.Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    INCONCLUSIVE = "inconclusive"

class FindingCategory(str, enum.Enum):
    ACCESS_CONTROL = "access_control"
    INJECTION = "injection"
    AUTH_BYPASS = "auth_bypass"
    INFO_DISCLOSURE = "info_disclosure"
    MISCONFIGURATION = "misconfiguration"
    CRYPTOGRAPHY = "cryptography"
    CVE = "cve"

class FindingSchema(BaseModel):
    id: str
    scan_id: str
    module: str
    category: FindingCategory
    title: str
    severity: Severity
    verification_status: VerificationStatus
    endpoint: str
    summary: str
    description: str
    evidence_references: List[str] = Field(default_factory=list)
    remediation_guidance: str
    ml_confidence: Optional[float] = Field(
        default=None,
        description="Assisted confidence score (0.0 to 1.0). Distinct from verification status."
    )
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    created_at: str
    is_demo: bool = True
