import enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanProfile(str, enum.Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"

class ScanCreateRequest(BaseModel):
    target_url: str = Field(..., description="Target URL within authorized lab scope")
    authorized_confirmation: bool = Field(..., description="Must explicitly confirm authorization")
    profile: ScanProfile = Field(default=ScanProfile.STANDARD)
    enabled_modules: List[str] = Field(
        default_factory=lambda: ["cve_intel", "web_analyzer", "auth_tester", "api_inspector"]
    )
    scope_notes: Optional[str] = Field(default=None)

class ScanResponse(BaseModel):
    id: str
    target_url: str
    status: ScanStatus
    profile: ScanProfile
    enabled_modules: List[str]
    is_demo: bool = True
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    error_message: Optional[str] = None
    log_messages: List[str] = Field(default_factory=list)
