from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class EvidenceSchema(BaseModel):
    id: str
    scan_id: str
    finding_id: Optional[str] = None
    module: str
    evidence_type: str
    title: str
    sanitized_summary: str
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None
    collected_at: str
    is_demo: bool = True
