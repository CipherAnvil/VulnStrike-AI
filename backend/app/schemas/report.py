from typing import List, Optional, Dict, Any
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

class AttackGraphNode(BaseModel):
    id: str
    type: str # 'target', 'endpoint', 'finding', 'impact'
    label: str
    severity: Optional[str] = None
    status: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)

class AttackGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    evidence_id: Optional[str] = None
    relationship: str

class AttackGraphData(BaseModel):
    nodes: List[AttackGraphNode]
    edges: List[AttackGraphEdge]

class ReportSchema(BaseModel):
    id: str
    scan_id: str
    target_url: str
    generated_at: str
    summary_stats: Dict[str, Any]
    findings: List[Dict[str, Any]]
    evidence_list: List[Dict[str, Any]]
    attack_chain_summary: str
    remediation_roadmap: List[Dict[str, Any]]
    compliance_notes: str
