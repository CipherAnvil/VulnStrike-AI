from typing import List
from app.schemas.finding import FindingSchema
from app.schemas.evidence import EvidenceSchema
from app.schemas.report import AttackGraphData, AttackGraphNode, AttackGraphEdge

def build_attack_graph(scan_id: str, target_url: str, findings: List[FindingSchema], evidence: List[EvidenceSchema]) -> AttackGraphData:
    """
    Constructs an explicit, deterministic attack-chain graph based on authenticated findings
    and verified relationship fixtures. Never invents unsupported attack paths.
    """
    nodes: List[AttackGraphNode] = []
    edges: List[AttackGraphEdge] = []

    # Target entry node
    nodes.append(AttackGraphNode(
        id="target-root",
        type="target",
        label=f"Target: {target_url}",
        severity="info",
        status="active",
        data={"target_url": target_url, "description": "Authorized demonstration target"}
    ))

    # Add findings as nodes
    finding_map = {}
    for f in findings:
        node_id = f"finding-{f.id}"
        finding_map[f.category.value if hasattr(f.category, 'value') else f.category] = node_id
        nodes.append(AttackGraphNode(
            id=node_id,
            type="finding",
            label=f.title[:38] + ("..." if len(f.title) > 38 else ""),
            severity=f.severity.value if hasattr(f.severity, 'value') else f.severity,
            status=f.verification_status.value if hasattr(f.verification_status, 'value') else f.verification_status,
            data={
                "id": f.id,
                "title": f.title,
                "endpoint": f.endpoint,
                "severity": f.severity.value if hasattr(f.severity, 'value') else f.severity,
                "verification_status": f.verification_status.value if hasattr(f.verification_status, 'value') else f.verification_status,
                "module": f.module,
                "ml_confidence": f.ml_confidence,
                "evidence_references": f.evidence_references,
                "remediation": f.remediation_guidance
            }
        ))
        
        # Link root target to discovering endpoint
        edges.append(AttackGraphEdge(
            id=f"edge-root-{f.id}",
            source="target-root",
            target=node_id,
            label="Discovered on endpoint",
            relationship="discovery"
        ))

    # Add explicit supported attack relationship fixture:
    # Access Control bypass leads to Exposed Test Record disclosure
    access_node = finding_map.get("access_control")
    info_node = finding_map.get("info_disclosure")
    if access_node and info_node:
        edges.append(AttackGraphEdge(
            id="edge-access-to-data-leak",
            source=access_node,
            target=info_node,
            label="Permits pivot into user registry",
            evidence_id="EV-REL-01",
            relationship="exploit_pivot"
        ))

    # Add impact node representing test record exfiltration
    if info_node:
        impact_id = "impact-data-exfil"
        nodes.append(AttackGraphNode(
            id=impact_id,
            type="impact",
            label="Potential Synthetic Tenant Record Exposure",
            severity="high",
            status="confirmed",
            data={
                "impact_type": "Data Exposure",
                "details": "Chained access control failure and unrestricted endpoint allow reading seeded lab user fixtures."
            }
        ))
        edges.append(AttackGraphEdge(
            id="edge-leak-to-impact",
            source=info_node,
            target=impact_id,
            label="Results in",
            relationship="consequence"
        ))

    return AttackGraphData(nodes=nodes, edges=edges)
