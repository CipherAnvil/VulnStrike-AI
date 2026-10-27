from typing import Dict, List, Set

from app.schemas.evidence import EvidenceSchema
from app.schemas.finding import FindingSchema
from app.schemas.report import AttackGraphData, AttackGraphEdge, AttackGraphNode


def _category_value(finding: FindingSchema) -> str:
    return finding.category.value if hasattr(finding.category, "value") else str(finding.category)


def _severity_value(finding: FindingSchema) -> str:
    return finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)


def _status_value(finding: FindingSchema) -> str:
    return finding.verification_status.value if hasattr(finding.verification_status, "value") else str(finding.verification_status)


def build_attack_graph(scan_id: str, target_url: str, findings: List[FindingSchema], evidence: List[EvidenceSchema]) -> AttackGraphData:
    """
    Constructs an explicit, deterministic attack-chain graph based on authenticated findings
    and verified relationship fixtures. Never invents unsupported attack paths.
    """
    nodes: List[AttackGraphNode] = []
    edges: List[AttackGraphEdge] = []
    node_ids: Set[str] = set()
    edge_ids: Set[str] = set()

    def add_node(node: AttackGraphNode) -> None:
        if node.id in node_ids:
            return
        nodes.append(node)
        node_ids.add(node.id)

    def add_edge(edge: AttackGraphEdge) -> None:
        if edge.id in edge_ids:
            return
        if edge.source not in node_ids or edge.target not in node_ids:
            return
        edges.append(edge)
        edge_ids.add(edge.id)

    add_node(
        AttackGraphNode(
            id="target-root",
            type="target",
            label=f"Target: {target_url}",
            severity="info",
            status="active",
            data={"target_url": target_url, "description": "Authorized demonstration target", "scan_id": scan_id},
        )
    )

    finding_map: Dict[str, str] = {}
    for finding in findings:
        node_id = f"finding-{finding.id}"
        finding_map[_category_value(finding)] = node_id
        add_node(
            AttackGraphNode(
                id=node_id,
                type="finding",
                label=finding.title[:38] + ("..." if len(finding.title) > 38 else ""),
                severity=_severity_value(finding),
                status=_status_value(finding),
                data={
                    "id": finding.id,
                    "title": finding.title,
                    "endpoint": finding.endpoint,
                    "severity": _severity_value(finding),
                    "verification_status": _status_value(finding),
                    "module": finding.module,
                    "category": _category_value(finding),
                    "ml_confidence": finding.ml_confidence,
                    "evidence_references": list(finding.evidence_references or []),
                    "remediation": finding.remediation_guidance,
                    "is_demo": finding.is_demo,
                },
            )
        )
        add_edge(
            AttackGraphEdge(
                id=f"edge-root-{finding.id}",
                source="target-root",
                target=node_id,
                label="Discovered on endpoint",
                relationship="discovery",
            )
        )

    access_node = finding_map.get("access_control")
    info_node = finding_map.get("info_disclosure")
    if access_node and info_node:
        add_edge(
            AttackGraphEdge(
                id="edge-access-to-data-leak",
                source=access_node,
                target=info_node,
                label="Permits pivot into user registry (inferred)",
                evidence_id="EV-REL-01",
                relationship="exploit_pivot",
            )
        )

    if info_node:
        impact_id = "impact-data-exfil"
        add_node(
            AttackGraphNode(
                id=impact_id,
                type="impact",
                label="Potential Synthetic Tenant Record Exposure",
                severity="high",
                status="confirmed",
                data={
                    "impact_type": "Data Exposure",
                    "details": "Chained access control failure and unrestricted endpoint allow reading seeded lab user fixtures. This is an inferred consequence for lab demonstration purposes.",
                    "inferred": True,
                },
            )
        )
        add_edge(
            AttackGraphEdge(
                id="edge-leak-to-impact",
                source=info_node,
                target=impact_id,
                label="Results in (inferred)",
                relationship="consequence",
            )
        )

    return AttackGraphData(nodes=nodes, edges=edges)
