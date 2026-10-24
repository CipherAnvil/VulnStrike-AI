from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app.storage.database import get_db
from app.storage.repositories import ScanRepository, FindingRepository, EvidenceRepository
from app.reporting.generator import generate_json_report, generate_html_report
from app.orchestrator.attack_graph import build_attack_graph
from app.schemas.report import AttackGraphData

router = APIRouter(prefix="/api/reports", tags=["Reports & Attack Graphs"])

@router.get("/{scan_id}/json")
def get_scan_report_json(scan_id: str, db: Session = Depends(get_db)):
    scan_repo = ScanRepository(db)
    scan = scan_repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = FindingRepository(db).list_by_scan(scan_id)
    evidence = EvidenceRepository(db).list_by_scan(scan_id)
    return generate_json_report(scan, findings, evidence)

@router.get("/{scan_id}/html")
def get_scan_report_html(scan_id: str, db: Session = Depends(get_db)):
    scan_repo = ScanRepository(db)
    scan = scan_repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = FindingRepository(db).list_by_scan(scan_id)
    evidence = EvidenceRepository(db).list_by_scan(scan_id)
    html_content = generate_html_report(scan, findings, evidence)
    return Response(content=html_content, media_type="text/html")

@router.get("/{scan_id}/graph", response_model=AttackGraphData)
def get_scan_attack_graph(scan_id: str, db: Session = Depends(get_db)):
    scan_repo = ScanRepository(db)
    scan = scan_repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = FindingRepository(db).list_by_scan(scan_id)
    evidence = EvidenceRepository(db).list_by_scan(scan_id)
    return build_attack_graph(scan_id, scan.target_url, findings, evidence)
