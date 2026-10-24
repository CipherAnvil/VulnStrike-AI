import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.storage.database import get_db
from app.storage.repositories import ScanRepository, FindingRepository, EvidenceRepository
from app.schemas.scan import ScanCreateRequest, ScanResponse, ScanStatus
from app.orchestrator.scope import validate_scope
from app.orchestrator.engine import OrchestratorEngine

router = APIRouter(prefix="/api/scans", tags=["Scans"])

@router.post("", response_model=ScanResponse)
async def create_scan(req: ScanCreateRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    is_valid, msg = validate_scope(req.target_url, req.authorized_confirmation)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    evidence_repo = EvidenceRepository(db)

    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    scan = scan_repo.create(
        scan_id=scan_id,
        target_url=req.target_url,
        profile=req.profile.value,
        enabled_modules=req.enabled_modules
    )

    engine = OrchestratorEngine(scan_repo, finding_repo, evidence_repo)
    background_tasks.add_task(engine.execute_scan, scan_id, req.target_url, req.enabled_modules)

    return scan

@router.get("", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    repo = ScanRepository(db)
    return repo.list_all()

@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    repo = ScanRepository(db)
    scan = repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return scan

@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    repo = ScanRepository(db)
    scan = repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    repo.update_status(scan_id, ScanStatus.CANCELLED)
    repo.append_log(scan_id, "Scan execution cancelled by operator.")
    return repo.get(scan_id)
