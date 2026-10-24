from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.storage.database import get_db
from app.storage.repositories import FindingRepository
from app.schemas.finding import FindingSchema, Severity, VerificationStatus

router = APIRouter(prefix="/api/findings", tags=["Findings"])

@router.get("", response_model=List[FindingSchema])
def list_findings(
    scan_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    verification_status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    repo = FindingRepository(db)
    if scan_id:
        items = repo.list_by_scan(scan_id)
    else:
        items = repo.list_all(limit=200)

    # In-memory filtering for flexible queries
    if severity:
        items = [i for i in items if (i.severity.value if hasattr(i.severity, 'value') else i.severity) == severity]
    if verification_status:
        items = [i for i in items if (i.verification_status.value if hasattr(i.verification_status, 'value') else i.verification_status) == verification_status]
    if search:
        s = search.lower()
        items = [i for i in items if s in i.title.lower() or s in i.endpoint.lower() or s in i.summary.lower()]

    return items

@router.get("/{finding_id}", response_model=FindingSchema)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    repo = FindingRepository(db)
    f = repo.get(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")
    return f
