import json
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from app.storage.database import ScanModel, FindingModel, EvidenceModel
from app.schemas.scan import ScanResponse, ScanStatus, ScanProfile
from app.schemas.finding import FindingSchema, Severity, VerificationStatus, FindingCategory
from app.schemas.evidence import EvidenceSchema
from app.storage.evidence import sanitize_and_redact

class ScanRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, scan_id: str, target_url: str, profile: str, enabled_modules: List[str]) -> ScanResponse:
        model = ScanModel(
            id=scan_id,
            target_url=target_url,
            profile=profile,
            enabled_modules_json=json.dumps(enabled_modules),
            status=ScanStatus.QUEUED.value,
            is_demo=True,
            log_messages_json=json.dumps([f"Scan initialized for target: {target_url}"])
        )
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return self._to_schema(model)

    def get(self, scan_id: str) -> Optional[ScanResponse]:
        model = self.db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        return self._to_schema(model) if model else None

    def list_all(self, limit: int = 50) -> List[ScanResponse]:
        models = self.db.query(ScanModel).order_by(ScanModel.created_at.desc()).limit(limit).all()
        return [self._to_schema(m) for m in models]

    def update_status(self, scan_id: str, status: ScanStatus, started_at: Optional[str] = None, completed_at: Optional[str] = None, error_message: Optional[str] = None):
        model = self.db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        if model:
            model.status = status.value
            if started_at:
                model.started_at = started_at
            if completed_at:
                model.completed_at = completed_at
            if error_message:
                model.error_message = error_message
            self.db.commit()

    def append_log(self, scan_id: str, message: str):
        model = self.db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        if model:
            logs = json.loads(model.log_messages_json or "[]")
            logs.append(message)
            model.log_messages_json = json.dumps(logs)
            self.db.commit()

    def update_metrics(self, scan_id: str, counts: Dict[str, int]):
        model = self.db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        if model:
            model.findings_count = counts.get("total", 0)
            model.critical_count = counts.get("critical", 0)
            model.high_count = counts.get("high", 0)
            model.medium_count = counts.get("medium", 0)
            model.low_count = counts.get("low", 0)
            model.info_count = counts.get("info", 0)
            self.db.commit()

    def _to_schema(self, model: ScanModel) -> ScanResponse:
        return ScanResponse(
            id=model.id,
            target_url=model.target_url,
            status=ScanStatus(model.status),
            profile=ScanProfile(model.profile),
            enabled_modules=json.loads(model.enabled_modules_json or "[]"),
            is_demo=model.is_demo,
            created_at=model.created_at,
            started_at=model.started_at,
            completed_at=model.completed_at,
            findings_count=model.findings_count,
            critical_count=model.critical_count,
            high_count=model.high_count,
            medium_count=model.medium_count,
            low_count=model.low_count,
            info_count=model.info_count,
            error_message=model.error_message,
            log_messages=json.loads(model.log_messages_json or "[]")
        )

class FindingRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, finding: FindingSchema) -> FindingSchema:
        model = FindingModel(
            id=finding.id,
            scan_id=finding.scan_id,
            module=finding.module,
            category=finding.category.value if hasattr(finding.category, 'value') else finding.category,
            title=finding.title,
            severity=finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
            verification_status=finding.verification_status.value if hasattr(finding.verification_status, 'value') else finding.verification_status,
            endpoint=finding.endpoint,
            summary=sanitize_and_redact(finding.summary),
            description=sanitize_and_redact(finding.description),
            evidence_references_json=json.dumps(finding.evidence_references),
            remediation_guidance=finding.remediation_guidance,
            ml_confidence=finding.ml_confidence,
            cve_id=finding.cve_id,
            cvss_score=finding.cvss_score,
            created_at=finding.created_at,
            is_demo=finding.is_demo
        )
        self.db.add(model)
        self.db.commit()
        return finding

    def get(self, finding_id: str) -> Optional[FindingSchema]:
        model = self.db.query(FindingModel).filter(FindingModel.id == finding_id).first()
        return self._to_schema(model) if model else None

    def list_by_scan(self, scan_id: str) -> List[FindingSchema]:
        models = self.db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
        return [self._to_schema(m) for m in models]

    def list_all(self, limit: int = 100) -> List[FindingSchema]:
        models = self.db.query(FindingModel).order_by(FindingModel.created_at.desc()).limit(limit).all()
        return [self._to_schema(m) for m in models]

    def _to_schema(self, m: FindingModel) -> FindingSchema:
        return FindingSchema(
            id=m.id,
            scan_id=m.scan_id,
            module=m.module,
            category=FindingCategory(m.category),
            title=m.title,
            severity=Severity(m.severity),
            verification_status=VerificationStatus(m.verification_status),
            endpoint=m.endpoint,
            summary=m.summary,
            description=m.description,
            evidence_references=json.loads(m.evidence_references_json or "[]"),
            remediation_guidance=m.remediation_guidance,
            ml_confidence=m.ml_confidence,
            cve_id=m.cve_id,
            cvss_score=m.cvss_score,
            created_at=m.created_at,
            is_demo=m.is_demo
        )

class EvidenceRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, ev: EvidenceSchema) -> EvidenceSchema:
        model = EvidenceModel(
            id=ev.id,
            scan_id=ev.scan_id,
            finding_id=ev.finding_id,
            module=ev.module,
            evidence_type=ev.evidence_type,
            title=ev.title,
            sanitized_summary=sanitize_and_redact(ev.sanitized_summary),
            request_data_json=json.dumps(sanitize_and_redact(ev.request_data)) if ev.request_data else None,
            response_data_json=json.dumps(sanitize_and_redact(ev.response_data)) if ev.response_data else None,
            collected_at=ev.collected_at,
            is_demo=ev.is_demo
        )
        self.db.add(model)
        self.db.commit()
        return ev

    def list_by_scan(self, scan_id: str) -> List[EvidenceSchema]:
        models = self.db.query(EvidenceModel).filter(EvidenceModel.scan_id == scan_id).all()
        return [
            EvidenceSchema(
                id=m.id,
                scan_id=m.scan_id,
                finding_id=m.finding_id,
                module=m.module,
                evidence_type=m.evidence_type,
                title=m.title,
                sanitized_summary=m.sanitized_summary,
                request_data=json.loads(m.request_data_json) if m.request_data_json else None,
                response_data=json.loads(m.response_data_json) if m.response_data_json else None,
                collected_at=m.collected_at,
                is_demo=m.is_demo
            )
            for m in models
        ]
