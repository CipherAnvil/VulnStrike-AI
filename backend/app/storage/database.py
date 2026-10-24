import os
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulnstrike.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, index=True)
    target_url = Column(String, nullable=False)
    status = Column(String, default="queued")
    profile = Column(String, default="standard")
    enabled_modules_json = Column(Text, default="[]")
    is_demo = Column(Boolean, default=True)
    created_at = Column(String, default=lambda: datetime.utcnow().isoformat())
    started_at = Column(String, nullable=True)
    completed_at = Column(String, nullable=True)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    error_message = Column(String, nullable=True)
    log_messages_json = Column(Text, default="[]")

class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, index=True)
    scan_id = Column(String, index=True, nullable=False)
    module = Column(String, nullable=False)
    category = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    verification_status = Column(String, nullable=False)
    endpoint = Column(String, nullable=False)
    summary = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    evidence_references_json = Column(Text, default="[]")
    remediation_guidance = Column(Text, nullable=False)
    ml_confidence = Column(Float, nullable=True)
    cve_id = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    created_at = Column(String, default=lambda: datetime.utcnow().isoformat())
    is_demo = Column(Boolean, default=True)

class EvidenceModel(Base):
    __tablename__ = "evidence"

    id = Column(String, primary_key=True, index=True)
    scan_id = Column(String, index=True, nullable=False)
    finding_id = Column(String, index=True, nullable=True)
    module = Column(String, nullable=False)
    evidence_type = Column(String, nullable=False)
    title = Column(String, nullable=False)
    sanitized_summary = Column(Text, nullable=False)
    request_data_json = Column(Text, nullable=True)
    response_data_json = Column(Text, nullable=True)
    collected_at = Column(String, default=lambda: datetime.utcnow().isoformat())
    is_demo = Column(Boolean, default=True)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
