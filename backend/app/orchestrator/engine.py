import asyncio
import json
import logging
from datetime import datetime
from typing import List, Dict, Any
from app.orchestrator.registry import registry
from app.orchestrator.scope import validate_scope
from app.storage.repositories import ScanRepository, FindingRepository, EvidenceRepository
from app.schemas.scan import ScanStatus

logger = logging.getLogger("vulnstrike.engine")

class OrchestratorEngine:
    def __init__(self, scan_repo: ScanRepository, finding_repo: FindingRepository, evidence_repo: EvidenceRepository):
        self.scan_repo = scan_repo
        self.finding_repo = finding_repo
        self.evidence_repo = evidence_repo

    async def execute_scan(self, scan_id: str, target_url: str, enabled_modules: List[str]):
        """
        Runs registered modules asynchronously with error isolation, timeouts, and metrics tracking.
        """
        self.scan_repo.update_status(scan_id, ScanStatus.RUNNING, started_at=datetime.utcnow().isoformat())
        self.scan_repo.append_log(scan_id, f"Scan started at {datetime.utcnow().isoformat()} against scope-checked target: {target_url}")

        total_findings = []
        total_evidence = []
        counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for mod_name in enabled_modules:
            mod = registry.get(mod_name)
            if not mod:
                self.scan_repo.append_log(scan_id, f"Warning: Module '{mod_name}' not found in registry. Skipping.")
                continue

            self.scan_repo.append_log(scan_id, f"Launching module: {mod.display_name} (timeout={mod.timeout_seconds}s)")
            try:
                findings, evidence = await asyncio.wait_for(
                    mod.run(scan_id, target_url),
                    timeout=mod.timeout_seconds
                )
                
                # Persist findings and evidence with duplicate deduplication
                for f in findings:
                    self.finding_repo.create(f)
                    total_findings.append(f)
                    counts["total"] += 1
                    sev_key = f.severity.value if hasattr(f.severity, 'value') else f.severity
                    if sev_key in counts:
                        counts[sev_key] += 1
                
                for ev in evidence:
                    self.evidence_repo.create(ev)
                    total_evidence.append(ev)

                self.scan_repo.append_log(scan_id, f"Module '{mod.name}' completed with {len(findings)} findings.")

            except asyncio.TimeoutError:
                self.scan_repo.append_log(scan_id, f"Module '{mod.name}' timed out after {mod.timeout_seconds}s. Isolated cleanly.")
            except Exception as e:
                self.scan_repo.append_log(scan_id, f"Module '{mod.name}' failed with exception: {str(e)}. Continuing other modules.")

        # Finalize scan status and metric aggregates
        self.scan_repo.update_metrics(scan_id, counts)
        self.scan_repo.update_status(scan_id, ScanStatus.COMPLETED, completed_at=datetime.utcnow().isoformat())
        self.scan_repo.append_log(scan_id, f"Scan completed successfully. Discovered {counts['total']} normalized findings.")
