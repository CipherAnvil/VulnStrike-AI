import asyncio
import logging
from datetime import datetime
from typing import List

from app.orchestrator.registry import registry
from app.schemas.contracts import ContractStatus
from app.schemas.scan import ScanStatus
from app.storage.repositories import EvidenceRepository, FindingRepository, ScanRepository

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

        counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        completed = 0
        failed = 0
        skipped = 0

        for mod_name in enabled_modules:
            mod = registry.get(mod_name)
            if not mod:
                skipped += 1
                self.scan_repo.append_log(scan_id, f"Warning: Module '{mod_name}' not found in registry. Skipping.")
                continue

            self.scan_repo.append_log(scan_id, f"Launching module: {mod.display_name} (timeout={mod.timeout_seconds}s)")
            started = datetime.utcnow()
            try:
                findings, evidence = await asyncio.wait_for(
                    mod.run(scan_id, target_url),
                    timeout=mod.timeout_seconds,
                )

                for finding in findings:
                    self.finding_repo.create(finding)
                    counts["total"] += 1
                    sev_key = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
                    if sev_key in counts:
                        counts[sev_key] += 1

                for ev in evidence:
                    self.evidence_repo.create(ev)

                duration_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
                try:
                    contract = mod.to_output_contract(
                        scan_id,
                        findings,
                        evidence,
                        status=ContractStatus.OK,
                        duration_ms=duration_ms,
                    )
                    self.scan_repo.append_log(scan_id, f"Module '{mod.name}' contract validated ({contract.contract_version}) with {len(findings)} findings.")
                except Exception as contract_error:
                    self.scan_repo.append_log(scan_id, f"Module '{mod.name}' contract validation warning: {contract_error}")

                completed += 1
                self.scan_repo.append_log(scan_id, f"Module '{mod.name}' completed with {len(findings)} findings.")
            except asyncio.TimeoutError:
                failed += 1
                self.scan_repo.append_log(scan_id, f"Module '{mod.name}' timed out after {mod.timeout_seconds}s. Isolated cleanly.")
            except Exception as exc:
                failed += 1
                self.scan_repo.append_log(scan_id, f"Module '{mod.name}' failed with exception: {str(exc)}. Continuing other modules.")

        self.scan_repo.update_metrics(scan_id, counts)
        self.scan_repo.update_status(scan_id, ScanStatus.COMPLETED, completed_at=datetime.utcnow().isoformat())
        self.scan_repo.append_log(
            scan_id,
            f"Scan completed. Modules: completed={completed}, failed={failed}, skipped={skipped}. Discovered {counts['total']} normalized findings.",
        )
