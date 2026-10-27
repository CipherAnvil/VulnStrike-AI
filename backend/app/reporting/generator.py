import html
from datetime import datetime
from typing import Any, Dict, List

from app.schemas.evidence import EvidenceSchema
from app.schemas.finding import FindingSchema
from app.schemas.scan import ScanResponse
from app.storage.evidence import sanitize_and_redact


def _escape(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _severity_value(finding: FindingSchema) -> str:
    return finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)


def _status_value(finding: FindingSchema) -> str:
    return finding.verification_status.value if hasattr(finding.verification_status, "value") else str(finding.verification_status)


def _profile_value(scan: ScanResponse) -> str:
    return scan.profile.value if hasattr(scan.profile, "value") else str(scan.profile)


def generate_json_report(scan: ScanResponse, findings: List[FindingSchema], evidence: List[EvidenceSchema]) -> Dict[str, Any]:
    """Generates structured JSON assessment report."""
    sanitized_findings = [sanitize_and_redact(f.model_dump()) for f in findings]
    sanitized_evidence = [sanitize_and_redact(e.model_dump()) for e in evidence]
    return {
        "report_id": f"REP-{scan.id}",
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "scope_status": "Authorized Demonstration Scope",
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_findings": scan.findings_count,
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "info": scan.info_count,
            "scan_profile": _profile_value(scan),
            "scan_duration_started": scan.started_at,
            "scan_duration_completed": scan.completed_at,
        },
        "findings": sanitized_findings,
        "evidence_inventory": sanitized_evidence,
        "remediation_roadmap": [
            {
                "priority": idx + 1,
                "finding_id": f.id,
                "title": sanitize_and_redact(f.title),
                "severity": _severity_value(f),
                "remediation": sanitize_and_redact(f.remediation_guidance),
            }
            for idx, f in enumerate(sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(_severity_value(x), 99)))
        ],
        "disclaimer": "This report is generated for authorized laboratory educational evaluation. Findings and evidence are limited to observed lab data and are redacted.",
    }


def generate_html_report(scan: ScanResponse, findings: List[FindingSchema], evidence: List[EvidenceSchema]) -> str:
    """Generates standalone self-contained security assessment HTML report."""
    rows = ""
    for finding in findings:
        sev = _severity_value(finding)
        color = "#ef4444" if sev == "critical" else "#f97316" if sev == "high" else "#eab308" if sev == "medium" else "#3b82f6"
        status = _status_value(finding)
        rows += f"""
        <div style="background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h3 style="margin: 0; color: #f4f4f5; font-size: 1.15rem;">{_escape(finding.title)}</h3>
                <div>
                    <span style="background: {color}; color: #000; font-weight: bold; font-size: 0.75rem; padding: 4px 10px; border-radius: 4px; text-transform: uppercase;">{_escape(sev)}</span>
                    <span style="background: #27272a; color: #a1a1aa; font-size: 0.75rem; padding: 4px 10px; border-radius: 4px; margin-left: 8px;">{_escape(status)}</span>
                </div>
            </div>
            <p style="color: #a1a1aa; font-size: 0.9rem; margin-bottom: 8px;"><strong>Endpoint:</strong> <code style="color: #22c55e; background: #09090b; padding: 2px 6px; border-radius: 4px;">{_escape(finding.endpoint)}</code></p>
            <p style="color: #d4d4d8; font-size: 0.95rem; margin-bottom: 14px;">{_escape(finding.description)}</p>
            <div style="background: #09090b; border-left: 4px solid #22c55e; padding: 12px; border-radius: 4px;">
                <strong style="color: #22c55e; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;">Remediation Recommendation:</strong>
                <p style="color: #d4d4d8; font-size: 0.9rem; margin: 6px 0 0 0;">{_escape(finding.remediation_guidance)}</p>
            </div>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VulnStrike AI Security Assessment Report — {_escape(scan.id)}</title>
    <style>
        body {{
            background-color: #09090b;
            color: #fafafa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 1px solid #27272a;
            padding-bottom: 24px;
            margin-bottom: 30px;
        }}
        .badge {{
            display: inline-block;
            background: #22c55e;
            color: #000;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin: 24px 0;
        }}
        .stat-card {{
            background: #18181b;
            border: 1px solid #27272a;
            padding: 16px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-num {{
            font-size: 1.8rem;
            font-weight: bold;
            color: #22c55e;
        }}
        .stat-label {{
            color: #71717a;
            font-size: 0.75rem;
            text-transform: uppercase;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span class="badge">VULNSTRIKE AI SECURITY AUDIT</span>
            <h1 style="margin: 12px 0 6px 0; font-size: 2rem;">Executive Security Assessment Report</h1>
            <p style="color: #71717a; margin: 0;">Scan ID: {_escape(scan.id)} | Generated: {_escape(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))}</p>
            <p style="color: #a1a1aa; margin: 4px 0 0 0;">Target: <strong style="color: #22c55e;">{_escape(scan.target_url)}</strong> (Authorized Lab Demonstration)</p>
        </div>

        <div class="grid">
            <div class="stat-card">
                <div class="stat-num">{scan.findings_count}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: #ef4444;">{scan.critical_count}</div>
                <div class="stat-label">Critical Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: #f97316;">{scan.high_count}</div>
                <div class="stat-label">High Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: #eab308;">{scan.medium_count + scan.low_count}</div>
                <div class="stat-label">Med / Low</div>
            </div>
        </div>

        <h2 style="margin: 36px 0 16px 0; font-size: 1.4rem; border-left: 4px solid #22c55e; padding-left: 12px;">Detailed Findings & Evidence References</h2>
        {rows if rows else '<p style="color: #71717a;">No findings discovered in this assessment run.</p>'}

        <div style="margin-top: 40px; border-top: 1px solid #27272a; padding-top: 20px; font-size: 0.8rem; color: #71717a;">
            <p>Authorized Demonstration Scope Notice: VulnStrike AI is an academic cybersecurity orchestration platform. Results are generated from controlled lab targets and synthetic verification fixtures.</p>
            <p>Evidence has been sanitized and redacted. This report must only be used within the authorized lab environment.</p>
        </div>
    </div>
</body>
</html>"""
    return html_content
