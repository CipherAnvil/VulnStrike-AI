"use client";

import { useState, useEffect } from "react";
import {
  FileText,
  Download,
  Code,
  FileCheck,
  Calendar,
  ShieldCheck,
  AlertCircle
} from "lucide-react";
import { fetchScans, fetchFindings } from "@/lib/api";
import { Scan, Finding } from "@/lib/types";
import { SeverityBadge, StatusBadge, DemoNoticeBanner } from "@/components/Badges";

export default function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const scansData = await fetchScans();
      setScans(scansData);
      if (scansData.length > 0) {
        setSelectedScan(scansData[0]);
        const findingsData = await fetchFindings({ scan_id: scansData[0].id });
        setFindings(findingsData);
      }
      setLoading(false);
    }
    load();
  }, []);

  const handleSelectScan = async (scan: Scan) => {
    setSelectedScan(scan);
    const data = await fetchFindings({ scan_id: scan.id });
    setFindings(data);
  };

  const downloadJson = () => {
    if (!selectedScan) return;
    const reportData = {
      report_id: `REP-${selectedScan.id}`,
      scan_id: selectedScan.id,
      target_url: selectedScan.target_url,
      generated_at: new Date().toISOString(),
      summary: {
        total_findings: selectedScan.findings_count,
        critical: selectedScan.critical_count,
        high: selectedScan.high_count,
        medium: selectedScan.medium_count
      },
      findings: findings,
      disclaimer: "Authorized Demonstration Lab Assessment"
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `VulnStrike-Report-${selectedScan.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadHtml = () => {
    if (!selectedScan) return;
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>VulnStrike AI Report - ${selectedScan.id}</title>
<style>
body { background: #09090b; color: #fafafa; font-family: sans-serif; padding: 40px; }
.card { background: #18181b; border: 1px solid #27272a; padding: 20px; border-radius: 8px; margin-bottom: 16px; }
.badge { background: #22c55e; color: #000; font-weight: bold; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
</style>
</head>
<body>
<h1>VulnStrike AI - Security Assessment Report</h1>
<p>Scan ID: ${selectedScan.id} | Target: ${selectedScan.target_url}</p>
<hr style="border-color: #27272a; margin: 20px 0;"/>
<h2>Assessment Findings (${findings.length})</h2>
${findings.map(f => `
<div class="card">
  <h3>${f.title} <span class="badge">${f.severity.toUpperCase()}</span></h3>
  <p><strong>Endpoint:</strong> ${f.endpoint}</p>
  <p>${f.description}</p>
  <p><strong>Remediation:</strong> ${f.remediation_guidance}</p>
</div>
`).join("")}
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `VulnStrike-Report-${selectedScan.id}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <DemoNoticeBanner />

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-surface-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
            <FileText className="w-6 h-6 text-primary" />
            <span>Remediation & Compliance Reports</span>
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Export standalone JSON and self-contained executive HTML audit reports.
          </p>
        </div>

        {selectedScan && (
          <div className="flex items-center space-x-3">
            <button
              onClick={downloadJson}
              className="px-3.5 py-2 rounded bg-surface border border-surface-border hover:border-primary text-xs font-mono text-zinc-200 flex items-center space-x-2 transition"
            >
              <Code className="w-3.5 h-3.5 text-primary" />
              <span>EXPORT JSON</span>
            </button>
            <button
              onClick={downloadHtml}
              className="px-3.5 py-2 rounded bg-primary text-black font-semibold text-xs font-mono hover:bg-primary-glow flex items-center space-x-2 transition glow-primary"
            >
              <Download className="w-3.5 h-3.5" />
              <span>EXPORT HTML AUDIT</span>
            </button>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Scans Selector List */}
        <div className="lg:col-span-4 bg-surface-card border border-surface-border rounded-lg p-5 space-y-4">
          <h2 className="text-xs font-mono uppercase text-zinc-400 font-semibold">Available Scan Audits</h2>
          <div className="space-y-2.5">
            {scans.map((scan) => (
              <div
                key={scan.id}
                onClick={() => handleSelectScan(scan)}
                className={`p-3 rounded border cursor-pointer transition text-xs space-y-1 ${
                  selectedScan?.id === scan.id
                    ? "bg-surface border-primary"
                    : "bg-surface/50 border-surface-border hover:border-zinc-700"
                }`}
              >
                <div className="flex justify-between items-center">
                  <span className="font-mono font-bold text-white">{scan.id}</span>
                  <StatusBadge status={scan.status} />
                </div>
                <div className="text-zinc-400 font-mono text-[11px] truncate">{scan.target_url}</div>
                <div className="text-[10px] text-zinc-500">{scan.created_at}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Selected Report Preview */}
        <div className="lg:col-span-8 bg-surface-card border border-surface-border rounded-lg p-6 space-y-6">
          {selectedScan ? (
            <div className="space-y-6">
              <div className="flex justify-between items-start border-b border-surface-border pb-4">
                <div>
                  <span className="text-[10px] font-mono uppercase text-primary font-bold">EXECUTIVE SUMMARY</span>
                  <h2 className="text-xl font-bold text-white mt-1">Audit Record: {selectedScan.id}</h2>
                  <div className="text-xs text-zinc-400 font-mono mt-1">Target Host: {selectedScan.target_url}</div>
                </div>
                <div className="text-right text-xs font-mono text-zinc-400">
                  <div>Profile: {selectedScan.profile.toUpperCase()}</div>
                  <div className="text-zinc-500 text-[10px] mt-0.5">{selectedScan.completed_at || selectedScan.created_at}</div>
                </div>
              </div>

              {/* Statistics Grid */}
              <div className="grid grid-cols-4 gap-3">
                <div className="p-3 bg-surface border border-surface-border rounded text-center">
                  <div className="text-2xl font-bold font-mono text-white">{selectedScan.findings_count}</div>
                  <div className="text-[10px] font-mono uppercase text-zinc-400 mt-1">Total Findings</div>
                </div>
                <div className="p-3 bg-surface border border-surface-border rounded text-center">
                  <div className="text-2xl font-bold font-mono text-red-400">{selectedScan.critical_count}</div>
                  <div className="text-[10px] font-mono uppercase text-zinc-400 mt-1">Critical</div>
                </div>
                <div className="p-3 bg-surface border border-surface-border rounded text-center">
                  <div className="text-2xl font-bold font-mono text-orange-400">{selectedScan.high_count}</div>
                  <div className="text-[10px] font-mono uppercase text-zinc-400 mt-1">High</div>
                </div>
                <div className="p-3 bg-surface border border-surface-border rounded text-center">
                  <div className="text-2xl font-bold font-mono text-yellow-400">{selectedScan.medium_count}</div>
                  <div className="text-[10px] font-mono uppercase text-zinc-400 mt-1">Medium</div>
                </div>
              </div>

              {/* Finding Breakdown in Report */}
              <div>
                <h3 className="text-xs font-mono uppercase text-zinc-400 font-semibold mb-3">
                  Documented Findings & Remediation Advice
                </h3>
                <div className="space-y-3">
                  {findings.map((f) => (
                    <div key={f.id} className="p-4 rounded bg-surface border border-surface-border space-y-2 text-xs">
                      <div className="flex justify-between items-center">
                        <span className="font-semibold text-white">{f.title}</span>
                        <SeverityBadge severity={f.severity} />
                      </div>
                      <p className="text-zinc-300 leading-relaxed">{f.description}</p>
                      <div className="p-2.5 rounded bg-zinc-900 border-l-2 border-primary text-zinc-200">
                        <strong className="text-primary text-[10px] uppercase font-mono block mb-0.5">Remediation:</strong>
                        {f.remediation_guidance}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center text-xs text-zinc-500 py-16">
              Select an assessment audit on the left to review reports and export documents.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
