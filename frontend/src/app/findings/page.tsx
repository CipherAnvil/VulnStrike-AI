"use client";

import { useState, useEffect } from "react";
import {
  Bug,
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  ShieldCheck,
  ChevronRight,
  X,
  FileCode
} from "lucide-react";
import { fetchFindings } from "@/lib/api";
import { Finding, Severity, VerificationStatus } from "@/lib/types";
import { SeverityBadge, StatusBadge, DemoNoticeBanner } from "@/components/Badges";

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const data = await fetchFindings();
      setFindings(data);
      if (data.length > 0) setSelectedFinding(data[0]);
      setLoading(false);
    }
    load();
  }, []);

  const filtered = findings.filter(f => {
    const matchSearch =
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.endpoint.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchSev = severityFilter === "all" || f.severity === severityFilter;
    const matchStatus = statusFilter === "all" || f.verification_status === statusFilter;
    return matchSearch && matchSev && matchStatus;
  });

  return (
    <div className="space-y-6">
      <DemoNoticeBanner />

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-surface-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Bug className="w-6 h-6 text-primary" />
            <span>Findings Explorer</span>
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Normalized vulnerability inventory with evidence references and ML-assisted confidence.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-surface-card border border-surface-border rounded-lg p-4 flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-3" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search findings, endpoints, IDs..."
            className="w-full bg-surface border border-surface-border rounded pl-9 pr-3.5 py-2 text-xs font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-primary transition"
          />
        </div>

        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-surface border border-surface-border rounded px-3 py-2 text-xs font-mono text-zinc-300 focus:outline-none focus:border-primary"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-surface border border-surface-border rounded px-3 py-2 text-xs font-mono text-zinc-300 focus:outline-none focus:border-primary"
          >
            <option value="all">All Statuses</option>
            <option value="confirmed">Confirmed</option>
            <option value="suspected">Suspected</option>
            <option value="inconclusive">Inconclusive</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Findings Table List */}
        <div className="lg:col-span-7 bg-surface-card border border-surface-border rounded-lg overflow-hidden">
          <div className="p-4 border-b border-surface-border flex justify-between items-center text-xs font-mono text-zinc-400">
            <span>Showing {filtered.length} findings</span>
            <span>Simulated Lab Fixtures</span>
          </div>

          <div className="divide-y divide-surface-border overflow-x-auto">
            {filtered.map((f) => (
              <div
                key={f.id}
                onClick={() => setSelectedFinding(f)}
                className={`p-4 cursor-pointer transition flex items-center justify-between text-xs ${
                  selectedFinding?.id === f.id
                    ? "bg-surface border-l-2 border-primary"
                    : "hover:bg-surface/50"
                }`}
              >
                <div className="space-y-1.5 pr-4 flex-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-primary font-bold text-[11px]">{f.id}</span>
                    <SeverityBadge severity={f.severity} />
                    <StatusBadge status={f.verification_status} />
                  </div>
                  <div className="font-semibold text-white text-sm">{f.title}</div>
                  <div className="font-mono text-zinc-400 text-[11px] truncate">{f.endpoint}</div>
                </div>
                <ChevronRight className="w-4 h-4 text-zinc-600 shrink-0" />
              </div>
            ))}

            {filtered.length === 0 && (
              <div className="p-12 text-center text-zinc-500 text-xs font-mono">
                No findings match the current filter criteria.
              </div>
            )}
          </div>
        </div>

        {/* Finding Detail Panel */}
        <div className="lg:col-span-5 bg-surface-card border border-surface-border rounded-lg p-6 space-y-5">
          {selectedFinding ? (
            <div className="space-y-5">
              <div className="border-b border-surface-border pb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs text-primary font-bold">{selectedFinding.id}</span>
                  <div className="space-x-2">
                    <SeverityBadge severity={selectedFinding.severity} />
                    <StatusBadge status={selectedFinding.verification_status} />
                  </div>
                </div>
                <h2 className="text-lg font-bold text-white leading-snug">{selectedFinding.title}</h2>
                <div className="mt-2 text-xs font-mono text-zinc-400 flex items-center space-x-2">
                  <span>Module: {selectedFinding.module}</span>
                  {selectedFinding.cve_id && <span>| {selectedFinding.cve_id}</span>}
                </div>
              </div>

              <div>
                <h3 className="text-xs font-mono uppercase text-zinc-400 font-semibold mb-1">Affected Endpoint</h3>
                <div className="bg-surface border border-surface-border rounded p-2.5 text-xs font-mono text-primary break-all">
                  {selectedFinding.endpoint}
                </div>
              </div>

              <div>
                <h3 className="text-xs font-mono uppercase text-zinc-400 font-semibold mb-1">Vulnerability Description</h3>
                <p className="text-xs text-zinc-300 leading-relaxed">{selectedFinding.description}</p>
              </div>

              {selectedFinding.ml_confidence !== undefined && (
                <div className="p-3 bg-surface border border-surface-border rounded text-xs space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="font-mono text-zinc-400 uppercase text-[10px]">ML Assistant Confidence:</span>
                    <span className="font-mono text-primary font-bold">{(selectedFinding.ml_confidence * 100).toFixed(0)}%</span>
                  </div>
                  <p className="text-[10px] text-zinc-400">
                    *Assisted pattern classification. ML confidence is purely supportive and does not constitute exploitation proof.
                  </p>
                </div>
              )}

              <div>
                <h3 className="text-xs font-mono uppercase text-zinc-400 font-semibold mb-1">Remediation Roadmap</h3>
                <div className="bg-surface border-l-2 border-primary rounded p-3 text-xs text-zinc-200 leading-relaxed">
                  {selectedFinding.remediation_guidance}
                </div>
              </div>

              <div>
                <h3 className="text-xs font-mono uppercase text-zinc-400 font-semibold mb-2">Linked Evidence Records</h3>
                <div className="space-y-1.5">
                  {selectedFinding.evidence_references.map((ev) => (
                    <div key={ev} className="bg-surface border border-surface-border rounded p-2 text-xs font-mono text-zinc-300 flex items-center justify-between">
                      <span>{ev}</span>
                      <span className="text-[10px] text-primary">Simulated Lab Evidence</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-zinc-500 text-xs">
              Select a finding to inspect detailed description and remediation guidance.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
