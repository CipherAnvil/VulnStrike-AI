"use client";

import { useState, useEffect } from "react";
import {
  Radar,
  Play,
  CheckSquare,
  AlertCircle,
  ShieldCheck,
  Terminal,
  Clock,
  Layers,
  RotateCcw
} from "lucide-react";
import { fetchScans, startScan } from "@/lib/api";
import { Scan, ScanProfile } from "@/lib/types";
import { StatusBadge, DemoNoticeBanner } from "@/components/Badges";

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [targetUrl, setTargetUrl] = useState("http://demo-target:8088");
  const [authorizedConfirmation, setAuthorizedConfirmation] = useState(true);
  const [profile, setProfile] = useState<ScanProfile>("standard");
  const [selectedModules, setSelectedModules] = useState<string[]>([
    "cve_intel",
    "web_analyzer",
    "auth_tester",
    "api_inspector"
  ]);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);

  useEffect(() => {
    loadScans();
  }, []);

  async function loadScans() {
    const data = await fetchScans();
    setScans(data);
    if (data.length > 0 && !activeScan) {
      setActiveScan(data[0]);
    }
  }

  const toggleModule = (mod: string) => {
    if (selectedModules.includes(mod)) {
      setSelectedModules(selectedModules.filter(m => m !== mod));
    } else {
      setSelectedModules([...selectedModules, mod]);
    }
  };

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSubmitting(true);

    try {
      const newScan = await startScan(targetUrl, authorizedConfirmation, profile, selectedModules);
      setActiveScan(newScan);
      await loadScans();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to launch scan");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <DemoNoticeBanner />

      <div className="flex items-center justify-between pb-2 border-b border-surface-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Radar className="w-6 h-6 text-primary" />
            <span>Scan Orchestrator Workspace</span>
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Configure target boundaries, select inspection modules, and track scan lifecycles.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Scan Configuration Form */}
        <div className="lg:col-span-7 bg-surface-card border border-surface-border rounded-lg p-6 space-y-6">
          <form onSubmit={handleLaunchScan} className="space-y-5">
            <div>
              <label className="block text-xs font-mono uppercase text-zinc-300 font-semibold mb-2">
                Target Endpoint URL
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="http://demo-target:8088"
                  className="w-full bg-surface border border-surface-border rounded px-3.5 py-2.5 text-sm font-mono text-white placeholder-zinc-600 focus:outline-none focus:border-primary transition"
                  required
                />
              </div>
              <p className="text-[11px] text-zinc-400 mt-1.5">
                Authorized Lab scope: <code className="text-primary font-mono">http://demo-target:8088</code> or <code className="text-primary font-mono">http://localhost:8080</code>
              </p>
            </div>

            {/* Assessment Profile Selector */}
            <div>
              <label className="block text-xs font-mono uppercase text-zinc-300 font-semibold mb-2">
                Assessment Profile
              </label>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { id: "quick", label: "Quick Triage", desc: "Fast header & banner fingerprinting" },
                  { id: "standard", label: "Standard Lab", desc: "Full CVE & Auth verification" },
                  { id: "deep", label: "Deep Analysis", desc: "Exhaustive API schema discovery" }
                ].map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setProfile(item.id as ScanProfile)}
                    className={`p-3 text-left rounded border transition ${
                      profile === item.id
                        ? "bg-primary/10 border-primary text-white"
                        : "bg-surface border-surface-border text-zinc-400 hover:border-zinc-700"
                    }`}
                  >
                    <div className="text-xs font-semibold text-white">{item.label}</div>
                    <div className="text-[10px] text-zinc-400 mt-1">{item.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Assessment Modules Checklist */}
            <div>
              <label className="block text-xs font-mono uppercase text-zinc-300 font-semibold mb-2">
                Enabled Security Modules
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {[
                  { id: "cve_intel", name: "CVE Intelligence", desc: "Service header & known flaw check" },
                  { id: "web_analyzer", name: "Web Analyzer", desc: "CSP, TLS & defensive headers" },
                  { id: "auth_tester", name: "Auth & BOLA Inspector", desc: "Access control & RBAC verification" },
                  { id: "api_inspector", name: "API Schema Probe", desc: "Endpoint data leak detection" }
                ].map((mod) => (
                  <div
                    key={mod.id}
                    onClick={() => toggleModule(mod.id)}
                    className={`p-3 rounded border cursor-pointer flex items-start space-x-3 transition ${
                      selectedModules.includes(mod.id)
                        ? "bg-surface-card border-primary/50 text-white"
                        : "bg-surface border-surface-border text-zinc-400 hover:border-zinc-700"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={selectedModules.includes(mod.id)}
                      onChange={() => {}}
                      className="mt-0.5 accent-primary cursor-pointer"
                    />
                    <div>
                      <div className="text-xs font-medium text-white">{mod.name}</div>
                      <div className="text-[10px] text-zinc-400">{mod.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Scope Authorization Confirmation */}
            <div className="p-4 rounded bg-surface border border-surface-border space-y-2">
              <label className="flex items-start space-x-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={authorizedConfirmation}
                  onChange={(e) => setAuthorizedConfirmation(e.target.checked)}
                  className="mt-0.5 accent-primary cursor-pointer"
                  required
                />
                <span className="text-xs text-zinc-300 leading-relaxed">
                  I confirm that this assessment target belongs to our controlled demonstration laboratory environment and I hold authorization to conduct security testing.
                </span>
              </label>
            </div>

            {errorMessage && (
              <div className="p-3 bg-red-950/40 border border-red-500/50 rounded flex items-center space-x-2 text-red-300 text-xs font-mono">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-3 rounded bg-primary text-black font-semibold font-mono text-sm hover:bg-primary-glow transition flex items-center justify-center space-x-2 glow-primary disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>{submitting ? "INITIALIZING ORCHESTRATOR..." : "LAUNCH AUTHORIZED SCAN"}</span>
            </button>
          </form>
        </div>

        {/* Scan Status & Live Execution Logs */}
        <div className="lg:col-span-5 space-y-6">
          <div className="bg-surface-card border border-surface-border rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold tracking-wider uppercase text-zinc-300 font-mono">
                Active Scan Lifecycle
              </h2>
              {activeScan && <StatusBadge status={activeScan.status} />}
            </div>

            {activeScan ? (
              <div className="space-y-4">
                <div className="p-3 rounded bg-surface border border-surface-border text-xs space-y-1 font-mono">
                  <div className="text-zinc-400">Scan Identifier: <span className="text-white">{activeScan.id}</span></div>
                  <div className="text-zinc-400">Target Host: <span className="text-primary">{activeScan.target_url}</span></div>
                  <div className="text-zinc-400">Created: <span className="text-white">{activeScan.created_at}</span></div>
                  <div className="text-zinc-400">Total Findings: <span className="text-white">{activeScan.findings_count}</span></div>
                </div>

                <div>
                  <div className="text-xs font-mono uppercase text-zinc-300 font-semibold mb-2 flex items-center space-x-1.5">
                    <Terminal className="w-3.5 h-3.5 text-primary" />
                    <span>Orchestrator Execution Logs</span>
                  </div>
                  <div className="bg-surface border border-surface-border rounded p-3 text-[11px] font-mono text-zinc-300 h-56 overflow-y-auto space-y-1.5">
                    {activeScan.log_messages?.map((log, index) => (
                      <div key={index} className="flex items-start space-x-2">
                        <span className="text-zinc-400">&gt;</span>
                        <span className={log.includes("completed") ? "text-primary" : log.includes("Warning") ? "text-yellow-400" : "text-zinc-300"}>
                          {log}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-xs text-zinc-400">
                Select or launch a scan to monitor orchestrator logs.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
