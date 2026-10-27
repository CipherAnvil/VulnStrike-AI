"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Bug,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ArrowRight,
  Server
} from "lucide-react";
import { fetchScans, fetchFindings, fetchHealth } from "@/lib/api";
import { ApiSource, HealthData, Scan, Finding } from "@/lib/types";
import { SeverityBadge, StatusBadge, DemoNoticeBanner } from "@/components/Badges";
import { ApiErrorNotice, EmptyNotice, LoadingNotice } from "@/components/ApiState";

export default function OverviewPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [source, setSource] = useState<ApiSource | null>(null);
  const [notices, setNotices] = useState<string[]>([]);

  useEffect(() => {
    async function loadData() {
      const [scansResult, findingsResult, healthResult] = await Promise.allSettled([
        fetchScans(),
        fetchFindings(),
        fetchHealth()
      ]);
      const failures: string[] = [];
      const messages: string[] = [];
      let nextSource: ApiSource | null = null;

      if (scansResult.status === "fulfilled") {
        setScans(scansResult.value.data);
        nextSource = nextSource === "demo" || scansResult.value.source === "demo" ? "demo" : "live";
        if (scansResult.value.notice) messages.push(scansResult.value.notice);
      } else {
        failures.push(`Scans: ${scansResult.reason instanceof Error ? scansResult.reason.message : "unavailable"}`);
      }

      if (findingsResult.status === "fulfilled") {
        setFindings(findingsResult.value.data);
        nextSource = nextSource === "demo" || findingsResult.value.source === "demo" ? "demo" : "live";
        if (findingsResult.value.notice) messages.push(findingsResult.value.notice);
      } else {
        failures.push(`Findings: ${findingsResult.reason instanceof Error ? findingsResult.reason.message : "unavailable"}`);
      }

      if (healthResult.status === "fulfilled") {
        setHealth(healthResult.value.data);
        nextSource = nextSource === "demo" || healthResult.value.source === "demo" ? "demo" : "live";
        if (healthResult.value.notice) messages.push(healthResult.value.notice);
      } else {
        failures.push(`Health: ${healthResult.reason instanceof Error ? healthResult.reason.message : "unavailable"}`);
      }

      setSource(nextSource);
      setNotices(messages);
      setError(failures.length > 0 ? `Some live data could not be loaded. ${failures.join(" ")}` : null);
      setLoading(false);
    }
    loadData();
  }, []);

  const totalScans = scans.length;
  const confirmedFindings = findings.filter(f => f.verification_status === "confirmed").length;
  const suspectedFindings = findings.filter(f => f.verification_status === "suspected").length;
  const criticalHighCount = findings.filter(f => f.severity === "critical" || f.severity === "high").length;

  return (
    <div className="space-y-6">
      <DemoNoticeBanner
        visible={source === "demo" || health?.is_demo === true}
        message={
          notices.join(" ") ||
          (health?.is_demo ? "Simulated health and ML metrics are demo-only and are not verified live status." : undefined)
        }
      />
      {loading && <LoadingNotice />}
      {error && <ApiErrorNotice message={error} />}

      {/* Top Header & Fast Action */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-surface-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <span>Security Operations Overview</span>
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Real-time assessment metrics and normalized vulnerability intelligence.
          </p>
        </div>
        <Link
          href="/scans"
          className="inline-flex items-center space-x-2 px-4 py-2 rounded bg-primary text-black font-semibold text-sm hover:bg-primary-glow font-mono transition glow-primary"
        >
          <Activity className="w-4 h-4" />
          <span>RUN TARGET SCAN</span>
        </Link>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-surface-card border border-surface-border rounded-lg p-5">
          <div className="flex items-center justify-between text-zinc-400 text-xs font-mono uppercase tracking-wider mb-2">
            <span>Total Lab Scans</span>
            <Activity className="w-4 h-4 text-zinc-500" />
          </div>
          <div className="text-3xl font-bold text-white font-mono">{totalScans}</div>
          <div className="text-xs text-zinc-400 mt-2">Executed under authorized profile</div>
        </div>

        <div className="bg-surface-card border border-surface-border rounded-lg p-5">
          <div className="flex items-center justify-between text-zinc-400 text-xs font-mono uppercase tracking-wider mb-2">
            <span>Critical & High</span>
            <Flame className="w-4 h-4 text-severity-critical" />
          </div>
          <div className="text-3xl font-bold text-red-400 font-mono">{criticalHighCount}</div>
          <div className="text-xs text-zinc-400 mt-2">Requires prioritized remediation</div>
        </div>

        <div className="bg-surface-card border border-surface-border rounded-lg p-5">
          <div className="flex items-center justify-between text-zinc-400 text-xs font-mono uppercase tracking-wider mb-2">
            <span>Confirmed Findings</span>
            <CheckCircle2 className="w-4 h-4 text-primary" />
          </div>
          <div className="text-3xl font-bold text-primary font-mono">{confirmedFindings}</div>
          <div className="text-xs text-zinc-400 mt-2">Empirically backed with evidence</div>
        </div>

        <div className="bg-surface-card border border-surface-border rounded-lg p-5">
          <div className="flex items-center justify-between text-zinc-400 text-xs font-mono uppercase tracking-wider mb-2">
            <span>Suspected / Review</span>
            <AlertTriangle className="w-4 h-4 text-severity-medium" />
          </div>
          <div className="text-3xl font-bold text-yellow-400 font-mono">{suspectedFindings}</div>
          <div className="text-xs text-zinc-400 mt-2">Awaiting manual or deeper verification</div>
        </div>
      </div>

      {/* Severity Breakdown & Module Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold tracking-wider uppercase text-zinc-300 font-mono">
              Severity Distribution & Density
            </h2>
            <span className="text-xs text-zinc-400 font-mono">Normalized Standards</span>
          </div>

          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-red-400 font-medium">Critical (CVSS 9.0 - 10.0)</span>
                <span className="font-mono text-zinc-300">
                  {findings.filter(f => f.severity === "critical").length}
                </span>
              </div>
              <div className="w-full bg-zinc-900 h-2 rounded-full overflow-hidden">
                <div className="bg-red-500 h-full w-[25%]" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-orange-400 font-medium">High (CVSS 7.0 - 8.9)</span>
                <span className="font-mono text-zinc-300">
                  {findings.filter(f => f.severity === "high").length}
                </span>
              </div>
              <div className="w-full bg-zinc-900 h-2 rounded-full overflow-hidden">
                <div className="bg-orange-500 h-full w-[25%]" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-yellow-400 font-medium">Medium (CVSS 4.0 - 6.9)</span>
                <span className="font-mono text-zinc-300">
                  {findings.filter(f => f.severity === "medium").length}
                </span>
              </div>
              <div className="w-full bg-zinc-900 h-2 rounded-full overflow-hidden">
                <div className="bg-yellow-500 h-full w-[50%]" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-blue-400 font-medium">Low & Informational</span>
                <span className="font-mono text-zinc-300">
                  {findings.filter(f => f.severity === "low" || f.severity === "info").length}
                </span>
              </div>
              <div className="w-full bg-zinc-900 h-2 rounded-full overflow-hidden">
                <div className="bg-blue-500 h-full w-[0%]" />
              </div>
            </div>
          </div>
        </div>

        {/* Module Health Indicator */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold tracking-wider uppercase text-zinc-300 font-mono">
              Module Registry
            </h2>
            <Server className="w-4 h-4 text-zinc-500" />
          </div>
          <div className="space-y-3">
            {(health?.registered_modules || []).map((mod) => {
              const isDemoModule = health?.is_demo === true;
              return (
                <div key={mod.name} className="flex items-center justify-between py-2 border-b border-surface-border/50 text-xs">
                  <div>
                    <div className="font-medium text-white">{mod.display_name}</div>
                    <div className="text-[11px] font-mono text-zinc-400">{mod.name}</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded font-mono text-[10px] border ${
                    isDemoModule
                      ? "bg-amber-950/60 border-amber-500/40 text-amber-400"
                      : "bg-emerald-950/60 border-emerald-500/40 text-emerald-400"
                  }`}>
                    {isDemoModule ? "DEMO" : mod.status.toUpperCase()}
                  </span>
                </div>
              );
            })}
            {!loading && (health?.registered_modules || []).length === 0 && (
              <div className="py-6 text-center text-xs text-zinc-500">
                Module registry unavailable.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Scans & Recent Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold tracking-wider uppercase text-zinc-300 font-mono">
              Recent Assessment Runs
            </h2>
            <Link href="/scans" className="text-xs text-primary hover:underline flex items-center space-x-1">
              <span>View all</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="space-y-3">
            {scans.slice(0, 3).map((scan) => (
              <div key={scan.id} className="p-3 rounded bg-surface border border-surface-border flex items-center justify-between text-xs">
                <div>
                  <div className="font-mono font-semibold text-white">{scan.id}</div>
                  <div className="text-zinc-400 font-mono text-[11px]">{scan.target_url}</div>
                  <div className="text-zinc-400 text-[10px] mt-1">{scan.created_at}</div>
                </div>
                <div className="text-right space-y-1">
                  <StatusBadge status={scan.status} />
                  <div className="font-mono text-zinc-400 text-[11px]">
                    {scan.findings_count} findings
                  </div>
                </div>
              </div>
            ))}
            {!loading && scans.length === 0 && (
              <EmptyNotice title="No scans yet" description="Launch an authorized scan to populate the assessment history." />
            )}
          </div>
        </div>

        {/* Recent Findings */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold tracking-wider uppercase text-zinc-300 font-mono">
              Prioritized Findings
            </h2>
            <Link href="/findings" className="text-xs text-primary hover:underline flex items-center space-x-1">
              <span>Explorer</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="space-y-3">
            {findings.slice(0, 3).map((finding) => (
              <div key={finding.id} className="p-3 rounded bg-surface border border-surface-border text-xs space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-primary font-semibold text-[11px]">{finding.id}</span>
                  <SeverityBadge severity={finding.severity} />
                </div>
                <div className="font-medium text-white line-clamp-1">{finding.title}</div>
                <div className="text-zinc-400 font-mono text-[11px] truncate">{finding.endpoint}</div>
              </div>
            ))}
            {!loading && findings.length === 0 && (
              <EmptyNotice title="No findings recorded" description="Findings appear here after a completed assessment." />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
