"use client";

import { useEffect, useState } from "react";
import {
  Settings,
  Server,
  Database,
  ShieldCheck,
  CheckCircle2,
  RefreshCw
} from "lucide-react";
import { fetchHealth } from "@/lib/api";
import { ApiSource, HealthData } from "@/lib/types";
import { DemoNoticeBanner } from "@/components/Badges";
import { ApiErrorNotice, LoadingNotice } from "@/components/ApiState";

export default function SettingsPage() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [source, setSource] = useState<ApiSource | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const result = await fetchHealth();
      setHealth(result.data);
      setSource(result.source);
      setNotice(result.notice || null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to probe the backend.");
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const isDemoHealth = health?.is_demo === true;

  return (
    <div className="space-y-6">
      <DemoNoticeBanner
        visible={source === "demo" || isDemoHealth}
        message={notice || "Simulated health and ML metrics are demo-only. They are not verified live service status."}
      />
      {refreshing && !health && <LoadingNotice label="Probing backend health..." />}
      {error && <ApiErrorNotice message={`Backend health unavailable. ${error}`} />}

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-surface-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Settings className="w-6 h-6 text-primary" />
            <span>Settings & Module Integrations</span>
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Backend connection health, registered scanner modules, and system parameters.
          </p>
        </div>

        <button
          onClick={load}
          disabled={refreshing}
          className="px-3.5 py-1.5 rounded bg-surface border border-surface-border text-xs font-mono text-zinc-300 hover:text-white flex items-center space-x-2 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-primary" : ""}`} />
          <span>PROBE BACKEND</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Health */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-6 space-y-4">
          <h2 className="text-sm font-mono uppercase text-zinc-300 font-semibold flex items-center space-x-2">
            <Server className="w-4 h-4 text-primary" />
            <span>Core Orchestration Backend</span>
          </h2>

          <div className="space-y-3 text-xs">
            <div className="flex justify-between p-3 rounded bg-surface border border-surface-border">
              <span className="text-zinc-400 font-mono">Service Status</span>
              <span className={`font-mono font-bold uppercase ${
                isDemoHealth ? "text-amber-400" : error ? "text-red-400" : "text-emerald-400"
              }`}>
                {health?.status || "Unavailable"}
              </span>
            </div>
            <div className="flex justify-between p-3 rounded bg-surface border border-surface-border">
              <span className="text-zinc-400 font-mono">Persistence Engine</span>
              <span className="text-white font-mono">{health?.database || "Not reported"}</span>
            </div>
            <div className="flex justify-between p-3 rounded bg-surface border border-surface-border">
              <span className="text-zinc-400 font-mono">Target Scope Boundary</span>
              <span className="text-primary font-mono">STRICT ALLOWLIST ENFORCED</span>
            </div>
          </div>
        </div>

        {/* Scanner Module Registry */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-6 space-y-4">
          <h2 className="text-sm font-mono uppercase text-zinc-300 font-semibold flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-primary" />
            <span>Registered Scanner Adapters</span>
          </h2>

          <div className="space-y-2.5">
            {(health?.registered_modules || []).map((mod) => (
              <div key={mod.name} className="p-3 rounded bg-surface border border-surface-border flex justify-between items-center text-xs">
                <div>
                  <div className="font-semibold text-white">{mod.display_name}</div>
                  <div className="text-[10px] font-mono text-zinc-400">module_id: {mod.name}</div>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                  isDemoHealth
                    ? "bg-amber-950/60 border-amber-500/40 text-amber-400"
                    : "bg-emerald-950/60 border-emerald-500/40 text-emerald-400"
                }`}>
                  {isDemoHealth ? "DEMO" : mod.status.toUpperCase()}
                </span>
              </div>
            ))}
            {!refreshing && !error && (health?.registered_modules || []).length === 0 && (
              <div className="py-6 text-center text-xs text-zinc-500">
                No scanner modules reported by the backend.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
