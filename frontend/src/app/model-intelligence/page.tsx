"use client";

import { useEffect, useState } from "react";
import {
  Cpu,
  BarChart2,
  CheckCircle2,
  AlertCircle,
  Database,
  Layers,
  Terminal
} from "lucide-react";
import { fetchHealth } from "@/lib/api";
import { ApiSource, HealthData } from "@/lib/types";
import { DemoNoticeBanner } from "@/components/Badges";
import { ApiErrorNotice, EmptyNotice, LoadingNotice } from "@/components/ApiState";

export default function ModelIntelligencePage() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [source, setSource] = useState<ApiSource | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const result = await fetchHealth();
        setHealth(result.data);
        setSource(result.source);
        setNotice(result.notice || null);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : "Failed to load model health.");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const ml = health?.ml_engine;
  const isDemoMetrics = health?.is_demo === true || ml?.is_demo === true;
  const statusLabel = loading
    ? "LOADING"
    : error
      ? "UNAVAILABLE"
      : isDemoMetrics
        ? "SIMULATED DEMO DATA"
        : source === "live"
          ? "LIVE API"
          : "UNAVAILABLE";

  return (
    <div className="space-y-6">
      <DemoNoticeBanner
        visible={source === "demo" || isDemoMetrics}
        message={
          notice ||
          "Simulated health and ML metrics are demo-only. They are not a verified live model or service status."
        }
      />
      {loading && <LoadingNotice label="Loading model health..." />}
      {error && <ApiErrorNotice message={`Model health unavailable. ${error}`} />}

      <div className="flex items-center justify-between pb-2 border-b border-surface-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Cpu className="w-6 h-6 text-primary" />
            <span>ML-Assisted Verification Intelligence</span>
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Model verification metrics, evaluation split, and empirical boundaries.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Model Spec Card */}
        <div className="lg:col-span-8 bg-surface-card border border-surface-border rounded-lg p-6 space-y-6">
          <div className="flex justify-between items-start border-b border-surface-border pb-4">
            <div>
              <span className="text-[10px] font-mono uppercase text-primary font-bold">MODEL PROFILE</span>
              <h2 className="text-xl font-bold text-white mt-1">
                {ml?.model || "Model metrics not available"}
              </h2>
              <div className="text-xs text-zinc-400 font-mono mt-1">
                Version: {ml?.version || "Not reported"}
              </div>
            </div>
            <span className={`px-2.5 py-1 rounded text-xs font-mono border ${
              isDemoMetrics
                ? "bg-amber-950/60 border-amber-500/40 text-amber-400"
                : error
                  ? "bg-red-950/60 border-red-500/40 text-red-400"
                  : "bg-emerald-950/60 border-emerald-500/40 text-emerald-400"
            }`}>
              {statusLabel}
            </span>
          </div>

          {!loading && !error && !ml && (
            <EmptyNotice
              title="No model health reported"
              description="The backend did not return ML metrics. No simulated values are substituted."
            />
          )}

          <div className="space-y-3">
            <h3 className="text-xs font-mono uppercase text-zinc-400 font-semibold">Model Role & Boundaries</h3>
            <p className="text-xs text-zinc-300 leading-relaxed">
              Assists orchestrator in classifying vulnerability reports against historical CVE evidence patterns and predicting false positives.
              <strong className="text-white block mt-1">
                Notice: ML confidence scores do not constitute proof of active exploitation or replace rigorous deterministic HTTP verification.
              </strong>
            </p>
          </div>

          {/* Metrics Grid */}
          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 rounded bg-surface border border-surface-border text-center">
              <div className="text-xs font-mono uppercase text-zinc-400">Precision</div>
              <div className="text-2xl font-bold font-mono text-primary mt-1">
                {ml?.precision !== undefined ? `${(ml.precision * 100).toFixed(1)}%` : "Not evaluated"}
              </div>
              <div className="text-[10px] text-zinc-500 mt-1">Positive predictive value</div>
            </div>

            <div className="p-4 rounded bg-surface border border-surface-border text-center">
              <div className="text-xs font-mono uppercase text-zinc-400">Recall</div>
              <div className="text-2xl font-bold font-mono text-primary mt-1">
                {ml?.recall !== undefined ? `${(ml.recall * 100).toFixed(1)}%` : "Not evaluated"}
              </div>
              <div className="text-[10px] text-zinc-500 mt-1">True positive coverage</div>
            </div>

            <div className="p-4 rounded bg-surface border border-surface-border text-center">
              <div className="text-xs font-mono uppercase text-zinc-400">F1 Score</div>
              <div className="text-2xl font-bold font-mono text-primary mt-1">
                {ml?.f1 !== undefined ? `${(ml.f1 * 100).toFixed(1)}%` : "Not evaluated"}
              </div>
              <div className="text-[10px] text-zinc-500 mt-1">Harmonic mean</div>
            </div>
          </div>

          {/* Dataset info */}
          <div className="p-4 rounded bg-surface border border-surface-border space-y-2 text-xs">
            <div className="flex justify-between text-zinc-400 font-mono">
              <span>Benchmark Dataset:</span>
              <span className="text-white">{ml?.evaluation_split || "Not reported"}</span>
            </div>
            <div className="flex justify-between text-zinc-400 font-mono">
              <span>Evaluation Timestamp:</span>
              <span className="text-white">{ml?.evaluated_at || "Not reported"}</span>
            </div>
          </div>
        </div>

        {/* Future Integrations / Member Roles */}
        <div className="lg:col-span-4 bg-surface-card border border-surface-border rounded-lg p-6 space-y-4">
          <h2 className="text-xs font-mono uppercase text-zinc-400 font-semibold">Team Module Division</h2>
          <div className="space-y-3 text-xs">
            <div className="p-3 rounded bg-surface border border-surface-border space-y-1">
              <div className="font-semibold text-white">Member 1: CVE Intelligence</div>
              <div className="text-zinc-400 text-[11px]">NVD / MITRE pipeline & banner fingerprinting</div>
            </div>
            <div className="p-3 rounded bg-surface border border-surface-border space-y-1">
              <div className="font-semibold text-white">Member 2: Web Analyzer</div>
              <div className="text-zinc-400 text-[11px]">Dynamic crawler, TLS & header inspection</div>
            </div>
            <div className="p-3 rounded bg-surface border border-surface-border space-y-1">
              <div className="font-semibold text-white">Member 3: ML Verification</div>
              <div className="text-zinc-400 text-[11px]">Fine-tuned DeBERTa model training & embedding store</div>
            </div>
            <div className="p-3 rounded bg-surface border border-primary/40 space-y-1 bg-primary/5">
              <div className="font-semibold text-primary">Member 4 (Current Scope)</div>
              <div className="text-zinc-300 text-[11px]">Orchestrator, Next.js UI, Attack Graph, Docker Lab</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
