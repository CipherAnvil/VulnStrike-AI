"use client";

import { useState, useEffect } from "react";
import {
  GitFork,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Info,
  ShieldAlert,
  ArrowRight
} from "lucide-react";
import { fetchAttackGraph } from "@/lib/api";
import { AttackGraphData, GraphNode, GraphEdge } from "@/lib/types";
import { SeverityBadge, StatusBadge, DemoNoticeBanner } from "@/components/Badges";

export default function AttackGraphPage() {
  const [graphData, setGraphData] = useState<AttackGraphData | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoomLevel, setZoomLevel] = useState(1);

  useEffect(() => {
    async function load() {
      const data = await fetchAttackGraph();
      setGraphData(data);
      if (data.nodes.length > 0) {
        setSelectedNode(data.nodes[1]); // Default to first finding
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <DemoNoticeBanner />

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-surface-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
            <GitFork className="w-6 h-6 text-primary" />
            <span>Attack-Chain Relationship Graph</span>
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Evidence-backed relationship graph mapping vulnerability pivots to asset compromise.
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center space-x-4 text-xs font-mono text-zinc-400 bg-surface-card border border-surface-border px-3 py-1.5 rounded">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
            <span>Target Host</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
            <span>Critical Finding</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
            <span>Pivot / Impact</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Interactive Graph Canvas Area */}
        <div className="lg:col-span-8 bg-surface-card border border-surface-border rounded-lg p-5 flex flex-col h-[560px] relative overflow-hidden">
          {/* Controls Bar */}
          <div className="absolute top-4 right-4 z-10 flex space-x-2 bg-surface/90 border border-surface-border p-1.5 rounded backdrop-blur">
            <button
              onClick={() => setZoomLevel(prev => Math.min(prev + 0.1, 1.4))}
              className="p-1 hover:text-primary text-zinc-400 transition"
              title="Zoom In"
            >
              <ZoomIn className="w-4 h-4" />
            </button>
            <button
              onClick={() => setZoomLevel(prev => Math.max(prev - 0.1, 0.7))}
              className="p-1 hover:text-primary text-zinc-400 transition"
              title="Zoom Out"
            >
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="p-1 hover:text-primary text-zinc-400 transition"
              title="Reset View"
            >
              <Maximize2 className="w-4 h-4" />
            </button>
          </div>

          {/* Graph Nodes Representation */}
          <div
            className="flex-1 flex flex-col justify-center items-center relative transition-transform duration-200"
            style={{ transform: `scale(${zoomLevel})` }}
          >
            {/* Structured Synthetic Graph View */}
            <div className="space-y-10 w-full max-w-xl">
              {/* Root Target Node */}
              <div className="flex justify-center">
                <div
                  onClick={() => setSelectedNode(graphData?.nodes[0] || null)}
                  className={`p-3 rounded-lg border-2 cursor-pointer transition text-center max-w-xs ${
                    selectedNode?.id === "target-root"
                      ? "bg-cyan-950/40 border-cyan-400 shadow-lg shadow-cyan-950/50"
                      : "bg-surface border-cyan-500/40 hover:border-cyan-400"
                  }`}
                >
                  <div className="text-[10px] font-mono uppercase text-cyan-400 font-bold">Target Ingress</div>
                  <div className="text-xs font-mono text-white mt-0.5">demo-target:8088</div>
                </div>
              </div>

              {/* Edge line down */}
              <div className="flex justify-around items-center px-12">
                <div className="w-0.5 h-6 bg-zinc-700 mx-auto" />
              </div>

              {/* Vulnerability Discovery Layer */}
              <div className="grid grid-cols-2 gap-6">
                <div
                  onClick={() => setSelectedNode(graphData?.nodes[1] || null)}
                  className={`p-3.5 rounded-lg border-2 cursor-pointer transition text-left ${
                    selectedNode?.id === "finding-cve"
                      ? "bg-red-950/40 border-red-500 shadow-lg shadow-red-950/50"
                      : "bg-surface border-red-500/40 hover:border-red-400"
                  }`}
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-[10px] font-mono text-red-400 font-bold">CRITICAL</span>
                    <span className="text-[10px] font-mono text-zinc-400">CVE-2021-41773</span>
                  </div>
                  <div className="text-xs font-semibold text-white">Apache 2.4.49 Traversal</div>
                  <div className="text-[10px] font-mono text-zinc-400 mt-1">Endpoint: /cgi-bin/...</div>
                </div>

                <div
                  onClick={() => setSelectedNode(graphData?.nodes[2] || null)}
                  className={`p-3.5 rounded-lg border-2 cursor-pointer transition text-left ${
                    selectedNode?.id === "finding-bola"
                      ? "bg-orange-950/40 border-orange-500 shadow-lg shadow-orange-950/50"
                      : "bg-surface border-orange-500/40 hover:border-orange-400"
                  }`}
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-[10px] font-mono text-orange-400 font-bold">HIGH</span>
                    <span className="text-[10px] font-mono text-zinc-400">BOLA / RBAC</span>
                  </div>
                  <div className="text-xs font-semibold text-white">Unauth Admin Telemetry</div>
                  <div className="text-[10px] font-mono text-zinc-400 mt-1">Endpoint: /internal/admin/...</div>
                </div>
              </div>

              {/* Edge connection to Consequence */}
              <div className="flex justify-end pr-28">
                <div className="flex items-center space-x-2 text-[10px] font-mono text-primary bg-surface border border-surface-border px-2 py-0.5 rounded">
                  <span>Permits pivot into registry</span>
                  <ArrowRight className="w-3 h-3 text-primary" />
                </div>
              </div>

              {/* Pivoted Impact Node */}
              <div className="flex justify-end pr-14">
                <div
                  onClick={() => setSelectedNode(graphData?.nodes[4] || null)}
                  className={`p-3.5 rounded-lg border-2 cursor-pointer transition text-left w-64 ${
                    selectedNode?.id === "impact-data-exfil"
                      ? "bg-red-950/40 border-red-500 shadow-lg shadow-red-950/50"
                      : "bg-surface border-red-500/40 hover:border-red-400"
                  }`}
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-[10px] font-mono text-red-400 font-bold">POTENTIAL IMPACT</span>
                    <span className="text-[10px] font-mono text-zinc-400">EXFILTRATION</span>
                  </div>
                  <div className="text-xs font-semibold text-white">Synthetic Tenant Exposure</div>
                  <div className="text-[10px] text-zinc-400 mt-1">Seed customer tokens exposed</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Selected Node Details Panel */}
        <div className="lg:col-span-4 bg-surface-card border border-surface-border rounded-lg p-6 space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-surface-border">
            <h2 className="text-sm font-semibold tracking-wider uppercase text-zinc-300 font-mono">
              Relationship Evidence
            </h2>
            <Info className="w-4 h-4 text-zinc-500" />
          </div>

          {selectedNode ? (
            <div className="space-y-4 text-xs">
              <div>
                <span className="text-[10px] font-mono uppercase text-zinc-400">Node Type</span>
                <div className="text-sm font-bold text-white capitalize mt-0.5">{selectedNode.type}</div>
              </div>

              <div>
                <span className="text-[10px] font-mono uppercase text-zinc-400">Entity Title</span>
                <div className="text-xs font-semibold text-primary mt-0.5">{selectedNode.label}</div>
              </div>

              {selectedNode.severity && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-zinc-400 block mb-1">Severity Rating</span>
                  <SeverityBadge severity={selectedNode.severity} />
                </div>
              )}

              {selectedNode.data?.endpoint && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-zinc-400">Assessed Route</span>
                  <div className="bg-surface border border-surface-border rounded p-2 font-mono text-zinc-300 break-all mt-1">
                    {selectedNode.data.endpoint}
                  </div>
                </div>
              )}

              {selectedNode.data?.details && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-zinc-400">Impact Analysis</span>
                  <div className="bg-surface border border-surface-border rounded p-2.5 text-zinc-300 mt-1 leading-relaxed">
                    {selectedNode.data.details}
                  </div>
                </div>
              )}

              {selectedNode.data?.remediation && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-zinc-400">Remediation Action</span>
                  <div className="bg-surface border-l-2 border-primary rounded p-2.5 text-zinc-200 mt-1 leading-relaxed">
                    {selectedNode.data.remediation}
                  </div>
                </div>
              )}

              <div className="p-3 bg-surface border border-surface-border rounded text-[11px] text-zinc-400">
                <strong className="text-zinc-300">Integrity Note:</strong> Attack-chains are derived solely from verified relationships supported by collected evidence fixtures.
              </div>
            </div>
          ) : (
            <div className="text-center text-xs text-zinc-500 py-12">
              Select a node in the graph to view technical details and evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
