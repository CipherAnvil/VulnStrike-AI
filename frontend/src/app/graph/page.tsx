"use client";

import { useState, useEffect } from "react";
import {
  GitFork,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Info,
  ArrowRight
} from "lucide-react";
import { fetchScans, fetchAttackGraph } from "@/lib/api";
import { ApiSource, AttackGraphData, GraphNode } from "@/lib/types";
import { SeverityBadge, StatusBadge, DemoNoticeBanner } from "@/components/Badges";
import { ApiErrorNotice, EmptyNotice, LoadingNotice } from "@/components/ApiState";

function nodeClasses(node: GraphNode, selected: boolean): string {
  const base = "p-3 rounded-lg border-2 cursor-pointer transition text-left";

  if (node.type === "target") {
    return `${base} ${selected ? "bg-cyan-950/40 border-cyan-400" : "bg-surface border-cyan-500/40 hover:border-cyan-400"}`;
  }

  if (node.type === "impact") {
    return `${base} ${selected ? "bg-orange-950/40 border-orange-500" : "bg-surface border-orange-500/40 hover:border-orange-400"}`;
  }

  switch ((node.severity || "info").toLowerCase()) {
    case "critical":
      return `${base} ${selected ? "bg-red-950/40 border-red-500" : "bg-surface border-red-500/40 hover:border-red-400"}`;
    case "high":
      return `${base} ${selected ? "bg-orange-950/40 border-orange-500" : "bg-surface border-orange-500/40 hover:border-orange-400"}`;
    case "medium":
      return `${base} ${selected ? "bg-yellow-950/40 border-yellow-500" : "bg-surface border-yellow-500/40 hover:border-yellow-400"}`;
    default:
      return `${base} ${selected ? "bg-cyan-950/40 border-cyan-400" : "bg-surface border-cyan-500/40 hover:border-cyan-400"}`;
  }
}

export default function AttackGraphPage() {
  const [graphData, setGraphData] = useState<AttackGraphData | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [source, setSource] = useState<ApiSource | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [scanLabel, setScanLabel] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const scansResult = await fetchScans();
        const scan = scansResult.data[0];
        const messages: string[] = [];
        let nextSource: ApiSource = scansResult.source;

        if (scansResult.notice) messages.push(scansResult.notice);

        if (!scan) {
          setGraphData({ nodes: [], edges: [] });
          setSelectedNode(null);
          setScanLabel(null);
          setSource(nextSource);
          setNotice(messages.join(" ") || null);
          return;
        }

        setScanLabel(`${scan.id} · ${scan.target_url}`);
        const graphResult = await fetchAttackGraph(scan.id);
        setGraphData(graphResult.data);
        setSelectedNode(
          graphResult.data.nodes.find((node) => node.type === "finding") ||
            graphResult.data.nodes[0] ||
            null
        );
        if (graphResult.source === "demo") nextSource = "demo";
        if (graphResult.notice) messages.push(graphResult.notice);
        setSource(nextSource);
        setNotice(messages.join(" ") || null);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : "Failed to load the attack graph.");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const nodes = graphData?.nodes || [];
  const edges = graphData?.edges || [];
  const targetNodes = nodes.filter((node) => node.type === "target");
  const findingNodes = nodes.filter((node) => node.type === "finding");
  const impactNodes = nodes.filter((node) => node.type !== "target" && node.type !== "finding");
  const nodeById = new Map(nodes.map((node) => [node.id, node]));

  return (
    <div className="space-y-6">
      <DemoNoticeBanner visible={source === "demo"} message={notice || undefined} />
      {loading && <LoadingNotice label="Loading attack graph..." />}
      {error && <ApiErrorNotice message={`Attack graph unavailable. ${error}`} />}

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-surface-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
            <GitFork className="w-6 h-6 text-primary" />
            <span>Attack-Chain Relationship Graph</span>
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Evidence-backed relationship graph mapping vulnerability pivots to asset compromise.
          </p>
          {scanLabel && <p className="text-xs text-zinc-500 font-mono mt-1">{scanLabel}</p>}
        </div>

        <div className="flex items-center space-x-4 text-xs font-mono text-zinc-400 bg-surface-card border border-surface-border px-3 py-1.5 rounded">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
            <span>Target Host</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
            <span>Finding</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
            <span>Impact</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 bg-surface-card border border-surface-border rounded-lg p-5 flex flex-col h-[560px] relative overflow-y-auto">
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

          <div
            className="flex-1 flex flex-col justify-center items-center relative transition-transform duration-200 py-10"
            style={{ transform: `scale(${zoomLevel})` }}
          >
            {nodes.length === 0 ? (
              <div className="w-full px-6">
                <EmptyNotice
                  title={loading ? "Loading graph..." : "No attack graph yet"}
                  description={
                    loading
                      ? "Waiting for the latest scan graph."
                      : "Complete an authorized scan to generate evidence-backed graph relationships."
                  }
                />
              </div>
            ) : (
              <div className="space-y-8 w-full max-w-xl">
                {targetNodes.length > 0 && (
                  <div className="flex flex-wrap justify-center gap-3">
                    {targetNodes.map((node) => (
                      <div
                        key={node.id}
                        onClick={() => setSelectedNode(node)}
                        className={`${nodeClasses(node, selectedNode?.id === node.id)} text-center max-w-xs`}
                      >
                        <div className="text-[10px] font-mono uppercase text-cyan-400 font-bold">Target Ingress</div>
                        <div className="text-xs font-mono text-white mt-0.5">{node.label}</div>
                      </div>
                    ))}
                  </div>
                )}

                {findingNodes.length > 0 && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {findingNodes.map((node) => (
                      <div
                        key={node.id}
                        onClick={() => setSelectedNode(node)}
                        className={nodeClasses(node, selectedNode?.id === node.id)}
                      >
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-[10px] font-mono text-zinc-400 uppercase">{node.type}</span>
                          {node.severity && <SeverityBadge severity={node.severity} />}
                        </div>
                        <div className="text-xs font-semibold text-white">{node.label}</div>
                        {node.data?.endpoint && (
                          <div className="text-[10px] font-mono text-zinc-400 mt-1 break-all">{node.data.endpoint}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {impactNodes.length > 0 && (
                  <div className="flex flex-wrap justify-center gap-3">
                    {impactNodes.map((node) => (
                      <div
                        key={node.id}
                        onClick={() => setSelectedNode(node)}
                        className={`${nodeClasses(node, selectedNode?.id === node.id)} w-full sm:w-72`}
                      >
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-[10px] font-mono text-zinc-400 uppercase">{node.type}</span>
                          {node.severity && <SeverityBadge severity={node.severity} />}
                        </div>
                        <div className="text-xs font-semibold text-white">{node.label}</div>
                      </div>
                    ))}
                  </div>
                )}

                {edges.length > 0 && (
                  <div className="border-t border-surface-border pt-4 space-y-1.5">
                    {edges.map((edge) => (
                      <div key={edge.id} className="flex items-center justify-center space-x-2 text-[10px] font-mono text-zinc-400">
                        <span>{nodeById.get(edge.source)?.label || edge.source}</span>
                        <ArrowRight className="w-3 h-3 text-primary shrink-0" />
                        <span>{nodeById.get(edge.target)?.label || edge.target}</span>
                        <span className="text-zinc-600">({edge.label || edge.relationship})</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

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

              {selectedNode.status && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-zinc-400 block mb-1">Verification Status</span>
                  <StatusBadge status={selectedNode.status} />
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
                <strong className="text-zinc-300">Integrity Note:</strong> Graph entities are rendered from the selected scan response. Demo fixtures are explicitly labeled and are not live findings.
              </div>
            </div>
          ) : (
            <div className="text-center text-xs text-zinc-500 py-12">
              {loading
                ? "Loading graph details..."
                : error
                  ? "Graph details are unavailable until the API responds."
                  : "Select a node in the graph to view technical details and evidence."}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
