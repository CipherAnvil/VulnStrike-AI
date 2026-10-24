import React from "react";
import { Severity, VerificationStatus } from "@/lib/types";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const styles: Record<string, string> = {
    critical: "bg-red-950/70 border-red-500/50 text-red-400",
    high: "bg-orange-950/70 border-orange-500/50 text-orange-400",
    medium: "bg-yellow-950/70 border-yellow-500/50 text-yellow-400",
    low: "bg-blue-950/70 border-blue-500/50 text-blue-400",
    info: "bg-cyan-950/70 border-cyan-500/50 text-cyan-400"
  };

  const style = styles[severity.toLowerCase()] || styles.info;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono uppercase font-bold border ${style}`}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: VerificationStatus | string }) {
  const styles: Record<string, string> = {
    confirmed: "bg-emerald-950/60 border-emerald-500/40 text-emerald-400",
    suspected: "bg-amber-950/60 border-amber-500/40 text-amber-400",
    inconclusive: "bg-zinc-800 border-zinc-700 text-zinc-400",
    completed: "bg-emerald-950/60 border-emerald-500/40 text-emerald-400",
    running: "bg-sky-950/60 border-sky-500/40 text-sky-400",
    queued: "bg-zinc-800 border-zinc-700 text-zinc-300",
    failed: "bg-red-950/60 border-red-500/40 text-red-400",
    cancelled: "bg-zinc-800 border-zinc-700 text-zinc-500"
  };

  const style = styles[status.toLowerCase()] || "bg-zinc-800 border-zinc-700 text-zinc-300";

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono capitalize border ${style}`}>
      {status}
    </span>
  );
}

export function DemoNoticeBanner() {
  return (
    <div className="bg-amber-950/30 border border-amber-500/30 rounded-lg p-3 text-xs text-amber-200/90 flex items-start space-x-2 mb-6">
      <span className="font-mono font-bold bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider">
        Notice
      </span>
      <span>
        Educational Demonstration Mode. Assessment metrics and findings are generated from controlled seed fixtures. Targets outside authorized demonstration bounds are strictly rejected.
      </span>
    </div>
  );
}
