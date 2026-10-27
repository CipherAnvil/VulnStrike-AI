import React from "react";
import { AlertCircle, Loader2 } from "lucide-react";

export function LoadingNotice({ label = "Loading live data..." }: { label?: string }) {
  return (
    <div className="bg-surface-card border border-surface-border rounded-lg p-4 text-xs font-mono text-zinc-300 flex items-center space-x-2">
      <Loader2 className="w-4 h-4 text-primary animate-spin" />
      <span>{label}</span>
    </div>
  );
}

export function ApiErrorNotice({ message }: { message: string }) {
  return (
    <div className="bg-red-950/40 border border-red-500/50 rounded-lg p-4 text-xs font-mono text-red-300 flex items-start space-x-2">
      <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
      <span>{message}</span>
    </div>
  );
}

export function EmptyNotice({ title, description }: { title: string; description: string }) {
  return (
    <div className="p-10 text-center border border-dashed border-surface-border rounded-lg">
      <div className="text-sm font-semibold text-zinc-300">{title}</div>
      <div className="text-xs text-zinc-500 mt-1">{description}</div>
    </div>
  );
}
