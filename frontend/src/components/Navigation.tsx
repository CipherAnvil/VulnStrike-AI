"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  LayoutDashboard,
  Radar,
  Bug,
  GitFork,
  FileText,
  Cpu,
  Settings,
  ShieldCheck,
  Activity
} from "lucide-react";

export function Sidebar() {
  const pathname = usePathname();

  const navItems = [
    { label: "Overview", href: "/", icon: LayoutDashboard },
    { label: "Scan Workspace", href: "/scans", icon: Radar },
    { label: "Findings Explorer", href: "/findings", icon: Bug },
    { label: "Attack Graph", href: "/graph", icon: GitFork },
    { label: "Reports & Audits", href: "/reports", icon: FileText },
    { label: "Model Intelligence", href: "/model-intelligence", icon: Cpu },
    { label: "Settings & Modules", href: "/settings", icon: Settings },
  ];

  return (
    <aside className="w-64 border-r border-surface-border bg-surface flex flex-col h-screen sticky top-0 select-none z-20">
      {/* Brand Header */}
      <div className="p-5 border-b border-surface-border flex items-center justify-between">
        <Link href="/" className="flex items-center space-x-3 group">
          <div className="w-9 h-9 rounded bg-primary/10 border border-primary/30 flex items-center justify-center text-primary group-hover:border-primary transition-colors">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="font-bold text-white tracking-wider flex items-center space-x-1.5">
              <span>VULNSTRIKE</span>
              <span className="text-primary text-xs px-1.5 py-0.5 rounded bg-primary/10 border border-primary/20 font-mono">
                AI
              </span>
            </div>
            <div className="text-[10px] text-zinc-400 font-mono tracking-tight">AUTHORIZED SEC-OPS</div>
          </div>
        </Link>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        <div className="px-3 py-2 text-[11px] font-semibold text-zinc-300 uppercase tracking-wider">
          Assessment Suite
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center space-x-3 px-3 py-2.5 rounded text-sm font-medium transition-all ${
                isActive
                  ? "bg-primary/15 text-primary border border-primary/30"
                  : "text-zinc-300 hover:text-white hover:bg-surface-card"
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-primary" : "text-zinc-400"}`} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Environment Scope Notice */}
      <div className="p-4 border-t border-surface-border bg-surface-card/40">
        <div className="flex items-center space-x-2 text-xs text-zinc-300 mb-2">
          <ShieldCheck className="w-4 h-4 text-primary" />
          <span className="font-semibold uppercase tracking-wider text-[11px]">Lab Scope Policy</span>
        </div>
        <p className="text-[11px] text-zinc-400 leading-relaxed">
          Authorized demo mode active. Scans restricted to seeded targets and local test fixtures.
        </p>
      </div>
    </aside>
  );
}

export function TopBar() {
  return (
    <header className="h-14 border-b border-surface-border bg-surface/80 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-10">
      <div className="flex items-center space-x-3">
        <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono bg-zinc-900 border border-zinc-700 text-zinc-300">
          <ShieldCheck className="w-3 h-3" />
          <span>AUTHORIZED LAB SCOPE</span>
        </span>
        <span className="text-xs text-zinc-300 border-l border-zinc-800 pl-3">
          Target Scope: <span className="font-mono text-zinc-300">demo-target:8088 (Seed Lab)</span>
        </span>
      </div>

      <div className="flex items-center space-x-4">
        <Link
          href="/scans"
          className="inline-flex items-center space-x-2 text-xs font-medium px-3.5 py-1.5 rounded bg-primary text-black hover:bg-primary-glow font-mono font-semibold transition"
        >
          <Activity className="w-3.5 h-3.5" />
          <span>NEW SCAN</span>
        </Link>
      </div>
    </header>
  );
}
