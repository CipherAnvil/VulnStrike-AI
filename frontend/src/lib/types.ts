export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type VerificationStatus = "confirmed" | "suspected" | "inconclusive";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type ScanProfile = "quick" | "standard" | "deep";
export type ApiSource = "live" | "demo";

export interface ApiResult<T> {
  data: T;
  source: ApiSource;
  notice?: string;
}

export interface HealthModule {
  name: string;
  display_name: string;
  status: string;
  version?: string;
  timeout_seconds?: number;
}

export interface MlEngineHealth {
  status?: string;
  model?: string;
  version?: string;
  precision?: number;
  recall?: number;
  f1?: number;
  evaluation_split?: string;
  evaluated_at?: string;
  is_demo?: boolean;
}

export interface HealthData {
  status: string;
  service?: string;
  version?: string;
  database?: string;
  is_demo?: boolean;
  ml_engine?: MlEngineHealth;
  registered_modules?: HealthModule[];
}

export interface Scan {
  id: string;
  target_url: string;
  status: ScanStatus;
  profile: ScanProfile;
  enabled_modules: string[];
  is_demo: boolean;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message?: string;
  log_messages: string[];
}

export interface Finding {
  id: string;
  scan_id: string;
  module: string;
  category: string;
  title: string;
  severity: Severity;
  verification_status: VerificationStatus;
  endpoint: string;
  summary: string;
  description: string;
  evidence_references: string[];
  remediation_guidance: string;
  ml_confidence?: number;
  cve_id?: string;
  cvss_score?: number;
  created_at: string;
  is_demo: boolean;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  severity?: string;
  status?: string;
  data: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  evidence_id?: string;
  relationship: string;
}

export interface AttackGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
