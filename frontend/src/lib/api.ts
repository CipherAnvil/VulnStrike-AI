import {
  ApiResult,
  AttackGraphData,
  Finding,
  HealthData,
  Scan
} from "./types";
import { MOCK_SCANS, MOCK_FINDINGS, MOCK_ATTACK_GRAPH } from "./mockData";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export class ApiError extends Error {
  status: number | null;

  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function isDemoModeEnabled(): boolean {
  return process.env.NEXT_PUBLIC_DEMO_MODE === "true";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Backend request failed.";
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;

  try {
    response = await fetch(`${API_BASE}${path}`, {
      cache: "no-store",
      ...init
    });
  } catch {
    throw new ApiError("Backend API is unreachable.");
  }

  if (!response.ok) {
    let detail = `Backend request failed (${response.status}).`;
    try {
      const payload = await response.json();
      if (typeof payload?.detail === "string") detail = payload.detail;
    } catch {
      detail = `Backend request failed (${response.status}).`;
    }
    throw new ApiError(detail, response.status);
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(`Backend returned invalid JSON (${response.status}).`, response.status);
  }
}

async function requestCollection<T>(path: string): Promise<T[]> {
  const payload = await requestJson<unknown>(path);
  if (!Array.isArray(payload)) {
    throw new ApiError("Backend returned an unexpected collection response.");
  }
  return payload as T[];
}

function demoResult<T>(data: T, error: unknown, label: string): ApiResult<T> {
  return {
    data,
    source: "demo",
    notice: `${label} Demo fixtures are being shown because ${errorMessage(error)}`
  };
}

const DEMO_HEALTH: HealthData = {
  status: "demo_mode",
  service: "VulnStrike AI Demo Fixtures",
  version: "1.0.0",
  database: "demo_data",
  is_demo: true,
  registered_modules: [
    { name: "cve_intel", display_name: "CVE Intelligence", status: "demo" },
    { name: "web_analyzer", display_name: "Web Analyzer", status: "demo" },
    { name: "auth_tester", display_name: "Auth Tester", status: "demo" },
    { name: "api_inspector", display_name: "API Inspector", status: "demo" }
  ],
  ml_engine: {
    model: "VulnVerifier-DeBERTa-v3",
    version: "2.1.0",
    status: "simulated_demo",
    precision: 0.942,
    recall: 0.918,
    f1: 0.93,
    evaluation_split: "CVE-Bench-Synthetic-2026",
    evaluated_at: "2026-10-20T18:00:00Z",
    is_demo: true
  }
};

function normalizeHealth(payload: HealthData): HealthData {
  const mlIsDemo =
    payload.ml_engine?.is_demo === true ||
    /demo|simulated/i.test(payload.ml_engine?.status || "");

  return {
    ...payload,
    is_demo: payload.is_demo === true || mlIsDemo,
    ml_engine: payload.ml_engine
      ? { ...payload.ml_engine, is_demo: payload.ml_engine.is_demo === true || mlIsDemo }
      : undefined
  };
}

export async function fetchHealth(): Promise<ApiResult<HealthData>> {
  try {
    const payload = await requestJson<HealthData>("/api/health");
    if (!payload || typeof payload !== "object") {
      throw new ApiError("Backend returned an unexpected health response.");
    }
    return { data: normalizeHealth(payload), source: "live" };
  } catch (error) {
    if (isDemoModeEnabled()) {
      return demoResult(DEMO_HEALTH, error, "Simulated health and ML metrics are demo-only.");
    }
    throw error;
  }
}

export async function fetchScans(): Promise<ApiResult<Scan[]>> {
  try {
    return { data: await requestCollection<Scan>("/api/scans"), source: "live" };
  } catch (error) {
    if (isDemoModeEnabled()) {
      return demoResult(MOCK_SCANS, error, "Demo scan fixtures are active.");
    }
    throw error;
  }
}

export async function fetchScan(id: string): Promise<ApiResult<Scan | null>> {
  try {
    const payload = await requestJson<Scan>(`/api/scans/${encodeURIComponent(id)}`);
    return { data: payload, source: "live" };
  } catch (error) {
    if (isDemoModeEnabled()) {
      const data = MOCK_SCANS.find((scan) => scan.id === id) || null;
      return demoResult(data, error, "Demo scan fixtures are active.");
    }
    throw error;
  }
}

export async function startScan(
  target_url: string,
  authorized_confirmation: boolean,
  profile: string,
  enabled_modules: string[]
): Promise<Scan> {
  return requestJson<Scan>("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target_url,
      authorized_confirmation,
      profile,
      enabled_modules
    })
  });
}

export async function fetchFindings(params?: {
  scan_id?: string;
  severity?: string;
  verification_status?: string;
  search?: string;
}): Promise<ApiResult<Finding[]>> {
  const query = new URLSearchParams();
  if (params?.scan_id) query.append("scan_id", params.scan_id);
  if (params?.severity) query.append("severity", params.severity);
  if (params?.verification_status) query.append("verification_status", params.verification_status);
  if (params?.search) query.append("search", params.search);

  try {
    return {
      data: await requestCollection<Finding>(`/api/findings?${query.toString()}`),
      source: "live"
    };
  } catch (error) {
    if (isDemoModeEnabled()) {
      return demoResult(MOCK_FINDINGS, error, "Demo finding fixtures are active.");
    }
    throw error;
  }
}

export async function fetchAttackGraph(scanId?: string): Promise<ApiResult<AttackGraphData>> {
  if (!scanId) {
    throw new ApiError("Select a scan before loading the attack graph.");
  }

  try {
    const payload = await requestJson<AttackGraphData>(
      `/api/reports/${encodeURIComponent(scanId)}/graph`
    );
    if (!payload || !Array.isArray(payload.nodes) || !Array.isArray(payload.edges)) {
      throw new ApiError("Backend returned an unexpected attack graph response.");
    }
    return { data: payload, source: "live" };
  } catch (error) {
    if (isDemoModeEnabled()) {
      return demoResult(MOCK_ATTACK_GRAPH, error, "Demo attack graph fixtures are active.");
    }
    throw error;
  }
}
