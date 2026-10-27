import { Scan, Finding, AttackGraphData } from "./types";

export const MOCK_SCANS: Scan[] = [
  {
    id: "SCAN-LAB-9142",
    target_url: "http://demo-target:8088",
    status: "completed",
    profile: "standard",
    enabled_modules: ["cve_intel", "web_analyzer", "auth_tester", "api_inspector"],
    is_demo: true,
    created_at: "2026-10-24T11:45:00Z",
    started_at: "2026-10-24T11:45:02Z",
    completed_at: "2026-10-24T11:46:18Z",
    findings_count: 4,
    critical_count: 1,
    high_count: 1,
    medium_count: 2,
    low_count: 0,
    info_count: 0,
    log_messages: [
      "Scan initialized for authorized demo target: http://demo-target:8088",
      "Module cve_intel finished with 1 finding",
      "Module web_analyzer finished with 1 finding",
      "Module auth_tester finished with 1 finding",
      "Module api_inspector finished with 1 finding",
      "Assessment concluded. Findings persisted in evidence store."
    ]
  },
  {
    id: "SCAN-LAB-8021",
    target_url: "http://localhost:8080",
    status: "completed",
    profile: "quick",
    enabled_modules: ["cve_intel", "web_analyzer"],
    is_demo: true,
    created_at: "2026-10-24T09:12:00Z",
    started_at: "2026-10-24T09:12:01Z",
    completed_at: "2026-10-24T09:12:45Z",
    findings_count: 2,
    critical_count: 0,
    high_count: 0,
    medium_count: 2,
    low_count: 0,
    info_count: 0,
    log_messages: [
      "Target verified in local scope.",
      "Quick assessment finished."
    ]
  }
];

export const MOCK_FINDINGS: Finding[] = [
  {
    id: "VS-9142-01",
    scan_id: "SCAN-LAB-9142",
    module: "cve_intel",
    category: "cve",
    title: "Apache 2.4.49 Path Traversal & Remote Code Execution (Simulated)",
    severity: "critical",
    verification_status: "confirmed",
    endpoint: "http://demo-target:8088/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
    summary: "Server banner exposes Apache 2.4.49 with known path traversal flaw in test lab.",
    description: "Path normalization flaw in Apache HTTP Server 2.4.49 allows unauthenticated clients to map URLs outside document root.",
    evidence_references: ["EV-9142-01"],
    remediation_guidance: "Upgrade Apache HTTP Server to version 2.4.51 or later. Disable mod_cgi if unneeded.",
    ml_confidence: 0.98,
    cve_id: "CVE-2021-41773",
    cvss_score: 9.8,
    created_at: "2026-10-24T11:45:15Z",
    is_demo: true
  },
  {
    id: "VS-9142-02",
    scan_id: "SCAN-LAB-9142",
    module: "auth_tester",
    category: "access_control",
    title: "Broken Object Level Authorization on Internal Admin Telemetry",
    severity: "high",
    verification_status: "confirmed",
    endpoint: "http://demo-target:8088/internal/admin/metrics",
    summary: "Administrative metrics endpoint responds to unauthenticated client requests without role verification.",
    description: "The endpoint does not validate tokens or session cookies, exposing tenant counters and internal configuration flags.",
    evidence_references: ["EV-9142-03"],
    remediation_guidance: "Implement RBAC middleware to enforce valid admin bearer tokens and restrict route access at ingress.",
    ml_confidence: 0.95,
    created_at: "2026-10-24T11:45:32Z",
    is_demo: true
  },
  {
    id: "VS-9142-03",
    scan_id: "SCAN-LAB-9142",
    module: "api_inspector",
    category: "info_disclosure",
    title: "Excessive Data Exposure in User Listing API",
    severity: "medium",
    verification_status: "suspected",
    endpoint: "http://demo-target:8088/api/v1/users",
    summary: "User enumeration route returns extensive internal profile fields without field filtering.",
    description: "Responses include synthetic user tokens and debug role attributes not intended for public callers.",
    evidence_references: ["EV-9142-04"],
    remediation_guidance: "Apply response DTO serialization to filter internal fields before serialization.",
    ml_confidence: 0.74,
    created_at: "2026-10-24T11:45:48Z",
    is_demo: true
  },
  {
    id: "VS-9142-04",
    scan_id: "SCAN-LAB-9142",
    module: "web_analyzer",
    category: "misconfiguration",
    title: "Missing Strict Content-Security-Policy & Transport Headers",
    severity: "medium",
    verification_status: "confirmed",
    endpoint: "http://demo-target:8088/api/v1/health",
    summary: "Defensive headers CSP and HSTS are absent, increasing exposure to cross-site scripting and downgrade vectors.",
    description: "HTTP headers lack CSP and HSTS directives across assessed public routes.",
    evidence_references: ["EV-9142-02"],
    remediation_guidance: "Configure Content-Security-Policy with strict script-src and default-src directives. Add HSTS with max-age=31536000.",
    ml_confidence: 0.82,
    created_at: "2026-10-24T11:46:01Z",
    is_demo: true
  }
];

export const MOCK_ATTACK_GRAPH: AttackGraphData = {
  nodes: [
    {
      id: "target-root",
      type: "target",
      label: "Target: http://demo-target:8088",
      severity: "info",
      status: "active",
      data: { description: "Authorized demonstration target container" }
    },
    {
      id: "finding-cve",
      type: "finding",
      label: "Apache 2.4.49 Path Traversal",
      severity: "critical",
      status: "confirmed",
      data: {
        id: "VS-9142-01",
        endpoint: "/cgi-bin/.%2e/.%2e/etc/passwd",
        cvss: 9.8,
        module: "cve_intel",
        remediation: "Upgrade Apache HTTP Server >= 2.4.51"
      }
    },
    {
      id: "finding-bola",
      type: "finding",
      label: "BOLA on Internal Admin Telemetry",
      severity: "high",
      status: "confirmed",
      data: {
        id: "VS-9142-02",
        endpoint: "/internal/admin/metrics",
        module: "auth_tester",
        remediation: "Enforce RBAC middleware on internal routes"
      }
    },
    {
      id: "finding-leak",
      type: "finding",
      label: "Excessive Data Exposure (Users API)",
      severity: "medium",
      status: "suspected",
      data: {
        id: "VS-9142-03",
        endpoint: "/api/v1/users",
        module: "api_inspector",
        remediation: "Filter internal JSON response fields"
      }
    },
    {
      id: "impact-data-exfil",
      type: "impact",
      label: "Synthetic Tenant Record Exposure",
      severity: "high",
      status: "confirmed",
      data: {
        details: "Access control pivot permits querying unmasked test customer records."
      }
    }
  ],
  edges: [
    {
      id: "e1",
      source: "target-root",
      target: "finding-cve",
      label: "Discovered on host",
      relationship: "discovery"
    },
    {
      id: "e2",
      source: "target-root",
      target: "finding-bola",
      label: "Discovered on endpoint",
      relationship: "discovery"
    },
    {
      id: "e3",
      source: "finding-bola",
      target: "finding-leak",
      label: "Permits pivot into user registry",
      evidence_id: "EV-REL-01",
      relationship: "exploit_pivot"
    },
    {
      id: "e4",
      source: "finding-leak",
      target: "impact-data-exfil",
      label: "Results in",
      relationship: "consequence"
    }
  ]
};
