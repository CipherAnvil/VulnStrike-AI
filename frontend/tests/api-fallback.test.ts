import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import {
  ApiError,
  fetchAttackGraph,
  fetchFindings,
  fetchHealth,
  fetchScans
} from "../src/lib/api";
import { MOCK_ATTACK_GRAPH, MOCK_FINDINGS, MOCK_SCANS } from "../src/lib/mockData";

const originalFetch = globalThis.fetch;
const originalDemoMode = process.env.NEXT_PUBLIC_DEMO_MODE;

function setFetch(handler: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  globalThis.fetch = handler as typeof fetch;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDemoMode === undefined) {
    delete process.env.NEXT_PUBLIC_DEMO_MODE;
  } else {
    process.env.NEXT_PUBLIC_DEMO_MODE = originalDemoMode;
  }
});

test("a successful empty scans response stays empty", async () => {
  setFetch(async () => jsonResponse([]));

  const result = await fetchScans();

  assert.equal(result.source, "live");
  assert.deepEqual(result.data, []);
  assert.notEqual(result.data, MOCK_SCANS);
});

test("a successful empty findings response stays empty", async () => {
  setFetch(async () => jsonResponse([]));

  const result = await fetchFindings();

  assert.equal(result.source, "live");
  assert.deepEqual(result.data, []);
  assert.notEqual(result.data, MOCK_FINDINGS);
});

test("a successful empty response stays empty even when demo mode is enabled", async () => {
  process.env.NEXT_PUBLIC_DEMO_MODE = "true";
  setFetch(async () => jsonResponse([]));

  const scans = await fetchScans();
  const findings = await fetchFindings();

  assert.equal(scans.source, "live");
  assert.deepEqual(scans.data, []);
  assert.equal(findings.source, "live");
  assert.deepEqual(findings.data, []);
});

test("an API failure is distinguishable from an empty response", async () => {
  delete process.env.NEXT_PUBLIC_DEMO_MODE;
  setFetch(async () => {
    throw new Error("offline");
  });

  await assert.rejects(fetchScans(), (error: unknown) => {
    assert.ok(error instanceof ApiError);
    assert.match(error.message, /unreachable/i);
    return true;
  });
});

test("demo mode returns labeled scan fixtures on API failure", async () => {
  process.env.NEXT_PUBLIC_DEMO_MODE = "true";
  setFetch(async () => {
    throw new Error("offline");
  });

  const result = await fetchScans();

  assert.equal(result.source, "demo");
  assert.equal(result.data, MOCK_SCANS);
  assert.match(result.notice || "", /demo fixtures/i);
});

test("demo mode returns labeled finding fixtures on API failure", async () => {
  process.env.NEXT_PUBLIC_DEMO_MODE = "true";
  setFetch(async () => {
    throw new Error("offline");
  });

  const result = await fetchFindings();

  assert.equal(result.source, "demo");
  assert.equal(result.data, MOCK_FINDINGS);
  assert.match(result.notice || "", /demo fixtures/i);
});

test("simulated live health payloads are marked as demo metrics", async () => {
  delete process.env.NEXT_PUBLIC_DEMO_MODE;
  setFetch(async () =>
    jsonResponse({
      status: "healthy",
      ml_engine: { status: "online_simulated", precision: 0.9 }
    })
  );

  const result = await fetchHealth();

  assert.equal(result.source, "live");
  assert.equal(result.data.is_demo, true);
  assert.equal(result.data.ml_engine?.is_demo, true);
});

test("demo mode returns clearly labeled health metrics on API failure", async () => {
  process.env.NEXT_PUBLIC_DEMO_MODE = "true";
  setFetch(async () => {
    throw new Error("offline");
  });

  const result = await fetchHealth();

  assert.equal(result.source, "demo");
  assert.equal(result.data.is_demo, true);
  assert.equal(result.data.ml_engine?.is_demo, true);
  assert.match(result.data.ml_engine?.status || "", /demo/i);
});

test("health failures are not replaced with demo metrics unless demo mode is enabled", async () => {
  delete process.env.NEXT_PUBLIC_DEMO_MODE;
  setFetch(async () => {
    throw new Error("offline");
  });

  await assert.rejects(fetchHealth(), ApiError);
});

test("an attack graph without a selected scan is not replaced with mock data", async () => {
  process.env.NEXT_PUBLIC_DEMO_MODE = "true";

  await assert.rejects(fetchAttackGraph(), ApiError);
});

test("demo mode returns a labeled attack graph on API failure", async () => {
  process.env.NEXT_PUBLIC_DEMO_MODE = "true";
  setFetch(async () => {
    throw new Error("offline");
  });

  const result = await fetchAttackGraph("SCAN-LAB-9142");

  assert.equal(result.source, "demo");
  assert.equal(result.data, MOCK_ATTACK_GRAPH);
  assert.match(result.notice || "", /demo attack graph/i);
});

test("a successful empty attack graph response stays empty", async () => {
  setFetch(async () => jsonResponse({ nodes: [], edges: [] }));

  const result = await fetchAttackGraph("SCAN-TEST-EMPTY");

  assert.equal(result.source, "live");
  assert.deepEqual(result.data, { nodes: [], edges: [] });
});
