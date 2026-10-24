#!/usr/bin/env python3
"""End-to-end verification suite for all five VulnStrike AI standalone scripts.

Runs 100% locally by default (zero external internet calls required), making it
safe and fast inside firewalled sandboxes, CI pipelines, and isolated Docker lab
networks. Pass ``--live-nvd`` to optionally query the real NIST NVD v2.0 API.

Verifies:
  1. crawler.py           — BFS crawl, forms, cookies, XHR/fetch logging, broken-link resilience
  2. cve_fingerprinter.py — Header/meta/script fingerprinting, HTTP 429 retry logic,
                            AND fast-fail circuit-breaker when NVD is unreachable/blocked
  3. idor_tester.py       — Dual-context hybrid auth (cookies + Bearer JWT), IDOR detection,
                            and zero false positives on protected / self-profile routes
  4. jwt_inspector.py     — Unverified decode, alg:none server acceptance, PyJWT secret cracking
  5. xss_verifier.py      — Reflected dialog XSS, Stored DOM XSS (--verify-url), screenshots,
                            and negative check on HTML-escaped output
  6. merge_reports.py     — Consolidates all subsystem JSON reports
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse
import warnings

import jwt

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from examples.merge_reports import merge_subsystem_outputs  # noqa: E402
from tests.mock_lab_app import LAB_JWT_SECRET, start_mock_server  # noqa: E402

SAMPLE_OUT = ROOT_DIR / "sample_outputs"

MOCK_NVD_FIXTURES: dict[str, list[dict[str, Any]]] = {
    "nginx": [
        {
            "cve": {
                "id": "CVE-2021-23017",
                "vulnStatus": "Analyzed",
                "metrics": {
                    "cvssMetricV31": [
                        {"type": "Primary", "cvssData": {"baseScore": 7.7}}
                    ]
                },
                "references": [
                    {
                        "url": "https://packetstormsecurity.com/files/nginx-resolver",
                        "tags": ["Exploit", "Third Party Advisory"],
                    }
                ],
            }
        }
    ],
    "php": [
        {
            "cve": {
                "id": "CVE-2021-21708",
                "vulnStatus": "Analyzed",
                "metrics": {
                    "cvssMetricV31": [
                        {"type": "Primary", "cvssData": {"baseScore": 9.8}}
                    ]
                },
                "references": [
                    {
                        "url": "https://bugs.php.net/bug.php?id=81727",
                        "tags": ["Exploit", "Vendor Advisory"],
                    }
                ],
            }
        }
    ],
    "wordpress": [
        {
            "cve": {
                "id": "CVE-2024-4439",
                "vulnStatus": "Analyzed",
                "metrics": {
                    "cvssMetricV31": [
                        {"type": "Primary", "cvssData": {"baseScore": 7.2}}
                    ]
                },
                "references": [
                    {
                        "url": "https://wordpress.org/news/2024/05/zeke/",
                        "tags": ["Patch", "Vendor Advisory"],
                    }
                ],
            }
        }
    ],
    "jquery": [
        {
            "cve": {
                "id": "CVE-2020-11022",
                "vulnStatus": "Analyzed",
                "metrics": {
                    "cvssMetricV31": [
                        {"type": "Primary", "cvssData": {"baseScore": 6.1}}
                    ]
                },
                "references": [
                    {
                        "url": "https://github.com/jquery/jquery/security/advisories",
                        "tags": ["Exploit", "Vendor Advisory"],
                    }
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2020-11023",
                "vulnStatus": "Analyzed",
                "metrics": {
                    "cvssMetricV31": [
                        {"type": "Primary", "cvssData": {"baseScore": 6.1}}
                    ]
                },
                "references": [
                    {
                        "url": "https://jquery.com/upgrade-guide/3.5/",
                        "tags": ["Vendor Advisory"],
                    }
                ],
            }
        },
    ],
}


def _run_cli(script_name: str, args: list[str], timeout_sec: float = 45.0) -> None:
    """Invoke one standalone script via subprocess and assert exit code 0."""
    cmd = [sys.executable, str(ROOT_DIR / script_name), *args]
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_sec,
    )
    if res.returncode != 0:
        raise AssertionError(
            f"{script_name} failed (exit={res.returncode}):\n"
            f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )


def _start_mock_nvd_server() -> tuple[ThreadingHTTPServer, str, dict[str, int]]:
    """Start a local NIST NVD v2.0 mock server that tests HTTP 429 retry + CPE matching."""
    stats = {"requests": 0, "rate_limited": 0}

    class MockNVDHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            stats["requests"] += 1
            # Simulate initial NVD rate limit on the very first call
            if stats["requests"] == 1:
                stats["rate_limited"] += 1
                self.send_response(429)
                self.send_header("Retry-After", "1")
                self.end_headers()
                self.wfile.write(b"Rate limit exceeded")
                return

            qs = parse_qs(urlparse(self.path).query)
            cpe = (qs.get("virtualMatchString", [""])[0] or "").lower()
            kw = (qs.get("keywordSearch", [""])[0] or "").lower()
            query_blob = f"{cpe} {kw}"

            vulns: list[dict[str, Any]] = []
            for tech_key, items in MOCK_NVD_FIXTURES.items():
                if tech_key in query_blob:
                    vulns = items
                    break

            raw = json.dumps(
                {"totalResults": len(vulns), "vulnerabilities": vulns}
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    nvd_srv = ThreadingHTTPServer(("127.0.0.1", 0), MockNVDHandler)
    nvd_port = nvd_srv.server_address[1]
    threading.Thread(target=nvd_srv.serve_forever, daemon=True).start()
    return nvd_srv, f"http://127.0.0.1:{nvd_port}/rest/json/cves/2.0", stats


def _find_closed_local_port() -> int:
    """Reserve and immediately close an ephemeral TCP port to simulate an unreachable NVD host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _verify_blocked_nvd_fast_fail(lab_url: str, tmp_out: Path) -> None:
    """Ensure cve_fingerprinter.py fast-fails via circuit-breaker when NVD is unreachable."""
    dead_port = _find_closed_local_port()
    start = time.monotonic()
    _run_cli(
        "cve_fingerprinter.py",
        [
            "--url",
            lab_url,
            "--nvd-url",
            f"http://127.0.0.1:{dead_port}/rest/json/cves/2.0",
            "--connect-timeout",
            "1.0",
            "--output",
            str(tmp_out),
        ],
        timeout_sec=10.0,
    )
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"Circuit-breaker should fail fast (<5s), took {elapsed:.2f}s"
    fallback_data = json.loads(tmp_out.read_text(encoding="utf-8"))
    assert len(fallback_data) >= 4, "All fingerprinted technologies must still be saved when offline"
    tmp_out.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    """Run all standalone module E2E tests and generate sample outputs."""
    parser = argparse.ArgumentParser(description="Run VulnStrike AI E2E verification")
    parser.add_argument(
        "--live-nvd",
        action="store_true",
        help="Query live services.nvd.nist.gov instead of the local mock NVD v2.0 server",
    )
    args = parser.parse_args(argv)

    SAMPLE_OUT.mkdir(parents=True, exist_ok=True)
    server, base_url = start_mock_server()
    nvd_server, mock_nvd_url, nvd_stats = _start_mock_nvd_server()
    print(f"[1/6] Started mock hybrid lab server at {base_url}")

    try:
        # 1. Subsystem 1 — Crawler
        crawl_out = SAMPLE_OUT / "crawl_report.json"
        _run_cli(
            "crawler.py",
            [
                "--url",
                base_url,
                "--max-depth",
                "2",
                "--output",
                str(crawl_out),
            ],
        )
        crawl_data = json.loads(crawl_out.read_text(encoding="utf-8"))
        assert "pages" in crawl_data and len(crawl_data["pages"]) >= 5
        home_page = next(p for p in crawl_data["pages"] if p["depth"] == 0)
        assert any("/api/stats" in c["url"] for c in home_page["api_calls"]), (
            "Expected crawler to log fetch('/api/stats') via page.on('request')"
        )
        assert any(c["name"] == "visitor_track" for c in home_page["cookies"]), (
            "Expected crawler to capture session cookies"
        )
        all_forms = [f for p in crawl_data["pages"] for f in p["forms"]]
        assert len(all_forms) >= 3, "Expected forms extracted across crawled pages"
        print(f"[2/6] Crawler verified: {len(crawl_data['pages'])} pages crawled")

        # 2. Subsystem 2 — CVE Fingerprinter (Blocked-network circuit-breaker + 429 retry + NVD scan)
        _verify_blocked_nvd_fast_fail(base_url, SAMPLE_OUT / "_tmp_offline_cve.json")

        cve_out = SAMPLE_OUT / "cve_report.json"
        cve_cli_args = [
            "--url",
            base_url,
            "--max-cves",
            "5",
            "--output",
            str(cve_out),
        ]
        if not args.live_nvd:
            cve_cli_args.extend(["--nvd-url", mock_nvd_url, "--min-interval", "0.05"])

        _run_cli("cve_fingerprinter.py", cve_cli_args, timeout_sec=60.0)
        cve_data = json.loads(cve_out.read_text(encoding="utf-8"))
        detected_names = {entry["technology"].lower() for entry in cve_data}
        assert {"nginx", "php", "wordpress", "jquery"}.issubset(detected_names), (
            f"Expected nginx, php, wordpress, jquery; got {detected_names}"
        )
        if not args.live_nvd:
            assert nvd_stats["rate_limited"] == 1 and nvd_stats["requests"] >= 5, (
                "Expected mock NVD server to test HTTP 429 Retry-After recovery"
            )
        for entry in cve_data:
            assert {"technology", "version", "cves"}.issubset(entry.keys())
            assert len(entry["cves"]) >= 1
            for cve in entry["cves"]:
                assert {"id", "cvss", "has_public_exploit"} == set(cve.keys())
                assert isinstance(cve["has_public_exploit"], bool)
        mode_label = "live NIST NVD" if args.live_nvd else "local Mock NVD + circuit-breaker"
        print(
            f"[3/6] CVE Fingerprinter verified ({mode_label}): {len(cve_data)} technologies enriched"
        )

        # 3. Subsystem 3.1 — IDOR Tester (hybrid login + range + false-positive checks)
        idor_out = SAMPLE_OUT / "idor_report.json"
        _run_cli(
            "idor_tester.py",
            [
                "--base-url",
                base_url,
                "--user-a",
                "alice:alice_password_123",
                "--user-b",
                "bob:bob_password_123",
                "--pattern",
                "/api/orders/{id}",
                "--pattern",
                "/api/invoices/{id}",
                "--pattern",
                "/api/me",
                "--ids",
                "201",
                "--id-range",
                "101-102",
                "--output",
                str(idor_out),
            ],
        )
        idor_data = json.loads(idor_out.read_text(encoding="utf-8"))
        by_url = {f["url"]: f for f in idor_data["findings"]}
        assert by_url[f"{base_url}/api/orders/101"]["vulnerable"] is True, (
            "Order 101 belongs to Alice and leaked to Bob -> must flag IDOR"
        )
        assert by_url[f"{base_url}/api/invoices/201"]["vulnerable"] is False, (
            "Invoice 201 returns 403 for Bob -> must NOT flag IDOR"
        )
        assert by_url[f"{base_url}/api/me"]["vulnerable"] is False, (
            "/api/me returns Bob's own profile -> must NOT false-positive"
        )
        print(
            f"[4/6] IDOR Tester verified: {idor_data['summary']['vulnerable_count']} true IDOR flagged"
        )

        # 4. Subsystem 3.2 — JWT Inspector
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sample_jwt = jwt.encode(
                {"sub": "alice", "role": "user"},
                LAB_JWT_SECRET,
                algorithm="HS256",
            )
        jwt_out = SAMPLE_OUT / "jwt_report.json"
        _run_cli(
            "jwt_inspector.py",
            [
                "--token",
                sample_jwt,
                "--endpoint",
                f"{base_url}/api/jwt-protected",
                "--tamper-claims",
                '{"role": "admin"}',
                "--wordlist",
                str(ROOT_DIR / "examples" / "sample_wordlist.txt"),
                "--output",
                str(jwt_out),
            ],
        )
        jwt_data = json.loads(jwt_out.read_text(encoding="utf-8"))
        assert jwt_data["decoded"]["payload"]["sub"] == "alice"
        assert jwt_data["alg_none_test"]["vulnerable"] is True
        assert jwt_data["secret_guessing"]["cracked"] is True
        assert jwt_data["secret_guessing"]["secret"] == LAB_JWT_SECRET
        print("[5/6] JWT Inspector verified: alg=none bypass & wordlist secret confirmed")

        # 5. Subsystem 3.3 — XSS Verifier (Reflected dialog XSS + Stored DOM XSS + Safe negative test)
        xss_refl_out = SAMPLE_OUT / "xss_reflected_report.json"
        shots_dir = SAMPLE_OUT / "screenshots"
        _run_cli(
            "xss_verifier.py",
            [
                "--url",
                f"{base_url}/search",
                "--selector",
                "#search-box",
                "--payload",
                "<script>alert('VulnStrike-Reflected')</script>",
                "--screenshot-dir",
                str(shots_dir),
                "--output",
                str(xss_refl_out),
            ],
        )
        refl_data = json.loads(xss_refl_out.read_text(encoding="utf-8"))
        assert refl_data["summary"]["confirmed_count"] == 1
        assert "dialog_event" in refl_data["findings"][0]["detection_methods"]
        assert Path(refl_data["findings"][0]["screenshot"]).is_file()

        # Stored DOM XSS test (/feedback -> /comments)
        xss_stored_out = SAMPLE_OUT / "xss_report.json"
        _run_cli(
            "xss_verifier.py",
            [
                "--url",
                f"{base_url}/feedback",
                "--verify-url",
                f"{base_url}/comments",
                "--selector",
                "#comment-input",
                "--submit-selector",
                "#submit-comment",
                "--extra-field",
                "#author-input=Auditor",
                "--payload",
                '<img src="x" onerror="alert(\'StoredXSS\')">',
                "--payload",
                '<svg id="xss-canary" data-xss="1"></svg>',
                "--screenshot-dir",
                str(shots_dir),
                "--output",
                str(xss_stored_out),
            ],
        )
        stored_data = json.loads(xss_stored_out.read_text(encoding="utf-8"))
        assert stored_data["summary"]["confirmed_count"] == 2
        for finding in stored_data["findings"]:
            assert finding["confirmed"] is True
            assert Path(finding["screenshot"]).is_file()

        # Negative test on escaped input (/safe-search) -> must NOT confirm XSS
        xss_safe_out = SAMPLE_OUT / "xss_safe_negative.json"
        _run_cli(
            "xss_verifier.py",
            [
                "--url",
                f"{base_url}/safe-search",
                "--selector",
                "#safe-box",
                "--payload",
                "<script>alert('SafeCheck')</script>",
                "--screenshot-dir",
                str(shots_dir),
                "--output",
                str(xss_safe_out),
            ],
        )
        safe_data = json.loads(xss_safe_out.read_text(encoding="utf-8"))
        assert safe_data["summary"]["confirmed_count"] == 0, (
            "HTML-escaped output must NOT trigger false-positive XSS confirmation"
        )
        xss_safe_out.unlink(missing_ok=True)

        # Merge all subsystem outputs via reference orchestrator script
        merged_path = SAMPLE_OUT / "merged_vulnstrike_report.json"
        merge_subsystem_outputs(SAMPLE_OUT, merged_path)
        assert merged_path.is_file()
        print("[6/6] XSS Verifier (Reflected + Stored + Negative check) & Orchestrator Merge verified!")
        return 0
    finally:
        nvd_server.shutdown()
        server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
