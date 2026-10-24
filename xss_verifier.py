#!/usr/bin/env python3
"""VulnStrike AI — Subsystem 3.3: Playwright XSS Verification Helper.

Given an authorized target URL, a list of input CSS selectors, and candidate XSS
payloads, automates browser-based payload injection and execution confirmation:
  - Injects each payload into each target input selector and submits the form
  - Supports optional hybrid login (HTML form cookies + Web Storage Bearer JWTs)
  - Supports both same-page (Reflected / DOM XSS) and separate post-submit
    display routes (``--verify-url`` for Stored XSS)
  - Confirms execution via:
      1. Browser ``dialog`` events (``alert``, ``confirm``, ``prompt``)
      2. Live ``MutationObserver`` tracking unescaped dangerous elements/inline
         event attributes added dynamically via JS ``innerHTML``/``fetch``
      3. Pre/post DOM element diffing for server-rendered Stored XSS payloads
  - Captures a PNG proof screenshot whenever execution/DOM injection is confirmed
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urljoin

from playwright.sync_api import (
    BrowserContext,
    Dialog,
    Error as PlaywrightError,
    Page,
    TimeoutError as PlaywrightTimeoutError,
    sync_playwright,
)

LOGGER = logging.getLogger("vulnstrike.xss_verifier")

MUTATION_OBSERVER_INIT_SCRIPT = """
(() => {
    window.__vulnstrikeMutations = [];
    const DANGEROUS_TAGS = new Set([
        "SCRIPT", "IFRAME", "SVG", "OBJECT", "EMBED", "MATH", "DETAILS"
    ]);

    function summarizeElement(el, reason) {
        return {
            tag: el.tagName ? el.tagName.toLowerCase() : "unknown",
            id: el.id || null,
            reason: reason,
            outer_html: (el.outerHTML || "").slice(0, 300)
        };
    }

    function inspectElementTree(root) {
        if (!root || root.nodeType !== 1) return;
        if (root.hasAttribute && root.hasAttribute("data-vulnstrike-audit")) return;

        const candidates = [root, ...Array.from(root.querySelectorAll ? root.querySelectorAll("*") : [])];
        for (const el of candidates) {
            if (!el.tagName || (el.hasAttribute && el.hasAttribute("data-vulnstrike-audit"))) continue;
            const tag = el.tagName.toUpperCase();

            // Inline event handler attributes (onerror, onload, onclick, etc.)
            const inlineHandlers = [];
            for (const attr of Array.from(el.attributes || [])) {
                const name = attr.name.toLowerCase();
                const val = (attr.value || "").trim().toLowerCase();
                if (name.startsWith("on") && attr.value) {
                    inlineHandlers.push(`${attr.name}=${attr.value}`);
                } else if ((name === "href" || name === "src" || name === "action") && val.startsWith("javascript:")) {
                    inlineHandlers.push(`${attr.name}=${attr.value}`);
                }
            }

            if (inlineHandlers.length > 0) {
                window.__vulnstrikeMutations.push(
                    summarizeElement(el, `inline_js_attribute:${inlineHandlers.join(",")}`)
                );
            } else if (DANGEROUS_TAGS.has(tag)) {
                window.__vulnstrikeMutations.push(
                    summarizeElement(el, `dangerous_element:${tag.toLowerCase()}`)
                );
            } else if (el.hasAttribute("data-xss") || el.id === "xss-canary") {
                window.__vulnstrikeMutations.push(
                    summarizeElement(el, "canary_marker_element")
                );
            }
        }
    }

    const attachObserver = () => {
        const target = document.documentElement || document;
        if (!target || window.__vulnstrikeObserverAttached) return;
        window.__vulnstrikeObserverAttached = true;

        const observer = new MutationObserver((records) => {
            for (const rec of records) {
                if (rec.type === "childList") {
                    for (const node of Array.from(rec.addedNodes || [])) {
                        inspectElementTree(node);
                    }
                } else if (rec.type === "attributes" && rec.target && rec.target.nodeType === 1) {
                    const attrName = (rec.attributeName || "").toLowerCase();
                    if (attrName.startsWith("on") || attrName === "src" || attrName === "href") {
                        inspectElementTree(rec.target);
                    }
                }
            }
        });

        observer.observe(target, {
            childList: true,
            subtree: true,
            attributes: true
        });
    };

    if (document.documentElement) {
        attachObserver();
    } else {
        document.addEventListener("DOMContentLoaded", attachObserver, { once: true });
    }
})();
"""

SNAPSHOT_DANGEROUS_DOM_JS = """
(customSelector) => {
    const results = [];
    const selectorParts = [
        "script:not([src])",
        "svg",
        "iframe",
        "object",
        "embed",
        "[onerror]",
        "[onload]",
        "[onclick]",
        "[onmouseover]",
        "[onfocus]",
        "[ontoggle]",
        "[data-xss]",
        "#xss-canary",
        "a[href^='javascript:']"
    ];
    if (customSelector) {
        selectorParts.push(customSelector);
    }
    const combined = selectorParts.join(", ");
    let elements = [];
    try {
        elements = Array.from(document.querySelectorAll(combined));
    } catch (e) {
        elements = [];
    }
    for (const el of elements) {
        if (el.hasAttribute && el.hasAttribute("data-vulnstrike-audit")) continue;
        results.push((el.outerHTML || "").trim().slice(0, 300));
    }
    return results;
}
"""


def sanitize_filename_token(raw: str) -> str:
    """Create a filesystem-safe slug from a CSS selector or label."""
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", raw).strip("_")
    return (slug[:40] or "input").lower()


def perform_optional_login(
    context: BrowserContext,
    base_url: str,
    login_cfg: dict[str, Any],
    *,
    timeout_ms: int = 10000,
) -> str | None:
    """Log into the lab application before testing authenticated XSS forms.

    Supports both session-cookie form logins and hybrid Bearer JWT capture.

    Args:
        context: Playwright ``BrowserContext`` used for XSS verification.
        base_url: Application base URL.
        login_cfg: Dictionary with ``login_path``, ``username``, ``password``,
            and optional field selectors.
        timeout_ms: Navigation timeout in milliseconds.

    Returns:
        Captured Bearer JWT string if present in Web Storage, else ``None``.
    """
    login_url = urljoin(
        base_url.rstrip("/") + "/",
        str(login_cfg.get("login_path", "/login")).lstrip("/"),
    )
    user_sel = login_cfg.get(
        "username_selector",
        'input[name="username"], input[name="email"], #username, #email, input[type="text"]',
    )
    pass_sel = login_cfg.get(
        "password_selector",
        'input[name="password"], #password, input[type="password"]',
    )
    sub_sel = login_cfg.get(
        "submit_selector",
        'button[type="submit"], input[type="submit"], button:not([type="button"])',
    )

    page = context.new_page()
    page.on("dialog", lambda d: d.dismiss())
    token: str | None = None
    try:
        page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
        page.locator(user_sel).first.fill(str(login_cfg["username"]), timeout=timeout_ms)
        page.locator(pass_sel).first.fill(str(login_cfg["password"]), timeout=timeout_ms)
        submit = page.locator(sub_sel).first
        if submit.count() > 0:
            submit.click(timeout=timeout_ms)
        else:
            page.locator(pass_sel).first.press("Enter")

        try:
            page.wait_for_load_state("networkidle", timeout=3000)
        except PlaywrightTimeoutError:
            pass
        page.wait_for_timeout(400)

        token = page.evaluate(
            """() => {
                for (const s of [window.localStorage, window.sessionStorage]) {
                    if (!s) continue;
                    for (const k of ["token", "access_token", "jwt", "authToken"]) {
                        const v = s.getItem(k);
                        if (v) return v;
                    }
                }
                return null;
            }"""
        )
    finally:
        page.close()

    return token


def collect_page_baseline(
    context: BrowserContext,
    url: str,
    *,
    mutation_selector: str | None = None,
    timeout_ms: int = 10000,
    settle_ms: int = 500,
) -> tuple[set[str], dict[tuple[str, str], int]]:
    """Capture pre-injection dangerous DOM elements and dialog counts on ``url``.

    Tracking both pre-existing DOM elements and pre-existing stored ``alert()``
    counts prevents persistent Stored XSS payloads from polluting subsequent
    payload test cases while still detecting duplicate ``alert(1)`` messages.
    """
    dialog_counts: dict[tuple[str, str], int] = {}
    page = context.new_page()

    def _on_baseline_dialog(dialog: Dialog) -> None:
        key = (dialog.type, dialog.message)
        dialog_counts[key] = dialog_counts.get(key, 0) + 1
        try:
            dialog.dismiss()
        except PlaywrightError:
            pass

    page.on("dialog", _on_baseline_dialog)
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 2500))
        except PlaywrightTimeoutError:
            pass
        if settle_ms > 0:
            page.wait_for_timeout(settle_ms)
        items: list[str] = page.evaluate(SNAPSHOT_DANGEROUS_DOM_JS, mutation_selector)
        return set(items), dialog_counts
    except PlaywrightError:
        return set(), dialog_counts
    finally:
        page.close()


def _payload_matches_element(payload: str, element_outer_html: str) -> bool:
    """Verify whether a newly appeared unescaped HTML element derives from ``payload``."""
    lower_html = element_outer_html.lower()
    lower_payload = payload.lower().strip()

    # Check distinctive tokens from payload (event handlers, ids, src/tag signatures)
    tokens = re.findall(r"[a-z0-9_-]{3,}", lower_payload)
    significant = [t for t in tokens if t not in {"script", "img", "svg", "div", "src"}]
    if not significant:
        return any(tag in lower_html for tag in ("<script", "<svg", "<img", "<iframe"))
    return any(tok in lower_html for tok in significant)


def _render_dialog_audit_banner(page: Page, dialogs: list[dict[str, str]]) -> None:
    """Render a non-intrusive visual proof banner when modal JS dialogs occurred.

    Headless Chromium dismisses native ``alert()`` dialogs before screenshots can
    complete; adding a marked audit overlay makes the confirmed dialog message
    clearly visible in the saved proof PNG.
    """
    if not dialogs:
        return
    summary = " | ".join(f"{d['type']}({d['message']!r})" for d in dialogs)
    page.evaluate(
        """(text) => {
            if (!document.body) return;
            const banner = document.createElement("div");
            banner.setAttribute("data-vulnstrike-audit", "true");
            banner.style.cssText = [
                "position:fixed",
                "top:10px",
                "right:10px",
                "z-index:2147483647",
                "background:#b91c1c",
                "color:#ffffff",
                "font-family:monospace",
                "font-size:13px",
                "font-weight:bold",
                "padding:8px 14px",
                "border-radius:6px",
                "box-shadow:0 4px 12px rgba(0,0,0,0.35)"
            ].join(";");
            banner.textContent = "VulnStrike XSS Dialog Confirmed: " + text;
            document.body.appendChild(banner);
        }""",
        summary,
    )


def test_single_xss_case(
    context: BrowserContext,
    *,
    case_index: int,
    target_url: str,
    input_selector: str,
    payload: str,
    submit_selector: str | None = None,
    verify_url: str | None = None,
    extra_fields: dict[str, str] | None = None,
    mutation_selector: str | None = None,
    baseline_elements: set[str] | None = None,
    baseline_dialog_counts: dict[tuple[str, str], int] | None = None,
    screenshot_dir: Path = Path("output/screenshots"),
    timeout_ms: int = 10000,
    settle_ms: int = 700,
) -> dict[str, Any]:
    """Inject one ``payload`` into ``input_selector`` and verify XSS execution.

    Args:
        context: Active Playwright ``BrowserContext`` (with ``MutationObserver`` init script).
        case_index: Numeric index used for deterministic screenshot naming.
        target_url: Page URL hosting the target input/form.
        input_selector: CSS selector of the input/textarea to test.
        payload: Candidate XSS payload string.
        submit_selector: Optional explicit CSS selector for submit trigger.
        verify_url: Optional secondary page URL visited after submit to verify
            Stored XSS rendering/execution.
        extra_fields: Optional companion form selector->value pairs (e.g. required fields).
        mutation_selector: Optional custom CSS selector indicating DOM injection.
        baseline_elements: Pre-existing dangerous ``outerHTML`` strings on the
            verification page so pre-existing elements are ignored.
        screenshot_dir: Directory where proof-of-execution PNGs are written.
        timeout_ms: Navigation/locator timeout in milliseconds.
        settle_ms: Post-action wait in milliseconds for async JS mutations.

    Returns:
        Dictionary describing execution confirmation, trigger mechanisms,
        captured dialogs/mutations, and proof ``screenshot_path``.
    """
    dialogs_captured: list[dict[str, str]] = []
    mutation_events: list[dict[str, Any]] = []
    screenshot_path_str: str | None = None
    error_msg: str | None = None

    page = context.new_page()

    def _on_dialog(dialog: Dialog) -> None:
        dialogs_captured.append(
            {"type": dialog.type, "message": dialog.message}
        )
        try:
            dialog.dismiss()
        except PlaywrightError:
            pass

    page.on("dialog", _on_dialog)

    try:
        page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 2500))
        except PlaywrightTimeoutError:
            pass

        # Clear any page-boot mutations before injecting our payload
        page.evaluate("() => { window.__vulnstrikeMutations = []; }")

        # Populate companion required fields if configured
        for field_sel, field_val in (extra_fields or {}).items():
            loc = page.locator(field_sel).first
            if loc.count() > 0:
                loc.fill(field_val, timeout=timeout_ms)

        target_input = page.locator(input_selector).first
        target_input.wait_for(state="visible", timeout=timeout_ms)
        target_input.fill(payload, timeout=timeout_ms)

        # Submit form via explicit selector, enclosing form button, or Enter key
        if submit_selector:
            page.locator(submit_selector).first.click(timeout=timeout_ms)
        else:
            enclosing_form = target_input.locator("xpath=ancestor::form[1]")
            form_btn = enclosing_form.locator(
                'button[type="submit"], button:not([type]), input[type="submit"]'
            ).first
            if enclosing_form.count() > 0 and form_btn.count() > 0:
                form_btn.click(timeout=timeout_ms)
            else:
                fallback_btn = page.locator(
                    'button[type="submit"], input[type="submit"]'
                ).first
                if fallback_btn.count() > 0:
                    fallback_btn.click(timeout=timeout_ms)
                else:
                    target_input.press("Enter")

        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 3000))
        except PlaywrightTimeoutError:
            pass
        if settle_ms > 0:
            page.wait_for_timeout(settle_ms)

        # Collect live MutationObserver records on submission response page
        live_muts: list[dict[str, Any]] = page.evaluate(
            "() => window.__vulnstrikeMutations || []"
        )
        mutation_events.extend(live_muts)

        # Navigate to optional separate view URL for Stored XSS verification
        if verify_url:
            page.goto(verify_url, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 3000))
            except PlaywrightTimeoutError:
                pass
            if settle_ms > 0:
                page.wait_for_timeout(settle_ms)

            verify_muts: list[dict[str, Any]] = page.evaluate(
                "() => window.__vulnstrikeMutations || []"
            )
            mutation_events.extend(verify_muts)

        # Inspect rendered DOM for newly injected unescaped dangerous/canary elements
        current_dom_elements: list[str] = page.evaluate(
            SNAPSHOT_DANGEROUS_DOM_JS, mutation_selector
        )
        known_baseline = baseline_elements or set()
        for html_snip in current_dom_elements:
            if html_snip not in known_baseline and _payload_matches_element(
                payload, html_snip
            ):
                already_logged = any(
                    m.get("outer_html") == html_snip for m in mutation_events
                )
                if not already_logged:
                    mutation_events.append(
                        {
                            "tag": "dom_diff",
                            "id": None,
                            "reason": "unescaped_stored_or_reflected_element",
                            "outer_html": html_snip,
                        }
                    )

        # Filter mutations to those plausibly caused by our payload or custom selector
        relevant_mutations = [
            m
            for m in mutation_events
            if _payload_matches_element(payload, str(m.get("outer_html", "")))
            or m.get("reason") == "canary_marker_element"
        ]

        # Subtract pre-existing persistent stored dialogs from baseline
        remaining_baseline = dict(baseline_dialog_counts or {})
        new_dialogs: list[dict[str, str]] = []
        for dlg in dialogs_captured:
            d_key = (dlg["type"], dlg["message"])
            if remaining_baseline.get(d_key, 0) > 0:
                remaining_baseline[d_key] -= 1
            else:
                new_dialogs.append(dlg)

        confirmed = bool(new_dialogs or relevant_mutations)
        triggers: list[str] = []
        if new_dialogs:
            triggers.append("dialog_event")
        if relevant_mutations:
            triggers.append("dom_mutation")

        if confirmed:
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            sel_slug = sanitize_filename_token(input_selector)
            ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            shot_file = screenshot_dir / f"xss_{case_index:03d}_{sel_slug}_{ts}.png"
            if new_dialogs:
                _render_dialog_audit_banner(page, new_dialogs)
            page.screenshot(path=str(shot_file), full_page=True)
            screenshot_path_str = str(shot_file)
            LOGGER.info(
                "Confirmed XSS on %s (triggers=%s) -> screenshot %s",
                input_selector,
                triggers,
                screenshot_path_str,
            )

        return {
            "target_url": target_url,
            "verify_url": verify_url,
            "final_url": page.url,
            "input_selector": input_selector,
            "payload": payload,
            "confirmed": confirmed,
            "detection_methods": triggers,
            "dialogs": new_dialogs,
            "dom_mutations": relevant_mutations,
            "screenshot": screenshot_path_str,
            "error": None,
        }

    except (PlaywrightTimeoutError, PlaywrightError) as exc:
        error_msg = str(exc)
        LOGGER.warning(
            "Error testing selector %s with payload %r: %s",
            input_selector,
            payload,
            exc,
        )
        return {
            "target_url": target_url,
            "verify_url": verify_url,
            "final_url": page.url,
            "input_selector": input_selector,
            "payload": payload,
            "confirmed": False,
            "detection_methods": [],
            "dialogs": dialogs_captured,
            "dom_mutations": [],
            "screenshot": None,
            "error": error_msg,
        }
    finally:
        try:
            page.close()
        except PlaywrightError:
            pass


def run_xss_verification(
    target_url: str,
    selectors: list[str],
    payloads: list[str],
    *,
    submit_selector: str | None = None,
    verify_url: str | None = None,
    extra_fields: dict[str, str] | None = None,
    mutation_selector: str | None = None,
    login_config: dict[str, Any] | None = None,
    auth_token: str | None = None,
    cookies: list[dict[str, Any]] | None = None,
    screenshot_dir: Path = Path("output/screenshots"),
    timeout_ms: int = 10000,
    settle_ms: int = 700,
    headless: bool = True,
) -> dict[str, Any]:
    """Run automated XSS verification across ``selectors`` x ``payloads``.

    Args:
        target_url: Page URL containing the input fields under test.
        selectors: List of CSS selectors for candidate inputs.
        payloads: List of XSS test payload strings.
        submit_selector: Optional submit button CSS selector.
        verify_url: Optional secondary page URL where Stored XSS payloads render.
        extra_fields: Optional dictionary of additional form fields to populate.
        mutation_selector: Optional custom CSS selector confirming DOM injection.
        login_config: Optional login configuration dict for authenticated routes.
        auth_token: Optional Bearer JWT token string.
        cookies: Optional list of pre-authenticated Playwright cookies.
        screenshot_dir: Output folder for confirmed XSS screenshots.
        timeout_ms: Per-step timeout in milliseconds.
        settle_ms: Post-submit wait in milliseconds.
        headless: Launch Chromium headless when ``True``.

    Returns:
        Structured JSON-serializable XSS verification report.
    """
    results: list[dict[str, Any]] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        extra_headers = (
            {"Authorization": f"Bearer {auth_token}"} if auth_token else None
        )
        context = browser.new_context(
            extra_http_headers=extra_headers,
            ignore_https_errors=True,
        )
        context.add_init_script(MUTATION_OBSERVER_INIT_SCRIPT)

        if cookies:
            context.add_cookies(cookies)

        if login_config:
            captured_jwt = perform_optional_login(
                context, target_url, login_config, timeout_ms=timeout_ms
            )
            effective_token = auth_token or captured_jwt
        else:
            effective_token = auth_token

        if effective_token:
            tok_json = json.dumps(effective_token)
            context.add_init_script(
                f"""() => {{
                    try {{
                        window.localStorage.setItem("token", {tok_json});
                        window.localStorage.setItem("jwt", {tok_json});
                    }} catch (e) {{}}
                }}"""
            )

        try:
            check_url = verify_url or target_url
            baseline, baseline_dialogs = collect_page_baseline(
                context,
                check_url,
                mutation_selector=mutation_selector,
                timeout_ms=timeout_ms,
                settle_ms=settle_ms,
            )

            case_idx = 0
            for selector in selectors:
                for payload in payloads:
                    case_idx += 1
                    LOGGER.info(
                        "Testing XSS case #%d: selector=%s payload=%s",
                        case_idx,
                        selector,
                        payload,
                    )
                    outcome = test_single_xss_case(
                        context,
                        case_index=case_idx,
                        target_url=target_url,
                        input_selector=selector,
                        payload=payload,
                        submit_selector=submit_selector,
                        verify_url=verify_url,
                        extra_fields=extra_fields,
                        mutation_selector=mutation_selector,
                        baseline_elements=baseline,
                        baseline_dialog_counts=baseline_dialogs,
                        screenshot_dir=screenshot_dir,
                        timeout_ms=timeout_ms,
                        settle_ms=settle_ms,
                    )
                    results.append(outcome)
                    # Update baselines with newly stored artifacts so later tests stay isolated
                    for mut in outcome["dom_mutations"]:
                        if mut.get("outer_html"):
                            baseline.add(str(mut["outer_html"]))
                    if verify_url:
                        for dlg in outcome["dialogs"]:
                            d_key = (dlg["type"], dlg["message"])
                            baseline_dialogs[d_key] = (
                                baseline_dialogs.get(d_key, 0) + 1
                            )
        finally:
            context.close()
            browser.close()

    confirmed_count = sum(1 for r in results if r["confirmed"])
    return {
        "module": "xss_verifier",
        "target_url": target_url,
        "verify_url": verify_url,
        "summary": {
            "total_cases": len(results),
            "confirmed_count": confirmed_count,
        },
        "findings": results,
    }


def parse_kv_pairs(items: list[str] | None, flag_name: str) -> dict[str, str]:
    """Parse ``KEY=VALUE`` repeatable CLI arguments into a dictionary."""
    out: dict[str, str] = {}
    for raw in items or []:
        if "=" not in raw:
            raise ValueError(f"Invalid {flag_name} {raw!r}; expected KEY=VALUE")
        k, v = raw.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def save_json_output(data: dict[str, Any], output_path: Path) -> None:
    """Write XSS verification report to ``output_path`` as formatted JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser for standalone XSS verification."""
    parser = argparse.ArgumentParser(
        description="VulnStrike AI — Subsystem 3.3: Playwright XSS Verification Helper",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional JSON config file specifying URLs, selectors, payloads, and login",
    )
    parser.add_argument("--url", help="Target page URL containing input selectors")
    parser.add_argument(
        "--selector",
        action="append",
        default=[],
        help="Input CSS selector to test, e.g., '#comment-box' (repeatable)",
    )
    parser.add_argument(
        "--payload",
        action="append",
        default=[],
        help="XSS payload string to inject (repeatable)",
    )
    parser.add_argument(
        "--payloads-file",
        type=Path,
        default=None,
        help="Optional newline-delimited file of XSS payloads",
    )
    parser.add_argument(
        "--submit-selector",
        default=None,
        help="Optional CSS selector for the form submit button",
    )
    parser.add_argument(
        "--verify-url",
        default=None,
        help="Optional secondary page URL visited after submit to verify Stored XSS",
    )
    parser.add_argument(
        "--mutation-selector",
        default=None,
        help="Optional custom CSS selector to flag injected DOM elements (e.g., '[data-xss]')",
    )
    parser.add_argument(
        "--extra-field",
        action="append",
        default=[],
        help="Populate sibling required field in SELECTOR=VALUE format (repeatable)",
    )
    parser.add_argument(
        "--cookie",
        action="append",
        default=[],
        help="Optional session cookie in NAME=VALUE format (repeatable)",
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        help="Optional Bearer JWT for authenticated hybrid routes",
    )
    parser.add_argument(
        "--screenshot-dir",
        type=Path,
        default=Path("output/screenshots"),
        help="Directory for proof-of-execution screenshots (default: output/screenshots)",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=10000,
        help="Navigation/action timeout in ms (default: 10000)",
    )
    parser.add_argument(
        "--settle-ms",
        type=int,
        default=700,
        help="Post-submit wait for async JS DOM rendering in ms (default: 700)",
    )
    parser.add_argument("--headed", action="store_true", help="Run Chromium headed")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/xss_report.json"),
        help="Output JSON report path (default: output/xss_report.json)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for standalone execution."""
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    try:
        cfg: dict[str, Any] = (
            json.loads(args.config.read_text(encoding="utf-8"))
            if args.config
            else {}
        )

        target_url = args.url or cfg.get("url")
        if not target_url:
            raise ValueError("--url (or 'url' in --config) is required")

        selectors: list[str] = list(args.selector) or list(cfg.get("selectors", []))
        if not selectors:
            raise ValueError("At least one --selector (or 'selectors' in --config) is required")

        payloads: list[str] = list(args.payload) or list(cfg.get("payloads", []))
        if args.payloads_file:
            file_lines = [
                ln.strip()
                for ln in args.payloads_file.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")
            ]
            payloads.extend(file_lines)
        if not payloads:
            raise ValueError(
                "At least one --payload, --payloads-file, or 'payloads' in --config is required"
            )

        extra_fields: dict[str, str] = dict(cfg.get("extra_fields", {}))
        extra_fields.update(parse_kv_pairs(args.extra_field, "--extra-field"))

        cookie_map = parse_kv_pairs(args.cookie, "--cookie")
        cookies = [
            {"name": k, "value": v, "url": target_url}
            for k, v in cookie_map.items()
        ]

        report = run_xss_verification(
            target_url=target_url,
            selectors=selectors,
            payloads=payloads,
            submit_selector=args.submit_selector or cfg.get("submit_selector"),
            verify_url=args.verify_url or cfg.get("verify_url"),
            extra_fields=extra_fields,
            mutation_selector=args.mutation_selector or cfg.get("mutation_selector"),
            login_config=cfg.get("login"),
            auth_token=args.auth_token or cfg.get("auth_token"),
            cookies=cookies if cookies else None,
            screenshot_dir=Path(cfg.get("screenshot_dir", args.screenshot_dir)),
            timeout_ms=int(cfg.get("timeout_ms", args.timeout_ms)),
            settle_ms=int(cfg.get("settle_ms", args.settle_ms)),
            headless=not args.headed,
        )
        save_json_output(report, args.output)
        LOGGER.info(
            "XSS verification complete: %d/%d confirmed finding(s) saved to %s",
            report["summary"]["confirmed_count"],
            report["summary"]["total_cases"],
            args.output,
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("XSS Verifier failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
