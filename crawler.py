#!/usr/bin/env python3
"""VulnStrike AI — Subsystem 1: Playwright Web Crawler.

Crawls an authorized lab web application starting from a base URL up to a
configurable link depth. Designed for hybrid server-rendered + JavaScript API
applications:
  - Discovers and follows internal links up to ``max_depth``
  - Extracts all ``<form>`` elements (resolved action URL, HTTP method, and
    every input/select/textarea/button field's ``name``, ``type``, and ``id``)
  - Captures all session cookies stored in the browser context
  - Listens to ``page.on("request")`` to log JavaScript XHR/fetch API calls
  - Handles timeouts, HTTP errors, and broken links without aborting the crawl

Outputs structured JSON:
    {
      "pages": [
        {
          "url": "...",
          "status_code": 200,
          "depth": 0,
          "forms": [...],
          "cookies": [...],
          "api_calls": [...],
          "error": null
        }
      ]
    }
"""

from __future__ import annotations

import argparse
from collections import deque
import json
import logging
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse

from playwright.sync_api import (
    BrowserContext,
    Error as PlaywrightError,
    Page,
    Request,
    TimeoutError as PlaywrightTimeoutError,
    sync_playwright,
)

LOGGER = logging.getLogger("vulnstrike.crawler")

SKIPPED_SCHEMES: frozenset[str] = frozenset(
    {"mailto", "tel", "javascript", "data", "blob", "about"}
)

STATIC_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".bmp",
        ".css",
        ".js",
        ".mjs",
        ".map",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".mp3",
        ".mp4",
        ".webm",
        ".avi",
    }
)


def normalize_url(raw_url: str, base_url: str) -> str | None:
    """Resolve and normalize a candidate URL relative to ``base_url``.

    Strips URL fragments, normalizes scheme/host casing, and filters out
    non-HTTP schemes (``javascript:``, ``mailto:``, etc.).

    Args:
        raw_url: Raw ``href`` or target URL string.
        base_url: Current page URL used to resolve relative links.

    Returns:
        Normalized absolute HTTP(S) URL string, or ``None`` if non-navigable.
    """
    cleaned = raw_url.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    scheme_prefix = cleaned.split(":", 1)[0].lower() if ":" in cleaned else ""
    if scheme_prefix in SKIPPED_SCHEMES:
        return None

    resolved = urljoin(base_url, cleaned)
    defragged, _ = urldefrag(resolved)
    parsed = urlparse(defragged)

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None

    normalized_path = parsed.path or "/"
    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            normalized_path,
            parsed.params,
            parsed.query,
            "",
        )
    )


def is_internal_crawlable_url(
    url: str,
    base_netloc: str,
    *,
    allow_logout_paths: bool = False,
) -> bool:
    """Check whether ``url`` belongs to the target host and is an HTML route.

    Args:
        url: Normalized absolute URL.
        base_netloc: ``host[:port]`` of the starting target URL.
        allow_logout_paths: If ``False``, skips ``/logout`` and ``/signout``
            links so authenticated sessions are preserved during crawling.

    Returns:
        ``True`` if the URL should be queued for crawling.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if parsed.netloc.lower() != base_netloc.lower():
        return False

    lower_path = parsed.path.lower()
    if any(lower_path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return False

    if not allow_logout_paths and any(
        seg in lower_path for seg in ("/logout", "/signout", "/sign-out")
    ):
        return False

    return True


def is_api_request(request: Request) -> bool:
    """Determine if a Playwright network request represents a JS API/XHR call.

    Matches ``xhr`` and ``fetch`` resource types directly, plus ``/api/`` or
    ``/graphql`` calls triggered dynamically by scripts without full document
    navigation.

    Args:
        request: Playwright ``Request`` object intercepted via ``page.on("request")``.

    Returns:
        ``True`` if the request should be logged in ``api_calls``.
    """
    if request.resource_type in {"xhr", "fetch"}:
        return True

    if request.resource_type in {"document", "stylesheet", "image", "font", "media"}:
        return False

    parsed_path = urlparse(request.url).path.lower()
    if "/api/" in parsed_path or parsed_path.endswith("/graphql"):
        return True

    accept_header = (request.headers.get("accept") or "").lower()
    return "application/json" in accept_header and request.resource_type != "script"


def extract_forms(page: Page, page_url: str) -> list[dict[str, Any]]:
    """Extract all ``<form>`` elements and their input controls from a live DOM.

    Args:
        page: Active Playwright ``Page`` after navigation.
        page_url: Final URL of the loaded page used to resolve relative actions.

    Returns:
        List of form dictionaries containing ``action``, ``method``, and ``inputs``.
    """
    raw_forms: list[dict[str, Any]] = page.evaluate(
        """() => {
            return Array.from(document.querySelectorAll("form")).map((form) => {
                const rawAction = form.getAttribute("action") || "";
                const rawMethod = (form.getAttribute("method") || "GET").trim().toUpperCase();
                const controls = Array.from(
                    form.querySelectorAll("input, textarea, select, button")
                );
                const inputs = controls.map((el) => {
                    const tag = el.tagName.toLowerCase();
                    let fieldType = el.getAttribute("type");
                    if (!fieldType) {
                        if (tag === "textarea") fieldType = "textarea";
                        else if (tag === "select") fieldType = "select";
                        else if (tag === "button") fieldType = "submit";
                        else fieldType = "text";
                    }
                    return {
                        name: el.getAttribute("name"),
                        type: fieldType.toLowerCase(),
                        id: el.getAttribute("id"),
                    };
                });
                return {
                    raw_action: rawAction,
                    method: rawMethod || "GET",
                    inputs: inputs,
                };
            });
        }"""
    )

    extracted: list[dict[str, Any]] = []
    for form in raw_forms:
        action_url = urljoin(page_url, form["raw_action"])
        extracted.append(
            {
                "action": action_url,
                "method": form["method"],
                "inputs": form["inputs"],
            }
        )
    return extracted


def extract_internal_links(
    page: Page,
    page_url: str,
    base_netloc: str,
    *,
    allow_logout_paths: bool = False,
) -> list[str]:
    """Extract deduplicated internal crawlable ``<a href>`` links from ``page``.

    Args:
        page: Active Playwright ``Page``.
        page_url: Current page URL for relative resolution.
        base_netloc: Target host ``netloc`` to restrict crawl to internal routes.
        allow_logout_paths: Whether to permit ``/logout`` URLs.

    Returns:
        Ordered list of unique normalized internal URLs.
    """
    hrefs: list[str] = page.evaluate(
        """() => Array.from(document.querySelectorAll("a[href]"))
            .map((a) => a.getAttribute("href") || "")"""
    )

    discovered: list[str] = []
    seen: set[str] = set()
    for raw_href in hrefs:
        normalized = normalize_url(raw_href, page_url)
        if not normalized or normalized in seen:
            continue
        if is_internal_crawlable_url(
            normalized, base_netloc, allow_logout_paths=allow_logout_paths
        ):
            seen.add(normalized)
            discovered.append(normalized)
    return discovered


def format_cookies(raw_cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize Playwright browser context cookies for JSON serialization.

    Args:
        raw_cookies: Cookie dictionaries returned by ``context.cookies()``.

    Returns:
        List of structured cookie metadata dictionaries.
    """
    return [
        {
            "name": cookie.get("name", ""),
            "value": cookie.get("value", ""),
            "domain": cookie.get("domain", ""),
            "path": cookie.get("path", "/"),
            "httpOnly": bool(cookie.get("httpOnly", False)),
            "secure": bool(cookie.get("secure", False)),
            "sameSite": cookie.get("sameSite", ""),
            "expires": cookie.get("expires", -1),
        }
        for cookie in raw_cookies
    ]


def crawl_single_page(
    context: BrowserContext,
    url: str,
    depth: int,
    base_netloc: str,
    *,
    timeout_ms: int = 10000,
    settle_ms: int = 600,
    allow_logout_paths: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Visit one page, record forms/cookies/API calls, and discover child links.

    Handles timeouts, broken links, non-HTML responses, and unexpected browser
    errors without raising exceptions to the caller.

    Args:
        context: Shared Playwright ``BrowserContext`` holding session state.
        url: Target URL to visit.
        depth: Current BFS crawl depth.
        base_netloc: Target host ``netloc`` for internal link filtering.
        timeout_ms: Navigation timeout in milliseconds.
        settle_ms: Post-load wait in milliseconds so hybrid JS ``fetch`` calls fire.
        allow_logout_paths: Whether to queue logout links.

    Returns:
        Tuple of ``(page_record_dict, discovered_internal_urls)``.
    """
    api_calls: list[dict[str, Any]] = []
    seen_api_keys: set[tuple[str, str]] = set()
    forms: list[dict[str, Any]] = []
    child_links: list[str] = []
    status_code: int | None = None
    error_message: str | None = None
    final_url: str = url

    page = context.new_page()

    def _on_request(req: Request) -> None:
        if is_api_request(req):
            key = (req.method.upper(), req.url)
            if key not in seen_api_keys:
                seen_api_keys.add(key)
                entry: dict[str, Any] = {
                    "method": req.method.upper(),
                    "url": req.url,
                    "resource_type": req.resource_type,
                }
                if req.post_data:
                    entry["post_data"] = req.post_data
                api_calls.append(entry)

    page.on("request", _on_request)
    page.on("dialog", lambda dialog: dialog.dismiss())

    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        if response is not None:
            status_code = response.status
        final_url = normalize_url(page.url, url) or page.url

        # Wait briefly for hybrid page JS fetch/XHR requests without failing on SSE/polling
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 3000))
        except PlaywrightTimeoutError:
            LOGGER.debug("Network remained active on %s; continuing after settle.", url)

        if settle_ms > 0:
            page.wait_for_timeout(settle_ms)

        content_type = (
            (response.headers.get("content-type") or "").lower()
            if response is not None
            else "text/html"
        )
        if "html" in content_type or content_type == "":
            forms = extract_forms(page, final_url)
            if is_internal_crawlable_url(
                final_url, base_netloc, allow_logout_paths=allow_logout_paths
            ):
                child_links = extract_internal_links(
                    page,
                    final_url,
                    base_netloc,
                    allow_logout_paths=allow_logout_paths,
                )

    except PlaywrightTimeoutError as exc:
        error_message = f"Timeout after {timeout_ms}ms: {exc}"
        LOGGER.warning("Timeout visiting %s: %s", url, exc)
    except PlaywrightError as exc:
        error_message = f"Browser navigation error: {exc}"
        LOGGER.warning("Navigation error visiting %s: %s", url, exc)
    except Exception as exc:  # noqa: BLE001 - isolate unexpected page-level errors
        error_message = f"Unexpected error: {exc}"
        LOGGER.warning("Unexpected error visiting %s: %s", url, exc)
    finally:
        try:
            cookies = format_cookies(context.cookies())
        except PlaywrightError:
            cookies = []
        try:
            page.close()
        except PlaywrightError:
            pass

    page_record: dict[str, Any] = {
        "url": final_url,
        "status_code": status_code,
        "depth": depth,
        "forms": forms,
        "cookies": cookies,
        "api_calls": api_calls,
        "error": error_message,
    }
    return page_record, child_links


def crawl_application(
    base_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 50,
    timeout_ms: int = 10000,
    settle_ms: int = 600,
    headless: bool = True,
    auth_token: str | None = None,
    initial_cookies: list[dict[str, Any]] | None = None,
    extra_headers: dict[str, str] | None = None,
    allow_logout_paths: bool = False,
) -> dict[str, Any]:
    """Perform a breadth-first crawl of ``base_url`` up to ``max_depth``.

    Args:
        base_url: Starting URL of the authorized lab web application.
        max_depth: Maximum link hop depth from ``base_url`` (0 = base URL only).
        max_pages: Safety limit on total pages visited.
        timeout_ms: Per-page navigation timeout in milliseconds.
        settle_ms: Post-load JS settle delay in milliseconds.
        headless: Run Chromium headless when ``True``.
        auth_token: Optional Bearer JWT injected via ``Authorization`` header
            and ``localStorage`` for authenticated hybrid crawling.
        initial_cookies: Optional list of Playwright cookie dicts to pre-seed.
        extra_headers: Optional custom HTTP headers sent with browser requests.
        allow_logout_paths: Whether to visit ``/logout`` routes.

    Returns:
        Dictionary matching ``{"pages": [...]}``.
    """
    start_url = normalize_url(base_url, base_url)
    if not start_url:
        raise ValueError(f"Invalid base_url provided: {base_url!r}")

    base_netloc = urlparse(start_url).netloc
    headers: dict[str, str] = dict(extra_headers or {})
    if auth_token:
        headers.setdefault("Authorization", f"Bearer {auth_token}")

    pages_output: list[dict[str, Any]] = []
    visited: set[str] = {start_url}
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        context = browser.new_context(
            extra_http_headers=headers if headers else None,
            ignore_https_errors=True,
        )

        if initial_cookies:
            context.add_cookies(initial_cookies)

        if auth_token:
            token_json = json.dumps(auth_token)
            context.add_init_script(
                f"""() => {{
                    try {{
                        window.localStorage.setItem("token", {token_json});
                        window.localStorage.setItem("jwt", {token_json});
                    }} catch (e) {{}}
                }}"""
            )

        try:
            while queue and len(pages_output) < max_pages:
                current_url, current_depth = queue.popleft()
                LOGGER.info(
                    "Crawling [depth=%d/%d] %s",
                    current_depth,
                    max_depth,
                    current_url,
                )

                page_record, child_links = crawl_single_page(
                    context,
                    current_url,
                    current_depth,
                    base_netloc,
                    timeout_ms=timeout_ms,
                    settle_ms=settle_ms,
                    allow_logout_paths=allow_logout_paths,
                )
                pages_output.append(page_record)

                # Also mark redirected destination as visited to avoid duplicate crawls
                visited.add(page_record["url"])

                if current_depth < max_depth:
                    for link in child_links:
                        if link not in visited:
                            visited.add(link)
                            queue.append((link, current_depth + 1))
        finally:
            context.close()
            browser.close()

    return {"pages": pages_output}


def parse_cookie_args(
    cookie_args: list[str] | None,
    base_url: str,
) -> list[dict[str, Any]]:
    """Convert ``NAME=VALUE`` CLI strings into Playwright cookie dictionaries.

    Args:
        cookie_args: List of ``name=value`` strings passed via ``--cookie``.
        base_url: Target base URL used to associate cookie scope.

    Returns:
        List of Playwright-compatible cookie dicts.
    """
    if not cookie_args:
        return []
    cookies: list[dict[str, Any]] = []
    for raw in cookie_args:
        if "=" not in raw:
            raise ValueError(f"Invalid --cookie format {raw!r}; expected NAME=VALUE")
        name, value = raw.split("=", 1)
        cookies.append({"name": name.strip(), "value": value.strip(), "url": base_url})
    return cookies


def save_json_output(data: dict[str, Any], output_path: Path) -> None:
    """Write crawl results to ``output_path`` as UTF-8 formatted JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for standalone orchestrator execution."""
    parser = argparse.ArgumentParser(
        description="VulnStrike AI — Subsystem 1: Playwright Web Crawler",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Base URL of the lab web app to crawl (e.g., http://localhost:8080)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum internal link crawl depth (default: 2)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Maximum number of pages to visit (default: 50)",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=10000,
        help="Navigation timeout per page in milliseconds (default: 10000)",
    )
    parser.add_argument(
        "--settle-ms",
        type=int,
        default=600,
        help="Post-load settle delay for hybrid JS API calls in ms (default: 600)",
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
        "--headed",
        action="store_true",
        help="Run Chromium in headed mode for visual debugging",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/crawl_report.json"),
        help="Output JSON file path (default: output/crawl_report.json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for standalone execution."""
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    try:
        cookies = parse_cookie_args(args.cookie, args.url)
        report = crawl_application(
            args.url,
            max_depth=max(0, args.max_depth),
            max_pages=max(1, args.max_pages),
            timeout_ms=args.timeout_ms,
            settle_ms=args.settle_ms,
            headless=not args.headed,
            auth_token=args.auth_token,
            initial_cookies=cookies,
        )
        save_json_output(report, args.output)
        LOGGER.info(
            "Crawl complete: %d page(s) saved to %s",
            len(report["pages"]),
            args.output,
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("Crawler failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
