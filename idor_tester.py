#!/usr/bin/env python3
"""VulnStrike AI — Subsystem 3.1: Automated IDOR (Broken Object Level Auth) Tester.

Logs into an authorized lab web application as two distinct users (User A and
User B) using isolated Playwright ``BrowserContext`` instances. Supports hybrid
applications using HTML form session cookies, Bearer JWTs stored in Web Storage
or login responses, or both simultaneously.

Workflow:
  1. Authenticate User A and User B in separate isolated browser contexts.
  2. Expand private resource URL patterns (e.g., ``/api/orders/{id}``) across
     explicit IDs, numeric ID ranges, and/or IDs auto-discovered from User A.
  3. Fetch each resource as User A to establish an authorized owner baseline.
  4. Replay the exact resource URL using User B's session (cookies + Bearer JWT).
  5. Flag IDOR vulnerabilities where User B receives User A's private data.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import logging
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urljoin, urlparse

from playwright.sync_api import (
    APIResponse,
    BrowserContext,
    Error as PlaywrightError,
    Response,
    TimeoutError as PlaywrightTimeoutError,
    sync_playwright,
)

LOGGER = logging.getLogger("vulnstrike.idor_tester")

JWT_REGEX = re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")

COMMON_TOKEN_KEYS: tuple[str, ...] = (
    "token",
    "access_token",
    "accessToken",
    "jwt",
    "id_token",
    "auth_token",
    "authToken",
)

DENIAL_KEYWORDS: tuple[str, ...] = (
    "unauthorized",
    "forbidden",
    "access denied",
    "permission denied",
    "not authorized",
    "login required",
    "invalid token",
)

DEFAULT_USERNAME_SELECTOR = (
    'input[name="username"], input[name="email"], input[name="user"], '
    '#username, #email, input[type="email"], input[type="text"]'
)
DEFAULT_PASSWORD_SELECTOR = (
    'input[name="password"], input[name="pass"], #password, input[type="password"]'
)
DEFAULT_SUBMIT_SELECTOR = (
    'button[type="submit"], input[type="submit"], button:not([type="button"])'
)


@dataclass
class UserCredentials:
    """Login credentials and optional identity markers for one test user."""

    username: str
    password: str
    extra_markers: list[str] = field(default_factory=list)


@dataclass
class AuthenticatedSession:
    """Encapsulates an isolated Playwright context and captured auth artifacts."""

    label: str
    credentials: UserCredentials
    context: BrowserContext
    bearer_token: str | None = None
    cookies: list[dict[str, Any]] = field(default_factory=list)

    def build_api_headers(self, base_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Construct HTTP headers for ``context.request`` including Bearer JWT."""
        headers: dict[str, str] = {"Accept": "application/json, text/html;q=0.9, */*;q=0.8"}
        if base_headers:
            headers.update(base_headers)
        if self.bearer_token:
            headers.setdefault("Authorization", f"Bearer {self.bearer_token}")
        return headers


def _extract_jwt_from_mapping(obj: Any) -> str | None:
    """Recursively search a parsed JSON response dict for a JWT or token field."""
    if isinstance(obj, dict):
        for key in COMMON_TOKEN_KEYS:
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                cleaned = val.strip()
                if cleaned.lower().startswith("bearer "):
                    cleaned = cleaned[7:].strip()
                return cleaned
        for val in obj.values():
            nested = _extract_jwt_from_mapping(val)
            if nested:
                return nested
    elif isinstance(obj, list):
        for item in obj:
            nested = _extract_jwt_from_mapping(item)
            if nested:
                return nested
    return None


def login_user_context(
    context: BrowserContext,
    base_url: str,
    credentials: UserCredentials,
    *,
    label: str,
    login_path: str = "/login",
    login_mode: str = "form",
    username_field: str = "username",
    password_field: str = "password",
    username_selector: str = DEFAULT_USERNAME_SELECTOR,
    password_selector: str = DEFAULT_PASSWORD_SELECTOR,
    submit_selector: str = DEFAULT_SUBMIT_SELECTOR,
    timeout_ms: int = 10000,
    settle_ms: int = 600,
) -> AuthenticatedSession:
    """Authenticate a user in ``context`` via HTML form or JSON API login.

    Automatically captures session cookies in ``context`` as well as any Bearer
    JWT stored in ``localStorage``/``sessionStorage``, returned in login JSON
    responses, or attached to outgoing ``Authorization`` headers.

    Args:
        context: Isolated Playwright ``BrowserContext`` for this user.
        base_url: Application base URL (e.g., ``http://localhost:8080``).
        credentials: Username/password credentials.
        label: Human-readable label (``"user_a"`` or ``"user_b"``).
        login_path: Relative path or full URL of the login page/endpoint.
        login_mode: ``"form"`` for browser HTML/SPA login, ``"api"`` for direct
            JSON POST login.
        username_field: JSON key name when ``login_mode == "api"``.
        password_field: JSON key name when ``login_mode == "api"``.
        username_selector: CSS selector list for the username input.
        password_selector: CSS selector list for the password input.
        submit_selector: CSS selector list for the login submit button.
        timeout_ms: Navigation/action timeout in milliseconds.
        settle_ms: Post-login wait in milliseconds for JS storage writes.

    Returns:
        Populated ``AuthenticatedSession`` ready for resource requests.
    """
    login_url = urljoin(base_url.rstrip("/") + "/", login_path.lstrip("/"))
    captured_token: str | None = None

    if login_mode == "api":
        resp = context.request.post(
            login_url,
            data=json.dumps(
                {
                    username_field: credentials.username,
                    password_field: credentials.password,
                }
            ),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=timeout_ms,
        )
        if not (200 <= resp.status < 400):
            raise RuntimeError(
                f"API login failed for {label} ({credentials.username}) at {login_url}: HTTP {resp.status}"
            )
        try:
            captured_token = _extract_jwt_from_mapping(resp.json())
        except ValueError:
            pass
    else:
        page = context.new_page()
        page.on("dialog", lambda d: d.dismiss())

        def _inspect_response(res: Response) -> None:
            nonlocal captured_token
            if captured_token:
                return
            ctype = (res.headers.get("content-type") or "").lower()
            if "json" in ctype:
                try:
                    token_candidate = _extract_jwt_from_mapping(res.json())
                    if token_candidate:
                        captured_token = token_candidate
                except Exception:  # noqa: BLE001
                    pass

        def _inspect_request_auth(req: Any) -> None:
            nonlocal captured_token
            if captured_token:
                return
            auth_hdr = req.headers.get("authorization") or ""
            if auth_hdr.lower().startswith("bearer "):
                captured_token = auth_hdr[7:].strip()

        page.on("response", _inspect_response)
        page.on("request", _inspect_request_auth)

        try:
            page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            user_loc = page.locator(username_selector).first
            pass_loc = page.locator(password_selector).first
            user_loc.wait_for(state="visible", timeout=timeout_ms)
            user_loc.fill(credentials.username)
            pass_loc.fill(credentials.password)

            submit_loc = page.locator(submit_selector).first
            if submit_loc.count() > 0:
                submit_loc.click(timeout=timeout_ms)
            else:
                pass_loc.press("Enter")

            try:
                page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 4000))
            except PlaywrightTimeoutError:
                pass

            if settle_ms > 0:
                page.wait_for_timeout(settle_ms)

            # Inspect Web Storage (localStorage + sessionStorage) for JWT/Bearer tokens
            if not captured_token:
                storage_token: str | None = page.evaluate(
                    """(knownKeys) => {
                        for (const store of [window.localStorage, window.sessionStorage]) {
                            if (!store) continue;
                            for (const k of knownKeys) {
                                const val = store.getItem(k);
                                if (val && val.trim()) return val.trim();
                            }
                            for (let i = 0; i < store.length; i++) {
                                const k = store.key(i);
                                const val = (store.getItem(k) || "").trim();
                                if (/^eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\./.test(val)) {
                                    return val;
                                }
                            }
                        }
                        return null;
                    }""",
                    list(COMMON_TOKEN_KEYS),
                )
                if storage_token:
                    if storage_token.lower().startswith("bearer "):
                        storage_token = storage_token[7:].strip()
                    captured_token = storage_token
        finally:
            page.close()

    cookies = context.cookies()
    if not captured_token:
        for ck in cookies:
            val = str(ck.get("value") or "")
            if JWT_REGEX.match(val) and ck.get("name", "").lower() in {
                "token",
                "jwt",
                "access_token",
                "Authorization".lower(),
            }:
                captured_token = val
                break

    LOGGER.info(
        "Logged in %s (%s): %d cookie(s), bearer_jwt=%s",
        label,
        credentials.username,
        len(cookies),
        bool(captured_token),
    )
    return AuthenticatedSession(
        label=label,
        credentials=credentials,
        context=context,
        bearer_token=captured_token,
        cookies=cookies,
    )


def parse_id_values(
    explicit_ids: list[str] | None = None,
    id_range: str | None = None,
) -> list[str]:
    """Build an ordered deduplicated list of resource IDs from explicit/range specs.

    Args:
        explicit_ids: Explicit ID strings (e.g. ``["101", "102"]`` or comma-separated).
        id_range: Numeric range string in ``START-END`` format (inclusive).

    Returns:
        Deduplicated list of string IDs.
    """
    result: list[str] = []
    seen: set[str] = set()

    for raw in explicit_ids or []:
        for part in str(raw).split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                result.append(cleaned)

    if id_range:
        match = re.match(r"^\s*(\d+)\s*-\s*(\d+)\s*$", id_range)
        if not match:
            raise ValueError(
                f"Invalid --id-range {id_range!r}; expected START-END (e.g., 1-10)"
            )
        start_id, end_id = int(match.group(1)), int(match.group(2))
        step = 1 if end_id >= start_id else -1
        for num in range(start_id, end_id + step, step):
            s_num = str(num)
            if s_num not in seen:
                seen.add(s_num)
                result.append(s_num)

    return result


def discover_ids_from_endpoint(
    session_a: AuthenticatedSession,
    base_url: str,
    discover_path: str,
    *,
    timeout_ms: int = 10000,
) -> list[str]:
    """Fetch a listing endpoint as User A and extract ``id`` fields from JSON.

    Args:
        session_a: User A's authenticated session.
        base_url: Application base URL.
        discover_path: Endpoint returning User A's owned objects (e.g. ``/api/orders``).
        timeout_ms: Request timeout in milliseconds.

    Returns:
        List of discovered string IDs owned by User A.
    """
    url = urljoin(base_url.rstrip("/") + "/", discover_path.lstrip("/"))
    resp = session_a.context.request.get(
        url,
        headers=session_a.build_api_headers(),
        timeout=timeout_ms,
    )
    if not (200 <= resp.status < 300):
        LOGGER.warning("ID discovery endpoint %s returned HTTP %d", url, resp.status)
        return []

    try:
        payload = resp.json()
    except ValueError:
        return []

    found: list[str] = []
    seen: set[str] = set()

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key in ("id", "order_id", "item_id", "record_id", "uuid"):
                if key in node and isinstance(node[key], (int, str)):
                    val = str(node[key]).strip()
                    if val and val not in seen:
                        seen.add(val)
                        found.append(val)
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for elem in node:
                _walk(elem)

    _walk(payload)
    return found


def expand_resource_patterns(
    base_url: str,
    patterns: list[str],
    ids: list[str],
) -> list[dict[str, str | None]]:
    """Expand URL patterns containing ``{id}`` against candidate ``ids``.

    Args:
        base_url: Application base URL.
        patterns: List of path/URL patterns (e.g., ``["/api/orders/{id}"]``).
        ids: Candidate ID values.

    Returns:
        List of dicts with ``pattern``, ``resource_id``, and ``url``.
    """
    expanded: list[dict[str, str | None]] = []
    root = base_url.rstrip("/") + "/"

    for pattern in patterns:
        if "{id}" in pattern:
            if not ids:
                raise ValueError(
                    f"Pattern {pattern!r} requires {{id}} values (--ids, --id-range, or --discover-endpoint)"
                )
            for rid in ids:
                rel = pattern.replace("{id}", str(rid))
                full_url = urljoin(root, rel.lstrip("/")) if not rel.startswith("http") else rel
                expanded.append(
                    {"pattern": pattern, "resource_id": str(rid), "url": full_url}
                )
        else:
            full_url = (
                urljoin(root, pattern.lstrip("/"))
                if not pattern.startswith("http")
                else pattern
            )
            expanded.append({"pattern": pattern, "resource_id": None, "url": full_url})

    return expanded


def _read_response_snapshot(resp: APIResponse) -> dict[str, Any]:
    """Capture status, final URL, content-type, raw text, and parsed JSON."""
    try:
        text = resp.text()
    except Exception:  # noqa: BLE001
        text = ""

    ctype = (resp.headers.get("content-type") or "").lower()
    parsed_json: Any = None
    if "json" in ctype or text.lstrip().startswith(("{", "[")):
        try:
            parsed_json = json.loads(text)
        except ValueError:
            parsed_json = None

    return {
        "status": resp.status,
        "final_url": resp.url,
        "content_type": ctype,
        "body": text,
        "json": parsed_json,
        "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
    }


def _looks_like_denial_or_login(snapshot: dict[str, Any], login_path: str) -> bool:
    """Detect soft 200-OK login redirects or JSON error envelopes."""
    status = snapshot["status"]
    if status < 200 or status >= 300:
        return True

    final_path = urlparse(snapshot["final_url"]).path.lower()
    norm_login = "/" + login_path.strip("/").lower()
    if norm_login != "/" and final_path.startswith(norm_login):
        return True
    if any(seg in final_path for seg in ("/login", "/signin", "/unauthorized")):
        return True

    parsed = snapshot["json"]
    if isinstance(parsed, dict):
        # Empty object or explicit error-only response
        if not parsed:
            return True
        if set(parsed.keys()).issubset({"error", "message", "status", "code", "detail"}):
            combined = " ".join(str(v).lower() for v in parsed.values())
            if any(kw in combined for kw in DENIAL_KEYWORDS) or "error" in parsed:
                return True

    lower_body = snapshot["body"][:1000].lower()
    if "<form" in lower_body and 'type="password"' in lower_body:
        return True

    return False


def evaluate_idor_pair(
    snap_a: dict[str, Any],
    snap_b: dict[str, Any],
    *,
    creds_a: UserCredentials,
    creds_b: UserCredentials,
    login_path: str = "/login",
    is_parameterized: bool = True,
) -> dict[str, Any]:
    """Compare User A's baseline response against User B's cross-account response.

    Args:
        snap_a: Response snapshot when accessed by User A.
        snap_b: Response snapshot when accessed by User B.
        creds_a: User A credentials/markers.
        creds_b: User B credentials/markers.
        login_path: Configured login route to detect soft auth redirects.
        is_parameterized: Whether the URL explicitly addressed a resource ``{id}``.

    Returns:
        Evaluation dictionary containing ``vulnerable``, ``verdict``,
        ``similarity``, and ``reason``.
    """
    if _looks_like_denial_or_login(snap_a, login_path):
        return {
            "vulnerable": False,
            "verdict": "skipped_user_a_not_authorized",
            "similarity": 0.0,
            "reason": (
                f"User A could not access baseline resource (HTTP {snap_a['status']}); "
                "resource may not exist or is not owned by User A."
            ),
        }

    if _looks_like_denial_or_login(snap_b, login_path):
        return {
            "vulnerable": False,
            "verdict": "properly_protected",
            "similarity": 0.0,
            "reason": f"Access denied to User B (HTTP {snap_b['status']}).",
        }

    body_a = snap_a["body"].strip()
    body_b = snap_b["body"].strip()

    # Exact payload match on an authenticated private resource
    if snap_a["sha256"] == snap_b["sha256"] and len(body_a) > 2:
        return {
            "vulnerable": True,
            "verdict": "vulnerable_exact_match",
            "similarity": 1.0,
            "reason": (
                "User B received HTTP 2xx with the exact same private payload "
                "returned to User A."
            ),
        }

    # Check if User A's identity markers leaked into User B's response
    markers_a = [m.lower() for m in [creds_a.username, *creds_a.extra_markers] if m]
    markers_b = [m.lower() for m in [creds_b.username, *creds_b.extra_markers] if m]
    lower_b = body_b.lower()

    leaked_markers = [m for m in markers_a if m in lower_b and m not in markers_b]
    if leaked_markers:
        return {
            "vulnerable": True,
            "verdict": "vulnerable_owner_data_exposed",
            "similarity": 0.9,
            "reason": (
                f"User B received HTTP {snap_b['status']} containing User A's "
                f"identifier(s): {leaked_markers}."
            ),
        }

    # Compare JSON key/value overlap (handles dynamic timestamps like fetched_at)
    json_a, json_b = snap_a["json"], snap_b["json"]
    if isinstance(json_a, dict) and isinstance(json_b, dict) and json_a:
        shared_keys = set(json_a.keys()) & set(json_b.keys())
        volatile_keys = {"timestamp", "fetched_at", "request_id", "csrf_token", "viewer"}
        meaningful_keys = [k for k in shared_keys if k.lower() not in volatile_keys]
        if meaningful_keys:
            matching_vals = sum(1 for k in meaningful_keys if json_a[k] == json_b[k])
            ratio = matching_vals / len(meaningful_keys)
            # Distinguish /api/me (returns B's own profile) from /api/orders/{id}
            if is_parameterized and ratio >= 0.6:
                return {
                    "vulnerable": True,
                    "verdict": "vulnerable_json_record_match",
                    "similarity": round(ratio, 3),
                    "reason": (
                        f"User B accessed parameterized resource with {matching_vals}/"
                        f"{len(meaningful_keys)} matching data fields from User A's record."
                    ),
                }

    return {
        "vulnerable": False,
        "verdict": "different_user_scoped_data",
        "similarity": 0.1,
        "reason": (
            "User B received HTTP 2xx, but response content differed from User A's "
            "private record (likely session-scoped endpoint)."
        ),
    }


def run_idor_tests(
    base_url: str,
    user_a: UserCredentials,
    user_b: UserCredentials,
    patterns: list[str],
    *,
    explicit_ids: list[str] | None = None,
    id_range: str | None = None,
    discover_endpoint: str | None = None,
    login_path: str = "/login",
    login_mode: str = "form",
    username_field: str = "username",
    password_field: str = "password",
    username_selector: str = DEFAULT_USERNAME_SELECTOR,
    password_selector: str = DEFAULT_PASSWORD_SELECTOR,
    submit_selector: str = DEFAULT_SUBMIT_SELECTOR,
    timeout_ms: int = 10000,
    headless: bool = True,
) -> dict[str, Any]:
    """Execute end-to-end IDOR verification across two isolated Playwright sessions.

    Args:
        base_url: Lab application base URL.
        user_a: Resource owner credentials (User A).
        user_b: Cross-account tester credentials (User B).
        patterns: Private resource URL patterns (e.g. ``["/api/orders/{id}"]``).
        explicit_ids: Optional explicit resource IDs.
        id_range: Optional numeric ID range ``START-END``.
        discover_endpoint: Optional User A listing endpoint to auto-extract IDs.
        login_path: Login form/API path.
        login_mode: ``"form"`` or ``"api"``.
        username_field: JSON key for API login mode.
        password_field: JSON key for API login mode.
        username_selector: CSS selector for form username field.
        password_selector: CSS selector for form password field.
        submit_selector: CSS selector for form submit button.
        timeout_ms: Request/navigation timeout in ms.
        headless: Run browser headless when ``True``.

    Returns:
        Structured JSON-serializable IDOR report dictionary.
    """
    findings: list[dict[str, Any]] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        context_a = browser.new_context(ignore_https_errors=True)
        context_b = browser.new_context(ignore_https_errors=True)

        try:
            session_a = login_user_context(
                context_a,
                base_url,
                user_a,
                label="user_a",
                login_path=login_path,
                login_mode=login_mode,
                username_field=username_field,
                password_field=password_field,
                username_selector=username_selector,
                password_selector=password_selector,
                submit_selector=submit_selector,
                timeout_ms=timeout_ms,
            )
            session_b = login_user_context(
                context_b,
                base_url,
                user_b,
                label="user_b",
                login_path=login_path,
                login_mode=login_mode,
                username_field=username_field,
                password_field=password_field,
                username_selector=username_selector,
                password_selector=password_selector,
                submit_selector=submit_selector,
                timeout_ms=timeout_ms,
            )

            candidate_ids = parse_id_values(explicit_ids, id_range)
            if discover_endpoint:
                discovered = discover_ids_from_endpoint(
                    session_a,
                    base_url,
                    discover_endpoint,
                    timeout_ms=timeout_ms,
                )
                for did in discovered:
                    if did not in candidate_ids:
                        candidate_ids.append(did)

            targets = expand_resource_patterns(base_url, patterns, candidate_ids)
            headers_a = session_a.build_api_headers()
            headers_b = session_b.build_api_headers()

            for target in targets:
                url = str(target["url"])
                is_param = target["resource_id"] is not None
                LOGGER.info("Testing IDOR candidate: %s", url)

                try:
                    resp_a = context_a.request.get(
                        url, headers=headers_a, timeout=timeout_ms
                    )
                    snap_a = _read_response_snapshot(resp_a)

                    resp_b = context_b.request.get(
                        url, headers=headers_b, timeout=timeout_ms
                    )
                    snap_b = _read_response_snapshot(resp_b)

                    evaluation = evaluate_idor_pair(
                        snap_a,
                        snap_b,
                        creds_a=user_a,
                        creds_b=user_b,
                        login_path=login_path,
                        is_parameterized=is_param,
                    )
                    findings.append(
                        {
                            "url": url,
                            "pattern": target["pattern"],
                            "resource_id": target["resource_id"],
                            "vulnerable": evaluation["vulnerable"],
                            "verdict": evaluation["verdict"],
                            "similarity": evaluation["similarity"],
                            "reason": evaluation["reason"],
                            "user_a_status": snap_a["status"],
                            "user_b_status": snap_b["status"],
                            "user_a_preview": snap_a["body"][:240],
                            "user_b_preview": snap_b["body"][:240],
                        }
                    )
                except PlaywrightError as exc:
                    LOGGER.warning("Request error testing %s: %s", url, exc)
                    findings.append(
                        {
                            "url": url,
                            "pattern": target["pattern"],
                            "resource_id": target["resource_id"],
                            "vulnerable": False,
                            "verdict": "request_error",
                            "similarity": 0.0,
                            "reason": f"Request failed: {exc}",
                            "user_a_status": None,
                            "user_b_status": None,
                            "user_a_preview": "",
                            "user_b_preview": "",
                        }
                    )
        finally:
            context_a.close()
            context_b.close()
            browser.close()

    vuln_count = sum(1 for f in findings if f["vulnerable"])
    return {
        "module": "idor_tester",
        "base_url": base_url,
        "user_a": user_a.username,
        "user_b": user_b.username,
        "summary": {
            "total_tested": len(findings),
            "vulnerable_count": vuln_count,
        },
        "findings": findings,
    }


def _parse_cred_pair(raw: str, arg_name: str) -> UserCredentials:
    """Parse ``USERNAME:PASSWORD`` CLI credential string."""
    if ":" not in raw:
        raise ValueError(f"{arg_name} must use USERNAME:PASSWORD format")
    username, password = raw.split(":", 1)
    return UserCredentials(username=username, password=password)


def load_config_file(config_path: Path) -> dict[str, Any]:
    """Load JSON configuration file for complex lab IDOR test setups."""
    return json.loads(config_path.read_text(encoding="utf-8"))


def save_json_output(data: dict[str, Any], output_path: Path) -> None:
    """Write IDOR report dictionary to ``output_path`` as formatted JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser for standalone IDOR test execution."""
    parser = argparse.ArgumentParser(
        description="VulnStrike AI — Subsystem 3.1: Automated IDOR Tester",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional JSON config file specifying credentials, login selectors, and patterns",
    )
    parser.add_argument("--base-url", help="Target lab app base URL (e.g., http://localhost:8080)")
    parser.add_argument("--user-a", help="Owner credentials in USERNAME:PASSWORD format")
    parser.add_argument("--user-b", help="Attacker/peer credentials in USERNAME:PASSWORD format")
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Private resource URL pattern, e.g., /api/orders/{id} (repeatable)",
    )
    parser.add_argument(
        "--ids",
        action="append",
        default=[],
        help="Comma-separated explicit resource IDs, e.g., 1,2,3 (repeatable)",
    )
    parser.add_argument(
        "--id-range",
        default=None,
        help="Inclusive numeric ID range, e.g., 1-10",
    )
    parser.add_argument(
        "--discover-endpoint",
        default=None,
        help="Optional User A listing endpoint (e.g., /api/orders) to auto-harvest IDs",
    )
    parser.add_argument(
        "--login-path",
        default="/login",
        help="Login route path (default: /login)",
    )
    parser.add_argument(
        "--login-mode",
        choices=("form", "api"),
        default="form",
        help="Authenticate via browser HTML/SPA form or JSON POST API (default: form)",
    )
    parser.add_argument(
        "--username-selector",
        default=DEFAULT_USERNAME_SELECTOR,
        help="CSS selector for username field in form mode",
    )
    parser.add_argument(
        "--password-selector",
        default=DEFAULT_PASSWORD_SELECTOR,
        help="CSS selector for password field in form mode",
    )
    parser.add_argument(
        "--submit-selector",
        default=DEFAULT_SUBMIT_SELECTOR,
        help="CSS selector for login submit button in form mode",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=10000,
        help="Request/navigation timeout in ms (default: 10000)",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Run Chromium in headed mode",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/idor_report.json"),
        help="Output JSON report path (default: output/idor_report.json)",
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
        cfg: dict[str, Any] = load_config_file(args.config) if args.config else {}

        base_url = args.base_url or cfg.get("base_url")
        if not base_url:
            raise ValueError("--base-url (or 'base_url' in --config) is required")

        if args.user_a:
            creds_a = _parse_cred_pair(args.user_a, "--user-a")
        elif "user_a" in cfg:
            ua = cfg["user_a"]
            creds_a = UserCredentials(
                username=ua["username"],
                password=ua["password"],
                extra_markers=ua.get("extra_markers", []),
            )
        else:
            raise ValueError("--user-a (or 'user_a' in --config) is required")

        if args.user_b:
            creds_b = _parse_cred_pair(args.user_b, "--user-b")
        elif "user_b" in cfg:
            ub = cfg["user_b"]
            creds_b = UserCredentials(
                username=ub["username"],
                password=ub["password"],
                extra_markers=ub.get("extra_markers", []),
            )
        else:
            raise ValueError("--user-b (or 'user_b' in --config) is required")

        patterns: list[str] = list(args.pattern) or list(cfg.get("patterns", []))
        if not patterns:
            raise ValueError("At least one --pattern (or 'patterns' in --config) is required")

        explicit_ids: list[str] = list(args.ids) or [
            str(x) for x in cfg.get("ids", [])
        ]
        id_range: str | None = args.id_range or cfg.get("id_range")
        discover_endpoint: str | None = args.discover_endpoint or cfg.get("discover_endpoint")

        report = run_idor_tests(
            base_url=base_url,
            user_a=creds_a,
            user_b=creds_b,
            patterns=patterns,
            explicit_ids=explicit_ids,
            id_range=id_range,
            discover_endpoint=discover_endpoint,
            login_path=cfg.get("login_path", args.login_path),
            login_mode=cfg.get("login_mode", args.login_mode),
            username_field=cfg.get("username_field", "username"),
            password_field=cfg.get("password_field", "password"),
            username_selector=cfg.get("username_selector", args.username_selector),
            password_selector=cfg.get("password_selector", args.password_selector),
            submit_selector=cfg.get("submit_selector", args.submit_selector),
            timeout_ms=int(cfg.get("timeout_ms", args.timeout_ms)),
            headless=not args.headed,
        )
        save_json_output(report, args.output)
        LOGGER.info(
            "IDOR testing complete: %d/%d vulnerable finding(s) saved to %s",
            report["summary"]["vulnerable_count"],
            report["summary"]["total_tested"],
            args.output,
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("IDOR Tester failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
