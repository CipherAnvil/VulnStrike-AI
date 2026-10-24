#!/usr/bin/env python3
"""Self-contained hybrid vulnerable lab server for testing VulnStrike AI modules.

Uses only Python 3.11+ standard library (``http.server``) and ``PyJWT`` so the
entire test suite adheres to the strict dependency policy.

Simulated hybrid app characteristics:
  - Exposes version headers (``Server: nginx/1.18.0 (Ubuntu)``,
    ``X-Powered-By: PHP/8.1.2-1ubuntu2``), ``<meta name="generator">``, and
    ``<script src="/static/js/jquery-3.4.1.min.js">``
  - Multi-page HTML navigation + client-side ``fetch("/api/stats")`` XHR calls
  - Includes a broken link (``/broken-route``) to test crawler error resilience
  - Hybrid auth: ``POST /api/login`` sets ``lab_session`` cookie AND returns a
    signed HS256 JWT that the login page saves to ``window.localStorage``
  - Vulnerable IDOR endpoint: ``GET /api/orders/{id}`` (missing owner check)
  - Properly protected endpoint: ``GET /api/invoices/{id}`` (enforces owner)
  - Session-scoped endpoint: ``GET /api/me`` (returns caller's own profile)
  - Vulnerable JWT endpoint: ``GET /api/jwt-protected`` (accepts ``alg: none``,
    rejects tampered HS256 signatures)
  - Reflected XSS page (``/search``) + Stored XSS hybrid feed (``/feedback`` ->
    ``/comments`` populated via ``fetch("/api/comments")`` + ``innerHTML``)
"""

from __future__ import annotations

import base64
import html
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any
from urllib.parse import parse_qs, urlparse
import warnings

import jwt

LAB_JWT_SECRET = "vulnstrike-lab-secret"

USERS_DB: dict[str, dict[str, str]] = {
    "alice": {"password": "alice_password_123", "email": "alice@lab.local", "role": "user"},
    "bob": {"password": "bob_password_123", "email": "bob@lab.local", "role": "user"},
}

ORDERS_DB: dict[str, dict[str, Any]] = {
    "101": {"id": 101, "owner": "alice", "item": "Hardware Security Key", "total": 89.99},
    "102": {"id": 102, "owner": "bob", "item": "USB Logic Analyzer", "total": 149.00},
}

INVOICES_DB: dict[str, dict[str, Any]] = {
    "201": {"id": 201, "owner": "alice", "amount": 89.99, "card_last4": "4242"},
}

STORED_COMMENTS: list[dict[str, str]] = [
    {"author": "system", "comment": "Welcome to the VulnStrike hybrid testbench."}
]

SESSIONS: dict[str, str] = {}


class MockLabHandler(BaseHTTPRequestHandler):
    """HTTP handler implementing hybrid MPA + REST API vulnerable test routes."""

    server_version = "nginx/1.18.0 (Ubuntu)"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        """Silence noisy default request logging during automated tests."""
        return

    def _send_response(
        self,
        status: int,
        body: str,
        *,
        content_type: str = "text/html; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Powered-By", "PHP/8.1.2-1ubuntu2")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(encoded)

    def _current_user(self) -> str | None:
        """Authenticate caller via Bearer JWT first, falling back to session cookie."""
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    claims = jwt.decode(tok, LAB_JWT_SECRET, algorithms=["HS256"])
                return str(claims.get("sub"))
            except jwt.InvalidTokenError:
                pass

        raw_cookie = self.headers.get("Cookie")
        if raw_cookie:
            jar = cookies.SimpleCookie()
            jar.load(raw_cookie)
            if "lab_session" in jar:
                sid = jar["lab_session"].value
                return SESSIONS.get(sid)
        return None

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/":
            page_html = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="generator" content="WordPress 6.4.1">
  <title>VulnStrike Hybrid Lab</title>
  <script src="/static/js/jquery-3.4.1.min.js"></script>
</head>
<body>
  <h1>VulnStrike Hybrid Lab Home</h1>
  <nav>
    <a href="/login">Login</a>
    <a href="/search">Search</a>
    <a href="/feedback">Feedback</a>
    <a href="/comments">Comments Feed</a>
    <a href="/broken-route">Broken Link</a>
  </nav>
  <div id="stats"></div>
  <script>
    fetch("/api/stats").then(r => r.json()).then(d => {
      document.getElementById("stats").textContent = "Status: " + d.status;
    });
  </script>
</body>
</html>"""
            self._send_response(
                200,
                page_html,
                extra_headers={"Set-Cookie": "visitor_track=lab_vis_01; Path=/; SameSite=Lax"},
            )
            return

        if path == "/static/js/jquery-3.4.1.min.js":
            self._send_response(
                200,
                "/* mock jquery 3.4.1 */ window.jQuery = {};",
                content_type="application/javascript",
            )
            return

        if path == "/api/stats":
            self._send_response(
                200,
                json.dumps({"status": "online", "active_orders": 2}),
                content_type="application/json",
            )
            return

        if path == "/login":
            login_html = """<!doctype html>
<html>
<body>
  <h2>Hybrid Login</h2>
  <form id="login-form" action="/api/login" method="POST">
    <input id="username-input" name="username" type="text" />
    <input id="password-input" name="password" type="password" />
    <button id="login-btn" type="submit">Sign In</button>
  </form>
  <div id="msg"></div>
  <script>
    document.getElementById("login-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = document.getElementById("username-input").value;
      const password = document.getElementById("password-input").value;
      const res = await fetch("/api/login", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({username, password})
      });
      const data = await res.json();
      if (data.token) {
        localStorage.setItem("token", data.token);
        document.getElementById("msg").textContent = "Logged in as " + username;
      }
    });
  </script>
</body>
</html>"""
            self._send_response(200, login_html)
            return

        if path == "/search":
            q = qs.get("q", [""])[0]
            # Deliberately unescaped reflected query for testing alert-based XSS
            search_html = f"""<!doctype html>
<html>
<body>
  <h2>Reflected Search</h2>
  <form action="/search" method="GET">
    <input id="search-box" name="q" type="text" value="" />
    <button id="search-submit" type="submit">Search</button>
  </form>
  <div id="results">Results for: {q}</div>
</body>
</html>"""
            self._send_response(200, search_html)
            return

        if path == "/safe-search":
            q = html.escape(qs.get("q", [""])[0], quote=True)
            safe_html = f"""<!doctype html>
<html>
<body>
  <form action="/safe-search" method="GET">
    <input id="safe-box" name="q" type="text" />
    <button type="submit">Safe Search</button>
  </form>
  <div>Escaped results: {q}</div>
</body>
</html>"""
            self._send_response(200, safe_html)
            return

        if path == "/feedback":
            fb_html = """<!doctype html>
<html>
<body>
  <h2>Leave Feedback</h2>
  <form id="feedback-form" action="/api/comments" method="POST">
    <input id="author-input" name="author" type="text" value="guest" />
    <textarea id="comment-input" name="comment"></textarea>
    <button id="submit-comment" type="submit">Post Comment</button>
  </form>
  <script>
    document.getElementById("feedback-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const author = document.getElementById("author-input").value;
      const comment = document.getElementById("comment-input").value;
      await fetch("/api/comments", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({author, comment})
      });
    });
  </script>
</body>
</html>"""
            self._send_response(200, fb_html)
            return

        if path == "/comments":
            comments_html = """<!doctype html>
<html>
<body>
  <h2>Community Comments Feed</h2>
  <div id="comments-feed"></div>
  <script>
    fetch("/api/comments").then(r => r.json()).then(items => {
      const feed = document.getElementById("comments-feed");
      // Deliberate hybrid Stored DOM XSS sink via innerHTML
      feed.innerHTML = items.map(c => `<div class="comment"><b>${c.author}:</b> ${c.comment}</div>`).join("");
    });
  </script>
</body>
</html>"""
            self._send_response(200, comments_html)
            return

        if path == "/api/comments":
            self._send_response(
                200, json.dumps(STORED_COMMENTS), content_type="application/json"
            )
            return

        if path == "/api/orders":
            user = self._current_user()
            if not user:
                self._send_response(
                    401, json.dumps({"error": "Unauthorized"}), content_type="application/json"
                )
                return
            owned = [o for o in ORDERS_DB.values() if o["owner"] == user]
            self._send_response(200, json.dumps(owned), content_type="application/json")
            return

        if path.startswith("/api/orders/"):
            user = self._current_user()
            if not user:
                self._send_response(
                    401, json.dumps({"error": "Unauthorized"}), content_type="application/json"
                )
                return
            oid = path.rsplit("/", 1)[-1]
            order = ORDERS_DB.get(oid)
            if not order:
                self._send_response(
                    404, json.dumps({"error": "Not found"}), content_type="application/json"
                )
                return
            # Deliberate IDOR bug: returns any user's order without checking order["owner"] == user
            resp_data = dict(order)
            resp_data["owner_email"] = USERS_DB[order["owner"]]["email"]
            self._send_response(200, json.dumps(resp_data), content_type="application/json")
            return

        if path.startswith("/api/invoices/"):
            user = self._current_user()
            if not user:
                self._send_response(
                    401, json.dumps({"error": "Unauthorized"}), content_type="application/json"
                )
                return
            iid = path.rsplit("/", 1)[-1]
            inv = INVOICES_DB.get(iid)
            if not inv:
                self._send_response(
                    404, json.dumps({"error": "Not found"}), content_type="application/json"
                )
                return
            if inv["owner"] != user:
                self._send_response(
                    403, json.dumps({"error": "Forbidden"}), content_type="application/json"
                )
                return
            self._send_response(200, json.dumps(inv), content_type="application/json")
            return

        if path == "/api/me":
            user = self._current_user()
            if not user:
                self._send_response(
                    401, json.dumps({"error": "Unauthorized"}), content_type="application/json"
                )
                return
            profile = {"username": user, "email": USERS_DB[user]["email"]}
            self._send_response(200, json.dumps(profile), content_type="application/json")
            return

        if path == "/api/jwt-protected":
            auth = self.headers.get("Authorization") or ""
            if not auth.lower().startswith("bearer "):
                self._send_response(
                    401, json.dumps({"error": "Missing token"}), content_type="application/json"
                )
                return
            tok = auth[7:].strip()
            parts = tok.split(".")
            if len(parts) not in {2, 3}:
                self._send_response(
                    401, json.dumps({"error": "Bad format"}), content_type="application/json"
                )
                return
            try:
                pad = "=" * ((4 - len(parts[0]) % 4) % 4)
                hdr = json.loads(base64.urlsafe_b64decode(parts[0] + pad).decode("utf-8"))
                # Deliberate lab flaw: trusts alg == "none" without signature check!
                if str(hdr.get("alg", "")).lower() == "none":
                    pad_p = "=" * ((4 - len(parts[1]) % 4) % 4)
                    claims = json.loads(
                        base64.urlsafe_b64decode(parts[1] + pad_p).decode("utf-8")
                    )
                    self._send_response(
                        200,
                        json.dumps({"authenticated": True, "claims": claims}),
                        content_type="application/json",
                    )
                    return

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    claims = jwt.decode(tok, LAB_JWT_SECRET, algorithms=["HS256"])
                self._send_response(
                    200,
                    json.dumps({"authenticated": True, "claims": claims}),
                    content_type="application/json",
                )
            except Exception:  # noqa: BLE001
                self._send_response(
                    401,
                    json.dumps({"error": "Invalid signature"}),
                    content_type="application/json",
                )
            return

        self._send_response(404, "<h1>404 Not Found</h1>")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"

        if self.path == "/api/login":
            data = json.loads(raw_body)
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))
            record = USERS_DB.get(username)
            if not record or record["password"] != password:
                self._send_response(
                    401,
                    json.dumps({"error": "Invalid credentials"}),
                    content_type="application/json",
                )
                return

            sid = f"sess_{username}_9988"
            SESSIONS[sid] = username
            with __import__("warnings").catch_warnings():
                __import__("warnings").simplefilter("ignore")
                token = jwt.encode(
                    {"sub": username, "role": record["role"]},
                    LAB_JWT_SECRET,
                    algorithm="HS256",
                )
            self._send_response(
                200,
                json.dumps({"ok": True, "token": token}),
                content_type="application/json",
                extra_headers={
                    "Set-Cookie": f"lab_session={sid}; Path=/; HttpOnly; SameSite=Lax"
                },
            )
            return

        if self.path == "/api/comments":
            data = json.loads(raw_body)
            STORED_COMMENTS.append(
                {
                    "author": str(data.get("author", "anon")),
                    "comment": str(data.get("comment", "")),
                }
            )
            self._send_response(
                201, json.dumps({"stored": True}), content_type="application/json"
            )
            return

        self._send_response(404, json.dumps({"error": "Not found"}), content_type="application/json")


def start_mock_server(port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """Start the mock vulnerable lab app on a background daemon thread."""
    server = ThreadingHTTPServer(("127.0.0.1", port), MockLabHandler)
    bound_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{bound_port}"
