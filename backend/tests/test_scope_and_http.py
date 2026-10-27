import http.server
import ipaddress
import socket
import threading
from urllib.parse import urlparse

import pytest

from app.orchestrator.http_client import SafeHttpClient, SafeHttpRequestError
from app.orchestrator.scope import evaluate_scope, validate_scope


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:8089/secret")
            self.end_headers()
            return
        if self.path == "/ok":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()


def _start_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def test_scope_rejects_missing_authorization():
    valid, msg = validate_scope("http://localhost:8088", authorized_confirmation=False)
    assert valid is False
    assert "confirmation" in msg.lower()


def test_scope_rejects_external_host():
    valid, msg = validate_scope("https://example.com", authorized_confirmation=True)
    assert valid is False
    assert "out of scope" in msg.lower()


def test_scope_rejects_metadata():
    valid, msg = validate_scope("http://169.254.169.254/latest/meta-data", authorized_confirmation=True)
    assert valid is False


def test_scope_rejects_credentials_in_url():
    decision = evaluate_scope("http://user:pass@127.0.0.1:8088/", authorized_confirmation=True)
    assert decision.allowed is False


def test_scope_rejects_disallowed_port():
    decision = evaluate_scope("http://127.0.0.1:22/", authorized_confirmation=True)
    assert decision.allowed is False


def test_scope_rejects_invalid_ipv6_mapped_style_and_unsafe_ips(monkeypatch):
    decision = evaluate_scope("http://0.0.0.0:8088/", authorized_confirmation=True)
    assert decision.allowed is False


def test_safe_http_blocks_redirect_outside_scope():
    server, port = _start_server()
    try:
        client = SafeHttpClient(timeout_seconds=2)
        with pytest.raises(SafeHttpRequestError):
            client.request(f"http://127.0.0.1:{port}/redirect")
    finally:
        server.shutdown()
        server.server_close()


def test_safe_http_rejects_unauthorized_target():
    client = SafeHttpClient(timeout_seconds=2)
    with pytest.raises(SafeHttpRequestError):
        client.request("http://example.com/")


def test_safe_http_enforces_response_limit(monkeypatch):
    class _BigHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args, **kwargs):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"a" * 200000)

    server = http.server.HTTPServer(("127.0.0.1", 0), _BigHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        from app.orchestrator.scope import ALLOWED_PORTS

        if port not in ALLOWED_PORTS:
            ALLOWED_PORTS.add(port)
        client = SafeHttpClient(timeout_seconds=2, max_response_bytes=1024)
        response = client.request(f"http://127.0.0.1:{port}/")
        assert response.body_truncated is True
        assert len(response.body_preview) <= 1024
    finally:
        server.shutdown()
        server.server_close()
