import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class DemoTargetHandler(BaseHTTPRequestHandler):
    def _send(self, status: int, data: dict, extra_headers: dict = None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "Apache/2.4.49 (Lab-Seed)")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        if self.path == "/" or self.path == "/api/v1/health":
            self._send(200, {"status": "ok", "service": "demo-target-lab", "version": "1.0.0"})
        elif self.path == "/internal/admin/metrics":
            # Seeded unauthenticated metrics endpoint demonstrating BOLA
            self._send(200, {
                "system": "demo-target",
                "role": "admin_unrestricted",
                "active_tenants": 12,
                "db_records": 1420,
                "debug_flag": True
            })
        elif self.path.startswith("/api/v1/users"):
            # Seeded sensitive customer fixture demonstrating excessive data exposure
            self._send(200, [
                {"id": 101, "name": "Synthetic User Alpha", "email": "alpha.test@lab.local", "token": "SEED_TEST_TOKEN_01"},
                {"id": 102, "name": "Synthetic User Beta", "email": "beta.test@lab.local", "token": "SEED_TEST_TOKEN_02"}
            ])
        else:
            self._send(404, {"error": "Not Found", "path": self.path})

def run(port: int = 8088):
    server = HTTPServer(("0.0.0.0", port), DemoTargetHandler)
    print(f"[*] Demo Target running on port {port}")
    server.serve_forever()

if __name__ == "__main__":
    run()
