import re
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler


class VulnerableTargetHandler(BaseHTTPRequestHandler):
    """
    Local mock vulnerable target for VulnStrike AI testing & live demos.
    Simulates:
    1. SQL Injection (Error-Based & Auth Bypass)
    2. Command Injection (RCE)
    3. Path Traversal (LFI)
    """

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # 1. SQL Injection Endpoint
        if "/vulnerabilities/sqli" in parsed.path:
            id_val = params.get("id", [""])[0]

            # Trigger MySQL Syntax Error on single quote or order by
            if "'" in id_val or '"' in id_val:
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Database Error</h1>"
                    b"<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1</p>"
                    b"</body></html>"
                )
                return

            # Normal Response
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>User Lookup</h1><p>User details for ID: " + id_val.encode() + b"</p></body></html>")
            return

        # 2. Command Injection (RCE) Endpoint
        elif "/vulnerabilities/exec" in parsed.path:
            ip_val = params.get("ip", [""])[0]

            # Check for command separators and injected commands
            if ";" in ip_val or "|" in ip_val or "&&" in ip_val or "`" in ip_val:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
                    b"64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.031 ms\n"
                    b"--- 127.0.0.1 ping statistics ---\n"
                    b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n</pre>"
                )
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<pre>PING " + ip_val.encode() + b" 56(84) bytes of data.\n1 packets transmitted, 1 received</pre>")
            return

        # 3. Path Traversal / LFI Endpoint
        elif "/vulnerabilities/fi" in parsed.path:
            page_val = params.get("page", [""])[0]

            if "etc/passwd" in page_val or "%2f" in page_val.lower():
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(
                    b"root:x:0:0:root:/root:/bin/bash\n"
                    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                    b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                )
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Welcome to page: " + page_val.encode() + b"</body></html>")
            return

        # Default fallback
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>VulnStrike Test Server Online</h1></body></html>")


def run(port=8080):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, VulnerableTargetHandler)
    print(f"[*] Mock Vulnerable Server listening on http://127.0.0.1:{port}")
    print("[*] Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")


if __name__ == "__main__":
    run()
