import http.client
import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlsplit


from app.orchestrator.scope import evaluate_scope


DEFAULT_TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 65536
MAX_REDIRECTS = 3


@dataclass(frozen=True)
class SafeHttpResponse:
    url: str
    status_code: int
    reason: str
    headers: Dict[str, str]
    content_type: Optional[str]
    body_preview: str
    body_truncated: bool
    body_length: int
    redirected_from: Optional[str]
    final_url: str
    elapsed_ms: int


class SafeHttpRequestError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


def _normalize_headers(headers) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    if headers is None:
        return normalized
    try:
        if hasattr(headers, "items"):
            items = headers.items()
        else:
            items = headers
        for key, value in items:
            normalized[str(key).lower()] = str(value)
    except Exception:
        return normalized
    return normalized


def _is_safe_address(raw_address: str) -> bool:
    try:
        address = ipaddress.ip_address(raw_address.split("%", 1)[0])
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def _resolve_addresses(hostname: str, port: int):
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SafeHttpRequestError(f"DNS resolution failed for authorized host: {exc}")

    results = []
    for info in infos:
        family, socktype, proto, _, sockaddr = info
        raw_address = sockaddr[0]
        if not _is_safe_address(raw_address):
            raise SafeHttpRequestError("Refused to connect to non-lab network address.")
        results.append((family, socktype, proto, sockaddr))
    return results


class SafeHttpClient:
    def __init__(
        self,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_redirects: int = MAX_REDIRECTS,
        user_agent: str = "VulnStrike-Scanner/1.0",
    ):
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self.user_agent = user_agent

    def request(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None) -> SafeHttpResponse:
        start = time.monotonic()
        current_url = url
        redirected_from: Optional[str] = None
        redirects = 0
        current_method = method.upper()

        while True:
            decision = evaluate_scope(current_url, authorized_confirmation=True, require_active_scheme=True)
            if not decision.allowed or decision.normalized_url is None or decision.hostname is None or decision.port is None:
                raise SafeHttpRequestError(f"Request blocked by scope policy: {decision.reason}")

            parsed = urlsplit(decision.normalized_url)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"

            request_headers = {"User-Agent": self.user_agent, "Accept": "*/*", "Host": parsed.netloc}
            if headers:
                for key, value in headers.items():
                    request_headers[str(key)] = str(value)

            sock = None
            connection = None
            try:
                addresses = _resolve_addresses(decision.hostname, decision.port)
                last_error = None
                for family, socktype, proto, sockaddr in addresses:
                    try:
                        sock = socket.socket(family, socktype, proto)
                        sock.settimeout(self.timeout_seconds)
                        sock.connect(sockaddr)
                        break
                    except OSError as exc:
                        last_error = exc
                        if sock is not None:
                            try:
                                sock.close()
                            except Exception:
                                pass
                            sock = None
                if sock is None:
                    raise SafeHttpRequestError(f"Connection failed: {last_error}")

                if decision.port == 443 and parsed.scheme == "https":
                    import ssl

                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=decision.hostname)

                connection = http.client.HTTPConnection(decision.hostname, decision.port, timeout=self.timeout_seconds)
                connection.sock = sock
                connection.request(current_method, path, headers=request_headers)
                response = connection.getresponse()
                response_headers = _normalize_headers(response.getheaders())
                status_code = response.status

                if status_code in (301, 302, 303, 307, 308) and "location" in response_headers:
                    if redirects >= self.max_redirects:
                        raise SafeHttpRequestError("Too many redirects while following authorized targets.")
                    location = response_headers["location"]
                    next_url = urlsplit(location)
                    if next_url.scheme or next_url.netloc:
                        redirect_target = location
                    else:
                        base = urlsplit(decision.normalized_url)
                        redirect_target = base._replace(
                            path=next_url.path or "/",
                            query=next_url.query or "",
                            fragment="",
                        ).geturl()

                    redirected_from = current_url
                    current_url = redirect_target
                    redirects += 1
                    if status_code in (301, 302, 303) and current_method == "POST":
                        current_method = "GET"
                    if connection is not None:
                        try:
                            response.read()
                        except Exception:
                            pass
                    continue

                raw_body = response.read(self.max_response_bytes + 1)
                truncated = len(raw_body) > self.max_response_bytes
                body_bytes = raw_body[: self.max_response_bytes]
                try:
                    body_preview = body_bytes.decode("utf-8", errors="replace")
                except Exception:
                    body_preview = body_bytes.decode("latin-1", errors="replace")

                elapsed_ms = int((time.monotonic() - start) * 1000)
                content_type = response_headers.get("content-type")
                final_url = decision.normalized_url
                return SafeHttpResponse(
                    url=current_url,
                    status_code=status_code,
                    reason=response.reason or "",
                    headers=response_headers,
                    content_type=content_type,
                    body_preview=body_preview,
                    body_truncated=truncated,
                    body_length=len(raw_body),
                    redirected_from=redirected_from,
                    final_url=final_url,
                    elapsed_ms=elapsed_ms,
                )
            except SafeHttpRequestError:
                raise
            except OSError as exc:
                raise SafeHttpRequestError(f"HTTP request failed: {exc}")
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass
                elif sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
