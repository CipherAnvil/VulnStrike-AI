import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

AUTHORIZED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "demo-target",
    "test-lab.local",
    "vuln-demo.internal",
}

ALLOWED_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8088, 9000, 9090}
ALLOWED_SCHEMES = {"http", "https"}
ACTIVE_SCHEMES = {"http"}

HOSTNAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x20\x7f\\]")


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    normalized_url: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    resolved_ips: Tuple[str, ...] = ()


def _reject(reason: str) -> ScopeDecision:
    return ScopeDecision(allowed=False, reason=reason)


def _is_allowed_ip(address: ipaddress._BaseAddress) -> bool:
    if address.is_loopback:
        return True
    if (
        address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        return False
    return address.is_private


def _resolve_host(hostname: str, port: int) -> Tuple[bool, Tuple[str, ...], str]:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return False, (), f"Authorized host '{hostname}' could not be resolved safely: {exc}"

    addresses = tuple(sorted({info[4][0] for info in infos}))
    if not addresses:
        return False, (), f"Authorized host '{hostname}' returned no network addresses."

    for raw_address in addresses:
        try:
            address = ipaddress.ip_address(raw_address.split("%", 1)[0])
        except ValueError:
            return False, (), f"Authorized host '{hostname}' resolved to an invalid address."
        if not _is_allowed_ip(address):
            return (
                False,
                (),
                f"Forbidden target: '{hostname}' resolves to non-lab address '{raw_address}'.",
            )

    return True, addresses, "Target resolution is confined to loopback or private lab addresses."


def evaluate_scope(
    url: str,
    authorized_confirmation: bool = True,
    *,
    resolve_dns: bool = True,
    require_active_scheme: bool = False,
) -> ScopeDecision:
    if not authorized_confirmation:
        return _reject("Target authorization confirmation checkbox is required.")

    if not url or not isinstance(url, str):
        return _reject("Invalid URL format.")

    candidate = url.strip()
    if not candidate:
        return _reject("Invalid URL format.")
    if FORBIDDEN_URL_CHARS.search(candidate):
        return _reject("URL contains whitespace, control characters, or backslashes.")

    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        return _reject(f"Failed to parse URL: {exc}")

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return _reject("Only http:// and https:// URLs are permitted.")
    if require_active_scheme and scheme not in ACTIVE_SCHEMES:
        return _reject(
            "Active HTTPS observations are disabled in this local lab. Use an explicit http:// demo target."
        )
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return _reject("URLs containing embedded credentials or user information are prohibited.")
    if not parsed.netloc:
        return _reject("Hostname could not be extracted from URL.")

    raw_hostname = parsed.hostname
    if not raw_hostname:
        return _reject("Hostname could not be extracted from URL.")

    hostname = raw_hostname.lower().rstrip(".")
    if not hostname:
        return _reject("Hostname could not be extracted from URL.")

    try:
        port = parsed.port
    except ValueError:
        return _reject("URL contains an invalid port.")
    if port is None:
        port = 443 if scheme == "https" else 80
    if port < 1 or port > 65535:
        return _reject("URL contains an invalid port.")
    if port not in ALLOWED_PORTS:
        return _reject(f"Port {port} is not in the allowed security test profile port range.")

    try:
        literal_address = ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        literal_address = None

    if literal_address is not None:
        if not _is_allowed_ip(literal_address):
            return _reject(
                f"Forbidden target: Cloud metadata or prohibited address '{hostname}'"
            )
        if hostname not in AUTHORIZED_HOSTS:
            return _reject(
                f"Target '{hostname}' is out of scope. Authorized demonstration targets are limited to: "
                f"{', '.join(sorted(AUTHORIZED_HOSTS))}"
            )
        addresses = (str(literal_address),)
    else:
        encoded_host = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if encoded_host != hostname or not HOSTNAME_PATTERN.match(hostname):
            return _reject("Hostname contains unsupported or ambiguous characters.")
        if hostname not in AUTHORIZED_HOSTS:
            return _reject(
                f"Target '{hostname}' is out of scope. Authorized demonstration targets are limited to: "
                f"{', '.join(sorted(AUTHORIZED_HOSTS))}"
            )
        if not resolve_dns:
            addresses = ()
        else:
            resolved, addresses, reason = _resolve_host(hostname, port)
            if not resolved:
                return _reject(reason)

    netloc = hostname
    if ":" in hostname:
        netloc = f"[{hostname}]"
    if parsed.port is not None:
        netloc = f"{netloc}:{port}"

    path = parsed.path or "/"
    if not path.startswith("/"):
        return _reject("URL path must be absolute.")
    normalized_url = urlunsplit((scheme, netloc, path, parsed.query, ""))

    return ScopeDecision(
        allowed=True,
        reason="Target is verified within authorized lab demonstration scope.",
        normalized_url=normalized_url,
        hostname=hostname,
        port=port,
        resolved_ips=addresses,
    )


def validate_scope(url: str, authorized_confirmation: bool = True) -> Tuple[bool, str]:
    decision = evaluate_scope(url, authorized_confirmation)
    return decision.allowed, decision.reason
