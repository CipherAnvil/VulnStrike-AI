import re
from urllib.parse import urlparse
from typing import Tuple

AUTHORIZED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "demo-target",
    "test-lab.local",
    "vuln-demo.internal"
}

ALLOWED_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8088, 9000, 9090}

DISALLOWED_PATTERNS = [
    r"^169\.254\.", # AWS/GCP/Azure link-local metadata
    r"^metadata\.google\.internal",
    r"^100\.100\.",
    r"^0\.0\.0\.0",
]

def validate_scope(url: str, authorized_confirmation: bool = True) -> Tuple[bool, str]:
    """
    Enforces strict target scope validation for authorized lab environments.
    Guards against external destinations, metadata services, and SSRF.
    """
    if not authorized_confirmation:
        return False, "Target authorization confirmation checkbox is required."
    
    if not url or not isinstance(url, str):
        return False, "Invalid URL format."
    
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    try:
        parsed = urlparse(clean_url)
    except Exception as e:
        return False, f"Failed to parse URL: {str(e)}"

    hostname = parsed.hostname
    if not hostname:
        return False, "Hostname could not be extracted from URL."

    hostname_lower = hostname.lower()

    # Check against disallowed IP / cloud metadata patterns
    for pattern in DISALLOWED_PATTERNS:
        if re.search(pattern, hostname_lower):
            return False, f"Forbidden target: Cloud metadata or prohibited address '{hostname}'"

    # Enforce strict allowlist for lab demonstration
    if hostname_lower not in AUTHORIZED_HOSTS:
        return (
            False,
            f"Target '{hostname}' is out of scope. Authorized demonstration targets are limited to: "
            f"{', '.join(sorted(AUTHORIZED_HOSTS))}"
        )

    # Validate port if present
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        return False, f"Port {port} is not in the allowed security test profile port range."

    return True, "Target is verified within authorized lab demonstration scope."
