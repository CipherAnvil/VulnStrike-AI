import re
from typing import Any, Union


SENSITIVE_PATTERNS = [
    (r"(password|passwd|pwd|secret|api[_-]?key|apikey|session|refresh[_-]?token|access[_-]?token)[\"':\s=]+([^\s\"',;}{]+)", r"\1: [REDACTED_SECRET]"),
    (r"Authorization:\s*Bearer\s+[^\s\"']+", "Authorization: Bearer [REDACTED_TOKEN]"),
    (r"(eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+)", "[REDACTED_JWT_TOKEN]"),
    (r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", "[REDACTED_EMAIL]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
]


def sanitize_and_redact(data: Union[str, dict, list, Any]) -> Any:
    """
    Sanitizes log messages, payload strings, headers, and metadata to ensure no
    plaintext credentials, session tokens, or sensitive data escape to reports or storage.
    """
    if isinstance(data, str):
        sanitized = data
        for pattern, replacement in SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        if len(sanitized) > 8192:
            sanitized = sanitized[:8192] + "\n...[TRUNCATED: Exceeded 8KB evidence size boundary]"
        return sanitized

    if isinstance(data, dict):
        cleaned = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(term in key_lower for term in ["password", "passwd", "pwd", "secret", "private_key", "client_secret"]):
                cleaned[key] = "[REDACTED_SENSITIVE_FIELD]"
                continue
            if any(term in key_lower for term in ["token", "auth", "authorization", "cookie", "session"]):
                if isinstance(value, str):
                    cleaned[key] = sanitize_and_redact(value)
                    if cleaned[key] == value and value:
                        cleaned[key] = "[REDACTED_SENSITIVE_FIELD]"
                else:
                    cleaned[key] = "[REDACTED_SENSITIVE_FIELD]"
                continue
            cleaned[key] = sanitize_and_redact(value)
        return cleaned

    if isinstance(data, list):
        return [sanitize_and_redact(item) for item in data]

    return data
