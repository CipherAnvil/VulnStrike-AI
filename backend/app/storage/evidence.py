import re
from typing import Dict, Any, Union

SENSITIVE_PATTERNS = [
    (r"(password|passwd|pwd|secret|token|api_key|apikey|bearer)[\"':\s=]+([a-zA-Z0-9_\-\.\$]{4,})", r"\1: [REDACTED_SECRET]"),
    (r"Authorization:\s*Bearer\s+[a-zA-Z0-9_\-\.]+", "Authorization: Bearer [REDACTED_TOKEN]"),
    (r"(eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+)", "[REDACTED_JWT_TOKEN]")
]

def sanitize_and_redact(data: Union[str, Dict[str, Any], Any]) -> Any:
    """
    Sanitizes log messages, payload strings, headers, and metadata to ensure no
    plaintext credentials, session tokens, or sensitive data escape to reports or storage.
    """
    if isinstance(data, str):
        sanitized = data
        for pattern, replacement in SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        # Content size limiter (max 8KB per string field in evidence summary)
        if len(sanitized) > 8192:
            sanitized = sanitized[:8192] + "\n...[TRUNCATED: Exceeded 8KB evidence size boundary]"
        return sanitized
    
    elif isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if any(term in k.lower() for term in ["password", "secret", "token", "auth", "private_key"]):
                cleaned[k] = "[REDACTED_SENSITIVE_FIELD]"
            else:
                cleaned[k] = sanitize_and_redact(v)
        return cleaned

    elif isinstance(data, list):
        return [sanitize_and_redact(item) for item in data]

    return data
