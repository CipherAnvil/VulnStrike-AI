#!/usr/bin/env python3
"""VulnStrike AI — Subsystem 2: CVE Technology Fingerprinter.

Fetches an authorized target URL, inspects HTTP response headers (``Server``,
``X-Powered-By``, ``X-Generator``, ``X-AspNet-Version``), HTML ``<meta>`` tags,
and ``<script src="...">`` paths/filenames to identify software technologies and
version numbers. Queries the NIST NVD v2.0 REST API for each detected
technology/version with automatic rate-limit pacing and exponential-backoff
retry handling.

Outputs structured JSON:
    [
      {
        "technology": "nginx",
        "version": "1.18.0",
        "source": "header:Server",
        "cves": [
          {
            "id": "CVE-2021-23017",
            "cvss": 7.7,
            "has_public_exploit": false
          }
        ]
      }
    ]
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from html.parser import HTMLParser
import json
import logging
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests

LOGGER = logging.getLogger("vulnstrike.cve_fingerprinter")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Canonical CPE (vendor, product, part) mappings for common web stack components
KNOWN_CPE_PRODUCTS: dict[str, tuple[str, str, str]] = {
    "apache": ("apache", "http_server", "a"),
    "httpd": ("apache", "http_server", "a"),
    "nginx": ("*", "nginx", "a"),
    "openssl": ("openssl", "openssl", "a"),
    "openssh": ("openbsd", "openssh", "a"),
    "php": ("php", "php", "a"),
    "python": ("python", "python", "a"),
    "werkzeug": ("palletsprojects", "werkzeug", "a"),
    "flask": ("palletsprojects", "flask", "a"),
    "django": ("djangoproject", "django", "a"),
    "gunicorn": ("gunicorn", "gunicorn", "a"),
    "uvicorn": ("encode", "uvicorn", "a"),
    "express": ("expressjs", "express", "a"),
    "node": ("nodejs", "node.js", "a"),
    "node.js": ("nodejs", "node.js", "a"),
    "next.js": ("vercel", "next.js", "a"),
    "nextjs": ("vercel", "next.js", "a"),
    "nuxt": ("nuxt", "nuxt", "a"),
    "jquery": ("jquery", "jquery", "a"),
    "jquery-ui": ("jquery", "jquery_ui", "a"),
    "bootstrap": ("getbootstrap", "bootstrap", "a"),
    "lodash": ("lodash", "lodash", "a"),
    "lodash.js": ("lodash", "lodash", "a"),
    "underscore": ("underscorejs", "underscore", "a"),
    "moment": ("momentjs", "moment", "a"),
    "moment.js": ("momentjs", "moment", "a"),
    "axios": ("axios", "axios", "a"),
    "react": ("facebook", "react", "a"),
    "react-dom": ("facebook", "react", "a"),
    "vue": ("vuejs", "vue.js", "a"),
    "vue.js": ("vuejs", "vue.js", "a"),
    "angular": ("angularjs", "angular.js", "a"),
    "angularjs": ("angularjs", "angular.js", "a"),
    "handlebars": ("handlebarsjs", "handlebars.js", "a"),
    "dompurify": ("cure53", "dompurify", "a"),
    "marked": ("marked", "marked", "a"),
    "wordpress": ("wordpress", "wordpress", "a"),
    "drupal": ("drupal", "drupal", "a"),
    "joomla": ("joomla", "joomla\\!", "a"),
    "tomcat": ("apache", "tomcat", "a"),
    "jetty": ("eclipse", "jetty", "a"),
}

GENERIC_BUNDLE_STEMS: frozenset[str] = frozenset(
    {
        "app",
        "main",
        "index",
        "bundle",
        "vendor",
        "vendors",
        "runtime",
        "chunk",
        "polyfills",
        "scripts",
        "script",
        "common",
        "client",
        "page",
    }
)

PUBLIC_EXPLOIT_DOMAINS: tuple[str, ...] = (
    "exploit-db.com",
    "packetstormsecurity.com",
    "0day.today",
    "rapid7.com/db/modules",
    "metasploit.com",
)

HEADER_TOKEN_RE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9._+-]{1,40})\s*[/ ]\s*v?(?P<version>\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)"
)

META_TECH_RE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9.!_+-]{1,40})\s*(?:[/ ]|\s+v)(?P<version>\d+\.\d+(?:\.\d+)?)"
)

CDN_NPM_RE = re.compile(
    r"/(?:npm|gh)/(@?[A-Za-z0-9._-]+?)@v?(?P<version>\d+\.\d+(?:\.\d+)?)(?:/|$)"
)

CDN_AJAX_LIBS_RE = re.compile(
    r"/ajax/libs/(?P<name>[A-Za-z0-9._-]+)/(?P<version>\d+\.\d+(?:\.\d+)?)/"
)

FILENAME_VERSION_RE = re.compile(
    r"^(?P<name>[A-Za-z][A-Za-z0-9._-]*?)[-.]v?(?P<version>\d+\.\d+(?:\.\d+)?)"
    r"(?:\.(?:min|bundle|slim|production|development|umd|esm))*\.m?js$",
    re.IGNORECASE,
)

CLEAN_STEM_RE = re.compile(
    r"^(?P<name>[A-Za-z][A-Za-z0-9_-]*?)(?:\.(?:min|bundle|slim|production|umd|esm))*\.m?js$",
    re.IGNORECASE,
)

SEMVER_QUERY_RE = re.compile(r"^v?(?P<version>\d+\.\d+(?:\.\d+)?)$")


@dataclass(frozen=True)
class DetectedTech:
    """Represents a single technology and version fingerprinted from a page."""

    technology: str
    version: str
    source: str


class _HTMLTechExtractor(HTMLParser):
    """Lightweight stdlib HTML parser extracting ``<meta>`` and ``<script src>``."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta_tags: list[dict[str, str]] = []
        self.script_srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        lower_tag = tag.lower()
        if lower_tag == "meta":
            self.meta_tags.append(attr_map)
        elif lower_tag == "script" and attr_map.get("src"):
            self.script_srcs.append(attr_map["src"])


def clean_version(raw_version: str) -> str:
    """Strip distribution suffixes (e.g., ``8.1.2-1ubuntu2`` -> ``8.1.2``)."""
    base = raw_version.strip().lstrip("vV")
    return base.split("-", 1)[0].split("+", 1)[0]


def normalize_tech_name(raw_name: str) -> str:
    """Normalize technology display name while stripping trailing punctuation."""
    cleaned = raw_name.strip().rstrip("!").strip()
    if cleaned.lower().endswith(".js") and cleaned.lower() not in {
        "node.js",
        "next.js",
        "vue.js",
    }:
        cleaned = cleaned[:-3]
    if cleaned.lower().endswith(".bundle"):
        cleaned = cleaned[:-7]
    return cleaned


def extract_from_headers(headers: dict[str, str]) -> list[DetectedTech]:
    """Inspect HTTP response headers for technology/version pairs.

    Checks ``Server``, ``X-Powered-By``, ``X-Generator``, and
    ``X-AspNet-Version`` (case-insensitive).

    Args:
        headers: HTTP response headers dictionary.

    Returns:
        List of ``DetectedTech`` entries discovered in headers.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    detected: list[DetectedTech] = []

    inspected_keys = (
        ("server", "header:Server"),
        ("x-powered-by", "header:X-Powered-By"),
        ("x-generator", "header:X-Generator"),
    )

    for key, label in inspected_keys:
        val = lower_headers.get(key)
        if not val:
            continue
        # Strip parenthetical OS hints like "(Ubuntu)" before token matching
        sanitized = re.sub(r"\([^)]*\)", " ", val)
        for match in HEADER_TOKEN_RE.finditer(sanitized):
            tech = normalize_tech_name(match.group("name"))
            ver = clean_version(match.group("version"))
            if tech and ver:
                detected.append(DetectedTech(technology=tech, version=ver, source=label))

    aspnet_ver = lower_headers.get("x-aspnet-version")
    if aspnet_ver:
        ver = clean_version(aspnet_ver)
        if re.match(r"^\d+\.\d+", ver):
            detected.append(
                DetectedTech(
                    technology="ASP.NET",
                    version=ver,
                    source="header:X-AspNet-Version",
                )
            )

    return detected


def extract_from_meta_tags(meta_tags: list[dict[str, str]]) -> list[DetectedTech]:
    """Extract technology/version pairs from HTML ``<meta>`` tags.

    Args:
        meta_tags: Parsed ``<meta>`` attribute dictionaries.

    Returns:
        List of ``DetectedTech`` objects discovered in meta tags.
    """
    relevant_names = {"generator", "application-name", "framework", "cms"}
    detected: list[DetectedTech] = []

    for meta in meta_tags:
        meta_name = meta.get("name", "").lower().strip()
        content = meta.get("content", "").strip()
        if meta_name not in relevant_names or not content:
            continue
        for match in META_TECH_RE.finditer(content):
            tech = normalize_tech_name(match.group("name"))
            ver = clean_version(match.group("version"))
            if tech and ver:
                detected.append(
                    DetectedTech(
                        technology=tech,
                        version=ver,
                        source=f"meta:{meta_name}",
                    )
                )
    return detected


def extract_from_script_srcs(script_srcs: list[str]) -> list[DetectedTech]:
    """Extract JavaScript library names and versions from ``<script src>`` URLs.

    Supports jsDelivr/unpkg ``@version`` paths, cdnjs ``/ajax/libs/<pkg>/<ver>/``
    paths, versioned filenames (e.g. ``jquery-3.4.1.min.js``), and ``?ver=`` /
    ``?v=`` query parameters on non-generic library filenames.

    Args:
        script_srcs: List of ``src`` attribute strings from ``<script>`` tags.

    Returns:
        List of ``DetectedTech`` entries discovered in script URLs.
    """
    detected: list[DetectedTech] = []

    for src in script_srcs:
        parsed = urlparse(src)
        path = parsed.path or ""
        filename = path.rsplit("/", 1)[-1]

        npm_match = CDN_NPM_RE.search(path)
        if npm_match:
            pkg_raw = npm_match.group(1).split("/")[-1]
            tech = normalize_tech_name(pkg_raw)
            ver = clean_version(npm_match.group("version"))
            if tech.lower() not in GENERIC_BUNDLE_STEMS:
                detected.append(
                    DetectedTech(technology=tech, version=ver, source="script:src")
                )
                continue

        cdnjs_match = CDN_AJAX_LIBS_RE.search(path)
        if cdnjs_match:
            tech = normalize_tech_name(cdnjs_match.group("name"))
            ver = clean_version(cdnjs_match.group("version"))
            if tech.lower() not in GENERIC_BUNDLE_STEMS:
                detected.append(
                    DetectedTech(technology=tech, version=ver, source="script:src")
                )
                continue

        file_match = FILENAME_VERSION_RE.match(filename)
        if file_match:
            tech = normalize_tech_name(file_match.group("name"))
            ver = clean_version(file_match.group("version"))
            if tech.lower() not in GENERIC_BUNDLE_STEMS:
                detected.append(
                    DetectedTech(technology=tech, version=ver, source="script:src")
                )
                continue

        # Check ?ver=X.Y.Z or ?v=X.Y.Z on identifiable library script names
        if parsed.query and filename:
            stem_match = CLEAN_STEM_RE.match(filename)
            if stem_match:
                tech = normalize_tech_name(stem_match.group("name"))
                if tech.lower() not in GENERIC_BUNDLE_STEMS:
                    qs = parse_qs(parsed.query)
                    for q_key in ("ver", "version", "v"):
                        for q_val in qs.get(q_key, []):
                            ver_match = SEMVER_QUERY_RE.match(q_val.strip())
                            if ver_match:
                                detected.append(
                                    DetectedTech(
                                        technology=tech,
                                        version=clean_version(ver_match.group("version")),
                                        source="script:src",
                                    )
                                )
                                break

    return detected


def fingerprint_url(
    url: str,
    *,
    session: requests.Session | None = None,
    timeout_sec: float = 15.0,
    verify_tls: bool = True,
) -> list[DetectedTech]:
    """Fetch ``url`` and return deduplicated fingerprinted technologies/versions.

    Args:
        url: Target HTTP(S) URL to inspect.
        session: Optional reusable ``requests.Session``.
        timeout_sec: HTTP request timeout in seconds.
        verify_tls: Verify SSL certificates (set ``False`` for self-signed lab certs).

    Returns:
        Deduplicated list of ``DetectedTech`` instances in discovery order.
    """
    own_session = session is None
    http = session or requests.Session()
    try:
        resp = http.get(
            url,
            timeout=timeout_sec,
            verify=verify_tls,
            headers={"User-Agent": "VulnStrike-TechFingerprinter/1.0"},
        )
        resp.raise_for_status()
    finally:
        if own_session:
            http.close()

    parser = _HTMLTechExtractor()
    content_type = (resp.headers.get("Content-Type") or "").lower()
    if "html" in content_type or "<html" in resp.text[:500].lower():
        parser.feed(resp.text)

    candidates: list[DetectedTech] = []
    candidates.extend(extract_from_headers(dict(resp.headers)))
    candidates.extend(extract_from_meta_tags(parser.meta_tags))
    candidates.extend(extract_from_script_srcs(parser.script_srcs))

    deduped: list[DetectedTech] = []
    seen: set[tuple[str, str]] = set()
    for item in candidates:
        key = (item.technology.lower(), item.version)
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    return deduped


class NVDClient:
    """NIST NVD API v2.0 client with rate-limit pacing, retries, and offline circuit-breaker."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        nvd_base_url: str = NVD_API_URL,
        max_retries: int = 3,
        connect_timeout_sec: float = 3.5,
        timeout_sec: float = 15.0,
        min_interval_sec: float | None = None,
        session: requests.Session | None = None,
    ) -> None:
        """Initialize the NVD v2.0 client.

        Args:
            api_key: Optional NVD API key (50 req/30s vs 5 req/30s without key).
            nvd_base_url: Base endpoint URL for NVD CVE v2.0 REST API.
            max_retries: Maximum retry attempts on HTTP 429/403/5xx responses.
            connect_timeout_sec: Fast TCP/TLS connect timeout in seconds so
                firewalled/air-gapped environments fail fast instead of hanging.
            timeout_sec: Per-request read timeout in seconds once connected.
            min_interval_sec: Explicit minimum spacing between calls; defaults
                to ``0.65s`` with ``api_key`` or ``6.2s`` without ``api_key``.
            session: Optional custom ``requests.Session`` (useful for testing).
        """
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.nvd_base_url = nvd_base_url
        self.max_retries = max_retries
        self.connect_timeout_sec = connect_timeout_sec
        self.timeout_sec = timeout_sec
        self.min_interval_sec = (
            min_interval_sec
            if min_interval_sec is not None
            else (0.65 if self.api_key else 6.2)
        )
        self._last_request_ts: float = 0.0
        self._endpoint_unreachable: bool = False
        self._ever_succeeded: bool = False
        self._owns_session = session is None
        self.session = session or requests.Session()

    @property
    def endpoint_unreachable(self) -> bool:
        """Return ``True`` if outbound connectivity to NVD failed."""
        return self._endpoint_unreachable

    def close(self) -> None:
        """Close underlying HTTP session if owned by this instance."""
        if self._owns_session:
            self.session.close()

    def _pace_request(self) -> None:
        """Sleep if needed to respect NVD's rolling rate limit."""
        if self._last_request_ts > 0 and self.min_interval_sec > 0:
            elapsed = time.monotonic() - self._last_request_ts
            remaining = self.min_interval_sec - elapsed
            if remaining > 0:
                LOGGER.debug("Rate-limit pacing: sleeping %.2fs", remaining)
                time.sleep(remaining)

    def _request_json(self, params: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Issue one NVD API GET request with retries and fast-fail circuit breaker.

        Returns:
            Tuple of ``(response_json_dict, request_reached_server_bool)``.
        """
        if self._endpoint_unreachable:
            return {"vulnerabilities": []}, False

        headers: dict[str, str] = {"User-Agent": "VulnStrike-NVDClient/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        attempt = 0
        connect_retry_cap = min(1, self.max_retries)

        while True:
            if attempt == 0:
                self._pace_request()
            try:
                resp = self.session.get(
                    self.nvd_base_url,
                    params=params,
                    headers=headers,
                    timeout=(self.connect_timeout_sec, self.timeout_sec),
                )
                self._last_request_ts = time.monotonic()
            except (requests.ConnectTimeout, requests.ConnectionError) as exc:
                if attempt >= connect_retry_cap:
                    self._endpoint_unreachable = True
                    LOGGER.warning(
                        "NVD endpoint %s is unreachable (%s); tripping circuit breaker "
                        "to skip remaining outbound NVD calls.",
                        self.nvd_base_url,
                        exc,
                    )
                    return {"vulnerabilities": []}, False
                LOGGER.warning(
                    "NVD connection failed (%s); retrying once in 0.5s...",
                    exc,
                )
                time.sleep(0.5)
                attempt += 1
                continue
            except requests.RequestException as exc:
                effective_cap = connect_retry_cap if not self._ever_succeeded else self.max_retries
                if attempt >= effective_cap:
                    if not self._ever_succeeded:
                        self._endpoint_unreachable = True
                        LOGGER.warning(
                            "NVD endpoint %s timed out/blocked (%s); tripping circuit breaker "
                            "to skip remaining outbound NVD calls.",
                            self.nvd_base_url,
                            exc,
                        )
                    else:
                        LOGGER.warning("NVD request error after %d retries: %s", attempt, exc)
                    return {"vulnerabilities": []}, False
                backoff = 0.5 if not self._ever_succeeded else min(15.0, 2.0 * (2**attempt))
                LOGGER.warning(
                    "NVD request error (%s); retrying in %.1fs (attempt %d/%d)",
                    exc,
                    backoff,
                    attempt + 1,
                    effective_cap,
                )
                time.sleep(backoff)
                attempt += 1
                continue

            self._ever_succeeded = True
            if resp.status_code == 200:
                try:
                    return resp.json(), True
                except ValueError as exc:
                    LOGGER.warning("Invalid JSON from NVD API: %s", exc)
                    return {"vulnerabilities": []}, True

            if resp.status_code in {403, 429, 500, 502, 503, 504}:
                if attempt >= self.max_retries:
                    LOGGER.warning(
                        "NVD returned HTTP %d after %d retries; skipping.",
                        resp.status_code,
                        attempt,
                    )
                    return {"vulnerabilities": []}, True

                retry_after_raw = resp.headers.get("Retry-After")
                if retry_after_raw and retry_after_raw.isdigit():
                    backoff = float(retry_after_raw)
                else:
                    backoff = min(35.0, 6.5 * (2**attempt))

                LOGGER.warning(
                    "NVD HTTP %d (rate-limit/transient); sleeping %.1fs (attempt %d/%d)",
                    resp.status_code,
                    backoff,
                    attempt + 1,
                    self.max_retries,
                )
                time.sleep(backoff)
                attempt += 1
                continue

            # Non-retryable 4xx (e.g., 404 invalid CPE filter) -> server WAS reached
            LOGGER.debug("NVD returned HTTP %d for params %s", resp.status_code, params)
            return {"vulnerabilities": []}, True

    @staticmethod
    def build_virtual_cpe(technology: str) -> str:
        """Construct a CPE 2.3 virtual match string for ``technology``."""
        key = technology.lower().strip()
        if key in KNOWN_CPE_PRODUCTS:
            vendor, product, part = KNOWN_CPE_PRODUCTS[key]
            return f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*"

        slug = re.sub(r"[^a-z0-9._-]+", "_", key).strip("_") or "unknown"
        return f"cpe:2.3:a:*:{slug}:*:*:*:*:*:*:*:*"

    @staticmethod
    def extract_cvss_score(cve_obj: dict[str, Any]) -> float | None:
        """Extract the highest-priority CVSS base score from an NVD CVE item."""
        metrics = cve_obj.get("metrics") or {}
        for metric_key in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            entries = metrics.get(metric_key)
            if not entries or not isinstance(entries, list):
                continue
            # Prefer NVD 'Primary' assessment over secondary assessments
            primary = next(
                (m for m in entries if m.get("type") == "Primary"),
                entries[0],
            )
            score = (primary.get("cvssData") or {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
        return None

    @staticmethod
    def check_has_public_exploit(cve_obj: dict[str, Any]) -> bool:
        """Check NVD reference tags, CISA KEV metadata, and exploit URLs."""
        if cve_obj.get("cisaExploitAdd"):
            return True

        for ref in cve_obj.get("references") or []:
            tags = [str(t).lower() for t in (ref.get("tags") or [])]
            if "exploit" in tags:
                return True
            ref_url = str(ref.get("url") or "").lower()
            if any(domain in ref_url for domain in PUBLIC_EXPLOIT_DOMAINS):
                return True

        return False

    def query_cves_for_tech(
        self,
        technology: str,
        version: str,
        *,
        max_results: int = 25,
    ) -> list[dict[str, Any]]:
        """Query NVD v2.0 for CVEs affecting ``technology`` at ``version``.

        First queries CPE range match via ``virtualMatchString`` +
        ``versionStart``/``versionEnd`` (catches ``versionEndExcluding`` CVEs
        such as ``jQuery < 3.5.0`` for ``3.4.1``), and falls back to
        ``keywordSearch`` if no CPE match exists in NVD.

        Args:
            technology: Detected software name.
            version: Detected version string.
            max_results: Maximum CVEs to include per technology.

        Returns:
            List of ``{"id": ..., "cvss": ..., "has_public_exploit": bool}``
            sorted by CVSS score descending.
        """
        if self._endpoint_unreachable:
            return []

        virtual_cpe = self.build_virtual_cpe(technology)
        cpe_params: dict[str, Any] = {
            "virtualMatchString": virtual_cpe,
            "versionStart": version,
            "versionStartType": "including",
            "versionEnd": version,
            "versionEndType": "including",
            "resultsPerPage": max(1, min(max_results, 100)),
        }
        payload, reached_server = self._request_json(cpe_params)
        raw_vulns = payload.get("vulnerabilities") or []

        # Fallback to keywordSearch ONLY if NVD was reachable and returned 0 CPE matches
        if reached_server and not raw_vulns:
            kw_params: dict[str, Any] = {
                "keywordSearch": f"{technology} {version}",
                "resultsPerPage": max(1, min(max_results, 100)),
            }
            payload, _ = self._request_json(kw_params)
            raw_vulns = payload.get("vulnerabilities") or []

        parsed_cves: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for item in raw_vulns:
            cve = item.get("cve") or {}
            # Skip rejected CVEs
            if str(cve.get("vulnStatus") or "").lower() == "rejected":
                continue
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            parsed_cves.append(
                {
                    "id": cve_id,
                    "cvss": self.extract_cvss_score(cve),
                    "has_public_exploit": self.check_has_public_exploit(cve),
                }
            )

        parsed_cves.sort(
            key=lambda entry: (
                entry["has_public_exploit"],
                entry["cvss"] if entry["cvss"] is not None else -1.0,
            ),
            reverse=True,
        )
        return parsed_cves[:max_results]


def run_cve_fingerprint_scan(
    url: str,
    *,
    api_key: str | None = None,
    nvd_base_url: str = NVD_API_URL,
    max_cves_per_tech: int = 25,
    max_retries: int = 3,
    connect_timeout_sec: float = 3.5,
    timeout_sec: float = 15.0,
    verify_tls: bool = True,
    min_interval_sec: float | None = None,
    offline: bool = False,
) -> list[dict[str, Any]]:
    """Fingerprint ``url`` and enrich every detected technology with NVD CVEs.

    Args:
        url: Authorized target URL to inspect.
        api_key: Optional NVD API key.
        nvd_base_url: NVD v2.0 REST API base URL.
        max_cves_per_tech: Cap on CVEs returned per technology.
        max_retries: Max retry attempts for transient/rate-limit NVD responses.
        connect_timeout_sec: Fast TCP connect timeout for NVD calls in seconds.
        timeout_sec: HTTP read timeout in seconds.
        verify_tls: Verify TLS certificates when fetching ``url``.
        min_interval_sec: Optional override for NVD rate-limit delay.
        offline: If ``True``, skip outbound NVD calls and return fingerprinted
            technologies with empty ``cves`` lists immediately.

    Returns:
        List of technology CVE report dictionaries matching:
        ``[{"technology": ..., "version": ..., "cves": [...]}]``.
    """
    detected_techs = fingerprint_url(
        url,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
    )
    LOGGER.info("Detected %d versioned technology component(s) on %s", len(detected_techs), url)

    if offline:
        LOGGER.info("Offline mode enabled (--offline); skipping external NVD API calls.")
        return [
            {
                "technology": item.technology,
                "version": item.version,
                "source": item.source,
                "cves": [],
            }
            for item in detected_techs
        ]

    nvd = NVDClient(
        api_key=api_key,
        nvd_base_url=nvd_base_url,
        max_retries=max_retries,
        connect_timeout_sec=connect_timeout_sec,
        timeout_sec=timeout_sec,
        min_interval_sec=min_interval_sec,
    )

    results: list[dict[str, Any]] = []
    try:
        for item in detected_techs:
            if not nvd.endpoint_unreachable:
                LOGGER.info(
                    "Querying NVD for %s %s (from %s)",
                    item.technology,
                    item.version,
                    item.source,
                )
            cves = nvd.query_cves_for_tech(
                item.technology,
                item.version,
                max_results=max_cves_per_tech,
            )
            results.append(
                {
                    "technology": item.technology,
                    "version": item.version,
                    "source": item.source,
                    "cves": cves,
                }
            )
    finally:
        nvd.close()

    return results


def save_json_output(data: Any, output_path: Path) -> None:
    """Write CVE report data to ``output_path`` as formatted JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser for standalone orchestrator invocation."""
    parser = argparse.ArgumentParser(
        description="VulnStrike AI — Subsystem 2: CVE Technology Fingerprinter",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL to fingerprint (e.g., http://localhost:8080)",
    )
    parser.add_argument(
        "--nvd-api-key",
        default=None,
        help="Optional NVD API key (defaults to NVD_API_KEY environment variable)",
    )
    parser.add_argument(
        "--nvd-url",
        default=NVD_API_URL,
        help=f"NVD v2.0 CVE endpoint (default: {NVD_API_URL})",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=25,
        help="Maximum CVEs returned per detected technology (default: 25)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retry attempts on NVD rate-limit/5xx errors (default: 3)",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=3.5,
        help="TCP connect timeout in seconds for NVD API (default: 3.5; fast-fails when firewalled)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP read timeout in seconds (default: 15.0)",
    )
    parser.add_argument(
        "--min-interval",
        type=float,
        default=None,
        help="Override minimum seconds between NVD requests (default: 0.65s with key, 6.2s without)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Fingerprint technologies locally without making external NVD API requests",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification when fetching self-signed Docker lab targets",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/cve_report.json"),
        help="Output JSON report path (default: output/cve_report.json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for standalone execution."""
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    try:
        report = run_cve_fingerprint_scan(
            args.url,
            api_key=args.nvd_api_key,
            nvd_base_url=args.nvd_url,
            max_cves_per_tech=max(1, args.max_cves),
            max_retries=max(0, args.max_retries),
            connect_timeout_sec=max(0.5, args.connect_timeout),
            timeout_sec=max(1.0, args.timeout),
            verify_tls=not args.insecure,
            min_interval_sec=args.min_interval,
            offline=args.offline,
        )
        save_json_output(report, args.output)
        total_cves = sum(len(entry["cves"]) for entry in report)
        LOGGER.info(
            "Fingerprinting complete: %d tech(s), %d CVE(s) saved to %s",
            len(report),
            total_cves,
            args.output,
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("CVE Fingerprinter failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
