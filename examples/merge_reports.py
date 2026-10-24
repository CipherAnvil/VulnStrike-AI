#!/usr/bin/env python3
"""Reference helper demonstrating how the VulnStrike AI orchestrator merges outputs.

Reads the JSON output files produced by:
  - crawler.py           -> crawl_report.json
  - cve_fingerprinter.py -> cve_report.json
  - idor_tester.py       -> idor_report.json
  - jwt_inspector.py     -> jwt_report.json
  - xss_verifier.py      -> xss_report.json
and writes a single consolidated JSON report for downstream LLM/reporting modules.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


def _load_optional_json(path: Path) -> Any:
    """Load JSON file if present, otherwise return ``None``."""
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def merge_subsystem_outputs(input_dir: Path, output_file: Path) -> dict[str, Any]:
    """Read individual subsystem JSON reports from ``input_dir`` and merge them."""
    crawl = _load_optional_json(input_dir / "crawl_report.json")
    cves = _load_optional_json(input_dir / "cve_report.json")
    idor = _load_optional_json(input_dir / "idor_report.json")
    jwt_rep = _load_optional_json(input_dir / "jwt_report.json")
    xss = _load_optional_json(input_dir / "xss_report.json")

    merged: dict[str, Any] = {
        "project": "VulnStrike AI",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "subsystems": {
            "crawler": crawl,
            "cve_fingerprinter": cves,
            "auth_exploits": {
                "idor": idor,
                "jwt": jwt_rep,
                "xss": xss,
            },
        },
    }

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(merged, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return merged


def main() -> int:
    """CLI entrypoint for merging subsystem reports."""
    parser = argparse.ArgumentParser(
        description="Merge VulnStrike AI subsystem JSON outputs into one file",
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("output"),
        help="Folder containing individual subsystem JSON outputs (default: output)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/merged_vulnstrike_report.json"),
        help="Consolidated output JSON path",
    )
    args = parser.parse_args()
    merge_subsystem_outputs(args.input_dir, args.output)
    print(f"Merged report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
