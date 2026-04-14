#!/usr/bin/env python3
"""Build frontend-compatible dataset from NVD Windows 10 CVE data.

This script reads data/cve_windows10.json (NVD-oriented schema) and
produces data/windows-10-cve-data.json matching the frontend schema
expected by index.html.

Mapping rules:
- cve_id              <- cve_id
- published_at        <- published
- cvss_base_score     <- cvss_score  (float or null)
- cvss_severity       <- cvss_severity (str or null: CRITICAL/HIGH/MEDIUM/LOW/NONE)
- exploitation_status <- "unknown"
- impact_type         <- impact_type
- windows_10_versions <- derived from the CPE variants we query
- reference_url       <- reference_url (NVD URL or first available reference)

The script does *not* modify data/cve_windows10.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

# Paths
ROOT_DIR = Path(__file__).resolve().parents[1]
NVD_INPUT_PATH = ROOT_DIR / "data" / "cve_windows10.json"
FRONTEND_OUTPUT_PATH = ROOT_DIR / "data" / "windows-10-cve-data.json"


@dataclass
class FrontendCVE:
    cve_id: str
    published_at: str
    cvss_base_score: Optional[float]
    cvss_severity: Optional[str]
    exploitation_status: str
    impact_type: str
    windows_10_versions: List[str]
    reference_url: str


def load_nvd_dataset() -> Dict[str, Any]:
    if not NVD_INPUT_PATH.is_file():
        raise FileNotFoundError(f"NVD input dataset not found: {NVD_INPUT_PATH}")
    with NVD_INPUT_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def normalise_severity(score: Optional[float], raw_severity: Optional[str]) -> Optional[str]:
    """Return a canonical CVSS v3 severity label.

    Priority:
    1. Use raw_severity from NVD if it is a known label.
    2. Derive from score using official CVSS v3 thresholds.
    3. Return None if neither is available.
    """
    known = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if raw_severity and raw_severity.upper() in known:
        return raw_severity.upper()
    if score is None:
        return None
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def build_frontend_dataset(nvd_data: Dict[str, Any]) -> Dict[str, Any]:
    coverage_start = nvd_data["coverage_start"]
    coverage_end = nvd_data["coverage_end"]
    raw_cves = nvd_data.get("cves", [])

    frontend_cves: List[FrontendCVE] = []

    for item in raw_cves:
        cve_id = item.get("cve_id")
        if not cve_id:
            continue

        published = item.get("published") or ""

        # cvss_score is the canonical field written by fetch_cve_windows10.py
        raw_score = item.get("cvss_score")
        try:
            cvss_base = float(raw_score) if raw_score is not None else None
        except (TypeError, ValueError):
            cvss_base = None

        raw_severity = item.get("cvss_severity")
        cvss_severity = normalise_severity(cvss_base, raw_severity)

        impact_type = item.get("impact_type") or "unknown"

        reference_url = (
            item.get("reference_url")
            or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        )

        windows_versions = ["1607", "1709", "1909", "21H2", "22H2"]

        frontend_cves.append(
            FrontendCVE(
                cve_id=cve_id,
                published_at=published,
                cvss_base_score=cvss_base,
                cvss_severity=cvss_severity,
                exploitation_status="unknown",
                impact_type=impact_type,
                windows_10_versions=windows_versions,
                reference_url=reference_url,
            )
        )

    return {
        "dataset": {
            "coverage_start": coverage_start,
            "coverage_end": coverage_end,
        },
        "cves": [asdict(c) for c in frontend_cves],
    }


def ensure_output_dir(path: Path) -> None:
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def main() -> None:
    nvd_data = load_nvd_dataset()
    frontend_data = build_frontend_dataset(nvd_data)

    ensure_output_dir(FRONTEND_OUTPUT_PATH)
    with FRONTEND_OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(frontend_data, f, ensure_ascii=False, indent=2)

    total = len(frontend_data["cves"])
    with_score = sum(1 for c in frontend_data["cves"] if c["cvss_base_score"] is not None)
    print(
        f"[INFO] Built frontend dataset: {total} CVE entries "
        f"({with_score} with CVSS score) → {FRONTEND_OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
