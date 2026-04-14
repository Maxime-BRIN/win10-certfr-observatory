#!/usr/bin/env python3
"""Build frontend-compatible dataset from NVD Windows 10 CVE data.

Handles both the old schema (cvss_base_score, certfr_url, certfr_id)
and the new schema (cvss_score, cvss_severity, published, reference_url)
so a mixed cve_windows10.json is gracefully normalised.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
NVD_INPUT_PATH = ROOT_DIR / "data" / "cve_windows10.json"
FRONTEND_OUTPUT_PATH = ROOT_DIR / "data" / "windows-10-cve-data.json"


@dataclass
class FrontendCVE:
    cve_id: str
    published_at: str
    cvss_base_score: Optional[float]
    cvss_severity: Optional[str]
    cvss_vector_string: Optional[str]   # <-- vectorString CVSS v3 persisté
    impact_type: str
    windows_10_versions: List[str]
    certfr_url: Optional[str]
    certfr_id: Optional[str]
    reference_url: str


def normalise_severity(score: Optional[float], raw_severity: Optional[str]) -> Optional[str]:
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


def load_nvd_dataset() -> Dict[str, Any]:
    if not NVD_INPUT_PATH.is_file():
        raise FileNotFoundError(f"NVD input dataset not found: {NVD_INPUT_PATH}")
    with NVD_INPUT_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_frontend_dataset(nvd_data: Dict[str, Any]) -> Dict[str, Any]:
    coverage_start = nvd_data.get("coverage_start") or nvd_data.get("dataset", {}).get("coverage_start", "")
    coverage_end = nvd_data.get("coverage_end") or nvd_data.get("dataset", {}).get("coverage_end", "")
    raw_cves = nvd_data.get("cves", [])

    seen: set = set()
    frontend_cves: List[FrontendCVE] = []

    for item in raw_cves:
        cve_id = item.get("cve_id")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)

        # --- Published date ---
        published_raw = item.get("published") or item.get("published_at") or ""
        published = published_raw[:10] if published_raw else ""

        # --- CVSS score ---
        raw_score = item.get("cvss_score") if item.get("cvss_score") is not None else item.get("cvss_base_score")
        try:
            cvss_base = float(raw_score) if raw_score is not None else None
        except (TypeError, ValueError):
            cvss_base = None

        # --- CVSS severity ---
        raw_severity = item.get("cvss_severity")
        cvss_severity = normalise_severity(cvss_base, raw_severity)

        # --- CVSS vector string (v3 prioritaire, sinon v2) ---
        cvss_vector_string: Optional[str] = item.get("cvss_vector_string") or None

        # --- Impact type ---
        impact_type = item.get("impact_type") or "unknown"

        # --- Reference URL ---
        reference_url = (
            item.get("reference_url")
            or item.get("certfr_url")
            or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        )
        if not reference_url:
            reference_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        # --- CERTFR ---
        certfr_url: Optional[str] = item.get("certfr_url") or None
        certfr_id: Optional[str] = item.get("certfr_id") or None

        windows_versions = ["1607", "1709", "1909", "21H2", "22H2"]

        frontend_cves.append(FrontendCVE(
            cve_id=cve_id,
            published_at=published,
            cvss_base_score=cvss_base,
            cvss_severity=cvss_severity,
            cvss_vector_string=cvss_vector_string,
            impact_type=impact_type,
            windows_10_versions=windows_versions,
            certfr_url=certfr_url,
            certfr_id=certfr_id,
            reference_url=reference_url,
        ))

    return {
        "dataset": {
            "coverage_start": coverage_start,
            "coverage_end": coverage_end,
        },
        "cves": [asdict(c) for c in frontend_cves],
    }


def main() -> None:
    nvd_data = load_nvd_dataset()
    frontend_data = build_frontend_dataset(nvd_data)

    FRONTEND_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with FRONTEND_OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(frontend_data, f, ensure_ascii=False, indent=2)

    total = len(frontend_data["cves"])
    with_score = sum(1 for c in frontend_data["cves"] if c["cvss_base_score"] is not None)
    with_vector = sum(1 for c in frontend_data["cves"] if c["cvss_vector_string"] is not None)
    without_score = total - with_score
    print(
        f"[INFO] Built frontend dataset: {total} CVE "
        f"({with_score} with CVSS score, {with_vector} with vector, {without_score} without score)"
        f" → {FRONTEND_OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
