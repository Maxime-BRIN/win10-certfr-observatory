#!/usr/bin/env python3
"""Build frontend-compatible dataset from CVE.org Windows 10 CVE data.

Reads data/cve_windows10.json (produced by fetch_cve_windows10.py)
and produces data/windows-10-cve-data.json.

Mapping rules:
- cve_id              <- cve_id
- published_at        <- published
- cvss_base_score     <- cvss_score
- cvss_severity       <- cvss_severity
- exploitation_status <- "unknown"
- impact_type         <- impact_type
- windows_10_versions <- windows_10_versions (liste reelle depuis CVE.org)
- reference_url       <- reference_url (URL CVE.org)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT_DIR             = Path(__file__).resolve().parents[1]
NVD_INPUT_PATH       = ROOT_DIR / "data" / "cve_windows10.json"
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
        raise FileNotFoundError(f"Input dataset not found: {NVD_INPUT_PATH}")
    with NVD_INPUT_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_frontend_dataset(source_data: Dict[str, Any]) -> Dict[str, Any]:
    coverage_start = source_data.get("coverage_start", "")
    coverage_end   = source_data.get("coverage_end", "")
    raw_cves       = source_data.get("cves", [])

    frontend_cves: List[FrontendCVE] = []

    for item in raw_cves:
        cve_id = item.get("cve_id")
        if not cve_id:
            continue

        published = item.get("published") or ""

        score = item.get("cvss_score")
        try:
            cvss_base = float(score) if score is not None else None
        except (TypeError, ValueError):
            cvss_base = None

        cvss_severity = item.get("cvss_severity") or None
        impact_type   = item.get("impact_type") or "unknown"

        # Versions Windows 10 reellement affectees (issues de CVE.org)
        windows_versions: List[str] = item.get("windows_10_versions") or []

        reference_url = (
            item.get("reference_url")
            or f"https://www.cve.org/CVERecord?id={cve_id}"
        )

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
            "source": source_data.get("source", "CVE.org (MITRE)"),
        },
        "cves": [asdict(c) for c in frontend_cves],
    }


def ensure_output_dir(path: Path) -> None:
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def main() -> None:
    source_data   = load_nvd_dataset()
    frontend_data = build_frontend_dataset(source_data)

    ensure_output_dir(FRONTEND_OUTPUT_PATH)
    with FRONTEND_OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(frontend_data, f, ensure_ascii=False, indent=2)

    print(
        f"[INFO] Built frontend dataset with {len(frontend_data['cves'])} CVE entries "
        f"into {FRONTEND_OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
