#!/usr/bin/env python3
"""Build frontend-compatible dataset from NVD Windows 10 CVE data.

This script reads data/cve_windows10.json (NVD-oriented schema) and
produces data/windows-10-cve-data.json matching the legacy frontend
schema expected by index.html.

Mapping rules (fixed by design):
- cve_id              <- cve_id
- published_at        <- published
- cvss_base_score     <- cvss_score
- exploitation_status <- "unknown"
- impact_type         <- impact_type
- windows_10_versions <- derived from the CPE variants we query (1607/1709/1909/21H2/22H2)
- reference_url       <- reference_url (URL NVD ou première référence disponible)

Note : les champs certfr_url et certfr_id ont été supprimés car toujours vides.
reference_url les remplace avec l'URL NVD de la CVE.

The script does *not* modify data/cve_windows10.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List

# Paths
ROOT_DIR = Path(__file__).resolve().parents[1]
NVD_INPUT_PATH = ROOT_DIR / "data" / "cve_windows10.json"
FRONTEND_OUTPUT_PATH = ROOT_DIR / "data" / "windows-10-cve-data.json"


@dataclass
class FrontendCVE:
    cve_id: str
    published_at: str
    cvss_base_score: float | None
    exploitation_status: str
    impact_type: str
    windows_10_versions: List[str]
    reference_url: str


def load_nvd_dataset() -> Dict[str, Any]:
    if not NVD_INPUT_PATH.is_file():
        raise FileNotFoundError(f"NVD input dataset not found: {NVD_INPUT_PATH}")
    with NVD_INPUT_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


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
        score = item.get("cvss_score")
        try:
            cvss_base = float(score) if score is not None else None
        except (TypeError, ValueError):
            cvss_base = None

        impact_type = item.get("impact_type") or "unknown"
        # reference_url contient l'URL NVD ou la première référence de la CVE
        reference_url = item.get("reference_url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        # TODO: when per-CPE info is available, derive versions precisely.
        windows_versions = ["1607", "1709", "1909", "21H2", "22H2"]

        frontend_cves.append(
            FrontendCVE(
                cve_id=cve_id,
                published_at=published,
                cvss_base_score=cvss_base,
                exploitation_status="unknown",
                impact_type=impact_type,
                windows_10_versions=windows_versions,
                reference_url=reference_url,
            )
        )

    dataset = {
        "coverage_start": coverage_start,
        "coverage_end": coverage_end,
    }

    return {
        "dataset": dataset,
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

    print(
        f"[INFO] Built frontend dataset with {len(frontend_data['cves'])} CVE entries "
        f"into {FRONTEND_OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
