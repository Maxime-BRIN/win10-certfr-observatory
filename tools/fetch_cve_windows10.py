#!/usr/bin/env python3
"""Fetch CVE impacting Windows 10 directly from the NVD API.

This minimal script queries the NVD API for CVE where the CPE matches
"cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*" in a fixed publication
window, then writes a single JSON file to data/cve_windows10.json.

Dependencies: Python 3.11, requests.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

import requests


# --- Configuration ---------------------------------------------------------

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Windows 10 CPE filter (operating system)
WINDOWS10_CPE = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"

# Publication window (UTC dates, inclusive)
COVERAGE_START = dt.date(2025, 10, 14)
COVERAGE_END = dt.date.today()

OUTPUT_PATH = os.path.join("data", "cve_windows10.json")

# Optional: use NVD API key from env if available to improve rate limits
NVD_API_KEY_ENV = "NVD_API_KEY"


# --- Data structures -------------------------------------------------------

@dataclass
class SimpleCVE:
    cve_id: str
    published: str
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    summary: str


# --- Helpers ---------------------------------------------------------------


def iso_date(d: dt.date) -> str:
    return d.isoformat()


def utc_now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def build_nvd_params(start: dt.date, end: dt.date, start_index: int = 0) -> Dict[str, Any]:
    params: Dict[str, Any] = {
        "cpeName": WINDOWS10_CPE,
        "pubStartDate": f"{start.isoformat()}T00:00:00.000Z",
        "pubEndDate": f"{end.isoformat()}T23:59:59.999Z",
        "startIndex": start_index,
        "resultsPerPage": 200,
    }
    return params


def get_nvd_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {"User-Agent": "win10-observatory-simple/1.0"}
    api_key = os.getenv(NVD_API_KEY_ENV)
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_page(start_index: int) -> Dict[str, Any]:
    params = build_nvd_params(COVERAGE_START, COVERAGE_END, start_index=start_index)
    headers = get_nvd_headers()

    # DEBUG: log exact request before calling NVD
    print(f"[DEBUG] NVD URL: {NVD_API_BASE} params={params}")

    resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
    if resp.status_code != 200:
        print(
            f"[ERROR] NVD API returned status {resp.status_code}: {resp.text[:200]}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        data = resp.json()
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[ERROR] Failed to decode NVD response as JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    return data


def extract_cvss_v3(metrics: Dict[str, Any]) -> (Optional[float], Optional[str]):
    # NVD 2.0 may provide several metric collections; try v3.1, then v3.0.
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if not arr:
            continue
        first = arr[0]
        cvss_data = first.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        return score, severity
    return None, None


def extract_summary(descriptions: List[Dict[str, Any]]) -> str:
    # Prefer English description if available.
    if not descriptions:
        return ""
    for d in descriptions:
        if d.get("lang") == "en" and d.get("value"):
            return d["value"].strip()
    # Fallback: first non-empty value
    for d in descriptions:
        val = d.get("value")
        if val:
            return str(val).strip()
    return ""


def parse_cves(payload: Dict[str, Any]) -> List[SimpleCVE]:
    cves: List[SimpleCVE] = []
    vulns = payload.get("vulnerabilities", [])

    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        published = cve.get("published", "")

        metrics = v.get("metrics", {})
        score, severity = extract_cvss_v3(metrics)

        descriptions = cve.get("descriptions", [])
        summary = extract_summary(descriptions)

        cves.append(
            SimpleCVE(
                cve_id=cve_id,
                published=published[:10] if published else "",
                cvss_score=score,
                cvss_severity=severity,
                summary=summary,
            )
        )

    return cves


def fetch_all_cves() -> List[SimpleCVE]:
    all_cves: List[SimpleCVE] = []

    start_index = 0
    total_results: Optional[int] = None

    while True:
        print(f"[INFO] Fetching NVD page at startIndex={start_index}…")
        payload = fetch_page(start_index)

        if total_results is None:
            total_results = payload.get("totalResults", 0)
            print(f"[INFO] NVD reports totalResults={total_results}")

        page_cves = parse_cves(payload)
        all_cves.extend(page_cves)
        print(f"[INFO] Retrieved {len(page_cves)} CVE from this page, {len(all_cves)} total so far.")

        # Pagination: next page if we have more results
        results_per_page = payload.get("resultsPerPage", len(page_cves))
        if results_per_page <= 0:
            break

        start_index += results_per_page
        if total_results is not None and start_index >= total_results:
            break

        # Safety: avoid over-fetching for now; this can be relaxed later if needed.
        if start_index > 2000:
            print("[WARN] Reached pagination safety limit (startIndex > 2000), stopping early.", file=sys.stderr)
            break

    return all_cves


def ensure_output_dir(path: str) -> None:
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def write_output(cves: List[SimpleCVE]) -> None:
    ensure_output_dir(OUTPUT_PATH)

    payload: Dict[str, Any] = {
        "generated_at": utc_now_iso(),
        "coverage_start": iso_date(COVERAGE_START),
        "coverage_end": iso_date(COVERAGE_END),
        "cves": [asdict(c) for c in cves],
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"[INFO] Wrote {len(cves)} CVE entries to {OUTPUT_PATH}")


def main() -> None:
    print(
        f"[INFO] Fetching Windows 10 CVE from NVD between {iso_date(COVERAGE_START)} and {iso_date(COVERAGE_END)} "
        f"for CPE {WINDOWS10_CPE}"
    )

    cves = fetch_all_cves()

    if not cves:
        print("[WARN] No CVE returned by NVD for the given filter.", file=sys.stderr)

    write_output(cves)


if __name__ == "__main__":
    main()
