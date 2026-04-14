#!/usr/bin/env python3
"""Fetch CVE impacting Windows 10 directly from the NVD API.

This minimal script queries the NVD API for CVE where the CPE matches
"cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*" in a publication
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

# NVD CVE 2.0 endpoint (documenté)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Windows 10 CPE filter (operating system)
WINDOWS10_CPE = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"

# Global publication window (inclusive, UTC dates)
COVERAGE_START = dt.date(2025, 10, 14)
COVERAGE_END = dt.date.today()

# NVD impose une fenêtre max (120 jours) : on reste en dessous
WINDOW_SLICE_DAYS = 90

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


def build_nvd_params(
    start: Optional[dt.date] = None,
    end: Optional[dt.date] = None,
    start_index: int = 0,
) -> Dict[str, Any]:
    """Build query parameters for NVD CVE 2.0 API.

    Always filters on cpeName (Windows 10).
    Optionally includes a publication date window when both start and end are provided.
    """
    params: Dict[str, Any] = {
        "cpeName": WINDOWS10_CPE,
        "startIndex": start_index,
        "resultsPerPage": 200,
    }

    if start is not None and end is not None:
        # NVD attend des dates ISO étendues (ex: 2025-10-14T00:00:00.000Z)
        params["pubStartDate"] = f"{start.isoformat()}T00:00:00.000Z"
        params["pubEndDate"] = f"{end.isoformat()}T23:59:59.000Z"

    return params


def get_nvd_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {"User-Agent": "win10-observatory-simple/1.0"}
    api_key = os.getenv(NVD_API_KEY_ENV)
    if api_key:
        headers["apiKey"] = api_key
    return headers


def call_nvd_once(params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Perform a single NVD request with given params.

    Returns parsed JSON on 200, None on HTTP error or JSON decode error.
    """
    headers = get_nvd_headers()

    print(f"[DEBUG] NVD URL: {NVD_API_BASE} params={params}")
    try:
        resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
    except requests.RequestException as exc:
        print(f"[ERROR] NVD request failed: {exc}", file=sys.stderr)
        return None

    if resp.status_code != 200:
        snippet = resp.text[:200] if resp.text else ""
        print(
            f"[ERROR] NVD API returned status {resp.status_code}: {snippet}",
            file=sys.stderr,
        )
        return None

    try:
        return resp.json()
    except Exception as exc:
        print(f"[ERROR] Failed to decode NVD response as JSON: {exc}", file=sys.stderr)
        return None


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


def iter_date_slices(start: dt.date, end: dt.date, slice_days: int) -> List[tuple[dt.date, dt.date]]:
    """Yield (slice_start, slice_end) pairs covering [start, end] with windows of at most slice_days."""
    slices: List[tuple[dt.date, dt.date]] = []
    current = start
    delta = dt.timedelta(days=slice_days)

    while current <= end:
        slice_start = current
        slice_end = min(end, slice_start + delta)
        slices.append((slice_start, slice_end))
        current = slice_end + dt.timedelta(days=1)

    return slices


def fetch_cves_for_window(
    window_start: Optional[dt.date],
    window_end: Optional[dt.date],
) -> List[SimpleCVE]:
    """Fetch CVE for a given date window (or no window if both are None), paginating as needed."""
    all_cves: List[SimpleCVE] = []

    start_index = 0
    total_results: Optional[int] = None

    while True:
        params = build_nvd_params(window_start, window_end, start_index=start_index)
        payload = call_nvd_once(params)
        if payload is None:
            # On error, stop for this window.
            break

        if total_results is None:
            total_results = payload.get("totalResults", 0)
            print(f"[INFO] NVD reports totalResults={total_results} for this window")

        page_cves = parse_cves(payload)
        all_cves.extend(page_cves)
        print(f"[INFO] Retrieved {len(page_cves)} CVE from this page, {len(all_cves)} total so far in window.")

        results_per_page = payload.get("resultsPerPage", len(page_cves))
        if results_per_page <= 0:
            break

        start_index += results_per_page
        if total_results is not None and start_index >= total_results:
            break

        if start_index > 2000:
            print(
                "[WARN] Reached pagination safety limit (startIndex > 2000) for this window, stopping early.",
                file=sys.stderr,
            )
            break

    return all_cves


def fetch_all_cves() -> List[SimpleCVE]:
    """Fetch CVE for Windows 10 over the global coverage window, sliced into smaller date ranges.

    Strategy:
    - First, try a simple recent window (last 30 days) to ensure at least one valid call.
    - Then, slice [COVERAGE_START, COVERAGE_END] into 90-day windows and aggregate.
    """
    all_cves: List[SimpleCVE] = []

    # 1. Simple sanity-check window: last 30 days
    recent_end = COVERAGE_END
    recent_start = max(COVERAGE_START, recent_end - dt.timedelta(days=30))
    print(f"[INFO] Fetching sanity window {iso_date(recent_start)} -> {iso_date(recent_end)}")
    sanity_cves = fetch_cves_for_window(recent_start, recent_end)
    all_cves.extend(sanity_cves)

    # 2. Full coverage sliced into safe windows
    print(
        f"[INFO] Fetching full coverage window {iso_date(COVERAGE_START)} -> {iso_date(COVERAGE_END)} "
        f"in slices of {WINDOW_SLICE_DAYS} days"
    )
    slices = iter_date_slices(COVERAGE_START, COVERAGE_END, WINDOW_SLICE_DAYS)
    for slice_start, slice_end in slices:
        print(f"[INFO] Fetching slice {iso_date(slice_start)} -> {iso_date(slice_end)}")
        slice_cves = fetch_cves_for_window(slice_start, slice_end)
        all_cves.extend(slice_cves)

    # Deduplicate by cve_id
    dedup: Dict[str, SimpleCVE] = {}
    for c in all_cves:
        dedup[c.cve_id] = c

    print(f"[INFO] Total unique CVE collected: {len(dedup)}")
    return list(dedup.values())


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
        "cves": [asdict(c) for c in sorted(cves, key=lambda c: c.cve_id)],
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"[INFO] Wrote {len(payload['cves'])} CVE entries to {OUTPUT_PATH}")


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
