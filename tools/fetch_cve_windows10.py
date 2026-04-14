#!/usr/bin/env python3
"""Fetch CVE impacting Windows 10 directly from the NVD API.

This minimal script queries the NVD API for CVE where the CPE matches
several explicit Windows 10 x64 CPEs in a publication window, then
writes a single JSON file to data/cve_windows10.json.

Dependencies: Python 3.11, requests.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

import requests


# --- Configuration ---------------------------------------------------------

# NVD CVE 2.0 endpoint (documenté)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Windows 10 CPE filters (explicit x64 variants)
WINDOWS10_CPE_LIST: List[str] = [
    "cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*",
    "cpe:2.3:o:microsoft:windows_10_1709:-:*:*:*:*:*:x64:*",
    "cpe:2.3:o:microsoft:windows_10_1909:-:*:*:*:*:*:x64:*",
    "cpe:2.3:o:microsoft:windows_10:21h2:*:*:*:*:*:x64:*",
    "cpe:2.3:o:microsoft:windows_10:22h2:*:*:*:*:*:x64:*",
]

# Global publication window (inclusive, UTC dates)
COVERAGE_START = dt.date(2025, 10, 14)
COVERAGE_END = dt.date.today()

# NVD impose une fenêtre max (120 jours) : on reste en dessous
WINDOW_SLICE_DAYS = 90

OUTPUT_PATH = os.path.join("data", "cve_windows10.json")

# Optional: use NVD API key from env if available to improve rate limits
NVD_API_KEY_ENV = "NVD_API_KEY"

# Simple rate limit handling for 429 responses
MAX_RETRIES_429 = 3
RETRY_SLEEP_SECONDS = 5

# Sleep entre requêtes d'enrichissement par cveId :
# - Sans clé API : NVD autorise ~5 req/30s → 6.5s minimum
# - Avec clé API : NVD autorise ~50 req/30s → 0.6s suffisant
ENRICH_SLEEP_NO_KEY = 6.5
ENRICH_SLEEP_WITH_KEY = 0.6


# --- Data structures -------------------------------------------------------

@dataclass
class SimpleCVE:
    cve_id: str
    published: str
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    impact_type: Optional[str]
    reference_url: str
    summary: str


# --- Helpers ---------------------------------------------------------------


def iso_date(d: dt.date) -> str:
    return d.isoformat()


def utc_now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def build_nvd_params(
    cpe_name: str,
    start: Optional[dt.date] = None,
    end: Optional[dt.date] = None,
    start_index: int = 0,
) -> Dict[str, Any]:
    """Build query parameters for NVD CVE 2.0 API."""
    params: Dict[str, Any] = {
        "cpeName": cpe_name,
        "startIndex": start_index,
        "resultsPerPage": 200,
    }

    if start is not None and end is not None:
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

    Handles HTTP 429 with a small bounded backoff. Returns parsed JSON on 200,
    None on repeated 429 or other HTTP/JSON errors.
    """
    headers = get_nvd_headers()

    for attempt in range(1, MAX_RETRIES_429 + 1):
        print(f"[DEBUG] NVD URL: {NVD_API_BASE} params={params} (attempt {attempt}/{MAX_RETRIES_429})")
        try:
            resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
        except requests.RequestException as exc:
            print(f"[ERROR] NVD request failed: {exc}", file=sys.stderr)
            return None

        if resp.status_code == 429:
            print(
                f"[WARN] NVD rate limit hit (429), backing off {RETRY_SLEEP_SECONDS}s before retry...",
                file=sys.stderr,
            )
            if attempt == MAX_RETRIES_429:
                print(
                    "[WARN] NVD still returning 429 after max retries; skipping this window/CPE.",
                    file=sys.stderr,
                )
                return None
            time.sleep(RETRY_SLEEP_SECONDS)
            continue

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

    return None


def extract_cvss_and_impact(metrics: Dict[str, Any]) -> tuple[Optional[float], Optional[str], Optional[str]]:
    """Extract a CVSS base score, severity label, and a coarse impact type.

    Prioritises CVSS v3.1, then v3.0, then v2.
    """
    score: Optional[float] = None
    severity: Optional[str] = None
    impact_type: Optional[str] = None

    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if not arr:
            continue
        first = arr[0]
        cvss_data = first.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or first.get("baseSeverity")
        vector = (cvss_data.get("vectorString") or "").upper()
        if "AV:N" in vector or "NETWORK" in vector:
            impact_type = "RCE"
        elif "PR:L" in vector or "PR:H" in vector:
            impact_type = "EoP"
        elif "C:H" in vector and "A:N" in vector:
            impact_type = "InfoLeak"
        elif "A:H" in vector:
            impact_type = "DoS"
        break

    if score is None:
        arr_v2 = metrics.get("cvssMetricV2")
        if arr_v2:
            first_v2 = arr_v2[0]
            cvss_data_v2 = first_v2.get("cvssData", {})
            score = cvss_data_v2.get("baseScore")
            severity = first_v2.get("baseSeverity") or severity
            vector_v2 = (cvss_data_v2.get("vectorString") or "").upper()
            if "AV:N" in vector_v2:
                impact_type = impact_type or "RCE"
            elif "PR:L" in vector_v2 or "PR:H" in vector_v2:
                impact_type = impact_type or "EoP"
            elif "C:C" in vector_v2 and "A:N" in vector_v2:
                impact_type = impact_type or "InfoLeak"
            elif "A:C" in vector_v2:
                impact_type = impact_type or "DoS"

    return score, severity, impact_type


def derive_impact_from_summary(summary: str) -> str:
    """Dériver un impact_type à partir du texte du summary quand CVSS est absent."""
    s = summary.lower()
    if "execute code" in s or "command injection" in s or "remote code execution" in s:
        return "RCE"
    if "elevate privileges" in s or "elevation of privilege" in s:
        return "EoP"
    if "disclose information" in s or "information disclosure" in s:
        return "InfoLeak"
    if "deny service" in s or "denial of service" in s:
        return "DoS"
    if "spoofing" in s:
        return "Spoofing"
    if "bypass" in s or "security feature" in s:
        return "SFB"
    if "tampering" in s:
        return "Tampering"
    return "unknown"


def extract_summary(descriptions: List[Dict[str, Any]]) -> str:
    if not descriptions:
        return ""
    for d in descriptions:
        if d.get("lang") == "en" and d.get("value"):
            return d["value"].strip()
    for d in descriptions:
        val = d.get("value")
        if val:
            return str(val).strip()
    return ""


def extract_reference_url(cve_id: str, refs: List[Dict[str, Any]]) -> str:
    """Pick a reference URL if available, otherwise default to the NVD detail page."""
    for ref in refs or []:
        url = ref.get("url")
        if url:
            return str(url)
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def parse_cves(payload: Dict[str, Any]) -> List[SimpleCVE]:
    cves: List[SimpleCVE] = []
    vulns = payload.get("vulnerabilities", [])

    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        published = cve.get("published", "")

        # Les métriques CVSS sont sous cve["metrics"], pas v["metrics"]
        metrics = cve.get("metrics", {}) or {}
        score, severity, impact_type = extract_cvss_and_impact(metrics)

        descriptions = cve.get("descriptions", [])
        summary = extract_summary(descriptions)

        # Si pas d'impact_type depuis CVSS, dériver depuis le summary
        if not impact_type:
            impact_type = derive_impact_from_summary(summary)

        references = cve.get("references", [])
        ref_url = extract_reference_url(cve_id, references)

        cves.append(
            SimpleCVE(
                cve_id=cve_id,
                published=published[:10] if published else "",
                cvss_score=score,
                cvss_severity=severity,
                impact_type=impact_type,
                reference_url=ref_url,
                summary=summary,
            )
        )

    return cves


def enrich_cvss(cves: List[SimpleCVE]) -> None:
    """Pour les CVE sans score CVSS, interroger NVD par cveId (sans filtre CPE).

    La requête filtrée par cpeName ne retourne pas toujours le bloc metrics.
    Une requête directe par cveId retourne la fiche complète avec les métriques.

    Rate limit NVD :
    - Sans clé API : ~5 req/30s → sleep 6.5s
    - Avec clé API : ~50 req/30s → sleep 0.6s
    """
    to_enrich = [c for c in cves if c.cvss_score is None]
    if not to_enrich:
        print("[INFO] Toutes les CVE ont déjà un score CVSS, pas d'enrichissement nécessaire.")
        return

    api_key = os.getenv(NVD_API_KEY_ENV)
    sleep_duration = ENRICH_SLEEP_WITH_KEY if api_key else ENRICH_SLEEP_NO_KEY
    print(
        f"[INFO] Enrichissement CVSS pour {len(to_enrich)} CVE sans score "
        f"(sleep={sleep_duration}s, clé API={'oui' if api_key else 'non'})..."
    )

    enriched_count = 0
    for c in to_enrich:
        params = {"cveId": c.cve_id}
        payload = call_nvd_once(params)
        if not payload:
            print(f"[WARN] Enrichissement échoué pour {c.cve_id} (NVD non disponible ou 429)", file=sys.stderr)
            continue

        vulns = payload.get("vulnerabilities", [])
        if not vulns:
            continue

        cve_data = vulns[0].get("cve", {})
        metrics = cve_data.get("metrics", {}) or {}

        score, severity, impact_type = extract_cvss_and_impact(metrics)

        if score is not None:
            c.cvss_score = score
            enriched_count += 1
        if severity is not None:
            c.cvss_severity = severity
        if impact_type and (c.impact_type is None or c.impact_type == "unknown"):
            c.impact_type = impact_type

        # Si toujours pas d'impact_type, re-dériver depuis le summary enrichi
        if not c.impact_type or c.impact_type == "unknown":
            summary_enriched = extract_summary(cve_data.get("descriptions", []))
            if summary_enriched:
                c.summary = summary_enriched
            c.impact_type = derive_impact_from_summary(c.summary)

        time.sleep(sleep_duration)

    print(f"[INFO] Enrichissement terminé : {enriched_count}/{len(to_enrich)} CVE ont reçu un score CVSS.")


def iter_date_slices(start: dt.date, end: dt.date, slice_days: int) -> List[tuple[dt.date, dt.date]]:
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
    cpe_name: str,
    window_start: Optional[dt.date],
    window_end: Optional[dt.date],
) -> List[SimpleCVE]:
    """Fetch CVE for a given CPE and date window, paginating as needed."""
    all_cves: List[SimpleCVE] = []
    start_index = 0
    total_results: Optional[int] = None

    while True:
        params = build_nvd_params(cpe_name, window_start, window_end, start_index=start_index)
        payload = call_nvd_once(params)
        if payload is None:
            break

        if total_results is None:
            total_results = payload.get("totalResults", 0)
            print(f"[INFO] NVD reports totalResults={total_results} for this window and CPE {cpe_name}")

        page_cves = parse_cves(payload)
        all_cves.extend(page_cves)
        print(
            f"[INFO] Retrieved {len(page_cves)} CVE from this page, {len(all_cves)} total so far "
            f"for CPE {cpe_name} in window."
        )

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
    """Fetch CVE for Windows 10 over the global coverage window and multiple CPEs."""
    dedup: Dict[str, SimpleCVE] = {}

    for cpe_name in WINDOWS10_CPE_LIST:
        print(f"[INFO] Fetching for CPE {cpe_name}")

        recent_end = COVERAGE_END
        recent_start = max(COVERAGE_START, recent_end - dt.timedelta(days=30))
        print(f"[INFO] Fetching sanity window {iso_date(recent_start)} -> {iso_date(recent_end)} for {cpe_name}")
        sanity_cves = fetch_cves_for_window(cpe_name, recent_start, recent_end)
        for c in sanity_cves:
            dedup[c.cve_id] = c

        print(
            f"[INFO] Fetching full coverage window {iso_date(COVERAGE_START)} -> {iso_date(COVERAGE_END)} "
            f"in slices of {WINDOW_SLICE_DAYS} days for {cpe_name}"
        )
        slices = iter_date_slices(COVERAGE_START, COVERAGE_END, WINDOW_SLICE_DAYS)
        for slice_start, slice_end in slices:
            print(f"[INFO] Fetching slice {iso_date(slice_start)} -> {iso_date(slice_end)} for {cpe_name}")
            slice_cves = fetch_cves_for_window(cpe_name, slice_start, slice_end)
            for c in slice_cves:
                dedup[c.cve_id] = c

    print(f"[INFO] Total unique CVE collected across all CPEs: {len(dedup)}")
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
        f"for CPE list of size {len(WINDOWS10_CPE_LIST)}"
    )

    cves = fetch_all_cves()

    if not cves:
        print("[WARN] No CVE returned by NVD for the given filters.", file=sys.stderr)
    else:
        # Passe d'enrichissement CVSS : requête par cveId pour récupérer les métriques
        # absentes de la réponse filtrée par CPE
        enrich_cvss(cves)

    write_output(cves)


if __name__ == "__main__":
    main()
