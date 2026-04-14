#!/usr/bin/env python3
"""Fetch CVE impacting Windows 10 from the CVE.org (MITRE) API.

Strategy:
  1. Query the CVE.org search endpoint for all CVEs published by
     Microsoft Corporation in the coverage window.
  2. Filter client-side to keep only CVEs whose affected products
     contain "Windows 10".
  3. Fetch each CVE's detail record to extract CVSS metrics, affected
     Windows 10 versions, description, and reference URL.
  4. Write a single JSON file to data/cve_windows10.json.

Dependencies: Python 3.11, requests.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CVE_ORG_SEARCH  = "https://cveawg.mitre.org/api/cve-search"
CVE_ORG_DETAIL  = "https://cveawg.mitre.org/api/cve/{cve_id}"

COVERAGE_START  = dt.date(2025, 10, 14)
COVERAGE_END    = dt.date.today()

OUTPUT_PATH     = os.path.join("data", "cve_windows10.json")

# CVE.org ne throttle pas agressivement, mais on reste poli
DETAIL_SLEEP    = 0.3   # secondes entre chaque requete detail

# Mapping produit -> version courte
VERSION_MAP: Dict[str, str] = {
    "1507": "1507", "1511": "1511", "1607": "1607",
    "1703": "1703", "1709": "1709", "1803": "1803",
    "1809": "1809", "1903": "1903", "1909": "1909",
    "2004": "2004", "20h2": "20H2", "21h2": "21H2", "22h2": "22H2",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SimpleCVE:
    cve_id: str
    published: str
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    impact_type: Optional[str]
    windows_10_versions: List[str] = field(default_factory=list)
    reference_url: str = ""
    summary: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def iso_date(d: dt.date) -> str:
    return d.isoformat()


def utc_now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def parse_windows10_versions(affected: List[Dict[str, Any]]) -> List[str]:
    """Extraire les versions Windows 10 depuis la liste affected de CVE.org."""
    versions: List[str] = []
    for entry in affected:
        product = entry.get("product", "")
        if "windows 10" not in product.lower():
            continue
        # Chercher un token de version connu dans le nom du produit
        product_lower = product.lower()
        for token, label in VERSION_MAP.items():
            if token in product_lower:
                if label not in versions:
                    versions.append(label)
                break
    return sorted(versions)


def extract_cvss_from_cve_org(metrics: List[Dict[str, Any]]) -> tuple[
    Optional[float], Optional[str], Optional[str]
]:
    """Extraire score, severite et impact depuis la liste metrics CVE.org.

    CVE.org place les metriques sous containers.cna.metrics[]
    avec des cles cvssV3_1, cvssV3_0 ou cvssV2_0.
    """
    score: Optional[float] = None
    severity: Optional[str] = None
    vector: Optional[str] = None

    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in m:
                cvss = m[key]
                score    = cvss.get("baseScore")
                severity = cvss.get("baseSeverity")
                vector   = (cvss.get("vectorString") or "").upper()
                break
        if score is not None:
            break

    impact_type: Optional[str] = None
    if vector:
        if "AV:N" in vector:
            impact_type = "RCE"
        elif "AV:L" in vector and ("PR:L" in vector or "PR:H" in vector):
            impact_type = "EoP"
        elif "C:H" in vector and "A:N" in vector:
            impact_type = "InfoLeak"
        elif "A:H" in vector or "A:C" in vector:
            impact_type = "DoS"

    return score, severity, impact_type


def derive_impact_from_summary(summary: str) -> str:
    """Fallback : deriv impact_type depuis le texte du summary."""
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


# ---------------------------------------------------------------------------
# CVE.org API calls
# ---------------------------------------------------------------------------

def fetch_cve_ids_from_cve_org(start: dt.date, end: dt.date) -> List[str]:
    """Lister les CVE IDs Microsoft affectant Windows 10 sur la periode.

    CVE.org /api/cve-search accepte les parametres :
      cna, startDate (YYYY-MM-DD), endDate (YYYY-MM-DD), resultsPerPage.
    On filtre cote client sur les produits contenant 'windows 10'.
    """
    params: Dict[str, Any] = {
        "cna": "Microsoft Corporation",
        "startDate": iso_date(start),
        "endDate": iso_date(end),
        "resultsPerPage": 2000,
    }
    print(f"[INFO] Recherche CVE.org : cna=Microsoft Corporation {iso_date(start)} -> {iso_date(end)}")

    try:
        resp = requests.get(CVE_ORG_SEARCH, params=params, timeout=60)
    except requests.RequestException as exc:
        print(f"[ERROR] CVE.org search failed: {exc}", file=sys.stderr)
        return []

    if resp.status_code != 200:
        print(f"[ERROR] CVE.org search returned HTTP {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
        return []

    try:
        data = resp.json()
    except Exception as exc:
        print(f"[ERROR] CVE.org search JSON decode failed: {exc}", file=sys.stderr)
        return []

    # La reponse peut etre une liste directe ou un objet avec une cle cveRecords/cves
    records: List[Dict[str, Any]] = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        for key in ("cveRecords", "cves", "results", "data"):
            if key in data and isinstance(data[key], list):
                records = data[key]
                break
        if not records:
            # Certaines versions de l'API retournent directement un dict de CVE
            records = [data]

    cve_ids: List[str] = []
    for record in records:
        # Deux formats possibles : {"cveId": ...} ou {"cveMetadata": {"cveId": ...}}
        cve_id = (
            record.get("cveId")
            or (record.get("cveMetadata") or {}).get("cveId")
        )
        if not cve_id:
            continue

        # Filtrer sur les produits Windows 10
        containers = record.get("containers", {})
        cna = containers.get("cna", {})
        affected = cna.get("affected", [])
        has_win10 = any(
            "windows 10" in (e.get("product") or "").lower()
            for e in affected
        )
        if has_win10:
            cve_ids.append(cve_id)

    print(f"[INFO] {len(cve_ids)} CVE Windows 10 identifies sur CVE.org (sur {len(records)} retournes par Microsoft)")
    return cve_ids


def fetch_cve_detail(cve_id: str) -> Optional[SimpleCVE]:
    """Recuperer la fiche complete d'une CVE depuis CVE.org."""
    url = CVE_ORG_DETAIL.format(cve_id=cve_id)
    try:
        resp = requests.get(url, timeout=15)
    except requests.RequestException as exc:
        print(f"[WARN] CVE.org detail fetch failed for {cve_id}: {exc}", file=sys.stderr)
        return None

    if resp.status_code == 404:
        print(f"[WARN] {cve_id} not found on CVE.org (404)", file=sys.stderr)
        return None

    if resp.status_code != 200:
        print(f"[WARN] CVE.org detail for {cve_id} returned HTTP {resp.status_code}", file=sys.stderr)
        return None

    try:
        data = resp.json()
    except Exception as exc:
        print(f"[WARN] CVE.org detail JSON decode failed for {cve_id}: {exc}", file=sys.stderr)
        return None

    # Metadata
    meta = data.get("cveMetadata", {})
    published_raw = meta.get("datePublished") or meta.get("dateReserved") or ""
    published = published_raw[:10] if published_raw else ""

    # Container CNA (source Microsoft)
    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    # CVSS
    metrics = cna.get("metrics", [])
    score, severity, impact_type = extract_cvss_from_cve_org(metrics)

    # Description
    descriptions = cna.get("descriptions", [])
    summary = ""
    for d in descriptions:
        if d.get("lang", "").startswith("en") and d.get("value"):
            summary = d["value"].strip()
            break
    if not summary and descriptions:
        summary = (descriptions[0].get("value") or "").strip()

    # Fallback impact depuis le summary
    if not impact_type:
        impact_type = derive_impact_from_summary(summary)

    # Versions Windows 10 affectees
    affected = cna.get("affected", [])
    windows_10_versions = parse_windows10_versions(affected)

    # URL de reference
    reference_url = f"https://www.cve.org/CVERecord?id={cve_id}"

    return SimpleCVE(
        cve_id=cve_id,
        published=published,
        cvss_score=score,
        cvss_severity=severity,
        impact_type=impact_type,
        windows_10_versions=windows_10_versions,
        reference_url=reference_url,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Main fetch pipeline
# ---------------------------------------------------------------------------

def fetch_all_cves() -> List[SimpleCVE]:
    """Pipeline complet : recherche CVE IDs puis enrichissement detail."""
    cve_ids = fetch_cve_ids_from_cve_org(COVERAGE_START, COVERAGE_END)

    if not cve_ids:
        print("[WARN] Aucun CVE Windows 10 trouve sur CVE.org pour la periode.", file=sys.stderr)
        return []

    print(f"[INFO] Recuperation des details pour {len(cve_ids)} CVE...")
    cves: List[SimpleCVE] = []
    errors = 0

    for i, cve_id in enumerate(cve_ids, 1):
        cve = fetch_cve_detail(cve_id)
        if cve:
            cves.append(cve)
        else:
            errors += 1

        if i % 50 == 0:
            print(f"[INFO] Progression : {i}/{len(cve_ids)} traites, {len(cves)} ok, {errors} echecs")

        time.sleep(DETAIL_SLEEP)

    print(f"[INFO] Fetch termine : {len(cves)}/{len(cve_ids)} CVE recuperes ({errors} echecs)")
    return cves


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

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
        "source": "CVE.org (MITRE)",
        "cves": [asdict(c) for c in sorted(cves, key=lambda c: c.cve_id)],
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"[INFO] Wrote {len(payload['cves'])} CVE entries to {OUTPUT_PATH}")


def main() -> None:
    print(
        f"[INFO] Fetching Windows 10 CVE from CVE.org between "
        f"{iso_date(COVERAGE_START)} and {iso_date(COVERAGE_END)}"
    )
    cves = fetch_all_cves()
    if not cves:
        print("[WARN] No CVE collected — check CVE.org availability.", file=sys.stderr)
    write_output(cves)


if __name__ == "__main__":
    main()
