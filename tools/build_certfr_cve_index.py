#!/usr/bin/env python3
# LEGACY / EXPERIMENTAL – plus utilisé par aucun workflow GitHub Actions, conservé pour usage manuel/offline.
import json
import sys
from datetime import datetime, date, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

import requests

BASE_URL = "https://www.cert.ssi.gouv.fr"
AVIS_INDEX_URL = f"{BASE_URL}/avis/json/"
ALERTE_INDEX_URL = f"{BASE_URL}/alerte/json/"

WINDOWS_10_EOS_DATE = "2025-10-14"
USER_AGENT = "win10-certfr-observatory-certfr-index/1.0 (contact: github.com/Maxime-BRIN)"
REQUEST_TIMEOUT = 20


def fetch_json(url: str) -> Any:
    print(f"[INFO] Fetch {url}")
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"[WARN] HTTP error for {url}: {exc}", file=sys.stderr)
        return None

    try:
        return resp.json()
    except ValueError as exc:
        print(f"[WARN] Failed to decode JSON from {url}: {exc}", file=sys.stderr)
        return None


def parse_iso_date(d: str) -> Optional[date]:
    if not d:
        return None
    d = d.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            dt = datetime.strptime(d[: len(fmt)], fmt)
            return dt.date()
        except ValueError:
            continue
    return None


def extract_first_revision_date(revisions: List[Dict[str, Any]]) -> Optional[date]:
    """Prend la date de révision la plus ancienne si disponible."""
    if not revisions:
        return None
    dates: List[date] = []
    for rev in revisions:
        rev_str = rev.get("revision_date")
        d = parse_iso_date(rev_str) if rev_str else None
        if d:
            dates.append(d)
    if not dates:
        return None
    return min(dates)


def extract_doc_first_date(doc: Dict[str, Any]) -> Optional[date]:
    """Logique centralisée pour déterminer la date du doc CERT-FR."""
    revisions = doc.get("revisions", [])
    first_date = extract_first_revision_date(revisions)
    if not first_date:
        fallback = parse_iso_date(doc.get("published_at", ""))
        first_date = fallback
    return first_date


def extract_cves_from_doc(doc: Dict[str, Any]) -> List[str]:
    """Extrait la liste des identifiants CVE depuis un doc JSON CERT-FR.

    Hypothèse :
    "cves": [ {"name": "CVE-2025-12345", ...}, ... ]
    Adapter cette fonction si la structure réelle diffère.
    """
    result: List[str] = []
    for entry in doc.get("cves", []) or []:
        name = entry.get("name")
        if name:
            result.append(name)
    return result


def process_index_entry(doc: Dict[str, Any], source_type: str) -> Optional[Dict[str, Any]]:
    """Convertit un JSON d'avis/alerte en doc intermédiaire minimal.

    Retourne un dict :
    {
      "ref": "CERTFR-...",
      "first_date": date,
      "cves": ["CVE-...", ...],
      "source_type": "avis" / "alerte"
    }
    """
    ref = doc.get("reference")
    if not ref:
        return None

    first_date = extract_doc_first_date(doc)
    if not first_date:
        print(f"[WARN] Impossible de déterminer la date pour {ref}", file=sys.stderr)
        return None

    cves = extract_cves_from_doc(doc)
    if not cves:
        # doc sans CVE, inutile pour notre index
        return None

    return {
        "ref": ref,
        "first_date": first_date,
        "cves": cves,
        "source_type": source_type,
    }


def load_certfr_docs() -> List[Dict[str, Any]]:
    """Charge /avis/json/ et /alerte/json/ en docs intermédiaires (sans filtrage Windows)."""
    docs: List[Dict[str, Any]] = []

    avis_index = fetch_json(AVIS_INDEX_URL)
    if isinstance(avis_index, list):
        for doc in avis_index:
            converted = process_index_entry(doc, "avis")
            if converted:
                docs.append(converted)
    else:
        print("[WARN] Structure inattendue pour /avis/json/ (attendu: liste)", file=sys.stderr)

    alerte_index = fetch_json(ALERTE_INDEX_URL)
    if isinstance(alerte_index, list):
        for doc in alerte_index:
            converted = process_index_entry(doc, "alerte")
            if converted:
                docs.append(converted)
    else:
        print("[WARN] Structure inattendue pour /alerte/json/ (attendu: liste)", file=sys.stderr)

    print(f"[INFO] Docs CERT-FR (avis + alerte) avec CVE: {len(docs)}")
    return docs


def build_certfr_cve_index(
    docs: List[Dict[str, Any]],
    coverage_start: date,
    coverage_end: date,
) -> Dict[str, Dict[str, Any]]:
    """Agrège par CVE toutes les occurrences CERT-FR dans la fenêtre [coverage_start, coverage_end]."""
    by_cve: Dict[str, Dict[str, Any]] = {}

    for doc in docs:
        ref = doc["ref"]
        first_date = doc["first_date"]
        if not (coverage_start <= first_date <= coverage_end):
            continue

        for cve_id in doc["cves"]:
            if cve_id not in by_cve:
                by_cve[cve_id] = {
                    "cve_id": cve_id,
                    "cert_refs": {ref},
                    "first_seen_certfr_date": first_date,
                    "last_seen_certfr_date": first_date,
                }
            else:
                entry = by_cve[cve_id]
                entry["cert_refs"].add(ref)
                if first_date < entry["first_seen_certfr_date"]:
                    entry["first_seen_certfr_date"] = first_date
                if first_date > entry["last_seen_certfr_date"]:
                    entry["last_seen_certfr_date"] = first_date

    print(f"[INFO] CVE uniques dans la fenêtre CERT-FR: {len(by_cve)}")
    return by_cve


def main() -> None:
    coverage_start = date.fromisoformat(WINDOWS_10_EOS_DATE)
    coverage_end = date.today()
    print(f"[INFO] Date EOS Windows 10: {coverage_start}")
    print(f"[INFO] Fenêtre de collecte CERT-FR: {coverage_start} -> {coverage_end}")

    docs = load_certfr_docs()
    cve_index = build_certfr_cve_index(docs, coverage_start, coverage_end)

    now = datetime.now(timezone.utc)

    payload = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "coverage_start": coverage_start.isoformat(),
        "coverage_end": coverage_end.isoformat(),
        "cves": [],
    }

    for cve_id, e in sorted(cve_index.items(), key=lambda kv: kv[0]):
        payload["cves"].append(
            {
                "cve_id": cve_id,
                "cert_refs": sorted(e["cert_refs"]),
                "first_seen_certfr_date": e["first_seen_certfr_date"].isoformat(),
                "last_seen_certfr_date": e["last_seen_certfr_date"].isoformat(),
            }
        )

    out_path = Path(__file__).resolve().parents[1] / "data" / "certfr_cve_index.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[INFO] Écrit {len(payload['cves'])} CVE dans {out_path}")


if __name__ == "__main__":
    main()
