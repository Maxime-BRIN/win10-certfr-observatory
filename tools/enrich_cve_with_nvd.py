#!/usr/bin/env python3
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, date, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import requests

CERTFR_INDEX_PATH = Path(__file__).resolve().parents[1] / "data" / "certfr_cve_index.json"
WINDOWS10_CVE_PATH = Path(__file__).resolve().parents[1] / "data" / "certfr_windows10_cve.json"
OBSERVATORY_PATH = Path(__file__).resolve().parents[1] / "data" / "certfr_windows10_observatory.json"
NVD_CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "nvd_cache"

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/2.0"
NVD_API_KEY_ENV = "NVD_API_KEY"
USER_AGENT = "win10-certfr-observatory-nvd/1.0 (contact: github.com/Maxime-BRIN)"
REQUEST_TIMEOUT = 20
MAX_RETRIES = 3
RETRY_SLEEP_SECONDS = 3


@dataclass
class CertfrCveIndexEntry:
    cve_id: str
    cert_refs: List[str]
    first_seen_certfr_date: date
    last_seen_certfr_date: date


def load_certfr_index(path: Path) -> Tuple[List[CertfrCveIndexEntry], date, date]:
    if not path.is_file():
        print(f"[ERROR] Fichier d'index CERT-FR introuvable: {path}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(path.read_text(encoding="utf-8"))
    coverage_start = date.fromisoformat(payload["coverage_start"])
    coverage_end = date.fromisoformat(payload["coverage_end"])

    entries: List[CertfrCveIndexEntry] = []
    for item in payload.get("cves", []):
        entries.append(
            CertfrCveIndexEntry(
                cve_id=item["cve_id"],
                cert_refs=list(item["cert_refs"]),
                first_seen_certfr_date=date.fromisoformat(item["first_seen_certfr_date"]),
                last_seen_certfr_date=date.fromisoformat(item["last_seen_certfr_date"]),
            )
        )

    print(f"[INFO] Chargé {len(entries)} CVE depuis {path}")
    return entries, coverage_start, coverage_end


def ensure_cache_dir() -> None:
    NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)


def nvd_cache_path_for(cve_id: str) -> Path:
    return NVD_CACHE_DIR / f"{cve_id}.json"


def fetch_nvd_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Récupère la réponse NVD pour une CVE, avec cache local par fichier."""
    ensure_cache_dir()
    cache_path = nvd_cache_path_for(cve_id)
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            print(f"[INFO] NVD cache hit pour {cve_id}")
            return data
        except ValueError as exc:
            print(f"[WARN] Cache NVD corrompu pour {cve_id}: {exc}", file=sys.stderr)

    params = {"cveId": cve_id}
    headers = {"User-Agent": USER_AGENT}
    api_key = os.getenv(NVD_API_KEY_ENV)
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(1, MAX_RETRIES + 1):
        print(f"[INFO] Fetch NVD {cve_id} (tentative {attempt}/{MAX_RETRIES})")
        try:
            resp = requests.get(
                NVD_BASE_URL,
                params=params,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            print(f"[WARN] Erreur HTTP NVD pour {cve_id}: {exc}", file=sys.stderr)
            time.sleep(RETRY_SLEEP_SECONDS)
            continue

        if resp.status_code == 429 or 500 <= resp.status_code < 600:
            print(
                f"[WARN] NVD rate limit ou erreur serveur ({resp.status_code}) pour {cve_id}, "
                f"sleep {RETRY_SLEEP_SECONDS}s",
                file=sys.stderr,
            )
            time.sleep(RETRY_SLEEP_SECONDS)
            continue

        if not resp.ok:
            print(f"[WARN] NVD renvoie {resp.status_code} pour {cve_id}", file=sys.stderr)
            return None

        try:
            data = resp.json()
        except ValueError as exc:
            print(f"[WARN] JSON NVD invalide pour {cve_id}: {exc}", file=sys.stderr)
            return None

        cache_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return data

    print(f"[WARN] Impossible de récupérer NVD pour {cve_id} après {MAX_RETRIES} tentatives", file=sys.stderr)
    return None


def parse_cpe_uri(cpe: str) -> Optional[Dict[str, str]]:
    """Parse un CPE 2.3 en composantes (part, vendor, product)."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None
    parts = cpe.split(":")
    if len(parts) < 5:
        return None
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
    }


def cpe_is_windows10(cpe: str) -> bool:
    parsed = parse_cpe_uri(cpe)
    if not parsed:
        return False
    return (
        parsed["part"] == "o"
        and parsed["vendor"] == "microsoft"
        and parsed["product"] == "windows_10"
    )


def extract_cpes_from_nvd_record(nvd_record: Dict[str, Any]) -> List[str]:
    """Extrait tous les CPE 'criteria' présents dans la réponse NVD 2.0."""
    cpes: List[str] = []
    for vuln in nvd_record.get("vulnerabilities", []):
        cve_obj = vuln.get("cve", {})
        configs = cve_obj.get("configurations", {})
        for node in configs.get("nodes", []):
            for match in node.get("cpeMatch", []):
                crit = match.get("criteria")
                if crit:
                    cpes.append(crit)
    return cpes


def build_windows10_cve_entries(
    index_entries: List[CertfrCveIndexEntry],
) -> Dict[str, Dict[str, Any]]:
    """Pour chaque CVE, interroge NVD, extrait les CPE et marque is_windows10."""
    result: Dict[str, Dict[str, Any]] = {}

    for entry in index_entries:
        cve_id = entry.cve_id
        nvd_record = fetch_nvd_cve(cve_id)
        if not nvd_record:
            windows10_cpes: List[str] = []
            is_win10 = False
        else:
            cpes = extract_cpes_from_nvd_record(nvd_record)
            windows10_cpes = [c for c in cpes if cpe_is_windows10(c)]
            is_win10 = len(windows10_cpes) > 0

        result[cve_id] = {
            "cve_id": cve_id,
            "cert_refs": sorted(entry.cert_refs),
            "first_seen_certfr_date": entry.first_seen_certfr_date.isoformat(),
            "last_seen_certfr_date": entry.last_seen_certfr_date.isoformat(),
            "is_windows10": is_win10,
            "windows10_cpes": windows10_cpes,
        }
        print(
            f"[INFO] {cve_id}: CERT-FR refs={len(entry.cert_refs)}, "
            f"is_windows10={is_win10}, win10_cpes={len(windows10_cpes)}"
        )

    return result


def build_observatory(
    index_entries: List[CertfrCveIndexEntry],
    windows10_map: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Construit la vue 'par doc CERT-FR' : doc -> liste de CVE avec flag is_windows10."""
    ref_dates: Dict[str, date] = {}
    for entry in index_entries:
        for ref in entry.cert_refs:
            d = entry.first_seen_certfr_date
            if ref not in ref_dates or d < ref_dates[ref]:
                ref_dates[ref] = d

    docs_map: Dict[str, Dict[str, Any]] = {}
    for entry in index_entries:
        for ref in entry.cert_refs:
            doc = docs_map.get(ref)
            if not doc:
                doc = {
                    "cert_ref": ref,
                    "first_date": ref_dates.get(ref).isoformat() if ref in ref_dates else None,
                    "source_type": None,  # TODO: à peupler si tu ajoutes l'info dans l'index
                    "cves": [],
                }
                docs_map[ref] = doc

            win10_info = windows10_map.get(entry.cve_id)
            is_win10 = win10_info["is_windows10"] if win10_info else False
            doc["cves"].append(
                {
                    "cve_id": entry.cve_id,
                    "is_windows10": is_win10,
                }
            )

    return {
        "docs": sorted(docs_map.values(), key=lambda d: d["cert_ref"]),
    }


def main() -> None:
    index_entries, coverage_start, coverage_end = load_certfr_index(CERTFR_INDEX_PATH)
    now = datetime.now(timezone.utc)

    windows10_map = build_windows10_cve_entries(index_entries)

    windows10_payload = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "coverage_start": coverage_start.isoformat(),
        "coverage_end": coverage_end.isoformat(),
        "cves": sorted(
            windows10_map.values(),
            key=lambda e: e["cve_id"],
        ),
    }
    WINDOWS10_CVE_PATH.parent.mkdir(parents=True, exist_ok=True)
    WINDOWS10_CVE_PATH.write_text(
        json.dumps(windows10_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[INFO] Écrit {len(windows10_payload['cves'])} entrées dans {WINDOWS10_CVE_PATH}")

    obs_docs = build_observatory(index_entries, windows10_map)
    observatory_payload = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "coverage_start": coverage_start.isoformat(),
        "coverage_end": coverage_end.isoformat(),
        "docs": obs_docs["docs"],
    }
    OBSERVATORY_PATH.write_text(
        json.dumps(observatory_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[INFO] Écrit {len(observatory_payload['docs'])} docs dans {OBSERVATORY_PATH}")


if __name__ == "__main__":
    main()
