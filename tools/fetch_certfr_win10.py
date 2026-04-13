#!/usr/bin/env python3
import json
import sys
import unicodedata
import re
from datetime import datetime, date, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

import requests

BASE_URL = "https://www.cert.ssi.gouv.fr"
AVIS_INDEX_URL = f"{BASE_URL}/avis/json/"
ALERTE_INDEX_URL = f"{BASE_URL}/alerte/json/"

WINDOWS_10_EOS_DATE = "2025-10-14"
USER_AGENT = "win10-certfr-observatory-avi-ale/1.0 (contact: github.com/Maxime-BRIN)"
REQUEST_TIMEOUT = 20


def normalize_text(s: str) -> str:
    """Minuscule + suppression des accents + normalisation espaces."""
    if not s:
        return ""
    nfkd = unicodedata.normalize("NFKD", s)
    no_accents = "".join(c for c in nfkd if not unicodedata.combining(c))
    s2 = no_accents.lower()
    s2 = s2.replace("\u00a0", " ").replace("\xa0", " ")
    return " ".join(s2.split())


def is_windows10(system_string: str) -> bool:
    """Détecte si une chaîne décrit clairement une version de Windows 10.

    Règle de base :
    - Normalisation (lower, sans accents, espaces compressés).
    - Présence du motif 'windows 10' (avec espaces facultatifs) -> True.

    Exemples inclus :
      - 'Microsoft Windows 10'
      - 'Microsoft Windows 10 version 21H2'
      - 'Windows 10 Enterprise'
      - 'Windows 10, Windows 11' -> True (Windows 10 est explicitement cité)

    Cas non inclus automatiquement :
      - 'Microsoft Windows'
      - 'Microsoft Windows (toutes versions)'
    """
    if not system_string:
        return False
    n = normalize_text(system_string)
    return bool(re.search(r"windows\s*10", n))


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


def extract_affected_system_descriptions(doc: Dict[str, Any]) -> List[str]:
    """Extrait des descriptions textuelles des systèmes affectés.

    Hypothèse sur la structure JSON :
    {
      "affected_systems": [
        {
          "description": "...",
          "product": {"name": "...", "vendor": {"name": "..."}}
        },
        ...
      ]
    }
    Adapter cette fonction si la structure réelle diffère.
    """
    systems: List[str] = []
    for entry in doc.get("affected_systems", []):
        desc = entry.get("description") or ""
        product = entry.get("product") or {}
        product_name = product.get("name") or ""
        vendor = product.get("vendor") or {}
        vendor_name = vendor.get("name") or ""
        parts = [vendor_name, product_name, desc]
        txt = " - ".join(p for p in parts if p)
        if txt:
            systems.append(txt)
    return systems


def extract_cves_from_doc(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extrait la liste brute d'objets CVE depuis un doc JSON.

    Hypothèse :
    "cves": [ {"name": "CVE-2025-36097", "url": "https://..."}, ... ]
    """
    return doc.get("cves", []) or []


def process_index_entry(doc: Dict[str, Any], source_type: str) -> Optional[Dict[str, Any]]:
    """Convertit un avis/alerte JSON en structure intermédiaire exploitable.

    Retourne un dict :
    {
      "ref": "CERTFR-...",
      "first_date": date,
      "systems": [...],
      "cves": [...],
      "url": "https://.../avis/CERTFR-.../" ou ".../alerte/.../",
      "source_type": "avis" ou "alerte"
    }
    """
    ref = doc.get("reference")
    if not ref:
        return None

    revisions = doc.get("revisions", [])
    first_date = extract_first_revision_date(revisions)
    if not first_date:
        fallback = parse_iso_date(doc.get("published_at", ""))
        first_date = fallback

    if not first_date:
        print(f"[WARN] Impossible de déterminer la date pour {ref}", file=sys.stderr)
        return None

    systems = extract_affected_system_descriptions(doc)
    cves = extract_cves_from_doc(doc)
    if not cves:
        return None

    if source_type == "avis":
        url = f"{BASE_URL}/avis/{ref}/"
    else:
        url = f"{BASE_URL}/alerte/{ref}/"

    return {
        "ref": ref,
        "first_date": first_date,
        "systems": systems,
        "cves": cves,
        "url": url,
        "source_type": source_type,
    }


def load_avis_and_alerte() -> List[Dict[str, Any]]:
    """Charge /avis/json/ et /alerte/json/ et retourne les docs avec CVE."""
    all_docs: List[Dict[str, Any]] = []

    avis_index = fetch_json(AVIS_INDEX_URL)
    if isinstance(avis_index, list):
        for doc in avis_index:
            converted = process_index_entry(doc, "avis")
            if converted:
                all_docs.append(converted)
    else:
        print("[WARN] Structure inattendue pour /avis/json/ (attendu: liste)", file=sys.stderr)

    alerte_index = fetch_json(ALERTE_INDEX_URL)
    if isinstance(alerte_index, list):
        for doc in alerte_index:
            converted = process_index_entry(doc, "alerte")
            if converted:
                all_docs.append(converted)
    else:
        print("[WARN] Structure inattendue pour /alerte/json/ (attendu: liste)", file=sys.stderr)

    print(f"[INFO] Docs indexés (avis + alerte) avec CVE: {len(all_docs)}")
    return all_docs


def build_windows10_cve_entries(
    docs: List[Dict[str, Any]],
    coverage_start: date,
    coverage_end: date,
) -> Dict[str, Dict[str, Any]]:
    """Construit un mapping cve_id -> entrée agrégée pour Windows 10 post-EOS."""
    by_cve: Dict[str, Dict[str, Any]] = {}

    for doc in docs:
        ref = doc["ref"]
        first_date = doc["first_date"]
        systems = doc["systems"]
        source_type = doc["source_type"]
        url = doc["url"]

        if not (coverage_start <= first_date <= coverage_end):
            continue

        windows10_systems = [s for s in systems if is_windows10(s)]
        if not windows10_systems:
            continue

        for cve_entry in doc["cves"]:
            cve_id = cve_entry.get("name")
            if not cve_id:
                continue

            if cve_id not in by_cve:
                by_cve[cve_id] = {
                    "cve_id": cve_id,
                    "first_seen_date": first_date,
                    "windows10_systems": set(windows10_systems),
                    "certfr_refs": {ref},
                    "source_types": {source_type},
                    "certfr_urls": {url},
                    "cvss_base_score": None,
                }
            else:
                e = by_cve[cve_id]
                if first_date < e["first_seen_date"]:
                    e["first_seen_date"] = first_date
                e["windows10_systems"].update(windows10_systems)
                e["certfr_refs"].add(ref)
                e["source_types"].add(source_type)
                e["certfr_urls"].add(url)

    print(f"[INFO] CVE Windows 10 post-EOS agrégées: {len(by_cve)}")
    return by_cve


def main() -> None:
    coverage_start = date.fromisoformat(WINDOWS_10_EOS_DATE)
    coverage_end = date.today()
    print(f"[INFO] Date EOS Windows 10: {coverage_start}")
    print(f"[INFO] Fenêtre de collecte (AVI + ALE): {coverage_start} -> {coverage_end}")

    docs = load_avis_and_alerte()
    cve_map = build_windows10_cve_entries(docs, coverage_start, coverage_end)

    now = datetime.now(timezone.utc)

    dataset: Dict[str, Any] = {
        "dataset": {
            "name": "Observatoire Windows 10 / CERT-FR (AVI + ALE JSON)",
            "version": "1.0.0",
            "generated_at": now.isoformat().replace("+00:00", "Z"),
            "coverage_start": coverage_start.isoformat(),
            "coverage_end": coverage_end.isoformat(),
            "windows_10_eos_date": WINDOWS_10_EOS_DATE,
            "methodology_summary": (
                "Jeu de données construit automatiquement à partir des endpoints JSON "
                "des avis (/avis/json/) et des alertes (/alerte/json/) du CERT-FR. "
                "Les documents sont filtrés pour ne conserver que ceux publiés après "
                "la fin de support de Windows 10 (14/10/2025) et mentionnant "
                "explicitement Windows 10 dans les systèmes affectés. Les "
                "vulnérabilités sont agrégées par identifiant CVE."
            ),
            "limitations": [
                "Le périmètre est limité aux avis et alertes exposés via les endpoints JSON du CERT-FR.",
                "La détection de Windows 10 repose sur une heuristique simple cherchant le motif 'Windows 10' "
                "dans les descriptions de systèmes affectés après normalisation.",
                "Les vulnérabilités Microsoft Windows génériques où Windows 10 n'est pas nommé ne sont pas incluses.",
                "La structure JSON des endpoints peut évoluer, ce qui peut nécessiter une adaptation du script.",
                "Ce jeu de données ne remplace pas un inventaire de parc, un scanner de vulnérabilités ou une "
                "analyse de risque détaillée.",
            ],
        },
        "cves": [],
    }

    for cve_id, e in sorted(cve_map.items(), key=lambda kv: kv[0]):
        dataset["cves"].append(
            {
                "cve_id": cve_id,
                "first_seen_date": e["first_seen_date"].isoformat(),
                "windows10_systems": sorted(e["windows10_systems"]),
                "certfr_refs": sorted(e["certfr_refs"]),
                "source_types": sorted(e["source_types"]),
                "certfr_urls": sorted(e["certfr_urls"]),
                "cvss_base_score": e["cvss_base_score"],
            }
        )

    out_path = Path(__file__).resolve().parents[1] / "data" / "windows-10-certfr-data.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(dataset, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[INFO] Écrit {len(dataset['cves'])} CVE dans {out_path}")


if __name__ == "__main__":
    main()
