#!/usr/bin/env python3
import json
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import requests
from bs4 import BeautifulSoup

BASE_URL = "https://www.cert.ssi.gouv.fr"

HEADERS = {
    "User-Agent": "win10-certfr-observatory-bot/0.2 (contact: github.com/Maxime-BRIN)",
}

WINDOWS_10_KEYWORD = "windows 10"
WINDOWS_10_EOS_DATE = "2025-10-14"


def normalize_text(s: str) -> str:
    if not s:
        return ""
    normalized = "".join(
        c for c in unicodedata.normalize("NFKD", s.lower()) if not unicodedata.combining(c)
    )
    return normalized.replace("\xa0", " ").replace("\u00a0", " ")


def text_contains_windows10(s: str) -> bool:
    return WINDOWS_10_KEYWORD in normalize_text(s)


def fetch_url(path: str) -> BeautifulSoup:
    url = path if path.startswith("http") else BASE_URL + path
    print(f"[INFO] Fetch {url}")
    resp = requests.get(url, headers=HEADERS, timeout=20)
    resp.raise_for_status()
    return BeautifulSoup(resp.text, "html.parser")


def extract_cve_ids(text: str) -> List[str]:
    pattern = r"CVE-\d{4}-\d{4,7}"
    cves = sorted(set(re.findall(pattern, text)))
    return cves


def normalize_exploitation(label: str) -> str:
    if not label:
        return "none"
    l = normalize_text(label)
    if "exploite" in l or "in the wild" in l:
        return "exploited"
    if "poc" in l:
        return "poc"
    return "none"


def parse_avis(slug: str) -> List[Dict]:
    print(f"[INFO] Parsing avis {slug}")
    soup = fetch_url(slug)

    title_tag = soup.find("h1")
    title = title_tag.get_text(strip=True) if title_tag else slug

    text = soup.get_text(" \n", strip=True)
    cve_ids = extract_cve_ids(text)
    print(f"[DEBUG] Avis {slug}: {len(cve_ids)} CVE brutes détectées")

    # trouver la section "Systèmes affectés"
    affected_block_texts: List[str] = []
    for heading_name in ["h2", "h3"]:
        for h in soup.find_all(heading_name):
            if "systemes affectes" in normalize_text(h.get_text(strip=True)):
                # on prend quelques frères suivants raisonnables
                for sib in h.find_all_next(limit=8):
                    if sib.name in {"ul", "ol"}:
                        affected_block_texts.append(sib.get_text(" ", strip=True))
                    elif sib.name == "p":
                        affected_block_texts.append(sib.get_text(" ", strip=True))
                break
    affected_text = " \n".join(affected_block_texts)
    print(f"[DEBUG] Avis {slug}: longueur bloc systèmes affectés = {len(affected_text)} caractères")

    if not text_contains_windows10(affected_text):
        print(f"[DEBUG] Avis {slug}: aucune mention explicite de Windows 10 dans les systèmes affectés")
        return []

    # extraire les lignes / versions Windows 10 depuis le bloc systèmes affectés
    versions: List[str] = []
    for line in affected_text.split("\n"):
        if text_contains_windows10(line):
            versions.append(line.strip())
    versions = sorted(set(versions))

    cvss_score = None
    m = re.search(r"CVSS[^0-9]*([0-9]\.[0-9])", text)
    if m:
        try:
            cvss_score = float(m.group(1))
        except ValueError:
            cvss_score = None

    impact_type = None
    lower_text = normalize_text(text)
    if "execution de code" in lower_text:
        impact_type = "RCE"
    elif "elevation de privilege" in lower_text:
        impact_type = "EoP"
    elif "deni de service" in lower_text:
        impact_type = "DoS"

    published_at = None
    date_el = soup.find(class_=re.compile("date", re.I))
    if date_el:
        published_at = date_el.get_text(strip=True)

    results = []
    for cve in cve_ids:
        results.append(
            {
                "cve_id": cve,
                "title": title,
                "published_at": published_at,
                "impact_type": impact_type,
                "cvss_base_score": cvss_score,
                "exploitation_status": "none",
                "windows_10_versions": versions,
                "affected_products_raw": [affected_text] if affected_text else [],
                "certfr_id": slug.strip("/").split("/")[-1],
                "certfr_url": BASE_URL + slug,
                "source_type": "avis",
                "references": [BASE_URL + slug],
            }
        )

    print(f"[INFO] Avis {slug}: {len(results)} CVE Windows 10 retenues après filtrage")
    return results


def parse_actualite(slug: str) -> List[Dict]:
    print(f"[INFO] Parsing actualité {slug}")
    soup = fetch_url(slug)

    tables = soup.find_all("table")
    if not tables:
        print(f"[DEBUG] Actualité {slug}: aucune table trouvée")
        return []

    results: List[Dict] = []
    for idx, table in enumerate(tables):
        header_cells = table.find_all("th")
        header = [normalize_text(th.get_text(strip=True)) for th in header_cells]
        if not header:
            continue
        # on cherche une table avec au moins produit + cve
        try:
            produit_idx = next(i for i, h in enumerate(header) if "produit" in h)
            cve_idx = next(i for i, h in enumerate(header) if "cve" in h)
        except StopIteration:
            continue

        cvss_idx = next((i for i, h in enumerate(header) if "cvss" in h), None)
        type_idx = next((i for i, h in enumerate(header) if "type" in h), None)
        expl_idx = next((i for i, h in enumerate(header) if "exploit" in h), None)

        rows = table.find_all("tr")
        for row in rows[1:]:
            cells = [td.get_text(" ", strip=True) for td in row.find_all("td")]
            if len(cells) < max(produit_idx, cve_idx) + 1:
                continue

            produit = cells[produit_idx]
            if not text_contains_windows10(produit):
                continue

            cve_text = cells[cve_idx]
            cve_ids = extract_cve_ids(cve_text)
            if not cve_ids:
                continue

            cvss_score = None
            if cvss_idx is not None and cvss_idx < len(cells):
                m = re.search(r"([0-9]\.[0-9])", cells[cvss_idx])
                if m:
                    try:
                        cvss_score = float(m.group(1))
                    except ValueError:
                        pass

            impact_type = None
            if type_idx is not None and type_idx < len(cells):
                impact_type = cells[type_idx] or None

            exploitation_status = "none"
            if expl_idx is not None and expl_idx < len(cells):
                exploitation_status = normalize_exploitation(cells[expl_idx])

            for cve in cve_ids:
                results.append(
                    {
                        "cve_id": cve,
                        "title": produit,
                        "published_at": None,
                        "impact_type": impact_type,
                        "cvss_base_score": cvss_score,
                        "exploitation_status": exploitation_status,
                        "windows_10_versions": [produit.strip()],
                        "affected_products_raw": [produit],
                        "certfr_id": slug.strip("/").split("/")[-1],
                        "certfr_url": BASE_URL + slug,
                        "source_type": "actualite",
                        "references": [BASE_URL + slug],
                    }
                )

    print(f"[INFO] Actualité {slug}: {len(results)} CVE Windows 10 retenues après filtrage")
    return results


def deduplicate(entries: List[Dict]) -> List[Dict]:
    by_cve: Dict[str, Dict] = {}
    for e in entries:
        cve = e["cve_id"]
        if cve not in by_cve:
            e["references"] = list(sorted(set(e.get("references", []))))
            by_cve[cve] = e
            continue

        existing = by_cve[cve]
        for key in ["windows_10_versions", "affected_products_raw", "references"]:
            merged = set(existing.get(key, [])) | set(e.get(key, []))
            existing[key] = sorted(merged)

        if not existing.get("cvss_base_score") and e.get("cvss_base_score"):
            existing["cvss_base_score"] = e["cvss_base_score"]
        if not existing.get("impact_type") and e.get("impact_type"):
            existing["impact_type"] = e["impact_type"]
        if existing.get("exploitation_status") == "none" and e.get("exploitation_status") in {"poc", "exploited"}:
            existing["exploitation_status"] = e["exploitation_status"]

        by_cve[cve] = existing
    return list(by_cve.values())


def main() -> None:
    # périmètre réduit mais explicite
    avis_slugs = [
        "/avis/CERTFR-2025-AVI-1092/",
    ]
    actualite_slugs = [
        "/actualite/CERTFR-2026-ACT-007/",
    ]

    raw_entries: List[Dict] = []

    for slug in avis_slugs:
        try:
            entries = parse_avis(slug)
            raw_entries.extend(entries)
        except Exception as exc:
            print(f"[WARN] Échec de parsing pour {slug}: {exc}", file=sys.stderr)

    for slug in actualite_slugs:
        try:
          	entries = parse_actualite(slug)
            raw_entries.extend(entries)
        except Exception as exc:
            print(f"[WARN] Échec de parsing pour {slug}: {exc}", file=sys.stderr)

    print(f"[INFO] Total brut toutes sources (après filtrage Windows 10 par page): {len(raw_entries)} CVE")

    if not raw_entries:
        print(
            "[WARN] Aucune CVE Windows 10 trouvée : vérifier le parsing ou étendre le périmètre de pages.",
            file=sys.stderr,
        )

    deduped = deduplicate(raw_entries)
    print(f"[INFO] Après déduplication par CVE: {len(deduped)} entrées")

    now = datetime.now(timezone.utc)
    coverage_start = WINDOWS_10_EOS_DATE
    coverage_end = now.date().isoformat()

    dataset = {
        "dataset": {
            "name": "Observatoire Windows 10 / CERT-FR (données réelles)",
            "version": "0.3.0",
            "generated_at": now.isoformat().replace("+00:00", "Z"),
            "coverage_start": coverage_start,
            "coverage_end": coverage_end,
            "windows_10_eos_date": WINDOWS_10_EOS_DATE,
            "methodology_summary": (
                "Jeu de données construit automatiquement à partir d'avis et de bulletins d'actualité CERT-FR "
                "qui mentionnent explicitement Windows 10 dans les systèmes ou produits affectés. "
                "Les vulnérabilités sont regroupées par identifiant CVE et enrichies avec leurs références CERT-FR."
            ),
            "limitations": [
                "Le périmètre est limité aux pages CERT-FR explicitement parcourues par le script.",
                "Seules les vulnérabilités mentionnant textuellement Windows 10 sont retenues, sans extrapolation à partir de libellés génériques (par exemple 'Microsoft Windows').",
                "Les données peuvent être incomplètes ou obsolètes si la structure des pages CERT-FR évolue.",
                "Ce jeu de données ne remplace pas un inventaire de parc, un scanner de vulnérabilités ni une analyse de risque détaillée.",
            ],
        },
        "cves": [],
    }

    for e in deduped:
        cve_obj = {
            "cve_id": e["cve_id"],
            "title": e.get("title"),
            "published_at": e.get("published_at"),
            "impact_type": e.get("impact_type"),
            "cvss_base_score": e.get("cvss_base_score"),
            "exploitation_status": e.get("exploitation_status", "none"),
            "windows_10_versions": e.get("windows_10_versions", []),
            "affected_products_raw": e.get("affected_products_raw", []),
            "certfr_id": e.get("certfr_id"),
            "certfr_url": e.get("certfr_url"),
            "source_type": e.get("source_type"),
            "references": e.get("references", []),
            "dedup_key": e["cve_id"],
        }
        dataset["cves"].append(cve_obj)

    out_path = Path(__file__).resolve().parents[1] / "data" / "windows-10-certfr-data.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(dataset, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Écrit {len(dataset['cves'])} CVE dans {out_path}")


if __name__ == "__main__":
    main()
