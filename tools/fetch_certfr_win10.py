#!/usr/bin/env python3
import json
import re
import sys
import time
import unicodedata
from datetime import datetime, timezone, date
from pathlib import Path
from typing import Dict, List

import requests
from bs4 import BeautifulSoup

BASE_URL = "https://www.cert.ssi.gouv.fr"

HEADERS = {
    "User-Agent": "win10-certfr-observatory-bot/0.4 (contact: github.com/Maxime-BRIN)",
}

WINDOWS_10_KEYWORD = "windows 10"
WINDOWS_10_EOS_DATE = "2025-10-14"
ACT_NUMBER_MAX = 200
REQUEST_SLEEP_SECONDS = 0.25
REQUEST_TIMEOUT_SECONDS = 20


def normalize_text(s: str) -> str:
    if not s:
        return ""
    normalized = "".join(
        c for c in unicodedata.normalize("NFKD", s.lower()) if not unicodedata.combining(c)
    )
    return normalized.replace("\xa0", " ").replace("\u00a0", " ")


def text_contains_windows10(s: str) -> bool:
    return WINDOWS_10_KEYWORD in normalize_text(s)


def fetch_url(url: str) -> BeautifulSoup | None:
    print(f"[INFO] Fetch {url}")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        print(f"[WARN] HTTP error for {url}: {exc}", file=sys.stderr)
        return None

    if resp.status_code == 404:
        print(f"[DEBUG] {url} -> 404 (no bulletin)")
        return None
    try:
        resp.raise_for_status()
    except requests.HTTPError as exc:
        print(f"[WARN] HTTP status {resp.status_code} for {url}: {exc}", file=sys.stderr)
        return None

    return BeautifulSoup(resp.text, "html.parser")


def extract_cve_ids(text: str) -> list[str]:
    pattern = r"CVE-\d{4}-\d{4,7}"
    return sorted(set(re.findall(pattern, text)))


def parse_french_long_date(s: str) -> date | None:
    """Convertit des dates type '07 avril 2026' en objet date.

    On tolère la présence éventuelle de 'er' (1er) et on normalise les mois français.
    """
    if not s:
        return None
    s = s.strip().lower()
    s = s.replace("1er", "1")

    months = {
        "janvier": 1,
        "fevrier": 2,
        "février": 2,
        "mars": 3,
        "avril": 4,
        "mai": 5,
        "juin": 6,
        "juillet": 7,
        "aout": 8,
        "août": 8,
        "septembre": 9,
        "octobre": 10,
        "novembre": 11,
        "decembre": 12,
        "décembre": 12,
    }

    m = re.search(r"(\d{1,2})\s+([a-zéèêûôàîïç]+)\s+(\d{4})", s)
    if not m:
        return None
    day = int(m.group(1))
    month_name = m.group(2)
    year = int(m.group(3))
    month = months.get(month_name)
    if not month:
        return None
    try:
        return date(year, month, day)
    except ValueError:
        return None


def discover_act_bulletins_by_bruteforce(coverage_start: date, coverage_end: date) -> list[dict]:
    """Bruteforce des références CERTFR-YYYY-ACT-XXX dans une plage raisonnable.

    Pour chaque ACT existant, on extrait la date de première version et on conserve
    uniquement ceux dont la date est dans [coverage_start, coverage_end].
    """
    year_start = 2025
    year_end = coverage_end.year

    discovered: list[dict] = []

    for year in range(year_start, year_end + 1):
        for n in range(1, ACT_NUMBER_MAX + 1):
            ref = f"CERTFR-{year}-ACT-{n:03d}"
            url = f"{BASE_URL}/actualite/{ref}/"
            soup = fetch_url(url)
            if soup is None:
                # 404 ou erreur HTTP : on passe au suivant
                time.sleep(REQUEST_SLEEP_SECONDS)
                continue

            # Chercher un bloc contenant "Date de la première version" puis la date
            first_version_date: date | None = None

            for p in soup.find_all(["p", "li", "div"]):
                txt = p.get_text(" ", strip=True)
                if "Date de la première version" in txt:
                    # Souvent le texte de la date se trouve dans le même bloc ou juste après
                    # On capture après le ':' si présent, sinon on garde tout et on laisse parse_french_long_date faire le tri
                    parts = txt.split(":", 1)
                    candidate = parts[1].strip() if len(parts) == 2 else txt
                    d = parse_french_long_date(candidate)
                    if not d:
                        # Essayer dans un frère immédiatement suivant
                        nxt = p.find_next_sibling()
                        if nxt:
                            d = parse_french_long_date(nxt.get_text(" ", strip=True))
                    first_version_date = d
                    break

            if not first_version_date:
                # fallback : chercher toute date longue dans la page
                txt = soup.get_text(" ", strip=True)
                d = parse_french_long_date(txt)
                first_version_date = d

            if not first_version_date:
                print(f"[WARN] Impossible d'extraire la date de première version pour {ref}", file=sys.stderr)
                time.sleep(REQUEST_SLEEP_SECONDS)
                continue

            print(f"[DEBUG] {ref}: Date de la première version = {first_version_date.isoformat()}")

            if not (coverage_start <= first_version_date <= coverage_end):
                time.sleep(REQUEST_SLEEP_SECONDS)
                continue

            discovered.append(
                {
                    "ref": ref,
                    "url": url,
                    "first_version_date": first_version_date,
                    "soup": soup,
                }
            )
            time.sleep(REQUEST_SLEEP_SECONDS)

    print(
        f"[INFO] Découvert {len(discovered)} bulletins ACT dans la fenêtre "
        f"{coverage_start.isoformat()} -> {coverage_end.isoformat()}",
    )
    return discovered


def extract_entries_from_act(act: dict) -> list[dict]:
    """Extrait les entrées Windows 10 (ou à défaut Windows) d'un bulletin ACT.

    Heuristique :
    - parcourir les tableaux;
    - identifier les colonnes éditeur / produit / CVE / CVSS si présentes;
    - ne garder que les lignes avec éditeur contenant 'microsoft' et produit contenant 'windows';
    - extraire les CVE; si le produit mentionne 'windows 10', on le marque explicitement.
    """
    soup: BeautifulSoup = act["soup"]
    ref: str = act["ref"]
    first_version_date: date = act["first_version_date"]

    results: list[dict] = []

    tables = soup.find_all("table")
    if not tables:
        print(f"[DEBUG] {ref}: aucune table de vulnérabilités trouvée")
        return results

    for table in tables:
        header_cells = table.find_all("th")
        header = [normalize_text(th.get_text(strip=True)) for th in header_cells]
        if not header:
            continue

        try:
            publisher_idx = next(i for i, h in enumerate(header) if "editeur" in h or "éditeur" in h)
        except StopIteration:
            publisher_idx = None
        try:
            product_idx = next(i for i, h in enumerate(header) if "produit" in h)
        except StopIteration:
            product_idx = None
        try:
            cve_idx = next(i for i, h in enumerate(header) if "cve" in h)
        except StopIteration:
            cve_idx = None
        try:
            cvss_idx = next(i for i, h in enumerate(header) if "cvss" in h)
        except StopIteration:
            cvss_idx = None

        if product_idx is None or cve_idx is None:
            continue

        rows = table.find_all("tr")
        for row in rows[1:]:
            cells = [td.get_text(" ", strip=True) for td in row.find_all("td")]
            if len(cells) < max(product_idx, cve_idx) + 1:
                continue

            publisher = cells[publisher_idx] if publisher_idx is not None and publisher_idx < len(cells) else ""
            product = cells[product_idx]
            cve_text = cells[cve_idx]

            if "microsoft" not in normalize_text(publisher):
                continue
            if "windows" not in normalize_text(product):
                continue

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

            for cve in cve_ids:
                results.append(
                    {
                        "cve_id": cve,
                        "certfr_act_ref": ref,
                        "act_first_version_date": first_version_date.isoformat(),
                        "publisher": publisher,
                        "product": product,
                        "cvss_base_score": cvss_score,
                        "source_type": "actualite",
                        "certfr_url": act["url"],
                    }
                )

    print(f"[INFO] {ref}: {len(results)} entrées Windows découvertes")
    return results


def deduplicate(entries: list[dict]) -> list[dict]:
    by_cve: Dict[str, dict] = {}
    for e in entries:
        cve = e["cve_id"]
        if cve not in by_cve:
            by_cve[cve] = e
            continue

        existing = by_cve[cve]
        if not existing.get("cvss_base_score") and e.get("cvss_base_score"):
            existing["cvss_base_score"] = e["cvss_base_score"]

        for key in ["publisher", "product"]:
            if key in e and e[key] and e[key] != existing.get(key):
                merged = sorted({existing.get(key, ""), e[key]})
                existing[key] = " | ".join(x for x in merged if x)

        by_cve[cve] = existing
    return list(by_cve.values())


def main() -> None:
    coverage_start = date.fromisoformat(WINDOWS_10_EOS_DATE)
    coverage_end_date = date.today()
    print(f"[INFO] Date EOS Windows 10: {coverage_start}")
    print(f"[INFO] Fenêtre de collecte (ACT): {coverage_start} -> {coverage_end_date}")

    acts = discover_act_bulletins_by_bruteforce(coverage_start, coverage_end_date)

    raw_entries: list[dict] = []
    windows10_entries: list[dict] = []

    for act in acts:
        entries = extract_entries_from_act(act)
        raw_entries.extend(entries)

        act_windows10 = [e for e in entries if text_contains_windows10(e.get("product", ""))]
        if act_windows10:
            windows10_entries.extend(act_windows10)
        else:
            print(
                f"[INFO] ACT {act['ref']}: 0 entrées Windows 10 explicites, ignoré pour ce dataset.",
            )

    print(f"[INFO] Total brut Windows (toutes versions) depuis ACT: {len(raw_entries)} entrées")
    print(f"[INFO] Total entrées Windows 10 explicites (tous ACT): {len(windows10_entries)}")

    entries_to_keep = windows10_entries

    deduped = deduplicate(entries_to_keep)
    print(f"[INFO] Total CVE Windows 10 explicites (après déduplication): {len(deduped)}")

    now = datetime.now(timezone.utc)

    dataset = {
        "dataset": {
            "name": "Observatoire Windows 10 / CERT-FR (données ACT)",
            "version": "0.6.1",
            "generated_at": now.isoformat().replace("+00:00", "Z"),
            "coverage_start": coverage_start.isoformat(),
            "coverage_end": coverage_end_date.isoformat(),
            "windows_10_eos_date": WINDOWS_10_EOS_DATE,
            "methodology_summary": (
                "Jeu de données construit automatiquement à partir des bulletins d'actualité CERT-FR (ACT) "
                "publiés après la fin de support de Windows 10 (14/10/2025). "
                "Seules les lignes de vulnérabilités où le produit mentionne explicitement Windows 10 dans les tableaux "
                "sont retenues pour ce dataset."
            ),
            "limitations": [
                "Le périmètre est limité aux références CERTFR-YYYY-ACT-XXX testées dans une plage raisonnable (1..200).",
                "Seuls les éditeurs Microsoft et les produits contenant 'Windows' sont considérés, puis filtrés pour ne garder que les mentions explicites de Windows 10.",
                "Les vulnérabilités Windows génériques où Windows 10 n'est pas nommé dans le champ produit ne sont pas incluses dans ce dataset.",
                "Les dates des bulletins sont dérivées du champ 'Date de la première version' lorsqu'il est présent dans la page.",
                "Ce jeu de données dépend de la structure HTML actuelle des bulletins ACT et peut devenir partiellement obsolète si cette structure évolue.",
                "Le champ 'source_type' vaut 'actualite' pour les CVE issues des bulletins d'actualité CERT-FR ACT référencés par 'certfr_act_ref'.",
            ],
        },
        "cves": [],
    }

    for e in deduped:
        cve_obj = {
            "cve_id": e["cve_id"],
            "certfr_act_ref": e.get("certfr_act_ref"),
            "act_first_version_date": e.get("act_first_version_date"),
            "publisher": e.get("publisher"),
            "product": e.get("product"),
            "cvss_base_score": e.get("cvss_base_score"),
            "source_type": e.get("source_type"),
            "certfr_url": e.get("certfr_url"),
        }
        dataset["cves"].append(cve_obj)

    out_path = Path(__file__).resolve().parents[1] / "data" / "windows-10-certfr-data.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(dataset, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Écrit {len(dataset['cves'])} CVE dans {out_path}")


if __name__ == "__main__":
    main()
