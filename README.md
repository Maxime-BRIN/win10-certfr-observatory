# 🔍 CVE Windows 10 – Observatoire NVD

> Tableau de bord statique HTML de surveillance des CVE affectant Windows 10, alimenté automatiquement par l'API NVD (NIST) via GitHub Actions.

[![Mise à jour automatique](https://github.com/Maxime-BRIN/win10-cve-observatory/actions/workflows/fetch-nvd-windows10.yml/badge.svg)](https://github.com/Maxime-BRIN/win10-cve-observatory/actions/workflows/fetch-nvd-windows10.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Maxime-BRIN/win10-cve-observatory/blob/main/LICENSE)

---

## 🎯 Objectif

Offrir une interface web légère et autonome pour visualiser, filtrer et analyser les CVE Windows 10 publiées depuis le **14 octobre 2025** (fin de support étendu de Windows 10), directement depuis les données officielles du [NVD (NIST)](https://nvd.nist.gov/).

---

## 📸 Fonctionnalités

| Fonctionnalité | Détail |
|---|---|
| **KPIs dynamiques** | Total CVE, CVE CVSS ≥ 8, CVE réseau (AV:N), avec animation count-up |
| **Graphique mensuel** | Histogramme interactif — clic sur une barre pour filtrer le tableau |
| **Tableau détaillé** | CVE, date, score NVD (badge coloré), type d'impact, vecteur CVSS, versions Win 10, référence NVD/CERTFR |
| **Badge CVSS coloré** | Score + sévérité (NONE/LOW/MEDIUM/HIGH/CRITICAL) selon NVD CVSS v3 |
| **Filtres** | CVSS ≥ 8, Réseau (AV:N), tri par score croissant/décroissant |
| **Filtre par mois** | Clic sur le graphique → badge de filtre actif avec suppression rapide |
| **Pagination** | 15 (défaut) / 25 / 50 / 100 / TOUS |
| **Vecteur CVSS visuel** | Badges colorés AV · PR · UI |
| **0 dépendance serveur** | Fichier HTML unique + JSON statiques, hébergeable sur GitHub Pages |

---

## 🗂️ Structure du projet

```
win10-cve-observatory/
│
├── index.html                            # Interface principale (SPA statique)
├── README.md
├── LICENSE                               # Licence MIT
│
├── data/
│   ├── windows-10-cve-data.json          # ✅ Dataset principal (utilisé par le frontend)
│   └── cve_windows10.json                # Dataset brut généré par fetch_cve_windows10.py
│
├── tools/
│   ├── fetch_cve_windows10.py            # Récupération CVE depuis l'API NVD
│   └── build_windows10_frontend_data.py  # Transformation → windows-10-cve-data.json
│
└── .github/
    └── workflows/
        └── fetch-nvd-windows10.yml       # CI/CD : mise à jour automatique quotidienne
```

---

## ⚙️ Pipeline de données

```
API NVD (NIST)
    │
    ▼
fetch_cve_windows10.py
    │  → data/cve_windows10.json  (données brutes)
    ▼
build_windows10_frontend_data.py
    │  → data/windows-10-cve-data.json  (données normalisées pour le frontend)
    ▼
index.html  (lecture JSON statique, rendu côté client)
```

> Le frontend dispose également d'un **fallback NVD API** (appel direct côté navigateur) pour compléter les scores CVSS manquants à la volée.

---

## 🤖 Automatisation GitHub Actions

Le workflow **`fetch-nvd-windows10.yml`** s'exécute :
- **Tous les jours à 06h00 UTC** (cron)
- **Manuellement** via `workflow_dispatch`

### Étapes du workflow

1. Checkout du dépôt
2. Setup Python 3.11
3. Installation de `requests`
4. Exécution de `fetch_cve_windows10.py` (requiert `NVD_API_KEY` en secret)
5. Exécution de `build_windows10_frontend_data.py`
6. Upload des datasets en artifact
7. Commit + push automatique si les données ont changé

### Secret requis

| Secret | Rôle |
|---|---|
| `NVD_API_KEY` | Clé API NVD pour lever la limite de taux (optionnel mais recommandé) |

> Sans clé API, le script fonctionne mais est limité à ~5 requêtes/30 secondes.

---

## 🚀 Déploiement local

```bash
# Cloner le dépôt
git clone https://github.com/Maxime-BRIN/win10-cve-observatory.git
cd win10-cve-observatory

# Installer les dépendances Python
pip install requests

# (Optionnel) Regénérer les données
export NVD_API_KEY="votre_cle"
python tools/fetch_cve_windows10.py
python tools/build_windows10_frontend_data.py

# Servir le frontend
python -m http.server 8080
# Ouvrir http://localhost:8080
```

---

## 🌐 Déploiement GitHub Pages

1. Aller dans **Settings → Pages**
2. Source : `main` / `/ (root)`
3. L'URL sera : `https://maxime-brin.github.io/win10-cve-observatory/`

---

## 📊 Format des données (`windows-10-cve-data.json`)

```json
{
  "cves": [
    {
      "cve_id": "CVE-2025-XXXXX",
      "published": "2025-11-12",
      "cvss_score": 7.8,
      "cvss_vector_string": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      "impact_type": "Elevation of Privilege",
      "windows_10_versions": ["21H2", "22H2"],
      "certfr_id": "CERTFR-2025-AVI-XXXX",
      "certfr_url": "https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-XXXX/"
    }
  ]
}
```

---

## 🛠️ Technologies

| Composant | Technologie |
|---|---|
| Frontend | HTML5 / CSS3 / Vanilla JS (ES2020+) |
| Graphiques | [Chart.js](https://www.chartjs.org/) (CDN) |
| Typographie | Google Fonts – Lato + Inter |
| Données | JSON statique (NVD API) |
| Automatisation | GitHub Actions (Python 3.11) |
| Scripts Python | `requests` |

---

## 📝 Licence

Ce projet est distribué sous licence **MIT** — voir le fichier [LICENSE](./LICENSE) pour le texte complet.

Copyright &copy; 2026 **Maxime BRIN**

Les données CVE sont issues du [NVD (NIST)](https://nvd.nist.gov/) et sont dans le domaine public.
