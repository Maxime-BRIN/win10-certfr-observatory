# Observatoire Windows 10 – données NVD

Ce dépôt contient l'outillage et les fichiers nécessaires pour construire un petit tableau de bord statique autour des vulnérabilités Windows 10.

L'observatoire est désormais **alimenté par la NVD (National Vulnerability Database)**, avec un jeu de données reconstruit pour rester compatible avec l'ancien frontend.

## Pipeline de données

### Nouveau pipeline (NVD – pipeline officiel)

Le pipeline principal repose sur la NVD et fonctionne ainsi :

- `tools/fetch_cve_windows10.py` interroge l'API NVD 2.0 (`/rest/json/cves/2.0`) pour plusieurs CPE Windows 10 x64 explicites (1607, 1709, 1909, 21H2, 22H2).
- Le script agrège et déduplique les CVE par `cve_id`, puis écrit un dataset brut NVD :
  - `data/cve_windows10.json` avec la structure :
    - `generated_at`, `coverage_start`, `coverage_end`
    - `cves[]` contenant `cve_id`, `published`, `cvss_score`, `cvss_severity`, `summary`.
- `tools/build_windows10_frontend_data.py` lit ce dataset NVD et construit un fichier **compatible avec l'ancien schéma frontend** :
  - `data/windows-10-certfr-data.json` avec la structure :
    - `dataset.coverage_start`, `dataset.coverage_end`
    - `cves[]` avec au minimum :
      - `cve_id`
      - `published_at` (depuis `published`)
      - `cvss_base_score` (depuis `cvss_score`)
      - `exploitation_status` (actuellement `"unknown"`)
      - `impact_type` (actuellement `"unknown"`)
      - `windows_10_versions` (dérivées grossièrement des CPE Windows 10 x64)
      - `certfr_url`, `certfr_id` (actuellement vides).
- Le workflow GitHub Actions `.github/workflows/fetch-nvd-windows10.yml` :
  - s'exécute via `workflow_dispatch` et `schedule`,
  - installe Python et `requests`,
  - lance `python tools/fetch_cve_windows10.py`,
  - lance `python tools/build_windows10_frontend_data.py`,
  - publie les deux fichiers JSON comme artefacts et, si `ALLOW_DATASET_COMMIT=true`, les commite dans la branche.

Ce pipeline NVD est le **chemin officiel** désormais utilisé par le site statique.

### Ancien pipeline (CERT-FR – LEGACY / OFFLINE)

Historiquement, le projet s'appuyait sur les flux CERT-FR (avis/alertes) pour identifier les CVE Windows 10, puis enrichir via la NVD. Ce pipeline est conservé uniquement pour usage manuel ou pour comparaison méthodologique.

Les scripts suivants sont marqués explicitement comme LEGACY / EXPERIMENTAL et ne sont plus appelés par la CI :

- `tools/build_certfr_cve_index.py`
- `tools/enrich_cve_with_nvd.py`
- `tools/fetch_certfr_win10.py`

Le workflow CI associé (`.github/workflows/fetch-certfr.yml`) a été supprimé : **aucun workflow GitHub Actions ne s'appuie plus sur CERT-FR**.

## Frontend (site statique)

Le tableau de bord principal est servi via `index.html` (static, sans framework JS). Il consomme :

- `./data/windows-10-certfr-data.json` comme source principale (format compat avec l'ancien modèle),
- `./data/windows-10-certfr-sample-data.json` comme fallback si le dataset principal est absent.

Les pages HTML se trouvent à la racine du dépôt :

- `index.html` : vue principale (KPI, histogramme des CVE par mois, tableau détaillé).
- `methodology.html` : explications sur le périmètre et les choix méthodologiques.

Même si le nom du fichier JSON inclut encore `certfr` pour compatibilité, le contenu est désormais **entièrement construit à partir de CVE NVD**, avec :

- une reconstruction minimale des métadonnées attendues par le frontend,
- des champs liés à CERT-FR (`certfr_url`, `certfr_id`) laissés vides par défaut,
- `exploitation_status` et `impact_type` initialisés à `"unknown"`.

## Scripts principaux

- `tools/fetch_cve_windows10.py` :
  - pipeline NVD officiel (multi-CPE Windows 10 x64, fenêtres de dates découpées, gestion basique du rate limit 429),
  - écrit `data/cve_windows10.json`.
- `tools/build_windows10_frontend_data.py` :
  - construit `data/windows-10-certfr-data.json` au format attendu par le frontend,
  - ne lit que `cve_windows10.json` (aucune dépendance aux scripts CERT-FR).

Les autres scripts Python marqués LEGACY ne sont pas utilisés par les workflows et ne doivent pas être considérés comme partie du chemin de données officiel.

## Déploiement

Le site peut être servi directement depuis GitHub Pages ou tout autre hébergement statique en exposant :

- `index.html` et `methodology.html`,
- le répertoire `data/` contenant `windows-10-certfr-data.json` (et éventuellement un échantillon),
- les fichiers JSON mis à jour via le workflow NVD.
