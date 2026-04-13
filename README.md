# Observatoire Windows 10 / CERT-FR

Ce dépôt contient une mini-application statique qui expose un observatoire documentaire des vulnérabilités (CVE) Windows 10 relayées par le CERT-FR après la fin de support de Windows 10 (14 octobre 2025).

## V2 : données semi-automatisées

La V2 introduit un pipeline de collecte qui parcourt certains avis et bulletins d'actualité publics du CERT-FR, en extrait les vulnérabilités mentionnant explicitement **Windows 10**, les normalise et les exporte dans un fichier JSON consommé par le tableau de bord.

- **Source des données** : contenus publics du site [CERT-FR](https://www.cert.ssi.gouv.fr/).
- **Périmètre** : uniquement les vulnérabilités pour lesquelles les systèmes ou produits affectés contiennent textuellement « Windows 10 » (par exemple « Windows 10 Version 22H2 »).
- **Nature** : proxy documentaire, pas un scanner de parc, pas un inventaire exhaustif de toutes les vulnérabilités existantes.
- **Référence fin de support** : l'actualité [CERTFR-2025-ACT-017](https://www.cert.ssi.gouv.fr/actualite/CERTFR-2025-ACT-017/) rappelle que Windows 10 22H2 ne reçoit plus de mises à jour de sécurité standard après le **14 octobre 2025**.

Chaque nouvelle CVE affectant Windows 10 après cette date représente donc, en première approximation, une vulnérabilité théoriquement non corrigée pour les systèmes qui resteraient sur Windows 10.

## Structure du dépôt

- `index.html` : tableau de bord statique en français.
  - Charge en priorité `data/windows-10-certfr-data.json`.
  - Si le fichier n'existe pas ou n'est pas accessible, bascule automatiquement sur `data/windows-10-certfr-sample-data.json`.
  - Affiche :
    - des KPI agrégés (total CVE Windows 10 référencées, CVE exploitées/PoC, CVE avec CVSS ≥ 8, CVE publiées après le 14/10/2025) ;
    - un graphique Chart.js (courbe par mois) ;
    - un tableau filtrable des CVE (filtre texte, sévérité CVSS, statut d'exploitation) ;
    - une section « Méthodologie » ;
    - une section « Limites ».
- `data/windows-10-certfr-sample-data.json` : jeu de données d'exemple, utilisé en secours.
- `data/windows-10-certfr-data.json` : jeu de données réel, généré par le script de collecte.
- `tools/fetch_certfr_win10.py` : script Python qui interroge certaines pages CERT-FR, filtre les vulnérabilités Windows 10 et exporte le JSON.
- `.github/workflows/fetch-certfr.yml` : workflow GitHub Actions pour exécuter périodiquement le script et committer le fichier JSON.

## Méthodologie (V2)

1. Le script `tools/fetch_certfr_win10.py` parcourt un ensemble limité de pages CERT-FR (avis et actualités).
2. Pour chaque page :
   - les identifiants CVE sont extraits du texte ;
   - les produits ou systèmes affectés sont inspectés ;
   - seules les entrées où « Windows 10 » apparaît explicitement sont retenues ;
   - les métadonnées disponibles sont collectées (type de vulnérabilité, CVSS, statut d'exploitation lorsque présent, date de publication, référence CERT-FR, URL).
3. Les vulnérabilités sont regroupées par identifiant CVE :
   - une CVE présente dans plusieurs avis/bulletins ne donne lieu qu'à une seule entrée ;
   - les listes de versions Windows 10, de produits affectés et de références CERT-FR sont fusionnées.
4. Le résultat est exporté dans `data/windows-10-certfr-data.json` avec la structure suivante :
   - `dataset` : métadonnées globales (nom, version, dates de couverture, date de fin de support Windows 10, résumé de méthodologie, limites).
   - `cves[]` : une entrée par CVE, avec notamment :
     - `cve_id`, `title`, `published_at`, `impact_type`, `cvss_base_score` ;
     - `exploitation_status` (`none` / `poc` / `exploited`) ;
     - `windows_10_versions[]`, `affected_products_raw[]` ;
     - `certfr_id`, `certfr_url`, `source_type` (`avis` / `actualite`) ;
     - `references[]` (toutes les URLs CERT-FR liées) ;
     - `dedup_key` (identique à `cve_id`).

### Limites importantes

- Le périmètre des pages CERT-FR parcourues est volontairement limité, pour rester dans un usage raisonnable du site et éviter le flood.
- La structure HTML de CERT-FR peut évoluer : le parsing repose sur des hypothèses (présence de tableaux, intitulés de colonnes, sections « Systèmes affectés »), il peut donc rater ou mal interpréter certaines entrées.
- Aucune extrapolation n'est faite à partir de termes génériques (« Microsoft Windows ») : si « Windows 10 » n'est pas mentionné textuellement, la vulnérabilité n'est pas comptée.
- Ce projet ne fournit **ni** un inventaire de parc, **ni** un scanner de vulnérabilités, **ni** une mesure exhaustive de toutes les vulnérabilités Windows 10 existantes, notamment celles qui ne sont pas rendues publiques.

## Activation de GitHub Pages

Pour publier le tableau de bord :

1. Aller dans l'onglet **Settings → Pages** du dépôt.
2. Section **Build and deployment** :
   - Source : `Deploy from a branch` ;
   - Branch : `main`, dossier `/ (root)`.
3. Sauvegarder, puis attendre le déploiement.

L'URL attendue sera alors :

- `https://maxime-brin.github.io/win10-certfr-observatory/`

## Intégration via iframe (exemple Hostinger)

Exemple d'intégration du tableau de bord dans un site tiers :

```html
<iframe src="https://maxime-brin.github.io/win10-certfr-observatory/" style="width:100%;min-height:900px;border:none;" loading="lazy"></iframe>
```

## Utilisation du script de collecte

Exécution locale :

```bash
python -m venv .venv
source .venv/bin/activate  # ou .venv\\Scripts\\activate sur Windows
pip install requests beautifulsoup4
python tools/fetch_certfr_win10.py
```

Le script écrase (ou crée) `data/windows-10-certfr-data.json` avec les données actualisées.

## Workflow GitHub Actions

Le workflow `.github/workflows/fetch-certfr.yml` :

- peut être déclenché à la demande via `workflow_dispatch` ;
- s'exécute automatiquement chaque lundi à 03:00 UTC ;
- installe Python, exécute `tools/fetch_certfr_win10.py`, commite `data/windows-10-certfr-data.json` si le fichier a changé.

Ce mécanisme permet de tenir à jour l'observatoire de façon semi-automatisée tout en restant dans un usage raisonnable du site CERT-FR.
