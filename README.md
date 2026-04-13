# Observatoire Windows 10 / CERT-FR (post EOS)

Ce projet construit un **observatoire des vulnérabilités Windows 10 référencées par le CERT-FR après la fin de support officielle de Windows 10 (14/10/2025)**.

L'objectif est de disposer d'un tableau de bord léger qui permet de visualiser, à partir de sources publiques CERT-FR :

- le volume de CVE Windows 10 post‑EOS ;
- la répartition dans le temps ;
- le nombre de vulnérabilités critiques ou exploitées ;
- le détail des CVE avec leurs références CERT-FR.

## Architecture

- **Dashboard** : `index.html`
  - Page principale, orientée "dashboard" :
    - en haut, des KPI (nombre total de CVE, CVE avec CVSS ≥ 8, CVE exploitées / PoC) ;
    - un graphique (histogramme mensuel du volume de CVE) ;
    - un tableau détaillé des vulnérabilités Windows 10.
  - La page consomme le fichier JSON `data/windows-10-certfr-data.json` s'il existe, sinon un échantillon `data/windows-10-certfr-sample-data.json`.

- **Méthodologie / explications** : `methodology.html`
  - Page textuelle qui décrit :
    - le périmètre (post‑EOS, sources CERT-FR) ;
    - la liste des types de pages utilisées (bulletins d'actualité ACT) ;
    - la façon dont Windows 10 est détecté dans les libellés ;
    - la fenêtre temporelle appliquée ;
    - la structure du JSON et les principales limites.

- **Script de collecte** : `tools/fetch_certfr_win10.py`
  - Script Python qui :
    - brute-force les références `CERTFR-YYYY-ACT-XXX` dans une plage raisonnable ;
    - détecte, dans les tableaux des ACT, les lignes où l'éditeur est Microsoft et le produit contient "Windows" ;
    - ne retient dans le dataset final **que les lignes dont le produit mentionne explicitement Windows 10** (par exemple "Windows 10", "Windows 10 version 22H2", "Windows 10, Windows 11", etc.) ;
    - extrait les identifiants CVE, les scores CVSS et les métadonnées associées ;
    - filtre les bulletins pour ne garder que ceux dont la date de première version est ≥ 14/10/2025 ;
    - déduplique les CVE et écrit le fichier `data/windows-10-certfr-data.json`.

- **Workflow GitHub Actions** : `.github/workflows/fetch-certfr.yml`
  - Workflow CI qui peut :
    - être lancé manuellement (`workflow_dispatch`) ;
    - être exécuté automatiquement à chaque `push` sur la branche `main` ;
    - installer les dépendances Python ;
    - exécuter `tools/fetch_certfr_win10.py` ;
    - *optionnellement* commiter/pousser le JSON mis à jour (protégé par un flag explicite, voir plus bas).

## Utilisation en local

### Prérequis

- Python 3.11+ (une version récente de Python 3);
- `git` (optionnel mais recommandé).

Installez les dépendances Python :

```bash
pip install -r requirements.txt
```

(le fichier `requirements.txt` contient au minimum `requests` et `beautifulsoup4`).

### Générer le dataset localement

Dans la racine du dépôt :

```bash
python tools/fetch_certfr_win10.py
```

Le script va :

- brute-forcer les bulletins d'actualité CERT-FR ACT dans une plage raisonnable ;
- analyser les tables pour trouver les lignes qui concernent Microsoft Windows ;
- filtrer pour ne conserver **que les entrées dont le produit mentionne explicitement Windows 10** ;
- dédupliquer les CVE et écrire le fichier `data/windows-10-certfr-data.json`.

En cas d'erreur de parsing ou si la structure HTML du CERT-FR évolue, le script loggue des avertissements sur la sortie standard.

### Visualiser le dashboard

Une fois le dataset généré :

1. Ouvrez `index.html` dans votre navigateur (par exemple via un petit serveur local ou en double‑cliquant si votre navigateur accepte les `file://`).
2. La page chargera le JSON depuis `data/windows-10-certfr-data.json` si présent, sinon depuis `data/windows-10-certfr-sample-data.json`.
3. Les KPI, le graphique et le tableau se mettront à jour en fonction des données.

La page `methodology.html` peut être ouverte pour consulter les détails du périmètre et les limitations.

## CI / CD : workflow "Fetch CERT-FR Windows 10 data"

Le workflow GitHub Actions est défini dans `.github/workflows/fetch-certfr.yml`.

### Déclencheurs

- `workflow_dispatch` : exécution manuelle depuis l'onglet **Actions** de GitHub.
- `push` sur `main` : exécution automatique à chaque push sur la branche principale.

### Étapes principales

- `Checkout repository` : récupère le code de la branche.
- `Set up Python` : installe Python 3.11 dans l'environnement CI.
- `Install dependencies` : installe les paquets listés dans `requirements.txt`.
- `Run CERT-FR Windows 10 fetch script` : exécute `python tools/fetch_certfr_win10.py`.
- `Commit and push updated dataset` : **optionnel** — ne s'exécute que si :
  - l'événement est `workflow_dispatch` (lancement manuel) ;
  - et la variable `ALLOW_DATASET_COMMIT` vaut `true` (voir ci‑dessous).

### Contrôle du commit automatique

Pour éviter que des exécutions de debug ou des changements temporaires ne poussent automatiquement un dataset vide ou incohérent sur `main`, l'étape de commit est protégée par un drapeau explicite :

- l'étape ne s'exécute que si **les deux conditions** suivantes sont réunies :
  - `github.event_name == 'workflow_dispatch'` (run manuel) ;
  - `env.ALLOW_DATASET_COMMIT == 'true'`.

Pour activer le commit automatique sur un run manuel :

1. Définir une variable de dépôt `ALLOW_DATASET_COMMIT` à `true` (ou utiliser un mécanisme équivalent de variables GitHub).
2. Lancer le workflow manuellement depuis l'onglet Actions.

Dans tous les autres cas, le workflow se contente de régénérer `data/windows-10-certfr-data.json` dans l'environnement CI sans tenter de pousser sur le dépôt.

## Limites et périmètre

- Le périmètre couvre **un sous‑ensemble** des publications CERT-FR :
  - des bulletins d'actualité CERTFR-YYYY-ACT-XXX découverts par brute-force ;
- Seules les lignes dont la colonne Produit mentionne explicitement **"Windows 10"** sont retenues dans le dataset final ;
- Les vulnérabilités Microsoft Windows génériques où Windows 10 n'est pas nommé ne sont **pas** incluses ;
- Les CVE sont associées à la date de première version du bulletin ACT, et à la référence `certfr_act_ref` ;
- Le jeu de données n'a **aucune prétention d'exhaustivité** sur toutes les vulnérabilités Windows 10 existantes ;
- Les décisions de sécurité opérationnelle doivent toujours se baser sur une combinaison de sources (avis de l'éditeur, inventaires internes, scanner de vulnérabilités, etc.).

Pour plus de détails, voir `methodology.html` qui reprend la méthodologie complète et les limitations connues.
