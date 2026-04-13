#!/usr/bin/env python3
"""Wrapper de pipeline pour l'observatoire Windows 10 basé sur CERT-FR + NVD.

Ce script exécute successivement :

- tools/build_certfr_cve_index.py
- tools/enrich_cve_with_nvd.py

Il remplace l'ancien pipeline basé sur le scraping HTML des ACT.
"""

import runpy


def main() -> None:
    runpy.run_module("tools.build_certfr_cve_index", run_name="__main__")
    runpy.run_module("tools.enrich_cve_with_nvd", run_name="__main__")


if __name__ == "__main__":
    main()
