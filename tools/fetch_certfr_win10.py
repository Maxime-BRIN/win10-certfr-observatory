#!/usr/bin/env python3
"""LEGACY / EXPERIMENTAL

Ce wrapper correspond à l'ancien pipeline CERT-FR + NVD pour l'observatoire Windows 10.
Il n'est plus utilisé par le workflow principal, qui interroge désormais directement la NVD
via tools/fetch_cve_windows10.py.
"""

import runpy


def main() -> None:
    runpy.run_module("tools.build_certfr_cve_index", run_name="__main__")
    runpy.run_module("tools.enrich_cve_with_nvd", run_name="__main__")


if __name__ == "__main__":
    main()
