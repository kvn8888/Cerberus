# Seed Data Directory

This directory contains pre-downloaded data feeds for offline/cached imports.

## Files (populated by import scripts on first run)

| File | Source | Created By |
|------|--------|-----------|
| `enterprise-attack.json` | MITRE ATT&CK STIX 2.1 bundle | `import_mitre.py` |
| `cves.json` | NVD API (curated ~50 CVEs) | `import_cve.py` |
| `threat_ips.json` | Abuse.ch Feodo Tracker | `import_threats.py` |
| `threat_domains.json` | Abuse.ch URLhaus | `import_threats.py` |
| `npm_packages.json` | Curated compromised packages | `import_npm.py` |
| `synthetic_links.json` | Synthetic cross-domain bridges | `import_synthetic.py` |

## Usage

Import scripts check for cached files here before hitting live APIs.
To force a re-fetch, delete the relevant JSON file and re-run the script.

## Note on MITRE ATT&CK data

The `enterprise-attack.json` file is ~30MB. It's `.gitignore`d to keep the repo lean.
Run `import_mitre.py` to download it on first setup.
