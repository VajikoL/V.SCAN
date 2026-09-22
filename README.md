# V.SCAN

**Lightweight vulnerability scanner — by Vazha Lomtatidze**

OpenVAS/Nessus-class **CLI** assessment (no web GUI): discovery, nmap fingerprinting, plugin checks, CVE/CVSS, remediation, risk score, reports.

```
Use only on networks you own or have explicit written permission to assess.
```

## Install

```bash
sudo apt install -y nmap arp-scan python3-venv
git clone https://github.com/VajikoL/V.SCAN.git
cd V.SCAN
sudo bash install.sh          # → vscan in PATH
```

## Usage

```bash
vscan                         # launcher
vscan 192.168.1.0/24          # scan a network
vscan help                    # full guide
vscan plugins                 # built-in checks
vscan nets
vscan history
vscan report 1 --format html  # also: json | csv | xml | txt
```

After every scan, reports auto-save to `~/.vscan/reports/` as **HTML + TXT** (IP, MAC, name, vulns, how to fix).

Profiles: `quick` · `balanced` (default, light) · `deep` · `audit` (**MAX** — everything)

Optional SSH auth audit: `vscan scan 10.0.0.5 --profile audit --creds ~/.vscan/creds.yaml`

Languages: `en` `ka` `ru` `de` `fr` `es` — `vscan --lang ru`

## License

MIT · Vazha Lomtatidze
