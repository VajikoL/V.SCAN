"""Full in-app help text for ``vscan help``."""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from vscan import __author__, __tagline__, __version__


HELP_MARKDOWN = """\
# V.SCAN — full guide

**{tagline}**  
Version **{version}** · Author **{author}**

## What it does (OpenVAS/Nessus-class CLI, no web GUI)

1. **Discovery** — live hosts (ARP / arp-scan / ping)
2. **Fingerprint** — real **nmap** (ports, `-sV`, OS, scripts)
3. **Plugins** — TLS, HTTP headers, dangerous services, DNS recursion, SMB, NSE
4. **CVE + CVSS** — NVD matching + remediation advice
5. **Auth audit (optional)** — SSH package inventory → CVE hints (`--creds`)
6. **Risk score** — 0–100 summary like Nessus
7. **History / reports** — auto HTML+TXT in `~/.vscan/reports/` + CSV/XML/JSON

## Quick start

```text
vscan                         interactive launcher
vscan 192.168.1.0/24          scan CIDR (profile: balanced)
vscan 10.0.0.0/24 --profile deep
vscan scan 192.168.1.0/24 --creds ~/.vscan/creds.yaml
vscan plugins                 list built-in checks
vscan help                    this guide
```

## Commands

| Command | Meaning |
|---------|---------|
| `vscan` / `vscan <CIDR>` | Launcher or direct scan |
| `vscan scan [CIDR]` | Assessment with flags |
| `vscan quick [CIDR]` | Hosts only |
| `vscan nets` | LAN + routed VLAN candidates |
| `vscan plugins` | List plugin checks |
| `vscan about` | About author / product |
| `vscan history` | Saved scans |
| `vscan report <id>` | `--format html\|json\|csv\|xml\|txt` → `~/.vscan/reports/` |
| `vscan diff <id1> <id2>` | Compare scans |
| `vscan update-db` | Refresh OUI / clear CVE cache |
| `vscan config --set-lang ru` | UI language |

## Profiles (keep the system light)

| Profile | Behaviour |
|---------|-----------|
| `quick` | Live hosts only |
| `balanced` | **Default** — top 1000 + light plugins + CVE |
| `deep` | All TCP (`-p-`) + deep plugins + NSE + CVE |
| `audit` | **MAX** — all TCP+UDP, all plugins, full NSE categories, max CVE (+ SSH if `--creds`) |

## Credentialed scan (optional)

`~/.vscan/creds.yaml` example:

```yaml
ssh_user: audit
ssh_key: /home/you/.ssh/id_ed25519
```

Then: `vscan scan 192.168.1.10 --profile audit --creds ~/.vscan/creds.yaml`

## Networks & VLANs

- LAN + subnets reachable at **L3**
- Auto-discover local VLAN ifaces + short passive listen
- Type **`c`** or a CIDR in the launcher
- **No** VLAN-hop attacks

## Tips

- Prefer **root/sudo** for ARP + OS detect (`-O`)
- Needs **nmap** (optional **arp-scan**)
- Data: `~/.vscan/`
- Languages: `en` `ka` `ru` `de` `fr` `es`

## Safety

Scan **only** networks you own or have written permission to assess.
"""


def print_help(console: Console) -> None:
    body = HELP_MARKDOWN.format(
        tagline=__tagline__,
        version=__version__,
        author=__author__,
    )
    console.print(Panel(Markdown(body), border_style="green", title="V.SCAN help"))
