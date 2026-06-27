# nxlookup

Domain and IP investigation tool — WHOIS, DNS records, IP/ASN info in one command.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)

Runs on Linux, macOS, Windows, WSL. Two modes:

- **Pure Python:** `pip install dnspython python-whois` — zero system dependencies
- **System tools:** uses `dig` and `whois` if available (no pip install needed)

## Features

- WHOIS with registrar, dates, statuses, nameservers (resolves NS hostnames to IPs)
- DNS records: A, AAAA, MX, NS, TXT, SOA, CNAME
- Per-IP analysis: PTR, ASN/provider, IP range, country, abuse contact
- IDN domains (объясняем.рф, 百度.cn) — auto punycode conversion
- URL input: `https://www.example.com/path` → strips to `example.com`
- IP mode: WHOIS + reverse DNS for direct IP lookups
- 90+ TLDs supported (ru, рф, com, net, org, it, de, fr, uk, cn, io, me, tv, ...)

## Install

### One-liner (Linux / macOS / WSL)

```bash
sudo curl -sSL https://raw.githubusercontent.com/nexxrt/nxlookup/main/nxlookup.py -o /usr/local/bin/nxlookup && sudo chmod +x /usr/local/bin/nxlookup
```

### From source

```bash
git clone https://github.com/nexxrt/nxlookup.git
cd nxlookup
sudo cp nxlookup.py /usr/local/bin/nxlookup
sudo chmod +x /usr/local/bin/nxlookup
```

### WSL (Windows) — step by step

If you're on Windows and new to WSL:

**1. Install WSL.** Open PowerShell as Administrator and run:

```powershell
wsl --install
```

Restart when prompted. After reboot, a Ubuntu terminal will open — create a username and password.

**2. Install dependencies.** In the Ubuntu terminal:

```bash
sudo apt update
sudo apt install -y dnsutils whois
```

**3. Install nxlookup:**

```bash
sudo curl -sSL https://raw.githubusercontent.com/nexxrt/nxlookup/main/nxlookup.py -o /usr/local/bin/nxlookup
sudo chmod +x /usr/local/bin/nxlookup
```

**4. Verify:**

```bash
nxlookup --version
```

### Dependencies

| Tool | Debian/Ubuntu | Arch | macOS | Fedora |
|------|--------------|------|-------|--------|
| dig | `apt install dnsutils` | `pacman -S bind` | `brew install bind` | `dnf install bind-utils` |
| whois | `apt install whois` | `pacman -S whois` | `brew install whois` | `dnf install whois` |

Python 3.8+ is required (included by default on all major distros).

## Usage

```bash
# Domain
nxlookup yandex.ru
nxlookup github.com

# IP address
nxlookup 8.8.8.8

# IDN domain
nxlookup объясняем.рф

# URL (protocol and path are stripped)
nxlookup https://www.example.com/some/path

# Interactive (asks for target)
nxlookup

# Help
nxlookup --help
```

## Example output

```
$ nxlookup github.com

╔══════════════════════════════════════════════════╗
║  nxlookup — Ultimate Domain/IP Investigation          ║
╚══════════════════════════════════════════════════╝

  Target: github.com (domain)

━━━ 1. WHOIS DATA ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Domain:          GITHUB.COM
  Registrar:       MarkMonitor Inc.
  Created:         2007-10-09T18:20:50Z
  Expires:         2026-10-09T18:20:50Z
  Status:          clientDeleteProhibited
                   clientTransferProhibited
                   clientUpdateProhibited
  ▸ DNS Servers (from WHOIS)
    [1] DNS1.P08.NSONE.NET  →  198.51.44.8
    [2] DNS2.P08.NSONE.NET  →  198.51.45.8
    [3] NS-421.AWSDNS-52.COM  →  205.251.193.165
    ... 5 more

━━━ 2. DNS RESOURCE RECORDS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▸ A Records (1)
    140.82.121.4
  ▸ MX Records (1)
    0 github-com.mail.protection.outlook.com
  ▸ NS Records (8)
    dns1.p08.nsone.net, dns2.p08.nsone.net, ns-421.awsdns-52.com, ...
  ▸ SOA Record
    dns1.p08.nsone.net. hostmaster.nsone.net. 1656468023 ...

━━━ 3. IP ADDRESS ANALYSIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▸ 140.82.121.4
    PTR:             lb-140-82-121-4-fra.github.com
    Organization:    GitHub, Inc.
    NetName:         GITHU
    Range:           140.82.112.0 - 140.82.127.255
    Country:         US
    Abuse Contact:   noc@github.com

━━━ 4. QUICK SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Domain:       github.com
  Registrar:    MarkMonitor Inc.
  Expires:      2026-10-09T18:20:50Z
  Nameservers:  8 found
  A Records:    1 — 140.82.121.4
  MX Records:  1
```

## Supported TLDs

The default `whois.conf` covers 250+ zones. For a lighter config (~90 zones), use `whois-normal.conf`:

```bash
# Default — full coverage (250+ zones)
sudo cp whois.conf /etc/whois.conf

# Light — core zones only (~90 zones)
sudo cp whois-normal.conf /etc/whois.conf
```

> **Note for Windows users:** `nxlookup.exe` uses direct socket connections and `python-whois` library — no system config needed.

| Region | Normal (~90) | Extended adds |
|--------|-------------|---------------|
| Russia/CIS | 14 | +2 IDN variants |
| Europe | 25 | +10 (ro, bg, hr, si, rs, ba, al, mk, mt, cy, li, mc, sm, va) |
| UK | 4 | +6 (.ltd.uk, .plc.uk, .net.uk, .ac.uk, .gov.uk, .sch.uk) |
| Asia-Pacific | 14 | +12 (th, vn, id, bd, pk, lk, np, mn, kh, la, mm, bn, mo) |
| gTLD | 15 | +5 (edu, gov, mil, int, arpa) |
| New gTLD | 25 | +120 (Identity Digital, Donuts, Google Registry, specialty) |
| Island/Pacific | 4 | +16 (fm, to, pw, nu, cx, gs, ms, vg, tc, gd, ki, ...) |
| Americas | 9 | +18 (ve, ec, uy, py, bo, do, cr, pa, gt, sv, hn, ...) |
| Africa | none | +16 (za, ng, ke, eg, ma, tn, dz, mu, gh, rw, tz, ...) |
| Middle East | none | +14 (il, ae, sa, qa, ir, tr, lb, jo, bh, kw, om, ...) |

## Building a standalone Windows EXE

The script can be compiled into a single `.exe` that runs on Windows without Python installed.

### Requirements

- Windows with Python 3.8+
- Git (optional — you can download the script manually)

### Steps

```powershell
# 1. Clone or download
git clone https://github.com/nexxrt/nxlookup.git
cd nxlookup

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# 3. Install dependencies + PyInstaller
pip install -r requirements.txt pyinstaller

# 4. Build
pyinstaller --onefile --name nxlookup nxlookup.py
```

The compiled `.exe` will be in `dist\nxlookup.exe` (roughly 8–12 MB).

Pre-built releases are available on the [Releases](https://github.com/nexxrt/nxlookup/releases) page — built automatically via GitHub Actions on every version tag.

### What's bundled

The EXE includes `dnspython` (DNS resolution) and a built-in WHOIS client (direct socket connections to registry servers). No `dig`, `whois`, or other system tools needed.

## Notes

- Some registries (.it, .de) return limited WHOIS data due to GDPR. DNS and IP analysis still work.
- To update: re-run the curl install command — it overwrites the script.
- For the `.exe` version: download the latest release from GitHub.
- **Windows Defender false positive:** PyInstaller-packed `.exe` files may trigger antivirus warnings. This is a known false positive — the tool is open source and safe. If you get a warning, use `nxlookup.zip` from the releases page instead, or add an exclusion for the file.

## License

MIT — see [LICENSE](LICENSE).
