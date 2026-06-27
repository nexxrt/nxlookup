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

The tool uses the system `whois` with an extended config covering 90+ zones:

| Region | TLDs |
|--------|------|
| Russia/CIS | ru, рф, su, kz, by, uz, kg, tj, tm, az, ge, am, md, ua |
| Europe | eu, it, de, fr, nl, be, ch, at, es, pt, pl, se, no, dk, fi, ie, cz, sk, hu, lt, lv, ee, lu, is, gr |
| UK | uk, co.uk, org.uk, me.uk |
| Asia-Pacific | cn, jp, kr, in, sg, au, nz, hk, tw, ph, my |
| gTLD | com, net, org, info, biz, name, mobi, xxx, tel, aero, asia, cat |
| New gTLD | xyz, top, club, online, site, shop, blog, app, dev, cloud, tech, digital, email, guru, link, live, media, rocks, solutions, space, today, website, world, zone |
| Island/ccTLD | io, me, tv, cc, ws, tk |
| Americas | ca, br, mx, us, co, pe, cl, ar |

`.pro` uses RDAP (port 43 whois is disabled) — queried over HTTPS.

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

## License

MIT — see [LICENSE](LICENSE).
