#!/usr/bin/env python3
"""
nxlookup — Domain/IP Investigation Tool
Cross-platform: Linux, macOS, Windows, WSL.
Pure Python mode: pip install dnspython python-whois
Fallback mode: requires dig + whois on PATH.
Usage: nxlookup <domain|ip>   or   nxlookup (interactive)
"""

import sys
import re
import ipaddress
import socket
import os

# ── Optional pure-Python deps ──────────────────────────────────────────
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois as pywhois
    HAS_PYWHOIS = True
except ImportError:
    HAS_PYWHOIS = False

# We still need subprocess/shutil for fallback mode
import subprocess
import shutil

HAS_DIG = shutil.which("dig") is not None
HAS_WHOIS = shutil.which("whois") is not None

# ── Colors (ANSI; use colorama on Windows if available) ────────────────
try:
    import colorama
    colorama.init()
except ImportError:
    pass

C = {
    "reset":   "\033[0m",  "bold": "\033[1m",  "dim":  "\033[2m",
    "red":     "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue":    "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "white":   "\033[37m",
}

def c(color: str, text: str) -> str:
    if os.name == "nt" and "colorama" not in sys.modules:
        return text  # no ANSI on Windows without colorama
    return f"{C.get(color, '')}{text}{C['reset']}"


# ── Banner ─────────────────────────────────────────────────────────────

def banner():
    return f"""
{c('cyan', '╔══════════════════════════════════════════════════╗')}
{c('cyan', '║')}  {c('bold', 'nxlookup')} — {c('green', 'Domain / IP Investigation')}                {c('cyan', '║')}
{c('cyan', '╚══════════════════════════════════════════════════╝')}
"""


# ── Helpers ────────────────────────────────────────────────────────────

def section(title: str):
    print(f"\n{c('yellow', '━━━')} {c('bold', title)} {c('yellow', '━' * (60 - len(title)))}")

def sub_section(title: str):
    print(f"  {c('cyan', '▸')} {c('bold', title)}")

def kv(key: str, value: str, highlight: bool = False):
    val = c('green', value) if highlight else value
    print(f"  {c('dim', key + ':') :<24s} {val}")

def kv_list(key: str, values: list):
    if not values:
        return
    print(f"  {c('dim', key + ':') :<24s} {values[0]}")
    for v in values[1:]:
        print(f"  {'':24s} {v}")

def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_domain(target: str) -> bool:
    if is_ip(target):
        return False
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z0-9\-]{2,}$', target))


# ── DNS (pure Python via dnspython, fallback to dig) ───────────────────

def _dns_resolve(domain: str, rtype: str) -> list[str]:
    """Resolve DNS records using dnspython."""
    if not HAS_DNSPYTHON:
        return _dns_dig(domain, rtype)
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [str(r).rstrip('.') for r in answers]
    except Exception:
        return []

def _dns_dig(domain: str, rtype: str) -> list[str]:
    """Fallback: resolve DNS using dig command."""
    try:
        out = subprocess.run(["dig", "+short", domain, rtype],
                           capture_output=True, text=True, timeout=15)
        return [l.strip().rstrip('.') for l in out.stdout.splitlines() if l.strip()]
    except Exception:
        return []

def dns_query(domain: str, rtype: str) -> list[str]:
    return _dns_resolve(domain, rtype)

def dns_all(domain: str) -> dict:
    types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    return {t: dns_query(domain, t) for t in types}

def ptr_lookup(ip: str) -> str:
    """Reverse DNS."""
    if HAS_DNSPYTHON:
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            return str(answers[0]).rstrip('.')
        except Exception:
            return ""
    try:
        out = subprocess.run(["dig", "+short", "-x", ip],
                           capture_output=True, text=True, timeout=10)
        return out.stdout.strip().rstrip('.')
    except Exception:
        return ""


# ── WHOIS ──────────────────────────────────────────────────────────────

def _whois_query(target: str) -> str:
    """WHOIS lookup — pure Python or fallback to CLI."""
    if HAS_PYWHOIS:
        try:
            w = pywhois.whois(target)
            return w.text if hasattr(w, 'text') and w.text else ""
        except Exception:
            pass
    if HAS_WHOIS:
        try:
            r = subprocess.run(["whois", "-H", target],
                             capture_output=True, text=True, timeout=20)
            return r.stdout
        except Exception:
            pass
    return ""

def _ip_whois_raw(ip: str) -> str:
    """Raw WHOIS for an IP address using direct socket connection."""
    # Step 1: find RIR from IANA
    try:
        s = socket.create_connection(("whois.iana.org", 43), timeout=10)
        s.sendall((ip + "\r\n").encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        text = resp.decode("utf-8", errors="replace")
        # Extract referral server
        m = re.search(r'(?i)^refer:\s*(\S+)', text, re.MULTILINE)
        if not m:
            m = re.search(r'(?i)^whois:\s*(\S+)', text, re.MULTILINE)
        if m:
            server = m.group(1)
            # Step 2: query the RIR
            s2 = socket.create_connection((server, 43), timeout=10)
            s2.sendall((ip + "\r\n").encode())
            resp2 = b""
            while True:
                chunk = s2.recv(4096)
                if not chunk:
                    break
                resp2 += chunk
            s2.close()
            return resp2.decode("utf-8", errors="replace")
        return text
    except Exception:
        return ""

def _domain_whois_data(domain: str) -> dict:
    """WHOIS lookup for a domain — returns parsed dict with structured fields."""
    data = {
        "domain": "", "registrar": "", "whois_server": "", "status": [],
        "nameservers": [], "created": "", "expires": "", "updated": "",
        "registrant": "", "org": "", "country": "",
    }

    # Prefer python-whois structured data
    if HAS_PYWHOIS:
        try:
            w = pywhois.whois(domain)
            # domain name
            dn = w.get('domain_name')
            if dn:
                data["domain"] = dn if isinstance(dn, str) else dn[0]
            # registrar
            r = w.get('registrar')
            if r:
                data["registrar"] = r if isinstance(r, str) else r
            # whois server
            ws = w.get('whois_server')
            if ws:
                data["whois_server"] = ws if isinstance(ws, str) else ws
            # nameservers — strip trailing dot and inline IPs
            ns = w.get('name_servers')
            if ns:
                cleaned = []
                for n in ns:
                    if n:
                        host = n.split()[0].rstrip('.').lower()
                        cleaned.append(host)
                data["nameservers"] = cleaned
            # status
            st = w.get('status')
            if st:
                data["status"] = st if isinstance(st, list) else [st]
            # dates
            cd = w.get('creation_date')
            if cd:
                data["created"] = str(cd if isinstance(cd, str) else cd[0] if isinstance(cd, list) else cd)
            ed = w.get('expiration_date')
            if ed:
                data["expires"] = str(ed if isinstance(ed, str) else ed[0] if isinstance(ed, list) else ed)
            ud = w.get('updated_date')
            if ud:
                data["updated"] = str(ud if isinstance(ud, str) else ud[0] if isinstance(ud, list) else ud)
            # org
            o = w.get('org')
            if o:
                data["org"] = o if isinstance(o, str) else o
            # country
            c = w.get('country')
            if c:
                data["country"] = c if isinstance(c, str) else c
            # registrant
            reg = w.get('name') or w.get('registrant_name')
            if reg:
                data["registrant"] = reg if isinstance(reg, str) else reg

            return data
        except Exception:
            pass

    # Fallback: system whois + regex parsing
    if HAS_WHOIS:
        try:
            r = subprocess.run(["whois", "-H", domain],
                             capture_output=True, text=True, timeout=20)
            return parse_domain_whois(r.stdout)
        except Exception:
            pass

    return data


def _domain_whois_raw(domain: str) -> str:
    """Raw WHOIS text for a domain (used only as fallback display)."""
    if HAS_PYWHOIS:
        try:
            w = pywhois.whois(domain)
            return w.text if hasattr(w, 'text') and w.text else ""
        except Exception:
            pass
    if HAS_WHOIS:
        try:
            r = subprocess.run(["whois", "-H", domain],
                             capture_output=True, text=True, timeout=20)
            return r.stdout
        except Exception:
            pass
    return ""

def ip_whois_raw(ip: str) -> str:
    """WHOIS for an IP."""
    # Try pure Python socket approach first
    raw = _ip_whois_raw(ip)
    if raw:
        return raw
    # Fall back to whois CLI
    return _whois_query(ip)


# ── Parsing ────────────────────────────────────────────────────────────

def parse_domain_whois(raw: str) -> dict:
    data = {
        "domain": "", "registrar": "", "whois_server": "", "status": [],
        "nameservers": [], "created": "", "expires": "", "updated": "",
        "registrant": "", "org": "", "country": "",
    }

    patterns = [
        (r'(?i)^\s*Domain Name:\s*(.+)', 'domain'),
        (r'(?i)^\s*domain:\s*(.+)', 'domain'),
        (r'(?i)^\s*Registrar:\s*(.+)', 'registrar'),
        (r'(?i)^\s*registrar:\s*(.+)', 'registrar'),
        (r'(?i)^\s*Registrar WHOIS Server:\s*(.+)', 'whois_server'),
        (r'(?i)^\s*Creation Date:\s*(.+)', 'created'),
        (r'(?i)^\s*created:\s*(.+)', 'created'),
        (r'(?i)^\s*Created:\s*(.+)', 'created'),
        (r'(?i)^\s*Registry Expiry Date:\s*(.+)', 'expires'),
        (r'(?i)^\s*Expiry Date:\s*(.+)', 'expires'),
        (r'(?i)^\s*paid-till:\s*(.+)', 'expires'),
        (r'(?i)^\s*Updated Date:\s*(.+)', 'updated'),
        (r'(?i)^\s*Registrant Organization:\s*(.+)', 'org'),
        (r'(?i)^\s*org:\s*(.+)', 'org'),
        (r'(?i)^\s*Registrant:\s*(.+)', 'registrant'),
        (r'(?i)^\s*Registrant Country:\s*(.+)', 'country'),
    ]

    for pat, key in patterns:
        m = re.search(pat, raw, re.MULTILINE)
        if m and not data[key]:
            data[key] = m.group(1).strip()

    # Nameservers
    ns_patterns = [
        r'(?i)^\s*Name Server:\s*(.+)',
        r'(?i)^\s*nserver:\s*(.+)',
        r'(?i)^\s*Nserver:\s*(.+)',
    ]
    seen = set()
    for p in ns_patterns:
        for m in re.finditer(p, raw, re.MULTILINE):
            ns = m.group(1).split()[0].rstrip('.')
            if ns and ns not in seen:
                seen.add(ns)
                data["nameservers"].append(ns)

    # Status
    for m in re.finditer(r'(?i)^\s*(?:Domain |domain |)Status:\s*(.+)', raw, re.MULTILINE):
        data["status"].append(m.group(1).strip())
    for m in re.finditer(r'(?i)^\s*state:\s*(.+)', raw, re.MULTILINE):
        data["status"].append(m.group(1).strip())

    return data


def parse_ip_whois(raw: str) -> dict:
    data = {
        "inetnum": "", "netname": "", "org": "", "country": "",
        "descr": "", "role": "", "abuse": "",
    }
    patterns = [
        (r'(?i)^\s*inetnum:\s*(.+)', 'inetnum'),
        (r'(?i)^\s*NetRange:\s*(.+)', 'inetnum'),
        (r'(?i)^\s*CIDR:\s*(.+)', 'inetnum'),
        (r'(?i)^\s*netname:\s*(.+)', 'netname'),
        (r'(?i)^\s*NetName:\s*(.+)', 'netname'),
        (r'(?i)^\s*(?:org-name|OrgName):\s*(.+)', 'org'),
        (r'(?i)^\s*organisation:\s*(.+)', 'org'),
        (r'(?i)^\s*Organization:\s*(.+)', 'org'),
        (r'(?i)^\s*(?:country|Country):\s*(.+)', 'country'),
        (r'(?i)^\s*descr:\s*(.+)', 'descr'),
        (r'(?i)^\s*role:\s*(.+)', 'role'),
        (r'(?i)^\s*OrgAbuseEmail:\s*(.+)', 'abuse'),
    ]
    for pat, key in patterns:
        m = re.search(pat, raw, re.MULTILINE)
        if m and not data[key]:
            data[key] = m.group(1).strip()
    return data


# ── Display ────────────────────────────────────────────────────────────

def display_domain(target: str, display_target: str = ""):
    if not display_target:
        display_target = target
    print(banner())
    print(f"  {c('bold', 'Target:')} {c('green', display_target)} {c('dim', '(domain)')}")
    if target != display_target:
        print(f"  {c('dim', 'Punycode:')} {c('dim', target)}")
    print()

    # 1. WHOIS
    section("1. WHOIS DATA")
    w = _domain_whois_data(target)

    if w["domain"]:
        kv("Domain", w["domain"])
    if w["registrar"]:
        kv("Registrar", w["registrar"], highlight=True)
    if w["whois_server"]:
        kv("WHOIS Server", w["whois_server"])
    if w["org"]:
        kv("Organization", w["org"])
    if w["registrant"]:
        kv("Registrant", w["registrant"])
    if w["created"]:
        kv("Created", w["created"])
    if w["expires"]:
        kv("Expires", w["expires"], highlight=True)
    if w["updated"]:
        kv("Updated", w["updated"])
    if w["country"]:
        kv("Country", w["country"])
    if w["status"]:
        kv_list("Status", w["status"])

    if w["nameservers"]:
        sub_section("DNS Servers (from WHOIS)")
        for i, ns in enumerate(w["nameservers"][:12], 1):
            ns_ip = dns_query(ns, "A")
            ip_str = f"  →  {', '.join(ns_ip)}" if ns_ip else ""
            print(f"    {c('dim', f'[{i}]')} {c('green', ns)}{c('cyan', ip_str)}")
    else:
        print(f"  {c('red', '(no nameservers in WHOIS)')}")

    # 2. DNS
    section("2. DNS RESOURCE RECORDS")
    dns = dns_all(target)

    sub_section(f"A Records ({c('green', str(len(dns['A'])))})")
    for ip in dns["A"]:
        print(f"    {c('green', ip)}")
    if not dns["A"]:
        print(f"    {c('dim', '(none)')}")

    sub_section(f"AAAA Records ({c('green', str(len(dns['AAAA'])))})")
    for ip in dns["AAAA"]:
        print(f"    {c('green', ip)}")
    if not dns["AAAA"]:
        print(f"    {c('dim', '(none)')}")

    if dns["CNAME"]:
        sub_section("CNAME")
        for cname in dns["CNAME"]:
            print(f"    {c('green', cname)}")

    sub_section(f"MX Records ({c('green', str(len(dns['MX'])))})")
    for mx in dns["MX"]:
        print(f"    {c('green', mx)}")
    if not dns["MX"]:
        print(f"    {c('dim', '(none)')}")

    sub_section(f"NS Records ({c('green', str(len(dns['NS'])))})")
    for ns in dns["NS"]:
        print(f"    {c('green', ns)}")
    if not dns["NS"]:
        print(f"    {c('dim', '(none)')}")

    if dns["SOA"]:
        sub_section("SOA Record")
        for soa in dns["SOA"]:
            print(f"    {c('green', soa)}")

    if dns["TXT"]:
        sub_section(f"TXT Records ({c('green', str(len(dns['TXT'])))})")
        for txt in dns["TXT"][:6]:
            display = txt if len(txt) < 120 else txt[:117] + "..."
            print(f"    {c('dim', display)}")
        if len(dns["TXT"]) > 6:
            remaining = len(dns["TXT"]) - 6
            print(f"    {c('dim', f'... and {remaining} more')}")

    # 3. IP Analysis
    section("3. IP ADDRESS ANALYSIS")
    all_ips = dns["A"] + dns["AAAA"]
    if not all_ips:
        print(f"  {c('red', 'No A/AAAA records.')}")
    else:
        for i, ip in enumerate(all_ips[:10], 1):
            sub_section(f"{ip}")
            ptr = ptr_lookup(ip)
            if ptr and ptr != ip:
                print(f"    {c('dim', 'PTR:') :<24s} {c('green', ptr)}")

            raw_ip = ip_whois_raw(ip)
            ipw = parse_ip_whois(raw_ip)
            if ipw["org"]:
                print(f"    {c('dim', 'Organization:') :<24s} {c('yellow', ipw['org'])}")
            if ipw["netname"]:
                print(f"    {c('dim', 'NetName:') :<24s} {ipw['netname']}")
            if ipw["inetnum"]:
                print(f"    {c('dim', 'Range:') :<24s} {ipw['inetnum']}")
            if ipw["country"]:
                print(f"    {c('dim', 'Country:') :<24s} {ipw['country']}")
            if ipw["descr"]:
                print(f"    {c('dim', 'Description:') :<24s} {ipw['descr']}")
            if ipw["abuse"]:
                print(f"    {c('dim', 'Abuse Contact:') :<24s} {ipw['abuse']}")

    # 4. Summary
    section("4. QUICK SUMMARY")
    print(f"  {c('bold', 'Domain:')}       {c('green', display_target)}")
    print(f"  {c('bold', 'Registrar:')}    {c('yellow', w.get('registrar', 'N/A'))}")
    print(f"  {c('bold', 'Expires:')}      {c('yellow', w.get('expires', 'N/A'))}")
    print(f"  {c('bold', 'Nameservers:')}  {c('green', str(len(w['nameservers'])))} found")
    a_list = ', '.join(dns['A'][:5])
    print(f"  {c('bold', 'A Records:')}    {c('green', str(len(dns['A'])))} — {a_list}{'...' if len(dns['A']) > 5 else ''}")
    if dns["AAAA"]:
        print(f"  {c('bold', 'AAAA Recs:')}   {c('green', str(len(dns['AAAA'])))}")
    if dns["MX"]:
        print(f"  {c('bold', 'MX Records:')}  {c('green', str(len(dns['MX'])))}")
    print()


def display_ip(target: str):
    print(banner())
    print(f"  {c('bold', 'Target:')} {c('green', target)} {c('dim', '(IP)')}")
    print()

    # Reverse DNS
    section("1. REVERSE DNS")
    ptr = ptr_lookup(target)
    if ptr and ptr != target:
        print(f"  {c('dim', 'PTR:') :<24s} {c('green', ptr)}")
    else:
        print(f"  {c('red', 'No PTR record.')}")

    # IP WHOIS
    section("2. IP WHOIS / PROVIDER INFO")
    raw = ip_whois_raw(target)
    ipw = parse_ip_whois(raw)

    if ipw["inetnum"]:
        kv("IP Range", ipw["inetnum"])
    if ipw["netname"]:
        kv("NetName", ipw["netname"], highlight=True)
    if ipw["org"]:
        kv("Organization", ipw["org"], highlight=True)
    if ipw["descr"]:
        kv("Description", ipw["descr"])
    if ipw["country"]:
        kv("Country", ipw["country"])
    if ipw["role"]:
        kv("Role", ipw["role"])
    if ipw["abuse"]:
        kv("Abuse Contact", ipw["abuse"], highlight=True)

    if not any([ipw["org"], ipw["netname"], ipw["inetnum"]]):
        print(f"\n  {c('dim', 'Raw WHOIS snippet:')}")
        for line in raw.splitlines()[:15]:
            print(f"    {c('dim', line)}")
    print()


# ── Main ───────────────────────────────────────────────────────────────

def lookup(target: str):
    """Process a single target (domain or IP). Returns True if valid, False otherwise."""
    # Clean input
    original = target
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    target = target.split(':')[0]
    target = re.sub(r'^www\.', '', target)

    # IDN support
    display_target = target
    if not target.isascii():
        try:
            target = target.encode('idna').decode('ascii')
        except (UnicodeError, ValueError):
            pass

    if is_ip(target):
        display_ip(target)
        return True
    elif is_domain(target):
        display_domain(target, display_target)
        return True
    else:
        print(f"{c('red', 'Error:')} '{original}' is not a valid domain or IP.")
        return False


def main():
    target = None
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg in ("--help", "-h"):
            print(banner())
            print(f"  {c('bold', 'Usage:')}  nxlookup {c('cyan', '<domain | IP>')}")
            print(f"  {c('bold', 'Examples:')}")
            print(f"    nxlookup {c('green', 'yandex.ru')}")
            print(f"    nxlookup {c('green', 'github.com')}")
            print(f"    nxlookup {c('green', '8.8.8.8')}")
            print(f"    nxlookup {c('dim', '(interactive)')}")
            print()
            sys.exit(0)
        if arg in ("--version", "-v"):
            print("nxlookup v1.1.1")
            sys.exit(0)
        # Single-shot mode: one lookup then exit
        if not lookup(arg):
            sys.exit(1)
        return

    # Interactive mode (no args or .exe double-click)
    print(banner())
    print(f"  {c('dim', 'Type a domain or IP. Empty line, exit or quit to quit.')}")
    print()
    while True:
        try:
            target = input(f"  {c('cyan', 'nxlookup')} {c('dim', '>')} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {c('dim', 'Bye.')}")
            break
        if not target or target.lower() in ("exit", "quit", "q"):
            print(f"  {c('dim', 'Bye.')}")
            break
        print()
        lookup(target)
        print()


if __name__ == "__main__":
    main()
