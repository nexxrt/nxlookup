#!/usr/bin/env python3
"""
nxlookup — Ultimate Domain/IP Investigation Tool
Linux/macOS/WSL version.
Requires: dig (bind), whois
Usage: nxlookup <domain|ip>   or   nxlookup (interactive)
"""

import subprocess
import sys
import re
import ipaddress
import shutil
import os
from typing import Optional

# ── Colors ─────────────────────────────────────────────────────────────
C = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "red":     "\033[31m",
    "green":   "\033[32m",
    "yellow":  "\033[33m",
    "blue":    "\033[34m",
    "magenta": "\033[35m",
    "cyan":    "\033[36m",
    "white":   "\033[37m",
    "R":        "\033[0m",   # alias
}

def c(color: str, text: str) -> str:
    return f"{C.get(color, '')}{text}{C['reset']}"

# ── Helpers ────────────────────────────────────────────────────────────

def banner():
    return f"""
{c('cyan', '╔══════════════════════════════════════════════════╗')}
{c('cyan', '║')}  {c('bold', 'nxlookup')} — {c('green', 'Ultimate Domain/IP Investigation')}          {c('cyan', '║')}
{c('cyan', '╚══════════════════════════════════════════════════╝')}
"""

def section(title: str):
    print(f"\n{c('yellow', '━━━')} {c('bold', title)} {c('yellow', '━' * (60 - len(title)))}")

def sub_section(title: str):
    print(f"  {c('cyan', '▸')} {c('bold', title)}")

def kv(key: str, value: str, highlight: bool = False):
    val = c('green', value) if highlight else value
    print(f"  {c('dim', key + ':') :<24s} {val}")

def kv_list(key: str, values: list, highlight: bool = False):
    if not values:
        return
    val = c('green', values[0]) if highlight else values[0]
    print(f"  {c('dim', key + ':') :<24s} {val}")
    for v in values[1:]:
        print(f"  {'':24s} {v}")

def run(cmd: list, timeout: int = 20) -> str:
    """Run command and return stdout, or '' on failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""

def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_domain(target: str) -> bool:
    # rough check: has at least one dot, no spaces, no path chars
    if is_ip(target):
        return False
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z0-9\-]{2,}$', target))

# ── WHOIS parsing ──────────────────────────────────────────────────────

def parse_whois(raw: str) -> dict:
    """Extract structured fields from whois output."""
    data = {
        "domain": "", "registrar": "", "whois_server": "", "status": [],
        "nameservers": [], "created": "", "expires": "", "updated": "",
        "registrant": "", "org": "", "country": "", "raw_short": raw[:2000],
    }

    # Common patterns across registries (some have leading whitespace)
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

    for pattern, key in patterns:
        if key is None:
            continue
        m = re.search(pattern, raw, re.MULTILINE)
        if m and not data[key]:
            data[key] = m.group(1).strip()

    # Nameservers: multiple formats (allow leading whitespace)
    ns_patterns = [
        r'(?i)^\s*Name Server:\s*(.+)',
        r'(?i)^\s*nserver:\s*(.+)',
        r'(?i)^\s*Nserver:\s*(.+)',
    ]
    seen_ns = set()
    for p in ns_patterns:
        for m in re.finditer(p, raw, re.MULTILINE):
            ns = m.group(1).strip()
            # Some servers include IP — split off
            ns_clean = ns.split()[0].rstrip('.')
            if ns_clean and ns_clean not in seen_ns:
                seen_ns.add(ns_clean)
                data["nameservers"].append(ns)

    # Status
    for m in re.finditer(r'(?i)^\s*(?:Domain |domain |)Status:\s*(.+)', raw, re.MULTILINE):
        data["status"].append(m.group(1).strip())
    for m in re.finditer(r'(?i)^\s*state:\s*(.+)', raw, re.MULTILINE):
        data["status"].append(m.group(1).strip())

    return data


def parse_ip_whois(raw: str) -> dict:
    """Extract fields from IP whois (ARIN/RIPE/APNIC)."""
    data = {
        "inetnum": "", "netname": "", "org": "", "country": "",
        "descr": "", "role": "", "abuse": "", "raw_short": raw[:2000],
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


# ── DNS queries ────────────────────────────────────────────────────────

def dig(domain: str, rtype: str) -> list[str]:
    """Return dig +short results as list."""
    out = run(["dig", "+short", domain, rtype], timeout=15)
    if not out:
        return []
    return [line.strip().rstrip('.') for line in out.splitlines() if line.strip()]

def dig_all(domain: str) -> dict:
    """Query all relevant record types."""
    types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    result = {}
    for t in types:
        result[t] = dig(domain, t)
    # Deduplicate NS (already in whois, but also useful here)
    return result

def ptr_lookup(ip: str) -> str:
    """Reverse DNS lookup."""
    out = run(["dig", "+short", "-x", ip], timeout=10)
    return out.rstrip('.') if out else ""

def ip_whois(ip: str) -> str:
    """WHOIS on an IP address."""
    return run(["whois", "-H", ip], timeout=20)

# ── Display ────────────────────────────────────────────────────────────

def display_domain(target: str, display_target: str = ""):
    """Full domain investigation."""
    if not display_target:
        display_target = target
    print(banner())
    print(f"  {c('bold', 'Target:')} {c('green', display_target)} {c('dim', '(domain)')}")
    if target != display_target:
        print(f"  {c('dim', 'Punycode:')} {c('dim', target)}")
    print()

    # ── 1. WHOIS ──
    section("1. WHOIS DATA")
    raw_whois = run(["whois", "-H", target], timeout=20)
    w = parse_whois(raw_whois)

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

    # Nameservers (from WHOIS — most reliable)
    if w["nameservers"]:
        sub_section("DNS Servers (from WHOIS)")
        for i, ns in enumerate(w["nameservers"], 1):
            # Resolve NS hostname to IP
            ns_ip = dig(ns, "A")
            ip_str = f"  →  {', '.join(ns_ip)}" if ns_ip else ""
            print(f"    {c('dim', f'[{i}]')} {c('green', ns)}{c('cyan', ip_str)}")
    else:
        print(f"  {c('red', '(no nameservers found in WHOIS)')}")

    # ── 2. DNS Resource Records ──
    section("2. DNS RESOURCE RECORDS")
    dns = dig_all(target)

    # A records
    sub_section(f"A Records ({c('green', str(len(dns['A'])))})")
    if dns["A"]:
        for ip in dns["A"]:
            print(f"    {c('green', ip)}")
    else:
        print(f"    {c('red', '(none)')}")

    # AAAA records
    sub_section(f"AAAA Records ({c('green', str(len(dns['AAAA'])))})")
    if dns["AAAA"]:
        for ip in dns["AAAA"]:
            print(f"    {c('green', ip)}")
    else:
        print(f"    {c('dim', '(none)')}")

    # CNAME
    if dns["CNAME"]:
        sub_section("CNAME")
        for cname in dns["CNAME"]:
            print(f"    {c('green', cname)}")

    # MX
    sub_section(f"MX Records ({c('green', str(len(dns['MX'])))})")
    if dns["MX"]:
        for mx in dns["MX"]:
            print(f"    {c('green', mx)}")
    else:
        print(f"    {c('dim', '(none)')}")

    # NS (from DNS)
    sub_section(f"NS Records ({c('green', str(len(dns['NS'])))})")
    if dns["NS"]:
        for ns in dns["NS"]:
            print(f"    {c('green', ns)}")
    else:
        print(f"    {c('dim', '(none)')}")

    # SOA
    if dns["SOA"]:
        sub_section("SOA Record")
        for soa in dns["SOA"]:
            print(f"    {c('green', soa)}")

    # TXT (abbreviated)
    if dns["TXT"]:
        sub_section(f"TXT Records ({c('green', str(len(dns['TXT'])))})")
        for txt in dns["TXT"][:6]:
            # Truncate long TXT records
            display = txt if len(txt) < 120 else txt[:117] + "..."
            print(f"    {c('dim', display)}")
        if len(dns["TXT"]) > 6:
            remaining = len(dns["TXT"]) - 6
            print(f"    {c('dim', f'... and {remaining} more')}")

    # ── 3. IP Analysis ──
    section("3. IP ADDRESS ANALYSIS")
    all_ips = dns["A"] + dns["AAAA"]
    if not all_ips:
        print(f"  {c('red', 'No A/AAAA records to analyze.')}")
    else:
        for i, ip in enumerate(all_ips[:10], 1):  # max 10 IPs
            sub_section(f"{ip}")
            # Reverse DNS
            ptr = ptr_lookup(ip)
            if ptr and ptr != ip:
                print(f"    {c('dim', 'PTR:') :<24s} {c('green', ptr)}")

            # IP WHOIS (abbreviated)
            raw_ip_whois = ip_whois(ip)
            ipw = parse_ip_whois(raw_ip_whois)
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

    # ── 4. Quick Summary ──
    section("4. QUICK SUMMARY")
    print(f"  {c('bold', 'Domain:')}       {c('green', display_target)}")
    print(f"  {c('bold', 'Registrar:')}    {c('yellow', w.get('registrar', 'N/A'))}")
    print(f"  {c('bold', 'Expires:')}      {c('yellow', w.get('expires', 'N/A'))}")
    print(f"  {c('bold', 'Nameservers:')}  {c('green', str(len(w['nameservers'])))} found")
    print(f"  {c('bold', 'A Records:')}    {c('green', str(len(dns['A'])))} — {', '.join(dns['A'][:5])}{'...' if len(dns['A']) > 5 else ''}")
    if dns["AAAA"]:
        print(f"  {c('bold', 'AAAA Recs:')}   {c('green', str(len(dns['AAAA'])))}")
    if dns["MX"]:
        print(f"  {c('bold', 'MX Records:')}  {c('green', str(len(dns['MX'])))}")
    print()


def display_ip(target: str):
    """Full IP investigation."""
    print(banner())
    print(f"  {c('bold', 'Target:')} {c('green', target)} {c('dim', '(IP address)')}")
    print()

    # ── 1. Reverse DNS ──
    section("1. REVERSE DNS")
    ptr = ptr_lookup(target)
    if ptr and ptr != target:
        print(f"  {c('dim', 'PTR:') :<24s} {c('green', ptr)}")
    else:
        print(f"  {c('red', 'No PTR record found.')}")

    # ── 2. IP WHOIS ──
    section("2. IP WHOIS / PROVIDER INFO")
    raw_ip_whois = ip_whois(target)
    ipw = parse_ip_whois(raw_ip_whois)

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

    # Show a raw snippet if fields are sparse
    if not any([ipw["org"], ipw["netname"], ipw["inetnum"]]):
        print(f"\n  {c('dim', 'Raw WHOIS snippet:')}")
        for line in raw_ip_whois.splitlines()[:15]:
            print(f"    {c('dim', line)}")

    print()


# ── Main ───────────────────────────────────────────────────────────────

def main():
    target = None

    # Parse arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg in ("--help", "-h"):
            print(banner())
            print(f"  {c('bold', 'Usage:')}  nxlookup {c('cyan', '<domain | IP>')}")
            print(f"  {c('bold', 'Examples:')}")
            print(f"    nxlookup {c('green', 'yandex.ru')}")
            print(f"    nxlookup {c('green', 'github.com')}")
            print(f"    nxlookup {c('green', '8.8.8.8')}")
            print(f"    nxlookup {c('dim', '(interactive mode)')}")
            print()
            sys.exit(0)
        if arg in ("--version", "-v"):
            print("nxlookup v1.0.0 — Ultimate Domain/IP Investigation Tool")
            sys.exit(0)
        target = arg
    else:
        # Interactive mode
        print(banner())
        target = input(f"  {c('cyan', 'Enter domain or IP')} {c('dim', '>')} ").strip()

    if not target:
        print(f"{c('red', 'Error:')} no target provided.")
        sys.exit(1)

    # Strip protocol, path, port, and www. prefix
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    target = target.split(':')[0]  # strip port
    target = re.sub(r'^www\.', '', target)  # strip www.

    # IDN → punycode for non-ASCII domains (e.g. объясняем.рф → xn--80aafh9a1amc6c5d.xn--p1ai)
    display_target = target
    if not target.isascii():
        try:
            target = target.encode('idna').decode('ascii')
        except (UnicodeError, ValueError):
            pass  # fall through, will fail validation later

    # Check tools
    for tool in ["dig", "whois"]:
        if not shutil.which(tool):
            print(f"{c('red', 'Error:')} {tool} not found. Install it first.")
            sys.exit(1)

    if is_ip(target):
        display_ip(target)
    elif is_domain(target):
        display_domain(target, display_target)
    else:
        print(f"{c('red', 'Error:')} '{target}' is not a valid domain or IP.")
        sys.exit(1)


if __name__ == "__main__":
    main()
