#!/root/nexxlookup/.venv/bin/python3
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
import ssl
import threading
from datetime import datetime, timezone

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

def ssl_check(domain: str) -> dict:
    """Fetch SSL certificate info — IPv4 first, 7s hard timeout."""
    result = {"ok": False, "subject_cn": "", "subject_o": "", "issuer_cn": "", "issuer_o": "",
              "not_before": "", "not_after": "", "days": None, "error": ""}

    def _do():
        last_error = ""
        ctx = ssl.create_default_context()
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                addrs = socket.getaddrinfo(domain, 443, family, socket.SOCK_STREAM)
                if addrs:
                    ip = addrs[0][4][0]
                    try:
                        sock = socket.create_connection((ip, 443), timeout=3)
                        sock.settimeout(3)
                        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                        result["ok"] = True
                        for item in cert.get("subject", []):
                            for k, v in item:
                                if k == "commonName": result["subject_cn"] = v
                                if k == "organizationName": result["subject_o"] = v
                        for item in cert.get("issuer", []):
                            for k, v in item:
                                if k == "commonName": result["issuer_cn"] = v
                                if k == "organizationName": result["issuer_o"] = v
                        result["not_before"] = cert.get("notBefore", "")
                        result["not_after"] = cert.get("notAfter", "")
                        if result["not_after"]:
                            end = datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
                            result["days"] = (end.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                        return
                    except Exception as e:
                        last_error = str(e)
            except Exception:
                continue
        result["error"] = last_error or "No SSL / connection failed"

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout=7)
    if t.is_alive():
        result["error"] = "No SSL / connection failed (timeout)"
    return result

def http_check(domain: str) -> dict:
    """Check HTTP and HTTPS response. Returns status codes for both."""
    result = {"https": 0, "http": 0, "redirect": "", "error": ""}
    for proto, port, key in [("https", 443, "https"), ("http", 80, "http")]:
        try:
            ctx = ssl.create_default_context() if proto == "https" else None
            s = socket.create_connection((domain, port), timeout=8)
            if ctx:
                s = ctx.wrap_socket(s, server_hostname=domain)
            req = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
                if b"\r\n\r\n" in resp: break
            s.close()
            status_line = resp.decode(errors="replace").split("\r\n")[0]
            m = re.match(r"HTTP/\S+\s+(\d+)", status_line)
            if m:
                result[key] = int(m.group(1))
            headers = resp.decode(errors="replace")
            loc = re.search(r"(?i)^Location:\s*(.+)", headers, re.MULTILINE)
            if loc: result["redirect"] = loc.group(1).strip()
        except Exception as e:
            if not result["error"]:
                result["error"] = str(e)
    result["ok"] = result["https"] > 0 or result["http"] > 0
    return result

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
    """Resolve DNS records using dnspython (0.5s timeout)."""
    if not HAS_DNSPYTHON:
        return _dns_dig(domain, rtype)
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=0.5)
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
    result = {t: [] for t in types}

    def _do():
        for t in types:
            result[t] = dns_query(domain, t)

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout=3)
    return result

def ptr_lookup(ip: str) -> str:
    """Reverse DNS."""
    if HAS_DNSPYTHON:
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR", lifetime=1)
            return str(answers[0]).rstrip('.')
        except Exception:
            return ""
    try:
        out = subprocess.run(["dig", "+short", "-x", ip],
                           capture_output=True, text=True, timeout=5)
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
    return _socket_whois(ip, ip)

def _domain_whois_socket(domain: str) -> str:
    """Raw WHOIS for a domain — IANA referral with fallback for known servers."""
    tld = domain.lower().rstrip('.').split('.')[-1]
    result = _socket_whois(tld, domain)
    # Fallback: some ccTLD referral servers don't handle third-level domains.
    # Known servers that work better than IANA referrals:
    _fallback = {
        'ru': 'whois.nic.ru',
    }
    if ('No entries found' in result or 'No match for' in result) and tld in _fallback:
        result = _socket_whois(_fallback[tld], domain, skip_iana=True)
    return result

def _socket_whois(iana_query: str, referral_query: str, skip_iana: bool = False) -> str:
    """Generic socket WHOIS with IANA referral.
    Sends iana_query to whois.iana.org, follows referral, sends referral_query.
    If skip_iana=True, iana_query is used directly as the WHOIS server host."""
    try:
        if skip_iana:
            s2 = socket.create_connection((iana_query, 43), timeout=10)
            s2.sendall((referral_query + "\r\n").encode())
            resp2 = b""
            while True:
                chunk = s2.recv(4096)
                if not chunk: break
                resp2 += chunk
            s2.close()
            return resp2.decode("utf-8", errors="replace")

        # Step 1: query IANA for the right whois server
        s = socket.create_connection(("whois.iana.org", 43), timeout=10)
        s.sendall((iana_query + "\r\n").encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        text = resp.decode("utf-8", errors="replace")

        # Find referral server
        m = re.search(r'(?i)^refer:\s*(\S+)', text, re.MULTILINE)
        if not m:
            m = re.search(r'(?i)^whois:\s*(\S+)', text, re.MULTILINE)
        if not m:
            return text

        ref_server = m.group(1)
        # Step 2: query the referral server
        s2 = socket.create_connection((ref_server, 43), timeout=10)
        s2.sendall((referral_query + "\r\n").encode())
        resp2 = b""
        while True:
            chunk = s2.recv(4096)
            if not chunk:
                break
            resp2 += chunk
        s2.close()
        return resp2.decode("utf-8", errors="replace")
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

    # Fallback 1: direct socket WHOIS + regex parsing (works everywhere)
    raw = _domain_whois_socket(domain)
    if raw:
        parsed = parse_domain_whois(raw)
        if parsed.get("domain"):
            return parsed

    # Fallback 2: system whois CLI
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
        exp_str = w["expires"]
        days = ""
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(exp_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                d = (dt - datetime.now(timezone.utc)).days
                days = f" ({d}d left)" if d >= 0 else " (EXPIRED)"
                break
            except ValueError:
                continue
        kv("Expires", w["expires"] + days, highlight=True)
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

    # 2. SSL — skip if no A records
    section("2. SSL CERTIFICATE")
    a_records = dns_query(target, "A")
    ssl = {"ok": False}
    if not a_records:
        print(f"  {c('dim', 'Skipped — no A records')}")
    else:
        ssl = ssl_check(target)
    if ssl["ok"]:
        if ssl.get("subject_cn"): kv("Issued to", ssl["subject_cn"], highlight=True)
        if ssl.get("subject_o"): kv("Organization", ssl["subject_o"])
        if ssl.get("issuer_cn"): kv("Issued by", ssl["issuer_cn"], highlight=True)
        if ssl.get("issuer_o"): kv("Issuer Org", ssl["issuer_o"])
        if ssl.get("not_before"): kv("Valid from", ssl["not_before"])
        if ssl.get("not_after"):
            days = ssl.get("days")
            label = f"{ssl['not_after']}"
            if days is not None:
                if days < 0:
                    label += c('red', f"  (EXPIRED {abs(days)}d ago)")
                elif days < 30:
                    label += c('yellow', f"  ({days}d left)")
                else:
                    label += c('green', f"  ({days}d left)")
            kv("Valid until", label)
    elif a_records:
        print(f"  {c('red', 'No SSL / connection failed')}")

    # HTTP — skip if no A records
    http = {"ok": False}
    if a_records:
        http = http_check(target)
    else:
        print(f"  {c('dim', 'Skipped — no A records')}")
    if http["ok"]:
        for proto, key in [("HTTPS", "https"), ("HTTP", "http")]:
            code = http[key]
            if code:
                color = "green" if code == 200 else "yellow" if code in (301, 302, 307, 308) else "red"
                msgs = {
                    200: "OK",
                    301: "Moved Permanently", 302: "Found", 307: "Temporary Redirect", 308: "Permanent Redirect",
                    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
                    405: "Method Not Allowed", 429: "Too Many Requests",
                    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
                }
                desc = f" — {msgs[code]}" if code in msgs else ""
                label = f"HTTP {code}{desc}"
                if http["redirect"] and key == "http" and http["https"] in (301, 302, 307, 308):
                    label += f"  →  {http['redirect']}"
                kv(proto, label)
    elif a_records:
        kv("Response", c('red', 'No HTTP response'))

    # 3. DNS
    section("3. DNS RESOURCE RECORDS")
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
    section("4. IP ADDRESS ANALYSIS")
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
    section("5. QUICK SUMMARY")
    print(f"  {c('bold', 'Domain:')}       {c('green', display_target)}")
    print(f"  {c('bold', 'Registrar:')}    {c('yellow', w.get('registrar', 'N/A'))}")
    exp_str = w.get('expires', '')
    exp_display = exp_str or 'N/A'
    if exp_str:
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(exp_str, fmt)
                if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
                d = (dt - datetime.now(timezone.utc)).days
                exp_display = f"{exp_str} ({d}d left)" if d >= 0 else f"{exp_str} (EXPIRED)"
                break
            except ValueError: continue
    print(f"  {c('bold', 'Expires:')}      {c('yellow', exp_display)}")
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
            print("nxlookup v1.1.4")
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
