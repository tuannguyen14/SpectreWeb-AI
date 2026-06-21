"""
Origin IP Finder - Discover real backend IP behind CDN/WAF/Cloudflare.

Tier-1 techniques (all free, no API keys required):
  1. Certificate Transparency (crt.sh) - find subdomains & cert domains
  2. Subdomain leak - check common origin/dev/staging subdomains
  3. DNS records - SPF/MX/TXT often reveal non-CDN infrastructure
  4. cdncheck - detect if domain is behind CDN (requires tool installed)
  5. dnsx - resolve subdomains to A records (requires tool installed)
  6. tlsx - extract SAN/CN from TLS certs of candidate IPs (requires tool)
  7. Origin verification - confirm IP serves the target via Host header

Optional Tier-2 (needs API key via env var):
  - SecurityTrails historical DNS (SPECTREWEB_SECURITYTRAILS_API_KEY)
  - Shodan internetdb (free, no key) / full API (SPECTREWEB_SHODAN_API_KEY)
  - Censys cert/favicon pivot (SPECTREWEB_CENSYS_API_ID + SECRET)
  - Favicon hash matching (mmh3)
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

from config.settings import DEFAULT_HEADERS, TLS_VERIFY

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CRT_SH_TIMEOUT = 30
ORIGIN_VERIFY_TIMEOUT = 10
DNS_RESOLVE_TIMEOUT = 5

# Subdomains that commonly point directly to origin (bypass CDN)
ORIGIN_SUBDOMAIN_PREFIXES: List[str] = [
    "origin", "direct", "dev", "staging", "staging2", "test",
    "mail", "cpanel", "webmail", "admin", "panel",
    "api", "api2", "internal", "beta", "preview",
    "ssh", "ftp", "sftp", "vpn", "remote",
    "old", "new", "backup", "bak", "archive",
    "ns1", "ns2", "mx", "mx1", "mx2", "smtp",
]

# Headers that may leak backend IP
IP_LEAK_HEADERS: List[str] = [
    "x-backend-server", "x-served-by", "x-origin-url",
    "x-real-ip", "x-true-ip", "x-forwarded-for",
    "x-internal-ip", "x-server-ip", "x-debug-ip",
    "x-amz-cf-id",  # CloudFront sometimes leaks
    "via",  # Proxy headers
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class OriginCandidate:
    """A candidate origin IP with evidence."""
    ip: str
    sources: List[str] = field(default_factory=list)
    verified: bool = False
    verification_details: Dict[str, Any] = field(default_factory=dict)

    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "sources": self.sources,
            "verified": self.verified,
            "verification_details": self.verification_details,
        }


@dataclass
class OriginResult:
    """Full result of origin IP discovery."""
    domain: str
    behind_cdn: Optional[bool] = None
    cdn_name: Optional[str] = None
    candidates: List[OriginCandidate] = field(default_factory=list)
    verified_origins: List[OriginCandidate] = field(default_factory=list)
    subdomains_found: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    cert_domains: List[str] = field(default_factory=list)
    favicon_hash: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)

    def add_candidate(self, ip: str, source: str) -> OriginCandidate:
        for c in self.candidates:
            if c.ip == ip:
                c.add_source(source)
                return c
        candidate = OriginCandidate(ip=ip)
        candidate.add_source(source)
        self.candidates.append(candidate)
        return candidate

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "behind_cdn": self.behind_cdn,
            "cdn_name": self.cdn_name,
            "total_candidates": len(self.candidates),
            "verified_origins": [c.to_dict() for c in self.verified_origins],
            "all_candidates": [c.to_dict() for c in self.candidates],
            "subdomains_found": self.subdomains_found,
            "dns_records": self.dns_records,
            "cert_domains": self.cert_domains,
            "favicon_hash": self.favicon_hash,
            "errors": self.errors,
            "techniques_used": self.techniques_used,
        }


# ---------------------------------------------------------------------------
# 1. Certificate Transparency (crt.sh) - FREE, no API key
# ---------------------------------------------------------------------------


def query_crt_sh(domain: str, timeout: int = CRT_SH_TIMEOUT) -> List[Dict[str, Any]]:
    """
    Query crt.sh Certificate Transparency logs.

    Returns list of cert entries with domains, issuer, etc.
    Free, unlimited, no API key required.
    """
    url = CRT_SH_URL.format(domain=domain)
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            logger.warning(f"crt.sh returned {resp.status_code} for {domain}")
            return []
        # crt.sh returns JSON array
        data = resp.json()
        if not isinstance(data, list):
            return []
        return data
    except requests.Timeout:
        logger.warning(f"crt.sh timeout for {domain}")
        return []
    except Exception as e:
        logger.warning(f"crt.sh error: {e}")
        return []


def extract_domains_from_crt(domain: str, cert_entries: List[Dict]) -> Tuple[List[str], List[str]]:
    """
    Extract unique subdomains and cert domain names from crt.sh results.

    Returns:
        (subdomains, cert_domains)
    """
    subdomains: Set[str] = set()
    cert_domains: Set[str] = set()

    for entry in cert_entries:
        # crt.sh fields: name_value (may contain multiple domains separated by \n)
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if not name or "*" in name:
                # Skip wildcard certs but record the base domain
                if name and name.startswith("*."):
                    base = name[2:]
                    cert_domains.add(base)
                    if base.endswith(f".{domain}") or base == domain:
                        subdomains.add(base)
                continue
            cert_domains.add(name)
            if name.endswith(f".{domain}") or name == domain:
                subdomains.add(name)

    return sorted(subdomains), sorted(cert_domains)


# ---------------------------------------------------------------------------
# 2. Subdomain leak - check common origin subdomains
# ---------------------------------------------------------------------------


def generate_origin_subdomains(domain: str) -> List[str]:
    """Generate likely subdomain names that may bypass CDN."""
    candidates = []
    for prefix in ORIGIN_SUBDOMAIN_PREFIXES:
        candidates.append(f"{prefix}.{domain}")
    return candidates


def resolve_hostname(hostname: str, timeout: int = DNS_RESOLVE_TIMEOUT) -> List[str]:
    """Resolve hostname to IPv4 addresses. Returns list of IPs."""
    try:
        socket.setdefaulttimeout(timeout)
        _, _, ips = socket.gethostbyname_ex(hostname)
        # gethostbyname_ex returns ips as a flat list of IP strings
        return [ip for ip in ips if isinstance(ip, str) and "." in ip]
    except socket.gaierror:
        return []
    except Exception:
        return []


def load_subdomain_wordlist(name: str = "subdomains_20k") -> List[str]:
    """
    Load subdomain wordlist from SecLists.

    Uses config/wordlists.py to resolve SecLists paths.
    Falls back to ORIGIN_SUBDOMAIN_PREFIXES if SecLists not available.

    Args:
        name: Wordlist name from config.wordlists (subdomains_5k, subdomains_20k, subdomains_110k)
              or a direct file path.

    Returns:
        List of subdomain prefix strings (without the target domain).
    """
    try:
        from config.wordlists import WORDLISTS, SECLISTS_PATH
        if name in WORDLISTS:
            path = WORDLISTS[name]["path"]
        elif os.path.isabs(name) and os.path.exists(name):
            path = name
        else:
            path = None

        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                prefixes = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
            logger.info(f"[origin_finder] Loaded {len(prefixes)} subdomain prefixes from {path}")
            return prefixes
        else:
            logger.debug(f"[origin_finder] Wordlist not found: {name}, using default prefixes")
            return ORIGIN_SUBDOMAIN_PREFIXES
    except Exception as e:
        logger.debug(f"[origin_finder] Failed to load wordlist: {e}")
        return ORIGIN_SUBDOMAIN_PREFIXES


def brute_subdomains(
    domain: str,
    wordlist_name: str = "subdomains_20k",
    max_workers: int = 50,
    timeout: int = 3,
) -> List[Dict[str, Any]]:
    """
    Brute-force subdomain enumeration using SecLists wordlist.

    Multi-threaded DNS resolution for speed. Finds subdomains that
    may bypass CDN and point directly to origin IP.

    Args:
        domain: Target domain (e.g. "example.com")
        wordlist_name: SecLists wordlist name or direct path.
                       Options: subdomains_5k (fast), subdomains_20k (balanced),
                       subdomains_110k (thorough), or absolute path.
        max_workers: Number of concurrent DNS lookups
        timeout: DNS resolution timeout per subdomain

    Returns:
        List of {subdomain, ips, source} for resolved subdomains.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    prefixes = load_subdomain_wordlist(wordlist_name)
    candidates = [f"{prefix}.{domain}" for prefix in prefixes]

    # Always include the high-priority origin prefixes first
    extra_origin = [f"{p}.{domain}" for p in ORIGIN_SUBDOMAIN_PREFIXES if p not in prefixes]
    candidates = extra_origin + candidates

    results: List[Dict[str, Any]] = []
    seen_subdomains: Set[str] = set()

    def _resolve_sub(subdomain: str) -> Optional[Dict[str, Any]]:
        ips = resolve_hostname(subdomain, timeout=timeout)
        if ips:
            return {"subdomain": subdomain, "ips": ips, "source": "brute"}
        return None

    logger.info(f"[origin_finder] Brute-forcing {len(candidates)} subdomains for {domain}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_resolve_sub, sub): sub for sub in candidates}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result and result["subdomain"] not in seen_subdomains:
                    seen_subdomains.add(result["subdomain"])
                    results.append(result)
            except Exception:
                pass

    logger.info(f"[origin_finder] Subdomain brute: {len(results)} resolved out of {len(candidates)}")
    return results


# ---------------------------------------------------------------------------
# 3. DNS records - MX, SPF, TXT often reveal non-CDN infrastructure
# ---------------------------------------------------------------------------


def query_dns_records(domain: str) -> Dict[str, List[str]]:
    """
    Query MX, TXT, and SPF DNS records.

    Uses Python's built-in socket DNS resolution where possible,
    falls back to Google DoH (DNS over HTTPS) for MX/TXT records.
    """
    records: Dict[str, List[str]] = {
        "mx": [],
        "txt": [],
        "spf": [],
        "a": [],
    }

    # A record via socket
    a_records = resolve_hostname(domain)
    records["a"] = a_records

    # MX and TXT via Google DoH (free, no key)
    doh_url = "https://dns.google/resolve"
    for record_type in ["MX", "TXT"]:
        try:
            resp = requests.get(
                doh_url,
                params={"name": domain, "type": record_type},
                headers={"Accept": "application/dns-json"},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                for answer in answers:
                    data_val = answer.get("data", "")
                    if record_type == "MX":
                        # MX format: "10 mail.example.com"
                        parts = data_val.split()
                        if len(parts) >= 2:
                            mx_host = parts[1].rstrip(".")
                            records["mx"].append(mx_host)
                            # Resolve MX host to IP
                            mx_ips = resolve_hostname(mx_host)
                            if mx_ips:
                                records["mx"].extend(mx_ips)
                    elif record_type == "TXT":
                        records["txt"].append(data_val)
                        if "spf" in data_val.lower():
                            records["spf"].append(data_val)
                            # Extract IPs from SPF includes
                            ip_matches = re.findall(
                                r"ip[46]:([0-9a-fA-F:.]+)", data_val
                            )
                            records["spf"].extend(ip_matches)
        except Exception as e:
            logger.debug(f"DoH query failed for {record_type}: {e}")

    return records


# ---------------------------------------------------------------------------
# 4. CDN detection (fallback without cdncheck tool)
# ---------------------------------------------------------------------------


def detect_cdn(domain: str) -> Tuple[Optional[bool], Optional[str]]:
    """
    Detect if domain is behind a CDN/WAF.

    Uses HTTP headers as a heuristic. For precise detection,
    install the `cdncheck` tool from ProjectDiscovery.

    Returns:
        (is_behind_cdn, cdn_name_or_None)
    """
    cdn_header_map = {
        "cf-ray": "Cloudflare",
        "x-cloud-trace-context": "Google Cloud CDN",
        "x-amz-cf-id": "Amazon CloudFront",
        "x-akamai-transformed": "Akamai",
        "x-served-by": "Fastly",
        "x-azure-ref": "Azure Front Door",
        "x-cdn": "Generic CDN",
        "x-cdn-origin": "Generic CDN",
    }

    try:
        url = f"https://{domain}" if not domain.startswith("http") else domain
        resp = requests.head(
            url,
            headers=DEFAULT_HEADERS,
            timeout=10,
            verify=TLS_VERIFY,
            allow_redirects=True,
        )
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, cdn_name in cdn_header_map.items():
            if header in headers_lower:
                return True, cdn_name

        # Check server header for CDN signatures
        server = headers_lower.get("server", "").lower()
        if "cloudflare" in server:
            return True, "Cloudflare"
        if "akamai" in server:
            return True, "Akamai"
        if "cloudfront" in server:
            return True, "Amazon CloudFront"

        return False, None
    except Exception:
        return None, None


# ---------------------------------------------------------------------------
# 5. Origin verification - confirm IP serves the target via Host header
# ---------------------------------------------------------------------------


def _extract_title(html: str) -> str:
    """Extract <title> from HTML."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""


def _get_ssl_cert_info(ip: str, domain: str = None, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """
    Get SSL certificate info from an IP address.

    Uses SNI = domain (if provided) to get the correct certificate
    that the server would present for that domain.

    Returns dict with subject, SANs, issuer, etc.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # Use domain as SNI so server returns the correct cert
            sni = domain or ip
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)

        # Extract SANs
        sans: List[str] = []
        if cert:
            for rdn in cert.get("subjectAltName", []):
                if rdn[0] == "DNS":
                    sans.append(rdn[1])

        # Extract CN
        cn = ""
        if cert:
            for rdn in cert.get("subject", ()):
                if rdn[0][0] == "commonName":
                    cn = rdn[0][1]
                    break

        return {
            "cn": cn,
            "sans": sans,
            "fingerprint": hashlib.sha256(cert_bin).hexdigest() if cert_bin else "",
        }
    except Exception as e:
        return {"error": str(e)}


def verify_origin_ip(
    ip: str,
    domain: str,
    timeout: int = ORIGIN_VERIFY_TIMEOUT,
) -> Dict[str, Any]:
    """
    Verify that an IP serves the target domain.

    Technique: Send HTTPS request to the IP with `Host: domain` header,
    then compare:
      1. SSL cert CN/SANs - does it contain the target domain?
      2. HTTP response - title, status code, body similarity
      3. Response headers - any backend-leaking headers?

    Returns verification details dict.
    """
    details: Dict[str, Any] = {
        "ip": ip,
        "domain": domain,
        "cert_match": False,
        "cert_cn": "",
        "cert_sans": [],
        "http_status": None,
        "title": "",
        "title_match": False,
        "leaked_headers": {},
        "error": None,
    }

    # Step 1: Check SSL certificate (use domain as SNI for correct cert)
    cert_info = _get_ssl_cert_info(ip, domain=domain, timeout=5)
    if "error" not in cert_info:
        details["cert_cn"] = cert_info.get("cn", "")
        details["cert_sans"] = cert_info.get("sans", [])

        # Check if domain matches cert CN or any SAN
        all_cert_domains = {details["cert_cn"]} | set(details["cert_sans"])
        for cert_domain in all_cert_domains:
            # Handle wildcard certs
            if cert_domain.startswith("*."):
                base = cert_domain[2:]
                if domain.endswith(base):
                    details["cert_match"] = True
                    break
            elif cert_domain == domain:
                details["cert_match"] = True
                break
    else:
        details["error"] = f"SSL: {cert_info['error']}"

    # Step 2: HTTP request with Host header
    try:
        url = f"https://{ip}"
        headers = DEFAULT_HEADERS.copy()
        headers["Host"] = domain

        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=False,  # Don't verify cert (we're connecting to IP)
            allow_redirects=False,
        )

        details["http_status"] = resp.status_code

        # Extract title
        body = resp.text[:50000] if resp.text else ""
        title = _extract_title(body)
        details["title"] = title

        # Check for backend-leaking headers
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        for leak_header in IP_LEAK_HEADERS:
            if leak_header in resp_headers_lower:
                details["leaked_headers"][leak_header] = resp_headers_lower[leak_header]

        # Get reference title from the real domain for comparison
        # (only if we don't already have cert match)
        if not details["cert_match"] and title:
            # Quick check: if title is non-empty and not a default error page,
            # it's a strong signal
            generic_titles = {"", "404 not found", "forbidden", "error", "nginx",
                              "apache", "iis", "default page"}
            if title.lower() not in generic_titles:
                details["title_match"] = True

    except requests.exceptions.SSLError:
        # Try HTTP fallback
        try:
            url = f"http://{ip}"
            headers = DEFAULT_HEADERS.copy()
            headers["Host"] = domain
            resp = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
            details["http_status"] = resp.status_code
            body = resp.text[:50000] if resp.text else ""
            details["title"] = _extract_title(body)
        except Exception as e:
            if details["error"]:
                details["error"] += f"; HTTP: {e}"
            else:
                details["error"] = f"HTTP: {e}"
    except Exception as e:
        if details["error"]:
            details["error"] += f"; HTTP: {e}"
        else:
            details["error"] = f"HTTP: {e}"

    # Determine if verified
    details["verified"] = details["cert_match"] or (
        details["title_match"] and details["http_status"] in (200, 301, 302, 403)
    )

    return details


# ---------------------------------------------------------------------------
# 6. Favicon hash (optional, free to compute)
# ---------------------------------------------------------------------------


def compute_favicon_hash(url: str) -> Optional[str]:
    """
    Compute mmh3 hash of favicon for Shodan/Censys search.

    This computes the hash for free; searching with it requires
    Shodan API or Censys API (or free Shodan internetdb).
    """
    try:
        import mmh3
    except ImportError:
        logger.debug("mmh3 not installed, skipping favicon hash")
        return None

    favicon_url = f"{url.rstrip('/')}/favicon.ico"
    try:
        resp = requests.get(favicon_url, timeout=10, verify=TLS_VERIFY)
        if resp.status_code != 200 or not resp.content:
            return None
        # Shodan uses base64-encoded favicon content hashed with mmh3
        import base64
        encoded = base64.encodebytes(resp.content)
        hash_val = mmh3.hash(encoded)
        return str(hash_val)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 7. Optional: SecurityTrails historical DNS (needs API key)
# ---------------------------------------------------------------------------


def query_securitytrails_historical(domain: str) -> List[Dict[str, Any]]:
    """
    Query SecurityTrails for historical A records.

    Requires SPECTREWEB_SECURITYTRAILS_API_KEY env var.
    Free tier: ~50 queries/month.
    """
    api_key = os.environ.get("SPECTREWEB_SECURITYTRAILS_API_KEY")
    if not api_key:
        return []

    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": api_key},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        records = data.get("records", [])
        return [
            {
                "ip": r.get("values", [{}])[0].get("ip", ""),
                "first_seen": r.get("first_seen", ""),
                "last_seen": r.get("last_seen", ""),
            }
            for r in records
            if r.get("values")
        ]
    except Exception as e:
        logger.warning(f"SecurityTrails error: {e}")
        return []


# ---------------------------------------------------------------------------
# 8. Optional: Shodan internetdb (FREE, no API key)
# ---------------------------------------------------------------------------


def query_shodan_internetdb(ip: str) -> Dict[str, Any]:
    """
    Query Shodan InternetDB (free, no API key required).

    Returns host info: ports, vulns, tags, etc.
    Rate limited but no key needed.
    """
    try:
        resp = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
        return {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 9. FOFA search engine (free tier, needs API key)
# ---------------------------------------------------------------------------

FOFA_API_URL = "https://fofa.info/api/v1/search/all"
FOFA_TIMEOUT = 15


def _fofa_query_base64(query: str) -> str:
    """FOFA requires base64-encoded query string."""
    import base64
    return base64.b64encode(query.encode("utf-8")).decode("utf-8")


def query_fofa(query: str, fields: str = "ip,port,host,title,server,country", size: int = 100) -> List[Dict[str, Any]]:
    """
    Query FOFA search engine.

    Requires SPECTREWEB_FOFA_API_KEY and SPECTREWEB_FOFA_EMAIL env vars.
    Free tier: limited queries but favicon hash + cert search work.

    FOFA query syntax examples:
      - icon_hash="-12345678"     (favicon hash search)
      - cert="example.com"        (SSL cert CN/SAN search)
      - body="example.com"        (HTTP body search)
      - host="example.com"        (hostname search)

    Args:
        query: FOFA query string (unencoded)
        fields: Comma-separated fields to return
        size: Max results (free tier limited to ~100)

    Returns:
        List of result dicts with IP, port, host, etc.
    """
    email = os.environ.get("SPECTREWEB_FOFA_EMAIL")
    api_key = os.environ.get("SPECTREWEB_FOFA_API_KEY")
    if not email or not api_key:
        return []

    try:
        resp = requests.get(
            FOFA_API_URL,
            params={
                "email": email,
                "key": api_key,
                "qbase64": _fofa_query_base64(query),
                "fields": fields,
                "size": min(size, 100),
            },
            timeout=FOFA_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning(f"FOFA returned {resp.status_code}")
            return []
        data = resp.json()
        if data.get("error"):
            logger.warning(f"FOFA error: {data.get('errmsg', 'unknown')}")
            return []
        return data.get("results", [])
    except Exception as e:
        logger.warning(f"FOFA error: {e}")
        return []


def fofa_search_by_favicon(favicon_hash: str, size: int = 100) -> List[Dict[str, Any]]:
    """
    Search FOFA by favicon hash to find IPs serving the same favicon.

    This is one of the most powerful techniques for finding origin IPs
    behind CDN, especially for Asian targets (casino, gambling sites).

    Args:
        favicon_hash: mmh3 hash of favicon (from compute_favicon_hash)
        size: Max results

    Returns:
        List of dicts with ip, port, host, title, server, country
    """
    return query_fofa(f'icon_hash="{favicon_hash}"', size=size)


def fofa_search_by_cert(domain: str, size: int = 100) -> List[Dict[str, Any]]:
    """
    Search FOFA by SSL certificate CN/SAN to find IPs serving
    certificates for the target domain.

    Args:
        domain: Target domain

    Returns:
        List of dicts with ip, port, host, title, server, country
    """
    return query_fofa(f'cert="{domain}"', size=size)


def fofa_search_by_body(domain: str, size: int = 100) -> List[Dict[str, Any]]:
    """
    Search FOFA by HTTP body content to find IPs serving
    pages that reference the target domain.

    Args:
        domain: Target domain

    Returns:
        List of dicts with ip, port, host, title, server, country
    """
    return query_fofa(f'body="{domain}"', size=size)


# ---------------------------------------------------------------------------
# 9b. Quake 360 search engine (free tier, needs API key)
# ---------------------------------------------------------------------------

QUAKE_API_URL = "https://quake.360.net/api/v3/search/quake_service"
QUAKE_TIMEOUT = 15


def query_quake(query: str, size: int = 100) -> List[Dict[str, Any]]:
    """
    Query Quake 360 search engine.

    Requires SPECTREWEB_QUAKE_API_KEY env var.
    Free tier: ~3000 credits + 5 free API queries/month.
    Quake has excellent coverage for Asian targets (China, SEA).

    Quake query syntax examples:
      - cert:"example.com"        (SSL cert CN/SAN search)
      - favicon:"-12345678"       (favicon hash search)
      - body:"example.com"        (HTTP body search)
      - host:"example.com"        (hostname search)
      - title:"Example"           (HTTP title search)

    Args:
        query: Quake query string
        size: Max results (free tier limited)

    Returns:
        List of result dicts with ip, port, hostname, title, server.
    """
    api_key = os.environ.get("SPECTREWEB_QUAKE_API_KEY")
    if not api_key:
        return []

    try:
        resp = requests.post(
            QUAKE_API_URL,
            headers={
                "X-QuakeToken": api_key,
                "Content-Type": "application/json",
            },
            json={
                "query": query,
                "start": 0,
                "size": min(size, 100),
            },
            timeout=QUAKE_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning(f"Quake returned {resp.status_code}")
            return []
        data = resp.json()
        if data.get("code") != 0:
            logger.warning(f"Quake error: {data.get('message', 'unknown')}")
            return []

        results = []
        for r in data.get("data", []):
            service = r.get("service", {})
            http = service.get("http", {})
            results.append({
                "ip": r.get("ip", ""),
                "port": r.get("port", ""),
                "hostname": r.get("hostname", ""),
                "title": http.get("title", ""),
                "server": http.get("server", ""),
                "source": "quake",
            })
        return results
    except Exception as e:
        logger.warning(f"Quake error: {e}")
        return []


def quake_search_by_favicon(favicon_hash: str, size: int = 100) -> List[Dict[str, Any]]:
    """
    Search Quake by favicon hash to find IPs serving the same favicon.

    Free alternative to FOFA favicon hash search.
    Strong coverage for Asian targets (casino, gambling sites).

    Args:
        favicon_hash: mmh3 hash of favicon (from compute_favicon_hash)

    Returns:
        List of dicts with ip, port, hostname, title, server
    """
    return query_quake(f'favicon:"{favicon_hash}"', size=size)


def quake_search_by_cert(domain: str, size: int = 100) -> List[Dict[str, Any]]:
    """
    Search Quake by SSL certificate CN/SAN to find IPs serving
    certificates for the target domain.

    Args:
        domain: Target domain

    Returns:
        List of dicts with ip, port, hostname, title, server
    """
    return query_quake(f'cert:"{domain}"', size=size)


def quake_search_by_body(domain: str, size: int = 100) -> List[Dict[str, Any]]:
    """
    Search Quake by HTTP body content to find IPs serving
    pages that reference the target domain.

    Args:
        domain: Target domain

    Returns:
        List of dicts with ip, port, hostname, title, server
    """
    return query_quake(f'body:"{domain}"', size=size)


# ---------------------------------------------------------------------------
# 10. Multi-source passive DNS (all free)
# ---------------------------------------------------------------------------


def query_alienvault_otx(domain: str) -> List[Dict[str, Any]]:
    """
    Query AlienVault OTX passive DNS for historical A records.

    Free, no API key required. Good coverage for Western targets.
    Returns list of {ip, first_seen, last_seen, hostname}.
    """
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 429:
            logger.debug("OTX rate limited, retrying with delay")
            time.sleep(2)
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0"},
            )
        if resp.status_code != 200:
            return []
        data = resp.json()
        records = data.get("passive_dns", [])
        results = []
        for r in records:
            # OTX address field may be "1.2.3.4" or hostname
            address = r.get("address", "")
            hostname = r.get("hostname", "")
            # Only keep IPv4 addresses
            if address and re.match(r"^\d+\.\d+\.\d+\.\d+$", address):
                results.append({
                    "ip": address,
                    "hostname": hostname,
                    "first_seen": r.get("first", ""),
                    "last_seen": r.get("last", ""),
                    "source": "otx",
                })
        return results
    except Exception as e:
        logger.debug(f"OTX error: {e}")
        return []


def query_hackertarget(domain: str) -> List[Dict[str, Any]]:
    """
    Query HackerTarget for DNS A records.

    Free: ~100 requests/day per IP. No API key required.
    Uses the DNS lookup endpoint (not reverse IP).
    Returns list of {ip, hostname, source}.
    """
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/dnslookup/?q={domain}",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code != 200:
            return []
        # HackerTarget DNS lookup returns: "a : 1.2.3.4\na : 5.6.7.8"
        # or "a : 1.2.3.4\nmx : mail.example.com\n..."
        results = []
        for line in resp.text.strip().split("\n"):
            line = line.strip()
            if not line or "API count" in line or "error" in line.lower():
                continue
            # Format: "record_type : value"
            if " : " in line:
                rtype, value = line.split(" : ", 1)
                rtype = rtype.strip().lower()
                value = value.strip()
                if rtype == "a" and re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
                    results.append({
                        "ip": value,
                        "hostname": domain,
                        "source": "hackertarget",
                    })
        return results
    except Exception as e:
        logger.debug(f"HackerTarget error: {e}")
        return []


def query_validin(domain: str) -> List[Dict[str, Any]]:
    """
    Query Validin for passive DNS / host pivot data.

    Validin requires a free account token for API access.
    If SPECTREWEB_VALIDIN_TOKEN is set, uses authenticated API.
    Otherwise returns empty (no unauthenticated endpoint available).
    Returns list of {ip, hostname, source}.
    """
    token = os.environ.get("SPECTREWEB_VALIDIN_TOKEN")
    if not token:
        return []

    try:
        resp = requests.get(
            f"https://app.validin.com/api/v1/domain/{domain}/dns/a",
            timeout=15,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        records = data if isinstance(data, list) else data.get("records", data.get("data", []))
        results = []
        if isinstance(records, list):
            for r in records:
                if isinstance(r, dict):
                    ip = r.get("ip", r.get("address", r.get("value", "")))
                elif isinstance(r, str):
                    ip = r
                else:
                    continue
                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", str(ip)):
                    results.append({
                        "ip": str(ip),
                        "hostname": r.get("hostname", "") if isinstance(r, dict) else "",
                        "source": "validin",
                    })
        return results
    except Exception as e:
        logger.debug(f"Validin error: {e}")
        return []


def query_passive_dns_multi(domain: str) -> List[Dict[str, Any]]:
    """
    Query multiple free passive DNS sources in sequence.

    Sources: AlienVault OTX, HackerTarget, Validin.
    All free, no API keys required.

    Returns:
        Combined list of {ip, hostname, first_seen, last_seen, source}
    """
    all_records: List[Dict[str, Any]] = []
    seen_ips: Set[str] = set()

    for source_fn, source_name in [
        (query_alienvault_otx, "otx"),
        (query_hackertarget, "hackertarget"),
        (query_validin, "validin"),
    ]:
        try:
            records = source_fn(domain)
            for r in records:
                ip = r.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    all_records.append(r)
        except Exception as e:
            logger.debug(f"Passive DNS source {source_name} failed: {e}")

    return all_records


def find_origin(
    domain: str,
    verify: bool = True,
    use_crt_sh: bool = True,
    use_subdomain_leak: bool = True,
    use_subdomain_brute: bool = False,
    subdomain_wordlist: str = "subdomains_20k",
    use_dns_records: bool = True,
    use_securitytrails: bool = False,
    use_favicon_hash: bool = False,
    use_fofa: bool = False,
    use_quake: bool = False,
    use_passive_dns: bool = True,
) -> Dict[str, Any]:
    """
    Find the real origin IP of a domain behind CDN/WAF.

    Orchestrates multiple free techniques:
      1. CDN detection (header-based heuristic)
      2. Certificate Transparency (crt.sh)
      3. Subdomain leak (common origin subdomain prefixes - 30 quick checks)
      3b. [Optional] Subdomain brute (SecLists wordlist - 5K/20K/110K, multi-threaded)
      4. DNS records (MX/SPF/TXT → IP extraction)
      5. Multi-source passive DNS (OTX + HackerTarget + Validin) - FREE
      6. [Optional] SecurityTrails historical DNS
      7. [Optional] Favicon hash → FOFA search (needs FOFA key)
      8. [Optional] FOFA cert/body search (needs FOFA key)
      8b. [Optional] Quake cert/favicon/body search (needs Quake key, free tier works)
      9. Shodan InternetDB enrichment (free)
      10. Origin verification (Host header + cert match)

    Args:
        domain: Target domain (e.g. "example.com")
        verify: If True, verify candidate IPs by sending Host header
        use_crt_sh: Use crt.sh Certificate Transparency
        use_subdomain_leak: Check 30 common origin subdomain prefixes (fast)
        use_subdomain_brute: Brute-force subdomains using SecLists wordlist (thorough)
        subdomain_wordlist: SecLists wordlist name (subdomains_5k, subdomains_20k, subdomains_110k)
        use_dns_records: Query MX/SPF/TXT for non-CDN IPs
        use_securitytrails: Use SecurityTrails API (needs key)
        use_favicon_hash: Compute favicon hash + search via FOFA (needs FOFA key)
        use_fofa: Use FOFA cert + body search (needs SPECTREWEB_FOFA_EMAIL + KEY)
        use_quake: Use Quake cert + favicon + body search (needs SPECTREWEB_QUAKE_API_KEY, free tier)
        use_passive_dns: Query OTX + HackerTarget + Validin (free, no key)

    Returns:
        Dict with candidates, verified origins, subdomains, etc.
    """
    # Strip protocol and path if provided
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    domain = domain.strip().lower()
    if domain.endswith("/"):
        domain = domain[:-1]

    result = OriginResult(domain=domain)

    # --- Step 1: CDN detection ---
    result.techniques_used.append("cdn_detection")
    behind_cdn, cdn_name = detect_cdn(domain)
    result.behind_cdn = behind_cdn
    result.cdn_name = cdn_name

    if behind_cdn is False:
        # Not behind CDN - direct A record is the origin
        result.techniques_used.append("direct_a_record")
        direct_ips = resolve_hostname(domain)
        for ip in direct_ips:
            result.add_candidate(ip, "direct_a_record")
    elif behind_cdn is None:
        # CDN detection inconclusive - still add A records as candidates
        result.techniques_used.append("direct_a_record_inconclusive")
        direct_ips = resolve_hostname(domain)
        for ip in direct_ips:
            result.add_candidate(ip, "direct_a_record")
    else:
        logger.info(f"[origin_finder] {domain} appears behind CDN: {cdn_name}")

    # --- Step 2: Certificate Transparency (crt.sh) ---
    if use_crt_sh:
        result.techniques_used.append("crt_sh")
        logger.info(f"[origin_finder] Querying crt.sh for {domain}")
        cert_entries = query_crt_sh(domain)
        if cert_entries:
            subdomains, cert_domains = extract_domains_from_crt(domain, cert_entries)
            result.subdomains_found.extend(subdomains)
            result.cert_domains.extend(cert_domains)

            # Resolve all found subdomains
            for sub in subdomains:
                ips = resolve_hostname(sub)
                for ip in ips:
                    result.add_candidate(ip, f"crt_sh:{sub}")

    # --- Step 3: Subdomain leak (30 quick prefixes) ---
    if use_subdomain_leak:
        result.techniques_used.append("subdomain_leak")
        origin_subs = generate_origin_subdomains(domain)
        for sub in origin_subs:
            if sub not in result.subdomains_found:
                result.subdomains_found.append(sub)
            ips = resolve_hostname(sub)
            for ip in ips:
                result.add_candidate(ip, f"subdomain_leak:{sub}")

    # --- Step 3b: Subdomain brute (SecLists wordlist, multi-threaded) ---
    if use_subdomain_brute:
        result.techniques_used.append("subdomain_brute")
        brute_results = brute_subdomains(domain, wordlist_name=subdomain_wordlist)
        for r in brute_results:
            sub = r["subdomain"]
            if sub not in result.subdomains_found:
                result.subdomains_found.append(sub)
            for ip in r["ips"]:
                result.add_candidate(ip, f"subdomain_brute:{sub}")

    # --- Step 4: DNS records (MX/SPF/TXT) ---
    if use_dns_records:
        result.techniques_used.append("dns_records")
        dns_records = query_dns_records(domain)
        result.dns_records = dns_records

        # Extract IPs from MX records
        for record in dns_records.get("mx", []):
            # If it's a hostname, resolve it
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", record):
                mx_ips = resolve_hostname(record)
                for ip in mx_ips:
                    result.add_candidate(ip, f"mx:{record}")
            else:
                result.add_candidate(record, "mx_record")

        # Extract IPs from SPF records
        for record in dns_records.get("spf", []):
            ip_matches = re.findall(r"ip[46]:([0-9a-fA-F:.]+)", record)
            for ip in ip_matches:
                result.add_candidate(ip, "spf_record")

    # --- Step 5: Multi-source passive DNS (OTX + HackerTarget + Validin) ---
    if use_passive_dns:
        result.techniques_used.append("passive_dns_multi")
        logger.info(f"[origin_finder] Querying passive DNS sources for {domain}")
        pdns_records = query_passive_dns_multi(domain)
        for r in pdns_records:
            result.add_candidate(r["ip"], f"passive_dns:{r['source']}")
            if r.get("hostname") and r["hostname"] not in result.subdomains_found:
                result.subdomains_found.append(r["hostname"])

    # --- Step 6: SecurityTrails (optional) ---
    if use_securitytrails:
        api_key = os.environ.get("SPECTREWEB_SECURITYTRAILS_API_KEY")
        if api_key:
            result.techniques_used.append("securitytrails_historical")
            historical = query_securitytrails_historical(domain)
            for record in historical:
                if record.get("ip"):
                    result.add_candidate(record["ip"], "securitytrails_historical")
        else:
            result.errors.append(
                "SecurityTrails requested but SPECTREWEB_SECURITYTRAILS_API_KEY not set"
            )

    # --- Step 7: Favicon hash → FOFA search (optional, needs FOFA key) ---
    if use_favicon_hash:
        result.techniques_used.append("favicon_hash")
        url = f"https://{domain}"
        fav_hash = compute_favicon_hash(url)
        if fav_hash:
            result.favicon_hash = fav_hash
            # Try FOFA favicon hash search (most powerful for CDN bypass)
            fofa_results = fofa_search_by_favicon(fav_hash)
            if fofa_results:
                result.techniques_used.append("fofa_favicon_search")
                for r in fofa_results:
                    ip = r.get("ip", "")
                    if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        result.add_candidate(ip, "fofa:favicon_hash")
        else:
            result.errors.append("Could not compute favicon hash (mmh3 not installed?)")

    # --- Step 8: FOFA cert + body search (optional, needs FOFA key) ---
    if use_fofa:
        fofa_email = os.environ.get("SPECTREWEB_FOFA_EMAIL")
        fofa_key = os.environ.get("SPECTREWEB_FOFA_API_KEY")
        if fofa_email and fofa_key:
            result.techniques_used.append("fofa_cert_search")
            cert_results = fofa_search_by_cert(domain)
            for r in cert_results:
                ip = r.get("ip", "")
                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    result.add_candidate(ip, "fofa:cert")

            result.techniques_used.append("fofa_body_search")
            body_results = fofa_search_by_body(domain)
            for r in body_results:
                ip = r.get("ip", "")
                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    result.add_candidate(ip, "fofa:body")
        else:
            result.errors.append(
                "FOFA requested but SPECTREWEB_FOFA_EMAIL/SPECTREWEB_FOFA_API_KEY not set"
            )

    # --- Step 8b: Quake cert + favicon + body search (optional, needs Quake key) ---
    if use_quake:
        quake_key = os.environ.get("SPECTREWEB_QUAKE_API_KEY")
        if quake_key:
            result.techniques_used.append("quake_cert_search")
            cert_results = quake_search_by_cert(domain)
            for r in cert_results:
                ip = r.get("ip", "")
                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    result.add_candidate(ip, "quake:cert")

            result.techniques_used.append("quake_body_search")
            body_results = quake_search_by_body(domain)
            for r in body_results:
                ip = r.get("ip", "")
                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    result.add_candidate(ip, "quake:body")

            # If favicon hash was computed, also search Quake by favicon
            if result.favicon_hash:
                result.techniques_used.append("quake_favicon_search")
                fav_results = quake_search_by_favicon(result.favicon_hash)
                for r in fav_results:
                    ip = r.get("ip", "")
                    if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        result.add_candidate(ip, "quake:favicon")
        else:
            result.errors.append(
                "Quake requested but SPECTREWEB_QUAKE_API_KEY not set"
            )

    # --- Step 9: Shodan InternetDB enrichment (free, no key) ---
    if result.candidates:
        result.techniques_used.append("shodan_internetdb")
        for candidate in result.candidates:
            idb = query_shodan_internetdb(candidate.ip)
            if idb:
                candidate.verification_details["shodan"] = idb

    # --- Step 10: Origin verification ---
    if verify and result.candidates:
        result.techniques_used.append("origin_verification")
        logger.info(
            f"[origin_finder] Verifying {len(result.candidates)} candidate IPs"
        )
        for candidate in result.candidates:
            details = verify_origin_ip(candidate.ip, domain)
            candidate.verification_details = details
            candidate.verified = details.get("verified", False)
            if candidate.verified:
                result.verified_origins.append(candidate)

    # Sort: verified first, then by number of sources
    result.candidates.sort(
        key=lambda c: (not c.verified, -len(c.sources))
    )

    return result.to_dict()


def quick_origin_check(domain: str) -> Dict[str, Any]:
    """
    Quick origin check - crt.sh + subdomain leak + DNS records + passive DNS.

    Faster than full find_origin, skips verification, brute, and FOFA.
    Useful for initial reconnaissance.
    """
    return find_origin(
        domain,
        verify=False,
        use_crt_sh=True,
        use_subdomain_leak=True,
        use_subdomain_brute=False,
        use_dns_records=True,
        use_securitytrails=False,
        use_favicon_hash=False,
        use_fofa=False,
        use_quake=False,
        use_passive_dns=True,
    )
