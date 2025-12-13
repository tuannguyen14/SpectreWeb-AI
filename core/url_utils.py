"""
URL Utilities - Canonicalization and normalization

Provides consistent URL handling to reduce duplicates in findings/endpoints.
"""

from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote, unquote
from typing import Optional, Tuple
import re


def canonicalize_url(url: str, sort_params: bool = True, 
                     lowercase_host: bool = True,
                     strip_fragment: bool = True,
                     strip_trailing_slash: bool = False,
                     strip_default_port: bool = True) -> str:
    """
    Normalize URL to canonical form for deduplication.
    
    Args:
        url: Input URL
        sort_params: Sort query parameters alphabetically
        lowercase_host: Lowercase the hostname
        strip_fragment: Remove URL fragment (#...)
        strip_trailing_slash: Remove trailing slash from path
        strip_default_port: Remove :80 for http, :443 for https
    
    Returns:
        Canonicalized URL string
    """
    if not url or not isinstance(url, str):
        return ""
    
    url = url.strip()
    if not url:
        return ""
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://', '//')):
        url = 'https://' + url
    elif url.startswith('//'):
        url = 'https:' + url
    
    try:
        parsed = urlparse(url)
    except Exception:
        return url
    
    # Lowercase scheme
    scheme = parsed.scheme.lower()
    
    # Lowercase and normalize host
    netloc = parsed.netloc
    host = parsed.hostname or ""
    port = parsed.port
    
    if lowercase_host:
        host = host.lower()
    
    # Strip default ports
    if strip_default_port:
        if (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443):
            port = None
    
    # Rebuild netloc
    if port:
        netloc = f"{host}:{port}"
    else:
        netloc = host
    
    # Normalize path
    path = parsed.path or "/"
    # Decode then re-encode to normalize
    path = quote(unquote(path), safe='/-_.~')
    # Remove double slashes
    path = re.sub(r'/+', '/', path)
    
    if strip_trailing_slash and path != "/" and path.endswith('/'):
        path = path.rstrip('/')
    
    # Handle query string
    query = parsed.query
    if query and sort_params:
        try:
            params = parse_qs(query, keep_blank_values=True)
            # Sort params and their values
            sorted_params = []
            for key in sorted(params.keys()):
                for value in sorted(params[key]):
                    sorted_params.append((key, value))
            query = urlencode(sorted_params)
        except Exception:
            pass
    
    # Handle fragment
    fragment = "" if strip_fragment else parsed.fragment
    
    return urlunparse((scheme, netloc, path, "", query, fragment))


def extract_domain(url: str) -> str:
    """Extract domain (host without port) from URL"""
    if not url or not isinstance(url, str):
        return ""
    
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def extract_root_domain(url: str) -> str:
    """Extract root domain (e.g., example.com from sub.example.com)"""
    domain = extract_domain(url)
    if not domain:
        return ""
    
    # Handle IP addresses
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return domain
    
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    
    # Common TLDs with second level
    two_part_tlds = {'co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in'}
    if len(parts) >= 3:
        potential_tld = '.'.join(parts[-2:])
        if potential_tld in two_part_tlds:
            return '.'.join(parts[-3:])
    
    return '.'.join(parts[-2:])


def get_url_fingerprint(url: str) -> str:
    """
    Get fingerprint for URL deduplication.
    Strips dynamic parts like session IDs, timestamps, etc.
    """
    canonical = canonicalize_url(url)
    if not canonical:
        return ""
    
    try:
        parsed = urlparse(canonical)
        
        # Remove common dynamic parameters
        dynamic_params = {
            'sid', 'session', 'sessionid', 'token', 'csrf', 'nonce',
            'timestamp', 'ts', 't', '_', 'cache', 'nocache', 'rand',
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'fbclid', 'gclid', 'ref', 'source'
        }
        
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            filtered_params = {
                k: v for k, v in params.items() 
                if k.lower() not in dynamic_params
            }
            query = urlencode([(k, v[0]) for k, v in sorted(filtered_params.items())])
        else:
            query = ""
        
        # Create fingerprint from scheme + host + path + filtered query
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))
    except Exception:
        return canonical


def normalize_endpoint(url: str, base_url: str = None) -> str:
    """
    Normalize endpoint URL, optionally resolving relative URLs.
    """
    if not url or not isinstance(url, str):
        return ""
    
    url = url.strip()
    
    # Handle relative URLs
    if base_url and not url.startswith(('http://', 'https://')):
        from urllib.parse import urljoin
        url = urljoin(base_url, url)
    
    return canonicalize_url(url)


def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin (scheme + host + port)"""
    try:
        p1 = urlparse(canonicalize_url(url1))
        p2 = urlparse(canonicalize_url(url2))
        return (p1.scheme == p2.scheme and p1.netloc == p2.netloc)
    except Exception:
        return False


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs share the same root domain"""
    return extract_root_domain(url1) == extract_root_domain(url2)
