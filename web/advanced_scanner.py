#!/usr/bin/env python3
"""
SpectreWeb AI - Advanced Scanner v1.0
Specialized vulnerability scanners for bug bounty hunting

Features:
- Subdomain Takeover Detection
- Open Redirect Testing
- CRLF Injection Testing
- JavaScript Endpoint Extraction
- Parameter Mining
- Header Injection Testing
"""

import re
import json
import socket
import concurrent.futures
import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote, parse_qs
from dataclasses import dataclass
from datetime import datetime

# Import web client
try:
    from .client import make_request
except ImportError:
    from web.client import make_request


# ============================================================================
# SUBDOMAIN TAKEOVER
# ============================================================================

TAKEOVER_FINGERPRINTS = {
    "aws_s3": {
        "cnames": ["s3.amazonaws.com", "s3-website"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
        "service": "AWS S3"
    },
    "github_pages": {
        "cnames": ["github.io", "githubusercontent.com"],
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
        "severity": "high",
        "service": "GitHub Pages"
    },
    "heroku": {
        "cnames": ["herokuapp.com", "herokussl.com"],
        "fingerprints": ["No such app", "there is no app configured at that hostname"],
        "severity": "high",
        "service": "Heroku"
    },
    "shopify": {
        "cnames": ["myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "severity": "medium",
        "service": "Shopify"
    },
    "tumblr": {
        "cnames": ["tumblr.com"],
        "fingerprints": ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
        "severity": "medium",
        "service": "Tumblr"
    },
    "wordpress": {
        "cnames": ["wordpress.com"],
        "fingerprints": ["Do you want to register"],
        "severity": "medium",
        "service": "WordPress.com"
    },
    "ghost": {
        "cnames": ["ghost.io"],
        "fingerprints": ["The thing you were looking for is no longer here"],
        "severity": "medium",
        "service": "Ghost"
    },
    "surge": {
        "cnames": ["surge.sh"],
        "fingerprints": ["project not found"],
        "severity": "medium",
        "service": "Surge.sh"
    },
    "bitbucket": {
        "cnames": ["bitbucket.io"],
        "fingerprints": ["Repository not found"],
        "severity": "high",
        "service": "Bitbucket"
    },
    "pantheon": {
        "cnames": ["pantheonsite.io"],
        "fingerprints": ["The gods are wise", "404 error unknown site"],
        "severity": "medium",
        "service": "Pantheon"
    },
    "fastly": {
        "cnames": ["fastly.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "severity": "high",
        "service": "Fastly"
    },
    "zendesk": {
        "cnames": ["zendesk.com"],
        "fingerprints": ["Help Center Closed", "this help center no longer exists"],
        "severity": "medium",
        "service": "Zendesk"
    },
    "unbounce": {
        "cnames": ["unbounce.com"],
        "fingerprints": ["The requested URL was not found on this server", "The page you're looking for"],
        "severity": "medium",
        "service": "Unbounce"
    },
    "azure": {
        "cnames": ["azurewebsites.net", "cloudapp.azure.com", "cloudapp.net", "azure-api.net"],
        "fingerprints": ["404 Web Site not found", "Error 404 - Web app not found"],
        "severity": "high",
        "service": "Microsoft Azure"
    },
    "netlify": {
        "cnames": ["netlify.app", "netlify.com"],
        "fingerprints": ["Not Found - Request ID"],
        "severity": "high",
        "service": "Netlify"
    },
    "fly_io": {
        "cnames": ["fly.dev"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
        "service": "Fly.io"
    },
    "vercel": {
        "cnames": ["vercel.app", "now.sh"],
        "fingerprints": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "severity": "high",
        "service": "Vercel"
    },
    "aws_eb": {
        "cnames": ["elasticbeanstalk.com"],
        "fingerprints": [],
        "severity": "high",
        "service": "AWS Elastic Beanstalk",
        "nxdomain": True
    },
    "cloudfront": {
        "cnames": ["cloudfront.net"],
        "fingerprints": ["Bad Request", "ERROR: The request could not be satisfied"],
        "severity": "high",
        "service": "AWS CloudFront"
    }
}


def get_cname(domain: str) -> Optional[str]:
    """Get CNAME record for a domain"""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except:
        pass
    return None


def check_subdomain_takeover(subdomain: str) -> Dict[str, Any]:
    """
    Check if a subdomain is vulnerable to takeover.
    
    Returns:
        vulnerability status, service, and evidence
    """
    result = {
        "subdomain": subdomain,
        "vulnerable": False,
        "service": None,
        "severity": None,
        "evidence": None,
        "cname": None,
        "timestamp": datetime.now().isoformat()
    }
    
    # Try to get CNAME
    try:
        cname = get_cname(subdomain)
        result["cname"] = cname
    except:
        cname = None
    
    # Check for NXDOMAIN (domain doesn't resolve)
    try:
        socket.gethostbyname(subdomain)
        is_nxdomain = False
    except socket.gaierror:
        is_nxdomain = True
        result["nxdomain"] = True
    
    # Make HTTP request
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{subdomain}"
            resp = make_request(url, timeout=10)
            body = resp.get("body", "").lower()
            status = resp.get("status_code", 0)
            
            # Check against fingerprints
            for service_id, service_info in TAKEOVER_FINGERPRINTS.items():
                # Check CNAME match
                cname_match = False
                if cname:
                    for cname_pattern in service_info.get("cnames", []):
                        if cname_pattern.lower() in cname.lower():
                            cname_match = True
                            break
                
                # Check fingerprints in response
                for fingerprint in service_info.get("fingerprints", []):
                    if fingerprint.lower() in body:
                        result["vulnerable"] = True
                        result["service"] = service_info["service"]
                        result["severity"] = service_info["severity"]
                        result["evidence"] = fingerprint
                        result["cname_match"] = cname_match
                        return result
                
                # Check NXDOMAIN-based takeover
                if is_nxdomain and service_info.get("nxdomain") and cname_match:
                    result["vulnerable"] = True
                    result["service"] = service_info["service"]
                    result["severity"] = service_info["severity"]
                    result["evidence"] = "NXDOMAIN with vulnerable CNAME"
                    return result
            
            break  # Success, no need to try http if https worked
        except:
            continue
    
    return result


def scan_subdomains_takeover(subdomains: List[str], max_workers: int = 10) -> Dict[str, Any]:
    """
    Scan multiple subdomains for takeover vulnerabilities with progress tracking.
    """
    import sys
    
    results = []
    vulnerable = []
    lock = threading.Lock()
    
    total = len(subdomains)
    scanned_count = 0
    start_time = time.time()
    
    print(f"[PROGRESS] Subdomain Takeover: Starting scan of {total} subdomains")
    sys.stdout.flush()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_subdomain = {
            executor.submit(check_subdomain_takeover, sub): sub 
            for sub in subdomains
        }
        
        for future in concurrent.futures.as_completed(future_to_subdomain):
            with lock:
                scanned_count += 1
                result = future.result()
                results.append(result)
                
                if result.get("vulnerable"):
                    vulnerable.append(result)
                    print(f"[VULNERABLE] {result.get('subdomain')} - {result.get('service')} ({result.get('severity')})")
                    sys.stdout.flush()
                
                if scanned_count % 10 == 0 or scanned_count == total:
                    progress = (scanned_count / total) * 100
                    elapsed = time.time() - start_time
                    eta = (elapsed / scanned_count) * (total - scanned_count) if scanned_count > 0 else 0
                    print(f"[PROGRESS] Subdomain Takeover: {scanned_count}/{total} ({progress:.1f}%) - Vulnerable: {len(vulnerable)} - ETA: {eta:.1f}s")
                    sys.stdout.flush()
    
    elapsed_total = time.time() - start_time
    print(f"[COMPLETE] Subdomain Takeover: {len(vulnerable)} vulnerable of {total} in {elapsed_total:.1f}s")
    sys.stdout.flush()
    
    return {
        "success": True,
        "total_scanned": len(subdomains),
        "vulnerable_count": len(vulnerable),
        "vulnerable": vulnerable,
        "results": results,
        "elapsed_seconds": round(elapsed_total, 2)
    }


# ============================================================================
# OPEN REDIRECT TESTING
# ============================================================================

OPEN_REDIRECT_PAYLOADS = [
    # Basic
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "///evil.com",
    
    # Protocol-relative
    "//evil.com/%2f..",
    "///evil.com/%2f..",
    
    # Encoding
    "https:%2f%2fevil.com",
    "https://evil.com%00.target.com",
    "https://evil.com%0d%0a.target.com",
    
    # Bypass attempts
    "https://evil.com?.target.com",
    "https://evil.com#.target.com",
    "https://evil.com@target.com",
    "https://target.com.evil.com",
    
    # JavaScript
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    
    # Path manipulation
    "/https://evil.com",
    "/.evil.com",
    "/evil.com",
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "redir", "return", "return_url",
    "returnUrl", "returnTo", "return_to", "next", "next_url", "goto", "go", "target",
    "to", "out", "view", "link", "ref", "site", "html", "val", "validate", "domain",
    "callback", "r", "u", "n", "forward", "location", "dest", "destination",
    "rurl", "redirect_to", "uri", "path", "continue", "checkout_url", "login_url"
]


def test_open_redirect(url: str, param: str = "", payloads: List[str] = None) -> Dict[str, Any]:
    """
    Test URL for open redirect vulnerabilities with realtime progress.
    
    Args:
        url: Target URL
        param: Specific parameter to test (optional, will try common ones)
        payloads: Custom payloads (optional)
    """
    import sys
    
    payloads = payloads or OPEN_REDIRECT_PAYLOADS
    # Limit to most common params if no specific param provided
    if not param:
        params_to_test = REDIRECT_PARAMS[:10]  # Test only first 10 params
    else:
        params_to_test = [param]
    
    findings = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Use fewer payloads for speed
    test_payloads = payloads[:8] if len(params_to_test) > 5 else payloads[:10]
    
    # Progress tracking
    total_tests = len(params_to_test) * len(test_payloads)
    current_test = 0
    start_time = time.time()
    
    for test_param in params_to_test:
        for payload in test_payloads:
            current_test += 1
            progress = (current_test / total_tests) * 100
            elapsed = time.time() - start_time
            eta = (elapsed / current_test) * (total_tests - current_test) if current_test > 0 else 0
            
            # Print progress to stdout (visible in logs)
            if current_test % 3 == 0 or current_test == total_tests:
                print(f"[PROGRESS] Open Redirect: {current_test}/{total_tests} ({progress:.1f}%) - ETA: {eta:.1f}s")
                sys.stdout.flush()
            
            test_url = f"{base_url}?{test_param}={quote(payload, safe='')}"
            
            try:
                resp = make_request(test_url, follow_redirects=False, timeout=15)
                status = resp.get("status_code", 0)
                location = resp.get("headers", {}).get("Location", "")
                
                # Check for redirect
                if status in [301, 302, 303, 307, 308]:
                    # Check if redirects to our payload
                    if "evil.com" in location or payload in location:
                        findings.append({
                            "param": test_param,
                            "payload": payload,
                            "status": status,
                            "location": location,
                            "vulnerable": True,
                            "severity": "high" if "javascript:" not in payload else "critical"
                        })
                        # Early exit if found vulnerability
                        if len(findings) >= 3:
                            return {
                                "success": True,
                                "url": url,
                                "findings": findings,
                                "vulnerable": True,
                                "total_tests": total_tests,
                                "completed_tests": current_test,
                                "progress": f"{progress:.1f}%",
                                "elapsed": f"{elapsed:.1f}s",
                                "note": "Early exit - vulnerabilities found"
                            }
                
                # Check for meta refresh or JS redirect in body
                body = resp.get("body", "").lower()
                if "evil.com" in body or (payload.lower() in body and "redirect" in body):
                    findings.append({
                        "param": test_param,
                        "payload": payload,
                        "status": status,
                        "evidence": "Payload reflected in body",
                        "vulnerable": True,
                        "severity": "medium"
                    })
                    
            except Exception as e:
                print(f"[ERROR] Test {current_test}/{total_tests} failed: {str(e)}")
                sys.stdout.flush()
                continue
    
    total_time = time.time() - start_time
    return {
        "success": True,
        "url": url,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "total_tests": total_tests,
        "completed_tests": current_test,
        "progress": "100.0%",
        "elapsed": f"{total_time:.1f}s"
    }


# ============================================================================
# CRLF INJECTION TESTING
# ============================================================================

CRLF_PAYLOADS = [
    "%0d%0aX-Injected: header",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%0aX-Injected: header",
    "%0dX-Injected: header",
    "%23%0d%0aX-Injected: header",
    "%5cr%5cnX-Injected: header",
    "%E5%98%8A%E5%98%8DX-Injected: header",  # UTF-8
    "\r\nX-Injected: header",
    "\r\n\r\n<script>alert(1)</script>",
    "%%0d0a%0d%0aX-Injected: header",
    "%0d%0aContent-Length: 0%0d%0a%0d%0a",
    "%0d%0aSet-Cookie: injected=true",
]


def test_crlf_injection(url: str, param: str = "") -> Dict[str, Any]:
    """
    Test for CRLF injection vulnerabilities with realtime progress.
    """
    import sys
    
    findings = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Use fewer payloads for speed
    test_payloads = CRLF_PAYLOADS[:8]
    
    # Progress tracking
    if param:
        total_tests = len(test_payloads)
    else:
        total_tests = len(test_payloads) * 6  # 6 common params
    current_test = 0
    start_time = time.time()
    
    # Test in URL path
    for payload in test_payloads:
        # Test in parameter
        if param:
            current_test += 1
            progress = (current_test / total_tests) * 100
            elapsed = time.time() - start_time
            eta = (elapsed / current_test) * (total_tests - current_test) if current_test > 0 else 0
            if current_test % 2 == 0 or current_test == total_tests:
                print(f"[PROGRESS] CRLF: {current_test}/{total_tests} ({progress:.1f}%) - ETA: {eta:.1f}s")
                sys.stdout.flush()
            
            test_url = f"{base_url}?{param}={payload}"
            
            try:
                resp = make_request(test_url, timeout=15)
                headers = resp.get("headers", {})
                
                # Check for injected header
                if "X-Injected" in headers:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "evidence": "X-Injected header present",
                        "severity": "high",
                        "vulnerable": True
                    })
                    # Early exit
                    if len(findings) >= 2:
                        break
                
                # Check for Set-Cookie injection
                if "injected=true" in str(headers.get("Set-Cookie", "")):
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "evidence": "Set-Cookie injection",
                        "severity": "critical",
                        "vulnerable": True
                    })
                    # Early exit
                    if len(findings) >= 2:
                        break
                        
            except Exception as e:
                print(f"[ERROR] CRLF test {current_test}/{total_tests} failed: {str(e)}")
                sys.stdout.flush()
                continue
        else:
            # Test common params
            test_params = ["url", "redirect", "page", "path", "file", "next"]
            for test_param in test_params:
                current_test += 1
                progress = (current_test / total_tests) * 100
                elapsed = time.time() - start_time
                eta = (elapsed / current_test) * (total_tests - current_test) if current_test > 0 else 0
                if current_test % 2 == 0 or current_test == total_tests:
                    print(f"[PROGRESS] CRLF: {current_test}/{total_tests} ({progress:.1f}%) - ETA: {eta:.1f}s")
                    sys.stdout.flush()
                
                test_url = f"{base_url}?{test_param}={payload}"
                
                try:
                    resp = make_request(test_url, timeout=15)
                    headers = resp.get("headers", {})
                    
                    # Check for injected header
                    if "X-Injected" in headers:
                        findings.append({
                            "param": test_param,
                            "payload": payload,
                            "evidence": "X-Injected header present",
                            "severity": "high",
                            "vulnerable": True
                        })
                        # Early exit if found
                        if len(findings) >= 2:
                            return {
                                "success": True,
                                "url": url,
                                "findings": findings,
                                "vulnerable": True,
                                "total_tests": total_tests,
                                "completed_tests": current_test,
                                "progress": f"{progress:.1f}%",
                                "elapsed": f"{elapsed:.1f}s",
                                "note": "Early exit - vulnerabilities found"
                            }
                    
                    # Check for Set-Cookie injection
                    if "injected=true" in str(headers.get("Set-Cookie", "")):
                        findings.append({
                            "param": test_param,
                            "payload": payload,
                            "evidence": "Set-Cookie injection",
                            "severity": "critical",
                            "vulnerable": True
                        })
                        # Early exit if found
                        if len(findings) >= 2:
                            return {
                                "success": True,
                                "url": url,
                                "findings": findings,
                                "vulnerable": True,
                                "total_tests": total_tests,
                                "completed_tests": current_test,
                                "progress": f"{progress:.1f}%",
                                "elapsed": f"{elapsed:.1f}s",
                                "note": "Early exit - vulnerabilities found"
                            }
                        
                except Exception as e:
                    print(f"[ERROR] CRLF test {current_test}/{total_tests} failed: {str(e)}")
                    continue
    
    total_time = time.time() - start_time
    return {
        "success": True,
        "url": url,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "total_tests": total_tests,
        "completed_tests": current_test,
        "progress": "100.0%",
        "elapsed": f"{total_time:.1f}s"
    }


# ============================================================================
# JAVASCRIPT ENDPOINT EXTRACTION
# ============================================================================

JS_ENDPOINT_PATTERNS = [
    # API endpoints
    r'["\']/(api|v[0-9]+)/[a-zA-Z0-9/_-]+["\']',
    r'["\']https?://[^"\']+/api/[^"\']+["\']',
    
    # Paths with common extensions
    r'["\'](/[a-zA-Z0-9/_-]+\.(php|asp|aspx|jsp|json|xml|action|do))["\']',
    
    # REST-like paths
    r'["\'](/[a-zA-Z0-9]+/[a-zA-Z0-9]+(/[a-zA-Z0-9]+)?)["\']',
    
    # Full URLs
    r'["\'](https?://[a-zA-Z0-9.-]+/[^"\']+)["\']',
    
    # Relative paths
    r'["\'](\./[a-zA-Z0-9/_-]+)["\']',
    r'["\'](\.\.\/[a-zA-Z0-9/_-]+)["\']',
    
    # GraphQL endpoints
    r'["\']([^"\']*graphql[^"\']*)["\']',
    
    # WebSocket endpoints
    r'["\'](wss?://[^"\']+)["\']',
    
    # Fetch/XHR calls
    r'fetch\(["\']([^"\']+)["\']',
    r'\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'XMLHttpRequest.*open\([^,]+,\s*["\']([^"\']+)["\']',
]

JS_SENSITIVE_PATTERNS = [
    # API Keys
    (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', "API Key"),
    (r'["\']?apikey["\']?\s*[:=]\s*["\']([^"\']+)["\']', "API Key"),
    
    # Auth tokens
    (r'["\']?(?:access|auth)[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Auth Token"),
    (r'["\']?bearer["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Bearer Token"),
    
    # AWS
    (r'["\']?aws[_-]?(?:access|secret)[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', "AWS Key"),
    
    # Admin paths
    (r'["\']/(admin|administrator|manage|dashboard|control)[/a-zA-Z0-9_-]*["\']', "Admin Path"),
    
    # Debug endpoints
    (r'["\']/(debug|test|dev|staging)[/a-zA-Z0-9_-]*["\']', "Debug Endpoint"),
    
    # Internal endpoints
    (r'["\']/(internal|private|hidden)[/a-zA-Z0-9_-]*["\']', "Internal Endpoint"),
]


def extract_js_endpoints(js_content: str, base_url: str = "") -> Dict[str, Any]:
    """
    Extract endpoints and sensitive data from JavaScript.
    """
    endpoints = set()
    sensitive = []
    
    # Extract endpoints
    for pattern in JS_ENDPOINT_PATTERNS:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            # Clean and normalize
            endpoint = match.strip()
            if len(endpoint) > 3 and not endpoint.startswith("data:"):
                # Make absolute if base_url provided
                if base_url and not endpoint.startswith(("http://", "https://", "ws://", "wss://")):
                    endpoint = urljoin(base_url, endpoint)
                endpoints.add(endpoint)
    
    # Extract sensitive data
    for pattern, desc in JS_SENSITIVE_PATTERNS:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            sensitive.append({
                "type": desc,
                "value": match[:50] + "..." if len(match) > 50 else match,
                "severity": "high" if "key" in desc.lower() or "token" in desc.lower() else "medium"
            })
    
    # Categorize endpoints
    api_endpoints = [e for e in endpoints if "/api" in e.lower() or "/v1" in e.lower() or "/v2" in e.lower()]
    admin_endpoints = [e for e in endpoints if any(x in e.lower() for x in ["admin", "manage", "dashboard"])]
    auth_endpoints = [e for e in endpoints if any(x in e.lower() for x in ["login", "auth", "token", "oauth"])]
    
    return {
        "success": True,
        "total_endpoints": len(endpoints),
        "endpoints": list(endpoints),
        "api_endpoints": api_endpoints,
        "admin_endpoints": admin_endpoints,
        "auth_endpoints": auth_endpoints,
        "sensitive_data": sensitive,
        "summary": {
            "total": len(endpoints),
            "api": len(api_endpoints),
            "admin": len(admin_endpoints),
            "auth": len(auth_endpoints),
            "sensitive": len(sensitive)
        }
    }


def scan_js_files(urls: List[str]) -> Dict[str, Any]:
    """
    Fetch and scan multiple JS files for endpoints with concurrent execution and progress tracking.
    """
    import sys
    
    all_endpoints = set()
    all_sensitive = []
    results = []
    lock = threading.Lock()
    
    total_urls = len(urls)
    scanned_count = 0
    start_time = time.time()
    
    print(f"[PROGRESS] JS Scanner: Starting scan of {total_urls} files")
    sys.stdout.flush()
    
    def scan_single_js(url: str) -> Optional[Dict]:
        """Scan a single JS file."""
        try:
            resp = make_request(url, timeout=15)
            if resp.get("success"):
                body = resp.get("body", "")
                parsed = urlparse(url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                
                result = extract_js_endpoints(body, base)
                result["url"] = url
                return result
        except Exception:
            pass
        return None
    
    # Use ThreadPoolExecutor for concurrent scanning
    max_workers = 5
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_single_js, url): url for url in urls}
        
        for future in concurrent.futures.as_completed(futures):
            with lock:
                scanned_count += 1
                progress = (scanned_count / total_urls) * 100
                elapsed = time.time() - start_time
                eta = (elapsed / scanned_count) * (total_urls - scanned_count) if scanned_count > 0 else 0
                
                result = future.result()
                if result:
                    results.append(result)
                    all_endpoints.update(result.get("endpoints", []))
                    all_sensitive.extend(result.get("sensitive_data", []))
                    
                    endpoints_found = result.get("total_endpoints", 0)
                    if endpoints_found > 0:
                        print(f"[FOUND] {result['url']}: {endpoints_found} endpoints")
                        sys.stdout.flush()
                
                if scanned_count % 3 == 0 or scanned_count == total_urls:
                    print(f"[PROGRESS] JS Scanner: {scanned_count}/{total_urls} ({progress:.1f}%) - Endpoints: {len(all_endpoints)} - ETA: {eta:.1f}s")
                    sys.stdout.flush()
    
    elapsed_total = time.time() - start_time
    print(f"[COMPLETE] JS Scanner: {len(all_endpoints)} endpoints from {len(results)} files in {elapsed_total:.1f}s")
    sys.stdout.flush()
    
    return {
        "success": True,
        "files_scanned": len(results),
        "total_endpoints": len(all_endpoints),
        "all_endpoints": list(all_endpoints),
        "sensitive_data": all_sensitive,
        "per_file": results,
        "elapsed_seconds": round(elapsed_total, 2)
    }


# ============================================================================
# PARAMETER MINING
# ============================================================================

COMMON_PARAMS = [
    # Auth
    "id", "user", "username", "user_id", "uid", "userid", "account", "email",
    "password", "pass", "pwd", "token", "auth", "key", "api_key", "apikey",
    
    # Data
    "file", "filename", "path", "dir", "document", "folder", "root", "pg",
    "page", "p", "q", "query", "search", "keyword", "s", "term",
    
    # Redirect
    "url", "uri", "redirect", "return", "next", "goto", "target", "dest",
    "destination", "rurl", "return_url", "link", "ref",
    
    # Debug/Admin
    "debug", "test", "admin", "mode", "config", "env", "action", "cmd",
    "command", "exec", "execute", "run", "do", "func", "function",
    
    # Common
    "name", "value", "data", "content", "text", "msg", "message", "body",
    "title", "description", "comment", "input", "output", "result",
    
    # IDs
    "order_id", "order", "invoice", "product", "item", "category", "type",
    "ref", "reference", "code", "num", "number", "no",
    
    # Format
    "format", "type", "callback", "jsonp", "json", "xml", "output_format",
    
    # Version
    "v", "version", "ver", "api_version",
    
    # Pagination
    "limit", "offset", "start", "count", "size", "per_page", "page_size",
]


def discover_params(url: str, wordlist: List[str] = None, method: str = "GET") -> Dict[str, Any]:
    """
    Discover hidden parameters on a URL with concurrent testing and progress tracking.
    """
    import sys
    
    wordlist = wordlist or COMMON_PARAMS
    found_params = []
    
    # Progress tracking
    start_time = time.time()
    total_params = len(wordlist)
    tested_count = 0
    lock = threading.Lock()
    
    print(f"[PROGRESS] Parameter Discovery: Starting scan of {total_params} params on {url}")
    sys.stdout.flush()
    
    # Get baseline response
    baseline = make_request(url, method=method, timeout=10)
    baseline_length = len(baseline.get("body", ""))
    baseline_status = baseline.get("status_code", 0)
    
    print(f"[PROGRESS] Baseline: status={baseline_status}, length={baseline_length}")
    sys.stdout.flush()
    
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query)
    
    def test_param(param: str) -> Optional[Dict]:
        """Test a single parameter with multiple values."""
        nonlocal tested_count
        
        if param in existing_params:
            return None
        
        test_values = ["1", "test", "true", "../etc/passwd"]
        
        for test_value in test_values:
            try:
                if method == "GET":
                    separator = "&" if "?" in url else "?"
                    test_url = f"{url}{separator}{param}={test_value}"
                    resp = make_request(test_url, timeout=10)
                else:
                    resp = make_request(url, method=method, data={param: test_value}, timeout=10)
                
                resp_length = len(resp.get("body", ""))
                resp_status = resp.get("status_code", 0)
                
                length_diff = abs(resp_length - baseline_length)
                if length_diff > 50 or resp_status != baseline_status:
                    return {
                        "param": param,
                        "value": test_value,
                        "length_diff": length_diff,
                        "status_change": resp_status != baseline_status,
                        "new_status": resp_status
                    }
            except Exception:
                continue
        
        return None
    
    # Use ThreadPoolExecutor for concurrent testing
    max_workers = 10  # Limit concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_param, param): param for param in wordlist}
        
        for future in concurrent.futures.as_completed(futures):
            with lock:
                tested_count += 1
                progress = (tested_count / total_params) * 100
                elapsed = time.time() - start_time
                eta = (elapsed / tested_count) * (total_params - tested_count) if tested_count > 0 else 0
                
                # Print progress every 5 params or on found
                result = future.result()
                if result:
                    found_params.append(result)
                    print(f"[FOUND] {result['param']}={result['value']} (status={result.get('new_status')}, diff={result['length_diff']})")
                    sys.stdout.flush()
                
                if tested_count % 5 == 0 or tested_count == total_params:
                    print(f"[PROGRESS] Parameter Discovery: {tested_count}/{total_params} ({progress:.1f}%) - Found: {len(found_params)} - ETA: {eta:.1f}s")
                    sys.stdout.flush()
    
    elapsed_total = time.time() - start_time
    print(f"[COMPLETE] Parameter Discovery: {len(found_params)} params found in {elapsed_total:.1f}s")
    sys.stdout.flush()
    
    return {
        "success": True,
        "url": url,
        "method": method,
        "baseline_length": baseline_length,
        "baseline_status": baseline_status,
        "found_params": found_params,
        "total_found": len(found_params),
        "total_tested": tested_count,
        "elapsed_seconds": round(elapsed_total, 2)
    }


# ============================================================================
# HEADER INJECTION TESTING
# ============================================================================

def test_header_injection(url: str) -> Dict[str, Any]:
    """
    Test for header injection vulnerabilities with realtime progress.
    """
    import sys
    
    findings = []
    
    # Headers to inject (reduced for speed)
    injection_headers = {
        "X-Forwarded-For": ["127.0.0.1", "evil.com"],
        "X-Forwarded-Host": ["evil.com"],
        "X-Original-URL": ["/admin"],
        "X-Rewrite-URL": ["/admin"],
        "X-Real-IP": ["127.0.0.1"],
        "Host": ["evil.com"],
    }
    
    # Progress tracking
    total_tests = sum(len(values) for values in injection_headers.values())
    current_test = 0
    start_time = time.time()
    
    # Baseline request
    baseline = make_request(url, timeout=15)
    baseline_body = baseline.get("body", "")
    baseline_status = baseline.get("status_code", 0)
    
    for header, values in injection_headers.items():
        for value in values:
            current_test += 1
            progress = (current_test / total_tests) * 100
            elapsed = time.time() - start_time
            eta = (elapsed / current_test) * (total_tests - current_test) if current_test > 0 else 0
            if current_test % 2 == 0 or current_test == total_tests:
                print(f"[PROGRESS] Header Injection: {current_test}/{total_tests} ({progress:.1f}%) - ETA: {eta:.1f}s")
                sys.stdout.flush()
            
            try:
                resp = make_request(url, headers={header: value}, timeout=15)
                resp_body = resp.get("body", "")
                resp_status = resp.get("status_code", 0)
                
                # Check for differences
                if resp_status != baseline_status:
                    findings.append({
                        "header": header,
                        "value": value,
                        "original_status": baseline_status,
                        "new_status": resp_status,
                        "type": "status_change",
                        "severity": "high" if resp_status in [200, 302] and baseline_status in [401, 403] else "medium"
                    })
                    # Early exit if found bypass
                    if resp_status in [200, 302] and baseline_status in [401, 403]:
                        return {
                            "success": True,
                            "url": url,
                            "findings": findings,
                            "vulnerable": True,
                            "total_tests": total_tests,
                            "completed_tests": current_test,
                            "progress": f"{progress:.1f}%",
                            "elapsed": f"{elapsed:.1f}s",
                            "note": "Early exit - auth bypass found"
                        }
                elif len(resp_body) != len(baseline_body) and abs(len(resp_body) - len(baseline_body)) > 100:
                    findings.append({
                        "header": header,
                        "value": value,
                        "type": "content_change",
                        "length_diff": len(resp_body) - len(baseline_body),
                        "severity": "medium"
                    })
                    
            except Exception as e:
                print(f"[ERROR] Header injection test {current_test}/{total_tests} failed: {str(e)}")
                continue
    
    total_time = time.time() - start_time
    return {
        "success": True,
        "url": url,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "total_tests": total_tests,
        "completed_tests": current_test,
        "progress": "100.0%",
        "elapsed": f"{total_time:.1f}s"
    }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def quick_vuln_scan(url: str) -> Dict[str, Any]:
    """
    Quick vulnerability scan combining multiple tests with realtime progress.
    """
    import sys
    
    print(f"[PROGRESS] Starting quick vulnerability scan for: {url}")
    sys.stdout.flush()
    start_time = time.time()
    
    results = {
        "url": url,
        "scans": {},
        "vulnerabilities": []
    }
    
    # Open redirect
    print(f"[PROGRESS] Running Open Redirect test...")
    sys.stdout.flush()
    redirect_result = test_open_redirect(url)
    results["scans"]["open_redirect"] = redirect_result
    if redirect_result.get("vulnerable"):
        results["vulnerabilities"].append({
            "type": "Open Redirect",
            "severity": "high",
            "details": redirect_result.get("findings", [])
        })
    
    # CRLF
    print(f"[PROGRESS] Running CRLF Injection test...")
    sys.stdout.flush()
    crlf_result = test_crlf_injection(url)
    results["scans"]["crlf"] = crlf_result
    if crlf_result.get("vulnerable"):
        results["vulnerabilities"].append({
            "type": "CRLF Injection",
            "severity": "high",
            "details": crlf_result.get("findings", [])
        })
    
    # Header injection
    print(f"[PROGRESS] Running Header Injection test...")
    sys.stdout.flush()
    header_result = test_header_injection(url)
    results["scans"]["header_injection"] = header_result
    if header_result.get("vulnerable"):
        results["vulnerabilities"].append({
            "type": "Header Injection",
            "severity": "medium",
            "details": header_result.get("findings", [])
        })
    
    total_time = time.time() - start_time
    results["total_vulnerabilities"] = len(results["vulnerabilities"])
    results["success"] = True
    results["total_elapsed"] = f"{total_time:.1f}s"
    print(f"[COMPLETE] Quick scan completed in {total_time:.1f}s - Found {results['total_vulnerabilities']} vulnerabilities")
    sys.stdout.flush()
    
    return results
