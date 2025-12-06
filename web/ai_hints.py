"""
AI Hints for 0-Day Hunting - Help AI think smarter about vulnerabilities

This module provides contextual hints and analysis patterns that help
the AI identify potential vulnerabilities without restricting its creativity.
"""

from typing import Dict, Any, List
import re

# ============================================================================
# VULNERABILITY PATTERNS - Things AI should look for
# ============================================================================

INTERESTING_PATTERNS = {
    "auth_bypass": {
        "indicators": [
            "admin", "login", "auth", "session", "token", "jwt", "bearer",
            "api_key", "password", "credential", "oauth", "sso"
        ],
        "test_ideas": [
            "Try removing auth headers entirely",
            "Try changing HTTP method (GET->POST, POST->PUT)",
            "Try path traversal in auth endpoints (/admin/../user)",
            "Try parameter pollution (?role=admin&role=user)",
            "Try case variation (Admin vs admin vs ADMIN)",
            "Try adding .json or .xml extension",
            "Try null byte injection (%00)",
        ]
    },
    
    "idor": {
        "indicators": [
            "id=", "user_id", "order_id", "file_id", "doc_id", "account",
            "profile", "uuid", "guid", "ref=", "num=", "no="
        ],
        "test_ideas": [
            "Try sequential IDs (id-1, id+1, id*2)",
            "Try negative values and zero",
            "Try array notation (id[]=1&id[]=2)",
            "Try string values where int expected",
            "Try UUID of another user",
            "Try wildcard (*) or empty value",
            "Try encoded values (base64, hex)",
        ]
    },
    
    "injection": {
        "indicators": [
            "search", "query", "filter", "sort", "order", "cmd", "exec",
            "eval", "template", "render", "include", "path", "file", "url"
        ],
        "test_ideas": [
            "Try basic SQL: ' OR '1'='1",
            "Try NoSQL: {$ne: null}, {$gt: ''}",
            "Try template: {{7*7}}, ${7*7}, <%= 7*7 %>",
            "Try command: ; id, | whoami, `id`",
            "Try path traversal: ../../../etc/passwd",
            "Try SSRF: http://localhost, http://169.254.169.254",
        ]
    },
    
    "file_operations": {
        "indicators": [
            "upload", "download", "file", "attachment", "document", "image",
            "import", "export", "backup", "restore", "read", "write"
        ],
        "test_ideas": [
            "Try uploading .php, .jsp, .aspx files",
            "Try double extension: file.php.jpg",
            "Try null byte: file.php%00.jpg",
            "Try content-type mismatch",
            "Try path traversal in filename",
            "Try large file for DoS",
            "Try symlink in zip/tar",
        ]
    },
    
    "api_design": {
        "indicators": [
            "/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/internal/",
            "swagger", "openapi", "docs", "schema"
        ],
        "test_ideas": [
            "Try accessing /api/v2 when /api/v1 is shown",
            "Try /api/internal/, /api/admin/, /api/debug/",
            "Try GraphQL introspection: {__schema{types{name}}}",
            "Try batch operations for race conditions",
            "Try HTTP method override: X-HTTP-Method-Override",
            "Try API versioning bypass",
        ]
    },
    
    "serialization": {
        "indicators": [
            "serialize", "object", "data=", "payload=", "state=", "viewstate",
            "pickle", "marshal", "yaml", "xml", "json"
        ],
        "test_ideas": [
            "Try Java deserialization gadgets",
            "Try Python pickle payloads",
            "Try PHP object injection",
            "Try XXE in XML parsers",
            "Try prototype pollution in JSON",
            "Try YAML code execution",
        ]
    }
}

# ============================================================================
# RESPONSE ANALYSIS - What to look for in responses
# ============================================================================

INTERESTING_RESPONSE_PATTERNS = {
    "errors": {
        "sql": ["sql", "mysql", "postgresql", "oracle", "sqlite", "syntax error", "query"],
        "path": ["no such file", "file not found", "cannot open", "permission denied"],
        "debug": ["stack trace", "traceback", "exception", "error in", "line \\d+"],
        "config": ["secret", "password", "api_key", "token", "credential", "private"],
    },
    "headers": {
        "tech_disclosure": ["X-Powered-By", "Server", "X-AspNet-Version"],
        "security_missing": ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"],
        "interesting": ["X-Debug", "X-Request-Id", "X-Trace-Id"],
    }
}

def analyze_for_0day(url: str, response: Dict) -> Dict[str, Any]:
    """
    Analyze URL and response for potential 0-day opportunities.
    Returns hints for AI to explore further.
    """
    hints = {
        "url_patterns": [],
        "response_hints": [],
        "test_suggestions": [],
        "risk_level": "LOW"
    }
    
    url_lower = url.lower()
    body = response.get("body", "").lower() if response.get("body") else ""
    headers = response.get("headers", {})
    
    # Analyze URL patterns
    for category, data in INTERESTING_PATTERNS.items():
        for indicator in data["indicators"]:
            if indicator in url_lower:
                hints["url_patterns"].append({
                    "category": category,
                    "found": indicator,
                    "suggestions": data["test_ideas"][:3]
                })
                hints["risk_level"] = "MEDIUM"
    
    # Analyze response for errors/leaks
    for error_type, patterns in INTERESTING_RESPONSE_PATTERNS["errors"].items():
        for pattern in patterns:
            if re.search(pattern, body, re.I):
                hints["response_hints"].append({
                    "type": f"{error_type}_leak",
                    "pattern": pattern,
                    "action": f"Investigate {error_type} error - potential info disclosure"
                })
                hints["risk_level"] = "HIGH"
    
    # Check headers
    for header in INTERESTING_RESPONSE_PATTERNS["headers"]["tech_disclosure"]:
        if header.lower() in [h.lower() for h in headers.keys()]:
            value = headers.get(header, headers.get(header.lower(), ""))
            hints["response_hints"].append({
                "type": "tech_disclosure",
                "header": header,
                "value": value,
                "action": f"Research known vulnerabilities for {value}"
            })
    
    # Generate test suggestions based on findings
    if hints["url_patterns"]:
        hints["test_suggestions"].append("🎯 URL contains interesting parameters - test for IDOR/injection")
    if "token" in url_lower or "jwt" in url_lower:
        hints["test_suggestions"].append("🔐 JWT/Token detected - try analyze_jwt tool")
    if "/api/" in url_lower:
        hints["test_suggestions"].append("🔗 API endpoint - try fuzzing, method tampering")
    if any(x in url_lower for x in ["file", "path", "download"]):
        hints["test_suggestions"].append("📁 File operation detected - test for path traversal")
    
    return hints

def suggest_next_steps(findings: List[Dict]) -> List[str]:
    """
    Based on current findings, suggest next steps for manual testing.
    Encourages AI to think creatively.
    """
    suggestions = []
    
    # Generic suggestions that encourage creative thinking
    base_suggestions = [
        "🤔 What happens if you chain multiple bugs together?",
        "🔄 Try the same request with different HTTP methods",
        "🎭 What if you're authenticated as a different user role?",
        "⏰ Is there a race condition opportunity here?",
        "📝 Check if input validation differs between endpoints",
        "🔍 Look for related endpoints that might share the same bug",
        "💡 What would happen in an edge case? (empty, null, max length)",
    ]
    
    if not findings:
        suggestions.append("🎯 Start with reconnaissance: technology detection, endpoint discovery")
        suggestions.append("🕷️ Crawl the application to find all entry points")
        suggestions.append("📋 Check for common files: robots.txt, sitemap.xml, .git/")
    
    suggestions.extend(base_suggestions[:3])
    
    return suggestions

# ============================================================================
# PAYLOAD GENERATION HELPERS
# ============================================================================

def generate_smart_payloads(context: str, base_value: str = "") -> List[Dict[str, str]]:
    """
    Generate context-aware payloads for testing.
    """
    payloads = []
    
    if "id" in context.lower() or "num" in context.lower():
        payloads.extend([
            {"payload": "0", "reason": "Zero value edge case"},
            {"payload": "-1", "reason": "Negative value"},
            {"payload": str(int(base_value) + 1) if base_value.isdigit() else "1", "reason": "Adjacent ID"},
            {"payload": "999999999", "reason": "Very large number"},
            {"payload": "null", "reason": "Null string"},
            {"payload": "undefined", "reason": "Undefined string"},
            {"payload": "[]", "reason": "Empty array"},
            {"payload": "1 OR 1=1", "reason": "Basic SQLi"},
        ])
    
    if "name" in context.lower() or "user" in context.lower():
        payloads.extend([
            {"payload": "admin", "reason": "Common admin username"},
            {"payload": "' OR '1'='1", "reason": "SQL injection"},
            {"payload": "<script>alert(1)</script>", "reason": "XSS test"},
            {"payload": "{{7*7}}", "reason": "SSTI test"},
            {"payload": "../../../etc/passwd", "reason": "Path traversal"},
        ])
    
    if "url" in context.lower() or "redirect" in context.lower():
        payloads.extend([
            {"payload": "http://evil.com", "reason": "Open redirect"},
            {"payload": "//evil.com", "reason": "Protocol-relative redirect"},
            {"payload": "javascript:alert(1)", "reason": "JavaScript URI"},
            {"payload": "http://169.254.169.254", "reason": "SSRF to metadata"},
        ])
    
    return payloads

# ============================================================================
# THINKING PROMPTS - Help AI reason about security
# ============================================================================

THINKING_PROMPTS = {
    "recon": [
        "What technologies is this application using?",
        "Are there any hidden endpoints or parameters?",
        "What user roles exist and what can each access?",
    ],
    "auth": [
        "How is the session managed? Cookies? JWT? API keys?",
        "Can I access resources without authentication?",
        "What happens if I tamper with the session token?",
    ],
    "injection": [
        "Where does user input end up? Database? Command line? Template?",
        "Is input validated on client-side only?",
        "What encoding/escaping is applied?",
    ],
    "logic": [
        "What is the expected workflow? Can I skip steps?",
        "Are there race conditions in multi-step processes?",
        "Can I manipulate prices, quantities, or other business values?",
    ],
    "access": [
        "Can I access other users' data by changing IDs?",
        "Are there horizontal and vertical privilege escalation paths?",
        "What happens with deleted/suspended accounts?",
    ]
}

def get_thinking_prompt(category: str = "general") -> List[str]:
    """Get thinking prompts to help AI reason about security"""
    if category in THINKING_PROMPTS:
        return THINKING_PROMPTS[category]
    
    # Return mix of all categories for general thinking
    all_prompts = []
    for prompts in THINKING_PROMPTS.values():
        all_prompts.extend(prompts)
    return all_prompts[:5]
