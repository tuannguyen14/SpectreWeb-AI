#!/usr/bin/env python3
"""
SpectreWeb AI - Smart Analyzer v3.1
AI-powered analysis engine for intelligent vulnerability detection
"""

import re
import json
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TechFingerprint:
    """Technology fingerprint for smart detection"""
    name: str
    category: str  # cms, framework, server, language, etc.
    patterns: List[str]
    vulns: List[str] = field(default_factory=list)
    priority_tests: List[str] = field(default_factory=list)


@dataclass
class AIInsight:
    """AI-generated insight"""
    category: str  # attack, info, warning, tip, next_step
    message: str
    confidence: float  # 0-1
    priority: int  # 1-5 (5 highest)
    related_tool: Optional[str] = None


class SmartAnalyzer:
    """
    AI-powered analyzer for intelligent scanning decisions.
    Provides real-time insights and recommendations.
    """
    
    # Technology fingerprints database
    TECH_FINGERPRINTS = [
        TechFingerprint(
            name="WordPress",
            category="cms",
            patterns=[r"wp-content", r"wp-includes", r"wp-admin", r"WordPress"],
            vulns=["WP Core CVEs", "Plugin vulnerabilities", "Theme exploits", "XML-RPC attacks"],
            priority_tests=["wpscan", "xmlrpc_test", "wp_user_enum", "plugin_enum"]
        ),
        TechFingerprint(
            name="Drupal",
            category="cms",
            patterns=[r"Drupal", r"/sites/default", r"drupal\.js"],
            vulns=["Drupalgeddon", "SA-CORE CVEs"],
            priority_tests=["droopescan", "drupal_version"]
        ),
        TechFingerprint(
            name="Laravel",
            category="framework",
            patterns=[r"laravel", r"Laravel", r"_token", r"XSRF-TOKEN"],
            vulns=["Debug mode info leak", "CVE-2021-3129 RCE", "Mass assignment"],
            priority_tests=["laravel_debug", "env_exposure", "debug_bar"]
        ),
        TechFingerprint(
            name="Django",
            category="framework",
            patterns=[r"csrfmiddlewaretoken", r"django", r"__debug__"],
            vulns=["Debug mode", "Admin panel", "ORM injection"],
            priority_tests=["django_debug", "admin_panel"]
        ),
        TechFingerprint(
            name="Express/Node.js",
            category="framework",
            patterns=[r"X-Powered-By: Express", r"node", r"npm"],
            vulns=["Prototype pollution", "NoSQL injection", "SSRF"],
            priority_tests=["prototype_pollution", "nosql_injection"]
        ),
        TechFingerprint(
            name="Spring Boot",
            category="framework",
            patterns=[r"Whitelabel Error", r"Spring", r"actuator"],
            vulns=["Actuator exposure", "SpEL injection", "CVE-2022-22965"],
            priority_tests=["actuator_scan", "heapdump", "env_endpoint"]
        ),
        TechFingerprint(
            name="ASP.NET",
            category="framework",
            patterns=[r"ASP\.NET", r"__VIEWSTATE", r"\.aspx", r"\.ashx"],
            vulns=["ViewState deserialization", "Padding Oracle", "Web.config exposure"],
            priority_tests=["viewstate_test", "trace_axd", "elmah"]
        ),
        TechFingerprint(
            name="Nginx",
            category="server",
            patterns=[r"nginx", r"Server: nginx"],
            vulns=["Off-by-slash", "Alias traversal", "CRLF injection"],
            priority_tests=["nginx_alias", "off_by_slash"]
        ),
        TechFingerprint(
            name="Apache",
            category="server",
            patterns=[r"Apache", r"Server: Apache", r"mod_"],
            vulns=["mod_proxy SSRF", "CVE-2021-41773", ".htaccess bypass"],
            priority_tests=["apache_status", "mod_status", "path_traversal"]
        ),
        TechFingerprint(
            name="Cloudflare",
            category="waf",
            patterns=[r"cloudflare", r"cf-ray", r"__cfduid"],
            vulns=["WAF bypass needed", "Origin IP exposure"],
            priority_tests=["waf_bypass", "origin_discovery"]
        ),
        TechFingerprint(
            name="JWT",
            category="auth",
            patterns=[r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", r"Bearer ", r"authorization"],
            vulns=["Algorithm confusion", "Weak secret", "None algorithm"],
            priority_tests=["jwt_analyze", "jwt_crack"]
        ),
        TechFingerprint(
            name="GraphQL",
            category="api",
            patterns=[r"graphql", r"__schema", r"query {"],
            vulns=["Introspection enabled", "Batching attacks", "DoS"],
            priority_tests=["graphql_introspection", "graphql_enum"]
        ),
        TechFingerprint(
            name="AWS",
            category="cloud",
            patterns=[r"amazonaws\.com", r"aws", r"s3\."],
            vulns=["S3 bucket misconfiguration", "SSRF to metadata"],
            priority_tests=["s3_bucket_enum", "metadata_ssrf"]
        ),
    ]
    
    # Vulnerability patterns to detect in responses
    VULN_PATTERNS = {
        "sql_error": [
            (r"SQL syntax.*MySQL", "MySQL SQL Injection", "high"),
            (r"Warning.*mysql_", "MySQL Error", "medium"),
            (r"PostgreSQL.*ERROR", "PostgreSQL SQL Injection", "high"),
            (r"ORA-\d{5}", "Oracle SQL Injection", "high"),
            (r"Microsoft OLE DB Provider for SQL Server", "MSSQL Injection", "high"),
            (r"SQLite.*Error", "SQLite Injection", "high"),
            (r"Unclosed quotation mark", "SQL Injection", "high"),
        ],
        "path_disclosure": [
            (r"\/var\/www\/", "Linux Path Disclosure", "low"),
            (r"C:\\\\[Ii]netpub", "Windows Path Disclosure", "low"),
            (r"\/home\/\w+\/", "Home Directory Disclosure", "low"),
        ],
        "stack_trace": [
            (r"Traceback \(most recent call last\)", "Python Stack Trace", "medium"),
            (r"at [\w\.$]+\([\w]+\.java:\d+\)", "Java Stack Trace", "medium"),
            (r"Fatal error:.*on line \d+", "PHP Fatal Error", "medium"),
            (r"System\..*Exception", ".NET Exception", "medium"),
        ],
        "sensitive_info": [
            (r"password[\"']\s*[=:]\s*[\"'][^\"']+", "Hardcoded Password", "critical"),
            (r"api[_-]?key[\"']\s*[=:]\s*[\"'][^\"']+", "API Key Exposure", "high"),
            (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY", "Private Key Exposure", "critical"),
            (r"AWS[_A-Z]*[=:]\s*['\"]?AKI[A-Z0-9]{16}", "AWS Key Exposure", "critical"),
        ],
        "xss_reflection": [
            (r"<script[^>]*>[^<]*alert\s*\(", "XSS Reflection", "high"),
            (r"onerror\s*=", "Event Handler XSS", "high"),
        ],
        "version_disclosure": [
            (r"PHP/[\d.]+", "PHP Version", "info"),
            (r"Apache/[\d.]+", "Apache Version", "info"),
            (r"nginx/[\d.]+", "Nginx Version", "info"),
            (r"OpenSSH[_/][\d.]+", "OpenSSH Version", "info"),
        ],
    }
    
    # Attack vectors based on context
    ATTACK_VECTORS = {
        "auth_endpoint": [
            "SQL injection in login",
            "Credential stuffing",
            "Rate limiting bypass",
            "Account enumeration",
            "Password reset poisoning",
        ],
        "file_upload": [
            "Unrestricted file upload",
            "Extension bypass",
            "Content-type bypass",
            "Double extension",
            "Null byte injection",
        ],
        "api_endpoint": [
            "IDOR/BOLA",
            "Mass assignment",
            "Rate limiting",
            "Broken authentication",
            "Information disclosure",
        ],
        "search_function": [
            "SQL injection",
            "XSS reflection",
            "LDAP injection",
            "NoSQL injection",
        ],
        "payment_flow": [
            "Price manipulation",
            "Race condition",
            "Currency confusion",
            "Negative quantity",
        ],
    }
    
    def __init__(self):
        self.findings: List[Dict] = []
        self.technologies: List[str] = []
        self.insights: List[AIInsight] = []
        self.scan_history: List[Dict] = []
    
    # ==================== TECHNOLOGY DETECTION ====================
    
    def detect_technologies(self, response: str, headers: Dict = None) -> List[TechFingerprint]:
        """Detect technologies from response and headers"""
        detected = []
        combined = response
        
        if headers:
            combined += " ".join(f"{k}: {v}" for k, v in headers.items())
        
        for tech in self.TECH_FINGERPRINTS:
            for pattern in tech.patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.append(tech)
                    if tech.name not in self.technologies:
                        self.technologies.append(tech.name)
                    break
        
        return detected
    
    def get_tech_insights(self, techs: List[TechFingerprint]) -> List[AIInsight]:
        """Generate insights based on detected technologies"""
        insights = []
        
        for tech in techs:
            # Priority tests
            for test in tech.priority_tests[:3]:
                insights.append(AIInsight(
                    category="next_step",
                    message=f"Run {test} for {tech.name}",
                    confidence=0.9,
                    priority=4,
                    related_tool=test
                ))
            
            # Known vulnerabilities
            for vuln in tech.vulns[:2]:
                insights.append(AIInsight(
                    category="attack",
                    message=f"{tech.name}: Check for {vuln}",
                    confidence=0.7,
                    priority=3
                ))
        
        return insights
    
    # ==================== VULNERABILITY DETECTION ====================
    
    def analyze_response(self, response: str, url: str = "") -> List[Dict]:
        """Analyze response for vulnerabilities"""
        findings = []
        
        for category, patterns in self.VULN_PATTERNS.items():
            for pattern, name, severity in patterns:
                matches = re.findall(pattern, response, re.IGNORECASE)
                if matches:
                    finding = {
                        "title": name,
                        "category": category,
                        "severity": severity,
                        "evidence": matches[0] if isinstance(matches[0], str) else str(matches[0]),
                        "url": url,
                        "timestamp": datetime.now().isoformat()
                    }
                    findings.append(finding)
                    self.findings.append(finding)
        
        return findings
    
    def analyze_headers(self, headers: Dict) -> List[Dict]:
        """Analyze HTTP headers for security issues"""
        findings = []
        
        security_headers = {
            "Strict-Transport-Security": ("Missing HSTS header", "medium"),
            "X-Content-Type-Options": ("Missing X-Content-Type-Options", "low"),
            "X-Frame-Options": ("Missing X-Frame-Options (Clickjacking)", "medium"),
            "Content-Security-Policy": ("Missing CSP header", "medium"),
            "X-XSS-Protection": ("Missing X-XSS-Protection", "low"),
        }
        
        for header, (msg, severity) in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                findings.append({
                    "title": msg,
                    "category": "missing_header",
                    "severity": severity,
                    "recommendation": f"Add {header} header"
                })
        
        # Check for dangerous headers
        if headers.get("Server"):
            findings.append({
                "title": "Server Version Disclosure",
                "category": "info_disclosure",
                "severity": "info",
                "evidence": headers.get("Server")
            })
        
        if headers.get("X-Powered-By"):
            findings.append({
                "title": "Technology Disclosure",
                "category": "info_disclosure", 
                "severity": "low",
                "evidence": headers.get("X-Powered-By")
            })
        
        return findings
    
    # ==================== SMART RECOMMENDATIONS ====================
    
    def get_attack_vectors(self, endpoint_type: str) -> List[str]:
        """Get relevant attack vectors for endpoint type"""
        return self.ATTACK_VECTORS.get(endpoint_type, [])
    
    def classify_endpoint(self, url: str, method: str = "GET") -> str:
        """Classify endpoint type based on URL patterns"""
        url_lower = url.lower()
        
        if any(x in url_lower for x in ["login", "signin", "auth", "session"]):
            return "auth_endpoint"
        elif any(x in url_lower for x in ["upload", "file", "attachment", "media"]):
            return "file_upload"
        elif any(x in url_lower for x in ["api/", "/v1/", "/v2/", "graphql"]):
            return "api_endpoint"
        elif any(x in url_lower for x in ["search", "query", "find", "filter"]):
            return "search_function"
        elif any(x in url_lower for x in ["pay", "checkout", "cart", "order", "purchase"]):
            return "payment_flow"
        
        return "generic"
    
    def suggest_next_scans(self, current_findings: List[Dict], 
                          technologies: List[str]) -> List[AIInsight]:
        """Suggest next scans based on current findings"""
        suggestions = []
        
        # Based on findings severity
        critical_count = sum(1 for f in current_findings if f.get("severity") == "critical")
        high_count = sum(1 for f in current_findings if f.get("severity") == "high")
        
        if critical_count > 0:
            suggestions.append(AIInsight(
                category="warning",
                message=f"🚨 {critical_count} CRITICAL findings! Prioritize exploitation",
                confidence=1.0,
                priority=5
            ))
        
        if high_count > 0:
            suggestions.append(AIInsight(
                category="attack",
                message=f"Found {high_count} HIGH severity issues - manual testing recommended",
                confidence=0.9,
                priority=4
            ))
        
        # Based on technologies
        if "WordPress" in technologies:
            suggestions.append(AIInsight(
                category="next_step",
                message="WP detected: Run wpscan, check /wp-json/wp/v2/users",
                confidence=0.95,
                priority=4,
                related_tool="wpscan"
            ))
        
        if "Cloudflare" in technologies:
            suggestions.append(AIInsight(
                category="tip",
                message="WAF detected: Use encoding/case variation to bypass",
                confidence=0.8,
                priority=3
            ))
        
        if "GraphQL" in technologies:
            suggestions.append(AIInsight(
                category="attack",
                message="GraphQL: Check introspection query for schema",
                confidence=0.9,
                priority=4
            ))
        
        if not current_findings:
            suggestions.append(AIInsight(
                category="tip",
                message="No findings yet - try deeper fuzzing or authenticated testing",
                confidence=0.7,
                priority=2
            ))
        
        return suggestions
    
    # ==================== INTELLIGENT ANALYSIS ====================
    
    def analyze_scan_result(self, tool: str, result: Dict) -> Dict[str, Any]:
        """Perform intelligent analysis on scan result"""
        analysis = {
            "tool": tool,
            "success": result.get("success", False),
            "findings": [],
            "technologies": [],
            "insights": [],
            "risk_score": 0
        }
        
        # Extract and analyze output
        output = result.get("stdout", "") + result.get("body", "")
        headers = result.get("headers", {})
        
        # Detect technologies
        techs = self.detect_technologies(output, headers)
        analysis["technologies"] = [t.name for t in techs]
        analysis["insights"].extend(self.get_tech_insights(techs))
        
        # Analyze for vulnerabilities
        findings = self.analyze_response(output, result.get("url", ""))
        if headers:
            findings.extend(self.analyze_headers(headers))
        analysis["findings"] = findings
        
        # Calculate risk score
        for f in findings:
            sev = f.get("severity", "info")
            if sev == "critical":
                analysis["risk_score"] += 10
            elif sev == "high":
                analysis["risk_score"] += 5
            elif sev == "medium":
                analysis["risk_score"] += 2
            elif sev == "low":
                analysis["risk_score"] += 1
        
        # Generate insights
        analysis["insights"].extend(
            self.suggest_next_scans(findings, analysis["technologies"])
        )
        
        return analysis
    
    def generate_executive_summary(self) -> str:
        """Generate an executive summary of all findings"""
        total = len(self.findings)
        critical = sum(1 for f in self.findings if f.get("severity") == "critical")
        high = sum(1 for f in self.findings if f.get("severity") == "high")
        medium = sum(1 for f in self.findings if f.get("severity") == "medium")
        
        if critical > 0:
            risk_level = "CRITICAL"
        elif high > 0:
            risk_level = "HIGH"
        elif medium > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        summary = f"""
# SpectreWeb AI - Executive Summary
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Risk Assessment: {risk_level}

## Statistics
- Total Findings: {total}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Technologies: {', '.join(self.technologies) or 'None detected'}

## Top Priorities
"""
        # Add top 5 findings
        sorted_findings = sorted(
            self.findings,
            key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(x.get("severity", "info"), 0),
            reverse=True
        )
        
        for i, finding in enumerate(sorted_findings[:5], 1):
            summary += f"{i}. [{finding.get('severity', 'info').upper()}] {finding.get('title', 'Unknown')}\n"
        
        return summary
    
    def get_ai_hints(self, context: Dict) -> List[str]:
        """Get AI hints based on current context"""
        hints = []
        
        target = context.get("target", "")
        findings = context.get("findings", [])
        techs = context.get("technologies", [])
        
        # Domain-specific hints
        if ".gov" in target:
            hints.append("🏛️ Government target - extra caution required")
        if "api" in target.lower():
            hints.append("🔌 API endpoint - test for IDOR, rate limiting, auth bypass")
        
        # Technology-specific
        if "WordPress" in techs:
            hints.append("📝 WordPress: Try /wp-json/wp/v2/users, xmlrpc.php")
        if "Cloudflare" in techs:
            hints.append("🛡️ WAF active: Use tamper scripts and encoding")
        
        # Finding-based
        sql_findings = [f for f in findings if "sql" in f.get("category", "").lower()]
        if sql_findings:
            hints.append("💉 SQL errors found - manual SQLi testing recommended")
        
        return hints


# Singleton instance
analyzer = SmartAnalyzer()


# Convenience functions
def analyze_response(response: str, url: str = "") -> List[Dict]:
    return analyzer.analyze_response(response, url)

def detect_technologies(response: str, headers: Dict = None) -> List[str]:
    techs = analyzer.detect_technologies(response, headers)
    return [t.name for t in techs]

def get_attack_vectors(endpoint_type: str) -> List[str]:
    return analyzer.get_attack_vectors(endpoint_type)

def classify_endpoint(url: str, method: str = "GET") -> str:
    return analyzer.classify_endpoint(url, method)

def analyze_scan(tool: str, result: Dict) -> Dict[str, Any]:
    return analyzer.analyze_scan_result(tool, result)

def get_insights() -> List[AIInsight]:
    return analyzer.insights

def get_findings() -> List[Dict]:
    return analyzer.findings

def get_summary() -> str:
    return analyzer.generate_executive_summary()
