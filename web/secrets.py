#!/usr/bin/env python3
"""
SpectreWeb AI - Secret Scanner v1.0
AI-powered detection of hardcoded secrets, API keys, and sensitive data

Features:
- 50+ secret patterns (AWS, Google, GitHub, Stripe, etc.)
- Entropy analysis for unknown secrets
- Context-aware false positive reduction
- JS/HTML/Config file parsing
"""

import re
import math
import json
import base64
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
from collections import Counter


@dataclass
class SecretMatch:
    """Represents a found secret"""
    secret_type: str
    value: str
    line_number: int
    context: str
    confidence: float  # 0-1
    severity: str  # critical, high, medium, low
    recommendation: str


# ============================================================================
# SECRET PATTERNS DATABASE
# ============================================================================

SECRET_PATTERNS = {
    # ==================== CLOUD PROVIDERS ====================
    "aws_access_key": {
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": "critical",
        "description": "AWS Access Key ID",
        "recommendation": "Rotate AWS credentials immediately via IAM console"
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws[_\-]?secret[_\-]?(?:access)?[_\-]?key['\"\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "critical",
        "description": "AWS Secret Access Key",
        "recommendation": "Rotate AWS credentials and check CloudTrail for unauthorized access"
    },
    "aws_mws_key": {
        "pattern": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "severity": "high",
        "description": "AWS MWS Auth Token",
        "recommendation": "Regenerate MWS auth token"
    },
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "description": "Google Cloud API Key",
        "recommendation": "Restrict API key and regenerate if exposed"
    },
    "gcp_service_account": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "severity": "critical",
        "description": "GCP Service Account JSON",
        "recommendation": "Rotate service account key immediately"
    },
    "azure_client_secret": {
        "pattern": r"(?i)azure[_\-]?(?:client)?[_\-]?secret['\"\s:=]+['\"]?([A-Za-z0-9~.]{34,})['\"]?",
        "severity": "critical",
        "description": "Azure Client Secret",
        "recommendation": "Rotate Azure AD application credentials"
    },
    
    # ==================== VERSION CONTROL ====================
    "github_token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "description": "GitHub Personal Access Token",
        "recommendation": "Revoke token at github.com/settings/tokens"
    },
    "github_oauth": {
        "pattern": r"gho_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "description": "GitHub OAuth Token",
        "recommendation": "Revoke OAuth token immediately"
    },
    "github_app_token": {
        "pattern": r"(?:ghu|ghs)_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "description": "GitHub App Token",
        "recommendation": "Regenerate GitHub App token"
    },
    "gitlab_token": {
        "pattern": r"glpat-[A-Za-z0-9\-_]{20,}",
        "severity": "critical",
        "description": "GitLab Personal Access Token",
        "recommendation": "Revoke token in GitLab settings"
    },
    "bitbucket_token": {
        "pattern": r"(?i)bitbucket[_\-]?(?:api)?[_\-]?(?:key|token|secret)['\"\s:=]+['\"]?([A-Za-z0-9]{32,})['\"]?",
        "severity": "high",
        "description": "Bitbucket Token",
        "recommendation": "Regenerate Bitbucket app password"
    },
    
    # ==================== PAYMENT PROVIDERS ====================
    "stripe_api_key": {
        "pattern": r"sk_live_[A-Za-z0-9]{24,}",
        "severity": "critical",
        "description": "Stripe Live API Key",
        "recommendation": "Roll API key in Stripe Dashboard immediately!"
    },
    "stripe_test_key": {
        "pattern": r"sk_test_[A-Za-z0-9]{24,}",
        "severity": "medium",
        "description": "Stripe Test API Key",
        "recommendation": "Still sensitive - rotate if exposed"
    },
    "stripe_restricted_key": {
        "pattern": r"rk_live_[A-Za-z0-9]{24,}",
        "severity": "critical",
        "description": "Stripe Restricted Key",
        "recommendation": "Delete and recreate restricted key"
    },
    "paypal_braintree": {
        "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "severity": "critical",
        "description": "PayPal/Braintree Access Token",
        "recommendation": "Regenerate PayPal API credentials"
    },
    "square_access_token": {
        "pattern": r"sq0atp-[A-Za-z0-9\-_]{22,}",
        "severity": "critical",
        "description": "Square Access Token",
        "recommendation": "Rotate Square API credentials"
    },
    "square_oauth": {
        "pattern": r"sq0csp-[A-Za-z0-9\-_]{43,}",
        "severity": "critical",
        "description": "Square OAuth Secret",
        "recommendation": "Regenerate OAuth secret in Square Dashboard"
    },
    
    # ==================== COMMUNICATION ====================
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "severity": "high",
        "description": "Slack Token",
        "recommendation": "Revoke token in Slack App settings"
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
        "severity": "high",
        "description": "Slack Webhook URL",
        "recommendation": "Regenerate webhook URL"
    },
    "discord_token": {
        "pattern": r"(?:mfa\.)?[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
        "severity": "critical",
        "description": "Discord Bot Token",
        "recommendation": "Regenerate bot token in Discord Developer Portal"
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        "severity": "medium",
        "description": "Discord Webhook URL",
        "recommendation": "Delete and recreate webhook"
    },
    "telegram_token": {
        "pattern": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
        "severity": "high",
        "description": "Telegram Bot Token",
        "recommendation": "Revoke via @BotFather"
    },
    "twilio_api_key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": "high",
        "description": "Twilio API Key",
        "recommendation": "Delete API key in Twilio Console"
    },
    "sendgrid_api_key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": "high",
        "description": "SendGrid API Key",
        "recommendation": "Delete and recreate API key"
    },
    "mailgun_api_key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "description": "Mailgun API Key",
        "recommendation": "Rotate API key in Mailgun dashboard"
    },
    "mailchimp_api_key": {
        "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}",
        "severity": "high",
        "description": "Mailchimp API Key",
        "recommendation": "Regenerate API key"
    },
    
    # ==================== DATABASES ====================
    "mongodb_uri": {
        "pattern": r"mongodb(?:\+srv)?://[^\s\"'<>]+",
        "severity": "critical",
        "description": "MongoDB Connection String",
        "recommendation": "Rotate database credentials and restrict IP access"
    },
    "postgres_uri": {
        "pattern": r"postgres(?:ql)?://[^\s\"'<>]+",
        "severity": "critical",
        "description": "PostgreSQL Connection String",
        "recommendation": "Change database password immediately"
    },
    "mysql_uri": {
        "pattern": r"mysql://[^\s\"'<>]+",
        "severity": "critical",
        "description": "MySQL Connection String",
        "recommendation": "Rotate database credentials"
    },
    "redis_uri": {
        "pattern": r"redis://[^\s\"'<>]+",
        "severity": "high",
        "description": "Redis Connection String",
        "recommendation": "Update Redis AUTH password"
    },
    
    # ==================== AUTH & JWT ====================
    "jwt_secret": {
        "pattern": r"(?i)(?:jwt|token)[_\-]?secret['\"\s:=]+['\"]?([A-Za-z0-9+/=]{20,})['\"]?",
        "severity": "critical",
        "description": "JWT Secret Key",
        "recommendation": "Rotate JWT secret and invalidate all tokens"
    },
    "oauth_client_secret": {
        "pattern": r"(?i)(?:client|oauth)[_\-]?secret['\"\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?",
        "severity": "high",
        "description": "OAuth Client Secret",
        "recommendation": "Regenerate OAuth credentials"
    },
    "auth0_client_secret": {
        "pattern": r"(?i)auth0[_\-]?(?:client)?[_\-]?secret['\"\s:=]+['\"]?([A-Za-z0-9\-_]{40,})['\"]?",
        "severity": "critical",
        "description": "Auth0 Client Secret",
        "recommendation": "Rotate Auth0 credentials"
    },
    
    # ==================== API KEYS (GENERIC) ====================
    "api_key_generic": {
        "pattern": r"(?i)(?:api|access)[_\-]?key['\"\s:=]+['\"]?([A-Za-z0-9\-_]{20,64})['\"]?",
        "severity": "medium",
        "description": "Generic API Key",
        "recommendation": "Identify service and rotate key"
    },
    "bearer_token": {
        "pattern": r"(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})",
        "severity": "high",
        "description": "Bearer Token",
        "recommendation": "Invalidate token if exposed"
    },
    "basic_auth": {
        "pattern": r"(?i)basic\s+([A-Za-z0-9+/=]{10,})",
        "severity": "high",
        "description": "Basic Auth Credentials",
        "recommendation": "Change password immediately"
    },
    
    # ==================== PRIVATE KEYS ====================
    "private_key_rsa": {
        "pattern": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "RSA Private Key",
        "recommendation": "Revoke and regenerate key pair!"
    },
    "private_key_ec": {
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "critical",
        "description": "EC Private Key",
        "recommendation": "Revoke and regenerate key pair!"
    },
    "private_key_openssh": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "critical",
        "description": "OpenSSH Private Key",
        "recommendation": "Remove from server and regenerate!"
    },
    "private_key_pgp": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "critical",
        "description": "PGP Private Key",
        "recommendation": "Revoke PGP key immediately"
    },
    
    # ==================== CRYPTO ====================
    "bitcoin_private_key": {
        "pattern": r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}",
        "severity": "critical",
        "description": "Bitcoin Private Key (WIF)",
        "recommendation": "Move funds immediately if this is real!"
    },
    "ethereum_private_key": {
        "pattern": r"(?i)(?:0x)?[a-fA-F0-9]{64}(?=\s|$|['\"])",
        "severity": "critical",
        "description": "Possible Ethereum Private Key",
        "recommendation": "Transfer funds if this is a real key!"
    },
    
    # ==================== PASSWORDS ====================
    "password_in_url": {
        "pattern": r"(?i)(?:password|passwd|pwd)[=:][^\s&\"'<>]{3,}",
        "severity": "high",
        "description": "Password in URL/Config",
        "recommendation": "Change password and use environment variables"
    },
    "hardcoded_password": {
        "pattern": r"(?i)(?:password|passwd|pwd|secret|token)['\"\s]*[:=]['\"\s]*['\"]([^'\"]{8,})['\"]",
        "severity": "high",
        "description": "Hardcoded Password",
        "recommendation": "Use environment variables or secret manager"
    },
    
    # ==================== OTHER SERVICES ====================
    "firebase_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "description": "Firebase API Key",
        "recommendation": "Restrict key to specific APIs"
    },
    "firebase_url": {
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "severity": "medium",
        "description": "Firebase Database URL",
        "recommendation": "Check database rules for security"
    },
    "heroku_api_key": {
        "pattern": r"(?i)heroku[_\-]?api[_\-]?key['\"\s:=]+['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
        "severity": "high",
        "description": "Heroku API Key",
        "recommendation": "Regenerate Heroku API key"
    },
    "shopify_token": {
        "pattern": r"shpat_[a-fA-F0-9]{32}",
        "severity": "high",
        "description": "Shopify Access Token",
        "recommendation": "Rotate Shopify API credentials"
    },
    "shopify_shared_secret": {
        "pattern": r"shpss_[a-fA-F0-9]{32}",
        "severity": "high",
        "description": "Shopify Shared Secret",
        "recommendation": "Regenerate shared secret"
    },
    "algolia_api_key": {
        "pattern": r"(?i)algolia[_\-]?(?:api)?[_\-]?key['\"\s:=]+['\"]?([a-zA-Z0-9]{32})['\"]?",
        "severity": "medium",
        "description": "Algolia API Key",
        "recommendation": "Check if it's admin key and rotate"
    },
    "npm_token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "severity": "high",
        "description": "NPM Access Token",
        "recommendation": "Revoke token at npmjs.com"
    },
    "pypi_token": {
        "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}",
        "severity": "high",
        "description": "PyPI API Token",
        "recommendation": "Delete token at pypi.org"
    },
}


# ============================================================================
# ENTROPY ANALYSIS
# ============================================================================

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0
    
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy -= p_x * math.log2(p_x)
    
    return entropy


def is_high_entropy(data: str, threshold: float = 4.5) -> bool:
    """Check if string has high entropy (likely random/secret)"""
    if len(data) < 8:
        return False
    return calculate_entropy(data) > threshold


# ============================================================================
# FALSE POSITIVE REDUCTION
# ============================================================================

# Common false positive patterns
FALSE_POSITIVE_PATTERNS = [
    r"example\.com",
    r"localhost",
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
    r"your[_\-]?api[_\-]?key",
    r"xxx+",
    r"placeholder",
    r"changeme",
    r"todo",
    r"fixme",
    r"\$\{",  # Template variables
    r"\{\{",  # Template variables
    r"<[A-Z_]+>",  # Placeholder patterns
    r"INSERT[_\-]?YOUR",
    r"REPLACE[_\-]?WITH",
    # Additional false positives
    r"^[a-f0-9]+$",  # Pure hex without context might be hash
    r"^[0-9]+$",  # Pure numbers
    r"undefined",
    r"null",
    r"none",
    r"process\.env",
    r"os\.environ",
    r"getenv",
    r"config\[",
    r"settings\.",
    r"require\(",
    r"import\s+",
    r"from\s+",
    r"base64",  # Base64 library reference
    r"sha256",
    r"md5",
    r"encrypt",
    r"decrypt",
    r"encode",
    r"decode",
    r"xxxxxxxxx",
    r"your[_\-]?token",
    r"add[_\-]?your",
    r"put[_\-]?your",
    r"enter[_\-]?your",
    r"sk[_\-]?test[_\-]",  # Test mode keys
    r"pk[_\-]?test[_\-]",
    r"_test[_\-]?key",
    r"sandbox",
    r"development",
    r"staging",
]

# Patterns that require manual verification (high false positive rate)
NEEDS_VERIFICATION_PATTERNS = [
    "api_key_generic",
    "bearer_token",
    "basic_auth",
    "hardcoded_password",
    "high_entropy_secret",
    "ethereum_private_key",
]


def is_false_positive(value: str) -> bool:
    """Check if a match is likely a false positive"""
    value_lower = value.lower()
    
    # Check against false positive patterns
    for pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, value_lower):
            return True
    
    # Check for repeated characters (aaaa, 1111, etc.)
    if len(value) > 5 and len(set(value)) < len(value) * 0.3:
        return True
    
    # Check for common test/example values
    test_values = ["test", "demo", "sample", "fake", "dummy", "mock", "example", "foo", "bar", "baz"]
    if any(tv in value_lower for tv in test_values):
        return True
    
    # Check for sequential patterns (1234, abcd, etc.)
    if is_sequential(value):
        return True
    
    # Check for keyboard patterns
    keyboard_patterns = ["qwerty", "asdf", "zxcv", "1234", "4321", "abcd", "dcba"]
    if any(kp in value_lower for kp in keyboard_patterns):
        return True
    
    return False


def is_sequential(s: str) -> bool:
    """Check if string is sequential (1234, abcd, etc.)"""
    if len(s) < 4:
        return False
    
    # Check ascending
    is_asc = all(ord(s[i]) + 1 == ord(s[i+1]) for i in range(len(s)-1))
    # Check descending
    is_desc = all(ord(s[i]) - 1 == ord(s[i+1]) for i in range(len(s)-1))
    
    return is_asc or is_desc


def needs_manual_verification(pattern_name: str, value: str, context: str) -> Tuple[bool, str]:
    """
    Determine if a finding needs manual verification.
    Returns (needs_verification, reason)
    """
    reasons = []
    
    # High false positive patterns always need verification
    if pattern_name in NEEDS_VERIFICATION_PATTERNS:
        reasons.append("Pattern có tỷ lệ false positive cao")
    
    # Check if in test/config context
    context_lower = context.lower()
    if any(kw in context_lower for kw in ["test", "spec", "mock", "example", "demo", "fixture"]):
        reasons.append("Có thể là test data")
    
    # Check if in comments
    if "//" in context or "/*" in context or "#" in context[:50]:
        reasons.append("Có thể trong comment")
    
    # Check for documentation patterns
    if any(kw in context_lower for kw in ["documentation", "readme", "example usage", "how to use"]):
        reasons.append("Có thể là documentation example")
    
    # Environment variable reference
    if "env" in context_lower or "process." in context_lower or "os." in context_lower:
        reasons.append("Có thể là environment variable reference")
    
    if reasons:
        return True, "; ".join(reasons)
    
    return False, ""


# ============================================================================
# MAIN SCANNER
# ============================================================================

class SecretScanner:
    """AI-powered secret scanner"""
    
    def __init__(self):
        self.patterns = SECRET_PATTERNS
        self.findings: List[SecretMatch] = []
    
    def scan_text(self, content: str, source: str = "unknown") -> List[Dict]:
        """
        Scan text content for secrets.
        
        Args:
            content: Text content to scan
            source: Source identifier (URL, filename, etc.)
        
        Returns:
            List of found secrets with metadata
        """
        findings = []
        lines = content.split('\n')
        
        for pattern_name, pattern_info in self.patterns.items():
            try:
                regex = re.compile(pattern_info["pattern"], re.MULTILINE)
                
                for match in regex.finditer(content):
                    # Get matched value
                    value = match.group(1) if match.lastindex else match.group(0)
                    
                    # Skip false positives
                    if is_false_positive(value):
                        continue
                    
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Get context (surrounding lines)
                    start_line = max(0, line_num - 2)
                    end_line = min(len(lines), line_num + 2)
                    context = '\n'.join(lines[start_line:end_line])
                    
                    # Calculate confidence based on entropy and pattern specificity
                    entropy = calculate_entropy(value)
                    confidence = min(1.0, 0.5 + (entropy / 10))
                    
                    if pattern_info["severity"] == "critical":
                        confidence = min(1.0, confidence + 0.2)
                    
                    # Check if needs manual verification
                    needs_verify, verify_reason = needs_manual_verification(pattern_name, value, context)
                    
                    # Adjust confidence if needs verification
                    if needs_verify:
                        confidence = max(0.3, confidence - 0.2)
                    
                    finding = {
                        "type": pattern_name,
                        "description": pattern_info["description"],
                        "value": self._mask_secret(value),
                        "raw_value": value,  # For verification
                        "line": line_num,
                        "context": context,
                        "confidence": round(confidence, 2),
                        "severity": pattern_info["severity"],
                        "recommendation": pattern_info["recommendation"],
                        "source": source,
                        "entropy": round(entropy, 2),
                        "needs_verification": needs_verify,
                        "verification_reason": verify_reason if needs_verify else None,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    findings.append(finding)
                    
            except re.error:
                continue
        
        # Also check for high entropy strings that might be secrets
        high_entropy_findings = self._scan_high_entropy(content, source, lines)
        findings.extend(high_entropy_findings)
        
        # Deduplicate
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["type"], f["raw_value"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        
        # Remove raw_value from output
        for f in unique_findings:
            del f["raw_value"]
        
        self.findings.extend(unique_findings)
        return unique_findings
    
    def _mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """Mask a secret, showing only first few chars"""
        if len(secret) <= visible_chars * 2:
            return "*" * len(secret)
        return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]
    
    def _scan_high_entropy(self, content: str, source: str, lines: List[str]) -> List[Dict]:
        """Scan for high entropy strings that might be secrets"""
        findings = []
        
        # Look for quoted strings with high entropy
        quoted_pattern = r"['\"]([A-Za-z0-9+/=\-_]{16,})['\"]"
        
        for match in re.finditer(quoted_pattern, content):
            value = match.group(1)
            
            # Skip if already matched by specific pattern
            if is_false_positive(value):
                continue
            
            if is_high_entropy(value, threshold=4.5):
                line_num = content[:match.start()].count('\n') + 1
                
                # Get surrounding context to determine what this might be
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 2)
                context = '\n'.join(lines[start_line:end_line])
                
                # Try to identify based on context
                context_lower = context.lower()
                if any(kw in context_lower for kw in ["key", "secret", "token", "password", "api", "auth", "credential"]):
                    findings.append({
                        "type": "high_entropy_secret",
                        "description": "High Entropy String (Potential Secret)",
                        "value": self._mask_secret(value),
                        "raw_value": value,
                        "line": line_num,
                        "context": context,
                        "confidence": 0.6,
                        "severity": "medium",
                        "recommendation": "Verify if this is a secret and rotate if exposed",
                        "source": source,
                        "entropy": round(calculate_entropy(value), 2),
                        "timestamp": datetime.now().isoformat()
                    })
        
        return findings
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan URL and query parameters for secrets"""
        findings = []
        
        # Check URL itself
        url_findings = self.scan_text(url, source=url)
        findings.extend(url_findings)
        
        # Parse and check query parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        sensitive_params = ["key", "token", "secret", "password", "apikey", "api_key", "access_token", "auth"]
        
        for param, values in params.items():
            param_lower = param.lower()
            if any(s in param_lower for s in sensitive_params):
                for value in values:
                    if len(value) > 8 and not is_false_positive(value):
                        findings.append({
                            "type": "secret_in_url",
                            "description": f"Secret in URL parameter: {param}",
                            "value": self._mask_secret(value),
                            "line": 0,
                            "context": url,
                            "confidence": 0.8,
                            "severity": "high",
                            "recommendation": "Never pass secrets in URLs - use headers or POST body",
                            "source": url,
                            "entropy": round(calculate_entropy(value), 2),
                            "timestamp": datetime.now().isoformat()
                        })
        
        return {
            "success": True,
            "url": url,
            "findings": findings,
            "total": len(findings)
        }
    
    def scan_js_files(self, js_content: str, source: str = "javascript") -> Dict[str, Any]:
        """
        Specialized scan for JavaScript files.
        Looks for secrets in common JS patterns.
        """
        findings = self.scan_text(js_content, source)
        
        # Additional JS-specific patterns
        js_patterns = [
            # Config objects
            (r"(?:config|settings|env)\s*[=:]\s*\{([^}]+)\}", "Configuration Object"),
            # Environment variable references
            (r"process\.env\.([A-Z_]+)", "Environment Variable Reference"),
            # Headers
            (r"['\"](?:Authorization|X-Api-Key|X-Auth-Token)['\"]:\s*['\"]([^'\"]+)['\"]", "Auth Header"),
        ]
        
        for pattern, desc in js_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE | re.MULTILINE):
                value = match.group(1) if match.lastindex else match.group(0)
                if len(value) > 100:
                    continue  # Skip large matches
                
                # Scan the matched content for secrets
                sub_findings = self.scan_text(value, f"{source} - {desc}")
                for f in sub_findings:
                    if f not in findings:
                        findings.append(f)
        
        return {
            "success": True,
            "source": source,
            "findings": findings,
            "total": len(findings),
            "summary": self._generate_summary(findings)
        }
    
    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate summary statistics"""
        summary = {
            "total": len(findings),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_type": {},
            "high_confidence": 0
        }
        
        for f in findings:
            sev = f.get("severity", "medium")
            if sev in summary["by_severity"]:
                summary["by_severity"][sev] += 1
            
            ftype = f.get("type", "unknown")
            summary["by_type"][ftype] = summary["by_type"].get(ftype, 0) + 1
            
            if f.get("confidence", 0) >= 0.8:
                summary["high_confidence"] += 1
        
        return summary
    
    def get_all_findings(self) -> List[Dict]:
        """Get all findings from this scanner instance"""
        return self.findings
    
    def clear_findings(self):
        """Clear all findings"""
        self.findings = []


# Singleton instance
scanner = SecretScanner()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def scan_for_secrets(content: str, source: str = "unknown") -> Dict[str, Any]:
    """Scan content for secrets"""
    findings = scanner.scan_text(content, source)
    return {
        "success": True,
        "source": source,
        "findings": findings,
        "total": len(findings),
        "summary": scanner._generate_summary(findings)
    }


def scan_js(js_content: str, source: str = "javascript") -> Dict[str, Any]:
    """Scan JavaScript for secrets"""
    return scanner.scan_js_files(js_content, source)


def scan_url_for_secrets(url: str) -> Dict[str, Any]:
    """Scan URL for secrets in parameters"""
    return scanner.scan_url(url)


def get_secret_patterns() -> Dict[str, Dict]:
    """Get all secret patterns for reference"""
    return {name: {k: v for k, v in info.items() if k != "pattern"} 
            for name, info in SECRET_PATTERNS.items()}


def calculate_string_entropy(text: str) -> Dict[str, Any]:
    """Calculate entropy of a string"""
    entropy = calculate_entropy(text)
    return {
        "text": text[:50] + "..." if len(text) > 50 else text,
        "length": len(text),
        "entropy": round(entropy, 3),
        "is_high_entropy": is_high_entropy(text),
        "likely_secret": is_high_entropy(text) and len(text) >= 16
    }
