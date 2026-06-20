#!/usr/bin/env python3
"""
SpectreWeb AI - Deep Secret Hunting Engine v1.0

A comprehensive multi-stage secret scanner that:
- Stage 0: Collects data sources (historical URLs, JS files, endpoints)
- Stage 1: Static code scanning with context analysis
- Stage 2: JavaScript-focused deep scanning
- Stage 3: Runtime response scanning
- Stage 4: Correlation analysis and deduplication
- Stage 5: Validation and exploitation suggestions

This is the "bloodhound" for secrets - thorough, precise, and actionable.
"""

import sys
import re
import json
import time
import hashlib
import threading
import concurrent.futures
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse, urljoin
from collections import defaultdict
from enum import Enum

from .client import make_request
from .secrets import (
    SecretScanner, SECRET_PATTERNS, 
    calculate_entropy, is_high_entropy, is_false_positive,
    scan_for_secrets, scan_js, scan_url_for_secrets
)
from .extractor import extract_js_files, extract_links
from .advanced_scanner import extract_js_endpoints, scan_js_files


# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================

class SecretCategory(Enum):
    """Categories of secrets for prioritization"""
    CLOUD = "cloud_credentials"  # AWS, GCP, Azure
    PAYMENT = "payment_keys"     # Stripe, PayPal, Square
    SCM = "source_control"       # GitHub, GitLab, Bitbucket
    DATABASE = "database_creds"  # Connection strings
    API = "api_keys"             # Generic API keys
    AUTH = "auth_tokens"         # JWT, OAuth, Bearer
    CRYPTO = "crypto_keys"       # Private keys, Bitcoin
    INTERNAL = "internal"        # Internal IPs, paths
    OTHER = "other"


class SecretRisk(Enum):
    """Risk level based on secret type and context"""
    CRITICAL = "critical"   # Production keys, full access
    HIGH = "high"           # Limited production access
    MEDIUM = "medium"       # Test/staging or limited scope
    LOW = "low"             # Likely false positive or minimal impact
    INFO = "info"           # Informational only


@dataclass
class EnrichedSecret:
    """A secret enriched with context and validation"""
    secret_id: str
    category: SecretCategory
    risk: SecretRisk
    secret_type: str
    value_masked: str
    value_hash: str  # For dedup without storing raw value
    source: str
    source_type: str  # "js", "html", "api_response", "url", "config"
    line_number: int
    context: str
    confidence: float
    entropy: float
    validated: bool = False
    validation_result: str = ""
    exploitation_hints: List[str] = field(default_factory=list)
    related_secrets: List[str] = field(default_factory=list)  # IDs of related secrets
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["risk"] = self.risk.value
        return d


@dataclass
class HuntingReport:
    """Complete report from a secret hunting session"""
    target: str
    started_at: str
    completed_at: str = ""
    stages_completed: List[str] = field(default_factory=list)
    sources_scanned: Dict[str, int] = field(default_factory=dict)
    secrets_found: List[EnrichedSecret] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    exploitation_paths: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# ============================================================================
# SECRET CATEGORIZATION
# ============================================================================

SECRET_CATEGORY_MAP = {
    # Cloud
    "aws_access_key": SecretCategory.CLOUD,
    "aws_secret_key": SecretCategory.CLOUD,
    "aws_mws_key": SecretCategory.CLOUD,
    "gcp_api_key": SecretCategory.CLOUD,
    "gcp_service_account": SecretCategory.CLOUD,
    "azure_client_secret": SecretCategory.CLOUD,
    
    # Payment
    "stripe_api_key": SecretCategory.PAYMENT,
    "stripe_test_key": SecretCategory.PAYMENT,
    "stripe_restricted_key": SecretCategory.PAYMENT,
    "paypal_braintree": SecretCategory.PAYMENT,
    "square_access_token": SecretCategory.PAYMENT,
    "square_oauth": SecretCategory.PAYMENT,
    
    # SCM
    "github_token": SecretCategory.SCM,
    "github_oauth": SecretCategory.SCM,
    "github_app_token": SecretCategory.SCM,
    "gitlab_token": SecretCategory.SCM,
    "bitbucket_token": SecretCategory.SCM,
    "npm_token": SecretCategory.SCM,
    "pypi_token": SecretCategory.SCM,
    
    # Database
    "mongodb_uri": SecretCategory.DATABASE,
    "postgres_uri": SecretCategory.DATABASE,
    "mysql_uri": SecretCategory.DATABASE,
    "redis_uri": SecretCategory.DATABASE,
    
    # Auth
    "jwt_secret": SecretCategory.AUTH,
    "oauth_client_secret": SecretCategory.AUTH,
    "auth0_client_secret": SecretCategory.AUTH,
    "bearer_token": SecretCategory.AUTH,
    "basic_auth": SecretCategory.AUTH,
    
    # Crypto
    "private_key_rsa": SecretCategory.CRYPTO,
    "private_key_ec": SecretCategory.CRYPTO,
    "private_key_openssh": SecretCategory.CRYPTO,
    "private_key_pgp": SecretCategory.CRYPTO,
    "bitcoin_private_key": SecretCategory.CRYPTO,
    "ethereum_private_key": SecretCategory.CRYPTO,
    
    # API
    "api_key_generic": SecretCategory.API,
    "slack_token": SecretCategory.API,
    "slack_webhook": SecretCategory.API,
    "discord_token": SecretCategory.API,
    "discord_webhook": SecretCategory.API,
    "telegram_token": SecretCategory.API,
    "twilio_api_key": SecretCategory.API,
    "sendgrid_api_key": SecretCategory.API,
    "mailgun_api_key": SecretCategory.API,
    "mailchimp_api_key": SecretCategory.API,
    "firebase_api_key": SecretCategory.API,
    "heroku_api_key": SecretCategory.API,
    "shopify_token": SecretCategory.API,
    "algolia_api_key": SecretCategory.API,
    
    # Internal
    "internal_ip": SecretCategory.INTERNAL,
    "password_in_url": SecretCategory.OTHER,
    "hardcoded_password": SecretCategory.OTHER,
}


def categorize_secret(secret_type: str) -> SecretCategory:
    """Get category for a secret type"""
    return SECRET_CATEGORY_MAP.get(secret_type, SecretCategory.OTHER)


def calculate_risk(
    secret_type: str, 
    category: SecretCategory, 
    confidence: float,
    context: str
) -> SecretRisk:
    """
    Calculate risk level based on secret type, category, and context.
    """
    context_lower = context.lower()
    
    # Check for test/dev indicators
    is_test = any(kw in context_lower for kw in ["test", "dev", "staging", "sandbox", "demo", "example"])
    
    # High-risk categories
    if category in [SecretCategory.CLOUD, SecretCategory.PAYMENT, SecretCategory.CRYPTO]:
        if is_test:
            return SecretRisk.MEDIUM
        if confidence >= 0.8:
            return SecretRisk.CRITICAL
        return SecretRisk.HIGH
    
    # Medium-risk categories
    if category in [SecretCategory.DATABASE, SecretCategory.AUTH, SecretCategory.SCM]:
        if is_test:
            return SecretRisk.LOW
        if confidence >= 0.8:
            return SecretRisk.HIGH
        return SecretRisk.MEDIUM
    
    # Lower risk
    if category == SecretCategory.INTERNAL:
        return SecretRisk.INFO
    
    # Default based on confidence
    if confidence >= 0.9:
        return SecretRisk.HIGH
    if confidence >= 0.7:
        return SecretRisk.MEDIUM
    return SecretRisk.LOW


# ============================================================================
# EXPLOITATION HINTS
# ============================================================================

EXPLOITATION_HINTS = {
    SecretCategory.CLOUD: {
        "aws": [
            "Use AWS CLI: aws configure (set key/secret)",
            "List S3 buckets: aws s3 ls",
            "Check IAM permissions: aws iam get-user",
            "Enumerate services: aws sts get-caller-identity",
            "Look for EC2 instances: aws ec2 describe-instances",
        ],
        "gcp": [
            "Activate service account: gcloud auth activate-service-account --key-file=key.json",
            "List projects: gcloud projects list",
            "Check compute instances: gcloud compute instances list",
        ],
        "azure": [
            "Login with service principal: az login --service-principal",
            "List subscriptions: az account list",
            "Enumerate resources: az resource list",
        ],
    },
    SecretCategory.PAYMENT: {
        "stripe": [
            "Test key validity: curl https://api.stripe.com/v1/charges -u sk_xxx:",
            "List customers: curl https://api.stripe.com/v1/customers -u sk_xxx:",
            "Check balance: curl https://api.stripe.com/v1/balance -u sk_xxx:",
        ],
    },
    SecretCategory.SCM: {
        "github": [
            "Check token scopes: curl -H 'Authorization: token xxx' https://api.github.com/user",
            "List repos: curl -H 'Authorization: token xxx' https://api.github.com/user/repos",
            "Check org access: curl -H 'Authorization: token xxx' https://api.github.com/user/orgs",
        ],
        "gitlab": [
            "Validate token: curl --header 'PRIVATE-TOKEN: xxx' https://gitlab.com/api/v4/user",
        ],
    },
    SecretCategory.DATABASE: {
        "mongodb": [
            "Connect: mongo 'mongodb://user:pass@host:port/db'",
            "List databases: show dbs",
        ],
        "postgres": [
            "Connect: psql 'postgresql://user:pass@host:port/db'",
            "List tables: \\dt",
        ],
    },
    SecretCategory.AUTH: {
        "jwt": [
            "Decode JWT at jwt.io",
            "Try 'none' algorithm attack",
            "Brute force weak secrets with hashcat",
        ],
    },
}


def get_exploitation_hints(category: SecretCategory, secret_type: str) -> List[str]:
    """Get exploitation hints for a secret"""
    hints = []
    
    category_hints = EXPLOITATION_HINTS.get(category, {})
    
    # Try to match specific type
    for key, hint_list in category_hints.items():
        if key in secret_type.lower():
            hints.extend(hint_list)
            break
    
    # Generic hints if no specific match
    if not hints:
        for key, hint_list in category_hints.items():
            hints.extend(hint_list[:2])  # Take top 2 from each
            break
    
    return hints[:5]  # Limit to 5 hints


# ============================================================================
# DEEP SECRET HUNTER
# ============================================================================

class DeepSecretHunter:
    """
    Multi-stage secret hunting engine.
    
    Usage:
        hunter = DeepSecretHunter("example.com")
        report = hunter.hunt()  # Run all stages
        
        # Or run specific stages
        hunter.collect_sources()
        hunter.scan_javascript()
        hunter.scan_responses()
        report = hunter.get_report()
    """
    
    def __init__(self, target_domain: str, max_urls: int = 100, max_js: int = 50):
        self.target_domain = target_domain
        self.max_urls = max_urls
        self.max_js = max_js
        
        self.report = HuntingReport(
            target=target_domain,
            started_at=datetime.now().isoformat()
        )
        
        self.scanner = SecretScanner()
        self.lock = threading.Lock()
        
        # Data stores
        self.urls_to_scan: Set[str] = set()
        self.js_urls: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.secrets_by_hash: Dict[str, EnrichedSecret] = {}  # For deduplication
        
    def _log(self, message: str):
        """Thread-safe logging"""
        print(f"[SECRETS:{self.target_domain[:15]}] {message}")
        sys.stdout.flush()
    
    def hunt(self, stages: List[str] = None, local_paths: List[str] = None) -> Dict[str, Any]:
        """
        Run the complete hunting flow.
        
        Args:
            stages: Specific stages to run (default: all)
                    Options: "collect", "static", "javascript", "runtime", "correlate"
            local_paths: List of local file/directory paths for static scanning
        """
        stages = stages or ["collect", "javascript", "runtime", "correlate"]
        
        self._log(f"Starting deep secret hunt on {self.target_domain}")
        
        if "collect" in stages:
            self._stage_0_collect_sources()
        
        if "static" in stages and local_paths:
            self._stage_1_scan_static(local_paths)
        
        if "javascript" in stages:
            self._stage_2_scan_javascript()
        
        if "runtime" in stages:
            self._stage_3_scan_runtime()
        
        if "correlate" in stages:
            self._stage_4_correlate()
        
        self._stage_5_generate_recommendations()
        
        self.report.completed_at = datetime.now().isoformat()
        return self.get_report()
    
    def _stage_0_collect_sources(self):
        """Stage 0: Collect data sources"""
        self._log("Stage 0: Collecting data sources...")
        self.report.stages_completed.append("collect")
        
        base_url = f"https://{self.target_domain}"
        
        # Get homepage and extract links/JS
        try:
            resp = make_request(base_url, timeout=30)
            if resp.get("success"):
                body = resp.get("body", "")
                
                # Extract JS files
                js_files = extract_js_files(body, base_url)
                self.js_urls.update(js_files[:self.max_js])
                
                # Extract links for runtime scanning
                links = extract_links(body, base_url)
                self.urls_to_scan.update(links[:self.max_urls])
                
                self._log(f"Found {len(self.js_urls)} JS files, {len(self.urls_to_scan)} URLs")
        except Exception as e:
            self._log(f"Error fetching homepage: {e}")
        
        # Try common JS paths
        common_js_paths = [
            "/main.js", "/app.js", "/bundle.js", "/vendor.js",
            "/static/js/main.js", "/assets/js/app.js",
            "/dist/main.js", "/build/bundle.js",
            "/_next/static/chunks/main.js",
            "/js/config.js", "/js/env.js",
        ]
        
        for path in common_js_paths:
            self.js_urls.add(urljoin(base_url, path))
        
        # Try common config/sensitive paths
        sensitive_paths = [
            "/.env", "/config.js", "/env.js", "/settings.js",
            "/api/config", "/api/settings", "/.git/config",
            "/package.json", "/composer.json",
            "/debug", "/info", "/status", "/health",
            "/swagger.json", "/openapi.json", "/api-docs",
        ]
        
        for path in sensitive_paths:
            self.urls_to_scan.add(urljoin(base_url, path))
        
        self.report.sources_scanned["js_files_found"] = len(self.js_urls)
        self.report.sources_scanned["urls_found"] = len(self.urls_to_scan)
    
    def _stage_1_scan_static(self, paths: List[str]):
        """
        Stage 1: Scan local files/directories for secrets.
        
        Supports:
        - Individual files
        - Directories (recursive scan)
        - Common config/code file extensions
        """
        import os
        import glob
        from config.settings import MAX_FILE_SIZE
        
        self._log(f"Stage 1: Scanning {len(paths)} local paths for secrets...")
        self.report.stages_completed.append("static")
        
        # File extensions to scan
        code_extensions = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
            ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt", ".scala"
        }
        config_extensions = {
            ".json", ".yml", ".yaml", ".xml", ".toml", ".ini", ".cfg", ".conf",
            ".env", ".properties", ".pem", ".key", ".crt"
        }
        all_extensions = code_extensions | config_extensions
        
        files_to_scan = []
        
        for path in paths:
            if os.path.isfile(path):
                files_to_scan.append(path)
            elif os.path.isdir(path):
                # Recursive file discovery
                for ext in all_extensions:
                    pattern = os.path.join(path, "**", f"*{ext}")
                    files_to_scan.extend(glob.glob(pattern, recursive=True))
                # Also check for .env* files without extension matching
                env_pattern = os.path.join(path, "**", ".env*")
                files_to_scan.extend(glob.glob(env_pattern, recursive=True))
        
        # Dedupe and limit
        files_to_scan = list(set(files_to_scan))[:500]  # Limit to 500 files
        
        self._log(f"Found {len(files_to_scan)} files to scan")
        
        scanned = 0
        secrets_found = 0
        
        for file_path in files_to_scan:
            try:
                # Skip large files (> MAX_FILE_SIZE)
                if os.path.getsize(file_path) > MAX_FILE_SIZE:
                    continue
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                if len(content) < 10:
                    continue
                
                # Scan content
                result = scan_for_secrets(content, source=f"file://{file_path}")
                findings = result.get("findings", [])
                
                for finding in findings:
                    enriched = self._enrich_finding(finding, "static_file", file_path)
                    if enriched:
                        secrets_found += 1
                
                scanned += 1
                
                if scanned % 50 == 0:
                    self._log(f"Static Progress: {scanned}/{len(files_to_scan)} - Secrets: {secrets_found}")
                    
            except Exception as e:
                continue
        
        self.report.sources_scanned["static_files_scanned"] = scanned
        self._log(f"Static scanning complete: {secrets_found} secrets from {scanned} files")
    
    def _stage_2_scan_javascript(self):
        """Stage 2: Deep JavaScript scanning"""
        self._log(f"Stage 2: Scanning {len(self.js_urls)} JavaScript files...")
        self.report.stages_completed.append("javascript")
        
        scanned = 0
        secrets_found = 0
        
        def scan_single_js(url: str) -> List[Dict]:
            """Scan a single JS file"""
            try:
                resp = make_request(url, timeout=15)
                if not resp.get("success"):
                    return []
                
                body = resp.get("body", "")
                if len(body) < 50:  # Skip empty/small files
                    return []
                
                # Use specialized JS scanner
                result = scan_js(body, source=url)
                return result.get("findings", [])
            except Exception:
                return []
        
        # Concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(scan_single_js, url): url for url in list(self.js_urls)[:self.max_js]}
            
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                with self.lock:
                    scanned += 1
                    if scanned % 10 == 0:
                        self._log(f"JS Progress: {scanned}/{len(self.js_urls)} - Secrets: {secrets_found}")
                
                try:
                    findings = future.result()
                    for finding in findings:
                        enriched = self._enrich_finding(finding, "javascript", url)
                        if enriched:
                            secrets_found += 1
                except Exception:
                    pass
        
        self.report.sources_scanned["js_files_scanned"] = scanned
        self._log(f"JS scanning complete: {secrets_found} secrets from {scanned} files")
    
    def _stage_3_scan_runtime(self):
        """Stage 3: Scan runtime responses"""
        self._log(f"Stage 3: Scanning {len(self.urls_to_scan)} URLs for runtime secrets...")
        self.report.stages_completed.append("runtime")
        
        scanned = 0
        secrets_found = 0
        
        # Headers that might reveal more
        debug_headers = [
            {"X-Debug": "1"},
            {"X-Debug-Mode": "true"},
            {},  # Normal request too
        ]
        
        def scan_url(url: str) -> List[Dict]:
            """Scan URL with various headers"""
            all_findings = []
            
            for headers in debug_headers:
                try:
                    resp = make_request(url, headers=headers, timeout=15)
                    if not resp.get("success"):
                        continue
                    
                    body = resp.get("body", "")
                    if not body or len(body) < 20:
                        continue
                    
                    # Check content type for relevance
                    content_type = resp.get("headers", {}).get("Content-Type", "")
                    if any(t in content_type.lower() for t in ["image/", "font/", "audio/", "video/"]):
                        continue
                    
                    # Scan content
                    result = scan_for_secrets(body, source=url)
                    all_findings.extend(result.get("findings", []))
                    
                    # Also check URL itself
                    url_result = scan_url_for_secrets(url)
                    all_findings.extend(url_result.get("findings", []))
                    
                    # If we found secrets, no need to try more headers
                    if result.get("findings"):
                        break
                        
                except Exception:
                    pass
            
            return all_findings
        
        # Concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(scan_url, url): url for url in list(self.urls_to_scan)[:self.max_urls]}
            
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                with self.lock:
                    scanned += 1
                    if scanned % 20 == 0:
                        self._log(f"Runtime Progress: {scanned}/{len(self.urls_to_scan)} - Secrets: {secrets_found}")
                
                try:
                    findings = future.result()
                    for finding in findings:
                        enriched = self._enrich_finding(finding, "api_response", url)
                        if enriched:
                            secrets_found += 1
                except Exception:
                    pass
        
        self.report.sources_scanned["urls_scanned"] = scanned
        self._log(f"Runtime scanning complete: {secrets_found} secrets from {scanned} URLs")
    
    def _stage_4_correlate(self):
        """Stage 4: Correlate and deduplicate findings"""
        self._log("Stage 4: Correlating findings...")
        self.report.stages_completed.append("correlate")
        
        secrets = list(self.secrets_by_hash.values())
        
        # Group by category
        by_category = defaultdict(list)
        for secret in secrets:
            by_category[secret.category].append(secret)
        
        # Look for related secrets (e.g., AWS key + secret together)
        aws_keys = [s for s in secrets if "aws_access_key" in s.secret_type]
        aws_secrets = [s for s in secrets if "aws_secret_key" in s.secret_type]
        
        for key in aws_keys:
            for secret in aws_secrets:
                # If found in same source, they're likely a pair
                if key.source == secret.source:
                    key.related_secrets.append(secret.secret_id)
                    secret.related_secrets.append(key.secret_id)
                    key.exploitation_hints.insert(0, "Found with corresponding secret key - likely valid credentials!")
                    key.risk = SecretRisk.CRITICAL
                    secret.risk = SecretRisk.CRITICAL
        
        # Similar for Stripe keys with matching test/live patterns
        # ... (can add more correlation logic)
        
        self._log(f"Correlation complete: {len(secrets)} unique secrets")
    
    def _stage_5_generate_recommendations(self):
        """Stage 5: Generate actionable recommendations"""
        self._log("Stage 5: Generating recommendations...")
        self.report.stages_completed.append("recommendations")
        
        secrets = list(self.secrets_by_hash.values())
        recommendations = []
        exploitation_paths = []
        
        # Group by risk
        critical = [s for s in secrets if s.risk == SecretRisk.CRITICAL]
        high = [s for s in secrets if s.risk == SecretRisk.HIGH]
        
        if critical:
            recommendations.append(f"🚨 CRITICAL: Found {len(critical)} critical secrets requiring immediate action!")
            for s in critical[:3]:
                recommendations.append(f"  - {s.secret_type}: {s.value_masked} ({s.source})")
        
        if high:
            recommendations.append(f"⚠️ HIGH: Found {len(high)} high-risk secrets")
        
        # Generate exploitation paths
        for secret in critical + high[:5]:
            path = {
                "secret_id": secret.secret_id,
                "type": secret.secret_type,
                "category": secret.category.value,
                "steps": secret.exploitation_hints,
                "risk": secret.risk.value,
            }
            exploitation_paths.append(path)
        
        # Category-specific recommendations
        categories_found = set(s.category for s in secrets)
        
        if SecretCategory.CLOUD in categories_found:
            recommendations.append("💡 Cloud credentials found - check for lateral movement opportunities")
            recommendations.append("   Try: enumerate IAM permissions, S3 buckets, EC2 instances")
        
        if SecretCategory.DATABASE in categories_found:
            recommendations.append("💡 Database credentials found - attempt connection")
            recommendations.append("   Check for: sensitive data, user tables, configuration")
        
        if SecretCategory.SCM in categories_found:
            recommendations.append("💡 Source control tokens found - check repository access")
            recommendations.append("   Look for: private repos, org secrets, commit history")
        
        if SecretCategory.PAYMENT in categories_found:
            recommendations.append("💡 Payment keys found - verify if production keys")
            recommendations.append("   ⚠️ Do NOT perform unauthorized transactions")
        
        if SecretCategory.AUTH in categories_found:
            recommendations.append("💡 Auth tokens/JWT secrets found - test for token forgery")
            recommendations.append("   Try: JWT none algorithm, weak secret brute force")
        
        if SecretCategory.API in categories_found:
            recommendations.append("💡 API keys found - enumerate accessible endpoints")
            recommendations.append("   Try: API documentation endpoints, rate limit testing")
        
        # Generate attack session suggestions based on secrets
        attack_suggestions = self._generate_attack_suggestions(secrets)
        if attack_suggestions:
            recommendations.append("")
            recommendations.append("🎯 SUGGESTED ATTACK PATHS:")
            recommendations.extend(attack_suggestions)
        
        self.report.recommendations = recommendations
        self.report.exploitation_paths = exploitation_paths
    
    def _generate_attack_suggestions(self, secrets: List[EnrichedSecret]) -> List[str]:
        """
        Generate attack session suggestions based on found secrets.
        Maps secrets to potential attack vectors.
        """
        suggestions = []
        
        for secret in secrets:
            if secret.risk not in [SecretRisk.CRITICAL, SecretRisk.HIGH]:
                continue
            
            category = secret.category
            
            if category == SecretCategory.CLOUD:
                if "aws" in secret.secret_type.lower():
                    suggestions.append(f"   → AWS Key ({secret.secret_id}): Try SSRF to metadata endpoint, S3 enumeration")
                elif "gcp" in secret.secret_type.lower():
                    suggestions.append(f"   → GCP Key ({secret.secret_id}): Access GCP APIs, check service account permissions")
                elif "azure" in secret.secret_type.lower():
                    suggestions.append(f"   → Azure Key ({secret.secret_id}): Enumerate Azure resources, check blob storage")
            
            elif category == SecretCategory.DATABASE:
                suggestions.append(f"   → DB Creds ({secret.secret_id}): Direct connection if accessible, look for exposed admin panels")
            
            elif category == SecretCategory.AUTH:
                if "jwt" in secret.secret_type.lower():
                    suggestions.append(f"   → JWT Secret ({secret.secret_id}): Forge tokens with admin claims, test on /admin endpoints")
                else:
                    suggestions.append(f"   → Auth Token ({secret.secret_id}): Replay token, test privilege escalation")
            
            elif category == SecretCategory.PAYMENT:
                suggestions.append(f"   → Payment Key ({secret.secret_id}): Verify scope (read-only vs write), check for test mode")
            
            elif category == SecretCategory.SCM:
                suggestions.append(f"   → SCM Token ({secret.secret_id}): Clone private repos, check for more secrets in code")
        
        # Limit suggestions
        return suggestions[:10]
    
    def _enrich_finding(self, finding: Dict, source_type: str, source: str) -> Optional[EnrichedSecret]:
        """
        Enrich a raw finding with category, risk, and exploitation hints.
        Returns None if duplicate.
        
        Also saves to LearningStore for self-learning AI.
        """
        secret_type = finding.get("type", "unknown")
        value = finding.get("value", "")
        
        # Generate hash for deduplication
        value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
        
        with self.lock:
            if value_hash in self.secrets_by_hash:
                return None  # Duplicate
            
            category = categorize_secret(secret_type)
            confidence = finding.get("confidence", 0.5)
            context = finding.get("context", "")
            entropy = finding.get("entropy", 0)
            
            risk = calculate_risk(secret_type, category, confidence, context)
            hints = get_exploitation_hints(category, secret_type)
            
            masked_value = value[:4] + "..." + value[-4:] if len(value) > 8 else "***"
            
            enriched = EnrichedSecret(
                secret_id=f"secret_{len(self.secrets_by_hash)+1}",
                category=category,
                risk=risk,
                secret_type=secret_type,
                value_masked=masked_value,
                value_hash=value_hash,
                source=source,
                source_type=source_type,
                line_number=finding.get("line", 0),
                context=context[:500] if context else "",
                confidence=confidence,
                entropy=entropy,
                exploitation_hints=hints,
            )
            
            self.secrets_by_hash[value_hash] = enriched
            self.report.secrets_found.append(enriched)
            
            # ====== SELF-LEARNING: Save to LearningStore ======
            try:
                from core.learning_store import add_secret_finding
                
                # Build features for ML training
                features = {
                    "secret_type": secret_type,
                    "entropy": entropy,
                    "length": len(value),
                    "in_test_file": any(p in source.lower() for p in ["test", "mock", "fake", "example", "sample"]),
                    "in_comment": "comment" in source_type.lower() or "//" in context or "/*" in context,
                    "has_placeholder": any(p in value.lower() for p in ["xxx", "your_", "example", "changeme", "todo"]),
                    "confidence": confidence,
                    "context_length": len(context),
                    "source_type": source_type,
                    "category": category.value,
                    "risk": risk.value,
                }
                
                add_secret_finding(
                    target=self.target_domain,
                    secret_type=secret_type,
                    value_masked=value[:8] + "..." if len(value) > 8 else value,
                    source=source,
                    confidence=confidence,
                    severity=risk.value,
                    context=context[:200],
                    features=features
                )
            except Exception as e:
                pass  # Don't break scanning if learning store fails
            
            return enriched
    
    def scan_content(self, content: str, source: str, source_type: str = "text") -> List[Dict]:
        """
        Manually scan arbitrary content.
        Useful for scanning local files, clipboard, etc.
        """
        result = scan_for_secrets(content, source=source)
        findings = result.get("findings", [])
        
        enriched = []
        for finding in findings:
            e = self._enrich_finding(finding, source_type, source)
            if e:
                enriched.append(e.to_dict())
        
        return enriched
    
    def add_urls(self, urls: List[str]):
        """Add URLs to scan"""
        self.urls_to_scan.update(urls[:self.max_urls])
    
    def add_js_urls(self, urls: List[str]):
        """Add JS URLs to scan"""
        self.js_urls.update(urls[:self.max_js])
    
    def get_report(self) -> Dict[str, Any]:
        """Generate the final report"""
        secrets = list(self.secrets_by_hash.values())
        
        # Summary
        summary = {
            "total_secrets": len(secrets),
            "by_risk": {
                "critical": len([s for s in secrets if s.risk == SecretRisk.CRITICAL]),
                "high": len([s for s in secrets if s.risk == SecretRisk.HIGH]),
                "medium": len([s for s in secrets if s.risk == SecretRisk.MEDIUM]),
                "low": len([s for s in secrets if s.risk == SecretRisk.LOW]),
                "info": len([s for s in secrets if s.risk == SecretRisk.INFO]),
            },
            "by_category": {},
            "high_confidence": len([s for s in secrets if s.confidence >= 0.8]),
        }
        
        for category in SecretCategory:
            count = len([s for s in secrets if s.category == category])
            if count > 0:
                summary["by_category"][category.value] = count
        
        self.report.summary = summary
        
        # Truncate secrets list if too large to prevent AI agent stuck
        max_secrets = 100
        total_secrets = len(secrets)
        truncated = total_secrets > max_secrets
        if truncated:
            secrets = secrets[:max_secrets]
        
        return {
            "target": self.report.target,
            "started_at": self.report.started_at,
            "completed_at": self.report.completed_at,
            "stages_completed": self.report.stages_completed,
            "sources_scanned": self.report.sources_scanned,
            "summary": summary,
            "secrets_total": total_secrets,
            "secrets_returned": len(secrets),
            "secrets_truncated": truncated,
            "secrets": [s.to_dict() for s in secrets],
            "exploitation_paths": self.report.exploitation_paths[:20] if len(self.report.exploitation_paths) > 20 else self.report.exploitation_paths,
            "recommendations": self.report.recommendations[:20] if len(self.report.recommendations) > 20 else self.report.recommendations,
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def deep_secret_hunt(
    domain: str, 
    max_urls: int = 100, 
    max_js: int = 50,
    stages: List[str] = None,
    local_paths: List[str] = None
) -> Dict[str, Any]:
    """
    Run a complete deep secret hunt on a domain.
    
    Args:
        domain: Target domain (e.g., "example.com")
        max_urls: Maximum URLs to scan
        max_js: Maximum JS files to scan
        stages: Specific stages to run
        local_paths: Local file/directory paths for static scanning (requires "static" stage)
    
    Returns:
        Complete hunting report with secrets and recommendations
    """
    hunter = DeepSecretHunter(domain, max_urls, max_js)
    return hunter.hunt(stages, local_paths=local_paths)


def scan_local_secrets(paths: List[str]) -> Dict[str, Any]:
    """
    Scan local files/directories for secrets only (no network requests).
    
    Args:
        paths: List of file or directory paths to scan
    
    Returns:
        Secrets found with categorization and risk scoring
    """
    hunter = DeepSecretHunter("local_scan", max_urls=0, max_js=0)
    hunter._stage_1_scan_static(paths)
    hunter._stage_4_correlate()
    hunter._stage_5_generate_recommendations()
    hunter.report.completed_at = datetime.now().isoformat()
    return hunter.get_report()


def quick_secret_scan(url: str) -> Dict[str, Any]:
    """
    Quick scan of a single URL for secrets.
    """
    result = {
        "url": url,
        "secrets": [],
        "total": 0,
    }
    
    try:
        resp = make_request(url, timeout=30)
        if resp.get("success"):
            body = resp.get("body", "")
            
            # Scan content
            scan_result = scan_for_secrets(body, source=url)
            result["secrets"] = scan_result.get("findings", [])
            result["total"] = len(result["secrets"])
            
            # Also scan URL
            url_result = scan_url_for_secrets(url)
            result["secrets"].extend(url_result.get("findings", []))
            result["total"] = len(result["secrets"])
    except Exception as e:
        result["error"] = str(e)
    
    return result


def scan_js_for_secrets(js_urls: List[str]) -> Dict[str, Any]:
    """
    Scan multiple JS files for secrets.
    """
    hunter = DeepSecretHunter("js_scan", max_js=len(js_urls))
    hunter.js_urls = set(js_urls)
    hunter._stage_2_scan_javascript()
    
    return {
        "total_files": len(js_urls),
        "secrets_found": len(hunter.report.secrets_found),
        "secrets": [s.to_dict() for s in hunter.report.secrets_found],
    }


def validate_secret(secret_type: str, value: str) -> Dict[str, Any]:
    """
    Attempt to validate a secret (where safe to do so).
    
    NOTE: This only performs safe, read-only validation.
    """
    result = {
        "secret_type": secret_type,
        "validated": False,
        "validation_method": "none",
        "result": "not_validated",
        "safe_to_validate": False,
    }
    
    # Only validate certain types safely
    safe_validations = {
        "github_token": {
            "method": "api_call",
            "url": "https://api.github.com/user",
            "header": "Authorization",
            "header_value": f"token {value}",
        },
        # Add more safe validations...
    }
    
    if secret_type in safe_validations:
        result["safe_to_validate"] = True
        result["validation_method"] = safe_validations[secret_type]["method"]
        result["note"] = "Validation available but not performed automatically for safety"
        result["manual_command"] = f"curl -H 'Authorization: token ***' {safe_validations[secret_type]['url']}"
    
    return result
