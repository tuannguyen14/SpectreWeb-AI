#!/usr/bin/env python3
"""
SpectreWeb AI MCP Client v5.3.1 - Consolidated Tools
Phantom Recon Engine - AI-Powered Web Penetration Testing

Changes from v3.0:
- Reduced from 92 to 50 tools
- Merged similar tools into unified interfaces
- Better organization and cleaner API

Usage:
    python mcp_client.py [--server URL] [--debug]
"""

import sys
import os
import argparse
import logging
import json
from typing import Dict, Any, List, Optional

import requests
import time
from mcp.server.fastmcp import FastMCP

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="[👻 SpectreWeb] %(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)

# Config
DEFAULT_SERVER = "http://127.0.0.1:8888"
DEFAULT_TIMEOUT = 3000


class SpectreClient:
    """HTTP Client for SpectreWeb Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self._connect()
    
    def _connect(self):
        for i in range(3):
            try:
                resp = self.session.get(f"{self.server_url}/health", timeout=5)
                resp.raise_for_status()
                logger.info(f"✅ Connected to {self.server_url}")
                return
            except Exception as e:
                logger.warning(f"⚠️ Attempt {i+1}/3 failed: {e}")
                time.sleep(2)
        logger.error(f"❌ Failed to connect")
    
    def get(self, endpoint: str, params: Dict = None) -> Dict:
        try:
            resp = self.session.get(f"{self.server_url}/{endpoint}", params=params or {}, timeout=self.timeout)
            return resp.json()
        except Exception as e:
            return {"error": str(e), "success": False}
    
    def post(self, endpoint: str, data: Dict) -> Dict:
        try:
            resp = self.session.post(f"{self.server_url}/{endpoint}", json=data, timeout=self.timeout)
            return resp.json()
        except Exception as e:
            return {"error": str(e), "success": False}

    def stream_tool(self, endpoint: str, data: Dict, tool_name: str) -> Dict:
        """Execute tool with streaming output"""
        logger.info(f"🚀 Starting {tool_name} (streaming)...")
        result = {"success": False, "output": "", "data": {}}
        data["stream"] = True
        
        # Limit logging to prevent memory/IO issues with large outputs
        max_log_lines = 50
        log_count = 0
        suppressed_count = 0
        
        try:
            with self.session.post(f"{self.server_url}/{endpoint}", json=data, timeout=self.timeout, stream=True) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line: continue
                    try:
                        msg = json.loads(line)
                        msg_type = msg.get("type")
                        msg_data = msg.get("data")
                        
                        if msg_type == "stdout":
                            # Only log first N lines to prevent flooding
                            if msg_data and msg_data.strip():
                                if log_count < max_log_lines:
                                    logger.info(f"  {msg_data.rstrip()}")
                                    log_count += 1
                                else:
                                    suppressed_count += 1
                        elif msg_type == "stderr":
                             if msg_data and msg_data.strip():
                                logger.warning(f"  {msg_data.rstrip()}")
                        elif msg_type == "result":
                            result = msg_data
                        elif msg_type == "error":
                            logger.error(f"❌ Error: {msg_data}")
                            result["error"] = msg_data
                            
                    except json.JSONDecodeError:
                        pass
            
            # Log summary if output was suppressed
            if suppressed_count > 0:
                logger.info(f"  ... ({suppressed_count} more lines suppressed)")
                        
            return result
        except Exception as e:
            return {"error": str(e), "success": False}


def _truncate_result(result: Dict, max_lines: int = 500) -> Dict:
    """Truncate result output to prevent large output causing AI agent to hang"""
    if not result or not isinstance(result, dict):
        return result
    
    # Truncate output field
    output = result.get("output", "") or ""
    if output:
        lines = output.split("\n")
        total_lines = len(lines)
        if total_lines > max_lines:
            result["output"] = "\n".join(lines[:max_lines])
            result["output_truncated"] = True
            result["output_total"] = total_lines
    
    # Truncate data.urls if present
    data = result.get("data", {})
    if data and isinstance(data, dict):
        urls = data.get("urls", [])
        if isinstance(urls, list) and len(urls) > max_lines:
            data["urls"] = urls[:max_lines]
            data["urls_truncated"] = True
            data["urls_total"] = len(urls)
            result["data"] = data
    
    return result


def setup_mcp_server(client: SpectreClient) -> FastMCP:
    """Setup MCP with consolidated tools (~50 tools)"""
    mcp = FastMCP("spectreweb-mcp")
    
    # ==================== CORE (3 tools) ====================
    
    @mcp.tool()
    def execute_command(command: str, use_cache: bool = False) -> Dict[str, Any]:
        """Execute any shell command on SpectreWeb server."""
        logger.info(f"🚀 {command}")
        return client.post("api/command", {"command": command, "use_cache": use_cache})
    
    @mcp.tool()
    def health_check() -> Dict[str, Any]:
        """Check server health."""
        return client.get("health")
    
    @mcp.tool()
    def web_request(url: str, method: str = "GET", headers: dict = None, data: str = None,
                    cookies: dict = None, follow_redirects: bool = True, proxy: str = None) -> Dict[str, Any]:
        """Make HTTP request like a browser."""
        return client.post("api/web/request", {
            "url": url, "method": method, "headers": headers or {},
            "data": data, "cookies": cookies or {}, "follow_redirects": follow_redirects, "proxy": proxy
        })
    
    # ==================== RECON TOOLS (8 tools) ====================
    
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """Nmap port scanning."""
        return client.post("api/tools/nmap", {"target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args})
    
    @mcp.tool()
    def naabu_scan(target: str, ports: str = "", top_ports: int = 0, additional_args: str = "") -> Dict[str, Any]:
        """Naabu - Fast port scanner (faster than nmap for large scans)."""
        return client.post("api/tools/naabu", {"target": target, "ports": ports, "top_ports": top_ports, "additional_args": additional_args})
    
    @mcp.tool()
    def subfinder_scan(domain: str, additional_args: str = "-silent") -> Dict[str, Any]:
        """Subfinder subdomain discovery. Output capped at 500 subdomains."""
        result = client.post("api/tools/subfinder", {"domain": domain, "additional_args": additional_args})
        return _truncate_result(result, 500)
    
    @mcp.tool()
    def httpx_probe(target: str, additional_args: str = "-sc -title -td") -> Dict[str, Any]:
        """Httpx - Fast HTTP toolkit for probing web servers."""
        return client.post("api/tools/httpx", {"target": target, "additional_args": additional_args})
    
    @mcp.tool()
    def whatweb_scan(url: str, additional_args: str = "-a 3") -> Dict[str, Any]:
        """WhatWeb technology detection."""
        return client.post("api/tools/whatweb", {"url": url, "additional_args": additional_args})
    
    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "common", match_codes: str = "200,301,302,403", headers: dict = None, additional_args: str = "", allow_large_wordlist: bool = False) -> Dict[str, Any]:
        """
        FFuf web fuzzing for directory/file discovery.
        
        Args:
            url: Target URL (use FUZZ keyword)
            wordlist: Path or alias (common, big, dir_small, etc). Default: 'common' (fast).
            match_codes: Comma-separated status codes to match
            headers: Dict of headers to include (safer than additional_args)
            additional_args: Raw arguments (use carefully)
            allow_large_wordlist: Allow using large wordlists like dir_medium/dir_big (defaults to False)
        """
        return client.post("api/tools/ffuf", {
            "url": url, "wordlist": wordlist, "match_codes": match_codes, 
            "headers": headers, "additional_args": additional_args,
            "allow_large_wordlist": bool(allow_large_wordlist)
        })
    
    @mcp.tool()
    def katana_crawl(url: str, depth: int = 2, js_crawl: bool = True, additional_args: str = "") -> Dict[str, Any]:
        """Katana web crawler - finds endpoints and JS files. Output capped at 500 URLs."""
        result = client.post("api/tools/katana", {"url": url, "depth": depth, "js_crawl": js_crawl, "additional_args": additional_args})
        return _truncate_result(result, 500)
    
    @mcp.tool()
    def historical_urls(domain: str, source: str = "all", limit: int = 0) -> Dict[str, Any]:
        """
        Get historical URLs from Wayback, GAU, CommonCrawl.
        
        Args:
            source: 'wayback', 'gau', 'all'
            limit: Max URLs to return (0 = unlimited, but output is capped at 500 for AI)
        """
        max_output_urls = 500  # Prevent large output causing AI agent to hang
        
        if source == "wayback":
            result = client.stream_tool("api/tools/waybackurls", {"domain": domain, "limit": limit}, "waybackurls")
            return _truncate_result(result, max_output_urls)
        elif source == "gau":
            result = client.stream_tool("api/tools/gau", {"domain": domain, "limit": limit}, "gau")
            return _truncate_result(result, max_output_urls)
        else:
            # Get from both
            wayback = client.stream_tool("api/tools/waybackurls", {"domain": domain, "limit": limit // 2 if limit else 0}, "waybackurls")
            gau = client.stream_tool("api/tools/gau", {"domain": domain, "limit": limit // 2 if limit else 0}, "gau")
            
            # Truncate each result
            wayback = _truncate_result(wayback, max_output_urls // 2)
            gau = _truncate_result(gau, max_output_urls // 2)
            
            # Combine outputs safely
            wayback_out = wayback.get("output", "") or ""
            gau_out = gau.get("output", "") or ""
            
            wayback_total = wayback.get("output_total", len(wayback_out.split("\n")))
            gau_total = gau.get("output_total", len(gau_out.split("\n")))
            
            return {
                "success": True,
                "wayback": wayback,
                "gau": gau,
                "combined_count": wayback_total + gau_total,
                "note": f"Output truncated to {max_output_urls} URLs max. Use limit parameter for specific counts."
            }
    
    # ==================== VULN TESTING (3 unified tools) ====================
    
    @mcp.tool()
    def vuln_test(vuln_type: str, url: str, param: str = "", payloads: list = None) -> Dict[str, Any]:
        """
        🎯 Unified vulnerability testing tool.
        
        Args:
            vuln_type: 'xss', 'sqli', 'lfi', 'ssrf', 'ssti', 'redirect', 'crlf'
            url: Target URL with parameters
            param: Specific parameter to test (optional)
            payloads: Custom payloads (optional)
        
        Returns:
            Vulnerability scan results with findings
        """
        logger.info(f"🎯 Testing {vuln_type.upper()}: {url}")
        
        endpoint_map = {
            "xss": "api/test/xss",
            "sqli": "api/test/sqli",
            "lfi": "api/test/lfi",
            "ssrf": "api/test/ssrf",
            "redirect": "api/scan/redirect",
            "crlf": "api/scan/crlf",
            "headers": "api/scan/headers",
        }
        
        endpoint = endpoint_map.get(vuln_type, "api/test/xss")
        data = {"url": url, "param": param}
        if payloads:
            data["payloads"] = payloads
        
        return client.post(endpoint, data)
    
    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """SQLMap - Advanced SQL injection testing."""
        return client.post("api/tools/sqlmap", {"url": url, "data": data, "additional_args": additional_args})
    
    @mcp.tool()
    def dalfox_scan(url: str, param: str = "", blind: str = "", cookie: str = "", additional_args: str = "") -> Dict[str, Any]:
        """Dalfox - Advanced XSS scanner with smart analysis."""
        return client.post("api/tools/dalfox", {"url": url, "param": param, "blind": blind, "cookie": cookie, "additional_args": additional_args})
    
    # ==================== PAYLOADS (1 unified tool) ====================
    
    @mcp.tool()
    def get_payloads(payload_type: str = "all", context: str = "", db_type: str = "mysql") -> Dict[str, Any]:
        """
        🔥 Get attack payloads for various vulnerability types.
        
        Args:
            payload_type: 'xss', 'sqli', 'lfi', 'ssrf', 'ssti', 'xxe', 'nosql', 'polyglot', 'all'
            context: For XSS - 'html', 'attribute', 'javascript', 'url', 'css'
                     For SSTI - 'detection', 'jinja2', 'twig', 'freemarker'
            db_type: For SQLi - 'mysql', 'mssql', 'postgresql', 'oracle', 'sqlite'
        
        Returns:
            Payloads optimized for the specified type and context
        """
        logger.info(f"🔥 Getting {payload_type} payloads (context: {context})")
        
        if payload_type == "xss" and context:
            return client.get("api/attack/xss/advanced", {"context": context})
        elif payload_type == "sqli" and db_type:
            return client.get("api/attack/sqli/advanced", {"db": db_type})
        elif payload_type == "ssti":
            return client.get("api/exploit/ssti", {"engine": context or "detection"})
        elif payload_type == "xxe":
            return client.get("api/attack/xxe", {"callback": context})
        elif payload_type == "nosql":
            return client.get("api/attack/nosql", {"param": context or "username"})
        elif payload_type == "ssrf":
            return client.get("api/attack/ssrf/payloads", {"target": context or "127.0.0.1"})
        elif payload_type == "polyglot":
            return client.get("api/manual/polyglot", {"type": context or "xss"})
        else:
            return client.get("api/payload/list", {"type": payload_type})
    
    # ==================== BYPASS GENERATORS (1 unified tool) ====================
    
    @mcp.tool()
    def generate_bypass(bypass_type: str, target: str = "", payload: str = "") -> Dict[str, Any]:
        """
        🛡️ Generate bypass payloads for various protections.
        
        Args:
            bypass_type: 'waf', 'auth', 'cache_poison', '403'
            target: URL or endpoint to target
            payload: Original payload to mutate (for WAF bypass)
        
        Returns:
            List of bypass techniques and payloads
        """
        logger.info(f"🛡️ Generating {bypass_type} bypass")
        
        if bypass_type == "waf":
            return client.post("api/exploit/waf_bypass", {"payload": payload})
        elif bypass_type == "auth":
            return client.post("api/exploit/auth_bypass", {"url": target, "endpoint": "/admin"})
        elif bypass_type == "cache_poison":
            return client.post("api/exploit/cache_poison", {"url": target})
        else:
            return client.post("api/manual/waf-bypass", {"payload": payload})
    
    # ==================== JWT TOOLS (1 unified tool) ====================
    
    @mcp.tool()
    def jwt_tools(action: str, token: str, claims: dict = None, public_key: str = "") -> Dict[str, Any]:
        """
        🔐 JWT analysis and attack tools.
        
        Args:
            action: 'analyze', 'none_attack', 'confusion', 'inject_claims'
            token: JWT token to analyze/attack
            claims: Claims to inject (for inject_claims action)
            public_key: Public key for confusion attack
        
        Returns:
            Analysis results or forged tokens
        """
        logger.info(f"🔐 JWT {action}")
        
        if action == "analyze":
            return client.post("api/analyze/jwt", {"token": token})
        elif action == "none_attack":
            return client.post("api/attack/jwt/none", {"token": token})
        elif action == "confusion":
            return client.post("api/attack/jwt/confusion", {"token": token, "public_key": public_key})
        elif action == "inject_claims":
            return client.post("api/attack/jwt/inject", {"token": token, "claims": claims or {}})
        else:
            return {"error": f"Unknown action: {action}"}
    
    # ==================== SECRET SCANNING (1 unified tool) ====================
    
    @mcp.tool()
    def scan_secrets(content: str = "", url: str = "", source: str = "unknown") -> Dict[str, Any]:
        """
        🔐 Scan for hardcoded secrets and sensitive data.
        
        Detects 50+ secret types: AWS, GCP, GitHub, Stripe, JWT, private keys, etc.
        
        Args:
            content: Text/code content to scan (if provided)
            url: URL to fetch and scan (if content not provided)
            source: Source identifier for reporting
        
        Returns:
            Found secrets with severity, confidence, and verification status
        """
        logger.info(f"🔐 Scanning for secrets: {source or url}")
        
        if url:
            return client.post("api/secrets/scan_response", {"url": url})
        else:
            # Detect if JavaScript
            if any(kw in content for kw in ["function", "const ", "let ", "var ", "=>"]):
                return client.post("api/secrets/scan_js", {"content": content, "source": source})
            return client.post("api/secrets/scan", {"content": content, "source": source})
    
    # ==================== JS ANALYSIS (2 tools) ====================
    
    @mcp.tool()
    def analyze_js(js_content: str = "", urls: list = None, base_url: str = "") -> Dict[str, Any]:
        """
        📜 Analyze JavaScript for endpoints, secrets, and DOM XSS.
        
        Args:
            js_content: JavaScript code to analyze
            urls: List of JS file URLs to fetch and analyze
            base_url: Base URL for resolving relative endpoints
        
        Returns:
            Endpoints, secrets, DOM XSS sinks/sources
        """
        logger.info("📜 Analyzing JavaScript...")
        
        if urls:
            return client.post("api/scan/js_files", {"urls": urls})
        else:
            # Analyze single JS content
            endpoints = client.post("api/scan/js_endpoints", {"content": js_content, "base_url": base_url})
            dom_xss = client.post("api/attack/dom_xss", {"content": js_content})
            secrets = client.post("api/secrets/scan_js", {"content": js_content, "source": "javascript"})
            
            return {
                "success": True,
                "endpoints": endpoints.get("endpoints", []),
                "dom_xss": dom_xss,
                "secrets": secrets.get("secrets", [])
            }
    
    @mcp.tool()
    def extract_from_webpage(url: str = "", html: str = "", extract_type: str = "all") -> Dict[str, Any]:
        """Extract links/forms/comments/js from webpage."""
        return client.post("api/web/extract", {"url": url, "html": html, "type": extract_type})
    
    # ==================== SUBDOMAIN TAKEOVER (1 tool) ====================
    
    @mcp.tool()
    def check_takeover(subdomains: list) -> Dict[str, Any]:
        """
        🎯 Check subdomains for takeover vulnerabilities.
        
        Detects: AWS S3, CloudFront, GitHub Pages, Heroku, Netlify, Azure, etc.
        
        Args:
            subdomains: List of subdomains to check (or single subdomain as list)
        
        Returns:
            Vulnerability status for each subdomain
        """
        logger.info(f"🎯 Checking {len(subdomains)} subdomains for takeover")
        
        if len(subdomains) == 1:
            return client.post("api/scan/takeover", {"subdomain": subdomains[0]})
        else:
            return client.post("api/scan/takeover/bulk", {"subdomains": subdomains[:100]})
    
    # ==================== ANALYSIS TOOLS (3 tools) ====================
    
    @mcp.tool()
    def analyze_response(response_body: str, url: str = "", status_code: int = 200) -> Dict[str, Any]:
        """
        🔍 Analyze HTTP response for vulnerabilities and info disclosure.
        
        Detects: SQL errors, stack traces, path disclosure, secrets, version info
        """
        logger.info("🔍 Analyzing response...")
        
        results = {}
        
        # Vuln scan
        vuln = client.post("api/ai/vuln_scan", {"response": response_body, "url": url})
        results["vulnerabilities"] = vuln
        
        # Error analysis if error status
        if status_code >= 400:
            error = client.post("api/manual/analyze-error", {"response": {"body": response_body, "status_code": status_code}})
            results["error_analysis"] = error
        
        # Secret extraction
        secrets = client.post("api/manual/extract-secrets", {"response": {"body": response_body}})
        results["secrets"] = secrets
        
        return results
    
    @mcp.tool()
    def analyze_hash(hash_str: str) -> Dict[str, Any]:
        """Identify hash type and get crack suggestions."""
        return client.post("api/analyze/hash", {"hash": hash_str})
    
    @mcp.tool()
    def test_cors(url: str, origin: str = "https://evil.com") -> Dict[str, Any]:
        """Test CORS configuration for vulnerabilities."""
        return client.post("api/analyze/cors", {"url": url, "origin": origin})
    
    # ==================== PARAMETER DISCOVERY (1 tool) ====================
    
    @mcp.tool()
    def discover_params(url: str, method: str = "GET", wordlist: str = None) -> Dict[str, Any]:
        """
        🔎 Discover hidden parameters on URL using Arjun.
        
        Uses Arjun - industry-standard parameter discovery tool with advanced detection techniques.
        Supports custom wordlists or uses Arjun's built-in wordlist.
        
        Args:
            url: Target URL
            method: HTTP method (GET/POST)
            wordlist: Wordlist name/alias (e.g., "params_common") or path (optional)
        
        Returns:
            Discovered parameters with detection details
        """
        logger.info(f"🔎 Discovering params with Arjun: {url}")
        return client.post("api/scan/params", {"url": url, "method": method, "wordlist": wordlist})
    
    # ==================== IDOR & PRIVESC (1 unified tool) ====================
    
    @mcp.tool()
    def generate_access_tests(test_type: str, value: str = "", role: str = "user") -> Dict[str, Any]:
        """
        🔑 Generate access control test cases.
        
        Args:
            test_type: 'idor', 'privesc', 'auth_bypass'
            value: ID value for IDOR testing
            role: Current role for privilege escalation
        
        Returns:
            Test cases to try
        """
        logger.info(f"🔑 Generating {test_type} tests")
        
        if test_type == "idor":
            return client.post("api/manual/idor", {"value": value})
        elif test_type == "privesc":
            return client.get("api/manual/privesc", {"role": role})
        elif test_type == "auth_bypass":
            return client.post("api/manual/auth-bypass", {"endpoint": value or "/admin"})
        else:
            return {"error": f"Unknown test type: {test_type}"}
    
    # ==================== BUSINESS LOGIC (1 tool) ====================
    
    @mcp.tool()
    def get_business_logic_tests(category: str = "all") -> Dict[str, Any]:
        """
        💼 Get business logic vulnerability test cases.
        
        Categories: 'price_manipulation', 'workflow_bypass', 'privilege_escalation', 'all'
        """
        return client.get("api/exploit/business_logic", {"category": category})
    
    # ==================== RACE CONDITION & RATE LIMIT (1 tool) ====================
    
    @mcp.tool()
    def test_concurrency(url: str, test_type: str = "race", count: int = 10, method: str = "POST", 
                         data: str = None, headers: dict = None) -> Dict[str, Any]:
        """
        ⚡ Test for race conditions and rate limiting.
        
        Args:
            test_type: 'race' or 'rate_limit'
            count: Number of concurrent requests
        """
        logger.info(f"⚡ {test_type} test: {url}")
        
        if test_type == "race":
            return client.post("api/attack/race", {
                "url": url, "method": method, "data": data,
                "headers": headers, "count": min(count, 50)
            })
        else:
            return client.post("api/manual/rate-limit", {"url": url, "count": count, "delay": 0.1})
    
    # ==================== GRAPHQL (1 tool) ====================
    
    @mcp.tool()
    def test_graphql(url: str, headers: dict = None) -> Dict[str, Any]:
        """
        🔮 Test GraphQL endpoint for vulnerabilities.
        
        Tests: introspection, batching attacks, field suggestions, schema exposure
        """
        return client.post("api/attack/graphql", {"url": url, "headers": headers})
    
    # ==================== WORDLISTS (2 tools) ====================
    
    @mcp.tool()
    def get_wordlist(name: str) -> Dict[str, Any]:
        """Get wordlist by name (common, big, dir_small, dir_medium, sqli, xss, lfi, api_endpoints, etc)."""
        return client.get(f"api/wordlists/{name}")
    
    @mcp.tool()
    def suggest_wordlist(task: str) -> Dict[str, Any]:
        """Suggest wordlists for a task description. Prefers smaller/faster lists (common/big) before large ones (dir_medium)."""
        return client.post("api/wordlists/suggest", {"task": task})
    
    # ==================== ENCODING (1 unified tool) ====================
    
    @mcp.tool()
    def encode_decode(action: str, payload: str, encoding: str = "url") -> Dict[str, Any]:
        """
        Encode or decode payload.
        
        Args:
            action: 'encode' or 'decode'
            encoding: 'url', 'base64', 'html', 'hex', 'unicode'
        """
        if action == "encode":
            return client.post("api/payload/encode", {"payload": payload, "encoding": encoding})
        else:
            return client.post("api/payload/decode", {"payload": payload, "encoding": encoding})
    
    # ==================== PAYLOAD MUTATION (1 tool) ====================
    
    @mcp.tool()
    def mutate_payload(payload: str, techniques: str = "case,encode,whitespace") -> Dict[str, Any]:
        """
        🔀 Mutate a payload using bypass techniques.
        
        Techniques: case, encode, whitespace, comments, concat, double, null
        """
        tech_list = [t.strip() for t in techniques.split(",")]
        return client.post("api/manual/mutate", {"payload": payload, "techniques": tech_list})
    
    # ==================== REPORTING (1 unified tool) ====================
    
    @mcp.tool()
    def report(action: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        📋 Smart reporting system.
        
        Args:
            action: 'get', 'add_finding', 'add_note', 'summary', 'next_steps'
            target: Target domain
            **kwargs: Additional args based on action:
                - add_finding: title, description, severity, url, evidence, recommendation
                - add_note: note
        """
        logger.info(f"📋 Report {action}: {target}")
        
        if action == "get":
            return client.post("api/report/get", {"target": target})
        elif action == "add_finding":
            return client.post("api/report/finding", {
                "target": target,
                "title": kwargs.get("title", ""),
                "description": kwargs.get("description", ""),
                "severity": kwargs.get("severity", "medium"),
                "url": kwargs.get("url", ""),
                "evidence": kwargs.get("evidence", ""),
                "recommendation": kwargs.get("recommendation", "")
            })
        elif action == "add_note":
            return client.post("api/report/note", {"target": target, "note": kwargs.get("note", "")})
        elif action == "summary":
            return client.post("api/report/summary", {"target": target})
        elif action == "next_steps":
            return client.post("api/report/next", {"target": target})
        else:
            return {"error": f"Unknown action: {action}"}
    
    # ==================== CONTEXT (2 tools) ====================
    
    @mcp.tool()
    def load_context(target: str) -> Dict[str, Any]:
        """
        🚨 IMPORTANT: Call this FIRST before scanning any target!
        
        Loads all previous intelligence: findings, subdomains, endpoints, technologies, notes.
        """
        logger.info(f"📋 Loading context for: {target}")
        return client.post("api/context/load", {"target": target})
    
    @mcp.tool()
    def list_targets() -> Dict[str, Any]:
        """List all previously scanned targets."""
        return client.get("api/context/targets")
    
    # ==================== AI ANALYSIS (1 unified tool) ====================
    
    @mcp.tool()
    def ai_analyze(analysis_type: str, data: dict = None, target: str = "") -> Dict[str, Any]:
        """
        🧠 AI-powered analysis.
        
        Args:
            analysis_type: 'scan_result', 'tech_detect', 'classify_endpoint', 'hints', 'summary'
            data: Data to analyze (response, headers, etc.)
            target: Target for hints/summary
        
        Returns:
            AI analysis with findings and recommendations
        """
        logger.info(f"🧠 AI {analysis_type}")
        
        if analysis_type == "scan_result":
            return client.post("api/ai/analyze", {"tool": data.get("tool", "unknown"), "result": data})
        elif analysis_type == "tech_detect":
            return client.post("api/ai/detect_tech", {"response": data.get("response", ""), "headers": data.get("headers", {})})
        elif analysis_type == "classify_endpoint":
            return client.post("api/ai/classify", {"url": data.get("url", ""), "method": data.get("method", "GET")})
        elif analysis_type == "hints":
            return client.post("api/ai/hints", {
                "target": target,
                "findings": data.get("findings", []),
                "technologies": data.get("technologies", [])
            })
        elif analysis_type == "summary":
            return client.get("api/ai/summary")
        else:
            return {"error": f"Unknown analysis type: {analysis_type}"}
    
    # ==================== COMBO SCANS (2 tools) ====================
    
    @mcp.tool()
    def quick_recon(target: str) -> Dict[str, Any]:
        """
        ⚡ Quick reconnaissance - runs whatweb + subfinder.
        Best for initial target assessment.
        """
        logger.info(f"⚡ Quick recon: {target}")
        
        results = {"target": target, "scans": {}}
        
        url = f"https://{target}" if not target.startswith("http") else target
        results["scans"]["whatweb"] = client.post("api/tools/whatweb", {"url": url})
        
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        results["scans"]["subfinder"] = client.post("api/tools/subfinder", {"domain": domain})
        
        results["success"] = True
        return results
    
    @mcp.tool()
    def quick_vuln_scan(url: str) -> Dict[str, Any]:
        """
        ⚡ Quick vulnerability scan - tests redirect, CRLF, header injection.
        Fast initial assessment.
        """
        return client.post("api/scan/quick", {"url": url})
    
    # ==================== FILES (3 tools) ====================
    
    @mcp.tool()
    def create_file(filename: str, content: str, binary: bool = False) -> Dict[str, Any]:
        """Create file on server."""
        return client.post("api/files/create", {"filename": filename, "content": content, "binary": binary})
    
    @mcp.tool()
    def read_file(filename: str) -> Dict[str, Any]:
        """Read file from server."""
        return client.post("api/files/read", {"filename": filename})
    
    @mcp.tool()
    def list_files(directory: str = ".") -> Dict[str, Any]:
        """List files in directory."""
        return client.get("api/files/list", {"directory": directory})
    
    # ==================== HASH TOOLS (1 tool) ====================
    
    @mcp.tool()
    def generate_hash(text: str) -> Dict[str, Any]:
        """Generate MD5, SHA1, SHA256, SHA512 hashes."""
        return client.post("api/analyze/hash/generate", {"text": text})
    
    # ==================== RESPONSE COMPARISON (1 tool) ====================
    
    @mcp.tool()
    def compare_responses(url1: str, url2: str, headers1: dict = None, headers2: dict = None) -> Dict[str, Any]:
        """Compare two HTTP responses for auth bypass/access control testing."""
        return client.post("api/analyze/compare", {
            "url1": url1, "url2": url2,
            "headers1": headers1 or {}, "headers2": headers2 or {}
        })
    
    # ==================== ADVANCED ATTACK SESSION (4 tools) ====================
    
    @mcp.tool()
    def attack_session_create(url: str, auth_headers: dict = None, cookies: dict = None) -> Dict[str, Any]:
        """
        🎯 Create an advanced attack session with AI-driven orchestration.
        
        This starts a stateful session that:
        - Fingerprints the endpoint type (auth, api, file, payment, etc.)
        - Discovers parameters automatically
        - Suggests relevant attack vectors
        - Maintains context across multiple attacks
        
        Returns session_id for subsequent operations.
        """
        logger.info(f"🎯 Creating attack session: {url}")
        return client.post("api/attack/session/create", {
            "url": url, "auth_headers": auth_headers, "cookies": cookies
        })
    
    @mcp.tool()
    def attack_session_run(session_id: str, attack_type: str = "injection", 
                          params: list = None, intensity: str = "medium",
                          waf_bypass_level: int = 1, max_requests: int = 100) -> Dict[str, Any]:
        """
        ⚡ Run specific attack type in an existing session.
        
        Args:
            session_id: Session ID from attack_session_create
            attack_type: 'injection', 'idor', 'auth_bypass', 'business_logic', 'ssrf', 'lfi'
            params: Specific parameters to test (or auto-discovered)
            intensity: 'light', 'medium', 'heavy'
            waf_bypass_level: 0-3 for WAF evasion mutations
            max_requests: Maximum requests to send
        
        Returns findings with severity and evidence.
        """
        logger.info(f"⚡ Running {attack_type} attack (intensity: {intensity})")
        return client.post(f"api/attack/session/{session_id}/run", {
            "attack_type": attack_type, "params": params,
            "intensity": intensity, "waf_bypass_level": waf_bypass_level,
            "max_requests": max_requests
        })
    
    @mcp.tool()
    def attack_session_analyze(session_id: str) -> Dict[str, Any]:
        """
        🧠 Get AI-driven analysis and suggestions for an attack session.
        
        Returns:
        - Priority attacks based on endpoint type
        - Smart suggestions for next steps
        - Recommended intensity level
        """
        return client.get(f"api/attack/session/{session_id}/analyze")
    
    @mcp.tool()
    def attack_quick(url: str, attack_types: list = None, intensity: str = "medium") -> Dict[str, Any]:
        """
        🚀 Run quick automated attack without session management.
        
        Automatically:
        - Fingerprints endpoint
        - Selects appropriate payloads
        - Runs specified attack types
        - Returns comprehensive report
        
        Args:
            url: Target URL with parameters
            attack_types: List of attack types (default: ['injection', 'idor'])
            intensity: 'light', 'medium', 'heavy'
        """
        logger.info(f"🚀 Quick attack: {url}")
        return client.post("api/attack/quick", {
            "url": url, "attack_types": attack_types, "intensity": intensity
        })
    
    # ==================== DEEP SECRET HUNTING (2 tools) ====================
    
    @mcp.tool()
    def secrets_hunt(domain: str, max_urls: int = 100, max_js: int = 50, 
                    stages: list = None) -> Dict[str, Any]:
        """
        🔐 Run comprehensive multi-stage secret hunting on a domain.
        
        Stages:
        - collect: Gather URLs, JS files, endpoints from target
        - javascript: Deep scan all JavaScript files
        - runtime: Scan HTTP responses with debug headers
        - correlate: Deduplicate and find related secrets
        
        Returns:
        - Categorized secrets (cloud, payment, database, auth, etc.)
        - Risk scoring (critical, high, medium, low)
        - Exploitation hints for each secret
        - Actionable recommendations
        
        Args:
            domain: Target domain (e.g., "example.com")
            max_urls: Maximum URLs to scan
            max_js: Maximum JS files to scan  
            stages: Specific stages to run (default: all)
        """
        logger.info(f"🔐 Deep secret hunt: {domain}")
        return client.post("api/secrets/hunt", {
            "domain": domain, "max_urls": max_urls, 
            "max_js": max_js, "stages": stages
        })
    
    @mcp.tool()
    def secrets_js_hunt(urls: list) -> Dict[str, Any]:
        """
        📜 Scan multiple JavaScript files for hardcoded secrets.
        
        Specialized for client-side secret detection:
        - API keys in config objects
        - Hardcoded tokens and credentials
        - Environment variable references
        - Auth headers in fetch/axios calls
        
        Returns findings with context, confidence, and risk level.
        """
        logger.info(f"📜 JS secret hunt: {len(urls)} files")
        return client.post("api/secrets/js_hunt", {"urls": urls})
    
    @mcp.tool()
    def secrets_local_scan(paths: list) -> Dict[str, Any]:
        """
        📁 Scan local files/directories for secrets (no network requests).
        
        Scans code files (.py, .js, .ts, .java, .go, etc.) and config files
        (.json, .yml, .env, .properties, etc.) for hardcoded secrets.
        
        Args:
            paths: List of file or directory paths to scan
        
        Returns:
        - Secrets found with category and risk scoring
        - Exploitation hints for each secret
        - Attack path suggestions
        """
        logger.info(f"📁 Local secrets scan: {len(paths)} paths")
        return client.post("api/secrets/local", {"paths": paths})
    
    # ==========================
    # SELF-LEARNING AI TOOLS
    # ==========================
    
    @mcp.tool()
    def ai_status() -> Dict[str, Any]:
        """
        🧠 Get AI system status.
        
        Returns:
        - Local AI models status (trained/not trained)
        - Learning store statistics
        - ML availability
        """
        logger.info("🧠 Getting AI status")
        return client.get("api/ai/status")
    
    @mcp.tool()
    def ai_classify_secret(
        secret_type: str,
        entropy: float = 3.0,
        length: int = 20,
        in_test_file: bool = False,
        in_comment: bool = False,
        has_placeholder: bool = False,
        confidence: float = 0.5
    ) -> Dict[str, Any]:
        """
        🔍 Classify a secret as real or false positive using local AI.
        
        Uses trained ML model if available, falls back to heuristics.
        
        Returns:
        - is_real: Whether the secret is likely real
        - score: Confidence score (0-1)
        - model_used: "ml" or "heuristic"
        """
        logger.info(f"🔍 Classifying secret: {secret_type}")
        return client.post("api/ai/classify_secret", {
            "secret_type": secret_type,
            "entropy": entropy,
            "length": length,
            "in_test_file": in_test_file,
            "in_comment": in_comment,
            "has_placeholder": has_placeholder,
            "confidence": confidence
        })
    
    @mcp.tool()
    def ai_score_endpoint(
        endpoint_type: str,
        method: str = "GET",
        path: str = "",
        tech_stack: list = None
    ) -> Dict[str, Any]:
        """
        📊 Score an endpoint's vulnerability risk using local AI.
        
        Returns:
        - risk_score: 0-1 score
        - priority: "high", "medium", or "low"
        - model_used: "ml" or "heuristic"
        """
        logger.info(f"📊 Scoring endpoint: {method} {path}")
        return client.post("api/ai/score_endpoint", {
            "endpoint_type": endpoint_type,
            "method": method,
            "path": path,
            "tech_stack": tech_stack or []
        })
    
    @mcp.tool()
    def ai_train() -> Dict[str, Any]:
        """
        🎓 Train local AI models from labeled data.
        
        Trains:
        - SecretClassifier (reduces FP in secret detection)
        - EndpointRiskScorer (prioritizes risky endpoints)
        
        Requires at least 50 labeled samples per model.
        """
        logger.info("🎓 Training AI models")
        return client.post("api/ai/train", {})
    
    @mcp.tool()
    def ai_auto_train() -> Dict[str, Any]:
        """
        🔄 Auto-train AI models if enough new labeled data is available.
        
        Conditions:
        - At least 50 labeled samples
        - At least 10 new samples since last train
        
        Call this periodically to keep models up-to-date!
        """
        logger.info("🔄 Auto-training AI models")
        return client.post("api/ai/auto_train", {})
    
    @mcp.tool()
    def ai_insights() -> Dict[str, Any]:
        """
        💡 Get smart insights from learning history.
        
        Returns:
        - Most effective attack types (success rates)
        - False positive patterns
        - Recommendations for improvement
        """
        logger.info("💡 Getting AI insights")
        return client.get("api/ai/insights")
    
    @mcp.tool()
    def learning_stats() -> Dict[str, Any]:
        """
        📈 Get learning store statistics.
        
        Returns:
        - Total findings stored
        - Findings by type (secret, endpoint, attack)
        - Labeled findings count
        - Attack success rate by type
        """
        logger.info("📈 Getting learning stats")
        return client.get("api/learning/stats")
    
    @mcp.tool()
    def learning_list_findings(
        finding_type: str = None,
        label: str = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """
        📋 List findings from learning store.
        
        Args:
            finding_type: "secret", "endpoint", "attack_result" (optional)
            label: "true_positive", "false_positive", etc. (optional)
            limit: Max results (default 50)
        
        Returns:
        - List of findings with their labels
        """
        logger.info(f"📋 Listing findings: type={finding_type}, label={label}")
        params = {"limit": limit}
        if finding_type:
            params["type"] = finding_type
        if label:
            params["label"] = label
        return client.get("api/learning/findings", params)
    
    @mcp.tool()
    def learning_label(
        finding_id: str,
        label: str,
        notes: str = None
    ) -> Dict[str, Any]:
        """
        🏷️ Label a finding for AI training.
        
        Args:
            finding_id: ID of the finding (e.g., "secret_abc123")
            label: One of: "true_positive", "false_positive", "needs_review", "confirmed_bug", "not_exploitable"
            notes: Optional notes
        
        This feedback helps the AI learn and improve!
        """
        logger.info(f"🏷️ Labeling finding {finding_id} as {label}")
        return client.post("api/learning/label", {
            "finding_id": finding_id,
            "label": label,
            "notes": notes
        })
    
    @mcp.tool()
    def learning_export(path: str = "/tmp/hexstrike_learning.json") -> Dict[str, Any]:
        """
        💾 Export learning data to JSON file.
        
        Useful for:
        - Backing up your training data
        - Sharing learnings across machines
        - Analysis and debugging
        """
        logger.info(f"💾 Exporting learning data to {path}")
        return client.post("api/learning/export", {"path": path})
    
    return mcp


def main():
    parser = argparse.ArgumentParser(description="SpectreWeb AI MCP v5.3.1 - Consolidated")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    logger.info("👻 Starting SpectreWeb MCP v5.3.1 - Self-Learning AI (67 tools)")
    
    try:
        client = SpectreClient(args.server)
        mcp = setup_mcp_server(client)
        logger.info("✅ MCP Ready - 67 tools loaded")
        mcp.run()
    except Exception as e:
        logger.error(f"💥 {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
