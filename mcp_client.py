#!/usr/bin/env python3
"""
SpectreWeb AI MCP Client v7.0.0 - Consolidated Tools
Phantom Recon Engine - AI-Powered Web Penetration Testing

Changes in v7.0.0:
- Removed self-learning AI orchestrator and broken AI model tools
- Removed advanced attack-session auto-orchestration tools
- Removed redundant combo/wrapper tools
- Streamlined to 45 focused tools (manual-testing first)
- Improved bare exception handling across all modules
- Enhanced SpectreClient with better retry logic and error categorization

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
    """HTTP Client for SpectreWeb Server with retry and connection management"""
    
    MAX_RETRIES = 2
    RETRY_DELAY = 1.0
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SpectreWeb-MCP/6.0.0"})
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
        logger.error(f"❌ Failed to connect to {self.server_url}")
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Unified request method with retry logic for transient failures"""
        url = f"{self.server_url}/{endpoint}"
        last_error = None
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
                return resp.json()
            except requests.exceptions.ConnectionError as e:
                last_error = e
                if attempt < self.MAX_RETRIES:
                    time.sleep(self.RETRY_DELAY * (attempt + 1))
                    continue
            except requests.exceptions.Timeout as e:
                return {"error": f"Request timed out: {e}", "success": False}
            except requests.exceptions.JSONDecodeError:
                return {"error": "Server returned invalid JSON", "success": False}
            except Exception as e:
                return {"error": str(e), "success": False}
        return {"error": f"Connection failed after {self.MAX_RETRIES + 1} attempts: {last_error}", "success": False}
    
    def get(self, endpoint: str, params: Dict = None) -> Dict:
        return self._request("GET", endpoint, params=params or {})
    
    def post(self, endpoint: str, data: Dict) -> Dict:
        return self._request("POST", endpoint, json=data)

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
    """Setup MCP with consolidated tools (53 tools)"""
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
    
    # ==================== ANALYSIS TOOLS (2 tools) ====================
    
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
    
    # ==================== RESPONSE COMPARISON (1 tool) ====================
    
    @mcp.tool()
    def compare_responses(url1: str, url2: str, headers1: dict = None, headers2: dict = None) -> Dict[str, Any]:
        """Compare two HTTP responses for auth bypass/access control testing."""
        return client.post("api/analyze/compare", {
            "url1": url1, "url2": url2,
            "headers1": headers1 or {}, "headers2": headers2 or {}
        })
    
    # ==================== DEEP SECRET HUNTING (3 tools) ====================
    
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
    # LEARNING STORE (2 tools)
    # ==========================
    
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
    
    # ==========================
    # ORIGIN IP FINDER (3 tools)
    # ==========================

    @mcp.tool()
    def find_origin_ip(
        domain: str,
        verify: bool = True,
        use_crt_sh: bool = True,
        use_subdomain_leak: bool = True,
        use_dns_records: bool = True,
        use_securitytrails: bool = False,
        use_favicon_hash: bool = False
    ) -> Dict[str, Any]:
        """
        Find the real origin IP of a domain behind CDN/WAF/Cloudflare.

        Combines multiple free techniques:
        - Certificate Transparency (crt.sh)
        - Subdomain leak (origin.*, dev.*, staging.* ...)
        - DNS records (MX/SPF/TXT → IP extraction)
        - Origin verification (Host header + SSL cert match)
        - [Optional] SecurityTrails historical DNS (needs API key)
        - [Optional] Favicon hash for Shodan search

        Args:
            domain: Target domain (e.g. "example.com")
            verify: Verify candidate IPs by sending Host header (default True)
            use_crt_sh: Query Certificate Transparency logs
            use_subdomain_leak: Check common origin subdomain prefixes
            use_dns_records: Query MX/SPF/TXT for non-CDN IPs
            use_securitytrails: Use SecurityTrails API (needs SPECTREWEB_SECURITYTRAILS_API_KEY)
            use_favicon_hash: Compute favicon hash for Shodan/Censys search

        Returns:
        - behind_cdn: Whether domain is behind CDN
        - cdn_name: Detected CDN name
        - verified_origins: List of confirmed origin IPs
        - all_candidates: All candidate IPs with sources
        - subdomains_found: Subdomains discovered
        - dns_records: MX/SPF/TXT/A records
        - cert_domains: Domains found in TLS certificates
        """
        logger.info(f"🔍 Finding origin IP for {domain}")
        return client.post("api/origin/find", {
            "domain": domain,
            "verify": verify,
            "use_crt_sh": use_crt_sh,
            "use_subdomain_leak": use_subdomain_leak,
            "use_dns_records": use_dns_records,
            "use_securitytrails": use_securitytrails,
            "use_favicon_hash": use_favicon_hash,
        })

    @mcp.tool()
    def verify_origin_ip(
        ip: str,
        domain: str
    ) -> Dict[str, Any]:
        """
        Verify that an IP address serves the target domain.

        Sends HTTPS request to the IP with `Host: domain` header,
        then checks SSL certificate CN/SANs and HTTP response title.

        Args:
            ip: Candidate origin IP address
            domain: Target domain to verify against

        Returns:
        - cert_match: Whether SSL cert contains the domain
        - cert_cn: Certificate Common Name
        - cert_sans: Subject Alternative Names
        - http_status: HTTP status code from IP
        - title: Page title from response
        - leaked_headers: Any backend-leaking headers found
        - verified: Whether IP is confirmed as origin
        """
        logger.info(f"🔍 Verifying {ip} serves {domain}")
        return client.post("api/origin/verify", {"ip": ip, "domain": domain})

    @mcp.tool()
    def cert_transparency(domain: str) -> Dict[str, Any]:
        """
        Query Certificate Transparency logs via crt.sh.

        Finds subdomains and certificate domains for a target.
        Free, unlimited, no API key required.

        Args:
            domain: Target domain (e.g. "example.com")

        Returns:
        - subdomains: Subdomains found in CT logs
        - cert_domains: All domains in certificates
        - total_certs: Number of certificates found
        """
        logger.info(f"📜 Querying crt.sh for {domain}")
        return client.post("api/origin/crt-sh", {"domain": domain})

    @mcp.tool()
    def shodan_lookup(ip: str) -> Dict[str, Any]:
        """
        Query Shodan InternetDB for an IP address.

        Free, no API key required. Returns open ports, hostnames,
        tags, CPEs, and vulnerabilities for the given IP.

        Args:
            ip: IP address to look up (e.g. "1.2.3.4")

        Returns:
        - ports: Open ports detected by Shodan
        - hostnames: Hostnames associated with the IP
        - tags: Shodan tags (cdn, cloud, etc.)
        - cpes: Software/hardware identifiers
        - vulns: Known vulnerabilities
        """
        logger.info(f"📡 Shodan InternetDB lookup for {ip}")
        return client.post("api/origin/shodan", {"ip": ip})

    @mcp.tool()
    def fofa_search(query: str, size: int = 100) -> Dict[str, Any]:
        """
        Search FOFA search engine for IPs, hosts, and services.

        Requires SPECTREWEB_FOFA_EMAIL + SPECTREWEB_FOFA_API_KEY env vars.
        Free tier: limited queries, but favicon hash + cert search work.
        FOFA is especially powerful for Asian targets (casino, gambling).

        FOFA query syntax:
        - icon_hash="-12345678"   (favicon hash search)
        - cert="example.com"      (SSL cert CN/SAN search)
        - body="example.com"      (HTTP body search)
        - host="example.com"      (hostname search)

        Args:
            query: FOFA query string (e.g. 'cert="example.com"')
            size: Max results (default 100, free tier limit)

        Returns:
        - results: List of {ip, port, host, title, server, country}
        - total: Number of results
        """
        logger.info(f"🔍 FOFA search: {query}")
        return client.post("api/origin/fofa", {"query": query, "size": size})

    @mcp.tool()
    def quake_search(query: str, size: int = 100) -> Dict[str, Any]:
        """
        Search Quake 360 search engine for IPs, hosts, and services.

        Requires SPECTREWEB_QUAKE_API_KEY env var.
        Free tier: ~3000 credits + 5 free API queries/month.
        Excellent coverage for Asian targets (casino, gambling sites).

        Quake query syntax:
        - cert:"example.com"      (SSL cert CN/SAN search)
        - favicon:"-12345678"     (favicon hash search)
        - body:"example.com"      (HTTP body search)
        - host:"example.com"      (hostname search)

        Args:
            query: Quake query string (e.g. 'cert="example.com"')
            size: Max results (default 100, free tier limited)

        Returns:
        - results: List of {ip, port, hostname, title, server, source}
        - total: Number of results
        """
        logger.info(f"🌐 Quake search: {query}")
        return client.post("api/origin/quake", {"query": query, "size": size})

    @mcp.tool()
    def passive_dns_lookup(domain: str) -> Dict[str, Any]:
        """
        Query multiple free passive DNS sources for historical IPs.

        Sources: AlienVault OTX + HackerTarget + Validin.
        All free, no API keys required.

        Finds IPs that historically resolved for the domain,
        including IPs before CDN was enabled (origin candidates).

        Args:
            domain: Target domain (e.g. "example.com")

        Returns:
        - records: List of {ip, hostname, first_seen, last_seen, source}
        - total: Number of unique IPs found
        """
        logger.info(f"🌐 Passive DNS lookup for {domain}")
        return client.post("api/origin/passive-dns", {"domain": domain})

    @mcp.tool()
    def subdomain_brute(domain: str, wordlist: str = "subdomains_20k", max_workers: int = 50) -> Dict[str, Any]:
        """
        Brute-force subdomain enumeration using SecLists wordlist.

        Multi-threaded DNS resolution (50 concurrent). Finds subdomains
        that may bypass CDN and point directly to origin IP.
        Free, no API key required. Uses SecLists wordlists (auto-detected).

        Wordlist options:
        - subdomains_5k: 5,000 entries (fast, ~10s)
        - subdomains_20k: 20,000 entries (balanced, ~30s)
        - subdomains_110k: 110,000 entries (thorough, ~2min)

        Args:
            domain: Target domain (e.g. "example.com")
            wordlist: SecLists wordlist name (default: subdomains_20k)
            max_workers: Concurrent DNS lookups (default: 50, max: 100)

        Returns:
        - results: List of {subdomain, ips, source} for resolved subdomains
        - total: Number of subdomains resolved
        """
        logger.info(f"🔨 Subdomain brute: {domain} ({wordlist})")
        return client.post("api/origin/subdomain-brute", {"domain": domain, "wordlist": wordlist, "max_workers": max_workers})

    return mcp


def main():
    parser = argparse.ArgumentParser(description="SpectreWeb AI MCP v7.0.0 - Consolidated")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    logger.info("👻 Starting SpectreWeb MCP v7.0.0 (53 tools)")
    
    try:
        client = SpectreClient(args.server)
        mcp = setup_mcp_server(client)
        logger.info("✅ MCP Ready - 53 tools loaded")
        mcp.run()
    except Exception as e:
        logger.error(f"💥 {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
