"""Flask API Routes"""
import itertools
import re
import shlex
import time
import urllib.parse
from flask import request, jsonify, Response, stream_with_context
import queue
import threading
import json

from core.executor import execute_command
from core.file_manager import file_manager
from core.telemetry import telemetry
from core.cache import cache
from core.utils import clean_projectdiscovery_output
from web import make_request, extract_links, extract_forms, extract_comments, extract_js_files
from web import encode_payload, decode_payload, XSS_PAYLOADS, SQLI_PAYLOADS, LFI_PAYLOADS, SSRF_PAYLOADS
from web import analyze_jwt, identify_hash, generate_hashes, analyze_cors_headers, compare_responses, detect_idor_params
from config import WORDLISTS, get_wordlist, suggest_wordlist, SECLISTS_PATH
from core.reporter import get_report, Finding
from core.context import load_target_context, list_all_targets, get_context
from web.exploits import (
    generate_auth_bypass_tests, generate_waf_bypass_variants,
    SSTI_PAYLOADS, get_business_logic_tests, generate_cache_poison_tests
)
from core.analyzer import (
    analyzer, analyze_response, detect_technologies, 
    get_attack_vectors, classify_endpoint, analyze_scan
)
from core.formatter import SpectreFormatter, Color
from web.secrets import (
    scan_for_secrets, scan_js, scan_url_for_secrets,
    get_secret_patterns, calculate_string_entropy, scanner as secret_scanner
)
from web.advanced_scanner import (
    check_subdomain_takeover, scan_subdomains_takeover,
    test_open_redirect, test_crlf_injection, test_header_injection,
    extract_js_endpoints, scan_js_files, discover_params, quick_vuln_scan
)
from web.advanced_attacks import (
    test_race_condition, test_graphql_endpoint,
    generate_xxe_payloads, jwt_none_attack, jwt_key_confusion, jwt_claim_injection,
    generate_ssrf_payloads, analyze_dom_xss, generate_nosql_payloads,
    generate_xss_payloads, generate_sqli_payloads,
    ADVANCED_XSS, ADVANCED_SQLI, NOSQL_PAYLOADS
)
from web.manual_testing import (
    build_request, send_request, replay_with_modifications,
    mutate_payload, generate_polyglot, generate_waf_bypass_payloads,
    test_rate_limit, diff_responses, extract_secrets_from_response,
    analyze_error_response, generate_idor_tests, generate_privilege_escalation_tests,
    create_test_chain, suggest_next_tests
)
from web.attack_session import (
    create_attack_session, get_session, run_quick_attack,
    fingerprint_endpoint, AttackSession
)
from web.deep_secrets import (
    deep_secret_hunt, quick_secret_scan, scan_js_for_secrets,
    DeepSecretHunter, scan_local_secrets
)
from core.job_queue import get_job_queue, JobStatus
from core.response import APIResponse, ErrorCode, set_request_id
from web.rate_limiter import get_rate_limiter
from core.plugin import get_tool, list_tools, run_tool, ToolCategory
from config.settings import VERSION
from core.learning_store import get_store, FeedbackLabel
from core.local_ai import get_local_ai
from core.ai_orchestrator import get_orchestrator


def stream_tool_execution(tool, target, **kwargs):
    """Helper to stream tool execution via generator with timeout protection"""
    q = queue.Queue()
    max_runtime = kwargs.pop('max_runtime', 1800)  # Default 30 minutes max
    start_time = time.time()
    
    def on_stdout(line):
        q.put({"type": "stdout", "data": line})
        
    def on_stderr(line):
        q.put({"type": "stderr", "data": line})
        
    def worker():
        try:
            result = tool.run(target, stdout_callback=on_stdout, stderr_callback=on_stderr, **kwargs)
            q.put({"type": "result", "data": result.to_dict()})
        except Exception as e:
            q.put({"type": "error", "data": str(e)})
        finally:
            q.put(None)  # Sentinel
            
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    
    heartbeat_count = 0
    max_heartbeats = 60  # Max 60 consecutive heartbeats (60 seconds no output)
    
    try:
        while True:
            # Check max runtime
            elapsed = time.time() - start_time
            if elapsed > max_runtime:
                yield json.dumps({"type": "error", "data": f"Max runtime exceeded ({max_runtime}s)"}) + "\n"
                break
                
            try:
                item = q.get(timeout=1)
                if item is None:
                    break
                heartbeat_count = 0  # Reset on actual data
                yield json.dumps(item) + "\n"
            except queue.Empty:
                heartbeat_count += 1
                if heartbeat_count > max_heartbeats:
                    yield json.dumps({"type": "warning", "data": "Long running operation, still waiting..."}) + "\n"
                    heartbeat_count = 0  # Reset to continue
                else:
                    yield json.dumps({"type": "heartbeat", "data": ""}) + "\n"
                continue
    except GeneratorExit:
        pass
    finally:
        t.join(timeout=5)
        if t.is_alive():
            import logging
            logging.getLogger(__name__).warning("Stream worker thread still alive after timeout")


def register_routes(app):
    """Register all API routes"""

    def _json():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}
    
    # ==========================
    # HEALTH & STATUS
    # ==========================
    
    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "healthy",
            "version": VERSION,
            "cache_stats": cache.get_stats(),
            "telemetry": telemetry.get_stats(),
            "ai_stats": {
                "findings": len(analyzer.findings),
                "technologies": analyzer.technologies
            }
        })
    
    # ==========================
    # COMMAND EXECUTION
    # ==========================
    
    @app.route("/api/command", methods=["POST"])
    def command():
        params = _json()
        cmd = params.get("command", "")
        if not cmd:
            return jsonify({"error": "Command required"}), 400
        result = execute_command(cmd, params.get("use_cache", False))
        telemetry.record("command", result.get("success", False))
        return jsonify(result)
    
    # ==========================
    # WEB REQUESTS
    # ==========================
    
    @app.route("/api/web/request", methods=["POST"])
    def web_request():
        p = _json()
        if not p.get("url"):
            return jsonify({"error": "URL required"}), 400
        result = make_request(
            p["url"], p.get("method", "GET"), p.get("headers"),
            p.get("data"), p.get("cookies"), p.get("follow_redirects", True),
            p.get("timeout", 30), p.get("proxy")
        )
        telemetry.record("web_request", result.get("success", False))
        return jsonify(result)
    
    @app.route("/api/web/extract", methods=["POST"])
    def web_extract():
        p = _json()
        url = p.get("url", "")
        html = p.get("html", "")
        
        if url and not html:
            result = make_request(url)
            if not result.get("success"):
                return jsonify(result)
            html = result.get("body", "")
            base_url = url.rsplit('/', 1)[0]
        else:
            base_url = url
        
        extract_type = p.get("type", "all")
        extracted = {"success": True, "url": url}
        
        if extract_type in ["links", "all"]:
            extracted["links"] = extract_links(html, base_url)
        if extract_type in ["forms", "all"]:
            extracted["forms"] = extract_forms(html)
        if extract_type in ["comments", "all"]:
            extracted["comments"] = extract_comments(html)
        if extract_type in ["js", "all"]:
            extracted["js_files"] = extract_js_files(html, base_url)
        
        return jsonify(extracted)
    
    # ==========================
    # PAYLOADS
    # ==========================
    
    @app.route("/api/payload/encode", methods=["POST"])
    def payload_encode():
        p = _json()
        return jsonify({
            "success": True,
            "original": p.get("payload", ""),
            "encoded": encode_payload(p.get("payload", ""), p.get("encoding", "url")),
            "encoding": p.get("encoding", "url")
        })
    
    @app.route("/api/payload/decode", methods=["POST"])
    def payload_decode():
        p = _json()
        return jsonify({
            "success": True,
            "decoded": decode_payload(p.get("payload", ""), p.get("encoding", "url"))
        })
    
    @app.route("/api/payload/list", methods=["GET"])
    def payload_list():
        t = request.args.get("type", "all")
        payloads = {}
        if t in ["xss", "all"]: payloads["xss"] = XSS_PAYLOADS
        if t in ["sqli", "all"]: payloads["sqli"] = SQLI_PAYLOADS
        if t in ["lfi", "all"]: payloads["lfi"] = LFI_PAYLOADS
        if t in ["ssrf", "all"]: payloads["ssrf"] = SSRF_PAYLOADS
        return jsonify({"success": True, "payloads": payloads})
    
    # ==========================
    # VULN TESTING
    # ==========================
    
    @app.route("/api/test/xss", methods=["POST"])
    def test_xss():
        p = _json()
        url, param = p.get("url", ""), p.get("param", "")
        payloads = p.get("payloads") or XSS_PAYLOADS[:5]
        
        results = []
        for payload in payloads:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encode_payload(payload, 'url')}" if param else url
            resp = make_request(test_url)
            results.append({
                "payload": payload,
                "reflected": payload in resp.get("body", ""),
                "status": resp.get("status_code", 0)
            })
        
        return jsonify({"success": True, "results": results, "vulnerable": any(r["reflected"] for r in results)})
    
    @app.route("/api/test/sqli", methods=["POST"])
    def test_sqli():
        p = _json()
        url, param = p.get("url", ""), p.get("param", "")
        payloads = p.get("payloads") or SQLI_PAYLOADS[:5]
        
        indicators = ["sql", "mysql", "syntax", "query", "oracle", "sqlite"]
        results = []
        
        for payload in payloads:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encode_payload(payload, 'url')}" if param else url
            resp = make_request(test_url)
            body = resp.get("body", "").lower()
            has_error = any(i in body for i in indicators)
            results.append({"payload": payload, "sql_error": has_error, "status": resp.get("status_code", 0)})
        
        return jsonify({"success": True, "results": results, "vulnerable": any(r["sql_error"] for r in results)})
    
    @app.route("/api/test/lfi", methods=["POST"])
    def test_lfi():
        p = _json()
        url, param = p.get("url", ""), p.get("param", "")
        payloads = p.get("payloads") or LFI_PAYLOADS[:5]
        
        indicators = ["root:", "bin/bash", "<?php"]
        results = []
        
        for payload in payloads:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encode_payload(payload, 'url')}" if param else url
            resp = make_request(test_url)
            has_indicator = any(i in resp.get("body", "") for i in indicators)
            results.append({"payload": payload, "lfi_detected": has_indicator, "status": resp.get("status_code", 0)})
        
        return jsonify({"success": True, "results": results, "vulnerable": any(r["lfi_detected"] for r in results)})
    
    # ==========================
    # WORDLISTS
    # ==========================
    
    @app.route("/api/wordlists", methods=["GET"])
    def get_wordlists():
        return jsonify({"success": True, "seclists_path": SECLISTS_PATH, "wordlists": WORDLISTS})
    
    @app.route("/api/wordlists/<name>", methods=["GET"])
    def get_wordlist_by_name(name):
        return jsonify(get_wordlist(name))
    
    @app.route("/api/wordlists/suggest", methods=["POST"])
    def suggest_wordlists():
        task = _json().get("task", "")
        return jsonify({"success": True, "task": task, "suggestions": suggest_wordlist(task)})
    
    @app.route("/api/wordlists/preview/<name>", methods=["GET"])
    def preview_wordlist(name):
        try:
            lines = int(request.args.get("lines", 20))
        except Exception:
            lines = 20
        lines = max(1, min(lines, 500))
        wl = get_wordlist(name)
        if not wl.get("success"):
            return jsonify(wl)
        
        with open(wl["path"], 'r', errors='ignore') as f:
            preview = [l.strip() for l in itertools.islice(f, lines)]
        return jsonify({"success": True, "name": name, "preview": preview})
    
    # ==========================
    # TOOLS - RECON
    # ==========================
    
    def _run_tool(name: str, command: str):
        result = execute_command(command)
        telemetry.record(name, result.get("success", False))
        return jsonify(result)

    def _run_plugin_tool(tool_name: str, target: str, options: dict = None, clean_output: bool = False, realtime: bool = True):
        tool = get_tool(tool_name)
        if not tool:
            return jsonify({"success": False, "error": f"Tool '{tool_name}' not found"}), 404
        if not tool.is_available():
            return jsonify({"success": False, "error": f"Tool '{tool_name}' is not installed"}), 400

        opts = options or {}
        result = tool.run(target, realtime=realtime, **opts)
        telemetry.record(tool_name, result.success)

        output = result.output or ""
        if clean_output:
            output = clean_projectdiscovery_output(output)

        payload = {
            "success": result.success,
            "command": result.command,
            "output": output,
            "return_code": result.exit_code,
            "execution_time": result.duration_seconds,
        }
        if result.error:
            payload["error"] = result.error
        if result.parsed_data is not None:
            payload["data"] = result.parsed_data

        return jsonify(payload)
    
    @app.route("/api/tools/nmap", methods=["POST"])
    def nmap():
        p = _json()
        target = (p.get("target") or "").strip()
        if not target:
            return jsonify({"success": False, "error": "Target required"}), 400

        options = {
            "scan_type": p.get("scan_type", "-sV"),
            "ports": p.get("ports", ""),
            "additional_args": p.get("additional_args", ""),
        }
        return _run_plugin_tool("nmap", target, options)
    
    @app.route("/api/tools/ffuf", methods=["POST"])
    def ffuf():
        p = _json()
        url = (p.get("url") or "").strip()
        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        # Prefer smaller wordlists by default. Large lists must be explicitly allowed.
        allow_large_wordlist = bool(p.get("allow_large_wordlist", False))
        requested_wordlist = p.get("wordlist", "common")
        if (not allow_large_wordlist) and requested_wordlist in {"dir_medium", "dir_big"}:
            requested_wordlist = "big"

        headers = p.get("headers")
        if isinstance(headers, str):
            headers = [headers]

        options = {
            "wordlist": requested_wordlist,
            "match_codes": p.get("match_codes", "200,301,302,403"),
            "headers": headers,
            "additional_args": p.get("additional_args", ""),
        }
        return _run_plugin_tool("ffuf", url, options)
    
    @app.route("/api/tools/subfinder", methods=["POST"])
    def subfinder():
        p = _json()
        domain = (p.get("domain") or "").strip()
        if not domain:
            return jsonify({"success": False, "error": "Domain is required"}), 400

        additional_args = p.get("additional_args", "-silent") or "-silent"
        if "-silent" not in additional_args:
            additional_args = "-silent " + additional_args

        options = {"additional_args": additional_args}
        return _run_plugin_tool("subfinder", domain, options, clean_output=True)
    
    @app.route("/api/tools/sqlmap", methods=["POST"])
    def sqlmap():
        p = _json()
        url = (p.get("url") or "").strip()
        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400

        options = {
            "data": p.get("data", "") or "",
            "additional_args": p.get("additional_args", ""),
        }
        return _run_plugin_tool("sqlmap", url, options)
    
    @app.route("/api/tools/whatweb", methods=["POST"])
    def whatweb():
        p = _json()
        url = (p.get("url") or "").strip()
        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400

        options = {"additional_args": p.get("additional_args", "-a 3")}
        return _run_plugin_tool("whatweb", url, options)
    
    @app.route("/api/tools/httpx", methods=["POST"])
    def httpx():
        p = _json()
        target = (p.get("target") or "").strip()
        additional_args = p.get("additional_args", "")

        if not target:
            return jsonify({"success": False, "error": "Target is required"}), 400

        if additional_args:
            additional_args = str(additional_args)
            additional_args = additional_args.replace("-status-code", "-sc").replace("--status-code", "-sc")
            additional_args = additional_args.replace("-tech-detect", "-td").replace("--tech-detect", "-td")

        options = {
            "additional_args": additional_args or "-silent -sc -title -td",
        }
        return _run_plugin_tool("httpx", target, options, clean_output=True)
    
    # ==========================
    # TOOLS - CRAWLERS
    # ==========================
    
    @app.route("/api/tools/katana", methods=["POST"])
    def katana():
        p = _json()
        url = (p.get("url") or "").strip()
        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400

        depth = p.get("depth", 2)
        try:
            depth = int(depth)
        except Exception:
            depth = 2

        additional_args = p.get("additional_args", "")
        if additional_args:
            additional_args = re.sub(r'-field\s+\S+', '', str(additional_args)).strip()

        options = {
            "depth": depth,
            "js_crawl": bool(p.get("js_crawl", True)),
            "additional_args": additional_args,
        }
        return _run_plugin_tool("katana", url, options, clean_output=True)
    
    @app.route("/api/tools/waybackurls", methods=["POST"])
    def waybackurls():
        p = _json()
        domain = (p.get("domain") or "").strip()
        if not domain:
            return jsonify({"success": False, "error": "Domain is required"}), 400

        limit = p.get("limit", 0)
        try:
            limit = int(limit)
        except Exception:
            limit = 0

        additional_args = p.get("additional_args", "") or ""
        additional_args = str(additional_args).replace("--limit", "").replace("-limit", "").strip()

        tool = get_tool("waybackurls")
        if not tool:
            return jsonify({"success": False, "error": "Tool 'waybackurls' not found"}), 404
        if not tool.is_available():
            return jsonify({"success": False, "error": "Tool 'waybackurls' is not installed"}), 400

        if p.get("stream"):
            return Response(stream_with_context(stream_tool_execution(
                tool, domain, additional_args=additional_args
            )), mimetype='application/x-ndjson')

        result = tool.run(domain, additional_args=additional_args)
        telemetry.record("waybackurls", result.success)

        urls = [l.strip() for l in (result.output or "").splitlines() if l.strip()]
        total_urls = len(urls)
        if limit and limit > 0:
            urls = urls[:limit]
        
        # Truncate URLs list if too large (max 1000 URLs in response)
        max_urls_in_response = 1000
        urls_truncated = len(urls) > max_urls_in_response
        if urls_truncated:
            urls = urls[:max_urls_in_response]

        payload = {
            "success": result.success,
            "command": result.command,
            "output": "\n".join(urls[:200]),  # Only first 200 in output field
            "return_code": result.exit_code,
            "execution_time": result.duration_seconds,
            "data": {
                "urls": urls,
                "total": total_urls,
                "returned": len(urls),
                "truncated": urls_truncated
            },
        }
        if result.error:
            payload["error"] = result.error

        return jsonify(payload)
    
    @app.route("/api/tools/gau", methods=["POST"])
    def gau():
        p = _json()
        domain = (p.get("domain") or "").strip()
        if not domain:
            return jsonify({"success": False, "error": "Domain is required"}), 400

        limit = p.get("limit", 0)
        try:
            limit = int(limit)
        except Exception:
            limit = 0

        tool = get_tool("gau")
        if not tool:
            return jsonify({"success": False, "error": "Tool 'gau' not found"}), 404
        if not tool.is_available():
            return jsonify({"success": False, "error": "Tool 'gau' is not installed"}), 400

        if p.get("stream"):
            return Response(stream_with_context(stream_tool_execution(
                tool, 
                domain,
                providers=p.get("providers", "") or "",
                additional_args=p.get("additional_args", "") or ""
            )), mimetype='application/x-ndjson')

        result = tool.run(
            domain,
            providers=p.get("providers", "") or "",
            additional_args=p.get("additional_args", "") or "",
        )
        telemetry.record("gau", result.success)

        urls = [l.strip() for l in (result.output or "").splitlines() if l.strip()]
        if limit and limit > 0:
            urls = urls[:limit]

        payload = {
            "success": result.success,
            "command": result.command,
            "output": "\n".join(urls),
            "return_code": result.exit_code,
            "execution_time": result.duration_seconds,
            "data": {"urls": urls, "total": len(urls)},
        }
        if result.error:
            payload["error"] = result.error

        return jsonify(payload)
    
    @app.route("/api/tools/arjun", methods=["POST"])
    def arjun():
        p = _json()
        url = (p.get("url") or "").strip()
        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400

        options = {
            "method": p.get("method", "GET"),
            "wordlist": p.get("wordlist", "") or "",
            "additional_args": p.get("additional_args", "") or "",
        }
        return _run_plugin_tool("arjun", url, options)
    
    # ==========================
    # TOOLS - ADVANCED SCANNERS
    # ==========================
    
    @app.route("/api/tools/dalfox", methods=["POST"])
    def dalfox():
        """Dalfox - Advanced XSS scanner"""
        p = _json()
        url = (p.get("url") or "").strip()
        if not url:
            return jsonify({"success": False, "error": "URL required"}), 400

        options = {
            "param": p.get("param", "") or "",
            "blind": p.get("blind", "") or "",
            "cookie": p.get("cookie", "") or "",
            "additional_args": p.get("additional_args", "") or "",
        }
        return _run_plugin_tool("dalfox", url, options)
    
    @app.route("/api/tools/naabu", methods=["POST"])
    def naabu():
        """Naabu - Fast port scanner"""
        p = _json()
        target = (p.get("target") or "").strip()
        if not target:
            return jsonify({"success": False, "error": "Target required"}), 400

        options = {
            "ports": p.get("ports", "") or "",
            "top_ports": p.get("top_ports", 0) or 0,
            "additional_args": p.get("additional_args", "") or "",
        }
        return _run_plugin_tool("naabu", target, options, clean_output=True)
    
    # ==========================
    # BUSINESS LOGIC & ANALYSIS
    # ==========================
    
    @app.route("/api/analyze/jwt", methods=["POST"])
    def jwt_analyze():
        """Decode and analyze JWT token for vulnerabilities"""
        p = _json()
        token = p.get("token", "")
        if not token:
            return jsonify({"error": "JWT token required"}), 400
        return jsonify(analyze_jwt(token))
    
    @app.route("/api/analyze/hash", methods=["POST"])
    def hash_analyze():
        """Identify hash type"""
        p = _json()
        hash_str = p.get("hash", "")
        if not hash_str:
            return jsonify({"error": "Hash required"}), 400
        return jsonify(identify_hash(hash_str))
    
    @app.route("/api/analyze/hash/generate", methods=["POST"])
    def hash_generate():
        """Generate common hashes for a string"""
        p = _json()
        text = p.get("text", "")
        if not text:
            return jsonify({"error": "Text required"}), 400
        return jsonify({"success": True, "hashes": generate_hashes(text)})
    
    @app.route("/api/analyze/cors", methods=["POST"])
    def cors_analyze():
        """Test CORS configuration"""
        p = _json()
        url = p.get("url", "")
        test_origin = p.get("origin", "https://evil.com")
        
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        # Make request with custom Origin
        headers = {"Origin": test_origin}
        resp = make_request(url, headers=headers)
        
        if not resp.get("success"):
            return jsonify(resp)
        
        cors_result = analyze_cors_headers(resp.get("headers", {}))
        cors_result["tested_origin"] = test_origin
        cors_result["target_url"] = url
        return jsonify(cors_result)
    
    @app.route("/api/analyze/idor", methods=["POST"])
    def idor_analyze():
        """Detect potential IDOR parameters in URL"""
        p = _json()
        url = p.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        return jsonify(detect_idor_params(url))
    
    @app.route("/api/analyze/compare", methods=["POST"])
    def response_compare():
        """Compare two responses for differences (useful for auth bypass testing)"""
        p = _json()
        url1, url2 = p.get("url1", ""), p.get("url2", "")
        headers1, headers2 = p.get("headers1", {}), p.get("headers2", {})
        
        if not url1 or not url2:
            return jsonify({"error": "Both URLs required"}), 400
        
        resp1 = make_request(url1, headers=headers1)
        resp2 = make_request(url2, headers=headers2)
        
        comparison = compare_responses(resp1, resp2)
        comparison["url1"] = url1
        comparison["url2"] = url2
        return jsonify(comparison)
    
    @app.route("/api/test/ssrf", methods=["POST"])
    def test_ssrf():
        """Quick SSRF testing"""
        p = _json()
        url = p.get("url", "")
        param = p.get("param", "")
        
        payloads = p.get("payloads") or [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://0.0.0.0",
        ]
        
        results = []
        for payload in payloads:
            encoded = urllib.parse.quote(payload, safe='')
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded}" if param else url
            resp = make_request(test_url)
            interesting = any(x in resp.get("body", "").lower() for x in ["root:", "ami-", "instance", "metadata"])
            results.append({
                "payload": payload,
                "status": resp.get("status_code", 0),
                "interesting": interesting,
                "body_preview": resp.get("body", "")[:200] if interesting else None
            })
        
        return jsonify({
            "success": True,
            "results": results,
            "vulnerable": any(r["interesting"] for r in results)
        })
    
    # ==========================
    # FILES
    # ==========================
    
    @app.route("/api/files/create", methods=["POST"])
    def create_file():
        p = _json()
        return jsonify(file_manager.create_file(p.get("filename", ""), p.get("content", ""), p.get("binary", False)))
    
    @app.route("/api/files/read", methods=["POST"])
    def read_file():
        return jsonify(file_manager.read_file(_json().get("filename", "")))
    
    @app.route("/api/files/list", methods=["GET"])
    def list_files():
        return jsonify(file_manager.list_files(request.args.get("directory", ".")))
    
    # ==========================
    # SMART REPORTING
    # ==========================
    
    @app.route("/api/report/get", methods=["POST"])
    def report_get():
        """Get or create report for target"""
        target = _json().get("target", "")
        if not target:
            return jsonify({"error": "Target required"}), 400
        
        report = get_report(target)
        return jsonify({
            "success": True,
            "target": target,
            "report": report.to_dict()
        })
    
    @app.route("/api/report/finding", methods=["POST"])
    def report_finding():
        """Add finding to report"""
        p = _json()
        target = p.get("target", "")
        if not target:
            return jsonify({"error": "Target required"}), 400
        
        report = get_report(target)
        finding = Finding(
            type="vulnerability",
            severity=p.get("severity", "medium"),
            title=p.get("title", ""),
            description=p.get("description", ""),
            url=p.get("url", ""),
            evidence=p.get("evidence", ""),
            recommendation=p.get("recommendation", "")
        )
        report.add_finding(finding)
        report.save()
        
        return jsonify({
            "success": True,
            "findings_count": len(report.findings),
            "message": f"Finding added: {finding.title}"
        })
    
    @app.route("/api/report/note", methods=["POST"])
    def report_note():
        """Add note to report"""
        p = _json()
        target = p.get("target", "")
        note = p.get("note", "")
        
        if not target or not note:
            return jsonify({"error": "Target and note required"}), 400
        
        report = get_report(target)
        report.add_note(note)
        report.save()
        
        return jsonify({
            "success": True,
            "notes_count": len(report.notes),
            "message": "Note added"
        })
    
    @app.route("/api/report/next", methods=["POST"])
    def report_next():
        """Get suggested next steps"""
        target = _json().get("target", "")
        if not target:
            return jsonify({"error": "Target required"}), 400
        
        report = get_report(target)
        return jsonify({
            "success": True,
            "target": target,
            "next_steps": report.get_next_steps(),
            "stats": {
                "findings": len(report.findings),
                "subdomains": len(report.subdomains),
                "endpoints": len(report.endpoints),
                "technologies": report.technologies
            }
        })
    
    @app.route("/api/report/summary", methods=["POST"])
    def report_summary():
        """Get report summary for AI"""
        target = _json().get("target", "")
        if not target:
            return jsonify({"error": "Target required"}), 400
        
        report = get_report(target)
        return jsonify({
            "success": True,
            "target": target,
            "summary": report.generate_summary(),
            "next_steps": report.get_next_steps()
        })
    
    # ==========================
    # SMART CONTEXT (AI Auto-Load)
    # ==========================
    
    @app.route("/api/context/load", methods=["POST"])
    def context_load():
        """
        Load context for target - AI should call this FIRST before scanning.
        Returns briefing with previous findings, subdomains, notes, recommendations.
        """
        target = _json().get("target", "")
        if not target:
            return jsonify({"error": "Target required"}), 400
        
        return jsonify(load_target_context(target))
    
    @app.route("/api/context/targets", methods=["GET"])
    def context_list_targets():
        """List all previously scanned targets"""
        return jsonify(list_all_targets())
    
    @app.route("/api/context/save_scan", methods=["POST"])
    def context_save_scan():
        """Save scan result to target context"""
        p = _json()
        target = p.get("target", "")
        tool = p.get("tool", "")
        result = p.get("result", {})
        
        if not target or not tool:
            return jsonify({"error": "Target and tool required"}), 400
        
        ctx = get_context(target)
        filepath = ctx.save_scan_result(tool, result, target=target)
        
        # Auto-extract subdomains if present
        if 'stdout' in result:
            lines = result['stdout'].split('\n')
            subs = [l.strip() for l in lines if ctx.domain in l and l.strip()]
            if subs:
                ctx.add_subdomains(subs)
        
        return jsonify({
            "success": True,
            "saved_to": filepath,
            "total_scans": ctx.meta.get('total_scans', 0)
        })
    
    # ==========================
    # ADVANCED EXPLOITATION
    # ==========================
    
    @app.route("/api/exploit/auth_bypass", methods=["POST"])
    def exploit_auth_bypass():
        """Generate auth bypass test cases"""
        p = _json()
        url = p.get("url", "")
        endpoint = p.get("endpoint", "/admin")
        
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        tests = generate_auth_bypass_tests(url, endpoint)
        return jsonify({
            "success": True,
            "url": url,
            "endpoint": endpoint,
            "tests": tests,
            "total": len(tests)
        })
    
    @app.route("/api/exploit/waf_bypass", methods=["POST"])
    def exploit_waf_bypass():
        """Generate WAF bypass variants for a payload"""
        payload = _json().get("payload", "")
        if not payload:
            return jsonify({"error": "Payload required"}), 400
        
        variants = generate_waf_bypass_variants(payload)
        return jsonify({
            "success": True,
            "original": payload,
            "variants": variants,
            "total": len(variants)
        })
    
    @app.route("/api/exploit/ssti", methods=["GET"])
    def exploit_ssti():
        """Get SSTI payloads by template engine"""
        engine = request.args.get("engine", "detection")
        payloads = SSTI_PAYLOADS.get(engine, SSTI_PAYLOADS["detection"])
        return jsonify({
            "success": True,
            "engine": engine,
            "payloads": payloads,
            "all_engines": list(SSTI_PAYLOADS.keys())
        })
    
    @app.route("/api/exploit/cache_poison", methods=["POST"])
    def exploit_cache_poison():
        """Generate cache poisoning test cases"""
        url = _json().get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        tests = generate_cache_poison_tests(url)
        return jsonify({
            "success": True,
            "url": url,
            "tests": tests,
            "total": len(tests)
        })
    
    @app.route("/api/exploit/business_logic", methods=["GET"])
    def exploit_business_logic():
        """Get business logic test cases"""
        category = request.args.get("category", "all")
        tests = get_business_logic_tests(category)
        return jsonify({
            "success": True,
            "category": category,
            "tests": tests
        })
    
    # ==========================
    # SMART ANALYZER (AI)
    # ==========================
    
    @app.route("/api/ai/analyze", methods=["POST"])
    def ai_analyze():
        """AI-powered analysis of scan results"""
        p = _json()
        tool = p.get("tool", "unknown")
        result = p.get("result", {})
        
        analysis = analyze_scan(tool, result)
        return jsonify({
            "success": True,
            "analysis": analysis,
            "insights": [
                {"category": i.category, "message": i.message, "priority": i.priority}
                for i in analysis.get("insights", [])
            ]
        })
    
    @app.route("/api/ai/detect_tech", methods=["POST"])
    def ai_detect_tech():
        """Detect technologies from response"""
        p = _json()
        response = p.get("response", "")
        headers = p.get("headers", {})
        
        techs = detect_technologies(response, headers)
        vectors = []
        for tech in techs:
            if tech == "WordPress":
                vectors.extend(["wpscan", "wp_user_enum", "xmlrpc_test"])
            elif tech == "GraphQL":
                vectors.extend(["graphql_introspection", "graphql_batching"])
            elif tech == "Laravel":
                vectors.extend(["laravel_debug", "env_exposure"])
        
        return jsonify({
            "success": True,
            "technologies": techs,
            "suggested_tests": list(set(vectors))
        })
    
    @app.route("/api/ai/classify", methods=["POST"])
    def ai_classify():
        """Classify endpoint and suggest attack vectors"""
        p = _json()
        url = p.get("url", "")
        method = p.get("method", "GET")
        
        endpoint_type = classify_endpoint(url, method)
        vectors = get_attack_vectors(endpoint_type)
        
        return jsonify({
            "success": True,
            "url": url,
            "endpoint_type": endpoint_type,
            "attack_vectors": vectors
        })
    
    @app.route("/api/ai/vuln_scan", methods=["POST"])
    def ai_vuln_scan():
        """Scan response for vulnerabilities"""
        p = _json()
        response = p.get("response", "")
        url = p.get("url", "")
        
        findings = analyze_response(response, url)
        return jsonify({
            "success": True,
            "findings": findings,
            "total": len(findings),
            "summary": {
                "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                "high": sum(1 for f in findings if f.get("severity") == "high"),
                "medium": sum(1 for f in findings if f.get("severity") == "medium"),
                "low": sum(1 for f in findings if f.get("severity") == "low"),
            }
        })
    
    @app.route("/api/ai/summary", methods=["GET"])
    def ai_summary():
        """Get AI executive summary"""
        summary = analyzer.generate_executive_summary()
        return jsonify({
            "success": True,
            "summary": summary,
            "total_findings": len(analyzer.findings),
            "technologies": analyzer.technologies
        })
    
    @app.route("/api/ai/hints", methods=["POST"])
    def ai_hints():
        """Get AI hints based on context"""
        context = _json()
        hints = analyzer.get_ai_hints(context)
        return jsonify({
            "success": True,
            "hints": hints
        })
    
    # ==========================
    # SECRET SCANNER
    # ==========================
    
    @app.route("/api/secrets/scan", methods=["POST"])
    def secrets_scan():
        """
        Scan content for hardcoded secrets.
        Detects: AWS keys, API tokens, passwords, private keys, etc.
        """
        p = _json()
        content = p.get("content", "")
        source = p.get("source", "unknown")
        
        if not content:
            return jsonify({"error": "Content required"}), 400
        
        result = scan_for_secrets(content, source)
        return jsonify(result)
    
    @app.route("/api/secrets/scan_js", methods=["POST"])
    def secrets_scan_js():
        """
        Specialized JavaScript secret scanner.
        Looks for secrets in config objects, env vars, headers.
        """
        p = _json()
        js_content = p.get("content", "")
        source = p.get("source", "javascript")
        
        if not js_content:
            return jsonify({"error": "JavaScript content required"}), 400
        
        result = scan_js(js_content, source)
        return jsonify(result)
    
    @app.route("/api/secrets/scan_url", methods=["POST"])
    def secrets_scan_url():
        """Scan URL for secrets in query parameters"""
        url = _json().get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = scan_url_for_secrets(url)
        return jsonify(result)
    
    @app.route("/api/secrets/scan_response", methods=["POST"])
    def secrets_scan_response():
        """
        Fetch URL and scan response for secrets.
        Useful for scanning JS files from CDN.
        """
        url = _json().get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        # Fetch the URL
        resp = make_request(url)
        if not resp.get("success"):
            return jsonify(resp)
        
        body = resp.get("body", "")
        
        # Determine scan type based on content-type
        content_type = resp.get("headers", {}).get("Content-Type", "")
        if "javascript" in content_type or url.endswith(".js"):
            result = scan_js(body, url)
        else:
            result = scan_for_secrets(body, url)
        
        result["url"] = url
        result["content_length"] = len(body)
        return jsonify(result)
    
    @app.route("/api/secrets/patterns", methods=["GET"])
    def secrets_patterns():
        """Get all secret detection patterns"""
        patterns = get_secret_patterns()
        return jsonify({
            "success": True,
            "patterns": patterns,
            "total": len(patterns),
            "categories": list(set(p.get("description", "").split()[0] for p in patterns.values()))
        })
    
    @app.route("/api/secrets/entropy", methods=["POST"])
    def secrets_entropy():
        """Calculate entropy of a string to detect potential secrets"""
        text = _json().get("text", "")
        if not text:
            return jsonify({"error": "Text required"}), 400
        
        result = calculate_string_entropy(text)
        return jsonify({"success": True, **result})
    
    # ==========================
    # ADVANCED SCANNERS
    # ==========================
    
    @app.route("/api/scan/takeover", methods=["POST"])
    def scan_takeover():
        """Check subdomain for takeover vulnerability"""
        subdomain = _json().get("subdomain", "")
        if not subdomain:
            return jsonify({"error": "Subdomain required"}), 400
        
        result = check_subdomain_takeover(subdomain)
        return jsonify(result)
    
    @app.route("/api/scan/takeover/bulk", methods=["POST"])
    def scan_takeover_bulk():
        """Bulk subdomain takeover check"""
        subdomains = _json().get("subdomains", [])
        if not subdomains:
            return jsonify({"error": "Subdomains list required"}), 400
        
        result = scan_subdomains_takeover(subdomains[:100])  # Max 100
        return jsonify(result)
    
    @app.route("/api/scan/redirect", methods=["POST"])
    def scan_redirect():
        """Test for open redirect vulnerabilities"""
        p = _json()
        url = p.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = test_open_redirect(url, p.get("param", ""), p.get("payloads"))
        return jsonify(result)
    
    @app.route("/api/scan/crlf", methods=["POST"])
    def scan_crlf():
        """Test for CRLF injection vulnerabilities"""
        p = _json()
        url = p.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = test_crlf_injection(url, p.get("param", ""))
        return jsonify(result)
    
    @app.route("/api/scan/headers", methods=["POST"])
    def scan_headers():
        """Test for header injection vulnerabilities"""
        url = _json().get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = test_header_injection(url)
        return jsonify(result)
    
    @app.route("/api/scan/js_endpoints", methods=["POST"])
    def scan_js_endpoints():
        """Extract endpoints from JavaScript content"""
        p = _json()
        js_content = p.get("content", "")
        base_url = p.get("base_url", "")
        
        if not js_content:
            return jsonify({"error": "JavaScript content required"}), 400
        
        result = extract_js_endpoints(js_content, base_url)
        return jsonify(result)
    
    @app.route("/api/scan/js_files", methods=["POST"])
    def scan_multiple_js():
        """Fetch and scan multiple JS files for endpoints"""
        urls = _json().get("urls", [])
        if not urls:
            return jsonify({"error": "JS URLs required"}), 400
        
        result = scan_js_files(urls[:20])  # Max 20
        return jsonify(result)
    
    @app.route("/api/scan/params", methods=["POST"])
    def scan_params():
        """Discover hidden parameters"""
        p = _json()
        url = p.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = discover_params(url, p.get("wordlist"), p.get("method", "GET"))
        return jsonify(result)
    
    @app.route("/api/scan/quick", methods=["POST"])
    def scan_quick_vuln():
        """Quick vulnerability scan (redirect, CRLF, headers)"""
        url = _json().get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = quick_vuln_scan(url)
        return jsonify(result)
    
    # ==========================
    # ADVANCED ATTACKS
    # ==========================
    
    @app.route("/api/attack/race", methods=["POST"])
    def attack_race():
        """Test for race condition vulnerabilities"""
        p = _json()
        url = p.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = test_race_condition(
            url,
            method=p.get("method", "POST"),
            data=p.get("data"),
            headers=p.get("headers"),
            concurrent_requests=min(p.get("count", 20), 50)
        )
        return jsonify(result)
    
    @app.route("/api/attack/graphql", methods=["POST"])
    def attack_graphql():
        """Test GraphQL endpoint for vulnerabilities"""
        url = _json().get("url", "")
        if not url:
            return jsonify({"error": "GraphQL URL required"}), 400
        
        result = test_graphql_endpoint(url, _json().get("headers"))
        return jsonify(result)
    
    @app.route("/api/attack/xxe", methods=["GET"])
    def attack_xxe():
        """Generate XXE payloads"""
        callback = request.args.get("callback", "")
        result = generate_xxe_payloads(callback)
        return jsonify(result)
    
    @app.route("/api/attack/jwt/none", methods=["POST"])
    def attack_jwt_none():
        """Generate JWT none algorithm attack tokens"""
        token = _json().get("token", "")
        if not token:
            return jsonify({"error": "JWT token required"}), 400
        
        result = jwt_none_attack(token)
        return jsonify(result)
    
    @app.route("/api/attack/jwt/confusion", methods=["POST"])
    def attack_jwt_confusion():
        """Generate JWT algorithm confusion attack tokens"""
        p = _json()
        token = p.get("token", "")
        if not token:
            return jsonify({"error": "JWT token required"}), 400
        
        result = jwt_key_confusion(token, p.get("public_key", ""))
        return jsonify(result)
    
    @app.route("/api/attack/jwt/inject", methods=["POST"])
    def attack_jwt_inject():
        """Generate JWT claim injection variants"""
        p = _json()
        token = p.get("token", "")
        if not token:
            return jsonify({"error": "JWT token required"}), 400
        
        result = jwt_claim_injection(token, p.get("claims"))
        return jsonify(result)
    
    @app.route("/api/attack/ssrf/payloads", methods=["GET"])
    def attack_ssrf_payloads():
        """Generate advanced SSRF bypass payloads"""
        target = request.args.get("target", "127.0.0.1")
        callback = request.args.get("callback", "")
        result = generate_ssrf_payloads(target, callback)
        return jsonify(result)
    
    @app.route("/api/attack/dom_xss", methods=["POST"])
    def attack_dom_xss():
        """Analyze JavaScript for DOM XSS vulnerabilities"""
        js_content = _json().get("content", "")
        if not js_content:
            return jsonify({"error": "JavaScript content required"}), 400
        
        result = analyze_dom_xss(js_content)
        return jsonify(result)
    
    @app.route("/api/attack/nosql", methods=["GET"])
    def attack_nosql():
        """Generate NoSQL injection payloads"""
        param = request.args.get("param", "username")
        result = generate_nosql_payloads(param)
        return jsonify(result)
    
    @app.route("/api/attack/xss/advanced", methods=["GET"])
    def attack_xss_advanced():
        """Generate advanced context-aware XSS payloads"""
        context = request.args.get("context", "html")
        result = generate_xss_payloads(context)
        return jsonify(result)
    
    @app.route("/api/attack/sqli/advanced", methods=["GET"])
    def attack_sqli_advanced():
        """Generate database-specific SQL injection payloads"""
        db_type = request.args.get("db", "mysql")
        result = generate_sqli_payloads(db_type)
        return jsonify(result)
    
    # ==========================
    # MANUAL TESTING HELPERS
    # ==========================
    
    @app.route("/api/manual/mutate", methods=["POST"])
    def manual_mutate_payload():
        """Mutate a payload using various techniques"""
        p = _json()
        payload = p.get("payload", "")
        techniques = p.get("techniques", ["case", "encode", "whitespace", "comments"])
        
        mutations = mutate_payload(payload, techniques)
        return jsonify({
            "success": True,
            "original": payload,
            "mutations": mutations,
            "count": len(mutations)
        })
    
    @app.route("/api/manual/polyglot", methods=["GET"])
    def manual_polyglot():
        """Get polyglot payloads for a vulnerability type"""
        vuln_type = request.args.get("type", "xss")
        payloads = generate_polyglot(vuln_type)
        return jsonify({
            "success": True,
            "type": vuln_type,
            "payloads": payloads,
            "count": len(payloads)
        })
    
    @app.route("/api/manual/rate-limit", methods=["POST"])
    def manual_rate_limit():
        """Test rate limiting on an endpoint"""
        p = _json()
        url = p.get("url", "")
        count = p.get("count", 20)
        delay = p.get("delay", 0.1)
        
        if not url:
            return jsonify({"success": False, "error": "URL required"})
        
        result = test_rate_limit(url, count, delay)
        return jsonify({"success": True, **result})
    
    @app.route("/api/manual/diff", methods=["POST"])
    def manual_diff_responses():
        """Compare two HTTP responses"""
        p = _json()
        resp1 = p.get("response1", {})
        resp2 = p.get("response2", {})
        
        diff = diff_responses(resp1, resp2)
        return jsonify({"success": True, **diff})
    
    @app.route("/api/manual/idor", methods=["POST"])
    def manual_idor_tests():
        """Generate IDOR test cases for a parameter value"""
        value = _json().get("value", "")
        tests = generate_idor_tests(value)
        return jsonify({
            "success": True,
            "original": value,
            "tests": tests,
            "count": len(tests)
        })
    
    @app.route("/api/manual/privesc", methods=["GET"])
    def manual_privesc_tests():
        """Generate privilege escalation test cases"""
        role = request.args.get("role", "user")
        tests = generate_privilege_escalation_tests(role)
        return jsonify({
            "success": True,
            "current_role": role,
            "tests": tests,
            "count": len(tests)
        })
    
    @app.route("/api/manual/auth-bypass", methods=["POST"])
    def manual_auth_bypass():
        """Generate authentication bypass test cases"""
        endpoint = _json().get("endpoint", "/admin")
        tests = generate_auth_bypass_tests(endpoint)
        return jsonify({
            "success": True,
            "endpoint": endpoint,
            "tests": tests,
            "count": len(tests)
        })
    
    @app.route("/api/manual/analyze-error", methods=["POST"])
    def manual_analyze_error():
        """Analyze error response for information disclosure"""
        response = _json().get("response", {})
        analysis = analyze_error_response(response)
        return jsonify({"success": True, **analysis})
    
    @app.route("/api/manual/extract-secrets", methods=["POST"])
    def manual_extract_secrets():
        """Extract secrets from HTTP response"""
        response = _json().get("response", {})
        secrets = extract_secrets_from_response(response)
        return jsonify({
            "success": True,
            "secrets": secrets,
            "count": len(secrets)
        })
    
    @app.route("/api/manual/suggest", methods=["POST"])
    def manual_suggest_tests():
        """Suggest next tests based on findings"""
        findings = _json().get("findings", [])
        suggestions = suggest_next_tests(findings)
        return jsonify({
            "success": True,
            "suggestions": suggestions,
            "count": len(suggestions)
        })
    
    # ==========================
    # ADVANCED ATTACK SESSION
    # ==========================
    
    @app.route("/api/attack/session/create", methods=["POST"])
    def attack_session_create():
        """
        Create an advanced attack session with AI-driven orchestration.
        
        Input: {url, auth_headers?, cookies?}
        Returns: Session info with fingerprinting and suggestions
        """
        p = _json()
        url = p.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = create_attack_session(
            url,
            auth_headers=p.get("auth_headers"),
            cookies=p.get("cookies")
        )
        return jsonify(result)
    
    @app.route("/api/attack/session/<session_id>/analyze", methods=["GET"])
    def attack_session_analyze(session_id):
        """Get AI-driven analysis and suggestions for a session"""
        session = get_session(session_id)
        if not session:
            return jsonify({"error": "Session not found"}), 404
        
        suggestions = session.analyze_and_suggest()
        return jsonify(suggestions)
    
    @app.route("/api/attack/session/<session_id>/run", methods=["POST"])
    def attack_session_run(session_id):
        """
        Run specific attack type in a session.
        
        Input: {attack_type, params?, intensity?, waf_bypass_level?, max_requests?}
        """
        session = get_session(session_id)
        if not session:
            return jsonify({"error": "Session not found"}), 404
        
        p = _json()
        result = session.run_attack(
            attack_type=p.get("attack_type", "injection"),
            params=p.get("params"),
            custom_payloads=p.get("custom_payloads"),
            intensity=p.get("intensity", "medium"),
            waf_bypass_level=p.get("waf_bypass_level", 1),
            max_requests=p.get("max_requests", 100)
        )
        return jsonify(result)
    
    @app.route("/api/attack/session/<session_id>/idor", methods=["POST"])
    def attack_session_idor(session_id):
        """Run specialized IDOR test in a session"""
        session = get_session(session_id)
        if not session:
            return jsonify({"error": "Session not found"}), 404
        
        p = _json()
        result = session.run_idor_test(
            id_param=p.get("param", "id"),
            current_value=p.get("value", "1")
        )
        return jsonify(result)
    
    @app.route("/api/attack/session/<session_id>/auth-bypass", methods=["POST"])
    def attack_session_auth_bypass(session_id):
        """Run auth bypass test in a session"""
        session = get_session(session_id)
        if not session:
            return jsonify({"error": "Session not found"}), 404
        
        endpoint = _json().get("endpoint")
        result = session.run_auth_bypass_test(endpoint)
        return jsonify(result)
    
    @app.route("/api/attack/session/<session_id>/report", methods=["GET"])
    def attack_session_report(session_id):
        """Get comprehensive session report"""
        session = get_session(session_id)
        if not session:
            return jsonify({"error": "Session not found"}), 404
        
        return jsonify(session.get_report())
    
    @app.route("/api/attack/quick", methods=["POST"])
    def attack_quick():
        """
        Run a quick automated attack without manual session management.
        
        Input: {url, attack_types?, intensity?}
        """
        p = _json()
        url = p.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = run_quick_attack(
            url,
            attack_types=p.get("attack_types"),
            intensity=p.get("intensity", "medium")
        )
        return jsonify(result)
    
    @app.route("/api/attack/fingerprint", methods=["POST"])
    def attack_fingerprint():
        """Fingerprint an endpoint to determine type and suggest attacks"""
        p = _json()
        url = p.get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        # Optionally get response first
        response = None
        if p.get("fetch_response", True):
            response = make_request(url, timeout=30)
        
        endpoint_type, confidence, reasons = fingerprint_endpoint(url, response)
        return jsonify({
            "success": True,
            "url": url,
            "endpoint_type": endpoint_type.value,
            "confidence": confidence,
            "reasons": reasons,
            "response_status": response.get("status_code") if response else None
        })
    
    # ==========================
    # DEEP SECRET HUNTING
    # ==========================
    
    @app.route("/api/secrets/hunt", methods=["POST"])
    def secrets_deep_hunt():
        """
        Run comprehensive multi-stage secret hunting on a domain.
        
        Input: {domain, max_urls?, max_js?, stages?}
        """
        p = _json()
        domain = p.get("domain", "")
        if not domain:
            return jsonify({"error": "Domain required"}), 400
        
        result = deep_secret_hunt(
            domain,
            max_urls=p.get("max_urls", 100),
            max_js=p.get("max_js", 50),
            stages=p.get("stages"),
            local_paths=p.get("local_paths")
        )
        return jsonify(result)
    
    @app.route("/api/secrets/local", methods=["POST"])
    def secrets_local_scan():
        """
        Scan local files/directories for secrets (no network requests).
        
        Input: {paths: ["/path/to/project", "/path/to/file.env"]}
        """
        paths = _json().get("paths", [])
        if not paths:
            return jsonify({"error": "Paths required"}), 400
        
        result = scan_local_secrets(paths)
        return jsonify(result)
    
    @app.route("/api/secrets/quick", methods=["POST"])
    def secrets_quick_scan():
        """Quick scan a single URL for secrets"""
        url = _json().get("url", "")
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        result = quick_secret_scan(url)
        return jsonify(result)
    
    @app.route("/api/secrets/js_hunt", methods=["POST"])
    def secrets_js_hunt():
        """
        Scan multiple JS files for secrets.
        
        Input: {urls: []}
        """
        urls = _json().get("urls", [])
        if not urls:
            return jsonify({"error": "JS URLs required"}), 400
        
        result = scan_js_for_secrets(urls[:50])  # Limit to 50
        return jsonify(result)
    
    # ==========================
    # SELF-LEARNING AI
    # ==========================
    
    @app.route("/api/ai/status", methods=["GET"])
    def ai_status():
        """Get AI system status including local models and learning store"""
        orchestrator = get_orchestrator()
        store = get_store()
        
        return jsonify({
            "orchestrator": orchestrator.get_status(),
            "learning_store": store.get_stats()
        })
    
    @app.route("/api/ai/classify_secret", methods=["POST"])
    def ai_classify_secret():
        """Classify a secret as real or false positive using local AI"""
        features = _json()
        orchestrator = get_orchestrator()
        response = orchestrator.classify_secret(features)
        return jsonify(response.to_dict())
    
    @app.route("/api/ai/score_endpoint", methods=["POST"])
    def ai_score_endpoint():
        """Score an endpoint's vulnerability risk using local AI"""
        features = _json()
        orchestrator = get_orchestrator()
        response = orchestrator.score_endpoint(features)
        return jsonify(response.to_dict())
    
    @app.route("/api/ai/rank_payloads", methods=["POST"])
    def ai_rank_payloads():
        """Rank payloads by predicted effectiveness"""
        data = _json()
        payloads = data.get("payloads", [])
        context = data.get("context", {})
        
        orchestrator = get_orchestrator()
        response = orchestrator.rank_payloads(payloads, context)
        return jsonify(response.to_dict())
    
    @app.route("/api/ai/train", methods=["POST"])
    def ai_train():
        """Train local AI models from learning store data"""
        orchestrator = get_orchestrator()
        results = orchestrator.train_local_models()
        return jsonify(results)
    
    @app.route("/api/learning/findings", methods=["GET"])
    def learning_get_findings():
        """Get findings from learning store"""
        store = get_store()
        
        finding_type = request.args.get("type")
        target = request.args.get("target")
        label = request.args.get("label")
        limit = int(request.args.get("limit", 100))
        
        findings = store.get_findings(
            finding_type=finding_type,
            target=target,
            label=label,
            limit=limit
        )
        
        return jsonify({
            "findings": [f.to_dict() for f in findings],
            "count": len(findings)
        })
    
    @app.route("/api/learning/label", methods=["POST"])
    def learning_label_finding():
        """Label a finding for training"""
        data = _json()
        finding_id = data.get("finding_id")
        label = data.get("label")
        notes = data.get("notes")
        
        if not finding_id or not label:
            return jsonify({"error": "finding_id and label required"}), 400
        
        # Validate label
        valid_labels = [l.value for l in FeedbackLabel]
        if label not in valid_labels:
            return jsonify({"error": f"Invalid label. Must be one of: {valid_labels}"}), 400
        
        store = get_store()
        success = store.label_finding(finding_id, label, notes)
        
        return jsonify({"success": success})
    
    @app.route("/api/learning/stats", methods=["GET"])
    def learning_stats():
        """Get learning store statistics"""
        store = get_store()
        return jsonify(store.get_stats())
    
    @app.route("/api/learning/export", methods=["POST"])
    def learning_export():
        """Export learning data to JSON"""
        output_path = _json().get("path", "/tmp/spectreweb_learning_export.json")
        store = get_store()
        success = store.export_to_json(output_path)
        
        return jsonify({
            "success": success,
            "path": output_path
        })
    
    @app.route("/api/ai/auto_train", methods=["POST"])
    def ai_auto_train():
        """
        Automatically train models if enough labeled data is available.
        
        Conditions:
        - At least 50 labeled samples
        - At least 10 new samples since last train
        """
        orchestrator = get_orchestrator()
        result = orchestrator.auto_train_if_ready()
        return jsonify(result)
    
    @app.route("/api/ai/insights", methods=["GET"])
    def ai_insights():
        """
        Get smart insights based on learning history.
        
        Returns:
        - Most effective attack types
        - Common false positive patterns
        - Recommendations
        """
        orchestrator = get_orchestrator()
        return jsonify(orchestrator.get_smart_insights())
    
    @app.route("/api/ai/filter_secrets", methods=["POST"])
    def ai_filter_secrets():
        """
        Use local AI to filter/rank secrets by likelihood of being real.
        
        Input: {secrets: [{secret_type, entropy, ...}, ...]}
        Output: Secrets sorted by is_real probability, with AI scores
        """
        secrets = _json().get("secrets", [])
        orchestrator = get_orchestrator()
        
        results = []
        for secret in secrets:
            response = orchestrator.classify_secret(secret)
            if response.success:
                results.append({
                    **secret,
                    "ai_score": response.result.get("score", 0.5),
                    "ai_is_real": response.result.get("is_real", True),
                    "ai_confidence": response.confidence,
                    "model_used": response.result.get("model_used", "heuristic")
                })
        
        # Sort by AI score descending (most likely real first)
        results.sort(key=lambda x: x.get("ai_score", 0), reverse=True)
        
        return jsonify({
            "filtered_secrets": results,
            "total": len(results),
            "likely_real": len([r for r in results if r.get("ai_is_real", True)]),
            "likely_fp": len([r for r in results if not r.get("ai_is_real", True)])
        })

    # ==========================
    # JOB QUEUE
    # ==========================
    
    @app.route("/api/jobs", methods=["GET"])
    def list_jobs():
        """List background jobs"""
        target = request.args.get("target")
        status = request.args.get("status")
        limit = int(request.args.get("limit", 50))
        
        status_enum = None
        if status:
            try:
                status_enum = JobStatus(status)
            except ValueError:
                pass
        
        queue = get_job_queue()
        jobs = queue.list_jobs(target=target, status=status_enum, limit=limit)
        return jsonify({"jobs": jobs, "total": len(jobs)})
    
    @app.route("/api/jobs/<job_id>", methods=["GET"])
    def get_job(job_id):
        """Get job status"""
        queue = get_job_queue()
        status = queue.get_status(job_id)
        if not status:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(status)
    
    @app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
    def cancel_job(job_id):
        """Cancel a running job"""
        queue = get_job_queue()
        if queue.cancel(job_id):
            return jsonify({"success": True, "message": "Cancellation requested"})
        return jsonify({"error": "Job not found or already completed"}), 400
    
    @app.route("/api/jobs/stats", methods=["GET"])
    def job_stats():
        """Get job queue statistics"""
        queue = get_job_queue()
        return jsonify(queue.get_stats())

    # ==========================
    # RATE LIMITER
    # ==========================
    
    @app.route("/api/rate-limit/stats", methods=["GET"])
    def rate_limit_stats():
        """Get rate limiter statistics"""
        limiter = get_rate_limiter()
        return jsonify(limiter.get_stats())
    
    @app.route("/api/rate-limit/configure", methods=["POST"])
    def configure_rate_limit():
        """Configure rate limit for a domain"""
        params = _json()
        domain = params.get("domain")
        if not domain:
            return jsonify({"error": "Domain required"}), 400
        
        limiter = get_rate_limiter()
        limiter.configure_domain(
            domain,
            requests_per_second=params.get("requests_per_second"),
            burst_size=params.get("burst_size")
        )
        return jsonify({"success": True, "domain": domain})
    
    @app.route("/api/rate-limit/reset", methods=["POST"])
    def reset_rate_limit():
        """Reset rate limiter state"""
        params = _json()
        domain = params.get("domain")
        limiter = get_rate_limiter()
        limiter.reset(domain)
        return jsonify({"success": True})

    # ==========================
    # PLUGIN SYSTEM
    # ==========================
    
    @app.route("/api/plugins", methods=["GET"])
    def get_plugins():
        """List all registered tool plugins"""
        tools = list_tools()
        return jsonify({
            "success": True,
            "tools": tools,
            "total": len(tools),
            "available": len([t for t in tools if t.get("available")])
        })
    
    @app.route("/api/plugins/<name>", methods=["GET"])
    def get_plugin_info(name):
        """Get info about a specific plugin"""
        tool = get_tool(name)
        if not tool:
            return jsonify({"error": f"Tool '{name}' not found"}), 404
        return jsonify({
            "success": True,
            "name": tool.name,
            "category": tool.category.value,
            "description": tool.description,
            "binary": tool.binary_name,
            "available": tool.is_available(),
            "default_timeout": tool.default_timeout
        })
    
    @app.route("/api/plugins/<name>/run", methods=["POST"])
    def run_plugin(name):
        """Run a tool plugin"""
        tool = get_tool(name)
        if not tool:
            return jsonify({"error": f"Tool '{name}' not found"}), 404
        
        if not tool.is_available():
            return jsonify({"error": f"Tool '{name}' is not installed"}), 400
        
        params = _json()
        target = params.get("target", "")
        if not target:
            return jsonify({"error": "Target required"}), 400
        
        # Extract tool-specific options
        timeout = params.get("timeout", tool.default_timeout)
        options = {k: v for k, v in params.items() if k not in ("target", "timeout")}
        
        result = tool.run(target, timeout=timeout, **options)
        telemetry.record(name, result.success)
        
        return jsonify(result.to_dict())
    
    @app.route("/api/plugins/<name>/run-async", methods=["POST"])
    def run_plugin_async(name):
        """Run a tool plugin asynchronously (returns job_id)"""
        tool = get_tool(name)
        if not tool:
            return jsonify({"error": f"Tool '{name}' not found"}), 404
        
        if not tool.is_available():
            return jsonify({"error": f"Tool '{name}' is not installed"}), 400
        
        params = _json()
        target = params.get("target", "")
        if not target:
            return jsonify({"error": "Target required"}), 400
        
        timeout = params.get("timeout", tool.default_timeout)
        options = {k: v for k, v in params.items() if k not in ("target", "timeout")}
        
        def run_tool_job(job, tool_instance, tgt, tout, opts):
            job.add_log(f"Running {tool_instance.name} on {tgt}")
            result = tool_instance.run(tgt, timeout=tout, **opts)
            job.update_progress(100, "Completed")
            return result.to_dict()
        
        queue = get_job_queue()
        job_id = queue.submit(
            name=f"plugin_{name}",
            target=target,
            func=run_tool_job,
            tool_instance=tool,
            tgt=target,
            tout=timeout,
            opts=options,
            metadata={"tool": name, "target": target}
        )
        
        return jsonify({
            "success": True,
            "job_id": job_id,
            "message": f"Tool {name} started in background"
        })
