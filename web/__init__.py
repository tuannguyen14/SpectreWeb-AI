"""SpectreWeb Web Module"""
from .client import make_request, DEFAULT_HEADERS
from .extractor import extract_links, extract_forms, extract_comments, extract_js_files, extract_endpoints_from_js
from .payloads import (
    encode_payload, decode_payload, 
    XSS_PAYLOADS, SQLI_PAYLOADS, LFI_PAYLOADS, SSRF_PAYLOADS,
    analyze_jwt, identify_hash, generate_hashes,
    analyze_cors_headers, compare_responses, detect_idor_params
)
from .ai_hints import (
    analyze_for_0day, suggest_next_steps, generate_smart_payloads,
    get_thinking_prompt, INTERESTING_PATTERNS, THINKING_PROMPTS
)
from .exploits import (
    generate_auth_bypass_tests, generate_hpp_payloads,
    PROTOTYPE_POLLUTION_PAYLOADS, check_prototype_pollution_vectors,
    SSTI_PAYLOADS, detect_template_engine,
    detect_deserialization_risk, generate_cache_poison_tests,
    generate_smuggling_payloads, get_business_logic_tests,
    generate_waf_bypass_variants, AUTH_BYPASS_PAYLOADS,
    scan_exposed_files, scan_cms, discover_vhosts
)
from .secrets import (
    scan_for_secrets, scan_js, scan_url_for_secrets,
    get_secret_patterns, calculate_string_entropy,
    SecretScanner, SECRET_PATTERNS
)

# Advanced modules
from .deep_secrets import (
    DeepSecretHunter, deep_secret_hunt, quick_secret_scan,
    scan_js_for_secrets, validate_secret, scan_local_secrets,
    SecretCategory, SecretRisk
)

# Origin IP Finder
from .origin_finder import (
    find_origin, quick_origin_check, verify_origin_ip,
    query_crt_sh, extract_domains_from_crt, detect_cdn,
    query_shodan_internetdb, query_fofa, fofa_search_by_favicon,
    fofa_search_by_cert, fofa_search_by_body,
    query_quake, quake_search_by_favicon, quake_search_by_cert, quake_search_by_body,
    query_passive_dns_multi, query_alienvault_otx, query_hackertarget, query_validin,
    brute_subdomains, load_subdomain_wordlist,
    OriginCandidate, OriginResult
)

__all__ = [
    "make_request", "DEFAULT_HEADERS",
    "extract_links", "extract_forms", "extract_comments", "extract_js_files",
    "extract_endpoints_from_js",
    "encode_payload", "decode_payload", "XSS_PAYLOADS", "SQLI_PAYLOADS",
    "LFI_PAYLOADS", "SSRF_PAYLOADS", "analyze_jwt", "identify_hash",
    "generate_hashes", "analyze_cors_headers", "compare_responses",
    "detect_idor_params",
    "analyze_for_0day", "suggest_next_steps", "generate_smart_payloads",
    "get_thinking_prompt", "INTERESTING_PATTERNS", "THINKING_PROMPTS",
    "generate_auth_bypass_tests", "generate_hpp_payloads",
    "PROTOTYPE_POLLUTION_PAYLOADS", "check_prototype_pollution_vectors",
    "SSTI_PAYLOADS", "detect_template_engine", "detect_deserialization_risk",
    "generate_cache_poison_tests", "generate_smuggling_payloads",
    "get_business_logic_tests", "generate_waf_bypass_variants",
    "AUTH_BYPASS_PAYLOADS",
    "scan_exposed_files", "scan_cms", "discover_vhosts",
    "scan_for_secrets", "scan_js", "scan_url_for_secrets",
    "get_secret_patterns", "calculate_string_entropy",
    "SecretScanner", "SECRET_PATTERNS",
    "DeepSecretHunter", "deep_secret_hunt", "quick_secret_scan",
    "scan_js_for_secrets", "validate_secret", "scan_local_secrets",
    "SecretCategory", "SecretRisk",
    "find_origin", "quick_origin_check", "verify_origin_ip",
    "query_crt_sh", "extract_domains_from_crt", "detect_cdn",
    "query_shodan_internetdb", "query_fofa", "fofa_search_by_favicon",
    "fofa_search_by_cert", "fofa_search_by_body",
    "query_quake", "quake_search_by_favicon", "quake_search_by_cert", "quake_search_by_body",
    "query_passive_dns_multi", "query_alienvault_otx", "query_hackertarget", "query_validin",
    "brute_subdomains", "load_subdomain_wordlist",
    "OriginCandidate", "OriginResult",
]
