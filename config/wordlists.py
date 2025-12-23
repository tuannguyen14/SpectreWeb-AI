"""SecLists Wordlist Configuration - AI-Friendly Descriptions"""
import os
from typing import Dict, Any, List

_seclists_env = os.environ.get("SPECTREWEB_SECLISTS_PATH") or os.environ.get("SECLISTS_PATH")
_seclists_candidates = [
    _seclists_env,
    "/usr/share/SecLists",
    "/usr/share/seclists",
    "/opt/SecLists",
    "/opt/seclists",
]
SECLISTS_PATH = "/usr/share/SecLists"
for _cand in _seclists_candidates:
    if _cand and os.path.isdir(_cand):
        SECLISTS_PATH = _cand
        break

WORDLISTS = {
    # Directory Discovery
    "dir_small": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
        "purpose": "Quick directory enumeration - 87K entries",
        "use_when": "Initial recon, time-limited",
        "category": "directory"
    },
    "dir_medium": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
        "purpose": "Standard directory enumeration - 220K entries",
        "use_when": "Normal pentesting",
        "category": "directory"
    },
    "dir_big": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt",
        "purpose": "Comprehensive enumeration - 1.2M entries",
        "use_when": "Thorough testing, bug bounty",
        "category": "directory"
    },
    "common": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/common.txt",
        "purpose": "Most common web paths - 4.7K entries",
        "use_when": "Very quick initial scan",
        "category": "directory"
    },
    
    # API Discovery
    "api_endpoints": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/api/api-endpoints.txt",
        "purpose": "Common API endpoints",
        "use_when": "API testing, REST/GraphQL",
        "category": "api"
    },
    "api_objects": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/api/objects.txt",
        "purpose": "API object names",
        "use_when": "IDOR testing",
        "category": "api"
    },
    
    # Parameters
    "params_common": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/burp-parameter-names.txt",
        "purpose": "Common HTTP parameters - 6.4K entries",
        "use_when": "Parameter discovery",
        "category": "params"
    },
    
    # Subdomains
    "subdomains_5k": {
        "path": f"{SECLISTS_PATH}/Discovery/DNS/subdomains-top1million-5000.txt",
        "purpose": "Top 5000 subdomains",
        "use_when": "Quick subdomain enum",
        "category": "subdomain"
    },
    "subdomains_20k": {
        "path": f"{SECLISTS_PATH}/Discovery/DNS/subdomains-top1million-20000.txt",
        "purpose": "Top 20000 subdomains",
        "use_when": "Standard subdomain enum",
        "category": "subdomain"
    },
    
    # Vulnerability Payloads
    "sqli": {
        "path": f"{SECLISTS_PATH}/Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        "purpose": "SQL injection payloads",
        "use_when": "SQLi testing",
        "category": "vuln"
    },
    "sqli_blind": {
        "path": f"{SECLISTS_PATH}/Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt",
        "purpose": "Blind SQL injection payloads",
        "use_when": "Blind SQLi testing",
        "category": "vuln"
    },
    "xss": {
        "path": f"{SECLISTS_PATH}/Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",
        "purpose": "XSS payloads by Jhaddix",
        "use_when": "XSS testing",
        "category": "vuln"
    },
    "xss_polyglot": {
        "path": f"{SECLISTS_PATH}/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",
        "purpose": "XSS polyglots for WAF bypass",
        "use_when": "Bypassing filters",
        "category": "vuln"
    },
    "lfi": {
        "path": f"{SECLISTS_PATH}/Fuzzing/LFI/LFI-Jhaddix.txt",
        "purpose": "LFI/Path traversal payloads",
        "use_when": "LFI testing",
        "category": "vuln"
    },
    "lfi_linux": {
        "path": f"{SECLISTS_PATH}/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        "purpose": "Linux-specific LFI paths",
        "use_when": "LFI on Linux",
        "category": "vuln"
    },
    "ssti": {
        "path": f"{SECLISTS_PATH}/Fuzzing/template-engines-expression.txt",
        "purpose": "SSTI payloads",
        "use_when": "Template injection",
        "category": "vuln"
    },
    "xxe": {
        "path": f"{SECLISTS_PATH}/Fuzzing/XXE-Fuzzing.txt",
        "purpose": "XXE payloads",
        "use_when": "XML injection",
        "category": "vuln"
    },
    "cmd_injection": {
        "path": f"{SECLISTS_PATH}/Fuzzing/command-injection-commix.txt",
        "purpose": "Command injection payloads",
        "use_when": "OS command injection",
        "category": "vuln"
    },
    
    # Authentication
    "passwords": {
        "path": f"{SECLISTS_PATH}/Passwords/Common-Credentials/10k-most-common.txt",
        "purpose": "Top 10K common passwords",
        "use_when": "Password spraying",
        "category": "auth"
    },
    "usernames": {
        "path": f"{SECLISTS_PATH}/Usernames/top-usernames-shortlist.txt",
        "purpose": "Common usernames",
        "use_when": "Username enumeration",
        "category": "auth"
    },
    
    # CMS
    "wordpress": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "purpose": "WordPress paths",
        "use_when": "WordPress pentesting",
        "category": "cms"
    },
    
    # Bypass
    "sqli_auth_bypass": {
        "path": f"{SECLISTS_PATH}/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
        "purpose": "SQL injection auth bypass payloads",
        "use_when": "Login bypass testing",
        "category": "bypass"
    },
    
    # Sensitive Files
    "backup_files": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/Common-DB-Backups.txt",
        "purpose": "Database backup filenames",
        "use_when": "Finding exposed backups",
        "category": "sensitive"
    },
    "quickhits": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/quickhits.txt",
        "purpose": "Sensitive/interesting files",
        "use_when": "Quick sensitive file check",
        "category": "sensitive"
    },
}

def get_wordlist(name: str) -> Dict[str, Any]:
    """Get wordlist info by name"""
    if name in WORDLISTS:
        wl = WORDLISTS[name].copy()
        wl["name"] = name
        if os.path.exists(wl["path"]):
            wl["success"] = True
            return wl
        return {"success": False, "error": f"File not found: {wl['path']}"}
    return {"success": False, "error": f"Unknown wordlist: {name}"}

def resolve_wordlist_path(name_or_path: str) -> str:
    """
    Resolve wordlist name to full path.
    If already a path, return as-is.
    If a wordlist name, return the full path.
    
    Examples:
        resolve_wordlist_path("dir_medium") -> "/usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
        resolve_wordlist_path("/path/to/custom.txt") -> "/path/to/custom.txt"
    """
    # 1. Try to resolve as wordlist name (alias) first
    if name_or_path in WORDLISTS:
        return WORDLISTS[name_or_path]["path"]

    # 2. If it exists as a path, return it
    if os.path.exists(name_or_path):
        return name_or_path

    # 3. If it looks like a path but doesn't exist, try to fix common casing issues
    if "/" in name_or_path:
        # Auto-correct lowercase seclists to SecLists
        if "/usr/share/seclists" in name_or_path.lower():
            fixed_path = name_or_path.replace("/usr/share/seclists", "/usr/share/SecLists")
            # Handle case where user might have typed /usr/share/SecLists manually but mixed other parts
            if not os.path.exists(fixed_path):
                 # Last ditch: simple string replace if it was purely lowercase mismatch
                 fixed_path = name_or_path.replace("seclists", "SecLists")
            
            if os.path.exists(fixed_path):
                return fixed_path
    
    # Return original if we can't fix it (let the tool fail naturally)
    return name_or_path

def suggest_wordlist(task: str) -> List[Dict]:
    """Suggest wordlists based on task description"""
    task = task.lower()
    suggestions = []
    
    keywords = {
        "directory": ["dir", "directory", "path", "enum"],
        "api": ["api", "rest", "graphql", "endpoint"],
        "params": ["param", "parameter", "query"],
        "subdomain": ["subdomain", "dns", "domain"],
        "sqli": ["sql", "sqli", "injection", "database"],
        "xss": ["xss", "cross-site", "script"],
        "lfi": ["lfi", "file inclusion", "traversal"],
        "ssti": ["ssti", "template"],
        "xxe": ["xxe", "xml"],
        "cmd": ["command injection", "rce", "cmd"],
        "auth": ["password", "brute", "login"],
        "cms": ["wordpress", "wp", "drupal", "joomla"],
        "bypass": ["403", "forbidden", "bypass"],
        "sensitive": ["backup", "sensitive", "exposed"],
    }
    
    for wl_name, wl_data in WORDLISTS.items():
        category = wl_data.get("category", "")
        if category in keywords:
            if any(kw in task for kw in keywords[category]):
                suggestions.append({**wl_data, "name": wl_name})
    
    return suggestions if suggestions else [
        {**WORDLISTS["common"], "name": "common"},
        {**WORDLISTS["dir_medium"], "name": "dir_medium"}
    ]
