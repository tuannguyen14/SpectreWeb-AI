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
    "D:\\SecLists",
    "C:\\SecLists",
    os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "SecLists"),
]
SECLISTS_PATH = None
for _cand in _seclists_candidates:
    if _cand and os.path.isdir(_cand):
        SECLISTS_PATH = _cand
        break
if SECLISTS_PATH is None:
    SECLISTS_PATH = "/usr/share/SecLists"  # fallback (Linux default)

WORDLISTS = {
    # Directory Discovery
    "dir_medium": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
        "purpose": "Extended directory enumeration - 220K entries (Slow)",
        "use_when": "Thorough testing only, after smaller lists",
        "priority": 90,
        "category": "directory"
    },
    "dir_big": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt",
        "purpose": "Comprehensive enumeration - 1.2M entries (Very Slow)",
        "use_when": "Exhaustive testing, bug bounty",
        "priority": 100,
        "category": "directory"
    },
    "common": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/common.txt",
        "purpose": "Standard web paths - 4.7K entries (Fast & Recommended)",
        "use_when": "Initial discovery and standard scans",
        "priority": 10,
        "category": "directory"
    },
    "big": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/big.txt",
        "purpose": "Large common paths - 20K entries (Balanced)",
        "use_when": "Standard pentesting after common.txt",
        "priority": 20,
        "category": "directory"
    },
    "dir_small": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
        "purpose": "Quick directory enumeration - 87K entries",
        "use_when": "Secondary scan if common/big fail",
        "priority": 30,
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
        "path": f"{SECLISTS_PATH}/Fuzzing/LFI/Linux/LFI-gracefulsecurity-linux.txt",
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
    
    # NoSQL & SQLi Extras
    "nosql": {
        "path": f"{SECLISTS_PATH}/Fuzzing/Databases/SQLi/NoSQL.txt",
        "purpose": "NoSQL injection payloads (MongoDB, CouchDB)",
        "use_when": "NoSQL injection testing",
        "category": "vuln"
    },
    "sqli_mysql_bypass": {
        "path": f"{SECLISTS_PATH}/Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
        "purpose": "MySQL login bypass payloads",
        "use_when": "MySQL auth bypass",
        "category": "bypass"
    },
    "sqli_polyglots": {
        "path": f"{SECLISTS_PATH}/Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
        "purpose": "SQLi polyglot payloads",
        "use_when": "Multi-context SQLi",
        "category": "vuln"
    },
    "sqli_quick": {
        "path": f"{SECLISTS_PATH}/Fuzzing/Databases/SQLi/quick-SQLi.txt",
        "purpose": "Quick SQLi payloads (fast scan)",
        "use_when": "Initial SQLi probe",
        "category": "vuln"
    },
    "login_bypass": {
        "path": f"{SECLISTS_PATH}/Fuzzing/login_bypass.txt",
        "purpose": "Login bypass payloads (15KB)",
        "use_when": "Auth bypass testing",
        "category": "bypass"
    },
    
    # Default Credentials
    "default_creds": {
        "path": f"{SECLISTS_PATH}/Passwords/Default-Credentials/default-passwords.txt",
        "purpose": "Default credentials for admin panels, routers, services",
        "use_when": "Default credential testing",
        "category": "auth"
    },
    "tomcat_creds": {
        "path": f"{SECLISTS_PATH}/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt",
        "purpose": "Tomcat manager default credentials",
        "use_when": "Tomcat admin panel",
        "category": "auth"
    },
    "mysql_creds": {
        "path": f"{SECLISTS_PATH}/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt",
        "purpose": "MySQL default credentials",
        "use_when": "MySQL service brute",
        "category": "auth"
    },
    "postgres_creds": {
        "path": f"{SECLISTS_PATH}/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt",
        "purpose": "PostgreSQL default credentials",
        "use_when": "PostgreSQL service brute",
        "category": "auth"
    },
    
    # API & GraphQL Discovery
    "api_wild": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/api/api-seen-in-wild.txt",
        "purpose": "166K real-world API endpoints seen in production",
        "use_when": "Thorough API endpoint discovery",
        "category": "api"
    },
    "graphql": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/graphql.txt",
        "purpose": "GraphQL endpoint paths",
        "use_when": "GraphQL discovery",
        "category": "api"
    },
    "login_pages": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/Logins.fuzz.txt",
        "purpose": "Login page paths",
        "use_when": "Finding admin/login panels",
        "category": "sensitive"
    },
    
    # Subdomains (thorough)
    "subdomains_110k": {
        "path": f"{SECLISTS_PATH}/Discovery/DNS/subdomains-top1million-110000.txt",
        "purpose": "Top 110K subdomains (thorough)",
        "use_when": "Exhaustive subdomain enum",
        "category": "subdomain"
    },
    
    # Directory (additional)
    "raft_medium_dirs": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/raft-medium-directories.txt",
        "purpose": "Raft medium directory list (280K)",
        "use_when": "Balanced directory enum",
        "category": "directory"
    },
    "combined_dirs": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/combined_directories.txt",
        "purpose": "Combined directories from multiple sources (1.2M)",
        "use_when": "Comprehensive directory enum",
        "category": "directory"
    },
    
    # CMS (additional)
    "joomla": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",
        "purpose": "Joomla plugin paths",
        "use_when": "Joomla pentesting",
        "category": "cms"
    },
    "drupal": {
        "path": f"{SECLISTS_PATH}/Discovery/Web-Content/CMS/Drupal.txt",
        "purpose": "Drupal paths (3.7M)",
        "use_when": "Drupal pentesting",
        "category": "cms"
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

    # Prefer SecLists equivalents for legacy Kali wordlists paths (even if legacy file exists)
    if isinstance(name_or_path, str) and "/usr/share/wordlists/" in name_or_path:
        try:
            legacy_map = {
                "/usr/share/wordlists/dirb/common.txt": f"{SECLISTS_PATH}/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirb/big.txt": f"{SECLISTS_PATH}/Discovery/Web-Content/big.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt": f"{SECLISTS_PATH}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt": f"{SECLISTS_PATH}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
            }
            mapped = legacy_map.get(name_or_path)
            if mapped and os.path.exists(mapped):
                return mapped
        except Exception:
            pass

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
        "directory": ["dir", "directory", "path", "enum", "fuzz"],
        "api": ["api", "rest", "graphql", "endpoint"],
        "params": ["param", "parameter", "query"],
        "subdomain": ["subdomain", "dns", "domain"],
        "vuln": ["sql", "sqli", "injection", "database", "db", "nosql", "xss", "cross-site", "script", "lfi", "file inclusion", "traversal", "ssti", "template", "xxe", "xml", "command injection", "rce", "cmd", "polyglot"],
        "sqli": ["sql", "sqli", "injection", "database", "db", "nosql"],
        "xss": ["xss", "cross-site", "script"],
        "lfi": ["lfi", "file inclusion", "traversal", "path traversal"],
        "ssti": ["ssti", "template"],
        "xxe": ["xxe", "xml"],
        "cmd": ["command injection", "rce", "cmd", "os injection"],
        "auth": ["password", "brute", "login", "credential", "default", "admin"],
        "cms": ["wordpress", "wp", "drupal", "joomla", "cms"],
        "bypass": ["403", "forbidden", "bypass", "waf", "filter"],
        "sensitive": ["backup", "sensitive", "exposed", "login", "admin panel"],
    }
    
    for wl_name, wl_data in WORDLISTS.items():
        category = wl_data.get("category", "")
        if category in keywords:
            if any(kw in task for kw in keywords[category]):
                suggestions.append({**wl_data, "name": wl_name})

    if suggestions:
        suggestions.sort(key=lambda x: int(x.get("priority", 1000)))
        return suggestions
    
    return suggestions if suggestions else [
        {**WORDLISTS["common"], "name": "common"},
        {**WORDLISTS["big"], "name": "big"}
    ]
