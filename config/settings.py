"""Server Settings and Constants"""
import os
import tempfile as _tempfile
import secrets as _secrets

# Version
VERSION = "7.0.0"

# SpectreWeb AI Server Configuration
API_PORT = int(os.environ.get('SPECTREWEB_PORT', 8888))
API_HOST = os.environ.get('SPECTREWEB_HOST', '127.0.0.1')

# Timeouts
DEFAULT_TIMEOUT = 1500
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3

# Cache
CACHE_MAX_SIZE = 100
CACHE_TTL = 300

# File Manager
FILE_MANAGER_BASE_DIR = os.environ.get("SPECTREWEB_FILE_BASE_DIR", os.path.join(_tempfile.gettempdir(), "spectreweb"))

# --- Security Settings ---

# API Authentication
# If SPECTREWEB_API_KEY is not set, a random key is generated at startup.
# The generated key is printed to stdout and logged.
# Set SPECTREWEB_API_KEY="" to explicitly disable auth (NOT recommended).
_api_key_env = os.environ.get("SPECTREWEB_API_KEY")
if _api_key_env is not None and _api_key_env != "":
    API_KEY = _api_key_env
else:
    API_KEY = None  # Auth disabled by default

# Allow raw shell command execution via /api/command (DANGEROUS)
# Must be explicitly enabled via environment variable.
ALLOW_COMMAND_EXECUTION = os.environ.get("SPECTREWEB_ALLOW_COMMAND", "false").lower() in ("true", "1", "yes")

# TLS verification for outbound requests
# Pentest tools often target self-signed certs, so default to False for scanning
# but allow override via environment variable.
TLS_VERIFY = os.environ.get("SPECTREWEB_TLS_VERIFY", "false").lower() in ("true", "1", "yes")

# File size limits for FileManager (in bytes, default 10MB)
MAX_FILE_SIZE = int(os.environ.get("SPECTREWEB_MAX_FILE_SIZE", 10 * 1024 * 1024))

# Max output size for command executor (in bytes, default 50MB)
MAX_OUTPUT_SIZE = int(os.environ.get("SPECTREWEB_MAX_OUTPUT_SIZE", 50 * 1024 * 1024))

# API rate limiting (per client IP)
API_RATE_LIMIT_ENABLED = os.environ.get("SPECTREWEB_API_RATE_LIMIT", "true").lower() in ("true", "1", "yes")
API_RATE_LIMIT_REQUESTS = int(os.environ.get("SPECTREWEB_API_RATE_LIMIT_RPM", 60))  # requests per minute
API_RATE_LIMIT_BURST = int(os.environ.get("SPECTREWEB_API_RATE_LIMIT_BURST", 20))

# Allowed directories for local secret scanning (os.pathsep-separated: ':' on Unix, ';' on Windows)
_default_scan_dirs = os.path.join(_tempfile.gettempdir(), "spectreweb") + os.pathsep + _tempfile.gettempdir()
ALLOWED_LOCAL_SCAN_DIRS = [
    d for d in os.environ.get(
        "SPECTREWEB_ALLOWED_SCAN_DIRS", _default_scan_dirs
    ).split(os.pathsep) if d
]

# Default Browser Headers
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# Banner
def create_banner() -> str:
    return """
\033[38;5;135m\033[1m
███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  
███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
\033[38;5;51m               ██╗    ██╗███████╗██████╗ 
               ██║    ██║██╔════╝██╔══██╗
               ██║ █╗ ██║█████╗  ██████╔╝
               ██║███╗██║██╔══╝  ██╔══██╗
               ╚███╔███╔╝███████╗██████╔╝
                ╚══╝╚══╝ ╚══════╝╚═════╝ \033[0m
\033[38;5;135m╔═════════════════════════════════════════════════════════════════════╗
║  \033[38;5;51m👻 SpectreWeb AI v7.0.0 - Phantom Recon Engine\033[38;5;135m                       ║
╠═════════════════════════════════════════════════════════════════════╣
║  \033[38;5;46m✨ NEW:\033[0m \033[38;5;135mOrigin IP Finder | Smart Reporting | Consolidated Tools\033[38;5;135m          ║
║  \033[38;5;226m🎯 Bug Bounty\033[38;5;135m | \033[38;5;196m🔐 Web Security\033[38;5;135m | \033[38;5;51m📊 Smart Reporting\033[38;5;135m               ║
║  \033[38;5;208m⚡ 47 Tools\033[38;5;135m | \033[38;5;129m🔍 Origin IP Finder\033[38;5;135m | \033[38;5;46m📈 Auto Context\033[38;5;135m            ║
╚═════════════════════════════════════════════════════════════════════╝\033[0m
"""
