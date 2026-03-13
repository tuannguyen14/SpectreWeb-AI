"""Server Settings and Constants"""
import os

# Version
VERSION = "6.0.0"

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
FILE_MANAGER_BASE_DIR = "/tmp/spectreweb"

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
║  \033[38;5;51m👻 SpectreWeb AI v6.0.0 - Phantom Recon Engine\033[38;5;135m                       ║
╠═════════════════════════════════════════════════════════════════════╣
║  \033[38;5;46m✨ NEW:\033[0m \033[38;5;135mSelf-Learning AI | Smart Reporting | Consolidated Tools\033[38;5;135m            ║
║  \033[38;5;226m🎯 Bug Bounty\033[38;5;135m | \033[38;5;196m🔐 Web Security\033[38;5;135m | \033[38;5;51m📊 Smart Reporting\033[38;5;135m               ║
║  \033[38;5;208m⚡ 55 Tools\033[38;5;135m | \033[38;5;129m🧠 AI-Powered Analysis\033[38;5;135m | \033[38;5;46m📈 Auto Context\033[38;5;135m            ║
╚═════════════════════════════════════════════════════════════════════╝\033[0m
"""
