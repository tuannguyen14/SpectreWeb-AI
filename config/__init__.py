"""SpectreWeb Configuration Module"""
from .settings import *
from .wordlists import WORDLISTS, SECLISTS_PATH, get_wordlist, suggest_wordlist, resolve_wordlist_path

# Explicitly export security settings for clarity
from .settings import (
    API_KEY,
    ALLOW_COMMAND_EXECUTION,
    TLS_VERIFY,
    MAX_FILE_SIZE,
    API_RATE_LIMIT_ENABLED,
    API_RATE_LIMIT_REQUESTS,
    API_RATE_LIMIT_BURST,
    ALLOWED_LOCAL_SCAN_DIRS,
    MAX_OUTPUT_SIZE,
)
