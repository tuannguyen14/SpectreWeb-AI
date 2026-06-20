#!/usr/bin/env python3
"""
SpectreWeb AI - Phantom Recon Engine v6.0.0
AI-Powered Web Penetration Testing with Smart Reporting

Usage:
    python server.py [--host HOST] [--port PORT] [--debug] [--structured-logs]
"""

import os
import sys
import signal
import atexit
from pathlib import Path
import argparse
import logging

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Ensure projectdiscovery tools take precedence
os.environ["PATH"] = "/usr/local/bin:" + os.environ.get("PATH", "")

from flask import Flask

from config import API_HOST, API_PORT, create_banner
from api import register_routes
from core.middleware import setup_middleware
from core.logging_config import setup_logging

# Default logging setup (will be reconfigured in main())
try:
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('spectreweb.log', mode='a')
    ]
except PermissionError:
    handlers = [logging.StreamHandler(sys.stdout)]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=handlers
)
logger = logging.getLogger(__name__)

# Flask App
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max request body

# Setup middleware (request tracking, error handling)
setup_middleware(app)

# Register routes
register_routes(app)

# Graceful shutdown for job queue on exit
def _shutdown_job_queue():
    try:
        from core.job_queue import get_job_queue
        get_job_queue().shutdown(wait=False)
    except Exception:
        pass

atexit.register(_shutdown_job_queue)


def main():
    parser = argparse.ArgumentParser(description="SpectreWeb AI Server v6.0.0")
    parser.add_argument("--host", default=API_HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=API_PORT, help="Port to bind")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    parser.add_argument("--structured-logs", action="store_true", help="Use JSON structured logging")
    parser.add_argument("--log-file", default=None, help="Log file path")
    args = parser.parse_args()
    
    # Setup structured logging if requested
    log_level = "DEBUG" if args.debug else "INFO"
    setup_logging(
        level=log_level,
        structured=args.structured_logs,
        log_file=args.log_file
    )
    
    print(create_banner())
    logger.info(f"👻 Starting SpectreWeb AI v6.0.0 on {args.host}:{args.port}")

    # Display API key at startup for operator convenience
    from config.settings import API_KEY, ALLOW_COMMAND_EXECUTION
    if API_KEY:
        masked = f"{API_KEY[:8]}...{API_KEY[-4:]}" if len(API_KEY) > 12 else "***"
        print(f"\n  🔑 API Key: {masked}")
        print(f"     Send as header: X-API-Key: <your-key>\n")
    else:
        logger.warning("⚠️  API authentication is DISABLED. Set SPECTREWEB_API_KEY to secure the server.")
    if ALLOW_COMMAND_EXECUTION:
        logger.warning("⚠️  Raw command execution is ENABLED via /api/command. This is dangerous.")
    
    if not args.debug:
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
    
    def _shutdown_handler(signum, frame):
        logger.info("🛑 Shutdown signal received, exiting gracefully...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
