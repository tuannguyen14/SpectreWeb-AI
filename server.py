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

# Setup middleware (request tracking, error handling)
setup_middleware(app)

# Register routes
register_routes(app)


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
