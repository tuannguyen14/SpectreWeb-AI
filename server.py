#!/usr/bin/env python3
"""
SpectreWeb AI - Phantom Recon Engine v3.0
AI-Powered Web Penetration Testing with Smart Reporting

Usage:
    python server.py [--host HOST] [--port PORT] [--debug]
"""

import os
import sys
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

# Logging
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

# Register routes
register_routes(app)


def main():
    parser = argparse.ArgumentParser(description="SpectreWeb AI Server v3.0")
    parser.add_argument("--host", default=API_HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=API_PORT, help="Port to bind")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()
    
    print(create_banner())
    logger.info(f"👻 Starting SpectreWeb AI on {args.host}:{args.port}")
    
    if not args.debug:
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
    
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
