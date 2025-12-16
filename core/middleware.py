"""
Flask Middleware for Request Tracking

Provides request ID injection, timing, logging, and error handling.
"""

import uuid
import time
from functools import wraps
from flask import Flask, request, g, jsonify
from typing import Callable, Optional
from werkzeug.exceptions import HTTPException

from core.logging_config import set_log_context, clear_log_context, get_logger
from core.response import set_request_id, APIResponse, ErrorCode

logger = get_logger("middleware")


def setup_middleware(app: Flask):
    """
    Setup all middleware for the Flask app.
    
    Usage:
        app = Flask(__name__)
        setup_middleware(app)
    """
    
    @app.before_request
    def before_request():
        """Inject request ID and start timing"""
        # Generate or extract request ID
        request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())[:12]
        g.request_id = request_id
        g.start_time = time.time()
        
        # Set logging context
        set_request_id(request_id)
        
        # Extract target from request for logging
        target = None
        if request.is_json:
            try:
                data = request.get_json(silent=True) or {}
                target = data.get('target') or data.get('url') or data.get('domain')
            except Exception:
                pass
        
        if target:
            set_log_context(request_id=request_id, target=target)
        else:
            set_log_context(request_id=request_id)
        
        # Log request start (debug level)
        logger.debug(f"Request started: {request.method} {request.path}")
    
    @app.after_request
    def after_request(response):
        """Add headers and log completion"""
        # Add request ID to response headers
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        
        # Calculate duration
        duration_ms = 0
        if hasattr(g, 'start_time'):
            duration_ms = int((time.time() - g.start_time) * 1000)
            response.headers['X-Response-Time'] = f"{duration_ms}ms"
        
        # Log completion
        logger.debug(
            f"Request completed: {request.method} {request.path} "
            f"status={response.status_code} duration={duration_ms}ms"
        )
        
        return response
    
    @app.teardown_request
    def teardown_request(exception=None):
        """Cleanup after request"""
        clear_log_context()
        if exception:
            logger.error(f"Request failed with exception: {exception}")
    
    @app.errorhandler(400)
    def bad_request(error):
        """Handle 400 Bad Request"""
        return jsonify(APIResponse.error(
            ErrorCode.INVALID_INPUT,
            str(error.description) if hasattr(error, 'description') else "Bad request"
        )[0]), 400
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found"""
        return jsonify(APIResponse.error(
            ErrorCode.NOT_FOUND,
            f"Endpoint not found: {request.path}",
            status_code=404
        )[0]), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 Internal Server Error"""
        logger.error(f"Internal error: {error}")
        return jsonify(APIResponse.error(
            ErrorCode.INTERNAL_ERROR,
            "Internal server error",
            status_code=500
        )[0]), 500

    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        code = getattr(error, 'code', 500) or 500
        description = getattr(error, 'description', None) or str(error)
        return jsonify(APIResponse.error(
            ErrorCode.INVALID_INPUT,
            description,
            status_code=code
        )[0]), code
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle uncaught exceptions"""
        logger.error(f"Uncaught exception: {error}", exc_info=True)
        return jsonify(APIResponse.error(
            ErrorCode.INTERNAL_ERROR,
            str(error),
            status_code=500
        )[0]), 500


def require_json(f: Callable) -> Callable:
    """Decorator to require JSON body"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.is_json:
            return jsonify(APIResponse.error(
                ErrorCode.INVALID_INPUT,
                "Content-Type must be application/json"
            )[0]), 400
        return f(*args, **kwargs)
    return decorated


def require_fields(*fields: str) -> Callable:
    """
    Decorator to require specific fields in JSON body.
    
    Usage:
        @app.route("/api/scan", methods=["POST"])
        @require_fields("url", "target")
        def scan():
            ...
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(silent=True) or {}
            missing = [field for field in fields if not data.get(field)]
            if missing:
                return jsonify(APIResponse.error(
                    ErrorCode.MISSING_REQUIRED,
                    f"Missing required fields: {', '.join(missing)}",
                    details={"missing_fields": missing}
                )[0]), 400
            return f(*args, **kwargs)
        return decorated
    return decorator


def timed_route(name: str = None):
    """
    Decorator to time and log route execution.
    
    Usage:
        @app.route("/api/scan", methods=["POST"])
        @timed_route("scan_endpoint")
        def scan():
            ...
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            route_name = name or f.__name__
            start = time.time()
            
            try:
                result = f(*args, **kwargs)
                duration_ms = int((time.time() - start) * 1000)
                logger.info(f"Route {route_name} completed in {duration_ms}ms")
                return result
            except Exception as e:
                duration_ms = int((time.time() - start) * 1000)
                logger.error(f"Route {route_name} failed after {duration_ms}ms: {e}")
                raise
        
        return decorated
    return decorator


class RequestContext:
    """
    Context manager for request-scoped operations.
    
    Usage:
        with RequestContext(target="example.com", tool="nmap"):
            # Operations here will have logging context
            result = run_scan()
    """
    
    def __init__(self, target: str = None, tool: str = None):
        self.target = target
        self.tool = tool
        self.request_id = str(uuid.uuid4())[:12]
    
    def __enter__(self):
        set_request_id(self.request_id)
        set_log_context(
            request_id=self.request_id,
            target=self.target,
            tool=self.tool
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        clear_log_context()
        return False
