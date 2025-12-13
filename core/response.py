"""
Standardized API Response Schema

All API responses follow this format:
{
    "success": true/false,
    "request_id": "uuid",
    "data": {...} or null,
    "error": {"code": "ERROR_CODE", "message": "..."} or null,
    "meta": {"duration_ms": 123, "timestamp": "..."}
}
"""

import uuid
import time
from datetime import datetime
from typing import Any, Dict, Optional
from functools import wraps
from flask import g
import threading

# Thread-local storage for request context
_request_context = threading.local()


def get_request_id() -> str:
    """Get current request ID or generate new one"""
    if hasattr(g, 'request_id'):
        return g.request_id
    if hasattr(_request_context, 'request_id'):
        return _request_context.request_id
    return str(uuid.uuid4())[:12]


def set_request_id(request_id: str = None):
    """Set request ID for current context"""
    rid = request_id or str(uuid.uuid4())[:12]
    try:
        g.request_id = rid
    except RuntimeError:
        pass
    _request_context.request_id = rid
    return rid


class APIResponse:
    """Standardized API response builder"""
    
    @staticmethod
    def success(
        data: Any = None,
        message: str = None,
        meta: Dict = None
    ) -> Dict:
        """Build successful response"""
        response = {
            "success": True,
            "request_id": get_request_id(),
            "data": data,
            "error": None,
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                **(meta or {})
            }
        }
        if message:
            response["message"] = message
        return response
    
    @staticmethod
    def error(
        code: str,
        message: str,
        details: Any = None,
        status_code: int = 400
    ) -> tuple:
        """Build error response with HTTP status code"""
        response = {
            "success": False,
            "request_id": get_request_id(),
            "data": None,
            "error": {
                "code": code,
                "message": message,
                "details": details
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }
        return response, status_code
    
    @staticmethod
    def from_result(result: Dict, error_code: str = "OPERATION_FAILED") -> Dict:
        """Convert legacy result dict to standard response"""
        if result.get("success", True) and "error" not in result:
            return APIResponse.success(data=result)
        else:
            error_msg = result.get("error", "Operation failed")
            return APIResponse.error(error_code, error_msg)[0]


# Common error codes
class ErrorCode:
    INVALID_INPUT = "INVALID_INPUT"
    MISSING_REQUIRED = "MISSING_REQUIRED"
    NOT_FOUND = "NOT_FOUND"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    TOOL_ERROR = "TOOL_ERROR"
    NETWORK_ERROR = "NETWORK_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"


def validate_required(data: Dict, fields: list) -> Optional[tuple]:
    """
    Validate required fields in request data.
    Returns error response tuple if validation fails, None if ok.
    """
    missing = [f for f in fields if not data.get(f)]
    if missing:
        return APIResponse.error(
            ErrorCode.MISSING_REQUIRED,
            f"Missing required fields: {', '.join(missing)}",
            details={"missing_fields": missing}
        )
    return None


def validate_url(url: str) -> Optional[tuple]:
    """Validate URL format"""
    if not url or not isinstance(url, str):
        return APIResponse.error(
            ErrorCode.INVALID_INPUT,
            "URL is required"
        )
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        return APIResponse.error(
            ErrorCode.INVALID_INPUT,
            "URL must start with http:// or https://"
        )
    return None
