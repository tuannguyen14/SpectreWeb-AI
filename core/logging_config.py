"""
Structured Logging Configuration

Provides request-aware logging with request IDs, timing, and structured output.
"""

import logging
import json
import time
import sys
from datetime import datetime
from typing import Any, Dict, Optional
from functools import wraps
import threading

# Thread-local for request context
_log_context = threading.local()


class StructuredFormatter(logging.Formatter):
    """JSON-based structured log formatter"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add request context if available
        if hasattr(_log_context, 'request_id'):
            log_data["request_id"] = _log_context.request_id
        if hasattr(_log_context, 'target'):
            log_data["target"] = _log_context.target
        if hasattr(_log_context, 'tool'):
            log_data["tool"] = _log_context.tool
        
        # Add extra fields from record
        if hasattr(record, 'extra_data'):
            log_data.update(record.extra_data)
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


class SimpleFormatter(logging.Formatter):
    """Simple text formatter with request ID"""
    
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        request_id = getattr(_log_context, 'request_id', '-')
        target = getattr(_log_context, 'target', '')
        
        prefix = f"[{timestamp}] [{record.levelname}] [{request_id}]"
        if target:
            prefix += f" [{target}]"
        
        msg = f"{prefix} {record.getMessage()}"
        
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        
        return msg


def set_log_context(request_id: str = None, target: str = None, tool: str = None):
    """Set logging context for current thread"""
    if request_id:
        _log_context.request_id = request_id
    if target:
        _log_context.target = target
    if tool:
        _log_context.tool = tool


def clear_log_context():
    """Clear logging context"""
    for attr in ['request_id', 'target', 'tool']:
        if hasattr(_log_context, attr):
            delattr(_log_context, attr)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    return logging.getLogger(f"spectreweb.{name}")


def setup_logging(
    level: str = "INFO",
    structured: bool = False,
    log_file: str = None
):
    """
    Configure logging for SpectreWeb.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        structured: Use JSON structured logging
        log_file: Optional file path for logging
    """
    root_logger = logging.getLogger("spectreweb")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Remove existing handlers
    root_logger.handlers = []
    
    # Choose formatter
    if structured:
        formatter = StructuredFormatter()
    else:
        formatter = SimpleFormatter()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    return root_logger


class LogTimer:
    """Context manager for timing operations"""
    
    def __init__(self, logger: logging.Logger, operation: str, level: int = logging.INFO):
        self.logger = logger
        self.operation = operation
        self.level = level
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = int((time.time() - self.start_time) * 1000)
        if exc_type:
            self.logger.log(
                logging.ERROR,
                f"{self.operation} failed after {duration_ms}ms: {exc_val}"
            )
        else:
            self.logger.log(
                self.level,
                f"{self.operation} completed in {duration_ms}ms"
            )
        return False


def log_request(logger: logging.Logger = None):
    """Decorator to log function entry/exit with timing"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)
            
            func_name = func.__name__
            logger.debug(f"Entering {func_name}")
            
            start = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = int((time.time() - start) * 1000)
                logger.debug(f"Exiting {func_name} ({duration_ms}ms)")
                return result
            except Exception as e:
                duration_ms = int((time.time() - start) * 1000)
                logger.error(f"{func_name} failed ({duration_ms}ms): {e}")
                raise
        
        return wrapper
    return decorator


# Default logger
_default_logger = None


def log(level: str, message: str, **extra):
    """Quick logging function"""
    global _default_logger
    if _default_logger is None:
        _default_logger = get_logger("main")
    
    record = _default_logger.makeRecord(
        _default_logger.name,
        getattr(logging, level.upper(), logging.INFO),
        "", 0, message, (), None
    )
    record.extra_data = extra
    _default_logger.handle(record)
