"""Browser-like HTTP Client with retry and rate limiting"""
import time
from typing import Dict, Any, Optional
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

# Retry configuration
RETRY_STATUS_CODES = {502, 503, 504, 429}  # Transient errors
RETRY_EXCEPTIONS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
)


def make_request(url: str, method: str = "GET", headers: Dict = None,
                 data: Any = None, cookies: Dict = None,
                 follow_redirects: bool = True, timeout: int = 60,
                 proxy: str = None, retries: int = 2,
                 retry_delay: float = 1.0,
                 rate_limit: bool = True) -> Dict[str, Any]:
    """
    Make HTTP request like a real browser with retry support.
    
    Args:
        url: Target URL
        method: HTTP method
        headers: Custom headers
        data: Request body
        cookies: Cookies to send
        follow_redirects: Follow HTTP redirects
        timeout: Request timeout (1-300 seconds)
        proxy: Proxy URL
        retries: Number of retries for transient errors (default 2)
        retry_delay: Base delay between retries in seconds
        rate_limit: Apply per-domain rate limiting (default True)
    
    Returns:
        Dict with success, status_code, headers, body, etc.
    """
    # Input validation
    if not isinstance(url, str) or not url.strip():
        return {"success": False, "error": "URL required"}

    if not isinstance(method, str) or not method.strip():
        method = "GET"

    if headers is not None and not isinstance(headers, dict):
        headers = None

    if cookies is not None and not isinstance(cookies, dict):
        cookies = None

    if not isinstance(timeout, (int, float)):
        timeout = 60
    timeout = max(1, min(int(timeout), 300))

    if proxy is not None and (not isinstance(proxy, str) or not proxy.strip()):
        proxy = None

    if not isinstance(retries, int) or retries < 0:
        retries = 2
    retries = min(retries, 5)  # Cap at 5 retries

    url = url.strip()
    method = method.upper()
    
    final_headers = DEFAULT_HEADERS.copy()
    if headers:
        final_headers.update(headers)
    
    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    # Apply rate limiting if enabled
    if rate_limit:
        try:
            from web.rate_limiter import get_rate_limiter
            limiter = get_rate_limiter()
            if not limiter.acquire(url, timeout=min(timeout, 30)):
                return {"success": False, "error": "Rate limited", "rate_limited": True}
        except ImportError:
            pass  # Rate limiter not available
    
    last_error = None
    last_status = None
    
    for attempt in range(retries + 1):
        try:
            start = time.time()
            response = requests.request(
                method=method,
                url=url,
                headers=final_headers,
                data=data,
                cookies=cookies or {},
                allow_redirects=follow_redirects,
                timeout=timeout,
                verify=False,
                proxies=proxies
            )
            elapsed = time.time() - start
            
            # Check if we should retry based on status code
            if response.status_code in RETRY_STATUS_CODES and attempt < retries:
                last_status = response.status_code
                # Exponential backoff with jitter
                delay = retry_delay * (2 ** attempt) + (time.time() % 0.5)
                time.sleep(delay)
                continue
            
            return {
                "success": True,
                "status_code": response.status_code,
                "url": response.url,
                "headers": dict(response.headers),
                "cookies": dict(response.cookies),
                "body": response.text[:100000],
                "body_length": len(response.text),
                "elapsed": elapsed,
                "redirect_history": [r.url for r in response.history],
                "attempts": attempt + 1
            }
            
        except RETRY_EXCEPTIONS as e:
            last_error = str(e)
            if attempt < retries:
                delay = retry_delay * (2 ** attempt)
                time.sleep(delay)
                continue
            return {
                "success": False, 
                "error": last_error,
                "attempts": attempt + 1,
                "retryable": True
            }
        except Exception as e:
            return {
                "success": False, 
                "error": str(e),
                "attempts": attempt + 1,
                "retryable": False
            }
    
    # All retries exhausted with status code errors
    return {
        "success": False,
        "error": f"Request failed after {retries + 1} attempts (last status: {last_status})",
        "last_status_code": last_status,
        "attempts": retries + 1,
        "retryable": True
    }
