"""Browser-like HTTP Client"""
import time
from typing import Dict, Any
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

def make_request(url: str, method: str = "GET", headers: Dict = None,
                 data: Any = None, cookies: Dict = None,
                 follow_redirects: bool = True, timeout: int = 60,
                 proxy: str = None) -> Dict[str, Any]:
    """Make HTTP request like a real browser"""
    try:
        final_headers = DEFAULT_HEADERS.copy()
        if headers:
            final_headers.update(headers)
        
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        start = time.time()
        response = requests.request(
            method=method.upper(),
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
        
        return {
            "success": True,
            "status_code": response.status_code,
            "url": response.url,
            "headers": dict(response.headers),
            "cookies": dict(response.cookies),
            "body": response.text[:100000],
            "body_length": len(response.text),
            "elapsed": elapsed,
            "redirect_history": [r.url for r in response.history]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
