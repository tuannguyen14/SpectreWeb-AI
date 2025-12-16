"""
Rate Limiter - Per-domain request throttling

Prevents getting blocked by target servers during scanning.
"""

import time
import threading
from typing import Dict, Optional
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class DomainBucket:
    """Token bucket for a single domain"""
    tokens: float = 10.0
    max_tokens: float = 10.0
    refill_rate: float = 2.0  # tokens per second
    last_refill: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)
    
    def refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
    
    def acquire(self, tokens: int = 1, timeout: float = 30.0) -> bool:
        """
        Try to acquire tokens, blocking if necessary.
        
        Returns:
            True if tokens acquired, False if timeout
        """
        deadline = time.time() + timeout

        while True:
            now = time.time()
            if now >= deadline:
                return False

            with self.lock:
                self.refill()

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

                needed = tokens - self.tokens
                wait_time = needed / max(self.refill_rate, 0.0001)

            # Sleep outside the lock to allow other threads to progress.
            sleep_for = min(wait_time, 0.1)
            if now + sleep_for > deadline:
                return False
            time.sleep(sleep_for)
    
    def try_acquire(self, tokens: int = 1) -> bool:
        """Non-blocking token acquisition"""
        with self.lock:
            self.refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class RateLimiter:
    """
    Per-domain rate limiter using token bucket algorithm.
    
    Usage:
        limiter = RateLimiter(requests_per_second=5)
        
        # Block until allowed
        limiter.acquire("https://example.com/api")
        
        # Or check without blocking
        if limiter.try_acquire("https://example.com/api"):
            make_request()
    """
    
    def __init__(
        self,
        requests_per_second: float = 5.0,
        burst_size: int = 10,
        default_timeout: float = 30.0
    ):
        """
        Args:
            requests_per_second: Sustained request rate per domain
            burst_size: Maximum burst of requests allowed
            default_timeout: Default timeout for blocking acquire
        """
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.default_timeout = default_timeout
        
        self._buckets: Dict[str, DomainBucket] = {}
        self._buckets_lock = threading.Lock()
        
        # Per-domain overrides
        self._domain_configs: Dict[str, Dict] = {}
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for rate limiting"""
        if not url:
            return "unknown"
        try:
            parsed = urlparse(url)
            return (parsed.hostname or "unknown").lower()
        except Exception:
            return "unknown"
    
    def _get_bucket(self, domain: str) -> DomainBucket:
        """Get or create bucket for domain"""
        with self._buckets_lock:
            if domain not in self._buckets:
                config = self._domain_configs.get(domain, {})
                self._buckets[domain] = DomainBucket(
                    tokens=float(config.get('burst_size', self.burst_size)),
                    max_tokens=float(config.get('burst_size', self.burst_size)),
                    refill_rate=config.get('requests_per_second', self.requests_per_second)
                )
            return self._buckets[domain]
    
    def configure_domain(
        self,
        domain: str,
        requests_per_second: float = None,
        burst_size: int = None
    ):
        """Configure rate limit for specific domain"""
        config = {}
        if requests_per_second is not None:
            config['requests_per_second'] = requests_per_second
        if burst_size is not None:
            config['burst_size'] = burst_size
        
        self._domain_configs[domain.lower()] = config
        
        # Reset bucket if exists
        with self._buckets_lock:
            self._buckets.pop(domain.lower(), None)
    
    def acquire(self, url: str, tokens: int = 1, timeout: float = None) -> bool:
        """
        Acquire rate limit tokens for URL, blocking if necessary.
        
        Args:
            url: Target URL
            tokens: Number of tokens to acquire (default 1)
            timeout: Max time to wait (default: self.default_timeout)
        
        Returns:
            True if acquired, False if timeout
        """
        domain = self._extract_domain(url)
        bucket = self._get_bucket(domain)
        return bucket.acquire(tokens, timeout or self.default_timeout)
    
    def try_acquire(self, url: str, tokens: int = 1) -> bool:
        """
        Try to acquire tokens without blocking.
        
        Returns:
            True if acquired, False if rate limited
        """
        domain = self._extract_domain(url)
        bucket = self._get_bucket(domain)
        return bucket.try_acquire(tokens)
    
    def wait_time(self, url: str, tokens: int = 1) -> float:
        """
        Get estimated wait time for tokens.
        
        Returns:
            Seconds to wait, 0 if tokens available now
        """
        domain = self._extract_domain(url)
        bucket = self._get_bucket(domain)
        
        with bucket.lock:
            bucket.refill()
            if bucket.tokens >= tokens:
                return 0.0
            needed = tokens - bucket.tokens
            return needed / bucket.refill_rate
    
    def get_stats(self) -> Dict:
        """Get rate limiter statistics"""
        stats = {
            "domains": {},
            "total_domains": 0
        }
        
        with self._buckets_lock:
            stats["total_domains"] = len(self._buckets)
            for domain, bucket in self._buckets.items():
                with bucket.lock:
                    bucket.refill()
                    stats["domains"][domain] = {
                        "available_tokens": round(bucket.tokens, 2),
                        "max_tokens": bucket.max_tokens,
                        "refill_rate": bucket.refill_rate
                    }
        
        return stats
    
    def reset(self, domain: str = None):
        """Reset rate limiter state"""
        with self._buckets_lock:
            if domain:
                self._buckets.pop(domain.lower(), None)
            else:
                self._buckets.clear()


# Global rate limiter instance
_global_limiter: Optional[RateLimiter] = None
_limiter_lock = threading.Lock()


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance"""
    global _global_limiter
    with _limiter_lock:
        if _global_limiter is None:
            _global_limiter = RateLimiter()
        return _global_limiter


def configure_rate_limit(
    requests_per_second: float = 5.0,
    burst_size: int = 10
):
    """Configure global rate limiter"""
    global _global_limiter
    with _limiter_lock:
        _global_limiter = RateLimiter(
            requests_per_second=requests_per_second,
            burst_size=burst_size
        )


def rate_limited(url: str, tokens: int = 1) -> bool:
    """
    Decorator-friendly rate limit check.
    Blocks until rate limit allows request.
    
    Usage:
        rate_limited("https://example.com")
        response = make_request(...)
    """
    return get_rate_limiter().acquire(url, tokens)
