"""Simple Cache Implementation"""
import time
import hashlib
import json
from collections import OrderedDict
from typing import Dict, Any, Optional

class SimpleCache:
    def __init__(self, max_size: int = 100, ttl: int = 300):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.stats = {"hits": 0, "misses": 0}

    def _hash_key(self, command: str, params: Dict) -> str:
        key_str = f"{command}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, command: str, params: Dict = None) -> Optional[Dict]:
        params = params or {}
        key = self._hash_key(command, params)
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry["timestamp"] < self.ttl:
                self.stats["hits"] += 1
                self.cache.move_to_end(key)
                return entry["data"]
            del self.cache[key]
        self.stats["misses"] += 1
        return None

    def set(self, command: str, params: Dict, data: Dict):
        params = params or {}
        key = self._hash_key(command, params)
        if len(self.cache) >= self.max_size:
            self.cache.popitem(last=False)
        self.cache[key] = {"data": data, "timestamp": time.time()}

    def get_stats(self) -> Dict:
        total = self.stats["hits"] + self.stats["misses"]
        return {
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "hit_rate": self.stats["hits"] / total if total > 0 else 0,
            "size": len(self.cache),
            "max_size": self.max_size
        }

# Global cache instance
cache = SimpleCache()
