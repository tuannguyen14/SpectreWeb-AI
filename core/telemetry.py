"""Telemetry and Statistics"""
import time
from typing import Dict

class Telemetry:
    def __init__(self):
        self.stats = {
            "start_time": time.time(),
            "requests": 0,
            "tools_used": {},
            "errors": 0
        }
    
    def record(self, tool: str, success: bool):
        self.stats["requests"] += 1
        if tool not in self.stats["tools_used"]:
            self.stats["tools_used"][tool] = {"success": 0, "failed": 0}
        
        if success:
            self.stats["tools_used"][tool]["success"] += 1
        else:
            self.stats["tools_used"][tool]["failed"] += 1
            self.stats["errors"] += 1
    
    def get_stats(self) -> Dict:
        return {
            **self.stats,
            "uptime": time.time() - self.stats["start_time"]
        }

# Global instance
telemetry = Telemetry()
