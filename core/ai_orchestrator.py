"""
AI Orchestrator - Hybrid Local + Remote AI coordination.

This module provides intelligent routing between:
- Local AI (fast, learns from your data, no API cost)
- Remote AI (powerful, for complex analysis)

Strategy:
1. Try local AI first for supported tasks
2. If local confidence is low, escalate to remote
3. Use remote AI for complex reasoning tasks
4. Learn from remote AI responses to improve local

This design ensures:
- Fast response for common cases
- No single point of failure
- Continuous improvement
- Cost optimization
"""

import json
import hashlib
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum

from .local_ai import get_local_ai, LocalAI, ML_AVAILABLE, AIResponse
from .learning_store import get_store, LearningStore


class AIBackend(Enum):
    LOCAL = "local"
    REMOTE = "remote"
    HYBRID = "hybrid"


class TaskType(Enum):
    # Local AI can handle these
    CLASSIFY_SECRET = "classify_secret"
    SCORE_ENDPOINT = "score_endpoint"
    RANK_PAYLOADS = "rank_payloads"
    TRIAGE_FINDING = "triage_finding"
    
    # Remote AI needed for these
    ANALYZE_VULNERABILITY = "analyze_vulnerability"
    GENERATE_EXPLOIT = "generate_exploit"
    WRITE_REPORT = "write_report"
    SUGGEST_ATTACK_STRATEGY = "suggest_attack_strategy"
    EXPLAIN_FINDING = "explain_finding"


@dataclass
class AIRequest:
    """Represents a request to the AI system"""
    task_type: TaskType
    data: Dict[str, Any]
    require_high_confidence: bool = False
    force_backend: Optional[AIBackend] = None


class AIOrchestrator:
    """
    Orchestrates AI requests between local and remote backends.
    
    Features:
    - Automatic backend selection based on task type
    - Confidence-based escalation to remote
    - Caching of remote responses
    - Learning from remote responses
    """
    
    # Confidence threshold for escalation
    CONFIDENCE_THRESHOLD = 0.7
    
    # Tasks that can be handled locally
    LOCAL_TASKS = {
        TaskType.CLASSIFY_SECRET,
        TaskType.SCORE_ENDPOINT,
        TaskType.RANK_PAYLOADS,
        TaskType.TRIAGE_FINDING,
    }
    
    # Tasks that require remote AI
    REMOTE_TASKS = {
        TaskType.ANALYZE_VULNERABILITY,
        TaskType.GENERATE_EXPLOIT,
        TaskType.WRITE_REPORT,
        TaskType.SUGGEST_ATTACK_STRATEGY,
        TaskType.EXPLAIN_FINDING,
    }
    
    def __init__(self, remote_handler: Callable = None):
        """
        Initialize the orchestrator.
        
        Args:
            remote_handler: Async function to call remote AI
                           signature: (task_type: str, data: dict) -> dict
        """
        self.local_ai = get_local_ai()
        self.store = get_store()
        self.remote_handler = remote_handler
        
        # Response cache for remote calls
        self.cache: Dict[str, Any] = {}
        self.cache_ttl = 3600  # 1 hour
        self._cache_lock = threading.Lock()

        # Statistics
        self.stats = {
            "local_calls": 0,
            "remote_calls": 0,
            "escalations": 0,
            "cache_hits": 0,
        }
        self._stats_lock = threading.Lock()
    
    def process(self, request: AIRequest) -> AIResponse:
        """
        Process an AI request.
        
        Automatically selects the best backend based on:
        - Task type
        - Local model confidence
        - Force override if specified
        """
        import time
        start = time.time()
        
        try:
            # Force specific backend
            if request.force_backend == AIBackend.LOCAL:
                result, confidence = self._process_local(request)
                backend = AIBackend.LOCAL
                
            elif request.force_backend == AIBackend.REMOTE:
                result = self._process_remote(request)
                confidence = 0.9
                backend = AIBackend.REMOTE
                
            # Remote-only tasks
            elif request.task_type in self.REMOTE_TASKS:
                result = self._process_remote(request)
                confidence = 0.9
                backend = AIBackend.REMOTE
                
            # Local-capable tasks
            elif request.task_type in self.LOCAL_TASKS:
                result, confidence = self._process_local(request)
                backend = AIBackend.LOCAL
                
                # Escalate if confidence too low
                if request.require_high_confidence and confidence < self.CONFIDENCE_THRESHOLD:
                    if self.remote_handler:
                        with self._stats_lock:
                            self.stats["escalations"] += 1
                        result = self._process_remote(request)
                        confidence = 0.9
                        backend = AIBackend.HYBRID
                        
            else:
                return AIResponse(
                    success=False,
                    result=None,
                    backend_used=AIBackend.LOCAL.value,
                    confidence=0,
                    latency_ms=0,
                    error=f"Unknown task type: {request.task_type}"
                )
            
            latency = (time.time() - start) * 1000
            
            return AIResponse(
                success=True,
                result=result,
                backend_used=backend.value,
                confidence=confidence,
                latency_ms=round(latency, 2)
            )
            
        except Exception as e:
            latency = (time.time() - start) * 1000
            return AIResponse(
                success=False,
                result=None,
                backend_used=AIBackend.LOCAL.value,
                confidence=0,
                latency_ms=round(latency, 2),
                error=str(e)
            )
    
    def _process_local(self, request: AIRequest) -> tuple:
        """Process request using local AI"""
        with self._stats_lock:
            self.stats["local_calls"] += 1
        
        task = request.task_type
        data = request.data
        
        if task == TaskType.CLASSIFY_SECRET:
            response = self.local_ai.classify_secret(data)
            return response.result, response.confidence
            
        elif task == TaskType.SCORE_ENDPOINT:
            response = self.local_ai.score_endpoint(data)
            return response.result, response.confidence
            
        elif task == TaskType.RANK_PAYLOADS:
            payloads = data.get("payloads", [])
            context = data.get("context", {})
            response = self.local_ai.rank_payloads(payloads, context)
            return response.result, response.confidence
            
        elif task == TaskType.TRIAGE_FINDING:
            # Combine secret and endpoint scoring
            if data.get("type") == "secret":
                response = self.local_ai.classify_secret(data)
            else:
                response = self.local_ai.score_endpoint(data)
            return response.result, response.confidence
            
        else:
            return {"error": "Task not supported locally"}, 0.0
    
    def _process_remote(self, request: AIRequest) -> Dict[str, Any]:
        """Process request using remote AI"""
        with self._stats_lock:
            self.stats["remote_calls"] += 1
        
        # Check cache
        cache_key = self._get_cache_key(request)
        with self._cache_lock:
            cached = self.cache.get(cache_key)
            if cached and cached.get("expires_at", 0) > datetime.now().timestamp():
                with self._stats_lock:
                    self.stats["cache_hits"] += 1
                return cached.get("result")
        
        # Call remote handler
        if not self.remote_handler:
            return {
                "error": "Remote AI not configured",
                "hint": "Set remote_handler in AIOrchestrator"
            }
        
        result = self.remote_handler(request.task_type.value, request.data)
        
        # Cache result
        with self._cache_lock:
            self.cache[cache_key] = {
                "result": result,
                "expires_at": datetime.now().timestamp() + self.cache_ttl
            }
        
        return result
    
    def _get_cache_key(self, request: AIRequest) -> str:
        """Generate cache key for request"""
        data_str = json.dumps(request.data, sort_keys=True)
        return hashlib.sha256(
            f"{request.task_type.value}:{data_str}".encode()
        ).hexdigest()[:32]
    
    # =========================================================================
    # CONVENIENCE METHODS
    # =========================================================================
    
    def classify_secret(self, features: Dict[str, Any], require_high_confidence: bool = False) -> AIResponse:
        """Classify a secret finding"""
        return self.process(AIRequest(
            task_type=TaskType.CLASSIFY_SECRET,
            data=features,
            require_high_confidence=require_high_confidence
        ))
    
    def score_endpoint(self, features: Dict[str, Any], require_high_confidence: bool = False) -> AIResponse:
        """Score endpoint vulnerability risk"""
        return self.process(AIRequest(
            task_type=TaskType.SCORE_ENDPOINT,
            data=features,
            require_high_confidence=require_high_confidence
        ))
    
    def rank_payloads(self, payloads: List[Dict], context: Dict[str, Any]) -> AIResponse:
        """Rank payloads by effectiveness"""
        return self.process(AIRequest(
            task_type=TaskType.RANK_PAYLOADS,
            data={"payloads": payloads, "context": context}
        ))
    
    def analyze_vulnerability(self, finding: Dict[str, Any]) -> AIResponse:
        """Deep analysis of a vulnerability (requires remote AI)"""
        return self.process(AIRequest(
            task_type=TaskType.ANALYZE_VULNERABILITY,
            data=finding,
            force_backend=AIBackend.REMOTE
        ))
    
    def suggest_attack_strategy(self, target_info: Dict[str, Any]) -> AIResponse:
        """Get AI-suggested attack strategy (requires remote AI)"""
        return self.process(AIRequest(
            task_type=TaskType.SUGGEST_ATTACK_STRATEGY,
            data=target_info,
            force_backend=AIBackend.REMOTE
        ))
    
    # =========================================================================
    # TRAINING & MANAGEMENT
    # =========================================================================
    
    def train_local_models(self) -> Dict[str, Any]:
        """Train local AI models from learning store data"""
        return self.local_ai.train_all(self.store)
    
    def auto_train_if_ready(self) -> Dict[str, Any]:
        """
        Automatically train models if enough new labeled data is available.
        
        Conditions:
        - At least MIN_SAMPLES (50) labeled findings per model
        - At least 10 new samples since last train
        
        Returns training result or skip reason.
        """
        stats = self.store.get_stats()
        labeled = stats.get("labeled_findings", {})
        
        # Count positive + negative labels
        tp_count = labeled.get("true_positive", 0) + labeled.get("confirmed_bug", 0)
        fp_count = labeled.get("false_positive", 0) + labeled.get("not_exploitable", 0)
        total_labeled = tp_count + fp_count
        
        # Check if we have enough data
        min_samples = 50
        if total_labeled < min_samples:
            return {
                "action": "skipped",
                "reason": f"Need {min_samples} labeled samples, have {total_labeled}",
                "suggestion": "Label more findings using learning_label tool"
            }
        
        # Check model status
        model_status = self.local_ai.get_status()
        secret_model = model_status.get("models", {}).get("secret_classifier", {})
        
        # If not trained yet, or significantly more data available
        if secret_model.get("status") == "not_trained":
            return self.train_local_models()
        
        last_samples = secret_model.get("samples_count", 0)
        if total_labeled >= last_samples + 10:
            return self.train_local_models()
        
        return {
            "action": "skipped",
            "reason": "Models are up-to-date",
            "last_trained_samples": last_samples,
            "current_labeled": total_labeled
        }
    
    def get_smart_insights(self) -> Dict[str, Any]:
        """
        Generate smart insights based on learning history.
        
        Returns:
        - Most effective attack types
        - Common false positive patterns
        - Recommended focus areas
        """
        stats = self.store.get_stats()
        attacks = stats.get("attacks_by_type", {})
        
        insights = {
            "attack_effectiveness": {},
            "recommendations": [],
            "patterns": {}
        }
        
        # Calculate effectiveness per attack type
        for attack_type, data in attacks.items():
            total = data.get("total", 0)
            interesting = data.get("interesting", 0)
            if total > 0:
                rate = interesting / total
                insights["attack_effectiveness"][attack_type] = {
                    "success_rate": round(rate, 3),
                    "total_attempts": total,
                    "interesting_findings": interesting
                }
        
        # Generate recommendations
        if attacks:
            best_attack = max(attacks.items(), key=lambda x: x[1].get("interesting", 0) / max(x[1].get("total", 1), 1))
            insights["recommendations"].append(
                f"Most effective attack type: {best_attack[0]} ({best_attack[1].get('interesting', 0)} hits)"
            )
        
        labeled = stats.get("labeled_findings", {})
        fp_count = labeled.get("false_positive", 0)
        tp_count = labeled.get("true_positive", 0) + labeled.get("confirmed_bug", 0)
        
        if fp_count + tp_count > 0:
            fp_rate = fp_count / (fp_count + tp_count)
            if fp_rate > 0.5:
                insights["recommendations"].append(
                    f"High false positive rate ({fp_rate:.1%}). Consider training AI models."
                )
            insights["patterns"]["false_positive_rate"] = round(fp_rate, 3)
        
        return insights
    
    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        with self._cache_lock:
            cache_size = len(self.cache)
        return {
            "local_ai": self.local_ai.get_status(),
            "remote_configured": self.remote_handler is not None,
            "stats": self.stats,
            "cache_size": cache_size,
            "insights": self.get_smart_insights()
        }
    
    def set_remote_handler(self, handler: Callable):
        """Set the remote AI handler"""
        self.remote_handler = handler


# ============================================================================
# SINGLETON & CONVENIENCE
# ============================================================================

_orchestrator_instance = None
_orchestrator_lock = threading.Lock()

def get_orchestrator() -> AIOrchestrator:
    """Get singleton orchestrator instance"""
    global _orchestrator_instance
    with _orchestrator_lock:
        if _orchestrator_instance is None:
            _orchestrator_instance = AIOrchestrator()
        return _orchestrator_instance


def classify_secret(features: Dict[str, Any]) -> Dict[str, Any]:
    """Classify a secret finding"""
    response = get_orchestrator().classify_secret(features)
    return response.result if response.success else {"error": response.error}


def score_endpoint(features: Dict[str, Any]) -> Dict[str, Any]:
    """Score endpoint vulnerability risk"""
    response = get_orchestrator().score_endpoint(features)
    return response.result if response.success else {"error": response.error}


def rank_payloads(payloads: List[Dict], context: Dict[str, Any]) -> List[Dict]:
    """Rank payloads by effectiveness"""
    response = get_orchestrator().rank_payloads(payloads, context)
    return response.result if response.success else []
