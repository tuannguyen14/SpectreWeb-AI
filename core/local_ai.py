"""
Local AI - Self-learning ML models for security analysis.

This module provides local machine learning models that:
- Learn from historical scan data and user feedback
- Improve over time without modifying core code
- Run fast locally (no API calls needed)

Models included:
1. SecretClassifier - Reduces false positives in secret detection
2. EndpointRiskScorer - Prioritizes endpoints by vulnerability likelihood
3. PayloadRanker - Selects most effective payloads for each context
4. SeverityPredictor - Predicts finding severity based on context

Uses scikit-learn compatible models with fallback to heuristics.
"""

import json
import pickle
import hashlib
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Try importing ML libraries, fallback gracefully
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[LocalAI] Warning: scikit-learn not available, using heuristics only")


class ModelStatus(Enum):
    NOT_TRAINED = "not_trained"
    TRAINING = "training"
    READY = "ready"
    NEEDS_RETRAIN = "needs_retrain"


@dataclass
class ModelInfo:
    """Metadata about a trained model"""
    name: str
    status: ModelStatus
    version: str
    trained_at: Optional[str]
    samples_count: int
    accuracy: float
    precision: float
    recall: float
    feature_names: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "version": self.version,
            "trained_at": self.trained_at,
            "samples_count": self.samples_count,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "feature_names": self.feature_names
        }


class BaseLocalModel:
    """Base class for local ML models with fallback to heuristics"""
    
    MODEL_DIR = Path.home() / ".spectreweb" / "models"
    MIN_SAMPLES = 50  # Minimum samples needed to train
    
    def __init__(self, name: str):
        self.name = name
        self.model = None
        self.scaler = None
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.feature_names: List[str] = []
        self.info = ModelInfo(
            name=name,
            status=ModelStatus.NOT_TRAINED,
            version="0.0.0",
            trained_at=None,
            samples_count=0,
            accuracy=0.0,
            precision=0.0,
            recall=0.0,
            feature_names=[]
        )
        
        self.MODEL_DIR.mkdir(parents=True, exist_ok=True)
        self._load_model()
    
    def _get_model_path(self) -> Path:
        return self.MODEL_DIR / f"{self.name}.pkl"
    
    def _load_model(self):
        """Load trained model from disk if exists"""
        path = self._get_model_path()
        if path.exists():
            try:
                with open(path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data.get('model')
                    self.scaler = data.get('scaler')
                    self.label_encoders = data.get('label_encoders', {})
                    self.feature_names = data.get('feature_names', [])
                    self.info = data.get('info', self.info)
                    self.info.status = ModelStatus.READY
                print(f"[LocalAI] Loaded model: {self.name} (v{self.info.version})")
            except Exception as e:
                print(f"[LocalAI] Error loading model {self.name}: {e}")
    
    def _save_model(self):
        """Save trained model to disk"""
        path = self._get_model_path()
        try:
            with open(path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler,
                    'label_encoders': self.label_encoders,
                    'feature_names': self.feature_names,
                    'info': self.info
                }, f)
            print(f"[LocalAI] Saved model: {self.name}")
        except Exception as e:
            print(f"[LocalAI] Error saving model {self.name}: {e}")
    
    def _extract_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract numerical features from data dict - override in subclass"""
        raise NotImplementedError
    
    def _heuristic_predict(self, data: Dict[str, Any]) -> Tuple[float, float]:
        """Fallback heuristic prediction - override in subclass"""
        raise NotImplementedError
    
    def predict(self, data: Dict[str, Any]) -> Tuple[float, float]:
        """
        Predict score/label for input data.
        
        Returns:
            (prediction, confidence)
        """
        # If model not ready, use heuristics
        if not ML_AVAILABLE or self.model is None:
            return self._heuristic_predict(data)
        
        try:
            features = self._extract_features(data)
            X = np.array([features])
            
            if self.scaler:
                X = self.scaler.transform(X)
            
            # Get prediction and probability
            pred = self.model.predict(X)[0]
            
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(X)[0]
                confidence = max(proba)
            else:
                confidence = 0.7  # Default confidence
            
            return float(pred), float(confidence)
            
        except Exception as e:
            print(f"[LocalAI] Prediction error: {e}")
            return self._heuristic_predict(data)
    
    def is_ready(self) -> bool:
        """Check if model is trained and ready"""
        return self.info.status == ModelStatus.READY and self.model is not None
    
    def get_info(self) -> Dict[str, Any]:
        """Get model info"""
        return self.info.to_dict()


class SecretClassifier(BaseLocalModel):
    """
    Classifies secrets as true positive or false positive.
    
    Features:
    - secret_type (encoded)
    - entropy
    - length
    - in_test_file (bool)
    - in_comment (bool)
    - has_placeholder (bool)
    - confidence
    """
    
    FEATURE_NAMES = [
        "secret_type_encoded", "entropy", "length", "in_test_file",
        "in_comment", "has_placeholder", "confidence", "context_length"
    ]
    
    def __init__(self):
        super().__init__("secret_classifier")
        self.feature_names = self.FEATURE_NAMES
    
    def _extract_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract features from secret finding data"""
        # Encode secret type
        secret_type = data.get("secret_type", "unknown")
        type_hash = int(hashlib.md5(secret_type.encode()).hexdigest()[:8], 16) % 100
        
        return [
            float(type_hash),
            float(data.get("entropy", 3.0)),
            float(data.get("length", 20)),
            float(data.get("in_test_file", False)),
            float(data.get("in_comment", False)),
            float(data.get("has_placeholder", False)),
            float(data.get("confidence", 0.5)),
            float(len(data.get("context", "")) / 100.0),
        ]
    
    def _heuristic_predict(self, data: Dict[str, Any]) -> Tuple[float, float]:
        """Heuristic-based secret classification"""
        score = 0.5
        
        # High entropy = more likely real
        entropy = data.get("entropy", 3.0)
        if entropy > 4.5:
            score += 0.2
        elif entropy < 2.5:
            score -= 0.2
        
        # Test file = less likely real
        if data.get("in_test_file", False):
            score -= 0.3
        
        # Placeholder patterns = less likely real
        if data.get("has_placeholder", False):
            score -= 0.4
        
        # Comment = less likely real
        if data.get("in_comment", False):
            score -= 0.1
        
        # High confidence from regex = more likely real
        confidence = data.get("confidence", 0.5)
        score += (confidence - 0.5) * 0.3
        
        # Clamp to [0, 1]
        score = max(0.0, min(1.0, score))
        
        return score, 0.6  # Fixed confidence for heuristics
    
    def train(self, features_list: List[Dict], labels: List[int]) -> bool:
        """Train the model on labeled data"""
        if not ML_AVAILABLE:
            print("[LocalAI] Cannot train: scikit-learn not available")
            return False
        
        if len(features_list) < self.MIN_SAMPLES:
            print(f"[LocalAI] Need at least {self.MIN_SAMPLES} samples, got {len(features_list)}")
            return False
        
        try:
            self.info.status = ModelStatus.TRAINING
            
            # Extract features
            X = np.array([self._extract_features(f) for f in features_list])
            y = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Scale features
            self.scaler = StandardScaler()
            X_train = self.scaler.fit_transform(X_train)
            X_test = self.scaler.transform(X_test)
            
            # Train model
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                random_state=42
            )
            self.model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test)
            
            self.info = ModelInfo(
                name=self.name,
                status=ModelStatus.READY,
                version=f"1.{len(features_list)}",
                trained_at=datetime.now().isoformat(),
                samples_count=len(features_list),
                accuracy=accuracy_score(y_test, y_pred),
                precision=precision_score(y_test, y_pred, zero_division=0),
                recall=recall_score(y_test, y_pred, zero_division=0),
                feature_names=self.FEATURE_NAMES
            )
            
            self._save_model()
            print(f"[LocalAI] Trained {self.name}: accuracy={self.info.accuracy:.2f}")
            return True
            
        except Exception as e:
            print(f"[LocalAI] Training error: {e}")
            self.info.status = ModelStatus.NOT_TRAINED
            return False


class EndpointRiskScorer(BaseLocalModel):
    """
    Scores endpoints by vulnerability likelihood.
    
    Features:
    - endpoint_type (encoded)
    - method (encoded)
    - has_id_param
    - has_auth_keyword
    - has_file_keyword
    - path_depth
    - tech_stack_encoded
    """
    
    FEATURE_NAMES = [
        "endpoint_type_encoded", "method_encoded", "has_id_param",
        "has_auth_keyword", "has_file_keyword", "path_depth",
        "tech_count", "has_db_tech"
    ]
    
    # High-risk endpoint types
    HIGH_RISK_TYPES = ["auth", "admin", "payment", "user", "file", "api"]
    
    def __init__(self):
        super().__init__("endpoint_risk_scorer")
        self.feature_names = self.FEATURE_NAMES
    
    def _extract_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract features from endpoint data"""
        endpoint_type = data.get("endpoint_type", "unknown")
        method = data.get("method", "GET")
        tech_stack = data.get("tech_stack", [])
        path = data.get("path", "")
        
        # Encode categoricals
        type_hash = int(hashlib.md5(endpoint_type.encode()).hexdigest()[:8], 16) % 100
        method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4}
        method_encoded = method_map.get(method.upper(), 0)
        
        # Check for risky patterns
        path_lower = path.lower()
        has_id = any(p in path_lower for p in ["id=", "user_id", "userid", "/id/", "/{id}"])
        has_auth = any(p in path_lower for p in ["auth", "login", "token", "session", "password"])
        has_file = any(p in path_lower for p in ["file", "upload", "download", "image", "doc"])
        
        # Tech stack analysis
        db_techs = ["mysql", "postgres", "mongodb", "redis", "sqlite"]
        has_db = any(t.lower() in db_techs for t in tech_stack)
        
        return [
            float(type_hash),
            float(method_encoded),
            float(has_id),
            float(has_auth),
            float(has_file),
            float(path.count("/")),
            float(len(tech_stack)),
            float(has_db),
        ]
    
    def _heuristic_predict(self, data: Dict[str, Any]) -> Tuple[float, float]:
        """Heuristic-based endpoint risk scoring"""
        score = 0.3  # Base score
        
        endpoint_type = data.get("endpoint_type", "unknown").lower()
        method = data.get("method", "GET").upper()
        path = data.get("path", "").lower()
        
        # High-risk endpoint types
        if endpoint_type in self.HIGH_RISK_TYPES:
            score += 0.3
        
        # POST/PUT/DELETE more risky than GET
        if method in ["POST", "PUT", "DELETE"]:
            score += 0.1
        
        # ID parameters suggest IDOR potential
        if any(p in path for p in ["id=", "user_id", "userid", "/{id}"]):
            score += 0.2
        
        # Auth endpoints are high-value
        if "auth" in path or "login" in path or "password" in path:
            score += 0.2
        
        # File operations risky
        if "file" in path or "upload" in path:
            score += 0.15
        
        # Admin endpoints
        if "admin" in path:
            score += 0.25
        
        return min(1.0, score), 0.6


class PayloadRanker(BaseLocalModel):
    """
    Ranks payloads by effectiveness for given context.
    
    Learns which payload types work best for:
    - Different endpoint types
    - Different tech stacks
    - Different WAF levels
    """
    
    FEATURE_NAMES = [
        "endpoint_type_encoded", "attack_type_encoded", "payload_type_encoded",
        "waf_bypass_level", "tech_count", "has_php", "has_java", "has_node"
    ]
    
    def __init__(self):
        super().__init__("payload_ranker")
        self.feature_names = self.FEATURE_NAMES
        self.effectiveness_cache: Dict[str, float] = {}
    
    def _extract_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract features for payload ranking"""
        endpoint_type = data.get("endpoint_type", "unknown")
        attack_type = data.get("attack_type", "injection")
        payload_type = data.get("payload_type", "generic")
        tech_stack = data.get("tech_stack", [])
        
        # Encode categoricals
        et_hash = int(hashlib.md5(endpoint_type.encode()).hexdigest()[:8], 16) % 100
        at_hash = int(hashlib.md5(attack_type.encode()).hexdigest()[:8], 16) % 100
        pt_hash = int(hashlib.md5(payload_type.encode()).hexdigest()[:8], 16) % 100
        
        tech_lower = [t.lower() for t in tech_stack]
        
        return [
            float(et_hash),
            float(at_hash),
            float(pt_hash),
            float(data.get("waf_bypass_level", 0)),
            float(len(tech_stack)),
            float("php" in tech_lower),
            float("java" in tech_lower or "spring" in tech_lower),
            float("node" in tech_lower or "express" in tech_lower),
        ]
    
    def _heuristic_predict(self, data: Dict[str, Any]) -> Tuple[float, float]:
        """Heuristic payload effectiveness prediction"""
        score = 0.5
        
        attack_type = data.get("attack_type", "injection")
        endpoint_type = data.get("endpoint_type", "unknown")
        tech_stack = [t.lower() for t in data.get("tech_stack", [])]
        
        # SQLi more effective on auth/db endpoints
        if attack_type == "sqli" and endpoint_type in ["auth", "user", "api"]:
            score += 0.2
        
        # XSS more effective on content-displaying endpoints
        if attack_type == "xss" and endpoint_type in ["user", "content", "search"]:
            score += 0.2
        
        # LFI more effective on file endpoints
        if attack_type == "lfi" and "file" in endpoint_type:
            score += 0.3
        
        # Tech-specific adjustments
        if "php" in tech_stack and attack_type in ["lfi", "sqli"]:
            score += 0.1
        
        if "mysql" in tech_stack and attack_type == "sqli":
            score += 0.1
        
        return min(1.0, score), 0.5
    
    def rank_payloads(
        self, 
        payloads: List[Dict[str, Any]], 
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Rank payloads by predicted effectiveness.
        
        Args:
            payloads: List of {payload, payload_type, ...}
            context: {endpoint_type, tech_stack, ...}
        
        Returns:
            Payloads sorted by predicted effectiveness
        """
        scored = []
        for p in payloads:
            data = {**context, **p}
            score, confidence = self.predict(data)
            scored.append({
                **p,
                "predicted_score": score,
                "confidence": confidence
            })
        
        # Sort by score descending
        scored.sort(key=lambda x: x["predicted_score"], reverse=True)
        return scored


# ============================================================================
# AI ORCHESTRATOR
# ============================================================================

class LocalAI:
    """
    Orchestrates all local AI models.
    
    Provides unified interface for:
    - Predictions (with automatic fallback to heuristics)
    - Training (when enough data available)
    - Model management
    """
    
    def __init__(self):
        self.secret_classifier = SecretClassifier()
        self.endpoint_scorer = EndpointRiskScorer()
        self.payload_ranker = PayloadRanker()
        
        print(f"[LocalAI] Initialized with ML_AVAILABLE={ML_AVAILABLE}")
    
    def classify_secret(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a secret as true/false positive.
        
        Returns:
            {is_real: bool, confidence: float, model_used: str}
        """
        score, confidence = self.secret_classifier.predict(features)
        
        return {
            "is_real": score > 0.5,
            "score": score,
            "confidence": confidence,
            "model_used": "ml" if self.secret_classifier.is_ready() else "heuristic"
        }
    
    def score_endpoint(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score an endpoint by vulnerability risk.
        
        Returns:
            {risk_score: float, confidence: float, priority: str}
        """
        score, confidence = self.endpoint_scorer.predict(features)
        
        if score > 0.7:
            priority = "high"
        elif score > 0.4:
            priority = "medium"
        else:
            priority = "low"
        
        return {
            "risk_score": score,
            "confidence": confidence,
            "priority": priority,
            "model_used": "ml" if self.endpoint_scorer.is_ready() else "heuristic"
        }
    
    def rank_payloads(
        self, 
        payloads: List[Dict], 
        context: Dict[str, Any]
    ) -> List[Dict]:
        """Rank payloads by predicted effectiveness"""
        return self.payload_ranker.rank_payloads(payloads, context)
    
    def train_all(self, store) -> Dict[str, Any]:
        """
        Train all models from learning store data.
        
        Args:
            store: LearningStore instance
        
        Returns:
            Training results for each model
        """
        results = {}
        
        # Train secret classifier
        features, labels = store.get_training_data_secrets()
        if len(features) >= SecretClassifier.MIN_SAMPLES:
            success = self.secret_classifier.train(features, labels)
            results["secret_classifier"] = {
                "success": success,
                "samples": len(features),
                "info": self.secret_classifier.get_info()
            }
        else:
            results["secret_classifier"] = {
                "success": False,
                "reason": f"Need {SecretClassifier.MIN_SAMPLES} samples, got {len(features)}"
            }
        
        # Train endpoint scorer
        features, labels = store.get_training_data_endpoints()
        if len(features) >= EndpointRiskScorer.MIN_SAMPLES:
            success = self.endpoint_scorer.train(features, labels)
            results["endpoint_scorer"] = {
                "success": success,
                "samples": len(features),
                "info": self.endpoint_scorer.get_info()
            }
        else:
            results["endpoint_scorer"] = {
                "success": False,
                "reason": f"Need {EndpointRiskScorer.MIN_SAMPLES} samples, got {len(features)}"
            }
        
        return results
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all models"""
        return {
            "ml_available": ML_AVAILABLE,
            "models": {
                "secret_classifier": self.secret_classifier.get_info(),
                "endpoint_scorer": self.endpoint_scorer.get_info(),
                "payload_ranker": self.payload_ranker.get_info(),
            }
        }


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

_local_ai_instance = None

def get_local_ai() -> LocalAI:
    """Get singleton LocalAI instance"""
    global _local_ai_instance
    if _local_ai_instance is None:
        _local_ai_instance = LocalAI()
    return _local_ai_instance


# Convenience functions
def classify_secret(features: Dict[str, Any]) -> Dict[str, Any]:
    """Classify a secret finding"""
    return get_local_ai().classify_secret(features)


def score_endpoint(features: Dict[str, Any]) -> Dict[str, Any]:
    """Score an endpoint's risk"""
    return get_local_ai().score_endpoint(features)


def rank_payloads(payloads: List[Dict], context: Dict[str, Any]) -> List[Dict]:
    """Rank payloads by effectiveness"""
    return get_local_ai().rank_payloads(payloads, context)
