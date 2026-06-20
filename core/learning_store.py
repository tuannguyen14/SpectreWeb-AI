"""
Learning Store - Persistent storage for findings, feedback, and training data.

This module provides the data layer for the self-learning AI system:
- Store scan findings with rich metadata
- Collect user feedback (true positive, false positive, severity adjustments)
- Track attack effectiveness (which payloads worked on which endpoints)
- Export training data for local models

Storage: SQLite for durability + JSON export for portability
"""

import sqlite3
import json
import hashlib
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class FindingType(Enum):
    SECRET = "secret"
    VULNERABILITY = "vulnerability"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    ATTACK_RESULT = "attack_result"


class FeedbackLabel(Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED_BUG = "confirmed_bug"
    NOT_EXPLOITABLE = "not_exploitable"


@dataclass
class Finding:
    """Represents a finding that can be stored and learned from"""
    finding_id: str
    finding_type: str
    target: str
    source: str
    timestamp: str
    
    # Core data
    title: str
    description: str
    severity: str
    confidence: float
    
    # Rich metadata for learning
    features: Dict[str, Any]  # Extracted features for ML
    raw_data: Dict[str, Any]  # Original finding data
    context: str  # Surrounding context
    
    # Feedback
    label: Optional[str] = None
    label_timestamp: Optional[str] = None
    notes: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackRecord:
    """Records an attack attempt for learning payload effectiveness"""
    record_id: str
    timestamp: str
    target_url: str
    endpoint_type: str
    tech_stack: List[str]
    
    # Attack details
    attack_type: str
    payload: str
    payload_type: str
    injection_location: str
    waf_bypass_level: int
    
    # Results
    status_code: int
    response_length: int
    response_time: float
    interesting: bool
    findings: List[str]
    severity: str
    
    # Features for learning
    features: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LearningStore:
    """
    Persistent storage for learning data.
    
    Thread-safe SQLite-backed store with:
    - Findings (secrets, vulns, endpoints)
    - Attack records (payload effectiveness)
    - User feedback (labels, notes)
    - Training data export
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = Path.home() / ".spectreweb" / "learning.db"
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.lock = threading.Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema"""
        with self.lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    finding_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    source TEXT,
                    timestamp TEXT NOT NULL,
                    title TEXT,
                    description TEXT,
                    severity TEXT,
                    confidence REAL,
                    features TEXT,
                    raw_data TEXT,
                    context TEXT,
                    label TEXT,
                    label_timestamp TEXT,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Attack records table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_records (
                    record_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    endpoint_type TEXT,
                    tech_stack TEXT,
                    attack_type TEXT,
                    payload TEXT,
                    payload_type TEXT,
                    injection_location TEXT,
                    waf_bypass_level INTEGER,
                    status_code INTEGER,
                    response_length INTEGER,
                    response_time REAL,
                    interesting INTEGER,
                    findings TEXT,
                    severity TEXT,
                    features TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Feedback history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feedback_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    old_label TEXT,
                    new_label TEXT,
                    notes TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
                )
            """)
            
            # Model metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS model_metadata (
                    model_name TEXT PRIMARY KEY,
                    version TEXT,
                    trained_at TEXT,
                    samples_count INTEGER,
                    accuracy REAL,
                    config TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Indexes for fast queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_label ON findings(label)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attacks_type ON attack_records(attack_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attacks_interesting ON attack_records(interesting)")
            
            conn.commit()
            conn.close()
    
    def _get_conn(self) -> sqlite3.Connection:
        """Get a new connection (for thread safety)"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    # =========================================================================
    # FINDINGS CRUD
    # =========================================================================
    
    def add_finding(self, finding: Finding) -> bool:
        """Add a new finding to the store"""
        with self.lock:
            conn = None
            try:
                conn = self._get_conn()
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO findings 
                    (finding_id, finding_type, target, source, timestamp,
                     title, description, severity, confidence,
                     features, raw_data, context, label, label_timestamp, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding.finding_id,
                    finding.finding_type,
                    finding.target,
                    finding.source,
                    finding.timestamp,
                    finding.title,
                    finding.description,
                    finding.severity,
                    finding.confidence,
                    json.dumps(finding.features),
                    json.dumps(finding.raw_data),
                    finding.context,
                    finding.label,
                    finding.label_timestamp,
                    finding.notes
                ))
                
                conn.commit()
                return True
            except Exception as e:
                print(f"[LearningStore] Error adding finding: {e}")
                return False
            finally:
                if conn:
                    conn.close()
    
    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get a finding by ID"""
        conn = None
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_finding(row)
            return None
        finally:
            if conn:
                conn.close()
    
    def label_finding(
        self, 
        finding_id: str, 
        label: str, 
        notes: str = None
    ) -> bool:
        """Label a finding (true positive, false positive, etc.)"""
        with self.lock:
            conn = None
            try:
                conn = self._get_conn()
                cursor = conn.cursor()
                
                # Get old label for history
                cursor.execute("SELECT label FROM findings WHERE finding_id = ?", (finding_id,))
                row = cursor.fetchone()
                old_label = row["label"] if row else None
                
                # Update finding
                now = datetime.now().isoformat()
                cursor.execute("""
                    UPDATE findings 
                    SET label = ?, label_timestamp = ?, notes = COALESCE(?, notes)
                    WHERE finding_id = ?
                """, (label, now, notes, finding_id))
                
                # Record history
                cursor.execute("""
                    INSERT INTO feedback_history (finding_id, old_label, new_label, notes)
                    VALUES (?, ?, ?, ?)
                """, (finding_id, old_label, label, notes))
                
                conn.commit()
                return True
            except Exception as e:
                print(f"[LearningStore] Error labeling finding: {e}")
                return False
            finally:
                if conn:
                    conn.close()
    
    def get_findings(
        self,
        finding_type: str = None,
        target: str = None,
        label: str = None,
        limit: int = 1000
    ) -> List[Finding]:
        """Query findings with filters"""
        conn = None
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            
            if finding_type:
                query += " AND finding_type = ?"
                params.append(finding_type)
            if target:
                query += " AND target LIKE ?"
                params.append(f"%{target}%")
            if label:
                query += " AND label = ?"
                params.append(label)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            return [self._row_to_finding(row) for row in rows]
        finally:
            if conn:
                conn.close()
    
    def _row_to_finding(self, row) -> Finding:
        """Convert database row to Finding object"""
        return Finding(
            finding_id=row["finding_id"],
            finding_type=row["finding_type"],
            target=row["target"],
            source=row["source"],
            timestamp=row["timestamp"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            confidence=row["confidence"],
            features=json.loads(row["features"]) if row["features"] else {},
            raw_data=json.loads(row["raw_data"]) if row["raw_data"] else {},
            context=row["context"],
            label=row["label"],
            label_timestamp=row["label_timestamp"],
            notes=row["notes"]
        )
    
    # =========================================================================
    # ATTACK RECORDS
    # =========================================================================
    
    def add_attack_record(self, record: AttackRecord) -> bool:
        """Add an attack record for learning payload effectiveness"""
        with self.lock:
            conn = None
            try:
                conn = self._get_conn()
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO attack_records
                    (record_id, timestamp, target_url, endpoint_type, tech_stack,
                     attack_type, payload, payload_type, injection_location, waf_bypass_level,
                     status_code, response_length, response_time, interesting, findings, severity, features)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.record_id,
                    record.timestamp,
                    record.target_url,
                    record.endpoint_type,
                    json.dumps(record.tech_stack),
                    record.attack_type,
                    record.payload,
                    record.payload_type,
                    record.injection_location,
                    record.waf_bypass_level,
                    record.status_code,
                    record.response_length,
                    record.response_time,
                    1 if record.interesting else 0,
                    json.dumps(record.findings),
                    record.severity,
                    json.dumps(record.features)
                ))
                
                conn.commit()
                return True
            except Exception as e:
                print(f"[LearningStore] Error adding attack record: {e}")
                return False
            finally:
                if conn:
                    conn.close()
    
    def get_attack_records(
        self,
        attack_type: str = None,
        interesting_only: bool = False,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Query attack records"""
        conn = None
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            query = "SELECT * FROM attack_records WHERE 1=1"
            params = []
            
            if attack_type:
                query += " AND attack_type = ?"
                params.append(attack_type)
            if interesting_only:
                query += " AND interesting = 1"
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            return [dict(row) for row in rows]
        finally:
            if conn:
                conn.close()
    
    # =========================================================================
    # TRAINING DATA EXPORT
    # =========================================================================
    
    def get_training_data_secrets(self) -> Tuple[List[Dict], List[int]]:
        """
        Export training data for secret FP classifier.
        
        Returns:
            features: List of feature dicts
            labels: List of labels (1 = real secret, 0 = false positive)
        """
        findings = self.get_findings(finding_type="secret")
        
        features = []
        labels = []
        
        for f in findings:
            if f.label in [FeedbackLabel.TRUE_POSITIVE.value, FeedbackLabel.CONFIRMED_BUG.value]:
                labels.append(1)
            elif f.label == FeedbackLabel.FALSE_POSITIVE.value:
                labels.append(0)
            else:
                continue  # Skip unlabeled
            
            features.append(f.features)
        
        return features, labels
    
    def get_training_data_endpoints(self) -> Tuple[List[Dict], List[int]]:
        """
        Export training data for endpoint risk scorer.
        
        Returns:
            features: List of feature dicts
            labels: List of labels (1 = had vulnerability, 0 = clean)
        """
        conn = None
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            # Get all endpoint findings with their attack results
            cursor.execute("""
                SELECT f.*, 
                       (SELECT COUNT(*) FROM attack_records a 
                        WHERE a.target_url LIKE '%' || f.target || '%' AND a.interesting = 1) as vuln_count
                FROM findings f
                WHERE f.finding_type = 'endpoint'
            """)
            
            rows = cursor.fetchall()
            
            features = []
            labels = []
            
            for row in rows:
                f_data = json.loads(row["features"]) if row["features"] else {}
                features.append(f_data)
                labels.append(1 if row["vuln_count"] > 0 else 0)
            
            return features, labels
        finally:
            if conn:
                conn.close()
    
    def get_training_data_payloads(self) -> List[Dict[str, Any]]:
        """
        Export training data for payload effectiveness.
        
        Returns:
            List of {features, payload_type, interesting}
        """
        records = self.get_attack_records(limit=10000)
        
        data = []
        for r in records:
            data.append({
                "endpoint_type": r.get("endpoint_type"),
                "tech_stack": json.loads(r.get("tech_stack", "[]")),
                "attack_type": r.get("attack_type"),
                "payload_type": r.get("payload_type"),
                "waf_bypass_level": r.get("waf_bypass_level"),
                "interesting": r.get("interesting"),
                "features": json.loads(r.get("features", "{}"))
            })
        
        return data
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get learning store statistics"""
        conn = None
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            stats = {}
            
            # Findings stats
            cursor.execute("SELECT COUNT(*) FROM findings")
            stats["total_findings"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT finding_type, COUNT(*) FROM findings GROUP BY finding_type")
            stats["findings_by_type"] = {row[0]: row[1] for row in cursor.fetchall()}
            
            cursor.execute("SELECT label, COUNT(*) FROM findings WHERE label IS NOT NULL GROUP BY label")
            stats["labeled_findings"] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Attack stats
            cursor.execute("SELECT COUNT(*) FROM attack_records")
            stats["total_attacks"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM attack_records WHERE interesting = 1")
            stats["interesting_attacks"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT attack_type, COUNT(*), SUM(interesting) FROM attack_records GROUP BY attack_type")
            stats["attacks_by_type"] = {
                row[0]: {"total": row[1], "interesting": row[2] or 0} 
                for row in cursor.fetchall()
            }
            
            return stats
        finally:
            if conn:
                conn.close()
    
    def export_to_json(self, output_path: str) -> bool:
        """Export all data to JSON for backup/portability"""
        try:
            data = {
                "exported_at": datetime.now().isoformat(),
                "stats": self.get_stats(),
                "findings": [f.to_dict() for f in self.get_findings(limit=100000)],
                "attack_records": self.get_attack_records(limit=100000)
            }
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"[LearningStore] Export error: {e}")
            return False


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

_store_instance = None
_store_lock = threading.Lock()

def get_store() -> LearningStore:
    """Get singleton store instance (thread-safe)"""
    global _store_instance
    with _store_lock:
        if _store_instance is None:
            _store_instance = LearningStore()
        return _store_instance


def add_secret_finding(
    target: str,
    secret_type: str,
    value_masked: str,
    source: str,
    confidence: float,
    severity: str,
    context: str = "",
    features: Dict = None
) -> str:
    """Convenience function to add a secret finding"""
    finding_id = hashlib.sha256(f"{target}:{secret_type}:{value_masked}".encode()).hexdigest()[:16]
    
    finding = Finding(
        finding_id=f"secret_{finding_id}",
        finding_type=FindingType.SECRET.value,
        target=target,
        source=source,
        timestamp=datetime.now().isoformat(),
        title=f"{secret_type} found",
        description=f"Potential {secret_type} detected in {source}",
        severity=severity,
        confidence=confidence,
        features=features or {},
        raw_data={"type": secret_type, "value_masked": value_masked},
        context=context[:500]
    )
    
    get_store().add_finding(finding)
    return finding.finding_id


def add_endpoint_finding(
    target: str,
    url: str,
    method: str,
    endpoint_type: str,
    tech_stack: List[str],
    features: Dict = None
) -> str:
    """Convenience function to add an endpoint finding"""
    finding_id = hashlib.sha256(f"{url}:{method}".encode()).hexdigest()[:16]
    
    finding = Finding(
        finding_id=f"endpoint_{finding_id}",
        finding_type=FindingType.ENDPOINT.value,
        target=target,
        source=url,
        timestamp=datetime.now().isoformat(),
        title=f"{method} {url}",
        description=f"Endpoint classified as {endpoint_type}",
        severity="info",
        confidence=1.0,
        features=features or {
            "method": method,
            "endpoint_type": endpoint_type,
            "tech_stack": tech_stack,
            "path_segments": url.split("/"),
        },
        raw_data={"url": url, "method": method, "type": endpoint_type},
        context=""
    )
    
    get_store().add_finding(finding)
    return finding.finding_id


def record_attack(
    target_url: str,
    endpoint_type: str,
    tech_stack: List[str],
    attack_type: str,
    payload: str,
    payload_type: str,
    status_code: int,
    response_length: int,
    response_time: float,
    interesting: bool,
    findings: List[str],
    severity: str,
    injection_location: str = "query",
    waf_bypass_level: int = 0
) -> str:
    """Convenience function to record an attack"""
    record_id = hashlib.sha256(
        f"{target_url}:{payload}:{datetime.now().isoformat()}".encode()
    ).hexdigest()[:16]
    
    record = AttackRecord(
        record_id=f"attack_{record_id}",
        timestamp=datetime.now().isoformat(),
        target_url=target_url,
        endpoint_type=endpoint_type,
        tech_stack=tech_stack,
        attack_type=attack_type,
        payload=payload[:200],  # Truncate long payloads
        payload_type=payload_type,
        injection_location=injection_location,
        waf_bypass_level=waf_bypass_level,
        status_code=status_code,
        response_length=response_length,
        response_time=response_time,
        interesting=interesting,
        findings=findings,
        severity=severity,
        features={
            "payload_length": len(payload),
            "has_special_chars": any(c in payload for c in "<>\"'();"),
            "is_encoded": "%" in payload or "&#" in payload,
        }
    )
    
    get_store().add_attack_record(record)
    return record.record_id
