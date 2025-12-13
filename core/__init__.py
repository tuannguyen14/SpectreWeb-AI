"""SpectreWeb Core Module v4.5.1 - Self-Learning AI"""
from .cache import SimpleCache
from .executor import CommandExecutor, execute_command
from .file_manager import FileManager
from .telemetry import Telemetry
from .reporter import SpectreReport, Finding, get_report, auto_report
from .context import TargetContext, get_context, load_target_context, list_all_targets
from .formatter import (
    SpectreFormatter, Color, fmt,
    print_banner, print_status, print_finding, print_scan_header,
    print_scan_result, print_table, print_ai_insight, print_recommendations,
    print_box, print_summary
)
from .analyzer import (
    SmartAnalyzer, analyzer, AIInsight,
    analyze_response, detect_technologies, get_attack_vectors,
    classify_endpoint, analyze_scan, get_insights, get_findings, get_summary
)

# Self-Learning AI modules
from .learning_store import (
    LearningStore, Finding as LearningFinding, AttackRecord,
    FindingType, FeedbackLabel,
    get_store, add_secret_finding, add_endpoint_finding, record_attack
)
from .local_ai import (
    LocalAI, SecretClassifier, EndpointRiskScorer, PayloadRanker,
    get_local_ai, classify_secret, score_endpoint, rank_payloads,
    ML_AVAILABLE
)
from .ai_orchestrator import (
    AIOrchestrator, AIRequest, AIResponse, AIBackend, TaskType,
    get_orchestrator
)
