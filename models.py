#!/usr/bin/env python3
"""
Advanced LLM Fuzzing Monitor - Core Data Models
Part 1: Project Structure, Core Models & Base Infrastructure

Master's Thesis Research: "Enhancing Automated Security Testing in CI/CD/CT Pipelines with Large Language Models"
Author: Morris Darren Babu
Version: 3.0.0
License: MIT
"""

import os
import re
import sys
import json
import time
import uuid
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Protocol
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
import getpass
import pwd

# Third-party imports with error handling
try:
    import psutil
    import numpy as np
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install psutil numpy requests")
    sys.exit(1)

__version__ = "3.0.0"
__author__ = "Morris Darren Babu"

# Pre-compiled regex patterns for performance
SPARK_PATTERNS = [
    re.compile(r'cifuzz.*spark', re.IGNORECASE),
    re.compile(r'ci-fuzz.*spark', re.IGNORECASE),
    re.compile(r'cifuzz.*ai', re.IGNORECASE),
    re.compile(r'spark.*fuzz', re.IGNORECASE),
    re.compile(r'cifuzz.*llm', re.IGNORECASE),
    re.compile(r'fuzz.*ai', re.IGNORECASE),
    re.compile(r'llm.*fuzz', re.IGNORECASE),
    re.compile(r'intelligent.*fuzz', re.IGNORECASE),
]

LLM_API_PATTERNS = {
    'openai': re.compile(r'POST.*openai.*completions.*tokens.*(\d+)', re.IGNORECASE),
    'anthropic': re.compile(r'POST.*anthropic.*messages.*tokens.*(\d+)', re.IGNORECASE),
    'ollama': re.compile(r'POST.*localhost:11434.*generate', re.IGNORECASE),
    'huggingface': re.compile(r'POST.*huggingface.*inference', re.IGNORECASE),
}

VULNERABILITY_PATTERNS = {
    'buffer_overflow': re.compile(r'stack.*overflow|heap.*overflow|buffer.*overflow', re.IGNORECASE),
    'use_after_free': re.compile(r'use.*after.*free|heap.*corruption|double.*free', re.IGNORECASE),
    'null_pointer': re.compile(r'sigsegv|access.*violation|null.*pointer', re.IGNORECASE),
    'memory_leak': re.compile(r'memory.*leak|leak.*detected', re.IGNORECASE),
}

class SessionStatus(Enum):
    """Session status enumeration"""
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    ANALYZING = "analyzing"

class LLMProvider(Enum):
    """Supported LLM providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    HUGGINGFACE = "huggingface"
    LOCALAI = "localai"
    TOGETHER = "together"
    COHERE = "cohere"
    UNKNOWN = "unknown"

class VulnerabilityType(Enum):
    """Vulnerability classification"""
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    INTEGER_OVERFLOW = "integer_overflow"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    MEMORY_LEAK = "memory_leak"
    UNKNOWN = "unknown"

class SecuritySeverity(Enum):
    """Security severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class LLMInteraction:
    """Comprehensive LLM interaction tracking with enhanced metadata"""
    # Core identification
    interaction_id: str
    session_id: str
    timestamp: str
    
    # LLM configuration
    llm_provider: LLMProvider
    llm_model: str
    llm_endpoint: str
    
    # Interaction details
    prompt_type: str  # "fuzz_driver_generation", "test_case_generation", "vulnerability_analysis"
    prompt_text: str
    response_text: str
    
    # Token metrics
    prompt_tokens: int
    response_tokens: int
    total_tokens: int
    
    # Performance metrics
    response_time_ms: float
    queue_time_ms: float = 0.0
    processing_time_ms: float = 0.0
    
    # LLM parameters
    temperature: float = 0.0
    top_p: float = 0.0
    max_tokens: int = 0
    
    # Status and error handling
    success: bool = True
    error_message: Optional[str] = None
    retry_count: int = 0
    
    # Quality analysis
    hallucination_detected: bool = False
    hallucination_confidence: float = 0.0
    code_quality_score: float = 0.0
    security_risk_score: float = 0.0
    
    # Code analysis results
    compilation_success: bool = False
    syntax_errors: List[str] = field(default_factory=list)
    semantic_errors: List[str] = field(default_factory=list)
    
    # Cost analysis
    cost_estimate_usd: float = 0.0
    cost_model_version: str = "v1.0"
    
    # Metadata
    api_endpoint_used: str = ""
    request_headers_hash: str = ""
    context_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and enhancement"""
        if not self.interaction_id:
            self.interaction_id = f"llm_{self.session_id}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        
        # Validate token counts
        if self.total_tokens == 0 and (self.prompt_tokens > 0 or self.response_tokens > 0):
            self.total_tokens = self.prompt_tokens + self.response_tokens

@dataclass
class CodeMetrics:
    """Detailed code quality and complexity metrics"""
    lines_of_code: int = 0
    lines_of_comments: int = 0
    blank_lines: int = 0
    
    # Complexity metrics
    cyclomatic_complexity: int = 0
    cognitive_complexity: int = 0
    nesting_depth: int = 0
    
    # Function/class metrics
    function_count: int = 0
    class_count: int = 0
    method_count: int = 0
    
    # Code quality indicators
    duplicate_lines: int = 0
    magic_numbers_count: int = 0
    long_parameter_lists: int = 0
    
    # Documentation metrics
    documentation_coverage: float = 0.0
    api_documentation_coverage: float = 0.0
    
    # Language-specific metrics
    language_specific_metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityFinding:
    """Detailed security vulnerability finding"""
    finding_id: str
    session_id: str
    driver_id: Optional[str] = None
    
    # Classification
    vulnerability_type: VulnerabilityType = VulnerabilityType.UNKNOWN
    severity: SecuritySeverity = SecuritySeverity.INFO
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    
    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    code_snippet: str = ""
    
    # Analysis details
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    false_positive_probability: float = 0.0
    
    # Impact assessment
    exploitability: str = "unknown"  # "high", "medium", "low", "unknown"
    impact_score: float = 0.0
    attack_vectors: List[str] = field(default_factory=list)
    
    # Remediation
    remediation_suggestions: List[str] = field(default_factory=list)
    remediation_effort: str = "unknown"  # "low", "medium", "high", "unknown"
    
    # Metadata
    detection_method: str = ""
    detection_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    verification_status: str = "unverified"  # "verified", "false_positive", "unverified"
    
    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = f"vuln_{self.session_id}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"

@dataclass
class FuzzDriverMetrics:
    """Comprehensive fuzz driver analysis and performance metrics"""
    # Core identification
    driver_id: str
    session_id: str
    generation_timestamp: str
    
    # Generation details
    generation_method: str  # "llm_generated", "template_based", "hybrid", "manual"
    llm_model_used: Optional[str] = None
    generation_prompt: str = ""
    
    # Source code analysis
    source_code: str = ""
    source_code_hash: str = ""
    file_path: Optional[str] = None
    
    # Code metrics
    code_metrics: CodeMetrics = field(default_factory=CodeMetrics)
    
    # Compilation results
    compilation_time_ms: float = 0.0
    compilation_success: bool = False
    compilation_errors: List[str] = field(default_factory=list)
    compilation_warnings: List[str] = field(default_factory=list)
    compiler_version: str = ""
    compiler_flags: List[str] = field(default_factory=list)
    
    # Coverage metrics
    line_coverage_percentage: float = 0.0
    branch_coverage_percentage: float = 0.0
    function_coverage_percentage: float = 0.0
    mcdc_coverage_percentage: float = 0.0  # Modified Condition/Decision Coverage
    
    # Fuzzing effectiveness
    total_executions: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0
    edge_coverage: int = 0
    corpus_size: int = 0
    
    # Performance metrics
    executions_per_second: float = 0.0
    average_execution_time_ms: float = 0.0
    peak_memory_usage_mb: float = 0.0
    cpu_usage_percentage: float = 0.0
    
    # Security findings
    security_findings: List[SecurityFinding] = field(default_factory=list)
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    # Quality scores
    overall_quality_score: float = 0.0
    maintainability_index: float = 0.0
    security_score: float = 0.0
    performance_score: float = 0.0
    
    # Comparison metrics
    baseline_comparison: Dict[str, float] = field(default_factory=dict)
    improvement_metrics: Dict[str, float] = field(default_factory=dict)
    
    # Metadata
    target_language: str = "unknown"
    target_architecture: str = "unknown"
    fuzzing_engine: str = "unknown"
    
    def __post_init__(self):
        if not self.driver_id:
            self.driver_id = f"driver_{self.session_id}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        
        if not self.generation_timestamp:
            self.generation_timestamp = datetime.now().isoformat()
        
        if self.source_code and not self.source_code_hash:
            self.source_code_hash = hashlib.sha256(self.source_code.encode()).hexdigest()

@dataclass
class ProjectAnalysis:
    """Comprehensive project analysis results"""
    analysis_id: str
    project_path: str
    analysis_timestamp: str
    
    # Basic project information
    project_name: str = ""
    project_version: str = ""
    primary_language: str = "unknown"
    supported_languages: List[str] = field(default_factory=list)
    
    # Size and complexity metrics
    total_lines_of_code: int = 0
    total_files: int = 0
    total_directories: int = 0
    project_complexity_score: float = 0.0
    
    # Build system analysis
    build_system: str = "unknown"
    build_files: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    dev_dependencies: List[str] = field(default_factory=list)
    
    # Testing infrastructure
    existing_tests_count: int = 0
    test_frameworks: List[str] = field(default_factory=list)
    test_coverage_percentage: float = 0.0
    
    # Security analysis
    security_annotations_found: int = 0
    security_frameworks: List[str] = field(default_factory=list)
    potential_security_hotspots: List[str] = field(default_factory=list)
    
    # Git repository analysis
    git_branch: str = "unknown"
    git_commit_hash: Optional[str] = None
    git_commit_message: str = ""
    git_dirty: bool = False
    git_remote_url: Optional[str] = None
    
    # CI/CD analysis
    ci_config_files: List[str] = field(default_factory=list)
    ci_providers: List[str] = field(default_factory=list)
    deployment_configs: List[str] = field(default_factory=list)
    
    # Code quality metrics
    code_quality_score: float = 0.0
    maintainability_score: float = 0.0
    technical_debt_ratio: float = 0.0
    
    def __post_init__(self):
        if not self.analysis_id:
            self.analysis_id = f"proj_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        
        if not self.analysis_timestamp:
            self.analysis_timestamp = datetime.now().isoformat()
        
        if not self.project_name and self.project_path:
            self.project_name = Path(self.project_path).name

@dataclass
class SystemMetrics:
    """System resource utilization metrics"""
    timestamp: str
    session_id: str
    
    # CPU metrics
    cpu_percent: float = 0.0
    cpu_count: int = 0
    load_average: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    
    # Memory metrics
    memory_total_gb: float = 0.0
    memory_used_gb: float = 0.0
    memory_available_gb: float = 0.0
    memory_percent: float = 0.0
    swap_total_gb: float = 0.0
    swap_used_gb: float = 0.0
    
    # Disk metrics
    disk_total_gb: float = 0.0
    disk_used_gb: float = 0.0
    disk_free_gb: float = 0.0
    disk_percent: float = 0.0
    
    # Network metrics
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    network_packets_sent: int = 0
    network_packets_recv: int = 0
    
    # Process metrics
    process_count: int = 0
    thread_count: int = 0
    file_descriptor_count: int = 0
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

@dataclass
class CIFuzzSparkSession:
    """Comprehensive CI Fuzz Spark session tracking"""
    # Core identification
    session_id: str
    pid: int
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Process information
    command_line: str = ""
    working_directory: str = ""
    process_name: str = ""
    parent_pid: Optional[int] = None
    
    # Project context
    project_analysis: Optional[ProjectAnalysis] = None
    
    # LLM configuration
    llm_provider: LLMProvider = LLMProvider.UNKNOWN
    llm_model: str = "unknown"
    llm_endpoint: str = ""
    llm_api_key_hash: Optional[str] = None
    llm_configuration: Dict[str, Any] = field(default_factory=dict)
    
    # CI/CD context
    ci_pipeline_id: Optional[str] = None
    ci_provider: Optional[str] = None
    ci_job_id: Optional[str] = None
    ci_build_number: Optional[str] = None
    
    # Session metrics
    total_duration_ms: float = 0.0
    fuzz_drivers_generated: int = 0
    successful_compilations: int = 0
    failed_compilations: int = 0
    test_cases_generated: int = 0
    
    # LLM usage metrics
    total_llm_interactions: int = 0
    total_tokens_consumed: int = 0
    total_api_calls: int = 0
    estimated_cost_usd: float = 0.0
    
    # Effectiveness metrics
    total_bugs_found: int = 0
    unique_crashes_found: int = 0
    security_vulnerabilities_found: int = 0
    
    # Coverage metrics
    overall_line_coverage: float = 0.0
    overall_branch_coverage: float = 0.0
    overall_function_coverage: float = 0.0
    
    # Performance metrics
    peak_memory_usage_mb: float = 0.0
    average_cpu_usage: float = 0.0
    peak_cpu_usage: float = 0.0
    network_bytes_sent: int = 0
    network_bytes_received: int = 0
    
    # Quality scores
    automation_score: float = 0.0
    effectiveness_score: float = 0.0
    efficiency_score: float = 0.0
    overall_score: float = 0.0
    
    # Status and metadata
    status: SessionStatus = SessionStatus.INITIALIZING
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Monitoring data
    fuzz_drivers: List[FuzzDriverMetrics] = field(default_factory=list)
    llm_interactions: List[LLMInteraction] = field(default_factory=list)
    security_findings: List[SecurityFinding] = field(default_factory=list)
    system_metrics: List[SystemMetrics] = field(default_factory=list)
    
    def __post_init__(self):
        """Post-initialization validation and setup"""
        if not self.session_id:
            self.session_id = self._generate_session_id()
        
        # Get safe username
        if not hasattr(self, '_username'):
            self._username = self._get_safe_username()
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = int(time.time() * 1000)
        username = self._get_safe_username()
        random_suffix = uuid.uuid4().hex[:8]
        return f"spark_{self.pid}_{timestamp}_{username}_{random_suffix}"
    
    def _get_safe_username(self) -> str:
        """Get username with fallback for containers/cron"""
        try:
            return os.getlogin()
        except OSError:
            try:
                return getpass.getuser()
            except Exception:
                try:
                    return pwd.getpwuid(os.getuid()).pw_name
                except Exception:
                    return "unknown"
    
    def add_fuzz_driver(self, driver: FuzzDriverMetrics):
        """Add fuzz driver with validation"""
        if driver.session_id != self.session_id:
            driver.session_id = self.session_id
        self.fuzz_drivers.append(driver)
        self.fuzz_drivers_generated = len(self.fuzz_drivers)
    
    def add_llm_interaction(self, interaction: LLMInteraction):
        """Add LLM interaction with validation"""
        if interaction.session_id != self.session_id:
            interaction.session_id = self.session_id
        self.llm_interactions.append(interaction)
        self.total_llm_interactions = len(self.llm_interactions)
        self.total_tokens_consumed += interaction.total_tokens
        self.estimated_cost_usd += interaction.cost_estimate_usd
    
    def add_security_finding(self, finding: SecurityFinding):
        """Add security finding with validation"""
        if finding.session_id != self.session_id:
            finding.session_id = self.session_id
        self.security_findings.append(finding)
        self.security_vulnerabilities_found = len(self.security_findings)
    
    def calculate_duration(self) -> float:
        """Calculate session duration in milliseconds"""
        if self.end_time:
            duration = (self.end_time - self.start_time).total_seconds() * 1000
        else:
            duration = (datetime.now() - self.start_time).total_seconds() * 1000
        self.total_duration_ms = duration
        return duration
    
    def update_status(self, status: SessionStatus, error_message: Optional[str] = None):
        """Update session status"""
        self.status = status
        if error_message:
            self.error_message = error_message
        
        if status in [SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.INTERRUPTED]:
            self.end_time = datetime.now()
            self.calculate_duration()

@dataclass
class HistoricalAnalysisResult:
    """Results from historical log analysis"""
    analysis_id: str
    analysis_timestamp: str
    
    # Input data
    log_sources: List[str] = field(default_factory=list)
    total_log_size_bytes: int = 0
    analysis_duration_ms: float = 0.0
    
    # Session analysis
    total_sessions_analyzed: int = 0
    successful_sessions: int = 0
    failed_sessions: int = 0
    average_session_duration_ms: float = 0.0
    
    # LLM usage analysis
    total_llm_interactions: int = 0
    total_tokens_consumed: int = 0
    total_estimated_cost: float = 0.0
    most_used_models: Dict[str, int] = field(default_factory=dict)
    most_used_providers: Dict[str, int] = field(default_factory=dict)
    
    # Effectiveness analysis
    total_fuzz_drivers_generated: int = 0
    total_vulnerabilities_found: int = 0
    vulnerability_distribution: Dict[str, int] = field(default_factory=dict)
    average_code_quality_score: float = 0.0
    
    # Performance trends
    performance_trends: Dict[str, List[float]] = field(default_factory=dict)
    resource_utilization_trends: Dict[str, List[float]] = field(default_factory=dict)
    
    # Error analysis
    most_common_errors: List[Tuple[str, int]] = field(default_factory=list)
    error_patterns: Dict[str, int] = field(default_factory=dict)
    
    # Recommendations
    optimization_recommendations: List[str] = field(default_factory=list)
    cost_optimization_suggestions: List[str] = field(default_factory=list)
    security_recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.analysis_id:
            self.analysis_id = f"hist_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        
        if not self.analysis_timestamp:
            self.analysis_timestamp = datetime.now().isoformat()

# Configuration and constants
class MonitorConfig:
    """Global configuration for the monitor"""
    
    # Monitoring intervals (seconds)
    SYSTEM_METRICS_INTERVAL = 5
    LLM_MONITORING_INTERVAL = 10
    OUTPUT_PARSING_INTERVAL = 2
    FILE_MONITORING_INTERVAL = 5
    NETWORK_MONITORING_INTERVAL = 10
    
    # Queue configurations
    WRITER_QUEUE_MAXSIZE = 10000
    METRICS_QUEUE_MAXSIZE = 50000
    
    # File handling
    MAX_LOG_FILE_SIZE_MB = 100
    LOG_ROTATION_BACKUP_COUNT = 5
    ARCHIVE_AFTER_DAYS = 7
    
    # Performance tuning
    MAX_CONCURRENT_MONITORS = 10
    THREAD_POOL_SIZE = 20
    
    # LLM provider timeouts
    LLM_HEALTH_CHECK_TIMEOUT = 3
    LLM_API_TIMEOUT = 30
    
    # Cost estimation models
    TOKEN_COST_MODELS = {
        LLMProvider.OPENAI: {
            'gpt-4': 0.03,
            'gpt-4-turbo': 0.01,
            'gpt-3.5-turbo': 0.002,
            'default': 0.01
        },
        LLMProvider.ANTHROPIC: {
            'claude-3-opus': 0.015,
            'claude-3-sonnet': 0.003,
            'claude-3-haiku': 0.00025,
            'default': 0.01
        },
        LLMProvider.OLLAMA: {
            'default': 0.0  # Local models
        },
        LLMProvider.HUGGINGFACE: {
            'default': 0.001
        }
    }

# Utility functions
def safe_get_username() -> str:
    """Safely get username with multiple fallbacks"""
    try:
        return os.getlogin()
    except OSError:
        try:
            return getpass.getuser()
        except Exception:
            try:
                return pwd.getpwuid(os.getuid()).pw_name
            except Exception:
                return "unknown"

def create_robust_http_session() -> requests.Session:
    """Create HTTP session with retries and proper timeouts"""
    session = requests.Session()
    
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set default timeout
    session.timeout = 30
    
    return session

def estimate_llm_cost(tokens: int, model: str, provider: LLMProvider) -> float:
    """Estimate cost based on tokens, model, and provider"""
    provider_costs = MonitorConfig.TOKEN_COST_MODELS.get(provider, {})
    model_cost = provider_costs.get(model.lower(), provider_costs.get('default', 0.005))
    return (tokens / 1000.0) * model_cost

def validate_session_data(session: CIFuzzSparkSession) -> List[str]:
    """Validate session data and return list of issues"""
    issues = []
    
    if not session.session_id:
        issues.append("Missing session ID")
    
    if session.pid <= 0:
        issues.append("Invalid PID")
    
    if not session.start_time:
        issues.append("Missing start time")
    
    if session.total_tokens_consumed < 0:
        issues.append("Negative token count")
    
    if session.estimated_cost_usd < 0:
        issues.append("Negative cost estimate")
    
    return issues

# Error handling classes
class MonitorError(Exception):
    """Base exception for monitor errors"""
    pass

class ConfigurationError(MonitorError):
    """Configuration-related errors"""
    pass

class DataValidationError(MonitorError):
    """Data validation errors"""
    pass

class LLMProviderError(MonitorError):
    """LLM provider communication errors"""
    pass

class ProcessMonitoringError(MonitorError):
    """Process monitoring errors"""
    pass

# Export public API
__all__ = [
    # Core models
    'LLMInteraction',
    'FuzzDriverMetrics', 
    'CIFuzzSparkSession',
    'ProjectAnalysis',
    'SystemMetrics',
    'CodeMetrics',
    'SecurityFinding',
    'HistoricalAnalysisResult',
    
    # Enums
    'SessionStatus',
    'LLMProvider', 
    'VulnerabilityType',
    'SecuritySeverity',
    
    # Configuration
    'MonitorConfig',
    
    # Utilities
    'safe_get_username',
    'create_robust_http_session',
    'estimate_llm_cost',
    'validate_session_data',
    
    # Patterns
    'SPARK_PATTERNS',
    'LLM_API_PATTERNS',
    'VULNERABILITY_PATTERNS',
    
    # Exceptions
    'MonitorError',
    'ConfigurationError',
    'DataValidationError', 
    'LLMProviderError',
    'ProcessMonitoringError',
]

if __name__ == "__main__":
    # Basic model validation
    session = CIFuzzSparkSession(
        session_id="test",
        pid=12345,
        start_time=datetime.now()
    )
    
    issues = validate_session_data(session)
    if issues:
        print(f"Validation issues: {issues}")
    else:
        print("✅ Models validation passed")
        print(f"Session ID: {session.session_id}")
        print(f"Username: {safe_get_username()}")