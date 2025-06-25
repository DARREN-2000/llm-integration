#!/usr/bin/env python3
"""
Advanced LLM Fuzzing Monitor - Analysis Engines & LLM Provider Integrations
Part 3: Intelligent Analysis, Hallucination Detection & Provider Management

Master's Thesis Research: "Enhancing Automated Security Testing in CI/CD/CT Pipelines with Large Language Models"
Author: Morris Darren Babu
Version: 3.0.0
License: MIT
"""

import ast
import asyncio
import hashlib
import json
import logging
import re
import subprocess
import tempfile
import time
import urllib.parse
from abc import ABC, abstractmethod
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Protocol, Callable
import xml.etree.ElementTree as ET

# Third-party imports with fallbacks
try:
    import numpy as np
    from scipy import stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    np = None

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None

try:
    import psutil
except ImportError:
    psutil = None

from ..core.models import (
    LLMInteraction, FuzzDriverMetrics, SecurityFinding, CIFuzzSparkSession,
    VulnerabilityType, SecuritySeverity, LLMProvider, CodeMetrics,
    MonitorConfig, LLMProviderError, estimate_llm_cost
)

logger = logging.getLogger(__name__)

# Pre-compiled patterns for performance
SECURITY_PATTERNS = {
    VulnerabilityType.BUFFER_OVERFLOW: [
        re.compile(r'\bstrcpy\s*\(', re.IGNORECASE),
        re.compile(r'\bstrcat\s*\(', re.IGNORECASE),
        re.compile(r'\bsprintf\s*\(', re.IGNORECASE),
        re.compile(r'\bgets\s*\(', re.IGNORECASE),
        re.compile(r'\bscanf\s*\([^)]*%s', re.IGNORECASE),
    ],
    VulnerabilityType.SQL_INJECTION: [
        re.compile(r'SELECT.*\+.*|INSERT.*\+.*', re.IGNORECASE),
        re.compile(r'query.*\+.*', re.IGNORECASE),
        re.compile(r'executeQuery\s*\([^)]*\+', re.IGNORECASE),
    ],
    VulnerabilityType.COMMAND_INJECTION: [
        re.compile(r'system\s*\([^)]*\+', re.IGNORECASE),
        re.compile(r'exec\s*\([^)]*\+', re.IGNORECASE),
        re.compile(r'os\.system\s*\([^)]*\+', re.IGNORECASE),
        re.compile(r'subprocess\.[^(]*\([^)]*shell\s*=\s*True', re.IGNORECASE),
    ]
}

HALLUCINATION_PATTERNS = [
    re.compile(r'undefined_function\s*\(', re.IGNORECASE),
    re.compile(r'nonexistent_(?:library|module|package)', re.IGNORECASE),
    re.compile(r'fictional_(?:method|function|class)', re.IGNORECASE),
    re.compile(r'import\s+(?:nonexistent|fake|dummy)_\w+', re.IGNORECASE),
    re.compile(r'#include\s*<(?:nonexistent|fake|dummy)\.h>', re.IGNORECASE),
]

CODE_SMELL_PATTERNS = {
    'magic_numbers': re.compile(r'\b\d{3,}\b'),
    'long_lines': re.compile(r'^.{121,}$', re.MULTILINE),
    'deep_nesting': re.compile(r'^\s{20,}', re.MULTILINE),
    'todo_comments': re.compile(r'(?:TODO|FIXME|HACK|XXX).*', re.IGNORECASE),
}

class AnalysisProtocol(Protocol):
    """Protocol for analysis engines"""
    
    def analyze(self, data: Any) -> Dict[str, Any]:
        """Analyze data and return results"""
        ...

@dataclass
class AnalysisResult:
    """Generic analysis result container"""
    analyzer_name: str
    analysis_timestamp: str
    analysis_duration_ms: float
    confidence_score: float
    results: Dict[str, Any]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class BaseAnalyzer(ABC):
    """Base class for all analyzers"""
    
    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.stats = {
            'analyses_performed': 0,
            'total_analysis_time_ms': 0.0,
            'errors': 0,
            'average_confidence': 0.0
        }
    
    @abstractmethod
    def _analyze_impl(self, data: Any) -> Dict[str, Any]:
        """Implementation-specific analysis logic"""
        pass
    
    def analyze(self, data: Any) -> AnalysisResult:
        """Perform analysis with timing and error handling"""
        start_time = time.time()
        errors = []
        warnings = []
        
        try:
            results = self._analyze_impl(data)
            confidence = self._calculate_confidence(results)
            
            # Update statistics
            self.stats['analyses_performed'] += 1
            self.stats['average_confidence'] = (
                (self.stats['average_confidence'] * (self.stats['analyses_performed'] - 1) + confidence) /
                self.stats['analyses_performed']
            )
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            errors.append(str(e))
            results = {}
            confidence = 0.0
            self.stats['errors'] += 1
        
        analysis_time = (time.time() - start_time) * 1000
        self.stats['total_analysis_time_ms'] += analysis_time
        
        return AnalysisResult(
            analyzer_name=self.name,
            analysis_timestamp=datetime.now().isoformat(),
            analysis_duration_ms=analysis_time,
            confidence_score=confidence,
            results=results,
            errors=errors,
            warnings=warnings,
            metadata={'stats': self.stats.copy()}
        )
    
    def _calculate_confidence(self, results: Dict[str, Any]) -> float:
        """Calculate confidence score for analysis results"""
        # Default implementation - can be overridden
        if not results:
            return 0.0
        
        # Simple heuristic based on number of findings
        findings_count = sum(
            len(v) if isinstance(v, list) else (1 if v else 0)
            for v in results.values()
        )
        
        return min(findings_count * 0.1, 1.0)

class AdvancedHallucinationDetector(BaseAnalyzer):
    """Advanced LLM hallucination detection with multiple techniques"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("HallucinationDetector", config)
        self.language_validators = {
            'python': self._validate_python_code,
            'c': self._validate_c_code,
            'cpp': self._validate_cpp_code,
            'java': self._validate_java_code,
            'javascript': self._validate_javascript_code,
            'rust': self._validate_rust_code,
            'go': self._validate_go_code,
        }
        
        # Load standard library APIs for each language
        self._load_standard_apis()
    
    def _load_standard_apis(self):
        """Load standard library APIs for validation"""
        self.standard_apis = {
            'python': {
                'builtins': {'print', 'len', 'str', 'int', 'float', 'list', 'dict', 'range', 'enumerate'},
                'modules': {'os', 'sys', 'json', 'time', 'datetime', 'math', 'random', 're'},
            },
            'c': {
                'functions': {'printf', 'scanf', 'malloc', 'free', 'strlen', 'strcpy', 'strcmp'},
                'headers': {'stdio.h', 'stdlib.h', 'string.h', 'math.h', 'time.h'},
            },
            'java': {
                'classes': {'String', 'System', 'Object', 'Integer', 'ArrayList', 'HashMap'},
                'packages': {'java.util', 'java.io', 'java.lang', 'java.net'},
            }
        }
    
    def _analyze_impl(self, interaction: LLMInteraction) -> Dict[str, Any]:
        """Comprehensive hallucination analysis"""
        results = {
            'hallucination_detected': False,
            'confidence': 0.0,
            'issues': [],
            'severity': 'low',
            'analysis_details': {}
        }
        
        prompt = interaction.prompt_text
        response = interaction.response_text
        language = self._detect_language(response)
        
        # 1. Syntax-based detection
        syntax_issues = self._detect_syntax_hallucinations(response)
        if syntax_issues:
            results['issues'].extend(syntax_issues)
            results['confidence'] += 0.3
        
        # 2. API validation
        api_issues = self._validate_api_usage(response, language)
        if api_issues:
            results['issues'].extend(api_issues)
            results['confidence'] += 0.4
        
        # 3. Semantic consistency check
        semantic_issues = self._check_semantic_consistency(prompt, response, language)
        if semantic_issues:
            results['issues'].extend(semantic_issues)
            results['confidence'] += 0.3
        
        # 4. Language-specific validation
        if language in self.language_validators:
            lang_issues = self.language_validators[language](response)
            if lang_issues:
                results['issues'].extend(lang_issues)
                results['confidence'] += 0.4
        
        # 5. Compilation/execution test
        compilation_result = self._test_compilation(response, language)
        results['analysis_details']['compilation'] = compilation_result
        if not compilation_result.get('success', False):
            results['confidence'] += 0.3
        
        # 6. Context coherence analysis
        coherence_score = self._analyze_context_coherence(prompt, response)
        results['analysis_details']['coherence_score'] = coherence_score
        if coherence_score < 0.5:
            results['confidence'] += 0.2
        
        # Determine final result
        results['hallucination_detected'] = results['confidence'] > 0.3
        results['confidence'] = min(results['confidence'], 1.0)
        
        if results['confidence'] > 0.7:
            results['severity'] = 'high'
        elif results['confidence'] > 0.4:
            results['severity'] = 'medium'
        
        return results
    
    def _detect_language(self, code: str) -> str:
        """Detect programming language from code"""
        language_indicators = {
            'python': [r'def\s+', r'import\s+', r'print\s*\(', r'if\s+__name__'],
            'c': [r'#include\s*<', r'int\s+main\s*\(', r'printf\s*\('],
            'cpp': [r'#include\s*<iostream>', r'std::', r'cout\s*<<'],
            'java': [r'public\s+class', r'System\.out\.print', r'public\s+static\s+void\s+main'],
            'javascript': [r'function\s+', r'console\.log', r'var\s+', r'let\s+', r'const\s+'],
            'rust': [r'fn\s+', r'let\s+mut', r'println!', r'use\s+'],
            'go': [r'package\s+', r'func\s+', r'import\s+', r'fmt\.Print'],
        }
        
        scores = {}
        for lang, patterns in language_indicators.items():
            score = sum(1 for pattern in patterns if re.search(pattern, code))
            if score > 0:
                scores[lang] = score
        
        return max(scores.items(), key=lambda x: x[1])[0] if scores else 'unknown'
    
    def _detect_syntax_hallucinations(self, code: str) -> List[str]:
        """Detect syntax-based hallucinations"""
        issues = []
        
        for pattern in HALLUCINATION_PATTERNS:
            matches = pattern.finditer(code)
            for match in matches:
                issues.append(f"Potential hallucination: {match.group()}")
        
        # Check for impossible constructs
        impossible_patterns = [
            (r'malloc\s*\(\s*-\d+\s*\)', "Negative malloc size"),
            (r'array\[\s*-\d+\s*\]', "Negative array index"),
            (r'\w+\s*=\s*\w+\s*/\s*0(?!\.\d)', "Division by zero"),
            (r'for\s*\(\s*;\s*true\s*;\s*\)\s*{[^{}]*}(?![^{}]*break)', "Infinite loop without break"),
        ]
        
        for pattern, description in impossible_patterns:
            if re.search(pattern, code):
                issues.append(f"Impossible construct: {description}")
        
        return issues
    
    def _validate_api_usage(self, code: str, language: str) -> List[str]:
        """Validate API usage against known standard libraries"""
        issues = []
        
        if language not in self.standard_apis:
            return issues
        
        apis = self.standard_apis[language]
        
        # Extract function calls and imports
        if language == 'python':
            # Check imports
            import_pattern = r'import\s+(\w+)|from\s+(\w+)\s+import'
            imports = re.findall(import_pattern, code)
            for imp in imports:
                module = imp[0] or imp[1]
                if module and module not in apis['modules'] and not module.startswith('_'):
                    issues.append(f"Unknown module: {module}")
        
        elif language in ['c', 'cpp']:
            # Check includes
            include_pattern = r'#include\s*<([^>]+)>'
            includes = re.findall(include_pattern, code)
            for header in includes:
                if header not in apis['headers']:
                    issues.append(f"Unknown header: {header}")
        
        return issues
    
    def _check_semantic_consistency(self, prompt: str, response: str, language: str) -> List[str]:
        """Check semantic consistency between prompt and response"""
        issues = []
        
        # Language mixing detection
        if language != 'unknown':
            other_language_indicators = {
                'python': [r'#include', r'public\s+class', r'cout\s*<<'],
                'c': [r'import\s+', r'println!', r'console\.log'],
                'java': [r'#include', r'def\s+', r'fn\s+'],
                'javascript': [r'#include', r'def\s+', r'public\s+class'],
            }
            
            if language in other_language_indicators:
                for pattern in other_language_indicators[language]:
                    if re.search(pattern, response):
                        issues.append(f"Mixed language syntax: {language} code contains other language patterns")
                        break
        
        # Check prompt-response consistency
        prompt_keywords = set(re.findall(r'\b\w{3,}\b', prompt.lower()))
        response_keywords = set(re.findall(r'\b\w{3,}\b', response.lower()))
        
        # Should have some overlap for relevant responses
        overlap = len(prompt_keywords & response_keywords)
        if overlap / max(len(prompt_keywords), 1) < 0.1:
            issues.append("Low semantic overlap between prompt and response")
        
        return issues
    
    def _validate_python_code(self, code: str) -> List[str]:
        """Validate Python code using AST and static analysis"""
        issues = []
        
        try:
            # Parse as AST
            tree = ast.parse(code)
            
            # Check for undefined names
            class NameChecker(ast.NodeVisitor):
                def __init__(self):
                    self.undefined = []
                    self.defined = set()
                    self.builtins = self.standard_apis['python']['builtins']
                
                def visit_Name(self, node):
                    if isinstance(node.ctx, ast.Load):
                        if (node.id not in self.defined and 
                            node.id not in self.builtins and
                            not node.id.startswith('_')):
                            self.undefined.append(node.id)
                    elif isinstance(node.ctx, ast.Store):
                        self.defined.add(node.id)
                    self.generic_visit(node)
            
            checker = NameChecker()
            checker.visit(tree)
            
            for name in set(checker.undefined[:5]):  # Limit to 5 most common
                issues.append(f"Potentially undefined name: {name}")
                
        except SyntaxError as e:
            issues.append(f"Python syntax error: {e}")
        except Exception as e:
            issues.append(f"Python analysis error: {e}")
        
        return issues
    
    def _validate_c_code(self, code: str) -> List[str]:
        """Validate C code structure and syntax"""
        issues = []
        
        # Basic structure checks
        if 'main' in code and '#include' not in code:
            issues.append("Main function without includes")
        
        # Brace matching
        open_braces = code.count('{')
        close_braces = code.count('}')
        if open_braces != close_braces:
            issues.append(f"Unmatched braces: {open_braces} open, {close_braces} close")
        
        # Memory management
        malloc_count = len(re.findall(r'\bmalloc\s*\(', code))
        free_count = len(re.findall(r'\bfree\s*\(', code))
        if malloc_count > 0 and free_count == 0:
            issues.append("malloc without corresponding free")
        
        return issues
    
    def _validate_cpp_code(self, code: str) -> List[str]:
        """Validate C++ code"""
        issues = self._validate_c_code(code)  # Start with C validation
        
        # C++ specific checks
        if 'std::' in code and '#include <iostream>' not in code:
            issues.append("Using std:: without iostream include")
        
        return issues
    
    def _validate_java_code(self, code: str) -> List[str]:
        """Validate Java code structure"""
        issues = []
        
        # Class structure
        if 'main' in code and 'public static void main' not in code:
            issues.append("main method should be 'public static void main'")
        
        # Package structure
        if 'class' in code and 'public class' not in code:
            issues.append("Classes should typically be public")
        
        return issues
    
    def _validate_javascript_code(self, code: str) -> List[str]:
        """Validate JavaScript code"""
        issues = []
        
        # Basic syntax
        if code.count('(') != code.count(')'):
            issues.append("Unmatched parentheses")
        
        if code.count('[') != code.count(']'):
            issues.append("Unmatched square brackets")
        
        return issues
    
    def _validate_rust_code(self, code: str) -> List[str]:
        """Validate Rust code"""
        issues = []
        
        # Basic Rust patterns
        if 'fn main' in code and 'println!' not in code and 'print!' not in code:
            issues.append("Main function without output")
        
        return issues
    
    def _validate_go_code(self, code: str) -> List[str]:
        """Validate Go code"""
        issues = []
        
        # Package declaration
        if 'func main' in code and 'package main' not in code:
            issues.append("Main function without package main")
        
        return issues
    
    def _test_compilation(self, code: str, language: str) -> Dict[str, Any]:
        """Test code compilation/execution"""
        result = {'success': False, 'errors': [], 'warnings': []}
        
        if language == 'python':
            try:
                compile(code, '<string>', 'exec')
                result['success'] = True
            except SyntaxError as e:
                result['errors'].append(f"Syntax error: {e}")
            except Exception as e:
                result['errors'].append(f"Compilation error: {e}")
        
        elif language in ['c', 'cpp']:
            # For C/C++, we'd need actual compiler - simplified check
            if '{' in code and '}' in code:
                result['success'] = True
            else:
                result['errors'].append("Missing braces")
        
        return result
    
    def _analyze_context_coherence(self, prompt: str, response: str) -> float:
        """Analyze coherence between prompt and response"""
        if not prompt or not response:
            return 0.0
        
        # Extract key terms
        prompt_terms = set(re.findall(r'\b\w{4,}\b', prompt.lower()))
        response_terms = set(re.findall(r'\b\w{4,}\b', response.lower()))
        
        if not prompt_terms:
            return 0.5  # Neutral if no terms
        
        # Calculate overlap
        overlap = len(prompt_terms & response_terms)
        coherence = overlap / len(prompt_terms)
        
        return min(coherence * 2, 1.0)  # Scale up for better discrimination

class ComprehensiveCodeQualityAnalyzer(BaseAnalyzer):
    """Advanced code quality analysis with multiple metrics"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("CodeQualityAnalyzer", config)
        self.language_analyzers = {
            'python': self._analyze_python_specific,
            'c': self._analyze_c_specific,
            'cpp': self._analyze_cpp_specific,
            'java': self._analyze_java_specific,
            'javascript': self._analyze_javascript_specific,
        }
    
    def _analyze_impl(self, driver: FuzzDriverMetrics) -> Dict[str, Any]:
        """Comprehensive code quality analysis"""
        code = driver.source_code
        language = driver.target_language
        
        results = {
            'overall_score': 0.0,
            'metrics': {},
            'issues': {
                'code_smells': [],
                'security_issues': [],
                'performance_issues': [],
                'maintainability_issues': []
            },
            'recommendations': []
        }
        
        # Basic metrics
        basic_metrics = self._calculate_basic_metrics(code)
        results['metrics'].update(basic_metrics)
        
        # Code smells detection
        code_smells = self._detect_code_smells(code, language)
        results['issues']['code_smells'] = code_smells
        
        # Security analysis
        security_issues = self._analyze_security(code, language)
        results['issues']['security_issues'] = security_issues
        
        # Performance analysis
        performance_issues = self._analyze_performance(code, language)
        results['issues']['performance_issues'] = performance_issues
        
        # Maintainability analysis
        maintainability_issues = self._analyze_maintainability(code, language)
        results['issues']['maintainability_issues'] = maintainability_issues
        
        # Language-specific analysis
        if language in self.language_analyzers:
            lang_specific = self.language_analyzers[language](code)
            results['metrics'].update(lang_specific.get('metrics', {}))
            for category in results['issues']:
                results['issues'][category].extend(lang_specific.get(category, []))
        
        # Calculate overall score
        results['overall_score'] = self._calculate_overall_score(results)
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _calculate_basic_metrics(self, code: str) -> Dict[str, Any]:
        """Calculate basic code metrics"""
        lines = code.split('\n')
        
        metrics = {
            'total_lines': len(lines),
            'lines_of_code': len([line for line in lines if line.strip()]),
            'comment_lines': len([line for line in lines if line.strip().startswith(('#', '//', '/*'))]),
            'blank_lines': len([line for line in lines if not line.strip()]),
            'average_line_length': np.mean([len(line) for line in lines]) if lines else 0,
            'max_line_length': max([len(line) for line in lines]) if lines else 0,
        }
        
        # Calculate derived metrics
        if metrics['total_lines'] > 0:
            metrics['comment_ratio'] = metrics['comment_lines'] / metrics['total_lines']
        else:
            metrics['comment_ratio'] = 0.0
        
        # Cyclomatic complexity
        metrics['cyclomatic_complexity'] = self._calculate_cyclomatic_complexity(code)
        
        # Nesting depth
        metrics['max_nesting_depth'] = self._calculate_max_nesting_depth(code)
        
        return metrics
    
    def _calculate_cyclomatic_complexity(self, code: str) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1  # Base complexity
        
        # Decision points
        decision_patterns = [
            r'\bif\b', r'\belse\b', r'\belif\b', r'\bwhile\b', r'\bfor\b',
            r'\bswitch\b', r'\bcase\b', r'\bcatch\b', r'\&\&', r'\|\|', r'\?'
        ]
        
        for pattern in decision_patterns:
            complexity += len(re.findall(pattern, code))
        
        return complexity
    
    def _calculate_max_nesting_depth(self, code: str) -> int:
        """Calculate maximum nesting depth"""
        max_depth = 0
        current_depth = 0
        
        for char in code:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        
        return max_depth
    
    def _detect_code_smells(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Detect various code smells"""
        smells = []
        
        # Long method
        lines = code.split('\n')
        if len(lines) > 50:
            smells.append({
                'type': 'long_method',
                'description': f'Method too long ({len(lines)} lines)',
                'severity': 'medium',
                'line_count': len(lines)
            })
        
        # Magic numbers
        magic_number_matches = CODE_SMELL_PATTERNS['magic_numbers'].finditer(code)
        magic_numbers = [match.group() for match in magic_number_matches]
        if len(set(magic_numbers)) > 5:
            smells.append({
                'type': 'magic_numbers',
                'description': f'Too many magic numbers ({len(set(magic_numbers))})',
                'severity': 'low',
                'numbers': list(set(magic_numbers))[:10]
            })
        
        # Long lines
        long_lines = []
        for i, line in enumerate(lines):
            if len(line) > 120:
                long_lines.append(i + 1)
        
        if len(long_lines) > 3:
            smells.append({
                'type': 'long_lines',
                'description': f'Multiple long lines (>{120} chars)',
                'severity': 'low',
                'line_numbers': long_lines[:10]
            })
        
        # TODO comments
        todo_matches = CODE_SMELL_PATTERNS['todo_comments'].finditer(code)
        todos = [match.group() for match in todo_matches]
        if todos:
            smells.append({
                'type': 'todo_comments',
                'description': f'Unresolved TODO comments ({len(todos)})',
                'severity': 'low',
                'comments': todos[:5]
            })
        
        # Duplicate code (simplified)
        line_counts = Counter(line.strip() for line in lines if len(line.strip()) > 10)
        duplicates = [(line, count) for line, count in line_counts.items() if count > 2]
        if duplicates:
            smells.append({
                'type': 'duplicate_code',
                'description': f'Duplicate code lines detected ({len(duplicates)})',
                'severity': 'medium',
                'duplicates': duplicates[:5]
            })
        
        return smells
    
    def _analyze_security(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Analyze security issues"""
        issues = []
        
        for vuln_type, patterns in SECURITY_PATTERNS.items():
            for pattern in patterns:
                matches = list(pattern.finditer(code))
                if matches:
                    issues.append({
                        'type': vuln_type.value,
                        'description': f'Potential {vuln_type.value.replace("_", " ")}',
                        'severity': 'high' if vuln_type in [
                            VulnerabilityType.BUFFER_OVERFLOW,
                            VulnerabilityType.COMMAND_INJECTION
                        ] else 'medium',
                        'occurrences': len(matches),
                        'pattern': pattern.pattern
                    })
        
        # Language-specific security checks
        if language in ['c', 'cpp']:
            # Memory management issues
            malloc_without_check = re.search(r'malloc\s*\([^)]*\)(?!\s*;?\s*if)', code)
            if malloc_without_check:
                issues.append({
                    'type': 'unchecked_malloc',
                    'description': 'malloc without null check',
                    'severity': 'medium'
                })
        
        elif language == 'python':
            # Python-specific security issues
            if 'eval(' in code:
                issues.append({
                    'type': 'dangerous_eval',
                    'description': 'Use of eval() function',
                    'severity': 'high'
                })
            
            if 'pickle.loads' in code:
                issues.append({
                    'type': 'unsafe_deserialization',
                    'description': 'Unsafe pickle deserialization',
                    'severity': 'high'
                })
        
        return issues
    
    def _analyze_performance(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Analyze performance issues"""
        issues = []
        
        # Nested loops
        nested_loop_pattern = r'for\s*\([^}]*for\s*\(|while\s*\([^}]*while\s*\('
        if re.search(nested_loop_pattern, code):
            issues.append({
                'type': 'nested_loops',
                'description': 'Nested loops detected (O(n²) complexity)',
                'severity': 'medium'
            })
        
        # String concatenation in loops
        if 'for' in code and ('+=' in code or '.append(' in code):
            issues.append({
                'type': 'inefficient_string_ops',
                'description': 'String operations in loop',
                'severity': 'low'
            })
        
        # Language-specific performance issues
        if language == 'python':
            # List comprehension vs loops
            if re.search(r'for\s+\w+\s+in.*:\s*\w+\.append\(', code):
                issues.append({
                    'type': 'inefficient_list_building',
                    'description': 'Consider using list comprehension',
                    'severity': 'low'
                })
        
        return issues
    
    def _analyze_maintainability(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Analyze maintainability issues"""
        issues = []
        
        # Function parameter count
        func_patterns = {
            'python': r'def\s+\w+\s*\(([^)]*)\)',
            'c': r'\w+\s+\w+\s*\(([^)]*)\)',
            'java': r'\w+\s+\w+\s*\(([^)]*)\)',
        }
        
        if language in func_patterns:
            matches = re.finditer(func_patterns[language], code)
            for match in matches:
                params = [p.strip() for p in match.group(1).split(',') if p.strip()]
                if len(params) > 5:
                    issues.append({
                        'type': 'too_many_parameters',
                        'description': f'Function with {len(params)} parameters',
                        'severity': 'medium',
                        'parameter_count': len(params)
                    })
        
        # Missing documentation
        doc_patterns = {
            'python': r'""".*?"""',
            'c': r'/\*\*.*?\*/',
            'java': r'/\*\*.*?\*/',
        }
        
        if language in doc_patterns:
            docs = re.findall(doc_patterns[language], code, re.DOTALL)
            functions = len(re.findall(r'def\s+\w+|function\s+\w+|\w+\s+\w+\s*\(', code))
            if functions > 0 and len(docs) / functions < 0.5:
                issues.append({
                    'type': 'missing_documentation',
                    'description': 'Low documentation coverage',
                    'severity': 'low',
                    'coverage_ratio': len(docs) / functions if functions > 0 else 0
                })
        
        return issues
    
    def _analyze_python_specific(self, code: str) -> Dict[str, Any]:
        """Python-specific analysis"""
        results = {'metrics': {}, 'code_smells': [], 'performance_issues': []}
        
        try:
            tree = ast.parse(code)
            
            # Count different constructs
            class PythonMetrics(ast.NodeVisitor):
                def __init__(self):
                    self.function_count = 0
                    self.class_count = 0
                    self.import_count = 0
                    self.comprehension_count = 0
                
                def visit_FunctionDef(self, node):
                    self.function_count += 1
                    self.generic_visit(node)
                
                def visit_ClassDef(self, node):
                    self.class_count += 1
                    self.generic_visit(node)
                
                def visit_Import(self, node):
                    self.import_count += 1
                    self.generic_visit(node)
                
                def visit_ListComp(self, node):
                    self.comprehension_count += 1
                    self.generic_visit(node)
            
            metrics = PythonMetrics()
            metrics.visit(tree)
            
            results['metrics'] = {
                'function_count': metrics.function_count,
                'class_count': metrics.class_count,
                'import_count': metrics.import_count,
                'comprehension_count': metrics.comprehension_count,
            }
            
            # Python-specific code smells
            if 'import *' in code:
                results['code_smells'].append({
                    'type': 'wildcard_import',
                    'description': 'Wildcard import usage',
                    'severity': 'medium'
                })
            
            if re.search(r'except\s*:', code):
                results['code_smells'].append({
                    'type': 'bare_except',
                    'description': 'Bare except clause',
                    'severity': 'medium'
                })
        
        except SyntaxError:
            results['code_smells'].append({
                'type': 'syntax_error',
                'description': 'Code contains syntax errors',
                'severity': 'high'
            })
        
        return results
    
    def _analyze_c_specific(self, code: str) -> Dict[str, Any]:
        """C-specific analysis"""
        results = {'metrics': {}, 'security_issues': [], 'performance_issues': []}
        
        # Count functions and includes
        functions = len(re.findall(r'\w+\s+\w+\s*\([^)]*\)\s*{', code))
        includes = len(re.findall(r'#include', code))
        
        results['metrics'] = {
            'function_count': functions,
            'include_count': includes,
            'has_main': bool(re.search(r'int\s+main\s*\(', code))
        }
        
        # Memory management analysis
        malloc_count = len(re.findall(r'\bmalloc\s*\(', code))
        free_count = len(re.findall(r'\bfree\s*\(', code))
        
        if malloc_count > free_count:
            results['security_issues'].append({
                'type': 'memory_leak',
                'description': f'Potential memory leak: {malloc_count} malloc, {free_count} free',
                'severity': 'medium'
            })
        
        return results
    
    def _analyze_cpp_specific(self, code: str) -> Dict[str, Any]:
        """C++-specific analysis"""
        results = self._analyze_c_specific(code)  # Start with C analysis
        
        # C++ specific metrics
        results['metrics'].update({
            'uses_std_namespace': 'using namespace std' in code,
            'class_count': len(re.findall(r'class\s+\w+', code)),
            'template_count': len(re.findall(r'template\s*<', code)),
        })
        
        return results
    
    def _analyze_java_specific(self, code: str) -> Dict[str, Any]:
        """Java-specific analysis"""
        results = {'metrics': {}, 'code_smells': []}
        
        results['metrics'] = {
            'class_count': len(re.findall(r'class\s+\w+', code)),
            'method_count': len(re.findall(r'(public|private|protected)?\s*(static\s+)?\w+\s+\w+\s*\(', code)),
            'interface_count': len(re.findall(r'interface\s+\w+', code)),
            'package_declared': 'package ' in code,
        }
        
        return results
    
    def _analyze_javascript_specific(self, code: str) -> Dict[str, Any]:
        """JavaScript-specific analysis"""
        results = {'metrics': {}, 'code_smells': []}
        
        results['metrics'] = {
            'function_count': len(re.findall(r'function\s+\w+', code)),
            'arrow_function_count': len(re.findall(r'=>', code)),
            'var_declarations': len(re.findall(r'\bvar\s+', code)),
            'let_declarations': len(re.findall(r'\blet\s+', code)),
            'const_declarations': len(re.findall(r'\bconst\s+', code)),
        }
        
        # JavaScript code smells
        if results['metrics']['var_declarations'] > 0:
            results['code_smells'].append({
                'type': 'var_usage',
                'description': 'Use let/const instead of var',
                'severity': 'low'
            })
        
        return results
    
    def _calculate_overall_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall code quality score (0-10)"""
        base_score = 10.0
        
        # Deduct points for issues
        issue_penalties = {
            'code_smells': 0.3,
            'security_issues': 1.0,
            'performance_issues': 0.5,
            'maintainability_issues': 0.2
        }
        
        for category, penalty in issue_penalties.items():
            if category in results['issues']:
                issue_count = len(results['issues'][category])
                base_score -= issue_count * penalty
        
        # Complexity penalty
        complexity = results['metrics'].get('cyclomatic_complexity', 0)
        if complexity > 20:
            base_score -= 2.0
        elif complexity > 10:
            base_score -= 1.0
        
        # Documentation bonus
        comment_ratio = results['metrics'].get('comment_ratio', 0)
        if comment_ratio > 0.2:
            base_score += 0.5
        
        return max(0.0, min(10.0, base_score))
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate improvement recommendations"""
        recommendations = []
        
        # Based on issues found
        issue_counts = {category: len(issues) for category, issues in results['issues'].items()}
        
        if issue_counts['security_issues'] > 0:
            recommendations.append("Review and fix security vulnerabilities")
            recommendations.append("Enable static analysis tools for security scanning")
        
        if issue_counts['performance_issues'] > 0:
            recommendations.append("Optimize performance-critical sections")
            recommendations.append("Consider algorithmic improvements")
        
        if issue_counts['code_smells'] > 3:
            recommendations.append("Refactor code to reduce complexity")
            recommendations.append("Break down large functions into smaller ones")
        
        # Based on metrics
        complexity = results['metrics'].get('cyclomatic_complexity', 0)
        if complexity > 15:
            recommendations.append("Reduce cyclomatic complexity through refactoring")
        
        comment_ratio = results['metrics'].get('comment_ratio', 0)
        if comment_ratio < 0.1:
            recommendations.append("Add more documentation and comments")
        
        return recommendations

class IntelligentVulnerabilityAnalyzer(BaseAnalyzer):
    """Advanced vulnerability analysis with CVE mapping and ML techniques"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("VulnerabilityAnalyzer", config)
        self.cve_database = self._load_cve_database()
        self.severity_weights = {
            SecuritySeverity.CRITICAL: 10.0,
            SecuritySeverity.HIGH: 7.5,
            SecuritySeverity.MEDIUM: 5.0,
            SecuritySeverity.LOW: 2.5,
            SecuritySeverity.INFO: 1.0
        }
    
    def _load_cve_database(self) -> Dict[str, Any]:
        """Load comprehensive CVE database"""
        return {
            VulnerabilityType.BUFFER_OVERFLOW: {
                'cve_ids': ['CVE-2019-11043', 'CVE-2020-1472', 'CVE-2021-3156'],
                'severity': SecuritySeverity.HIGH,
                'cwe': 'CWE-120',
                'description': 'Buffer overflow vulnerability allowing arbitrary code execution',
                'indicators': ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf'],
                'patterns': SECURITY_PATTERNS[VulnerabilityType.BUFFER_OVERFLOW],
                'remediation': [
                    'Use safe string functions (strncpy, strncat, snprintf)',
                    'Enable stack canaries and ASLR',
                    'Implement bounds checking',
                    'Use memory-safe languages where possible'
                ]
            },
            VulnerabilityType.USE_AFTER_FREE: {
                'cve_ids': ['CVE-2020-0796', 'CVE-2019-0708'],
                'severity': SecuritySeverity.HIGH,
                'cwe': 'CWE-416',
                'description': 'Use after free vulnerability in memory management',
                'indicators': ['free(', 'delete ', 'dangling pointer'],
                'remediation': [
                    'Set pointers to NULL after free',
                    'Use smart pointers in C++',
                    'Implement proper lifetime management',
                    'Use memory debugging tools'
                ]
            },
            VulnerabilityType.SQL_INJECTION: {
                'cve_ids': ['CVE-2019-16928', 'CVE-2020-5777'],
                'severity': SecuritySeverity.HIGH,
                'cwe': 'CWE-89',
                'description': 'SQL injection vulnerability allowing database manipulation',
                'patterns': SECURITY_PATTERNS[VulnerabilityType.SQL_INJECTION],
                'remediation': [
                    'Use parameterized queries',
                    'Implement input validation',
                    'Use ORM frameworks',
                    'Apply principle of least privilege'
                ]
            },
            VulnerabilityType.COMMAND_INJECTION: {
                'cve_ids': ['CVE-2020-8597', 'CVE-2019-15107'],
                'severity': SecuritySeverity.HIGH,
                'cwe': 'CWE-78',
                'description': 'Command injection allowing arbitrary command execution',
                'patterns': SECURITY_PATTERNS[VulnerabilityType.COMMAND_INJECTION],
                'remediation': [
                    'Avoid shell execution with user input',
                    'Use safe APIs for system calls',
                    'Implement input sanitization',
                    'Use allowlist validation'
                ]
            }
        }
    
    def _analyze_impl(self, crash_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive vulnerability analysis"""
        results = {
            'vulnerabilities_found': [],
            'risk_assessment': {},
            'remediation_plan': [],
            'confidence_scores': {},
            'false_positive_analysis': {}
        }
        
        crash_signature = crash_data.get('signature', '')
        stack_trace = crash_data.get('stack_trace', '')
        source_code = crash_data.get('source_code', '')
        memory_info = crash_data.get('memory_info', {})
        
        # 1. Pattern-based vulnerability detection
        pattern_vulns = self._detect_pattern_vulnerabilities(source_code)
        results['vulnerabilities_found'].extend(pattern_vulns)
        
        # 2. Crash signature analysis
        signature_vulns = self._analyze_crash_signature(crash_signature)
        results['vulnerabilities_found'].extend(signature_vulns)
        
        # 3. Stack trace analysis
        if stack_trace:
            stack_vulns = self._analyze_stack_trace(stack_trace)
            results['vulnerabilities_found'].extend(stack_vulns)
        
        # 4. Memory analysis
        if memory_info:
            memory_vulns = self._analyze_memory_corruption(memory_info)
            results['vulnerabilities_found'].extend(memory_vulns)
        
        # 5. Risk assessment
        results['risk_assessment'] = self._assess_risk(results['vulnerabilities_found'])
        
        # 6. False positive analysis
        results['false_positive_analysis'] = self._analyze_false_positives(
            results['vulnerabilities_found'], crash_data
        )
        
        # 7. Generate remediation plan
        results['remediation_plan'] = self._generate_remediation_plan(
            results['vulnerabilities_found']
        )
        
        return results
    
    def _detect_pattern_vulnerabilities(self, source_code: str) -> List[SecurityFinding]:
        """Detect vulnerabilities using pattern matching"""
        findings = []
        
        for vuln_type, vuln_data in self.cve_database.items():
            if 'patterns' in vuln_data:
                for pattern in vuln_data['patterns']:
                    matches = list(pattern.finditer(source_code))
                    for match in matches:
                        finding = SecurityFinding(
                            finding_id=f"pattern_{vuln_type.value}_{hash(match.group())}",
                            session_id="analysis",
                            vulnerability_type=vuln_type,
                            severity=vuln_data['severity'],
                            cwe_id=vuln_data['cwe'],
                            description=f"Pattern match: {vuln_data['description']}",
                            code_snippet=match.group(),
                            line_number=source_code[:match.start()].count('\n') + 1,
                            confidence_score=0.7,
                            detection_method="pattern_matching",
                            remediation_suggestions=vuln_data['remediation']
                        )
                        findings.append(finding)
        
        return findings
    
    def _analyze_crash_signature(self, signature: str) -> List[SecurityFinding]:
        """Analyze crash signature for vulnerability indicators"""
        findings = []
        
        signature_patterns = {
            VulnerabilityType.BUFFER_OVERFLOW: [
                r'stack.*overflow', r'heap.*overflow', r'buffer.*overflow'
            ],
            VulnerabilityType.USE_AFTER_FREE: [
                r'use.*after.*free', r'heap.*corruption', r'double.*free'
            ],
            VulnerabilityType.NULL_POINTER_DEREFERENCE: [
                r'sigsegv', r'access.*violation', r'null.*pointer'
            ]
        }
        
        for vuln_type, patterns in signature_patterns.items():
            for pattern in patterns:
                if re.search(pattern, signature, re.IGNORECASE):
                    confidence = 0.6 + (0.3 if len(re.findall(pattern, signature, re.IGNORECASE)) > 1 else 0)
                    
                    finding = SecurityFinding(
                        finding_id=f"signature_{vuln_type.value}_{hash(signature)}",
                        session_id="analysis",
                        vulnerability_type=vuln_type,
                        severity=self.cve_database[vuln_type]['severity'],
                        description=f"Crash signature indicates {vuln_type.value.replace('_', ' ')}",
                        evidence=[f"Signature pattern: {pattern}"],
                        confidence_score=confidence,
                        detection_method="crash_signature_analysis"
                    )
                    findings.append(finding)
        
        return findings
    
    def _analyze_stack_trace(self, stack_trace: str) -> List[SecurityFinding]:
        """Analyze stack trace for vulnerability indicators"""
        findings = []
        
        # Extract function names
        function_pattern = r'(?:in|at)\s+(\w+)|(\w+)\s*\('
        functions = re.findall(function_pattern, stack_trace)
        functions = [f[0] or f[1] for f in functions if f[0] or f[1]]
        
        # Check for dangerous functions
        dangerous_functions = {
            'strcpy': VulnerabilityType.BUFFER_OVERFLOW,
            'strcat': VulnerabilityType.BUFFER_OVERFLOW,
            'sprintf': VulnerabilityType.BUFFER_OVERFLOW,
            'gets': VulnerabilityType.BUFFER_OVERFLOW,
            'free': VulnerabilityType.USE_AFTER_FREE,
            'malloc': VulnerabilityType.USE_AFTER_FREE,
        }
        
        for func in functions:
            if func in dangerous_functions:
                vuln_type = dangerous_functions[func]
                finding = SecurityFinding(
                    finding_id=f"stack_{vuln_type.value}_{func}",
                    session_id="analysis",
                    vulnerability_type=vuln_type,
                    severity=SecuritySeverity.MEDIUM,
                    function_name=func,
                    description=f"Dangerous function '{func}' in stack trace",
                    confidence_score=0.5,
                    detection_method="stack_trace_analysis"
                )
                findings.append(finding)
        
        # Check for memory addresses
        null_pattern = r'0x0+(?:\s|$)|0x00000000'
        if re.search(null_pattern, stack_trace):
            finding = SecurityFinding(
                finding_id=f"stack_null_deref_{hash(stack_trace)}",
                session_id="analysis",
                vulnerability_type=VulnerabilityType.NULL_POINTER_DEREFERENCE,
                severity=SecuritySeverity.MEDIUM,
                description="Null pointer dereference detected in stack trace",
                evidence=["Null address (0x0) in stack trace"],
                confidence_score=0.8,
                detection_method="stack_trace_analysis"
            )
            findings.append(finding)
        
        return findings
    
    def _analyze_memory_corruption(self, memory_info: Dict[str, Any]) -> List[SecurityFinding]:
        """Analyze memory information for corruption indicators"""
        findings = []
        
        if memory_info.get('heap_corruption'):
            finding = SecurityFinding(
                finding_id=f"memory_heap_corruption_{int(time.time())}",
                session_id="analysis",
                vulnerability_type=VulnerabilityType.USE_AFTER_FREE,
                severity=SecuritySeverity.HIGH,
                description="Heap corruption detected",
                confidence_score=0.9,
                detection_method="memory_analysis"
            )
            findings.append(finding)
        
        if memory_info.get('stack_overflow'):
            finding = SecurityFinding(
                finding_id=f"memory_stack_overflow_{int(time.time())}",
                session_id="analysis",
                vulnerability_type=VulnerabilityType.BUFFER_OVERFLOW,
                severity=SecuritySeverity.HIGH,
                description="Stack overflow detected",
                confidence_score=0.9,
                detection_method="memory_analysis"
            )
            findings.append(finding)
        
        return findings
    
    def _assess_risk(self, vulnerabilities: List[SecurityFinding]) -> Dict[str, Any]:
        """Assess overall risk from vulnerabilities"""
        if not vulnerabilities:
            return {'overall_risk': 'low', 'risk_score': 0.0, 'critical_count': 0}
        
        severity_counts = Counter(vuln.severity for vuln in vulnerabilities)
        
        # Calculate weighted risk score
        risk_score = sum(
            severity_counts[severity] * self.severity_weights[severity]
            for severity in severity_counts
        ) / len(vulnerabilities)
        
        # Determine overall risk level
        if risk_score >= 7.5:
            overall_risk = 'critical'
        elif risk_score >= 5.0:
            overall_risk = 'high'
        elif risk_score >= 2.5:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return {
            'overall_risk': overall_risk,
            'risk_score': risk_score,
            'severity_distribution': dict(severity_counts),
            'exploitability_assessment': self._assess_exploitability(vulnerabilities),
            'business_impact': self._assess_business_impact(vulnerabilities)
        }
    
    def _assess_exploitability(self, vulnerabilities: List[SecurityFinding]) -> Dict[str, Any]:
        """Assess exploitability of vulnerabilities"""
        high_exploitability = [
            VulnerabilityType.BUFFER_OVERFLOW,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.SQL_INJECTION
        ]
        
        exploitable_count = sum(
            1 for vuln in vulnerabilities 
            if vuln.vulnerability_type in high_exploitability
        )
        
        return {
            'highly_exploitable_count': exploitable_count,
            'exploitability_score': min(exploitable_count * 0.3, 1.0),
            'attack_vectors': self._identify_attack_vectors(vulnerabilities)
        }
    
    def _identify_attack_vectors(self, vulnerabilities: List[SecurityFinding]) -> List[str]:
        """Identify potential attack vectors"""
        vectors = set()
        
        vector_mapping = {
            VulnerabilityType.BUFFER_OVERFLOW: ['memory_corruption', 'code_execution'],
            VulnerabilityType.SQL_INJECTION: ['database_manipulation', 'data_exfiltration'],
            VulnerabilityType.COMMAND_INJECTION: ['system_command_execution', 'privilege_escalation'],
            VulnerabilityType.USE_AFTER_FREE: ['memory_corruption', 'information_disclosure']
        }
        
        for vuln in vulnerabilities:
            if vuln.vulnerability_type in vector_mapping:
                vectors.update(vector_mapping[vuln.vulnerability_type])
        
        return list(vectors)
    
    def _assess_business_impact(self, vulnerabilities: List[SecurityFinding]) -> Dict[str, Any]:
        """Assess business impact of vulnerabilities"""
        impact_scores = {
            SecuritySeverity.CRITICAL: 1.0,
            SecuritySeverity.HIGH: 0.8,
            SecuritySeverity.MEDIUM: 0.5,
            SecuritySeverity.LOW: 0.2,
            SecuritySeverity.INFO: 0.1
        }
        
        max_impact = max(
            (impact_scores[vuln.severity] for vuln in vulnerabilities),
            default=0.0
        )
        
        return {
            'confidentiality_impact': max_impact,
            'integrity_impact': max_impact,
            'availability_impact': max_impact * 0.8,  # Slightly lower
            'overall_business_impact': max_impact
        }
    
    def _analyze_false_positives(self, vulnerabilities: List[SecurityFinding], 
                                crash_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze likelihood of false positives"""
        fp_analysis = {}
        
        for vuln in vulnerabilities:
            fp_probability = self._calculate_false_positive_probability(vuln, crash_data)
            fp_analysis[vuln.finding_id] = {
                'probability': fp_probability,
                'factors': self._get_fp_factors(vuln, crash_data),
                'verification_needed': fp_probability > 0.3
            }
        
        return fp_analysis
    
    def _calculate_false_positive_probability(self, vuln: SecurityFinding, 
                                           crash_data: Dict[str, Any]) -> float:
        """Calculate false positive probability for a vulnerability"""
        base_fp_rate = 0.1
        
        # Confidence factor (higher confidence = lower FP rate)
        confidence_factor = 1.0 - vuln.confidence_score
        
        # Detection method factor
        method_factors = {
            'pattern_matching': 1.2,
            'crash_signature_analysis': 0.8,
            'stack_trace_analysis': 1.0,
            'memory_analysis': 0.6
        }
        
        method_factor = method_factors.get(vuln.detection_method, 1.0)
        
        # Vulnerability type factor
        type_factors = {
            VulnerabilityType.BUFFER_OVERFLOW: 0.8,
            VulnerabilityType.USE_AFTER_FREE: 0.9,
            VulnerabilityType.SQL_INJECTION: 1.1,
            VulnerabilityType.COMMAND_INJECTION: 1.0
        }
        
        type_factor = type_factors.get(vuln.vulnerability_type, 1.0)
        
        fp_rate = base_fp_rate * confidence_factor * method_factor * type_factor
        return min(max(fp_rate, 0.0), 1.0)
    
    def _get_fp_factors(self, vuln: SecurityFinding, crash_data: Dict[str, Any]) -> List[str]:
        """Get factors that influence false positive probability"""
        factors = []
        
        if vuln.confidence_score < 0.5:
            factors.append("Low confidence score")
        
        if vuln.detection_method == "pattern_matching":
            factors.append("Pattern-based detection can have false positives")
        
        if not crash_data.get('stack_trace'):
            factors.append("No stack trace for verification")
        
        if not vuln.code_snippet:
            factors.append("No code snippet for manual review")
        return factors
    
    def _generate_remediation_plan(self, vulnerabilities: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Generate comprehensive remediation plan"""
        remediation_plan = []
        
        # Group vulnerabilities by type
        vuln_groups = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_groups[vuln.vulnerability_type].append(vuln)
        
        # Generate remediation steps for each type
        for vuln_type, vulns in vuln_groups.items():
            if vuln_type in self.cve_database:
                plan_item = {
                    'vulnerability_type': vuln_type.value,
                    'affected_count': len(vulns),
                    'priority': self._calculate_remediation_priority(vulns),
                    'estimated_effort': self._estimate_remediation_effort(vulns),
                    'immediate_actions': self.cve_database[vuln_type]['remediation'][:2],
                    'long_term_solutions': self.cve_database[vuln_type]['remediation'][2:],
                    'verification_steps': self._get_verification_steps(vuln_type),
                    'timeline': self._estimate_remediation_timeline(vulns)
                }
                remediation_plan.append(plan_item)
        
        # Sort by priority
        remediation_plan.sort(key=lambda x: x['priority'], reverse=True)
        
        return remediation_plan
    
    def _calculate_remediation_priority(self, vulnerabilities: List[SecurityFinding]) -> int:
        """Calculate remediation priority (1-10)"""
        max_severity = max(vuln.severity for vuln in vulnerabilities)
        severity_scores = {
            SecuritySeverity.CRITICAL: 10,
            SecuritySeverity.HIGH: 8,
            SecuritySeverity.MEDIUM: 5,
            SecuritySeverity.LOW: 2,
            SecuritySeverity.INFO: 1
        }
        
        base_priority = severity_scores[max_severity]
        
        # Adjust for count
        count_factor = min(len(vulnerabilities) * 0.5, 2)
        
        # Adjust for confidence
        avg_confidence = sum(vuln.confidence_score for vuln in vulnerabilities) / len(vulnerabilities)
        confidence_factor = avg_confidence
        
        return min(int(base_priority + count_factor + confidence_factor), 10)
    
    def _estimate_remediation_effort(self, vulnerabilities: List[SecurityFinding]) -> str:
        """Estimate remediation effort"""
        effort_mapping = {
            VulnerabilityType.BUFFER_OVERFLOW: "high",
            VulnerabilityType.USE_AFTER_FREE: "high", 
            VulnerabilityType.SQL_INJECTION: "medium",
            VulnerabilityType.COMMAND_INJECTION: "medium",
            VulnerabilityType.NULL_POINTER_DEREFERENCE: "low"
        }
        
        if not vulnerabilities:
            return "unknown"
        
        max_effort = max(
            effort_mapping.get(vuln.vulnerability_type, "medium") 
            for vuln in vulnerabilities
        )
        
        return max_effort
    
    def _get_verification_steps(self, vuln_type: VulnerabilityType) -> List[str]:
        """Get verification steps for vulnerability type"""
        verification_steps = {
            VulnerabilityType.BUFFER_OVERFLOW: [
                "Run static analysis tools (cppcheck, PVS-Studio)",
                "Execute with AddressSanitizer (ASAN)",
                "Perform manual code review of buffer operations",
                "Test with boundary value inputs"
            ],
            VulnerabilityType.USE_AFTER_FREE: [
                "Run with AddressSanitizer and Valgrind",
                "Review memory management patterns",
                "Check for proper pointer nullification",
                "Test object lifetime scenarios"
            ],
            VulnerabilityType.SQL_INJECTION: [
                "Review all database query constructions",
                "Test with SQL injection payloads",
                "Verify parameterized query usage",
                "Check input validation implementation"
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                "Audit all system call invocations",
                "Test with command injection payloads",
                "Verify input sanitization",
                "Check for shell=True usage"
            ]
        }
        
        return verification_steps.get(vuln_type, ["Manual code review required"])
    
    def _estimate_remediation_timeline(self, vulnerabilities: List[SecurityFinding]) -> Dict[str, str]:
        """Estimate remediation timeline"""
        severity_timelines = {
            SecuritySeverity.CRITICAL: {"immediate": "24 hours", "complete": "1 week"},
            SecuritySeverity.HIGH: {"immediate": "72 hours", "complete": "2 weeks"},
            SecuritySeverity.MEDIUM: {"immediate": "1 week", "complete": "1 month"},
            SecuritySeverity.LOW: {"immediate": "2 weeks", "complete": "3 months"},
            SecuritySeverity.INFO: {"immediate": "1 month", "complete": "6 months"}
        }
        
        max_severity = max(vuln.severity for vuln in vulnerabilities)
        return severity_timelines[max_severity]

class LLMProviderManager:
    """Manages multiple LLM providers with health monitoring and failover"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.providers: Dict[str, 'LLMProvider'] = {}
        self.health_status: Dict[str, Dict[str, Any]] = {}
        self.usage_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'requests': 0, 'tokens': 0, 'errors': 0, 'total_cost': 0.0
        })
        self.rate_limiters: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.last_health_check = {}
        
        # Initialize providers
        self._initialize_providers()
        
        # Start health monitoring
        self.health_monitor_thread = threading.Thread(target=self._health_monitor_loop, daemon=True)
        self.health_monitor_thread.start()
    
    def _initialize_providers(self):
        """Initialize all available LLM providers"""
        # OpenAI Provider
        if HAS_OPENAI and os.getenv('OPENAI_API_KEY'):
            self.providers['openai'] = OpenAIProvider(self.config.get('openai', {}))
        
        # Anthropic Provider
        if HAS_ANTHROPIC and os.getenv('ANTHROPIC_API_KEY'):
            self.providers['anthropic'] = AnthropicProvider(self.config.get('anthropic', {}))
        
        # Ollama Provider (local)
        self.providers['ollama'] = OllamaProvider(self.config.get('ollama', {}))
        
        # HuggingFace Provider
        if os.getenv('HUGGINGFACE_API_TOKEN'):
            self.providers['huggingface'] = HuggingFaceProvider(self.config.get('huggingface', {}))
        
        # LocalAI Provider
        self.providers['localai'] = LocalAIProvider(self.config.get('localai', {}))
        
        logger.info(f"Initialized {len(self.providers)} LLM providers")
    
    def _health_monitor_loop(self):
        """Background health monitoring loop"""
        while True:
            try:
                for provider_name, provider in self.providers.items():
                    # Check health every 5 minutes, or immediately if last check failed
                    last_check = self.last_health_check.get(provider_name, 0)
                    current_time = time.time()
                    
                    should_check = (
                        current_time - last_check > 300 or  # 5 minutes
                        self.health_status.get(provider_name, {}).get('status') == 'unhealthy'
                    )
                    
                    if should_check:
                        health = provider.check_health()
                        self.health_status[provider_name] = health
                        self.last_health_check[provider_name] = current_time
                        
                        if health['status'] == 'unhealthy':
                            logger.warning(f"Provider {provider_name} is unhealthy: {health.get('error')}")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                time.sleep(60)
    
    def get_available_providers(self) -> List[str]:
        """Get list of healthy providers"""
        healthy_providers = []
        for name, status in self.health_status.items():
            if status.get('status') == 'healthy':
                healthy_providers.append(name)
        return healthy_providers
    
    def select_provider(self, preferences: Optional[List[str]] = None) -> Optional[str]:
        """Select best available provider based on preferences and health"""
        available = self.get_available_providers()
        
        if not available:
            logger.warning("No healthy providers available")
            return None
        
        # Apply preferences
        if preferences:
            for preferred in preferences:
                if preferred in available:
                    return preferred
        
        # Fallback to least loaded provider
        return min(available, key=lambda p: self.usage_stats[p]['requests'])
    
    async def generate_completion(self, prompt: str, provider_name: Optional[str] = None,
                                **kwargs) -> Dict[str, Any]:
        """Generate completion with automatic provider selection and failover"""
        if provider_name and provider_name not in self.providers:
            raise LLMProviderError(f"Provider {provider_name} not available")
        
        # Select provider
        if not provider_name:
            provider_name = self.select_provider()
            if not provider_name:
                raise LLMProviderError("No healthy providers available")
        
        provider = self.providers[provider_name]
        
        # Check rate limits
        if self._is_rate_limited(provider_name):
            # Try fallback provider
            fallback = self.select_provider([p for p in self.providers.keys() if p != provider_name])
            if fallback:
                provider_name = fallback
                provider = self.providers[provider_name]
            else:
                raise LLMProviderError("All providers rate limited")
        
        # Make request
        try:
            start_time = time.time()
            result = await provider.generate_completion(prompt, **kwargs)
            response_time = (time.time() - start_time) * 1000
            
            # Update statistics
            self.usage_stats[provider_name]['requests'] += 1
            self.usage_stats[provider_name]['tokens'] += result.get('total_tokens', 0)
            self.usage_stats[provider_name]['total_cost'] += result.get('cost', 0.0)
            
            # Update rate limiting
            self._update_rate_limit(provider_name, response_time)
            
            result['provider_used'] = provider_name
            result['response_time_ms'] = response_time
            
            return result
            
        except Exception as e:
            self.usage_stats[provider_name]['errors'] += 1
            logger.error(f"Provider {provider_name} failed: {e}")
            
            # Try failover
            fallback = self.select_provider([p for p in self.providers.keys() if p != provider_name])
            if fallback:
                logger.info(f"Failing over to {fallback}")
                return await self.generate_completion(prompt, fallback, **kwargs)
            else:
                raise LLMProviderError(f"All providers failed: {e}")
    
    def _is_rate_limited(self, provider_name: str) -> bool:
        """Check if provider is rate limited"""
        rate_data = self.rate_limiters.get(provider_name, {})
        current_time = time.time()
        
        # Simple rate limiting: max 60 requests per minute
        last_reset = rate_data.get('last_reset', 0)
        if current_time - last_reset > 60:
            rate_data['requests'] = 0
            rate_data['last_reset'] = current_time
        
        return rate_data.get('requests', 0) >= 60
    
    def _update_rate_limit(self, provider_name: str, response_time_ms: float):
        """Update rate limiting data"""
        rate_data = self.rate_limiters[provider_name]
        rate_data['requests'] = rate_data.get('requests', 0) + 1
        rate_data['avg_response_time'] = (
            rate_data.get('avg_response_time', 0) * 0.9 + response_time_ms * 0.1
        )
    
    def get_usage_statistics(self) -> Dict[str, Any]:
        """Get comprehensive usage statistics"""
        stats = {
            'providers': dict(self.usage_stats),
            'health_status': self.health_status,
            'total_requests': sum(stats['requests'] for stats in self.usage_stats.values()),
            'total_tokens': sum(stats['tokens'] for stats in self.usage_stats.values()),
            'total_cost': sum(stats['total_cost'] for stats in self.usage_stats.values()),
            'error_rate': self._calculate_error_rate()
        }
        
        return stats
    
    def _calculate_error_rate(self) -> float:
        """Calculate overall error rate"""
        total_requests = sum(stats['requests'] for stats in self.usage_stats.values())
        total_errors = sum(stats['errors'] for stats in self.usage_stats.values())
        
        return total_errors / total_requests if total_requests > 0 else 0.0

class BaseLLMProvider(ABC):
    """Base class for LLM providers"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.session = self._create_http_session()
    
    def _create_http_session(self) -> requests.Session:
        """Create HTTP session with retries"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    @abstractmethod
    async def generate_completion(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate completion from prompt"""
        pass
    
    @abstractmethod
    def check_health(self) -> Dict[str, Any]:
        """Check provider health"""
        pass
    
    def _estimate_tokens(self, text: str) -> int:
        """Rough token estimation (4 chars per token)"""
        return len(text) // 4

class OpenAIProvider(BaseLLMProvider):
    """OpenAI API provider"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("OpenAI", config)
        self.api_key = os.getenv('OPENAI_API_KEY')
        self.base_url = config.get('base_url', 'https://api.openai.com/v1')
        self.default_model = config.get('model', 'gpt-3.5-turbo')
        
        if HAS_OPENAI:
            self.client = openai.AsyncOpenAI(api_key=self.api_key)
    
    async def generate_completion(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate completion using OpenAI API"""
        if not HAS_OPENAI:
            raise LLMProviderError("OpenAI library not available")
        
        model = kwargs.get('model', self.default_model)
        max_tokens = kwargs.get('max_tokens', 1000)
        temperature = kwargs.get('temperature', 0.7)
        
        try:
            response = await self.client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature
            )
            
            completion = response.choices[0].message.content
            
            # Calculate tokens and cost
            prompt_tokens = response.usage.prompt_tokens
            completion_tokens = response.usage.completion_tokens
            total_tokens = response.usage.total_tokens
            
            cost = estimate_llm_cost(total_tokens, model, LLMProvider.OPENAI)
            
            return {
                'completion': completion,
                'prompt_tokens': prompt_tokens,
                'completion_tokens': completion_tokens,
                'total_tokens': total_tokens,
                'cost': cost,
                'model': model
            }
            
        except Exception as e:
            raise LLMProviderError(f"OpenAI API error: {e}")
    
    def check_health(self) -> Dict[str, Any]:
        """Check OpenAI API health"""
        try:
            if not HAS_OPENAI or not self.api_key:
                return {'status': 'unhealthy', 'error': 'API key not configured'}
            
            # Simple health check - list models
            response = self.session.get(
                f"{self.base_url}/models",
                headers={'Authorization': f'Bearer {self.api_key}'},
                timeout=10
            )
            
            if response.status_code == 200:
                return {'status': 'healthy', 'response_time_ms': response.elapsed.total_seconds() * 1000}
            else:
                return {'status': 'unhealthy', 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}

class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude API provider"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Anthropic", config)
        self.api_key = os.getenv('ANTHROPIC_API_KEY')
        self.base_url = config.get('base_url', 'https://api.anthropic.com')
        self.default_model = config.get('model', 'claude-3-sonnet-20240229')
        
        if HAS_ANTHROPIC:
            self.client = anthropic.AsyncAnthropic(api_key=self.api_key)
    
    async def generate_completion(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate completion using Anthropic API"""
        if not HAS_ANTHROPIC:
            raise LLMProviderError("Anthropic library not available")
        
        model = kwargs.get('model', self.default_model)
        max_tokens = kwargs.get('max_tokens', 1000)
        temperature = kwargs.get('temperature', 0.7)
        
        try:
            response = await self.client.messages.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            
            completion = response.content[0].text
            
            # Estimate tokens (Anthropic doesn't always return usage)
            prompt_tokens = self._estimate_tokens(prompt)
            completion_tokens = self._estimate_tokens(completion)
            total_tokens = prompt_tokens + completion_tokens
            
            cost = estimate_llm_cost(total_tokens, model, LLMProvider.ANTHROPIC)
            
            return {
                'completion': completion,
                'prompt_tokens': prompt_tokens,
                'completion_tokens': completion_tokens,
                'total_tokens': total_tokens,
                'cost': cost,
                'model': model
            }
            
        except Exception as e:
            raise LLMProviderError(f"Anthropic API error: {e}")
    
    def check_health(self) -> Dict[str, Any]:
        """Check Anthropic API health"""
        try:
            if not HAS_ANTHROPIC or not self.api_key:
                return {'status': 'unhealthy', 'error': 'API key not configured'}
            
            # Health check endpoint
            response = self.session.get(
                f"{self.base_url}/v1/complete",
                headers={'x-api-key': self.api_key, 'anthropic-version': '2023-06-01'},
                timeout=10
            )
            
            # Anthropic returns 400 for GET requests, but that means it's accessible
            if response.status_code in [200, 400, 405]:
                return {'status': 'healthy', 'response_time_ms': response.elapsed.total_seconds() * 1000}
            else:
                return {'status': 'unhealthy', 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}

class OllamaProvider(BaseLLMProvider):
    """Ollama local LLM provider"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Ollama", config)
        self.base_url = config.get('base_url', 'http://localhost:11434')
        self.default_model = config.get('model', 'llama2')
    
    async def generate_completion(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate completion using Ollama API"""
        model = kwargs.get('model', self.default_model)
        
        try:
            payload = {
                'model': model,
                'prompt': prompt,
                'stream': False
            }
            
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=60
            )
            
            if response.status_code != 200:
                raise LLMProviderError(f"Ollama error: HTTP {response.status_code}")
            
            data = response.json()
            completion = data.get('response', '')
            
            # Estimate tokens
            prompt_tokens = self._estimate_tokens(prompt)
            completion_tokens = self._estimate_tokens(completion)
            total_tokens = prompt_tokens + completion_tokens
            
            return {
                'completion': completion,
                'prompt_tokens': prompt_tokens,
                'completion_tokens': completion_tokens,
                'total_tokens': total_tokens,
                'cost': 0.0,  # Local model
                'model': model
            }
            
        except Exception as e:
            raise LLMProviderError(f"Ollama error: {e}")
    
    def check_health(self) -> Dict[str, Any]:
        """Check Ollama health"""
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                models = data.get('models', [])
                return {
                    'status': 'healthy',
                    'response_time_ms': response.elapsed.total_seconds() * 1000,
                    'models_available': len(models)
                }
            else:
                return {'status': 'unhealthy', 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}

class HuggingFaceProvider(BaseLLMProvider):
    """Hugging Face Inference API provider"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("HuggingFace", config)
        self.api_token = os.getenv('HUGGINGFACE_API_TOKEN')
        self.base_url = config.get('base_url', 'https://api-inference.huggingface.co')
        self.default_model = config.get('model', 'microsoft/DialoGPT-medium')
    
    async def generate_completion(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate completion using Hugging Face API"""
        model = kwargs.get('model', self.default_model)
        max_tokens = kwargs.get('max_tokens', 1000)
        
        try:
            headers = {'Authorization': f'Bearer {self.api_token}'}
            payload = {
                'inputs': prompt,
                'parameters': {
                    'max_new_tokens': max_tokens,
                    'temperature': kwargs.get('temperature', 0.7)
                }
            }
            
            response = self.session.post(
                f"{self.base_url}/models/{model}",
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code != 200:
                raise LLMProviderError(f"HuggingFace error: HTTP {response.status_code}")
            
            data = response.json()
            
            if isinstance(data, list) and data:
                completion = data[0].get('generated_text', '').replace(prompt, '').strip()
            else:
                completion = str(data)
            
            # Estimate tokens
            prompt_tokens = self._estimate_tokens(prompt)
            completion_tokens = self._estimate_tokens(completion)
            total_tokens = prompt_tokens + completion_tokens
            
            cost = estimate_llm_cost(total_tokens, model, LLMProvider.HUGGINGFACE)
            
            return {
                'completion': completion,
                'prompt_tokens': prompt_tokens,
                'completion_tokens': completion_tokens,
                'total_tokens': total_tokens,
                'cost': cost,
                'model': model
            }
            
        except Exception as e:
            raise LLMProviderError(f"HuggingFace error: {e}")
    
    def check_health(self) -> Dict[str, Any]:
        """Check Hugging Face API health"""
        try:
            if not self.api_token:
                return {'status': 'unhealthy', 'error': 'API token not configured'}
            
            headers = {'Authorization': f'Bearer {self.api_token}'}
            response = self.session.get(
                f"{self.base_url}/models/{self.default_model}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code in [200, 404]:  # 404 is OK, means model exists
                return {'status': 'healthy', 'response_time_ms': response.elapsed.total_seconds() * 1000}
            else:
                return {'status': 'unhealthy', 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}

class LocalAIProvider(BaseLLMProvider):
    """LocalAI provider for self-hosted models"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("LocalAI", config)
        self.base_url = config.get('base_url', 'http://localhost:8080')
        self.default_model = config.get('model', 'gpt-3.5-turbo')
    
    async def generate_completion(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate completion using LocalAI API"""
        model = kwargs.get('model', self.default_model)
        max_tokens = kwargs.get('max_tokens', 1000)
        temperature = kwargs.get('temperature', 0.7)
        
        try:
            payload = {
                'model': model,
                'messages': [{'role': 'user', 'content': prompt}],
                'max_tokens': max_tokens,
                'temperature': temperature
            }
            
            response = self.session.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                timeout=60
            )
            
            if response.status_code != 200:
                raise LLMProviderError(f"LocalAI error: HTTP {response.status_code}")
            
            data = response.json()
            completion = data['choices'][0]['message']['content']
            
            # Extract usage if available
            usage = data.get('usage', {})
            prompt_tokens = usage.get('prompt_tokens', self._estimate_tokens(prompt))
            completion_tokens = usage.get('completion_tokens', self._estimate_tokens(completion))
            total_tokens = usage.get('total_tokens', prompt_tokens + completion_tokens)
            
            return {
                'completion': completion,
                'prompt_tokens': prompt_tokens,
                'completion_tokens': completion_tokens,
                'total_tokens': total_tokens,
                'cost': 0.0,  # Local model
                'model': model
            }
            
        except Exception as e:
            raise LLMProviderError(f"LocalAI error: {e}")
    
    def check_health(self) -> Dict[str, Any]:
        """Check LocalAI health"""
        try:
            response = self.session.get(f"{self.base_url}/v1/models", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                models = data.get('data', [])
                return {
                    'status': 'healthy',
                    'response_time_ms': response.elapsed.total_seconds() * 1000,
                    'models_available': len(models)
                }
            else:
                return {'status': 'unhealthy', 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}

class PerformanceAnalyzer(BaseAnalyzer):
    """Advanced performance analysis with statistical methods"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("PerformanceAnalyzer", config)
        self.baseline_metrics = {}
        self.performance_history = defaultdict(list)
    
    def _analyze_impl(self, session: CIFuzzSparkSession) -> Dict[str, Any]:
        """Comprehensive performance analysis"""
        results = {
            'resource_efficiency': {},
            'throughput_analysis': {},
            'cost_analysis': {},
            'trend_analysis': {},
            'optimization_suggestions': [],
            'benchmark_comparison': {}
        }
        
        # Resource efficiency analysis
        results['resource_efficiency'] = self._analyze_resource_efficiency(session)
        
        # Throughput analysis
        results['throughput_analysis'] = self._analyze_throughput(session)
        
        # Cost analysis
        results['cost_analysis'] = self._analyze_costs(session)
        
        # Trend analysis
        results['trend_analysis'] = self._analyze_trends(session)
        
        # Generate optimization suggestions
        results['optimization_suggestions'] = self._generate_optimization_suggestions(results)
        
        # Benchmark comparison
        results['benchmark_comparison'] = self._compare_to_benchmark(session)
        
        return results
    
    def _analyze_resource_efficiency(self, session: CIFuzzSparkSession) -> Dict[str, Any]:
        """Analyze resource utilization efficiency"""
        efficiency = {
            'cpu_efficiency': 0.0,
            'memory_efficiency': 0.0,
            'network_efficiency': 0.0,
            'overall_efficiency': 0.0
        }
        
        # CPU efficiency (utilization vs results)
        if session.average_cpu_usage > 0 and session.fuzz_drivers_generated > 0:
            efficiency['cpu_efficiency'] = min(
                session.fuzz_drivers_generated / (session.average_cpu_usage / 100), 1.0
            )
        
        # Memory efficiency
        if session.peak_memory_usage_mb > 0:
            # Normalize by results produced
            memory_per_result = session.peak_memory_usage_mb / max(session.fuzz_drivers_generated, 1)
            efficiency['memory_efficiency'] = max(0.0, 1.0 - (memory_per_result / 1000))  # Assume 1GB baseline
        
        # Network efficiency (for LLM calls)
        if session.network_bytes_sent > 0 and session.total_llm_interactions > 0:
            bytes_per_interaction = session.network_bytes_sent / session.total_llm_interactions
            efficiency['network_efficiency'] = max(0.0, 1.0 - (bytes_per_interaction / 100000))  # 100KB baseline
        
        # Overall efficiency
        efficiency['overall_efficiency'] = np.mean([
            efficiency['cpu_efficiency'],
            efficiency['memory_efficiency'],
            efficiency['network_efficiency']
        ])
        
        return efficiency
    
    def _analyze_throughput(self, session: CIFuzzSparkSession) -> Dict[str, Any]:
        """Analyze throughput metrics"""
        throughput = {
            'drivers_per_hour': 0.0,
            'tokens_per_minute': 0.0,
            'interactions_per_hour': 0.0,
            'crashes_per_hour': 0.0
        }
        
        duration_hours = session.total_duration_ms / (1000 * 3600)
        
        if duration_hours > 0:
            throughput['drivers_per_hour'] = session.fuzz_drivers_generated / duration_hours
            throughput['interactions_per_hour'] = session.total_llm_interactions / duration_hours
            throughput['crashes_per_hour'] = session.unique_crashes_found / duration_hours
            
            duration_minutes = duration_hours * 60
            throughput['tokens_per_minute'] = session.total_tokens_consumed / duration_minutes
        
        return throughput
    
    def _analyze_costs(self, session: CIFuzzSparkSession) -> Dict[str, Any]:
        """Analyze cost efficiency"""
        costs = {
            'total_cost_usd': session.estimated_cost_usd,
            'cost_per_driver': 0.0,
            'cost_per_vulnerability': 0.0,
            'cost_per_token': 0.0,
            'roi_analysis': {}
        }
        
        if session.fuzz_drivers_generated > 0:
            costs['cost_per_driver'] = session.estimated_cost_usd / session.fuzz_drivers_generated
        
        if session.security_vulnerabilities_found > 0:
            costs['cost_per_vulnerability'] = session.estimated_cost_usd / session.security_vulnerabilities_found
        
        if session.total_tokens_consumed > 0:
            costs['cost_per_token'] = session.estimated_cost_usd / session.total_tokens_consumed
        
        # ROI analysis
        costs['roi_analysis'] = self._calculate_roi(session)
        
        return costs
    
    def _calculate_roi(self, session: CIFuzzSparkSession) -> Dict[str, float]:
        """Calculate return on investment"""
        # Estimate value of findings
        vuln_values = {
            'critical': 10000,  # Critical vulnerability value
            'high': 5000,
            'medium': 1000,
            'low': 100
        }
        
        total_value = (
            session.critical_vulnerabilities * vuln_values['critical'] +
            session.high_vulnerabilities * vuln_values['high'] +
            session.medium_vulnerabilities * vuln_values['medium'] +
            session.low_vulnerabilities * vuln_values['low']
        )
        
        roi = (total_value - session.estimated_cost_usd) / max(session.estimated_cost_usd, 0.01)
        
        return {
            'estimated_value_usd': total_value,
            'net_value_usd': total_value - session.estimated_cost_usd,
            'roi_ratio': roi,
            'break_even_cost': total_value
        }
    
    def _analyze_trends(self, session: CIFuzzSparkSession) -> Dict[str, Any]:
        """Analyze performance trends"""
        if not HAS_SCIPY:
            return {'error': 'SciPy not available for trend analysis'}
        
        trends = {}
        
        # Add session to history
        session_key = f"{session.llm_provider}_{session.llm_model}"
        self.performance_history[session_key].append({
            'timestamp': session.start_time,
            'duration': session.total_duration_ms,
            'drivers_generated': session.fuzz_drivers_generated,
            'cost': session.estimated_cost_usd,
            'efficiency': session.automation_score
        })
        
        # Analyze trends if we have enough data
        history = self.performance_history[session_key]
        if len(history) >= 3:
            trends = self._calculate_trends(history)
        
        return trends
    
    def _calculate_trends(self, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistical trends"""
        if not HAS_SCIPY:
            return {}
        
        # Extract time series data
        timestamps = [h['timestamp'].timestamp() for h in history]
        durations = [h['duration'] for h in history]
        drivers = [h['drivers_generated'] for h in history]
        costs = [h['cost'] for h in history]
        
        trends = {}
        
        # Calculate trends for each metric
        for metric_name, values in [('duration', durations), ('drivers', drivers), ('costs', costs)]:
            if len(values) >= 3:
                slope, intercept, r_value, p_value, std_err = stats.linregress(timestamps, values)
                
                trends[metric_name] = {
                    'slope': slope,
                    'r_squared': r_value ** 2,
                    'p_value': p_value,
                    'trend_direction': 'improving' if slope < 0 else 'degrading' if slope > 0 else 'stable',
                    'significance': 'significant' if p_value < 0.05 else 'not_significant'
                }
        
        return trends
    
    def _generate_optimization_suggestions(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate performance optimization suggestions"""
        suggestions = []
        
        efficiency = analysis.get('resource_efficiency', {})
        throughput = analysis.get('throughput_analysis', {})
        costs = analysis.get('cost_analysis', {})
        
        # CPU efficiency suggestions
        if efficiency.get('cpu_efficiency', 0) < 0.5:
            suggestions.append("Low CPU efficiency detected. Consider parallel processing or algorithm optimization.")
        
        # Memory efficiency suggestions
        if efficiency.get('memory_efficiency', 0) < 0.5:
            suggestions.append("High memory usage detected. Consider memory optimization and garbage collection tuning.")
        
        # Throughput suggestions
        if throughput.get('drivers_per_hour', 0) < 10:
            suggestions.append("Low driver generation rate. Consider optimizing LLM prompts or increasing concurrency.")
        
        # Cost efficiency suggestions
        if costs.get('cost_per_driver', 0) > 1.0:
            suggestions.append("High cost per driver. Consider using more efficient models or optimizing token usage.")
        
        # ROI suggestions
        roi = costs.get('roi_analysis', {}).get('roi_ratio', 0)
        if roi < 1.0:
            suggestions.append("Low ROI detected. Focus on finding higher-impact vulnerabilities or reducing costs.")
        
        return suggestions
    
    def _compare_to_benchmark(self, session: CIFuzzSparkSession) -> Dict[str, Any]:
        """Compare session performance to benchmarks"""
        # Default benchmarks (would be configurable in real implementation)
        benchmarks = {
            'drivers_per_hour': 20,
            'cost_per_driver': 0.50,
            'cpu_efficiency': 0.7,
            'memory_efficiency': 0.8,
            'vulnerability_find_rate': 0.1  # vulnerabilities per driver
        }
        
        comparison = {}
        
        # Calculate session metrics
        duration_hours = session.total_duration_ms / (1000 * 3600)
        session_metrics = {
            'drivers_per_hour': session.fuzz_drivers_generated / max(duration_hours, 0.01),
            'cost_per_driver': session.estimated_cost_usd / max(session.fuzz_drivers_generated, 1),
            'vulnerability_find_rate': session.security_vulnerabilities_found / max(session.fuzz_drivers_generated, 1)
        }
        
        # Compare to benchmarks
        for metric, benchmark_value in benchmarks.items():
            if metric in session_metrics:
                session_value = session_metrics[metric]
                comparison[metric] = {
                    'session_value': session_value,
                    'benchmark_value': benchmark_value,
                    'ratio': session_value / benchmark_value,
                    'performance': 'above' if session_value > benchmark_value else 'below'
                }
        
        return comparison

# Export public API
__all__ = [
    # Analysis engines
    'AdvancedHallucinationDetector',
    'ComprehensiveCodeQualityAnalyzer', 
    'IntelligentVulnerabilityAnalyzer',
    'PerformanceAnalyzer',
    
    # LLM providers
    'LLMProviderManager',
    'OpenAIProvider',
    'AnthropicProvider', 
    'OllamaProvider',
    'HuggingFaceProvider',
    'LocalAIProvider',
    
    # Base classes and protocols
    'BaseAnalyzer',
    'BaseLLMProvider',
    'AnalysisProtocol',
    
    # Data structures
    'AnalysisResult',
    
    # Patterns and constants
    'SECURITY_PATTERNS',
    'HALLUCINATION_PATTERNS',
    'CODE_SMELL_PATTERNS'
]

if __name__ == "__main__":
    # Basic functionality test
    print("🧪 Testing Analysis Engines...")
    
    # Test hallucination detector
    detector = AdvancedHallucinationDetector()
    test_interaction = LLMInteraction(
        interaction_id="test",
        session_id="test_session", 
        timestamp=datetime.now().isoformat(),
        llm_provider=LLMProvider.OPENAI,
        llm_model="gpt-3.5-turbo",
        llm_endpoint="test",
        prompt_type="test",
        prompt_text="Write a C function to copy strings",
        response_text="void copy_string(char* dest, char* src) { strcpy(dest, src); }",
        prompt_tokens=10,
        response_tokens=20,
        total_tokens=30,
        response_time_ms=100.0
    )
    
    result = detector.analyze(test_interaction)
    print(f"✅ Hallucination analysis: {result.confidence_score:.2f} confidence")
    
    # Test code quality analyzer
    quality_analyzer = ComprehensiveCodeQualityAnalyzer()
    test_driver = FuzzDriverMetrics(
        driver_id="test_driver",
        session_id="test_session",
        generation_timestamp=datetime.now().isoformat(),
        generation_method="llm_generated",
        source_code="void copy_string(char* dest, char* src) { strcpy(dest, src); }",
        target_language="c"
    )
    
    quality_result = quality_analyzer.analyze(test_driver)
    print(f"✅ Code quality analysis: {quality_result.results['overall_score']:.1f}/10 score")
    
    print("🎉 Analysis engines test completed!")       