#!/usr/bin/env python3
"""
Advanced LLM Fuzzing Monitor - CLI Interface & Daemon Management
Part 4: Complete CLI, Process Monitoring, Advanced Parsers & System Integration

Master's Thesis Research: "Enhancing Automated Security Testing in CI/CD/CT Pipelines with Large Language Models"
Author: Morris Darren Babu
Version: 3.0.0
License: MIT
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
import threading
import subprocess
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Iterator
import psutil
import yaml
import xml.etree.ElementTree as ET
import csv
import gzip
import tarfile
import zipfile
import re
from dataclasses import asdict
import urllib.parse
import hashlib
import uuid

# Third-party imports with fallbacks
try:
    import rich
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.syntax import Syntax
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False

try:
    import watchdog
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    import docker
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

# Import our modules
from ..core.models import (
    CIFuzzSparkSession, LLMInteraction, FuzzDriverMetrics, SecurityFinding,
    SessionStatus, LLMProvider, VulnerabilityType, SecuritySeverity,
    MonitorConfig, safe_get_username, SPARK_PATTERNS
)
from ..storage.manager import AdvancedTextDataManager, ConcurrentSessionManager
from ..analysis.engines import (
    AdvancedHallucinationDetector, ComprehensiveCodeQualityAnalyzer,
    IntelligentVulnerabilityAnalyzer, LLMProviderManager, PerformanceAnalyzer
)

# Initialize console for rich output
console = Console() if HAS_RICH else None

# Pre-compiled patterns for enhanced parsing
LOG_PATTERNS = {
    'timestamp': re.compile(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})?)', re.IGNORECASE),
    'log_level': re.compile(r'\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b', re.IGNORECASE),
    'process_id': re.compile(r'\bpid[:\s]*(\d+)', re.IGNORECASE),
    'memory_usage': re.compile(r'(?:memory|mem)[:\s]*(\d+(?:\.\d+)?)\s*(mb|gb|kb|bytes?)', re.IGNORECASE),
    'cpu_usage': re.compile(r'cpu[:\s]*(\d+(?:\.\d+)?)%', re.IGNORECASE),
    'execution_time': re.compile(r'(?:exec|execution|took)[:\s]*(\d+(?:\.\d+)?)\s*(ms|s|sec|seconds?|minutes?)', re.IGNORECASE),
    'coverage': re.compile(r'coverage[:\s]*(\d+(?:\.\d+)?)%', re.IGNORECASE),
    'crash': re.compile(r'\b(crash|abort|segfault|sigsegv|sigabrt)\b', re.IGNORECASE),
    'vulnerability': re.compile(r'\b(vulnerability|exploit|cve-\d{4}-\d+|buffer overflow|use after free)\b', re.IGNORECASE),
}

FUZZING_PATTERNS = {
    'afl_stats': re.compile(r'execs_done\s*:\s*(\d+)', re.IGNORECASE),
    'libfuzzer_stats': re.compile(r'#(\d+)\s+INITED.*exec/s:\s*(\d+)', re.IGNORECASE),
    'honggfuzz_stats': re.compile(r'Iterations:\s*(\d+).*Speed:\s*(\d+)', re.IGNORECASE),
    'cifuzz_output': re.compile(r'Running fuzz test.*?(\w+)', re.IGNORECASE),
    'compilation_error': re.compile(r'error:\s*(.+)', re.IGNORECASE),
    'llm_generation': re.compile(r'(?:generating|generated).*?(?:fuzz|test|driver).*?(\w+)', re.IGNORECASE),
}

CODE_PATTERNS = {
    'function_def': {
        'c': re.compile(r'(\w+\s+)*(\w+)\s*\([^)]*\)\s*{', re.MULTILINE),
        'cpp': re.compile(r'(\w+\s+)*(\w+)\s*\([^)]*\)\s*{', re.MULTILINE),
        'python': re.compile(r'def\s+(\w+)\s*\([^)]*\):', re.MULTILINE),
        'java': re.compile(r'(?:public|private|protected)?\s*(?:static\s+)?(\w+)\s+(\w+)\s*\([^)]*\)', re.MULTILINE),
        'javascript': re.compile(r'function\s+(\w+)\s*\([^)]*\)', re.MULTILINE),
    },
    'include_import': {
        'c': re.compile(r'#include\s*[<"]([^>"]+)[>"]', re.MULTILINE),
        'cpp': re.compile(r'#include\s*[<"]([^>"]+)[>"]', re.MULTILINE),
        'python': re.compile(r'(?:import\s+(\w+)|from\s+(\w+)\s+import)', re.MULTILINE),
        'java': re.compile(r'import\s+([^;]+);', re.MULTILINE),
        'javascript': re.compile(r'(?:import.*?from\s+[\'"]([^\'"]+)[\'"]|require\([\'"]([^\'"]+)[\'"]\))', re.MULTILINE),
    }
}

class AdvancedLogParser:
    """Advanced log parser for multiple formats and fuzzing tools"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.LogParser")
        self.parsed_entries = []
        self.statistics = {
            'total_lines': 0,
            'parsed_entries': 0,
            'errors': 0,
            'warnings': 0,
            'execution_events': 0,
            'crash_events': 0,
            'llm_events': 0
        }
        
        # Initialize parsers for different tools
        self.tool_parsers = {
            'afl': AFLParser(),
            'libfuzzer': LibFuzzerParser(),
            'honggfuzz': HonggFuzzParser(),
            'cifuzz': CIFuzzParser(),
            'llm': LLMParser(),
            'compilation': CompilationParser(),
            'coverage': CoverageParser(),
            'crash': CrashParser(),
        }
    
    def parse_file(self, file_path: Path, format_hint: Optional[str] = None) -> Dict[str, Any]:
        """Parse log file with automatic format detection"""
        self.logger.info(f"Parsing log file: {file_path}")
        
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        # Detect format if not provided
        if not format_hint:
            format_hint = self._detect_log_format(file_path)
        
        # Parse based on format
        if format_hint == 'json':
            return self._parse_json_log(file_path)
        elif format_hint == 'xml':
            return self._parse_xml_log(file_path)
        elif format_hint == 'csv':
            return self._parse_csv_log(file_path)
        else:
            return self._parse_text_log(file_path, format_hint)
    
    def _detect_log_format(self, file_path: Path) -> str:
        """Detect log file format"""
        extension = file_path.suffix.lower()
        
        if extension in ['.json', '.jsonl']:
            return 'json'
        elif extension in ['.xml']:
            return 'xml'
        elif extension in ['.csv']:
            return 'csv'
        
        # Analyze content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_lines = [f.readline().strip() for _ in range(5)]
            
            # Check for JSON
            if any(line.startswith('{') for line in first_lines):
                return 'json'
            
            # Check for XML
            if any(line.startswith('<?xml') or line.startswith('<') for line in first_lines):
                return 'xml'
            
            # Check for CSV
            if any(',' in line and len(line.split(',')) > 3 for line in first_lines):
                return 'csv'
            
            # Check for specific tools
            content = ' '.join(first_lines).lower()
            if 'afl-fuzz' in content or 'american fuzzy lop' in content:
                return 'afl'
            elif 'libfuzzer' in content:
                return 'libfuzzer'
            elif 'honggfuzz' in content:
                return 'honggfuzz'
            elif 'cifuzz' in content:
                return 'cifuzz'
            
        except Exception:
            pass
        
        return 'text'
    
    def _parse_json_log(self, file_path: Path) -> Dict[str, Any]:
        """Parse JSON/JSONL log file"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix == '.jsonl':
                    # JSON Lines format
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line:
                            try:
                                entry = json.loads(line)
                                entry['_line_number'] = line_num
                                entries.append(self._process_json_entry(entry))
                            except json.JSONDecodeError as e:
                                self.logger.warning(f"Invalid JSON at line {line_num}: {e}")
                                self.statistics['errors'] += 1
                else:
                    # Single JSON file
                    data = json.load(f)
                    if isinstance(data, list):
                        entries = [self._process_json_entry(entry) for entry in data]
                    else:
                        entries = [self._process_json_entry(data)]
        
        except Exception as e:
            self.logger.error(f"Error parsing JSON log: {e}")
            self.statistics['errors'] += 1
        
        self.statistics['parsed_entries'] = len(entries)
        return {
            'format': 'json',
            'entries': entries,
            'statistics': self.statistics.copy()
        }
    
    def _process_json_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Process individual JSON log entry"""
        processed = {
            'timestamp': entry.get('timestamp', entry.get('time')),
            'level': entry.get('level', entry.get('severity')),
            'message': entry.get('message', entry.get('msg')),
            'raw_entry': entry
        }
        
        # Extract specific fields
        if 'llm' in entry or 'model' in entry:
            processed['type'] = 'llm_interaction'
            processed['llm_data'] = self._extract_llm_data(entry)
            self.statistics['llm_events'] += 1
        
        if 'crash' in str(entry).lower() or 'segfault' in str(entry).lower():
            processed['type'] = 'crash'
            processed['crash_data'] = self._extract_crash_data(entry)
            self.statistics['crash_events'] += 1
        
        if 'exec' in entry or 'execution' in entry:
            processed['type'] = 'execution'
            self.statistics['execution_events'] += 1
        
        return processed
    
    def _parse_xml_log(self, file_path: Path) -> Dict[str, Any]:
        """Parse XML log file"""
        entries = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Handle different XML structures
            if root.tag in ['testsuites', 'testsuite']:
                entries = self._parse_junit_xml(root)
            elif root.tag == 'coverage':
                entries = self._parse_coverage_xml(root)
            else:
                entries = self._parse_generic_xml(root)
        
        except ET.ParseError as e:
            self.logger.error(f"XML parse error: {e}")
            self.statistics['errors'] += 1
        except Exception as e:
            self.logger.error(f"Error parsing XML log: {e}")
            self.statistics['errors'] += 1
        
        self.statistics['parsed_entries'] = len(entries)
        return {
            'format': 'xml',
            'entries': entries,
            'statistics': self.statistics.copy()
        }
    
    def _parse_junit_xml(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Parse JUnit XML format"""
        entries = []
        
        for testsuite in root.findall('.//testsuite'):
            suite_name = testsuite.get('name', 'unknown')
            
            for testcase in testsuite.findall('testcase'):
                entry = {
                    'type': 'test_case',
                    'suite': suite_name,
                    'name': testcase.get('name'),
                    'classname': testcase.get('classname'),
                    'time': float(testcase.get('time', 0)),
                    'status': 'passed'
                }
                
                # Check for failures/errors
                failure = testcase.find('failure')
                error = testcase.find('error')
                
                if failure is not None:
                    entry['status'] = 'failed'
                    entry['failure_message'] = failure.get('message')
                    entry['failure_text'] = failure.text
                elif error is not None:
                    entry['status'] = 'error'
                    entry['error_message'] = error.get('message')
                    entry['error_text'] = error.text
                
                entries.append(entry)
        
        return entries
    
    def _parse_coverage_xml(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Parse coverage XML format"""
        entries = []
        
        for package in root.findall('.//package'):
            package_name = package.get('name', 'unknown')
            
            for class_elem in package.findall('classes/class'):
                class_name = class_elem.get('name')
                
                entry = {
                    'type': 'coverage',
                    'package': package_name,
                    'class': class_name,
                    'filename': class_elem.get('filename'),
                    'line_rate': float(class_elem.get('line-rate', 0)),
                    'branch_rate': float(class_elem.get('branch-rate', 0)),
                    'lines': []
                }
                
                # Parse line coverage
                for line in class_elem.findall('lines/line'):
                    line_data = {
                        'number': int(line.get('number')),
                        'hits': int(line.get('hits', 0)),
                        'branch': line.get('branch') == 'true'
                    }
                    entry['lines'].append(line_data)
                
                entries.append(entry)
        
        return entries
    
    def _parse_generic_xml(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Parse generic XML structure"""
        entries = []
        
        def xml_to_dict(element):
            result = {'tag': element.tag, 'text': element.text}
            if element.attrib:
                result['attributes'] = element.attrib
            if list(element):
                result['children'] = [xml_to_dict(child) for child in element]
            return result
        
        entries.append({
            'type': 'xml_data',
            'data': xml_to_dict(root)
        })
        
        return entries
    
    def _parse_csv_log(self, file_path: Path) -> Dict[str, Any]:
        """Parse CSV log file"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Detect delimiter
                sample = f.read(1024)
                f.seek(0)
                
                delimiter = ','
                if '\t' in sample:
                    delimiter = '\t'
                elif ';' in sample:
                    delimiter = ';'
                
                reader = csv.DictReader(f, delimiter=delimiter)
                
                for row_num, row in enumerate(reader, 1):
                    entry = {
                        'type': 'csv_row',
                        'row_number': row_num,
                        'data': dict(row)
                    }
                    
                    # Try to extract common fields
                    for field in ['timestamp', 'time', 'date']:
                        if field in row:
                            entry['timestamp'] = row[field]
                            break
                    
                    for field in ['level', 'severity', 'type']:
                        if field in row:
                            entry['level'] = row[field]
                            break
                    
                    entries.append(entry)
        
        except Exception as e:
            self.logger.error(f"Error parsing CSV log: {e}")
            self.statistics['errors'] += 1
        
        self.statistics['parsed_entries'] = len(entries)
        return {
            'format': 'csv',
            'entries': entries,
            'statistics': self.statistics.copy()
        }
    
    def _parse_text_log(self, file_path: Path, format_hint: str) -> Dict[str, Any]:
        """Parse text log file with format-specific parsing"""
        entries = []
        
        try:
            # Handle compressed files
            if file_path.suffix == '.gz':
                file_opener = gzip.open
                mode = 'rt'
            else:
                file_opener = open
                mode = 'r'
            
            with file_opener(file_path, mode, encoding='utf-8', errors='ignore') as f:
                if format_hint in self.tool_parsers:
                    # Use specific tool parser
                    parser = self.tool_parsers[format_hint]
                    entries = parser.parse(f)
                else:
                    # Generic text parsing
                    entries = self._parse_generic_text(f)
        
        except Exception as e:
            self.logger.error(f"Error parsing text log: {e}")
            self.statistics['errors'] += 1
        
        self.statistics['parsed_entries'] = len(entries)
        return {
            'format': f'text_{format_hint}',
            'entries': entries,
            'statistics': self.statistics.copy()
        }
    
    def _parse_generic_text(self, file_handle) -> List[Dict[str, Any]]:
        """Generic text log parsing"""
        entries = []
        
        for line_num, line in enumerate(file_handle, 1):
            line = line.strip()
            if not line:
                continue
            
            self.statistics['total_lines'] += 1
            
            entry = {
                'type': 'log_line',
                'line_number': line_num,
                'raw_line': line,
                'timestamp': None,
                'level': None,
                'message': line
            }
            
            # Extract timestamp
            timestamp_match = LOG_PATTERNS['timestamp'].search(line)
            if timestamp_match:
                entry['timestamp'] = timestamp_match.group(1)
            
            # Extract log level
            level_match = LOG_PATTERNS['log_level'].search(line)
            if level_match:
                entry['level'] = level_match.group(1).upper()
            
            # Extract specific information
            self._extract_line_info(line, entry)
            
            entries.append(entry)
        
        return entries
    
    def _extract_line_info(self, line: str, entry: Dict[str, Any]):
        """Extract specific information from log line"""
        line_lower = line.lower()
        
        # Memory usage
        memory_match = LOG_PATTERNS['memory_usage'].search(line)
        if memory_match:
            value = float(memory_match.group(1))
            unit = memory_match.group(2).lower()
            # Convert to MB
            if unit in ['gb']:
                value *= 1024
            elif unit in ['kb']:
                value /= 1024
            elif unit in ['bytes', 'byte']:
                value /= (1024 * 1024)
            entry['memory_mb'] = value
        
        # CPU usage
        cpu_match = LOG_PATTERNS['cpu_usage'].search(line)
        if cpu_match:
            entry['cpu_percent'] = float(cpu_match.group(1))
        
        # Execution time
        exec_match = LOG_PATTERNS['execution_time'].search(line)
        if exec_match:
            value = float(exec_match.group(1))
            unit = exec_match.group(2).lower()
            # Convert to milliseconds
            if unit in ['s', 'sec', 'seconds', 'second']:
                value *= 1000
            elif unit in ['minutes', 'minute']:
                value *= 60000
            entry['execution_time_ms'] = value
            self.statistics['execution_events'] += 1
        
        # Coverage
        coverage_match = LOG_PATTERNS['coverage'].search(line)
        if coverage_match:
            entry['coverage_percent'] = float(coverage_match.group(1))
        
        # Crashes
        if LOG_PATTERNS['crash'].search(line):
            entry['type'] = 'crash'
            entry['crash_info'] = self._extract_crash_info(line)
            self.statistics['crash_events'] += 1
        
        # Vulnerabilities
        if LOG_PATTERNS['vulnerability'].search(line):
            entry['type'] = 'vulnerability'
            entry['vulnerability_info'] = self._extract_vulnerability_info(line)
        
        # LLM interactions
        if any(term in line_lower for term in ['llm', 'openai', 'anthropic', 'ollama', 'gpt', 'claude']):
            entry['type'] = 'llm_interaction'
            entry['llm_info'] = self._extract_llm_info(line)
            self.statistics['llm_events'] += 1
    
    def _extract_llm_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract LLM-specific data from log entry"""
        llm_data = {}
        
        # Common LLM fields
        for field in ['model', 'provider', 'tokens', 'cost', 'prompt', 'response']:
            if field in data:
                llm_data[field] = data[field]
        
        # Token extraction
        for token_field in ['prompt_tokens', 'completion_tokens', 'total_tokens']:
            if token_field in data:
                llm_data[token_field] = data[token_field]
        
        return llm_data
    
    def _extract_crash_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract crash-specific data from log entry"""
        crash_data = {}
        
        # Common crash fields
        for field in ['signal', 'exit_code', 'stack_trace', 'address', 'instruction']:
            if field in data:
                crash_data[field] = data[field]
        
        return crash_data
    
    def _extract_crash_info(self, line: str) -> Dict[str, str]:
        """Extract crash information from log line"""
        crash_info = {'raw_line': line}
        
        # Extract signal information
        signal_pattern = r'signal\s*(\d+|SIG\w+)'
        signal_match = re.search(signal_pattern, line, re.IGNORECASE)
        if signal_match:
            crash_info['signal'] = signal_match.group(1)
        
        # Extract memory address
        addr_pattern = r'0x[0-9a-fA-F]+'
        addr_matches = re.findall(addr_pattern, line)
        if addr_matches:
            crash_info['addresses'] = addr_matches
        
        return crash_info
    
    def _extract_vulnerability_info(self, line: str) -> Dict[str, str]:
        """Extract vulnerability information from log line"""
        vuln_info = {'raw_line': line}
        
        # Extract CVE ID
        cve_pattern = r'CVE-\d{4}-\d+'
        cve_match = re.search(cve_pattern, line, re.IGNORECASE)
        if cve_match:
            vuln_info['cve_id'] = cve_match.group(0).upper()
        
        # Extract vulnerability type
        vuln_types = {
            'buffer overflow': 'buffer_overflow',
            'use after free': 'use_after_free',
            'null pointer': 'null_pointer_dereference',
            'sql injection': 'sql_injection'
        }
        
        line_lower = line.lower()
        for vuln_text, vuln_type in vuln_types.items():
            if vuln_text in line_lower:
                vuln_info['type'] = vuln_type
                break
        
        return vuln_info
    
    def _extract_llm_info(self, line: str) -> Dict[str, str]:
        """Extract LLM information from log line"""
        llm_info = {'raw_line': line}
        
        # Extract model name
        model_patterns = [
            r'(?:gpt-[34](?:\.\d+)?(?:-turbo)?)',
            r'(?:claude-[23](?:-\w+)?)',
            r'(?:llama-?\d+)',
            r'(?:text-davinci-\d+)'
        ]
        
        for pattern in model_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                llm_info['model'] = match.group(0)
                break
        
        # Extract token count
        token_pattern = r'tokens?[:\s]*(\d+)'
        token_match = re.search(token_pattern, line, re.IGNORECASE)
        if token_match:
            llm_info['tokens'] = int(token_match.group(1))
        
        # Extract cost
        cost_pattern = r'\$(\d+(?:\.\d+)?)'
        cost_match = re.search(cost_pattern, line)
        if cost_match:
            llm_info['cost'] = float(cost_match.group(1))
        
        return llm_info

class AFLParser:
    """American Fuzzy Lop log parser"""
    
    def parse(self, file_handle) -> List[Dict[str, Any]]:
        """Parse AFL fuzzer output"""
        entries = []
        current_stats = {}
        
        for line_num, line in enumerate(file_handle, 1):
            line = line.strip()
            
            # AFL status screen parsing
            if 'american fuzzy lop' in line.lower():
                entries.append({
                    'type': 'afl_startup',
                    'line_number': line_num,
                    'message': line
                })
            
            # Parse stats
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                
                # Convert numeric values
                if value.isdigit():
                    current_stats[key] = int(value)
                elif re.match(r'^\d+\.\d+$', value):
                    current_stats[key] = float(value)
                else:
                    current_stats[key] = value
            
            # Crashes and hangs
            if 'saved crash' in line.lower():
                entries.append({
                    'type': 'crash_found',
                    'line_number': line_num,
                    'message': line,
                    'fuzzer': 'afl'
                })
            
            if 'saved hang' in line.lower():
                entries.append({
                    'type': 'hang_found',
                    'line_number': line_num,
                    'message': line,
                    'fuzzer': 'afl'
                })
        
        # Add final stats
        if current_stats:
            entries.append({
                'type': 'afl_stats',
                'stats': current_stats
            })
        
        return entries

class LibFuzzerParser:
    """LibFuzzer log parser"""
    
    def parse(self, file_handle) -> List[Dict[str, Any]]:
        """Parse LibFuzzer output"""
        entries = []
        
        for line_num, line in enumerate(file_handle, 1):
            line = line.strip()
            
            # LibFuzzer execution stats
            if line.startswith('#'):
                match = re.match(r'#(\d+)\s+INITED.*exec/s:\s*(\d+)', line)
                if match:
                    entries.append({
                        'type': 'execution_stats',
                        'line_number': line_num,
                        'iterations': int(match.group(1)),
                        'exec_per_sec': int(match.group(2)),
                        'fuzzer': 'libfuzzer'
                    })
            
            # Crashes
            if 'crash' in line.lower() or 'asan' in line.lower():
                entries.append({
                    'type': 'crash_found',
                    'line_number': line_num,
                    'message': line,
                    'fuzzer': 'libfuzzer'
                })
            
            # Memory leaks
            if 'leak' in line.lower():
                entries.append({
                    'type': 'leak_found',
                    'line_number': line_num,
                    'message': line,
                    'fuzzer': 'libfuzzer'
                })
        
        return entries

class HonggFuzzParser:
    """Honggfuzz log parser"""
    
    def parse(self, file_handle) -> List[Dict[str, Any]]:
        """Parse Honggfuzz output"""
        entries = []
        
        for line_num, line in enumerate(file_handle, 1):
            line = line.strip()
            
            # Honggfuzz stats
            if 'Iterations:' in line:
                match = re.search(r'Iterations:\s*(\d+).*Speed:\s*(\d+)', line)
                if match:
                    entries.append({
                        'type': 'execution_stats',
                        'line_number': line_num,
                        'iterations': int(match.group(1)),
                        'speed': int(match.group(2)),
                        'fuzzer': 'honggfuzz'
                    })
            
            # Crashes
            if 'crash' in line.lower() or 'unique' in line.lower():
                entries.append({
                    'type': 'crash_found',
                    'line_number': line_num,
                    'message': line,
                    'fuzzer': 'honggfuzz'
                })
        
        return entries

class CIFuzzParser:
    """CI Fuzz specific log parser"""
    
    def parse(self, file_handle) -> List[Dict[str, Any]]:
        """Parse CI Fuzz output"""
        entries = []
        
        for line_num, line in enumerate(file_handle, 1):
            line = line.strip()
            
            # Fuzz target execution
            if 'running fuzz test' in line.lower():
                entries.append({
                    'type': 'fuzz_test_start',
                    'line_number': line_num,
                    'message': line
                })
            
            # Build/compilation
            if 'building' in line.lower() or 'compiling' in line.lower():
                entries.append({
                    'type': 'build_event',
                    'line_number': line_num,
                    'message': line
                })
            
            # LLM interactions
            if any(term in line.lower() for term in ['generating', 'llm', 'ai']):
                entries.append({
                    'type': 'llm_interaction',
                    'line_number': line_num,
                    'message': line
                })
            
            # Findings
            if 'finding' in line.lower() or 'vulnerability' in line.lower():
                entries.append({
                    'type': 'finding',
                    'line_number': line_num,
                    'message': line
                })
        
        return entries

class LLMParser:
    """LLM API interaction parser"""
    
    def parse(self, file_handle) -> List[Dict[str, Any]]:
        """Parse LLM-related logs"""
        entries = []
        
        for line_num, line in enumerate(file_handle, 1):
            line = line.strip()
            
            # API calls
            if any(api in line.lower() for api in ['openai', 'anthropic', 'api.openai', 'api.anthropic']):
                entries.append({
                    'type': 'api_call',
                    'line_number': line_num,
                    'message': line
                })
            
            # Token usage
            token_match = re.search(r'tokens?[:\s]*(\d+)', line, re.IGNORECASE)
            if token_match:
                entries.append({
                    'type': 'token_usage',
                    'line_number': line_num,
                    'tokens': int(token_match.group(1)),
                    'message': line
                })
            
            # Costs
            cost_match = re.search(r'\$(\d+(?:\.\d+)?)', line)
            if cost_match:
                entries.append({
                    'type': 'cost_tracking',
                    'line_number': line_num,
                    'cost': float(cost_match.group(1)),
                    'message': line
                })
        
        return entries

class CompilationParser:
    """Compilation log parser"""
    
    def parse(self, file_handle) -> List[Dict[str, Any]]:
        """Parse compilation logs"""
        entries = []
        
        for line_num, line in enumerate(file_handle, 1):
            line = line.strip()
            
            # Compilation errors
            if 'error:' in line.lower():
                entries.append({
                    'type': 'compilation_error',
                    'line_number': line_num,
                    'message': line
                })
            
            # Warnings
            if 'warning:' in line.lower():
                entries.append({
                    'type': 'compilation_warning',
                    'line_number': line_num,
                    'message': line
                })
            
            # Success
            if any(term in line.lower() for term in ['successfully compiled', 'build successful']):
                entries.append({
                    'type': 'compilation_success',
                    'line_number': line_num,
                    'message': line
                })
        
        return entries

class CoverageParser:
    """Coverage data parser"""
    
    def parse(self, file_handle) -> List[Dict[str, Any]]:
        """Parse coverage logs"""
        entries = []
        
        for line_num, line in enumerate(file_handle, 1):
            line = line.strip()
            
            # Coverage percentages
            coverage_match = re.search(r'coverage[:\s]*(\d+(?:\.\d+)?)%', line, re.IGNORECASE)
            if coverage_match:
                entries.append({
                    'type': 'coverage_data',
                    'line_number': line_num,
                    'coverage_percent': float(coverage_match.group(1)),
                    'message': line
                })
            
            # Line coverage
            line_match = re.search(r'lines?[:\s]*(\d+(?:\.\d+)?)%', line, re.IGNORECASE)
            if line_match:
                entries.append({
                    'type': 'line_coverage',
                    'line_number': line_num,
                    'line_coverage_percent': float(line_match.group(1)),
                    'message': line
                })
            
            # Branch coverage
            branch_match = re.search(r'branch(?:es)?[:\s]*(\d+(?:\.\d+)?)%', line, re.IGNORECASE)
            if branch_match:
                entries.append({
                    'type': 'branch_coverage',
                    'line_number': line_num,
                    'branch_coverage_percent': float(branch_match.group(1)),
                    'message': line
                })
        
        return entries

class CrashParser:
    """Crash dump and analysis parser"""
    
    def parse(self, file_handle) -> List[Dict[str, Any]]:
        """Parse crash dumps and analysis"""
        entries = []
        in_stack_trace = False
        current_crash = None
        
        for line_num, line in enumerate(file_handle, 1):
            line = line.strip()
            
            # Start of crash
            if any(term in line.lower() for term in ['segmentation fault', 'sigsegv', 'sigabrt', 'crash']):
                current_crash = {
                    'type': 'crash_start',
                    'line_number': line_num,
                    'signal': self._extract_signal(line),
                    'stack_trace': [],
                    'message': line
                }
                in_stack_trace = True
                entries.append(current_crash)
            
            # Stack trace lines
            elif in_stack_trace and (line.startswith('#') or '0x' in line):
                if current_crash:
                    current_crash['stack_trace'].append(line)
            
            # End of stack trace
            elif in_stack_trace and not line:
                in_stack_trace = False
                current_crash = None
            
            # ASAN/MSAN reports
            elif 'asan' in line.lower() or 'msan' in line.lower():
                entries.append({
                    'type': 'sanitizer_report',
                    'line_number': line_num,
                    'sanitizer': 'asan' if 'asan' in line.lower() else 'msan',
                    'message': line
                })
        
        return entries
    
    def _extract_signal(self, line: str) -> Optional[str]:
        """Extract signal information from crash line"""
        signal_patterns = [
            r'SIG(\w+)',
            r'signal\s*(\d+)',
            r'segmentation fault',
            r'abort'
        ]
        
        for pattern in signal_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1) if match.groups() else match.group(0)
        
        return None

class CodeAnalysisParser:
    """Advanced code analysis and extraction parser"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.CodeAnalysisParser")
    
    def analyze_source_file(self, file_path: Path, language: Optional[str] = None) -> Dict[str, Any]:
        """Analyze source code file"""
        if not file_path.exists():
            raise FileNotFoundError(f"Source file not found: {file_path}")
        
        # Detect language if not provided
        if not language:
            language = self._detect_language(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return {'error': str(e)}
        
        analysis = {
            'file_path': str(file_path),
            'language': language,
            'size_bytes': len(content.encode('utf-8')),
            'line_count': len(content.split('\n')),
            'functions': self._extract_functions(content, language),
            'imports': self._extract_imports(content, language),
            'complexity_metrics': self._calculate_complexity(content, language),
            'security_patterns': self._find_security_patterns(content, language),
            'code_quality': self._assess_code_quality(content, language)
        }
        
        return analysis
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension"""
        extension_map = {
            '.c': 'c',
            '.h': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.hpp': 'cpp',
            '.py': 'python',
            '.java': 'java',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.rs': 'rust',
            '.go': 'go',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.swift': 'swift',
            '.kt': 'kotlin'
        }
        
        return extension_map.get(file_path.suffix.lower(), 'unknown')
    
    def _extract_functions(self, content: str, language: str) -> List[Dict[str, Any]]:
        """Extract function definitions from code"""
        functions = []
        
        if language not in CODE_PATTERNS['function_def']:
            return functions
        
        pattern = CODE_PATTERNS['function_def'][language]
        matches = pattern.finditer(content)
        
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            
            if language in ['c', 'cpp']:
                return_type = match.group(1) or 'void'
                func_name = match.group(2)
            elif language == 'python':
                return_type = 'unknown'
                func_name = match.group(1)
            elif language == 'java':
                return_type = match.group(1)
                func_name = match.group(2)
            elif language == 'javascript':
                return_type = 'unknown'
                func_name = match.group(1)
            else:
                return_type = 'unknown'
                func_name = match.group(0)
            
            # Extract function body for analysis
            func_start = match.end()
            func_body = self._extract_function_body(content, func_start, language)
            
            functions.append({
                'name': func_name,
                'return_type': return_type,
                'line_number': line_num,
                'body_lines': len(func_body.split('\n')) if func_body else 0,
                'complexity': self._calculate_function_complexity(func_body),
                'parameters': self._extract_parameters(match.group(0), language)
            })
        
        return functions
    
    def _extract_function_body(self, content: str, start_pos: int, language: str) -> str:
        """Extract function body from start position"""
        if language in ['c', 'cpp', 'java', 'javascript']:
            # Find matching braces
            brace_count = 0
            i = start_pos
            
            while i < len(content):
                char = content[i]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        return content[start_pos:i+1]
                i += 1
        
        elif language == 'python':
            # Find end of indented block
            lines = content[start_pos:].split('\n')
            if not lines:
                return ""
            
            # Find base indentation
            first_line = lines[0]
            base_indent = len(first_line) - len(first_line.lstrip())
            
            body_lines = []
            for line in lines:
                if line.strip() == "":
                    body_lines.append(line)
                    continue
                
                line_indent = len(line) - len(line.lstrip())
                if line_indent > base_indent:
                    body_lines.append(line)
                else:
                    break
            
            return '\n'.join(body_lines)
        
        return ""
    
    def _extract_parameters(self, func_signature: str, language: str) -> List[str]:
        """Extract function parameters"""
        # Find parameter list in parentheses
        paren_start = func_signature.find('(')
        paren_end = func_signature.rfind(')')
        
        if paren_start == -1 or paren_end == -1:
            return []
        
        param_str = func_signature[paren_start+1:paren_end].strip()
        if not param_str or param_str == 'void':
            return []
        
        # Split by comma and clean up
        params = []
        for param in param_str.split(','):
            param = param.strip()
            if param:
                # Extract parameter name (last word usually)
                words = param.split()
                if words:
                    params.append(words[-1])
        
        return params
    
    def _extract_imports(self, content: str, language: str) -> List[str]:
        """Extract import/include statements"""
        imports = []
        
        if language not in CODE_PATTERNS['include_import']:
            return imports
        
        pattern = CODE_PATTERNS['include_import'][language]
        matches = pattern.finditer(content)
        
        for match in matches:
            if language in ['c', 'cpp']:
                imports.append(match.group(1))
            elif language == 'python':
                imports.append(match.group(1) or match.group(2))
            elif language == 'java':
                imports.append(match.group(1))
            elif language == 'javascript':
                imports.append(match.group(1) or match.group(2))
        
        return list(set(imports))  # Remove duplicates
    
    def _calculate_complexity(self, content: str, language: str) -> Dict[str, int]:
        """Calculate code complexity metrics"""
        metrics = {
            'cyclomatic_complexity': 1,  # Base complexity
            'nesting_depth': 0,
            'cognitive_complexity': 0
        }
        
        # Count decision points for cyclomatic complexity
        decision_patterns = [
            r'\bif\b', r'\belse\b', r'\belif\b', r'\bwhile\b', r'\bfor\b',
            r'\bswitch\b', r'\bcase\b', r'\bcatch\b', r'\&\&', r'\|\|', r'\?'
        ]
        
        for pattern in decision_patterns:
            metrics['cyclomatic_complexity'] += len(re.findall(pattern, content))
        
        # Calculate nesting depth
        if language in ['c', 'cpp', 'java', 'javascript']:
            max_depth = 0
            current_depth = 0
            
            for char in content:
                if char == '{':
                    current_depth += 1
                    max_depth = max(max_depth, current_depth)
                elif char == '}':
                    current_depth = max(0, current_depth - 1)
            
            metrics['nesting_depth'] = max_depth
        
        elif language == 'python':
            lines = content.split('\n')
            max_indent = 0
            
            for line in lines:
                if line.strip():
                    indent = len(line) - len(line.lstrip())
                    max_indent = max(max_indent, indent)
            
            metrics['nesting_depth'] = max_indent // 4  # Assuming 4-space indentation
        
        return metrics
    
    def _calculate_function_complexity(self, func_body: str) -> int:
        """Calculate complexity for a single function"""
        if not func_body:
            return 1
        
        complexity = 1
        decision_patterns = [
            r'\bif\b', r'\belse\b', r'\belif\b', r'\bwhile\b', r'\bfor\b',
            r'\bswitch\b', r'\bcase\b', r'\&\&', r'\|\|', r'\?'
        ]
        
        for pattern in decision_patterns:
            complexity += len(re.findall(pattern, func_body))
        
        return complexity
    
    def _find_security_patterns(self, content: str, language: str) -> List[Dict[str, Any]]:
        """Find potential security issues in code"""
        security_issues = []
        
        # Language-specific security patterns
        patterns = {
            'c': {
                'buffer_overflow': [
                    r'\bstrcpy\s*\(',
                    r'\bstrcat\s*\(',
                    r'\bsprintf\s*\(',
                    r'\bgets\s*\('
                ],
                'memory_leak': [
                    r'\bmalloc\s*\(',
                    r'\bcalloc\s*\(',
                    r'\brealloc\s*\('
                ]
            },
            'python': {
                'code_injection': [
                    r'\beval\s*\(',
                    r'\bexec\s*\('
                ],
                'deserialization': [
                    r'pickle\.loads',
                    r'yaml\.load\s*\('
                ]
            },
            'java': {
                'sql_injection': [
                    r'Statement\.execute\s*\(',
                    r'createStatement\s*\('
                ],
                'deserialization': [
                    r'ObjectInputStream',
                    r'readObject\s*\('
                ]
            }
        }
        
        if language in patterns:
            for category, pattern_list in patterns[language].items():
                for pattern in pattern_list:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE))
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        security_issues.append({
                            'category': category,
                            'pattern': pattern,
                            'line_number': line_num,
                            'match': match.group(0),
                            'context': self._get_line_context(content, line_num)
                        })
        
        return security_issues
    
    def _get_line_context(self, content: str, line_num: int, context_lines: int = 2) -> List[str]:
        """Get context lines around a specific line number"""
        lines = content.split('\n')
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return lines[start:end]
    
    def _assess_code_quality(self, content: str, language: str) -> Dict[str, Any]:
        """Assess overall code quality"""
        lines = content.split('\n')
        total_lines = len(lines)
        code_lines = len([line for line in lines if line.strip()])
        comment_lines = len([line for line in lines if line.strip().startswith(('#', '//', '/*'))])
        
        quality = {
            'total_lines': total_lines,
            'code_lines': code_lines,
            'comment_lines': comment_lines,
            'comment_ratio': comment_lines / max(code_lines, 1),
            'average_line_length': sum(len(line) for line in lines) / max(total_lines, 1),
            'long_lines': len([line for line in lines if len(line) > 120]),
            'empty_lines': total_lines - code_lines - comment_lines,
            'quality_score': 0.0
        }
        
        # Calculate quality score (0-10)
        score = 10.0
        
        # Penalize long lines
        if quality['long_lines'] > total_lines * 0.1:
            score -= 1.0
        
        # Reward good commenting
        if quality['comment_ratio'] > 0.2:
            score += 0.5
        elif quality['comment_ratio'] < 0.05:
            score -= 1.0
        
        # Penalize very long or very short functions
        avg_line_length = quality['average_line_length']
        if avg_line_length > 100:
            score -= 0.5
        elif avg_line_length < 10:
            score -= 0.5
        
        quality['quality_score'] = max(0.0, min(10.0, score))
        
        return quality

class FileSystemMonitor:
    """Advanced file system monitoring with change detection"""
    
    def __init__(self, paths_to_monitor: List[str], callback: callable):
        self.paths_to_monitor = [Path(p) for p in paths_to_monitor]
        self.callback = callback
        self.observer = None
        self.is_monitoring = False
        self.logger = logging.getLogger(f"{__name__}.FileSystemMonitor")
        
        if HAS_WATCHDOG:
            self.event_handler = self._create_event_handler()
        else:
            self.logger.warning("Watchdog not available, falling back to polling")
    
    def _create_event_handler(self):
        """Create watchdog event handler"""
        class MonitorEventHandler(FileSystemEventHandler):
            def __init__(self, monitor):
                self.monitor = monitor
            
            def on_modified(self, event):
                if not event.is_directory:
                    self.monitor._handle_file_change('modified', event.src_path)
            
            def on_created(self, event):
                if not event.is_directory:
                    self.monitor._handle_file_change('created', event.src_path)
            
            def on_deleted(self, event):
                if not event.is_directory:
                    self.monitor._handle_file_change('deleted', event.src_path)
        
        return MonitorEventHandler(self)
    
    def start_monitoring(self):
        """Start file system monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        
        if HAS_WATCHDOG:
            self.observer = Observer()
            
            for path in self.paths_to_monitor:
                if path.exists():
                    self.observer.schedule(self.event_handler, str(path), recursive=True)
                    self.logger.info(f"Monitoring path: {path}")
            
            self.observer.start()
        else:
            # Fallback to polling
            self.polling_thread = threading.Thread(target=self._polling_monitor, daemon=True)
            self.polling_thread.start()
    
    def stop_monitoring(self):
        """Stop file system monitoring"""
        self.is_monitoring = False
        
        if HAS_WATCHDOG and self.observer:
            self.observer.stop()
            self.observer.join()
    
    def _handle_file_change(self, event_type: str, file_path: str):
        """Handle file system change event"""
        try:
            self.callback(event_type, file_path)
        except Exception as e:
            self.logger.error(f"Error handling file change {event_type} for {file_path}: {e}")
    
    def _polling_monitor(self):
        """Fallback polling-based monitoring"""
        file_states = {}
        
        # Initialize file states
        for path in self.paths_to_monitor:
            if path.exists():
                for file_path in path.rglob('*'):
                    if file_path.is_file():
                        try:
                            file_states[str(file_path)] = file_path.stat().st_mtime
                        except OSError:
                            pass
        
        while self.is_monitoring:
            try:
                current_states = {}
                
                # Check all files
                for path in self.paths_to_monitor:
                    if path.exists():
                        for file_path in path.rglob('*'):
                            if file_path.is_file():
                                try:
                                    current_states[str(file_path)] = file_path.stat().st_mtime
                                except OSError:
                                    continue
                
                # Detect changes
                for file_path, mtime in current_states.items():
                    if file_path not in file_states:
                        # New file
                        self._handle_file_change('created', file_path)
                    elif file_states[file_path] != mtime:
                        # Modified file
                        self._handle_file_change('modified', file_path)
                
                # Detect deletions
                for file_path in file_states:
                    if file_path not in current_states:
                        self._handle_file_change('deleted', file_path)
                
                file_states = current_states
                time.sleep(5)  # Poll every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Polling monitor error: {e}")
                time.sleep(5)

class ProcessMonitor:
    """Advanced process monitoring with comprehensive metrics"""
    
    def __init__(self, session_manager: ConcurrentSessionManager, data_manager: AdvancedTextDataManager):
        self.session_manager = session_manager
        self.data_manager = data_manager
        self.logger = logging.getLogger(f"{__name__}.ProcessMonitor")
        self.monitoring = False
        self.monitor_thread = None
        
        # Initialize analyzers
        self.hallucination_detector = AdvancedHallucinationDetector()
        self.code_analyzer = ComprehensiveCodeQualityAnalyzer()
        self.vuln_analyzer = IntelligentVulnerabilityAnalyzer()
        self.performance_analyzer = PerformanceAnalyzer()
        self.log_parser = AdvancedLogParser()
        self.code_parser = CodeAnalysisParser()
        
        # LLM provider manager
        self.llm_manager = LLMProviderManager()
        
        # File system monitoring
        self.fs_monitors: Dict[str, FileSystemMonitor] = {}
    
    def start_monitoring(self):
        """Start comprehensive process monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("🚀 Process monitoring started")
    
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        
        # Stop file system monitors
        for monitor in self.fs_monitors.values():
            monitor.stop_monitoring()
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        
        self.logger.info("⏹️ Process monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        scan_count = 0
        last_cleanup = time.time()
        
        while self.monitoring:
            try:
                scan_count += 1
                current_time = time.time()
                
                # Scan for new CI Fuzz Spark processes
                new_sessions = self._scan_for_spark_processes()
                
                # Start monitoring new sessions
                for session in new_sessions:
                    if self.session_manager.add_session(session):
                        self._start_session_monitoring(session)
                        self.logger.info(f"🔍 Started monitoring session: {session.session_id}")
                
                # Periodic maintenance
                if current_time - last_cleanup > 300:  # Every 5 minutes
                    self._perform_maintenance()
                    last_cleanup = current_time
                
                # Log status
                if scan_count % 20 == 0:  # Every minute
                    active_count = self.session_manager.get_session_count()
                    self.logger.info(f"📊 Status: {active_count} active sessions, scan #{scan_count}")
                
                time.sleep(3)  # Main loop interval
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(10)
    
    def _scan_for_spark_processes(self) -> List[CIFuzzSparkSession]:
        """Scan for CI Fuzz Spark processes with enhanced detection"""
        new_sessions = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd', 'create_time', 'status', 'ppid']):
                try:
                    info = proc.info
                    if not info['cmdline'] or info['status'] == psutil.STATUS_ZOMBIE:
                        continue
                    
                    cmdline = ' '.join(info['cmdline'])
                    process_name = info['name'].lower()
                    
                    # Enhanced detection using pre-compiled patterns
                    is_spark_process = any(pattern.search(cmdline) for pattern in SPARK_PATTERNS)
                    
                    # Additional checks for process name
                    if not is_spark_process:
                        spark_keywords = ['cifuzz', 'spark', 'ai-fuzz', 'llm-fuzz']
                        is_spark_process = any(keyword in process_name for keyword in spark_keywords)
                    
                    # Check for Docker containers running CI Fuzz
                    if not is_spark_process and HAS_DOCKER:
                        is_spark_process = self._check_docker_containers(info['pid'])
                    
                    if is_spark_process:
                        pid = info['pid']
                        
                        # Skip if already monitored
                        if any(session.pid == pid for session in self.session_manager.active_sessions.values()):
                            continue
                        
                        working_dir = info['cwd'] or os.getcwd()
                        project_path = self._extract_project_path(cmdline, working_dir)
                        
                        # Comprehensive project analysis
                        project_analysis = self._analyze_project_comprehensive(project_path)
                        
                        # Enhanced git information
                        git_info = self._get_comprehensive_git_info(project_path)
                        
                        # Advanced LLM configuration detection
                        llm_config = self._detect_comprehensive_llm_config(cmdline, working_dir, info)
                        
                        # CI/CD context detection
                        ci_context = self._detect_ci_context()
                        
                        # Create comprehensive session
                        session = CIFuzzSparkSession(
                            session_id=f"spark_{pid}_{int(time.time() * 1000)}_{safe_get_username()}_{uuid.uuid4().hex[:8]}",
                            pid=pid,
                            start_time=datetime.fromtimestamp(info['create_time']),
                            command_line=cmdline,
                            working_directory=working_dir,
                            process_name=info['name'],
                            parent_pid=info.get('ppid'),
                            project_analysis=project_analysis,
                            llm_provider=LLMProvider(llm_config.get('provider', 'unknown')),
                            llm_model=llm_config.get('model', 'unknown'),
                            llm_endpoint=llm_config.get('endpoint', ''),
                            llm_api_key_hash=llm_config.get('api_key_hash'),
                            llm_configuration=llm_config,
                            ci_pipeline_id=ci_context.get('pipeline_id'),
                            ci_provider=ci_context.get('provider'),
                            ci_job_id=ci_context.get('job_id'),
                            ci_build_number=ci_context.get('build_number'),
                            status=SessionStatus.INITIALIZING
                        )
                        
                        new_sessions.append(session)
                        self.logger.info(f"🔍 Detected CI Fuzz Spark session: {session.session_id} (PID: {pid})")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    self.logger.warning(f"Error processing process: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Error scanning for processes: {e}")
        
        return new_sessions
    
    def _check_docker_containers(self, host_pid: int) -> bool:
        """Check if process is running in a Docker container with CI Fuzz"""
        if not HAS_DOCKER:
            return False
        
        try:
            client = docker.from_env()
            containers = client.containers.list()
            
            for container in containers:
                try:
                    # Check if container has CI Fuzz related environment variables or commands
                    env_vars = container.attrs.get('Config', {}).get('Env', [])
                    cmd = container.attrs.get('Config', {}).get('Cmd', [])
                    
                    env_str = ' '.join(env_vars).lower()
                    cmd_str = ' '.join(cmd).lower() if cmd else ''
                    
                    if any(term in env_str or term in cmd_str for term in ['cifuzz', 'spark', 'llm-fuzz']):
                        return True
                        
                except Exception:
                    continue
        
        except Exception as e:
            self.logger.debug(f"Docker check failed: {e}")
        
        return False
    
    def _analyze_project_comprehensive(self, project_path: str) -> Optional[object]:
        """Comprehensive project analysis with advanced metrics"""
        from ..core.models import ProjectAnalysis
        
        try:
            project_dir = Path(project_path)
            if not project_dir.exists():
                return None
            
            analysis = ProjectAnalysis(
                analysis_id=f"proj_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}",
                project_path=project_path,
                analysis_timestamp=datetime.now().isoformat()
            )
            
            # Basic project information
            analysis.project_name = project_dir.name
            
            # Detect languages and build systems
            lang_info = self._detect_languages_and_build_systems(project_dir)
            analysis.primary_language = lang_info['primary_language']
            analysis.supported_languages = lang_info['supported_languages']
            analysis.build_system = lang_info['build_system']
            analysis.build_files = lang_info['build_files']
            
            # Size and complexity analysis
            size_info = self._analyze_project_size(project_dir)
            analysis.total_lines_of_code = size_info['total_loc']
            analysis.total_files = size_info['total_files']
            analysis.total_directories = size_info['total_directories']
            analysis.project_complexity_score = size_info['complexity_score']
            
            # Dependency analysis
            deps_info = self._analyze_dependencies_comprehensive(project_dir)
            analysis.dependencies = deps_info['dependencies']
            analysis.dev_dependencies = deps_info['dev_dependencies']
            
            # Testing infrastructure
            test_info = self._analyze_testing_infrastructure(project_dir)
            analysis.existing_tests_count = test_info['test_count']
            analysis.test_frameworks = test_info['frameworks']
            analysis.test_coverage_percentage = test_info['coverage_estimate']
            
            # Security analysis
            security_info = self._analyze_security_features(project_dir)
            analysis.security_annotations_found = security_info['annotations_count']
            analysis.security_frameworks = security_info['frameworks']
            analysis.potential_security_hotspots = security_info['hotspots']
            
            # CI/CD analysis
            ci_info = self._analyze_ci_cd_configuration(project_dir)
            analysis.ci_config_files = ci_info['config_files']
            analysis.ci_providers = ci_info['providers']
            analysis.deployment_configs = ci_info['deployment_configs']
            
            # Code quality assessment
            quality_info = self._assess_project_quality(project_dir, analysis)
            analysis.code_quality_score = quality_info['quality_score']
            analysis.maintainability_score = quality_info['maintainability_score']
            analysis.technical_debt_ratio = quality_info['technical_debt_ratio']
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Project analysis failed for {project_path}: {e}")
            return None
    
    def _detect_languages_and_build_systems(self, project_dir: Path) -> Dict[str, Any]:
        """Advanced language and build system detection"""
        # Build system detection
        build_systems = {
            'CMakeLists.txt': {'system': 'cmake', 'languages': ['c', 'cpp']},
            'Makefile': {'system': 'make', 'languages': ['c', 'cpp']},
            'pom.xml': {'system': 'maven', 'languages': ['java']},
            'build.gradle': {'system': 'gradle', 'languages': ['java', 'kotlin']},
            'package.json': {'system': 'npm', 'languages': ['javascript', 'typescript']},
            'Cargo.toml': {'system': 'cargo', 'languages': ['rust']},
            'go.mod': {'system': 'go', 'languages': ['go']},
            'setup.py': {'system': 'setuptools', 'languages': ['python']},
            'pyproject.toml': {'system': 'poetry', 'languages': ['python']},
            'requirements.txt': {'system': 'pip', 'languages': ['python']},
            'meson.build': {'system': 'meson', 'languages': ['c', 'cpp']},
            'BUILD.bazel': {'system': 'bazel', 'languages': ['multiple']},
        }
        
        detected_build_system = 'unknown'
        build_files = []
        detected_languages = set()
        
        # Check for build files
        for build_file, info in build_systems.items():
            if (project_dir / build_file).exists():
                detected_build_system = info['system']
                build_files.append(build_file)
                detected_languages.update(info['languages'])
        
        # File extension analysis for language detection
        extension_counts = defaultdict(int)
        for file_path in project_dir.rglob('*'):
            if file_path.is_file() and file_path.suffix:
                extension_counts[file_path.suffix.lower()] += 1
        
        # Map extensions to languages
        ext_to_lang = {
            '.c': 'c', '.h': 'c',
            '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
            '.java': 'java',
            '.py': 'python',
            '.js': 'javascript', '.ts': 'typescript',
            '.rs': 'rust',
            '.go': 'go',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.swift': 'swift',
            '.kt': 'kotlin'
        }
        
        for ext, count in extension_counts.items():
            if ext in ext_to_lang and count > 0:
                detected_languages.add(ext_to_lang[ext])
        
        # Determine primary language
        if detected_languages:
            # Count files for each language to determine primary
            lang_counts = defaultdict(int)
            for file_path in project_dir.rglob('*'):
                if file_path.is_file():
                    ext = file_path.suffix.lower()
                    if ext in ext_to_lang:
                        lang_counts[ext_to_lang[ext]] += 1
            
            primary_language = max(lang_counts.items(), key=lambda x: x[1])[0] if lang_counts else 'unknown'
        else:
            primary_language = 'unknown'
        
        return {
            'primary_language': primary_language,
            'supported_languages': list(detected_languages),
            'build_system': detected_build_system,
            'build_files': build_files
        }
    
    def _analyze_project_size(self, project_dir: Path) -> Dict[str, Any]:
        """Analyze project size and complexity"""
        total_files = 0
        total_directories = 0
        total_loc = 0
        complexity_factors = []
        
        code_extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.java', '.py', 
                          '.js', '.ts', '.rs', '.go', '.cs', '.php', '.rb', '.swift', '.kt'}
        
        try:
            for item in project_dir.rglob('*'):
                if item.is_file():
                    total_files += 1
                    
                    # Count lines of code
                    if item.suffix.lower() in code_extensions:
                        try:
                            with open(item, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = sum(1 for line in f if line.strip())
                                total_loc += lines
                        except (IOError, OSError):
                            continue
                elif item.is_dir():
                    total_directories += 1
            
            # Calculate complexity factors
            complexity_factors = [
                total_files / 100,  # File count factor
                total_directories / 10,  # Directory structure factor
                total_loc / 10000,  # Code size factor
            ]
            
            complexity_score = min(sum(complexity_factors), 10.0)
            
        except Exception as e:
            self.logger.warning(f"Project size analysis failed: {e}")
            complexity_score = 0.0
        
        return {
            'total_files': total_files,
            'total_directories': total_directories,
            'total_loc': total_loc,
            'complexity_score': complexity_score
        }
    
    def _analyze_dependencies_comprehensive(self, project_dir: Path) -> Dict[str, List[str]]:
        """Comprehensive dependency analysis"""
        dependencies = []
        dev_dependencies = []
        
        # Dependency file parsers
        dep_parsers = {
            'requirements.txt': self._parse_requirements_txt,
            'package.json': self._parse_package_json,
            'pom.xml': self._parse_pom_xml,
            'Cargo.toml': self._parse_cargo_toml,
            'go.mod': self._parse_go_mod,
            'setup.py': self._parse_setup_py,
            'pyproject.toml': self._parse_pyproject_toml,
        }
        
        for dep_file, parser in dep_parsers.items():
            file_path = project_dir / dep_file
            if file_path.exists():
                try:
                    parsed_deps = parser(file_path)
                    dependencies.extend(parsed_deps.get('dependencies', []))
                    dev_dependencies.extend(parsed_deps.get('dev_dependencies', []))
                except Exception as e:
                    self.logger.warning(f"Failed to parse {dep_file}: {e}")
        
        return {
            'dependencies': list(set(dependencies))[:100],  # Limit and deduplicate
            'dev_dependencies': list(set(dev_dependencies))[:50]
        }
    
    def _parse_requirements_txt(self, file_path: Path) -> Dict[str, List[str]]:
        """Enhanced requirements.txt parser"""
        deps = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    # Handle different requirement formats
                    dep_name = re.split(r'[><=!]', line)[0].strip()
                    if dep_name:
                        deps.append(dep_name)
        
        return {'dependencies': deps, 'dev_dependencies': []}
    
    def _parse_package_json(self, file_path: Path) -> Dict[str, List[str]]:
        """Enhanced package.json parser"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        deps = list(data.get('dependencies', {}).keys())
        dev_deps = list(data.get('devDependencies', {}).keys())
        
        return {'dependencies': deps, 'dev_dependencies': dev_deps}
    
    def _parse_pom_xml(self, file_path: Path) -> Dict[str, List[str]]:
        """Enhanced Maven pom.xml parser"""
        deps = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Handle namespaces
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            if not any(ns.values()):
                ns = {'maven': root.tag.split('}')[0][1:] if '}' in root.tag else ''}
            
            for dependency in root.findall('.//dependency', ns) or root.findall('.//dependency'):
                group_id = dependency.find('./groupId', ns) or dependency.find('./groupId')
                artifact_id = dependency.find('./artifactId', ns) or dependency.find('./artifactId')
                
                if group_id is not None and artifact_id is not None:
                    dep_name = f"{group_id.text}:{artifact_id.text}"
                    deps.append(dep_name)
        
        except ET.ParseError as e:
            self.logger.warning(f"XML parse error in pom.xml: {e}")
        
        return {'dependencies': deps, 'dev_dependencies': []}
    
    def _parse_cargo_toml(self, file_path: Path) -> Dict[str, List[str]]:
        """Enhanced Cargo.toml parser"""
        deps = []
        dev_deps = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Simple TOML parsing for dependencies
            in_deps = False
            in_dev_deps = False
            
            for line in content.split('\n'):
                line = line.strip()
                
                if line == '[dependencies]':
                    in_deps = True
                    in_dev_deps = False
                elif line == '[dev-dependencies]':
                    in_deps = False
                    in_dev_deps = True
                elif line.startswith('[') and line != '[dependencies]' and line != '[dev-dependencies]':
                    in_deps = False
                    in_dev_deps = False
                elif '=' in line and (in_deps or in_dev_deps):
                    dep_name = line.split('=')[0].strip().strip('"')
                    if dep_name:
                        if in_deps:
                            deps.append(dep_name)
                        elif in_dev_deps:
                            dev_deps.append(dep_name)
        
        except Exception as e:
            self.logger.warning(f"Error parsing Cargo.toml: {e}")
        
        return {'dependencies': deps, 'dev_dependencies': dev_deps}
    
    def _parse_go_mod(self, file_path: Path) -> Dict[str, List[str]]:
        """Go mod file parser"""
        deps = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract require block
            require_match = re.search(r'require\s*\((.*?)\)', content, re.DOTALL)
            if require_match:
                require_block = require_match.group(1)
                for line in require_block.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('//'):
                        # Extract module name (first part before version)
                        parts = line.split()
                        if parts:
                            deps.append(parts[0])
        
        except Exception as e:
            self.logger.warning(f"Error parsing go.mod: {e}")
        
        return {'dependencies': deps, 'dev_dependencies': []}
    
    def _parse_setup_py(self, file_path: Path) -> Dict[str, List[str]]:
        """Python setup.py parser"""
        deps = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Look for install_requires
            install_requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if install_requires_match:
                requires_str = install_requires_match.group(1)
                # Extract quoted strings
                deps = re.findall(r'["\']([^"\'>=<]+)', requires_str)
        
        except Exception as e:
            self.logger.warning(f"Error parsing setup.py: {e}")
        
        return {'dependencies': deps, 'dev_dependencies': []}
    
    def _parse_pyproject_toml(self, file_path: Path) -> Dict[str, List[str]]:
        """Python pyproject.toml parser"""
        deps = []
        dev_deps = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Simple TOML parsing for Python dependencies
            # Look for dependencies array
            dep_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if dep_match:
                dep_str = dep_match.group(1)
                deps = re.findall(r'["\']([^"\'>=<]+)', dep_str)
            
            # Look for optional dependencies
            opt_deps_match = re.search(r'\[project\.optional-dependencies\](.*?)(?=\[|\Z)', content, re.DOTALL)
            if opt_deps_match:
                opt_deps_str = opt_deps_match.group(1)
                dev_deps = re.findall(r'["\']([^"\'>=<]+)', opt_deps_str)
        
        except Exception as e:
            self.logger.warning(f"Error parsing pyproject.toml: {e}")
        
        return {'dependencies': deps, 'dev_dependencies': dev_deps}
    
    def _analyze_testing_infrastructure(self, project_dir: Path) -> Dict[str, Any]:
        """Analyze existing testing infrastructure"""
        test_count = 0
        frameworks = []
        coverage_estimate = 0.0
        
        # Test file patterns
        test_patterns = [
            '*test*.py', '*Test*.java', '*test*.js', '*test*.ts',
            '*_test.go', '*_test.rs', 'test_*.py', 'Test*.java',
            '*spec*.js', '*Spec*.java', '*Tests.cs'
        ]
        
        # Framework indicators
        framework_indicators = {
            'pytest': ['pytest', 'conftest.py'],
            'unittest': ['unittest', 'TestCase'],
            'jest': ['jest', '.spec.js'],
            'junit': ['junit', '@Test'],
            'gtest': ['gtest', 'TEST('],
            'mocha': ['mocha', 'describe('],
            'rspec': ['rspec', 'describe '],
            'cargo test': ['#[test]'],
        }
        
        try:
            # Count test files
            for pattern in test_patterns:
                test_count += len(list(project_dir.rglob(pattern)))
            
            # Detect frameworks by scanning files
            for file_path in project_dir.rglob('*'):
                if file_path.is_file() and file_path.suffix in ['.py', '.java', '.js', '.ts', '.cpp', '.rs', '.go']:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for framework, indicators in framework_indicators.items():
                                if any(indicator in content for indicator in indicators):
                                    if framework not in frameworks:
                                        frameworks.append(framework)
                    except (IOError, OSError):
                        continue
            
            # Estimate coverage based on test-to-code ratio
            total_files = len(list(project_dir.rglob('*.py'))) + len(list(project_dir.rglob('*.java'))) + len(list(project_dir.rglob('*.js')))
            if total_files > 0:
                coverage_estimate = min((test_count / total_files) * 100, 100.0)
        
        except Exception as e:
            self.logger.warning(f"Testing infrastructure analysis failed: {e}")
        
        return {
            'test_count': test_count,
            'frameworks': frameworks,
            'coverage_estimate': coverage_estimate
        }
    
    def _analyze_security_features(self, project_dir: Path) -> Dict[str, Any]:
        """Analyze security features and annotations"""
        annotations_count = 0
        frameworks = []
        hotspots = []
        
        # Security keywords and frameworks
        security_keywords = [
            'security', 'authentication', 'authorization', 'encrypt', 'decrypt',
            'hash', 'crypto', 'ssl', 'tls', 'jwt', 'oauth', 'sanitize', 'validate'
        ]
        
        security_frameworks = {
            'spring-security': ['@PreAuthorize', '@Secured', 'SpringSecurity'],
            'django-security': ['django.contrib.auth', 'CSRF', 'XSS'],
            'express-security': ['helmet', 'express-rate-limit', 'cors'],
            'owasp': ['OWASP', 'owasp'],
            'bcrypt': ['bcrypt', 'hash'],
            'jwt': ['jsonwebtoken', 'jwt'],
        }
        
        try:
            for file_path in project_dir.rglob('*'):
                if file_path.is_file() and file_path.suffix in ['.py', '.java', '.js', '.ts', '.cpp', '.c', '.h']:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().lower()
                            
                            # Count security annotations/keywords
                            for keyword in security_keywords:
                                annotations_count += content.count(keyword)
                            
                            # Detect security frameworks
                            for framework, indicators in security_frameworks.items():
                                if any(indicator.lower() in content for indicator in indicators):
                                    if framework not in frameworks:
                                        frameworks.append(framework)
                            
                            # Identify potential security hotspots
                            hotspot_patterns = [
                                'password', 'secret', 'key', 'token', 'api_key',
                                'database', 'sql', 'query', 'input', 'user_input'
                            ]
                            
                            for pattern in hotspot_patterns:
                                if pattern in content:
                                    hotspots.append(str(file_path.relative_to(project_dir)))
                                    break  # One hotspot per file
                    
                    except (IOError, OSError):
                        continue
        
        except Exception as e:
            self.logger.warning(f"Security analysis failed: {e}")
        
        return {
            'annotations_count': min(annotations_count, 1000),  # Cap at reasonable number
            'frameworks': frameworks,
            'hotspots': hotspots[:20]  # Limit to top 20 hotspots
        }
    
    def _analyze_ci_cd_configuration(self, project_dir: Path) -> Dict[str, List[str]]:
        """Analyze CI/CD configuration files"""
        config_files = []
        providers = []
        deployment_configs = []
        
        # CI/CD file patterns and their providers
        ci_patterns = {
            '.github/workflows/*.yml': 'github-actions',
            '.github/workflows/*.yaml': 'github-actions',
            '.gitlab-ci.yml': 'gitlab-ci',
            '.travis.yml': 'travis-ci',
            'circle.yml': 'circleci',
            '.circleci/config.yml': 'circleci',
            'azure-pipelines.yml': 'azure-devops',
            'buildspec.yml': 'aws-codebuild',
            'cloudbuild.yaml': 'google-cloud-build',
            'Jenkinsfile': 'jenkins',
            '.buildkite/pipeline.yml': 'buildkite',
            'bitbucket-pipelines.yml': 'bitbucket-pipelines',
        }
        
        # Deployment configuration patterns
        deployment_patterns = [
            'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            'k8s/*.yml', 'kubernetes/*.yaml', 'deployment.yml',
            'terraform/*.tf', 'ansible/*.yml', 'helm/Chart.yaml'
        ]
        
        try:
            # Check for CI/CD files
            for pattern, provider in ci_patterns.items():
                if '*' in pattern:
                    # Handle wildcard patterns
                    parent_dir = project_dir / pattern.split('*')[0].rstrip('/')
                    if parent_dir.exists():
                        for file_path in parent_dir.glob('*' + pattern.split('*')[1]):
                            config_files.append(str(file_path.relative_to(project_dir)))
                            if provider not in providers:
                                providers.append(provider)
                else:
                    # Handle exact file patterns
                    file_path = project_dir / pattern
                    if file_path.exists():
                        config_files.append(pattern)
                        if provider not in providers:
                            providers.append(provider)
            
            # Check for deployment configurations
            for pattern in deployment_patterns:
                if '*' in pattern:
                    parent_dir = project_dir / pattern.split('*')[0].rstrip('/')
                    if parent_dir.exists():
                        for file_path in parent_dir.glob('*' + pattern.split('*')[1]):
                            deployment_configs.append(str(file_path.relative_to(project_dir)))
                else:
                    file_path = project_dir / pattern
                    if file_path.exists():
                        deployment_configs.append(pattern)
        
        except Exception as e:
            self.logger.warning(f"CI/CD analysis failed: {e}")
        
        return {
            'config_files': config_files,
            'providers': providers,
            'deployment_configs': deployment_configs
        }
    
    def _assess_project_quality(self, project_dir: Path, analysis) -> Dict[str, float]:
        """Assess overall project quality metrics"""
        quality_score = 5.0  # Base score
        maintainability_score = 5.0
        technical_debt_ratio = 0.0
        
        try:
            # Factors that increase quality
            if analysis.test_coverage_percentage > 80:
                quality_score += 1.0
            elif analysis.test_coverage_percentage > 50:
                quality_score += 0.5
            
            if len(analysis.ci_config_files) > 0:
                quality_score += 0.5
            
            if len(analysis.security_frameworks) > 0:
                quality_score += 0.5
            
            if analysis.build_system != 'unknown':
                quality_score += 0.5
            
            # Factors that decrease quality
            if analysis.project_complexity_score > 8:
                quality_score -= 1.0
                technical_debt_ratio += 0.2
            
            if len(analysis.potential_security_hotspots) > 10:
                quality_score -= 0.5
                technical_debt_ratio += 0.1
            
            if analysis.existing_tests_count == 0:
                quality_score -= 1.0
                technical_debt_ratio += 0.3
            
            # Maintainability factors
            maintainability_score = quality_score
            
            if len(analysis.dependencies) > 50:
                maintainability_score -= 0.5
                technical_debt_ratio += 0.1
            
            # Documentation factor (estimate based on README, docs, etc.)
            has_readme = any((project_dir / name).exists() 
                           for name in ['README.md', 'README.txt', 'README.rst'])
            if has_readme:
                maintainability_score += 0.5
            else:
                technical_debt_ratio += 0.1
        
        except Exception as e:
            self.logger.warning(f"Quality assessment failed: {e}")
        
        return {
            'quality_score': max(0.0, min(10.0, quality_score)),
            'maintainability_score': max(0.0, min(10.0, maintainability_score)),
            'technical_debt_ratio': min(1.0, technical_debt_ratio)
        }
    
    def _get_comprehensive_git_info(self, project_path: str) -> Dict[str, Any]:
        """Enhanced git repository information extraction"""
        git_info = {}
        original_cwd = os.getcwd()
        
        try:
            os.chdir(project_path)
            
            # Check if it's a git repository
            if not Path('.git').exists():
                return git_info
            
            # Get current commit hash
            result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                git_info['commit_hash'] = result.stdout.strip()
            
            # Get branch name
            result = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                git_info['branch'] = result.stdout.strip()
            
            # Get commit message
            result = subprocess.run(['git', 'log', '-1', '--pretty=%B'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                git_info['commit_message'] = result.stdout.strip()
            
            # Check if working tree is clean
            result = subprocess.run(['git', 'diff', '--quiet'], 
                                  capture_output=True, timeout=10)
            git_info['is_dirty'] = result.returncode != 0
            
            # Get remote URL
            result = subprocess.run(['git', 'config', '--get', 'remote.origin.url'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                git_info['remote_url'] = result.stdout.strip()
            
            # Get commit count
            result = subprocess.run(['git', 'rev-list', '--count', 'HEAD'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                git_info['commit_count'] = int(result.stdout.strip())
            
            # Get contributors
            result = subprocess.run(['git', 'shortlog', '-sn'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                contributors = []
                for line in result.stdout.strip().split('\n')[:5]:  # Top 5 contributors
                    if line.strip():
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            contributors.append({'commits': int(parts[0]), 'name': parts[1]})
                git_info['top_contributors'] = contributors
        
        except subprocess.TimeoutExpired:
            self.logger.warning("Git command timeout")
        except Exception as e:
            self.logger.warning(f"Git info extraction failed: {e}")
        finally:
            os.chdir(original_cwd)
        
        return git_info
    
    def _detect_comprehensive_llm_config(self, cmdline: str, working_dir: str, proc_info: Dict) -> Dict[str, Any]:
        """Enhanced LLM configuration detection"""
        config = {
            'provider': 'unknown',
            'model': 'unknown', 
            'endpoint': '',
            'api_key_hash': None
        }
        
        # Extract from command line arguments
        llm_arg_patterns = [
            (r'--(?:llm-)?model[=\s]+([^\s]+)', 'model'),
            (r'--(?:llm-)?provider[=\s]+([^\s]+)', 'provider'),
            (r'--(?:llm-)?endpoint[=\s]+([^\s]+)', 'endpoint'),
            (r'--ai-model[=\s]+([^\s]+)', 'model'),
        ]
        
        for pattern, config_key in llm_arg_patterns:
            match = re.search(pattern, cmdline, re.IGNORECASE)
            if match:
                config[config_key] = match.group(1)
        
        # Detect provider from command line indicators
        provider_indicators = {
            'openai': ['openai', 'gpt-', 'chatgpt'],
            'anthropic': ['anthropic', 'claude'],
            'ollama': ['ollama', 'localhost:11434'],
            'huggingface': ['huggingface', 'hf-'],
            'localai': ['localai', 'localhost:8080'],
        }
        
        cmdline_lower = cmdline.lower()
        for provider, indicators in provider_indicators.items():
            if any(indicator in cmdline_lower for indicator in indicators):
                config['provider'] = provider
                break
        
        # Check environment variables for API keys and hash them
        api_key_vars = {
            'OPENAI_API_KEY': 'openai',
            'ANTHROPIC_API_KEY': 'anthropic',
            'HUGGINGFACE_API_TOKEN': 'huggingface',
            'COHERE_API_KEY': 'cohere',
        }
        
        for env_var, provider in api_key_vars.items():
            api_key = os.getenv(env_var)
            if api_key:
                if config['provider'] == 'unknown':
                    config['provider'] = provider
                # Hash the API key for privacy
                config['api_key_hash'] = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        
        # Check configuration files in working directory
        config_files = [
            '.env', 'config.json', 'settings.yml', 'cifuzz.yml',
            '.cifuzz/config.yml', 'llm_config.json'
        ]
        
        for config_file in config_files:
            config_path = Path(working_dir) / config_file
            if config_path.exists():
                try:
                    self._parse_config_file(config_path, config)
                except Exception as e:
                    self.logger.debug(f"Error parsing config file {config_path}: {e}")
        
        # Fallback to detected LLM providers
        if config['provider'] == 'unknown':
            available_providers = list(self.llm_manager.providers.keys())
            if available_providers:
                config['provider'] = available_providers[0]  # Use first available
        
        return config
    
    def _parse_config_file(self, config_path: Path, config: Dict[str, Any]):
        """Parse configuration file for LLM settings"""
        try:
            if config_path.suffix in ['.yml', '.yaml']:
                with open(config_path, 'r') as f:
                    data = yaml.safe_load(f)
            elif config_path.suffix == '.json':
                with open(config_path, 'r') as f:
                    data = json.load(f)
            elif config_path.name == '.env':
                data = {}
                with open(config_path, 'r') as f:
                    for line in f:
                        if '=' in line and not line.startswith('#'):
                            key, value = line.strip().split('=', 1)
                            data[key] = value
            else:
                return
            
            # Extract LLM configuration
            llm_keys = ['llm', 'ai', 'model', 'provider']
            for key in llm_keys:
                if key in data:
                    llm_config = data[key]
                    if isinstance(llm_config, dict):
                        config.update({k: v for k, v in llm_config.items() if k in config})
                    elif isinstance(llm_config, str):
                        if key == 'model':
                            config['model'] = llm_config
                        elif key == 'provider':
                            config['provider'] = llm_config
        
        except Exception as e:
            self.logger.debug(f"Config file parsing error: {e}")
    
    def _detect_ci_context(self) -> Dict[str, Optional[str]]:
        """Detect CI/CD pipeline context from environment"""
        ci_context = {
            'pipeline_id': None,
            'provider': None,
            'job_id': None,
            'build_number': None
        }
        
        # CI/CD environment variable mappings
        ci_env_mappings = {
            'github': {
                'pipeline_id': 'GITHUB_RUN_ID',
                'provider': 'github-actions',
                'job_id': 'GITHUB_JOB',
                'build_number': 'GITHUB_RUN_NUMBER'
            },
            'gitlab': {
                'pipeline_id': 'CI_PIPELINE_ID',
                'provider': 'gitlab-ci',
                'job_id': 'CI_JOB_ID',
                'build_number': 'CI_PIPELINE_IID'
            },
            'jenkins': {
                'pipeline_id': 'BUILD_ID',
                'provider': 'jenkins',
                'job_id': 'JOB_NAME',
                'build_number': 'BUILD_NUMBER'
            },
            'azure': {
                'pipeline_id': 'BUILD_BUILDID',
                'provider': 'azure-devops',
                'job_id': 'AGENT_JOBNAME',
                'build_number': 'BUILD_BUILDNUMBER'
            },
            'circleci': {
                'pipeline_id': 'CIRCLE_WORKFLOW_ID',
                'provider': 'circleci',
                'job_id': 'CIRCLE_JOB',
                'build_number': 'CIRCLE_BUILD_NUM'
            },
            'travis': {
                'pipeline_id': 'TRAVIS_BUILD_ID',
                'provider': 'travis-ci',
                'job_id': 'TRAVIS_JOB_ID',
                'build_number': 'TRAVIS_BUILD_NUMBER'
            }
        }
        
        # Check environment variables
        for provider, env_vars in ci_env_mappings.items():
            if os.getenv(env_vars['pipeline_id']):
                ci_context['provider'] = env_vars['provider']
                ci_context['pipeline_id'] = os.getenv(env_vars['pipeline_id'])
                ci_context['job_id'] = os.getenv(env_vars['job_id'])
                ci_context['build_number'] = os.getenv(env_vars['build_number'])
                break
        
        return ci_context
    
    def _extract_project_path(self, cmdline: str, working_dir: str) -> str:
        """Enhanced project path extraction"""
        # Try to extract from command line arguments
        path_patterns = [
            r'--(?:project-)?(?:dir|path|root)[=\s]+([^\s]+)',
            r'--source[=\s]+([^\s]+)',
            r'-d[=\s]+([^\s]+)',
            r'--workspace[=\s]+([^\s]+)',
        ]
        
        for pattern in path_patterns:
            match = re.search(pattern, cmdline)
            if match:
                path = match.group(1)
                if Path(path).exists():
                    return path
        
        # Look for common project indicators in working directory
        project_indicators = [
            'CMakeLists.txt', 'Makefile', 'pom.xml', 'package.json',
            'Cargo.toml', 'go.mod', 'setup.py', '.git'
        ]
        
        current_dir = Path(working_dir)
        while current_dir != current_dir.parent:  # Walk up the directory tree
            if any((current_dir / indicator).exists() for indicator in project_indicators):
                return str(current_dir)
            current_dir = current_dir.parent
        
        return working_dir
    
    def _start_session_monitoring(self, session: CIFuzzSparkSession):
        """Start comprehensive monitoring for a session"""
        try:
            # Update session status
            session.status = SessionStatus.RUNNING
            self.data_manager.save_session(session)
            
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=self._monitor_session_comprehensive,
                args=(session,),
                daemon=True,
                name=f"SessionMonitor-{session.session_id}"
            )
            monitor_thread.start()
            
            # Setup file system monitoring for the session
            monitor_paths = [
                session.working_directory,
                session.project_analysis.project_path if session.project_analysis else session.working_directory
            ]
            
            fs_monitor = FileSystemMonitor(
                monitor_paths,
                lambda event_type, file_path: self._handle_file_change(session.session_id, event_type, file_path)
            )
            fs_monitor.start_monitoring()
            self.fs_monitors[session.session_id] = fs_monitor
            
        except Exception as e:
            self.logger.error(f"Error starting session monitoring: {e}")
            session.status = SessionStatus.FAILED
            session.error_message = str(e)
            self.data_manager.save_session(session)
    
    def _monitor_session_comprehensive(self, session: CIFuzzSparkSession):
        """Comprehensive session monitoring with all analyzers"""
        self.logger.info(f"🔍 Starting comprehensive monitoring for {session.session_id}")
        
        try:
            process = psutil.Process(session.pid)
            
            # Start individual monitoring components
            monitor_tasks = [
                threading.Thread(target=self._monitor_system_resources, args=(session, process), daemon=True),
                threading.Thread(target=self._monitor_llm_interactions, args=(session,), daemon=True),
                threading.Thread(target=self._monitor_output_logs, args=(session, process), daemon=True),
                threading.Thread(target=self._monitor_code_generation, args=(session,), daemon=True),
                threading.Thread(target=self._monitor_vulnerability_detection, args=(session,), daemon=True),
                threading.Thread(target=self._monitor_performance_metrics, args=(session,), daemon=True),
            ]
            
            # Start all monitoring tasks
            for task in monitor_tasks:
                task.start()
            
            # Main session monitoring loop
            last_update = time.time()
            
            while process.is_running() and session.status == SessionStatus.RUNNING:
                try:
                    current_time = time.time()
                    
                    # Update session metrics periodically
                    if current_time - last_update > 30:  # Every 30 seconds
                        self._update_session_metrics(session, process)
                        last_update = current_time
                    
                    time.sleep(5)  # Check every 5 seconds
                    
                except psutil.NoSuchProcess:
                    self.logger.info(f"Process {session.pid} no longer exists")
                    break
                except Exception as e:
                    self.logger.warning(f"Session monitoring error: {e}")
                    time.sleep(5)
            
            # Session completed
            session.status = SessionStatus.COMPLETED
            session.end_time = datetime.now()
            self._finalize_session_analysis(session)
            
        except psutil.NoSuchProcess:
            session.status = SessionStatus.FAILED
            session.error_message = "Process no longer exists"
        except Exception as e:
            session.status = SessionStatus.FAILED
            session.error_message = str(e)
            self.logger.error(f"Session monitoring failed: {e}")
        finally:
            # Cleanup
            self._cleanup_session_monitoring(session)
    
    def _monitor_system_resources(self, session: CIFuzzSparkSession, process: psutil.Process):
        """Monitor system resource usage"""
        while session.status == SessionStatus.RUNNING:
            try:
                # CPU and Memory
                cpu_percent = process.cpu_percent(interval=1)
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                
                # Network I/O
                try:
                    net_io = process.connections()
                    active_connections = len(net_io)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    active_connections = 0
                
                # File descriptors
                try:
                    fd_count = process.num_fds() if hasattr(process, 'num_fds') else 0
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    fd_count = 0
                
                # Update session metrics
                session.average_cpu_usage = (session.average_cpu_usage * 0.9) + (cpu_percent * 0.1)
                session.peak_cpu_usage = max(session.peak_cpu_usage, cpu_percent)
                session.peak_memory_usage_mb = max(session.peak_memory_usage_mb, memory_mb)
                
                # Save metrics
                from ..core.models import SystemMetrics
                
                metrics = SystemMetrics(
                    timestamp=datetime.now().isoformat(),
                    session_id=session.session_id,
                    cpu_percent=cpu_percent,
                    memory_total_gb=psutil.virtual_memory().total / (1024**3),
                    memory_used_gb=memory_mb / 1024,
                    memory_percent=psutil.virtual_memory().percent,
                    process_count=len(psutil.pids()),
                    thread_count=process.num_threads(),
                    file_descriptor_count=fd_count
                )
                
                self.data_manager.save_real_time_metric(
                    session.session_id,
                    "system_resources",
                    "comprehensive_metrics",
                    json.dumps(asdict(metrics)),
                    asdict(metrics)
                )
                
                time.sleep(5)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception as e:
                self.logger.warning(f"System resource monitoring error: {e}")
                time.sleep(5)
    
    def _monitor_llm_interactions(self, session: CIFuzzSparkSession):
        """Monitor LLM interactions with advanced analysis"""
        log_files_monitored = set()
        
        # Discover LLM log files
        log_search_paths = [
            Path(session.working_directory),
            Path(session.working_directory) / ".cifuzz",
            Path(session.working_directory) / "logs",
            Path.home() / ".ollama" / "logs",
            Path("/tmp") / "llm_logs",
        ]
        
        while session.status == SessionStatus.RUNNING:
            try:
                # Discover new log files
                for search_path in log_search_paths:
                    if search_path.exists():
                        for log_file in search_path.rglob("*.log"):
                            if str(log_file) not in log_files_monitored:
                                self._monitor_llm_log_file(log_file, session)
                                log_files_monitored.add(str(log_file))
                
                # Monitor LLM provider health
                self._check_llm_provider_health(session)
                
                time.sleep(10)
                
            except Exception as e:
                self.logger.warning(f"LLM interaction monitoring error: {e}")
                time.sleep(10)
    
    def _monitor_llm_log_file(self, log_file: Path, session: CIFuzzSparkSession):
        """Monitor individual LLM log file"""
        try:
            # Parse the log file
            parsed_log = self.log_parser.parse_file(log_file, 'llm')
            
            for entry in parsed_log.get('entries', []):
                if entry.get('type') == 'llm_interaction':
                    # Create LLM interaction record
                    interaction = LLMInteraction(
                        interaction_id=f"llm_{session.session_id}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}",
                        session_id=session.session_id,
                        timestamp=entry.get('timestamp', datetime.now().isoformat()),
                        llm_provider=session.llm_provider,
                        llm_model=entry.get('llm_info', {}).get('model', session.llm_model),
                        llm_endpoint=session.llm_endpoint,
                        prompt_type="detected_from_log",
                        prompt_text=entry.get('message', ''),
                        response_text=entry.get('response', ''),
                        prompt_tokens=entry.get('llm_info', {}).get('tokens', 0) // 2,
                        response_tokens=entry.get('llm_info', {}).get('tokens', 0) // 2,
                        total_tokens=entry.get('llm_info', {}).get('tokens', 0),
                        response_time_ms=0.0,
                        cost_estimate_usd=entry.get('llm_info', {}).get('cost', 0.0)
                    )
                    
                    # Analyze for hallucinations
                    hallucination_result = self.hallucination_detector.analyze(interaction)
                    interaction.hallucination_detected = hallucination_result.results.get('hallucination_detected', False)
                    interaction.hallucination_confidence = hallucination_result.results.get('confidence', 0.0)
                    
                    # Save interaction
                    self.data_manager.save_llm_interaction(interaction)
                    session.add_llm_interaction(interaction)
        
        except Exception as e:
            self.logger.warning(f"Error monitoring LLM log file {log_file}: {e}")
    
    def _check_llm_provider_health(self, session: CIFuzzSparkSession):
        """Check health of LLM providers"""
        try:
            provider_stats = self.llm_manager.get_usage_statistics()
            
            self.data_manager.save_real_time_metric(
                session.session_id,
                "llm_provider_health",
                "provider_statistics",
                json.dumps(provider_stats),
                provider_stats
            )
        
        except Exception as e:
            self.logger.warning(f"LLM provider health check failed: {e}")
    
    def _monitor_output_logs(self, session: CIFuzzSparkSession, process: psutil.Process):
        """Monitor output logs and parse for insights"""
        monitored_logs = set()
        
        while session.status == SessionStatus.RUNNING:
            try:
                # Find log files in working directory
                log_dirs = [
                    Path(session.working_directory),
                    Path(session.working_directory) / ".cifuzz",
                    Path(session.working_directory) / "build",
                    Path(session.working_directory) / "logs",
                ]
                
                for log_dir in log_dirs:
                    if log_dir.exists():
                        for log_file in log_dir.rglob("*.log"):
                            if str(log_file) not in monitored_logs:
                                self._parse_and_analyze_log(log_file, session)
                                monitored_logs.add(str(log_file))
                
                time.sleep(5)
                
            except Exception as e:
                self.logger.warning(f"Output log monitoring error: {e}")
                time.sleep(5)
    
    def _parse_and_analyze_log(self, log_file: Path, session: CIFuzzSparkSession):
        """Parse and analyze log file for insights"""
        try:
            # Detect log format and parse
            parsed_log = self.log_parser.parse_file(log_file)
            
            for entry in parsed_log.get('entries', []):
                entry_type = entry.get('type', 'unknown')
                
                if entry_type == 'crash_found':
                    self._handle_crash_detection(entry, session)
                elif entry_type == 'compilation_error':
                    self._handle_compilation_error(entry, session)
                elif entry_type == 'coverage_data':
                    self._handle_coverage_update(entry, session)
                elif entry_type == 'finding':
                    self._handle_security_finding(entry, session)
        
        except Exception as e:
            self.logger.warning(f"Log parsing error for {log_file}: {e}")
    
    def _handle_crash_detection(self, entry: Dict[str, Any], session: CIFuzzSparkSession):
        """Handle crash detection from logs"""
        try:
            # Analyze the crash
            crash_analysis = self.vuln_analyzer.analyze({
                'signature': entry.get('message', ''),
                'stack_trace': entry.get('crash_info', {}).get('raw_line', ''),
                'source_code': '',
                'memory_info': {}
            })
            
            # Create security findings from vulnerabilities
            for vuln in crash_analysis.results.get('vulnerabilities_found', []):
                self.data_manager.save_security_finding(vuln)
                session.add_security_finding(vuln)
            
            session.unique_crashes_found += 1
            self.data_manager.save_session(session)
        
        except Exception as e:
            self.logger.warning(f"Crash handling error: {e}")
    
    def _handle_compilation_error(self, entry: Dict[str, Any], session: CIFuzzSparkSession):
        """Handle compilation error from logs"""
        session.failed_compilations += 1
        
        self.data_manager.save_real_time_metric(
            session.session_id,
            "compilation",
            "error",
            entry.get('message', ''),
            {'line_number': entry.get('line_number', 0)}
        )
    
    def _handle_coverage_update(self, entry: Dict[str, Any], session: CIFuzzSparkSession):
        """Handle coverage data update"""
        coverage_percent = entry.get('coverage_percent', 0.0)
        session.overall_line_coverage = max(session.overall_line_coverage, coverage_percent)
        
        self.data_manager.save_real_time_metric(
            session.session_id,
            "coverage",
            "line_coverage",
            coverage_percent
        )
    
    def _handle_security_finding(self, entry: Dict[str, Any], session: CIFuzzSparkSession):
        """Handle security finding from logs"""
        finding = SecurityFinding(
            finding_id=f"finding_{session.session_id}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}",
            session_id=session.session_id,
            description=entry.get('message', ''),
            detection_method="log_analysis",
            confidence_score=0.6
        )
        
        self.data_manager.save_security_finding(finding)
        session.add_security_finding(finding)
    
    def _monitor_code_generation(self, session: CIFuzzSparkSession):
        """Monitor code generation and quality"""
        while session.status == SessionStatus.RUNNING:
            try:
                # Look for generated code files
                generated_dirs = [
                    Path(session.working_directory) / "fuzz_targets",
                    Path(session.working_directory) / "generated",
                    Path(session.working_directory) / ".cifuzz" / "build",
                ]
                
                for gen_dir in generated_dirs:
                    if gen_dir.exists():
                        for code_file in gen_dir.rglob("*"):
                            if code_file.is_file() and code_file.suffix in ['.c', '.cpp', '.java', '.py']:
                                self._analyze_generated_code(code_file, session)
                
                time.sleep(15)  # Check every 15 seconds
                
            except Exception as e:
                self.logger.warning(f"Code generation monitoring error: {e}")
                time.sleep(15)
    
    def _analyze_generated_code(self, code_file: Path, session: CIFuzzSparkSession):
        """Analyze generated code file"""
        try:
            # Parse and analyze the code
            code_analysis = self.code_parser.analyze_source_file(code_file)
            
            # Create fuzz driver metrics
            driver_metrics = FuzzDriverMetrics(
                driver_id=f"driver_{session.session_id}_{int(time.time() * 1000)}_{code_file.stem}",
                session_id=session.session_id,
                generation_timestamp=datetime.now().isoformat(),
                generation_method="llm_generated",
                llm_model_used=session.llm_model,
                source_code=code_analysis.get('content', ''),
                file_path=str(code_file),
                target_language=code_analysis.get('language', 'unknown')
            )
            
            # Populate code metrics
            if 'complexity_metrics' in code_analysis:
                driver_metrics.code_metrics.cyclomatic_complexity = code_analysis['complexity_metrics']['cyclomatic_complexity']
                driver_metrics.code_metrics.nesting_depth = code_analysis['complexity_metrics']['nesting_depth']
                driver_metrics.code_metrics.cognitive_complexity = code_analysis['complexity_metrics'].get('cognitive_complexity', 0)
            
            if 'code_quality' in code_analysis:
                quality = code_analysis['code_quality']
                driver_metrics.code_metrics.lines_of_code = quality.get('code_lines', 0)
                driver_metrics.code_metrics.lines_of_comments = quality.get('comment_lines', 0)
                driver_metrics.code_metrics.documentation_coverage = quality.get('comment_ratio', 0.0)
                driver_metrics.overall_quality_score = quality.get('quality_score', 0.0)
            
            if 'functions' in code_analysis:
                driver_metrics.code_metrics.function_count = len(code_analysis['functions'])
            
            # Analyze for security issues
            if 'security_patterns' in code_analysis:
                for security_issue in code_analysis['security_patterns']:
                    finding = SecurityFinding(
                        finding_id=f"sec_{driver_metrics.driver_id}_{security_issue['category']}_{security_issue['line_number']}",
                        session_id=session.session_id,
                        driver_id=driver_metrics.driver_id,
                        vulnerability_type=VulnerabilityType(security_issue['category']) if security_issue['category'] in [v.value for v in VulnerabilityType] else VulnerabilityType.UNKNOWN,
                        severity=SecuritySeverity.MEDIUM,
                        file_path=str(code_file),
                        line_number=security_issue['line_number'],
                        code_snippet=security_issue['match'],
                        description=f"Security pattern detected: {security_issue['category']}",
                        confidence_score=0.7,
                        detection_method="static_analysis"
                    )
                    driver_metrics.security_findings.append(finding)
                    self.data_manager.save_security_finding(finding)
            
            # Perform comprehensive code quality analysis
            quality_analysis = self.code_analyzer.analyze(driver_metrics)
            driver_metrics.overall_quality_score = quality_analysis.results.get('overall_score', 0.0)
            driver_metrics.maintainability_index = quality_analysis.results.get('metrics', {}).get('maintainability_index', 0.0)
            
            # Save driver metrics
            self.data_manager.save_fuzz_driver(driver_metrics)
            session.add_fuzz_driver(driver_metrics)
            
        except Exception as e:
            self.logger.warning(f"Generated code analysis error for {code_file}: {e}")
    
    def _monitor_vulnerability_detection(self, session: CIFuzzSparkSession):
        """Monitor vulnerability detection and analysis"""
        while session.status == SessionStatus.RUNNING:
            try:
                # Look for crash reports and ASAN output
                crash_dirs = [
                    Path(session.working_directory) / "crashes",
                    Path(session.working_directory) / ".cifuzz" / "findings",
                    Path(session.working_directory) / "build" / "crashes",
                ]
                
                for crash_dir in crash_dirs:
                    if crash_dir.exists():
                        for crash_file in crash_dir.rglob("*"):
                            if crash_file.is_file():
                                self._analyze_crash_file(crash_file, session)
                
                time.sleep(20)  # Check every 20 seconds
                
            except Exception as e:
                self.logger.warning(f"Vulnerability detection monitoring error: {e}")
                time.sleep(20)
    
    def _analyze_crash_file(self, crash_file: Path, session: CIFuzzSparkSession):
        """Analyze crash file for vulnerabilities"""
        try:
            # Parse crash file
            crash_log = self.log_parser.parse_file(crash_file, 'crash')
            
            for entry in crash_log.get('entries', []):
                if entry.get('type') == 'crash_start':
                    # Perform vulnerability analysis
                    crash_data = {
                        'signature': entry.get('message', ''),
                        'stack_trace': '\n'.join(entry.get('stack_trace', [])),
                        'signal': entry.get('signal', ''),
                        'memory_info': {'heap_corruption': 'heap' in entry.get('message', '').lower()}
                    }
                    
                    vuln_analysis = self.vuln_analyzer.analyze(crash_data)
                    
                    # Create security findings
                    for vuln in vuln_analysis.results.get('vulnerabilities_found', []):
                        vuln.file_path = str(crash_file)
                        self.data_manager.save_security_finding(vuln)
                        session.add_security_finding(vuln)
                        
                        # Update session vulnerability counts
                        if vuln.severity == SecuritySeverity.CRITICAL:
                            session.critical_vulnerabilities += 1
                        elif vuln.severity == SecuritySeverity.HIGH:
                            session.high_vulnerabilities += 1
                        elif vuln.severity == SecuritySeverity.MEDIUM:
                            session.medium_vulnerabilities += 1
                        elif vuln.severity == SecuritySeverity.LOW:
                            session.low_vulnerabilities += 1
        
        except Exception as e:
            self.logger.warning(f"Crash file analysis error for {crash_file}: {e}")
    
    def _monitor_performance_metrics(self, session: CIFuzzSparkSession):
        """Monitor performance metrics and trends"""
        while session.status == SessionStatus.RUNNING:
            try:
                # Analyze current performance
                performance_analysis = self.performance_analyzer.analyze(session)
                
                # Save performance metrics
                self.data_manager.save_real_time_metric(
                    session.session_id,
                    "performance_analysis",
                    "comprehensive_metrics",
                    json.dumps(performance_analysis.results),
                    performance_analysis.results
                )
                
                # Update session scores
                session.efficiency_score = performance_analysis.results.get('resource_efficiency', {}).get('overall_efficiency', 0.0)
                session.automation_score = min(session.fuzz_drivers_generated / 10.0, 1.0) if session.fuzz_drivers_generated > 0 else 0.0
                session.effectiveness_score = performance_analysis.results.get('throughput_analysis', {}).get('drivers_per_hour', 0.0) / 20.0
                session.overall_score = (session.efficiency_score + session.automation_score + session.effectiveness_score) / 3.0
                
                time.sleep(60)  # Analyze every minute
                
            except Exception as e:
                self.logger.warning(f"Performance monitoring error: {e}")
                time.sleep(60)
    
    def _update_session_metrics(self, session: CIFuzzSparkSession, process: psutil.Process):
        """Update session metrics periodically"""
        try:
            # Update duration
            session.calculate_duration()
            
            # Update process metrics
            session.average_cpu_usage = (session.average_cpu_usage * 0.95) + (process.cpu_percent() * 0.05)
            current_memory = process.memory_info().rss / (1024 * 1024)
            session.peak_memory_usage_mb = max(session.peak_memory_usage_mb, current_memory)
            
            # Save updated session
            self.data_manager.save_session(session)
            
        except Exception as e:
            self.logger.warning(f"Session metrics update error: {e}")
    
    def _finalize_session_analysis(self, session: CIFuzzSparkSession):
        """Perform final analysis when session completes"""
        try:
            self.logger.info(f"🔬 Finalizing analysis for session {session.session_id}")
            
            # Calculate final metrics
            session.calculate_duration()
            
            # Comprehensive performance analysis
            final_performance = self.performance_analyzer.analyze(session)
            
            # Generate comprehensive report
            self._generate_session_report(session, final_performance)
            
            # Update session status
            session.status = SessionStatus.COMPLETED
            self.data_manager.save_session(session)
            
            self.logger.info(f"✅ Session {session.session_id} analysis completed")
            
        except Exception as e:
            self.logger.error(f"Session finalization error: {e}")
            session.status = SessionStatus.FAILED
            session.error_message = f"Finalization failed: {e}"
            self.data_manager.save_session(session)
    
    def _generate_session_report(self, session: CIFuzzSparkSession, performance_analysis):
        """Generate comprehensive session report"""
        try:
            report = {
                'session_summary': {
                    'session_id': session.session_id,
                    'duration_minutes': session.total_duration_ms / (1000 * 60),
                    'status': session.status.value,
                    'project_path': session.project_analysis.project_path if session.project_analysis else 'unknown',
                    'language': session.project_analysis.primary_language if session.project_analysis else 'unknown'
                },
                'llm_usage': {
                    'provider': session.llm_provider.value,
                    'model': session.llm_model,
                    'total_interactions': session.total_llm_interactions,
                    'total_tokens': session.total_tokens_consumed,
                    'estimated_cost_usd': session.estimated_cost_usd
                },
                'fuzzing_results': {
                    'drivers_generated': session.fuzz_drivers_generated,
                    'successful_compilations': session.successful_compilations,
                    'failed_compilations': session.failed_compilations,
                    'unique_crashes': session.unique_crashes_found,
                    'vulnerabilities_found': session.security_vulnerabilities_found
                },
                'vulnerability_breakdown': {
                    'critical': session.critical_vulnerabilities,
                    'high': session.high_vulnerabilities,
                    'medium': session.medium_vulnerabilities,
                    'low': session.low_vulnerabilities
                },
                'coverage_metrics': {
                    'line_coverage': session.overall_line_coverage,
                    'branch_coverage': session.overall_branch_coverage,
                    'function_coverage': session.overall_function_coverage
                },
                'performance_metrics': {
                    'efficiency_score': session.efficiency_score,
                    'automation_score': session.automation_score,
                    'effectiveness_score': session.effectiveness_score,
                    'overall_score': session.overall_score,
                    'peak_memory_mb': session.peak_memory_usage_mb,
                    'average_cpu_percent': session.average_cpu_usage
                },
                'performance_analysis': performance_analysis.results,
                'generated_at': datetime.now().isoformat()
            }
            
            # Save report
            report_file = self.data_manager.reports_dir / f"session_report_{session.session_id}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.logger.info(f"📋 Session report generated: {report_file}")
            
        except Exception as e:
            self.logger.error(f"Report generation error: {e}")
    
    def _handle_file_change(self, session_id: str, event_type: str, file_path: str):
        """Handle file system change events"""
        try:
            session = self.session_manager.get_session(session_id)
            if not session:
                return
            
            self.data_manager.save_real_time_metric(
                session_id,
                "file_system",
                event_type,
                file_path,
                {
                    'timestamp': datetime.now().isoformat(),
                    'file_size': Path(file_path).stat().st_size if Path(file_path).exists() else 0
                }
            )
            
            # Special handling for specific file types
            file_path_obj = Path(file_path)
            
            if file_path_obj.suffix in ['.c', '.cpp', '.java', '.py'] and event_type == 'created':
                # New source file created - likely a generated fuzz driver
                self._analyze_generated_code(file_path_obj, session)
            
            elif file_path_obj.name.endswith('.log') and event_type == 'modified':
                # Log file updated - parse for new information
                self._parse_and_analyze_log(file_path_obj, session)
        
        except Exception as e:
            self.logger.warning(f"File change handling error: {e}")
    
    def _cleanup_session_monitoring(self, session: CIFuzzSparkSession):
        """Cleanup session monitoring resources"""
        try:
            # Stop file system monitoring
            if session.session_id in self.fs_monitors:
                self.fs_monitors[session.session_id].stop_monitoring()
                del self.fs_monitors[session.session_id]
            
            # Remove from session manager
            self.session_manager.remove_session(session.session_id)
            
            self.logger.info(f"🧹 Cleaned up monitoring for session {session.session_id}")
            
        except Exception as e:
            self.logger.warning(f"Session cleanup error: {e}")
    
    def _perform_maintenance(self):
        """Perform periodic maintenance tasks"""
        try:
            # Archive old data
            archive_stats = self.data_manager.archive_old_data()
            if archive_stats['files_archived'] > 0:
                self.logger.info(f"📦 Archived {archive_stats['files_archived']} old files")
            
            # Generate periodic reports
            self._generate_periodic_reports()
            
            # Check LLM provider health
            provider_stats = self.llm_manager.get_usage_statistics()
            if provider_stats['error_rate'] > 0.1:  # More than 10% error rate
                self.logger.warning(f"⚠️ High LLM provider error rate: {provider_stats['error_rate']:.2%}")
            
        except Exception as e:
            self.logger.error(f"Maintenance task error: {e}")
    
    def _generate_periodic_reports(self):
        """Generate periodic summary reports"""
        try:
            # Get all sessions from last 24 hours
            cutoff_time = datetime.now() - timedelta(hours=24)
            recent_sessions = []
            
            for session_id in self.data_manager.list_sessions():
                session = self.data_manager.load_session(session_id)
                if session and session.start_time > cutoff_time:
                    recent_sessions.append(session)
            
            if not recent_sessions:
                return
            
            # Generate summary report
            summary = {
                'report_type': 'daily_summary',
                'generated_at': datetime.now().isoformat(),
                'time_period': '24_hours',
                'sessions_analyzed': len(recent_sessions),
                'total_duration_hours': sum(s.total_duration_ms for s in recent_sessions) / (1000 * 3600),
                'total_drivers_generated': sum(s.fuzz_drivers_generated for s in recent_sessions),
                'total_vulnerabilities_found': sum(s.security_vulnerabilities_found for s in recent_sessions),
                'total_cost_usd': sum(s.estimated_cost_usd for s in recent_sessions),
                'average_quality_score': sum(s.overall_score for s in recent_sessions) / len(recent_sessions),
                'provider_usage': {},
                'language_distribution': {},
                'performance_trends': {}
            }
            
            # Provider usage analysis
            provider_counts = {}
            for session in recent_sessions:
                provider = session.llm_provider.value
                provider_counts[provider] = provider_counts.get(provider, 0) + 1
            summary['provider_usage'] = provider_counts
            
            # Language distribution
            language_counts = {}
            for session in recent_sessions:
                if session.project_analysis:
                    lang = session.project_analysis.primary_language
                    language_counts[lang] = language_counts.get(lang, 0) + 1
            summary['language_distribution'] = language_counts
            
            # Save summary report
            summary_file = self.data_manager.reports_dir / f"daily_summary_{datetime.now().strftime('%Y%m%d')}.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            
            self.logger.info(f"📊 Generated daily summary report: {summary_file}")
            
        except Exception as e:
            self.logger.error(f"Periodic report generation error: {e}")

class ComprehensiveCLI:
    """Comprehensive CLI interface with rich output and advanced features"""
    
    def __init__(self):
        self.console = console if HAS_RICH else None
        self.data_manager = None
        self.process_monitor = None
        self.session_manager = None
        
    def setup_data_manager(self, data_dir: str):
        """Setup data manager"""
        self.data_manager = AdvancedTextDataManager(Path(data_dir))
        self.session_manager = ConcurrentSessionManager(self.data_manager)
        self.process_monitor = ProcessMonitor(self.session_manager, self.data_manager)
    
    def start_daemon(self, repo_root: str, detach: bool = True) -> int:
        """Start the monitoring daemon"""
        try:
            data_dir = Path(repo_root) / ".cifuzz_research_data"
            self.setup_data_manager(str(data_dir))
            
            if detach:
                return self._start_daemon_detached(repo_root)
            else:
                return self._start_daemon_foreground(repo_root)
                
        except Exception as e:
            self._print_error(f"Failed to start daemon: {e}")
            return 1
    
    def _start_daemon_detached(self, repo_root: str) -> int:
        """Start daemon in detached mode with proper daemonization"""
        try:
            # First fork
            pid = os.fork()
            if pid > 0:
                # Parent process
                self._print_success(f"🚀 Started CI Fuzz Monitor daemon (PID: {pid})")
                self._print_info(f"📁 Data directory: {Path(repo_root) / '.cifuzz_research_data'}")
                self._print_info(f"📋 Log file: {Path(repo_root) / '.cifuzz_research_data' / 'monitor.log'}")
                self._print_info("Use --status to check daemon status")
                return 0
        except OSError as e:
            self._print_error(f"First fork failed: {e}")
            return 1
        
        # First child process
        os.setsid()  # Create new session
        
        try:
            # Second fork
            pid = os.fork()
            if pid > 0:
                sys.exit(0)  # Exit first child
        except OSError as e:
            self._print_error(f"Second fork failed: {e}")
            return 1
        
        # Second child process (daemon)
        return self._run_daemon_process(repo_root)
    
    def _start_daemon_foreground(self, repo_root: str) -> int:
        """Start daemon in foreground mode"""
        self._print_info("🔍 Running in foreground mode (Ctrl+C to stop)")
        return self._run_daemon_process(repo_root)
    
    def _run_daemon_process(self, repo_root: str) -> int:
        """Run the actual daemon process"""
        try:
            # Redirect standard streams for daemon mode
            if sys.stdout.isatty():
                # Only redirect if we're actually daemonized
                pass
            else:
                sys.stdout = open(os.devnull, 'w')
                sys.stderr = open(os.devnull, 'w')
                sys.stdin = open(os.devnull, 'r')
            
            # Setup signal handlers
            def signal_handler(signum, frame):
                logging.info(f"Received signal {signum}, shutting down...")
                if self.process_monitor:
                    self.process_monitor.stop_monitoring()
                if self.data_manager:
                    self.data_manager.shutdown()
                sys.exit(0)
            
            signal.signal(signal.SIGTERM, signal_handler)
            signal.signal(signal.SIGINT, signal_handler)
            
            # Write PID file
            pid_file = Path(repo_root) / ".cifuzz_research_data" / "monitor.pid"
            with open(pid_file, 'w') as f:
                f.write(str(os.getpid()))
            
            # Start monitoring
            self.process_monitor.start_monitoring()
            
            # Main daemon loop
            while True:
                time.sleep(60)  # Sleep indefinitely
                
        except KeyboardInterrupt:
            logging.info("Daemon interrupted by user")
            return 0
        except Exception as e:
            logging.error(f"Daemon error: {e}")
            return 1
        finally:
            if self.process_monitor:
                self.process_monitor.stop_monitoring()
            if self.data_manager:
                self.data_manager.shutdown()
    
    def stop_daemon(self, repo_root: str) -> int:
        """Stop the daemon process"""
        try:
            pid_file = Path(repo_root) / ".cifuzz_research_data" / "monitor.pid"
            
            if not pid_file.exists():
                self._print_warning("No daemon PID file found")
                return 1
            
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            try:
                process = psutil.Process(pid)
                process.terminate()
                
                # Wait for graceful shutdown
                try:
                    process.wait(timeout=30)
                    self._print_success(f"✅ Daemon stopped gracefully (PID: {pid})")
                except psutil.TimeoutExpired:
                    process.kill()
                    self._print_warning(f"⚠️ Daemon killed forcefully (PID: {pid})")
                
            except psutil.NoSuchProcess:
                self._print_warning(f"Daemon process {pid} not found")
            
            # Clean up PID file
            pid_file.unlink()
            return 0
            
        except Exception as e:
            self._print_error(f"Error stopping daemon: {e}")
            return 1
    
    def check_status(self, repo_root: str) -> int:
        """Check comprehensive daemon and system status"""
        try:
            data_dir = Path(repo_root) / ".cifuzz_research_data"
            pid_file = data_dir / "monitor.pid"
            
            if HAS_RICH:
                self._display_rich_status(data_dir, pid_file)
            else:
                self._display_simple_status(data_dir, pid_file)
            
            return 0
            
        except Exception as e:
            self._print_error(f"Status check failed: {e}")
            return 1
    
    def _display_rich_status(self, data_dir: Path, pid_file: Path):
        """Display rich status information"""
        layout = Layout()
        
        # Create panels
        daemon_panel = self._create_daemon_status_panel(pid_file)
        sessions_panel = self._create_sessions_panel(data_dir)
        providers_panel = self._create_providers_panel()
        storage_panel = self._create_storage_panel(data_dir)
        
        # Arrange layout
        layout.split_column(
            Layout(daemon_panel, name="daemon"),
            Layout(sessions_panel, name="sessions"), 
            Layout(providers_panel, name="providers"),
            Layout(storage_panel, name="storage")
        )
        
        self.console.print(layout)
    
    def _create_daemon_status_panel(self, pid_file: Path) -> Panel:
        """Create daemon status panel"""
        if pid_file.exists():
            try:
                with open(pid_file, "r") as f:
                    pid = int(f.read().strip())
                
                try:
                    process = psutil.Process(pid)
                    status_text = Text()
                    status_text.append("✅ Monitor daemon is running\n", style="green")
                    status_text.append(f"PID: {pid}\n")
                    status_text.append(f"CPU: {process.cpu_percent():.1f}%\n")
                    status_text.append(f"Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB\n")
                    status_text.append(f"Threads: {process.num_threads()}\n")
                    status_text.append(f"Started: {datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')}")
                    
                except psutil.NoSuchProcess:
                    status_text = Text(f"❌ Daemon PID {pid} not found (stale PID file)", style="red")
                    
            except Exception as e:
                status_text = Text(f"❌ Error checking daemon status: {e}", style="red")
        else:
            status_text = Text("❌ Monitor daemon is not running (no PID file)", style="red")
        
        return Panel(status_text, title="🚀 Daemon Status", border_style="blue")
    
    def _create_sessions_panel(self, data_dir: Path) -> Panel:
        """Create active sessions panel"""
        sessions_dir = data_dir / "sessions"
        
        if not sessions_dir.exists():
            return Panel("No sessions directory found", title="📊 Active Sessions", border_style="yellow")
        
        # Load recent sessions
        session_files = sorted(sessions_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:5]
        
        if not session_files:
            return Panel("No sessions found", title="📊 Recent Sessions", border_style="yellow")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Session ID", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Duration", style="yellow")
        table.add_column("Drivers", style="blue")
        table.add_column("Vulns", style="red")
        
        for session_file in session_files:
            try:
                with open(session_file, 'r') as f:
                    session_data = json.load(f)
                
                session_id = session_data.get('session_id', 'unknown')[:20] + "..."
                status = session_data.get('status', 'unknown')
                duration = f"{session_data.get('total_duration_ms', 0) / (1000 * 60):.1f}m"
                drivers = str(session_data.get('fuzz_drivers_generated', 0))
                vulns = str(session_data.get('security_vulnerabilities_found', 0))
                
                table.add_row(session_id, status, duration, drivers, vulns)
                
            except Exception:
                continue
        
        return Panel(table, title="📊 Recent Sessions", border_style="green")
    
    def _create_providers_panel(self) -> Panel:
        """Create LLM providers panel"""
        # This would typically connect to the LLM manager
        # For now, show detected providers
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Provider", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Status", style="green")
        
        # Check common providers
        providers_to_check = [
            ("OpenAI", "cloud", "OPENAI_API_KEY"),
            ("Anthropic", "cloud", "ANTHROPIC_API_KEY"),
            ("HuggingFace", "cloud", "HUGGINGFACE_API_TOKEN"),
            ("Ollama", "local", None),
            ("LocalAI", "local", None),
        ]
        
        for provider, ptype, env_var in providers_to_check:
            if env_var and os.getenv(env_var):
                status = "🟢 Configured"
            elif ptype == "local":
                # Check if local service is running
                try:
                    if provider == "Ollama":
                        response = requests.get("http://localhost:11434/api/tags", timeout=2)
                        status = "🟢 Running" if response.status_code == 200 else "🔴 Offline"
                    elif provider == "LocalAI":
                        response = requests.get("http://localhost:8080/v1/models", timeout=2)
                        status = "🟢 Running" if response.status_code == 200 else "🔴 Offline"
                    else:
                        status = "🟡 Unknown"
                except:
                    status = "🔴 Offline"
            else:
                status = "🔴 Not configured"
            
            table.add_row(provider, ptype, status)
        
        return Panel(table, title="🤖 LLM Providers", border_style="purple")
    
    def _create_storage_panel(self, data_dir: Path) -> Panel:
        """Create storage status panel"""
        if not data_dir.exists():
            return Panel("Data directory not found", title="📁 Storage Status", border_style="red")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Directory", style="cyan")
        table.add_column("Files", style="yellow")
        table.add_column("Size", style="green")
        
        subdirs = ['sessions', 'llm_interactions', 'fuzz_drivers', 'real_time_metrics', 'reports']
        
        for subdir in subdirs:
            subdir_path = data_dir / subdir
            if subdir_path.exists():
                file_count = len(list(subdir_path.glob('*')))
                total_size = sum(f.stat().st_size for f in subdir_path.rglob('*') if f.is_file())
                size_str = self._format_bytes(total_size)
            else:
                file_count = 0
                size_str = "0 B"
            
            table.add_row(subdir, str(file_count), size_str)
        
        return Panel(table, title="📁 Storage Status", border_style="cyan")
    
    def _display_simple_status(self, data_dir: Path, pid_file: Path):
        """Display simple text status"""
        print("=== Comprehensive LLM Fuzz Monitor Status ===\n")
        
        # Daemon status
        if pid_file.exists():
            try:
                with open(pid_file, "r") as f:
                    pid = int(f.read().strip())
                
                try:
                    process = psutil.Process(pid)
                    print(f"✅ Monitor daemon is running (PID: {pid})")
                    print(f"   CPU: {process.cpu_percent():.1f}%")
                    print(f"   Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB")
                    print(f"   Started: {datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')}")
                except psutil.NoSuchProcess:
                    print(f"❌ Daemon PID {pid} not found (stale PID file)")
            except Exception as e:
                print(f"❌ Error checking daemon status: {e}")
        else:
            print("❌ Monitor daemon is not running (no PID file)")
        
        print("\n=== Recent Sessions ===")
        sessions_dir = data_dir / "sessions"
        if sessions_dir.exists():
            session_files = sorted(sessions_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:3]
            for session_file in session_files:
                try:
                    with open(session_file, 'r') as f:
                        session_data = json.load(f)
                    
                    session_id = session_data.get('session_id', 'unknown')
                    status = session_data.get('status', 'unknown')
                    print(f"📊 {session_id}: {status}")
                except Exception:
                    continue
        else:
            print("No sessions found")
    
    def analyze_logs(self, log_path: str, output_format: str = "json") -> int:
        """Analyze historical log files"""
        try:
            log_parser = AdvancedLogParser()
            
            if Path(log_path).is_dir():
                self._print_info(f"🔍 Analyzing log directory: {log_path}")
                
                # Analyze all log files in directory
                results = []
                for log_file in Path(log_path).rglob("*.log"):
                    try:
                        result = log_parser.parse_file(log_file)
                        results.append({
                            'file': str(log_file),
                            'result': result
                        })
                    except Exception as e:
                        self._print_warning(f"Failed to parse {log_file}: {e}")
                
                # Generate summary
                total_entries = sum(r['result']['statistics']['parsed_entries'] for r in results)
                total_errors = sum(r['result']['statistics']['errors'] for r in results)
                
                self._print_success(f"✅ Analyzed {len(results)} log files")
                self._print_info(f"📊 Total entries: {total_entries}")
                self._print_info(f"⚠️ Total errors: {total_errors}")
                
                # Save results
                if output_format == "json":
                    output_file = Path(log_path).parent / f"analysis_results_{int(time.time())}.json"
                    with open(output_file, 'w') as f:
                        json.dump(results, f, indent=2, default=str)
                    self._print_info(f"📋 Results saved: {output_file}")
            
            else:
                self._print_info(f"🔍 Analyzing log file: {log_path}")
                result = log_parser.parse_file(Path(log_path))
                
                self._print_success(f"✅ Analysis completed")
                self._print_info(f"📊 Entries parsed: {result['statistics']['parsed_entries']}")
                self._print_info(f"⚠️ Errors: {result['statistics']['errors']}")
                
                if HAS_RICH and output_format == "rich":
                    self._display_log_analysis_rich(result)
                else:
                    print(json.dumps(result, indent=2, default=str))
            
            return 0
            
        except Exception as e:
            self._print_error(f"Log analysis failed: {e}")
            return 1
    
    def _display_log_analysis_rich(self, result: Dict[str, Any]):
        """Display log analysis with rich formatting"""
        # Create summary table
        table = Table(title="Log Analysis Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        stats = result.get('statistics', {})
        for key, value in stats.items():
            table.add_row(key.replace('_', ' ').title(), str(value))
        
        self.console.print(table)
        
        # Display sample entries
        entries = result.get('entries', [])[:10]  # Show first 10 entries
        if entries:
            entries_table = Table(title="Sample Log Entries")
            entries_table.add_column("Type", style="green")
            entries_table.add_column("Message", style="yellow", max_width=50)
            entries_table.add_column("Timestamp", style="blue")
            
            for entry in entries:
                entry_type = entry.get('type', 'unknown')
                message = entry.get('message', entry.get('raw_line', ''))[:50]
                timestamp = entry.get('timestamp', 'unknown')
                entries_table.add_row(entry_type, message, timestamp)
            
            self.console.print(entries_table)
    
    def export_data(self, repo_root: str, output_path: str, format_type: str = "json") -> int:
        """Export research data for thesis"""
        try:
            data_dir = Path(repo_root) / ".cifuzz_research_data"
            if not data_dir.exists():
                self._print_error("No data directory found. Run the monitor first.")
                return 1
            
            self.setup_data_manager(str(data_dir))
            
            self._print_info(f"📤 Exporting research data to: {output_path}")
            
            if HAS_RICH:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TimeRemainingColumn(),
                    console=self.console
                ) as progress:
                    task = progress.add_task("Exporting data...", total=100)
                    
                    # Export data
                    success = self.data_manager.export_data(
                        Path(output_path),
                        format=format_type,
                        compress=True
                    )
                    
                    progress.update(task, completed=100)
            else:
                print("Exporting data...")
                success = self.data_manager.export_data(
                    Path(output_path),
                    format=format_type,
                    compress=True
                )
            
            if success:
                self._print_success(f"✅ Export completed: {output_path}")
                return 0
            else:
                self._print_error("❌ Export failed")
                return 1
                
        except Exception as e:
            self._print_error(f"Export failed: {e}")
            return 1
    
    def generate_report(self, repo_root: str, report_type: str = "summary") -> int:
        """Generate comprehensive analysis report"""
        try:
            data_dir = Path(repo_root) / ".cifuzz_research_data"
            self.setup_data_manager(str(data_dir))
            
            if report_type == "summary":
                return self._generate_summary_report()
            elif report_type == "detailed":
                return self._generate_detailed_report()
            elif report_type == "thesis":
                return self._generate_thesis_report()
            else:
                self._print_error(f"Unknown report type: {report_type}")
                return 1
                
        except Exception as e:
            self._print_error(f"Report generation failed: {e}")
            return 1
    
    def _generate_summary_report(self) -> int:
        """Generate summary report"""
        self._print_info("📋 Generating summary report...")
        
        # Get all sessions
        session_ids = self.data_manager.list_sessions()
        
        if not session_ids:
            self._print_warning("No sessions found")
            return 1
        
        summary_stats = {
            'total_sessions': len(session_ids),
            'total_duration_hours': 0.0,
            'total_drivers_generated': 0,
            'total_vulnerabilities': 0,
            'total_cost': 0.0,
            'provider_usage': {},
            'language_distribution': {}
        }
        
        for session_id in session_ids:
            session = self.data_manager.load_session(session_id)
            if session:
                summary_stats['total_duration_hours'] += session.total_duration_ms / (1000 * 3600)
                summary_stats['total_drivers_generated'] += session.fuzz_drivers_generated
                summary_stats['total_vulnerabilities'] += session.security_vulnerabilities_found
                summary_stats['total_cost'] += session.estimated_cost_usd
                
                provider = session.llm_provider.value
                summary_stats['provider_usage'][provider] = summary_stats['provider_usage'].get(provider, 0) + 1
        
        # Display summary
        if HAS_RICH:
            self._display_summary_rich(summary_stats)
        else:
            self._display_summary_simple(summary_stats)
        
        return 0
    
    def _display_summary_rich(self, stats: Dict[str, Any]):
        """Display summary with rich formatting"""
        # Main stats table
        table = Table(title="📊 Monitor Summary Report")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Total Sessions", str(stats['total_sessions']))
        table.add_row("Total Duration (hours)", f"{stats['total_duration_hours']:.1f}")
        table.add_row("Drivers Generated", str(stats['total_drivers_generated']))
        table.add_row("Vulnerabilities Found", str(stats['total_vulnerabilities']))
        table.add_row("Total Cost (USD)", f"${stats['total_cost']:.2f}")
        
        self.console.print(table)
        
        # Provider usage
        if stats['provider_usage']:
            provider_table = Table(title="🤖 LLM Provider Usage")
            provider_table.add_column("Provider", style="green")
            provider_table.add_column("Sessions", style="yellow")
            
            for provider, count in stats['provider_usage'].items():
                provider_table.add_row(provider, str(count))
            
            self.console.print(provider_table)
    
    def _display_summary_simple(self, stats: Dict[str, Any]):
        """Display summary in simple text format"""
        print("\n=== Monitor Summary Report ===")
        print(f"Total Sessions: {stats['total_sessions']}")
        print(f"Total Duration: {stats['total_duration_hours']:.1f} hours")
        print(f"Drivers Generated: {stats['total_drivers_generated']}")
        print(f"Vulnerabilities Found: {stats['total_vulnerabilities']}")
        print(f"Total Cost: ${stats['total_cost']:.2f}")
        
        if stats['provider_usage']:
            print("\nLLM Provider Usage:")
            for provider, count in stats['provider_usage'].items():
                print(f"  {provider}: {count} sessions")
    
    def _format_bytes(self, bytes_size: int) -> str:
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} TB"
    
    def _print_success(self, message: str):
        """Print success message"""
        if HAS_RICH:
            self.console.print(message, style="green")
        else:
            print(message)
    
    def _print_info(self, message: str):
        """Print info message"""
        if HAS_RICH:
            self.console.print(message, style="blue")
        else:
            print(message)
    
    def _print_warning(self, message: str):
        """Print warning message"""
        if HAS_RICH:
            self.console.print(message, style="yellow")
        else:
            print(f"WARNING: {message}")
    
    def _print_error(self, message: str):
        """Print error message"""
        if HAS_RICH:
            self.console.print(message, style="red")
        else:
            print(f"ERROR: {message}")

def create_cli_parser():
    """Create comprehensive CLI argument parser"""
    parser = argparse.ArgumentParser(
        description="Comprehensive LLM Fuzzing Monitor for Master's Thesis Research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --daemon                                    # Start daemon
  %(prog)s --daemon --foreground                       # Run in foreground  
  %(prog)s --stop                                      # Stop daemon
  %(prog)s --status                                    # Check status
  %(prog)s --analyze-logs /path/to/logs                # Analyze logs
  %(prog)s --export-data /path/to/export               # Export research data
  %(prog)s --generate-report summary                   # Generate summary report
  %(prog)s --parse-code /path/to/source.c              # Parse source code
        """
    )
    
    # Basic operations
    parser.add_argument("--repo-root", help="Repository root directory", default=".")
    
    # Daemon operations
    daemon_group = parser.add_mutually_exclusive_group()
    daemon_group.add_argument("--daemon", action="store_true", help="Start daemon")
    daemon_group.add_argument("--stop", action="store_true", help="Stop daemon")
    daemon_group.add_argument("--status", action="store_true", help="Check daemon status")
    
    # Daemon options
    parser.add_argument("--foreground", action="store_true", help="Run daemon in foreground")
    
    # Analysis operations
    parser.add_argument("--analyze-logs", help="Analyze historical log files/directory")
    parser.add_argument("--parse-code", help="Parse and analyze source code file")
    parser.add_argument("--output-format", choices=["json", "yaml", "rich"], default="json", help="Output format")
    
    # Data operations
    parser.add_argument("--export-data", help="Export thesis research data to directory")
    parser.add_argument("--generate-report", choices=["summary", "detailed", "thesis"], help="Generate analysis report")
    
    # Configuration
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--data-dir", help="Custom data directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    return parser

def main():
    """Main entry point"""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize CLI
    cli = ComprehensiveCLI()
    
    try:
        # Handle operations
        if args.stop:
            return cli.stop_daemon(args.repo_root)
        
        elif args.status:
            return cli.check_status(args.repo_root)
        
        elif args.analyze_logs:
            return cli.analyze_logs(args.analyze_logs, args.output_format)
        
        elif args.parse_code:
            parser = CodeAnalysisParser()
            result = parser.analyze_source_file(Path(args.parse_code))
            
            if args.output_format == "json":
                print(json.dumps(result, indent=2, default=str))
            elif args.output_format == "yaml":
                import yaml
                print(yaml.dump(result, default_flow_style=False))
            else:
                print(json.dumps(result, indent=2, default=str))
            return 0
        
        elif args.export_data:
            return cli.export_data(args.repo_root, args.export_data)
        
        elif args.generate_report:
            return cli.generate_report(args.repo_root, args.generate_report)
        
        elif args.daemon:
            return cli.start_daemon(args.repo_root, not args.foreground)
        
        else:
            parser.print_help()
            return 0
            
    except KeyboardInterrupt:
        if HAS_RICH:
            console.print("\n⏹️ Interrupted by user", style="yellow")
        else:
            print("\nInterrupted by user")
        return 0
    except Exception as e:
        if HAS_RICH:
            console.print(f"❌ Fatal error: {e}", style="red")
        else:
            print(f"ERROR: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())