#!/usr/bin/env python3
"""
Advanced LLM Fuzzing Monitor - Storage & Concurrency Management
Part 2: High-Performance Storage, Thread Management & I/O Operations

Master's Thesis Research: "Enhancing Automated Security Testing in CI/CD/CT Pipelines with Large Language Models"
Author: Morris Darren Babu
Version: 3.0.0
License: MIT
"""

import asyncio
import csv
import gzip
import json
import logging
import mmap
import os
import pickle
import queue
import shutil
import sqlite3
import tarfile
import threading
import time
import weakref
import zipfile
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from contextlib import contextmanager, asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Iterator, AsyncIterator
import fcntl
import portalocker

# Third-party imports
try:
    import aiofiles
    import ujson as fast_json
except ImportError:
    import json as fast_json
    aiofiles = None

try:
    import lz4.frame
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False

from ..core.models import (
    CIFuzzSparkSession, LLMInteraction, FuzzDriverMetrics, 
    SecurityFinding, SystemMetrics, HistoricalAnalysisResult,
    SessionStatus, MonitorConfig, DataValidationError
)

# Performance-optimized logger
logger = logging.getLogger(__name__)

class AsyncWriteQueue:
    """High-performance async write queue with back-pressure"""
    
    def __init__(self, maxsize: int = MonitorConfig.WRITER_QUEUE_MAXSIZE):
        self.queue = asyncio.Queue(maxsize=maxsize)
        self.active_writers = 0
        self.total_writes = 0
        self.failed_writes = 0
        self._shutdown = False
        
    async def put(self, item: Tuple[str, Any], timeout: float = 5.0):
        """Put item with timeout and back-pressure handling"""
        try:
            await asyncio.wait_for(self.queue.put(item), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Write queue full, dropping item: {item[0]}")
            raise queue.Full("Write queue timeout")
    
    async def get(self) -> Optional[Tuple[str, Any]]:
        """Get next item to write"""
        if self._shutdown and self.queue.empty():
            return None
        
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            return None
    
    def shutdown(self):
        """Signal shutdown"""
        self._shutdown = True
    
    @property
    def qsize(self) -> int:
        return self.queue.qsize()
    
    @property
    def stats(self) -> Dict[str, int]:
        return {
            'queue_size': self.qsize,
            'active_writers': self.active_writers,
            'total_writes': self.total_writes,
            'failed_writes': self.failed_writes
        }

class FileRotationManager:
    """Manages file rotation with compression and cleanup"""
    
    def __init__(self, max_size_mb: int = MonitorConfig.MAX_LOG_FILE_SIZE_MB, 
                 backup_count: int = MonitorConfig.LOG_ROTATION_BACKUP_COUNT):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.backup_count = backup_count
        self._locks = weakref.WeakValueDictionary()
    
    def should_rotate(self, file_path: Path) -> bool:
        """Check if file should be rotated"""
        try:
            return file_path.exists() and file_path.stat().st_size > self.max_size_bytes
        except OSError:
            return False
    
    def rotate_file(self, file_path: Path, compress: bool = True) -> bool:
        """Rotate file with optional compression"""
        if not self.should_rotate(file_path):
            return False
        
        lock = self._locks.setdefault(str(file_path), threading.Lock())
        
        with lock:
            try:
                # Create backup filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                if compress:
                    backup_path = file_path.with_suffix(f".{timestamp}.gz")
                    
                    # Compress the file
                    with open(file_path, 'rb') as f_in:
                        with gzip.open(backup_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                else:
                    backup_path = file_path.with_suffix(f".{timestamp}.bak")
                    shutil.copy2(file_path, backup_path)
                
                # Truncate original file
                file_path.write_text("")
                
                # Clean up old backups
                self._cleanup_old_backups(file_path)
                
                logger.info(f"Rotated {file_path} to {backup_path}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to rotate {file_path}: {e}")
                return False
    
    def _cleanup_old_backups(self, base_path: Path):
        """Remove old backup files beyond backup_count"""
        pattern = f"{base_path.stem}.*"
        backup_files = sorted(
            [f for f in base_path.parent.glob(pattern) if f != base_path],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        for old_file in backup_files[self.backup_count:]:
            try:
                old_file.unlink()
                logger.debug(f"Removed old backup: {old_file}")
            except OSError as e:
                logger.warning(f"Failed to remove backup {old_file}: {e}")

class CompressedStorageHandler:
    """Handles compressed storage with multiple algorithms"""
    
    def __init__(self, compression_level: int = 6):
        self.compression_level = compression_level
        self.preferred_algorithm = 'lz4' if HAS_LZ4 else 'gzip'
    
    def compress_data(self, data: bytes, algorithm: Optional[str] = None) -> Tuple[bytes, str]:
        """Compress data with specified or preferred algorithm"""
        algo = algorithm or self.preferred_algorithm
        
        if algo == 'lz4' and HAS_LZ4:
            compressed = lz4.frame.compress(data, compression_level=self.compression_level)
            return compressed, 'lz4'
        elif algo == 'gzip':
            compressed = gzip.compress(data, compresslevel=self.compression_level)
            return compressed, 'gzip'
        else:
            # Fallback to no compression
            return data, 'none'
    
    def decompress_data(self, data: bytes, algorithm: str) -> bytes:
        """Decompress data based on algorithm"""
        if algorithm == 'lz4' and HAS_LZ4:
            return lz4.frame.decompress(data)
        elif algorithm == 'gzip':
            return gzip.decompress(data)
        elif algorithm == 'none':
            return data
        else:
            raise ValueError(f"Unsupported compression algorithm: {algorithm}")

class AdvancedTextDataManager:
    """High-performance text-based data manager with async operations"""
    
    def __init__(self, data_dir: Path, enable_compression: bool = True,
                 enable_async: bool = True, max_workers: int = 4):
        self.data_dir = Path(data_dir)
        self.enable_compression = enable_compression
        self.enable_async = enable_async
        self.max_workers = max_workers
        
        # Create directory structure
        self.subdirs = {
            'sessions': self.data_dir / "sessions",
            'interactions': self.data_dir / "llm_interactions", 
            'drivers': self.data_dir / "fuzz_drivers",
            'metrics': self.data_dir / "real_time_metrics",
            'security': self.data_dir / "security_findings",
            'terminal': self.data_dir / "terminal_outputs",
            'historical': self.data_dir / "historical_analysis",
            'reports': self.data_dir / "reports",
            'archives': self.data_dir / "archives",
            'cache': self.data_dir / "cache",
            'temp': self.data_dir / "temp"
        }
        
        for subdir in self.subdirs.values():
            subdir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.compression_handler = CompressedStorageHandler()
        self.rotation_manager = FileRotationManager()
        self.write_queue = AsyncWriteQueue()
        
        # Thread management
        self.thread_pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="DataManager")
        self.process_pool = ProcessPoolExecutor(max_workers=2)
        
        # File locks and caches
        self.file_locks = weakref.WeakValueDictionary()
        self.write_cache = {}
        self.read_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Statistics
        self.stats = {
            'writes_completed': 0,
            'reads_completed': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'compression_ratio': 0.0,
            'errors': 0
        }
        
        # Start background workers
        if self.enable_async:
            self._start_async_workers()
        
        # Periodic maintenance
        self.maintenance_timer = threading.Timer(300, self._periodic_maintenance)
        self.maintenance_timer.daemon = True
        self.maintenance_timer.start()
    
    def _start_async_workers(self):
        """Start async worker tasks"""
        if not hasattr(self, '_loop'):
            self._loop = asyncio.new_event_loop()
            self._loop_thread = threading.Thread(target=self._run_async_loop, daemon=True)
            self._loop_thread.start()
    
    def _run_async_loop(self):
        """Run async event loop in background thread"""
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._async_writer_worker())
    
    async def _async_writer_worker(self):
        """Async writer worker"""
        while True:
            try:
                item = await self.write_queue.get()
                if item is None:
                    break
                
                operation, args = item
                self.write_queue.active_writers += 1
                
                try:
                    if operation == "write_json":
                        await self._async_write_json(*args)
                    elif operation == "write_csv":
                        await self._async_write_csv(*args)
                    elif operation == "write_binary":
                        await self._async_write_binary(*args)
                    
                    self.write_queue.total_writes += 1
                    
                except Exception as e:
                    logger.error(f"Async write failed: {e}")
                    self.write_queue.failed_writes += 1
                    self.stats['errors'] += 1
                finally:
                    self.write_queue.active_writers -= 1
                    
            except Exception as e:
                logger.error(f"Async writer worker error: {e}")
                await asyncio.sleep(1)
    
    @contextmanager
    def file_lock(self, file_path: Path):
        """File-based locking with portalocker"""
        lock_file = file_path.with_suffix(file_path.suffix + '.lock')
        
        try:
            with open(lock_file, 'w') as lock_fd:
                portalocker.lock(lock_fd, portalocker.LOCK_EX)
                yield
        finally:
            try:
                lock_file.unlink()
            except FileNotFoundError:
                pass
    
    def save_session(self, session: CIFuzzSparkSession, sync: bool = False):
        """Save session with async support"""
        session_file = self.subdirs['sessions'] / f"{session.session_id}.json"
        
        # Convert to dict and handle datetime serialization
        session_data = asdict(session)
        session_data['start_time'] = session.start_time.isoformat() if session.start_time else None
        session_data['end_time'] = session.end_time.isoformat() if session.end_time else None
        
        if sync or not self.enable_async:
            self._write_json_sync(session_file, session_data)
        else:
            self._queue_async_write("write_json", (session_file, session_data))
    
    def save_llm_interaction(self, interaction: LLMInteraction, sync: bool = False):
        """Save LLM interaction with batching support"""
        interaction_file = self.subdirs['interactions'] / f"{interaction.interaction_id}.json"
        interaction_data = asdict(interaction)
        
        if sync or not self.enable_async:
            self._write_json_sync(interaction_file, interaction_data)
        else:
            self._queue_async_write("write_json", (interaction_file, interaction_data))
    
    def save_fuzz_driver(self, driver: FuzzDriverMetrics, sync: bool = False):
        """Save fuzz driver metrics"""
        driver_file = self.subdirs['drivers'] / f"{driver.driver_id}.json"
        driver_data = asdict(driver)
        
        if sync or not self.enable_async:
            self._write_json_sync(driver_file, driver_data)
        else:
            self._queue_async_write("write_json", (driver_file, driver_data))
    
    def save_security_finding(self, finding: SecurityFinding, sync: bool = False):
        """Save security finding"""
        finding_file = self.subdirs['security'] / f"{finding.finding_id}.json"
        finding_data = asdict(finding)
        
        if sync or not self.enable_async:
            self._write_json_sync(finding_file, finding_data)
        else:
            self._queue_async_write("write_json", (finding_file, finding_data))
    
    def save_real_time_metric(self, session_id: str, metric_category: str,
                             metric_name: str, metric_value: Any, 
                             additional_data: Optional[Dict] = None, sync: bool = False):
        """Save real-time metric to CSV with high performance"""
        metrics_file = self.subdirs['metrics'] / f"{session_id}_metrics.csv"
        
        # Check if rotation is needed
        if self.rotation_manager.should_rotate(metrics_file):
            self.rotation_manager.rotate_file(metrics_file)
        
        row_data = [
            datetime.now().isoformat(),
            metric_category,
            metric_name,
            str(metric_value),
            fast_json.dumps(additional_data or {})
        ]
        
        if sync or not self.enable_async:
            self._write_csv_sync(metrics_file, row_data)
        else:
            self._queue_async_write("write_csv", (metrics_file, row_data))
    
    def _write_json_sync(self, file_path: Path, data: Dict):
        """Synchronous JSON write with compression"""
        try:
            with self.file_lock(file_path):
                json_str = fast_json.dumps(data, indent=2, default=str)
                
                if self.enable_compression:
                    json_bytes = json_str.encode('utf-8')
                    compressed_data, algorithm = self.compression_handler.compress_data(json_bytes)
                    
                    # Write compressed with metadata
                    with open(file_path.with_suffix('.json.compressed'), 'wb') as f:
                        # Write algorithm header
                        f.write(f"{algorithm}\n".encode('utf-8'))
                        f.write(compressed_data)
                    
                    # Update compression stats
                    ratio = len(compressed_data) / len(json_bytes) if json_bytes else 1.0
                    self.stats['compression_ratio'] = (self.stats['compression_ratio'] + ratio) / 2
                else:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(json_str)
                
                self.stats['writes_completed'] += 1
                
        except Exception as e:
            logger.error(f"Failed to write JSON {file_path}: {e}")
            self.stats['errors'] += 1
            raise
    
    def _write_csv_sync(self, file_path: Path, row_data: List[str]):
        """Synchronous CSV write with header management"""
        try:
            file_exists = file_path.exists()
            
            with self.file_lock(file_path):
                with open(file_path, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    
                    # Write header if new file
                    if not file_exists:
                        header = ['timestamp', 'metric_category', 'metric_name', 
                                'metric_value', 'additional_data']
                        writer.writerow(header)
                    
                    writer.writerow(row_data)
                
                self.stats['writes_completed'] += 1
                
        except Exception as e:
            logger.error(f"Failed to write CSV {file_path}: {e}")
            self.stats['errors'] += 1
            raise
    
    async def _async_write_json(self, file_path: Path, data: Dict):
        """Async JSON write"""
        if aiofiles:
            json_str = fast_json.dumps(data, indent=2, default=str)
            
            async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                await f.write(json_str)
        else:
            # Fallback to sync in thread
            await asyncio.get_event_loop().run_in_executor(
                self.thread_pool, self._write_json_sync, file_path, data
            )
    
    async def _async_write_csv(self, file_path: Path, row_data: List[str]):
        """Async CSV write"""
        await asyncio.get_event_loop().run_in_executor(
            self.thread_pool, self._write_csv_sync, file_path, row_data
        )
    
    async def _async_write_binary(self, file_path: Path, data: bytes):
        """Async binary write"""
        if aiofiles:
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(data)
        else:
            await asyncio.get_event_loop().run_in_executor(
                self.thread_pool, file_path.write_bytes, data
            )
    
    def _queue_async_write(self, operation: str, args: Tuple):
        """Queue async write operation"""
        if hasattr(self, '_loop'):
            asyncio.run_coroutine_threadsafe(
                self.write_queue.put((operation, args)), self._loop
            )
    
    def load_session(self, session_id: str, use_cache: bool = True) -> Optional[CIFuzzSparkSession]:
        """Load session with caching"""
        cache_key = f"session:{session_id}"
        
        # Check cache first
        if use_cache and cache_key in self.read_cache:
            cache_entry = self.read_cache[cache_key]
            if time.time() - cache_entry['timestamp'] < self.cache_ttl:
                self.stats['cache_hits'] += 1
                return cache_entry['data']
        
        self.stats['cache_misses'] += 1
        
        # Load from file
        session_file = self.subdirs['sessions'] / f"{session_id}.json"
        compressed_file = session_file.with_suffix('.json.compressed')
        
        try:
            if compressed_file.exists():
                data = self._load_compressed_json(compressed_file)
            elif session_file.exists():
                with open(session_file, 'r', encoding='utf-8') as f:
                    data = fast_json.load(f)
            else:
                return None
            
            # Convert back to dataclass
            session = self._dict_to_session(data)
            
            # Cache result
            if use_cache:
                self.read_cache[cache_key] = {
                    'data': session,
                    'timestamp': time.time()
                }
            
            self.stats['reads_completed'] += 1
            return session
            
        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            self.stats['errors'] += 1
            return None
    
    def _load_compressed_json(self, file_path: Path) -> Dict:
        """Load compressed JSON file"""
        with open(file_path, 'rb') as f:
            # Read algorithm header
            algorithm_line = f.readline().decode('utf-8').strip()
            compressed_data = f.read()
            
            # Decompress
            json_bytes = self.compression_handler.decompress_data(compressed_data, algorithm_line)
            return fast_json.loads(json_bytes.decode('utf-8'))
    
    def _dict_to_session(self, data: Dict) -> CIFuzzSparkSession:
        """Convert dictionary back to session dataclass"""
        # Handle datetime conversion
        if data.get('start_time'):
            data['start_time'] = datetime.fromisoformat(data['start_time'])
        if data.get('end_time'):
            data['end_time'] = datetime.fromisoformat(data['end_time'])
        
        # Convert enums
        from ..core.models import SessionStatus, LLMProvider
        if 'status' in data:
            data['status'] = SessionStatus(data['status'])
        if 'llm_provider' in data:
            data['llm_provider'] = LLMProvider(data['llm_provider'])
        
        return CIFuzzSparkSession(**data)
    
    def list_sessions(self, limit: Optional[int] = None, 
                     status_filter: Optional[SessionStatus] = None) -> List[str]:
        """List session IDs with filtering"""
        session_files = list(self.subdirs['sessions'].glob("*.json"))
        session_files.extend(self.subdirs['sessions'].glob("*.json.compressed"))
        
        session_ids = []
        for file_path in session_files:
            session_id = file_path.stem.replace('.json', '')
            
            if status_filter:
                # Quick status check without full load
                try:
                    session = self.load_session(session_id)
                    if session and session.status == status_filter:
                        session_ids.append(session_id)
                except Exception:
                    continue
            else:
                session_ids.append(session_id)
        
        # Sort by modification time (newest first)
        session_ids.sort(key=lambda sid: self._get_session_mtime(sid), reverse=True)
        
        return session_ids[:limit] if limit else session_ids
    
    def _get_session_mtime(self, session_id: str) -> float:
        """Get session file modification time"""
        session_file = self.subdirs['sessions'] / f"{session_id}.json"
        compressed_file = session_file.with_suffix('.json.compressed')
        
        if compressed_file.exists():
            return compressed_file.stat().st_mtime
        elif session_file.exists():
            return session_file.stat().st_mtime
        else:
            return 0.0
    
    def archive_old_data(self, days_old: int = MonitorConfig.ARCHIVE_AFTER_DAYS, 
                        compress: bool = True) -> Dict[str, int]:
        """Archive old data with progress tracking"""
        cutoff_time = datetime.now() - timedelta(days=days_old)
        archive_stats = {'files_archived': 0, 'bytes_saved': 0, 'errors': 0}
        
        # Create archive directory with timestamp
        archive_name = f"archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        archive_path = self.subdirs['archives'] / archive_name
        
        if compress:
            archive_file = archive_path.with_suffix('.tar.gz')
            tar_mode = 'w:gz'
        else:
            archive_file = archive_path.with_suffix('.tar')
            tar_mode = 'w'
        
        try:
            with tarfile.open(archive_file, tar_mode) as tar:
                for subdir_name, subdir_path in self.subdirs.items():
                    if subdir_name in ['archives', 'temp', 'cache']:
                        continue
                    
                    for file_path in subdir_path.rglob('*'):
                        if file_path.is_file():
                            try:
                                mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                                if mtime < cutoff_time:
                                    # Add to archive
                                    arcname = f"{subdir_name}/{file_path.relative_to(subdir_path)}"
                                    tar.add(file_path, arcname=arcname)
                                    
                                    archive_stats['bytes_saved'] += file_path.stat().st_size
                                    archive_stats['files_archived'] += 1
                                    
                                    # Remove original
                                    file_path.unlink()
                                    
                            except Exception as e:
                                logger.warning(f"Failed to archive {file_path}: {e}")
                                archive_stats['errors'] += 1
            
            logger.info(f"Archived {archive_stats['files_archived']} files to {archive_file}")
            
        except Exception as e:
            logger.error(f"Archive operation failed: {e}")
            archive_stats['errors'] += 1
        
        return archive_stats
    
    def _periodic_maintenance(self):
        """Periodic maintenance tasks"""
        try:
            # Clean cache
            current_time = time.time()
            expired_keys = [
                key for key, entry in self.read_cache.items()
                if current_time - entry['timestamp'] > self.cache_ttl
            ]
            
            for key in expired_keys:
                del self.read_cache[key]
            
            # Rotate large files
            for subdir_path in self.subdirs.values():
                for file_path in subdir_path.glob("*.csv"):
                    if self.rotation_manager.should_rotate(file_path):
                        self.rotation_manager.rotate_file(file_path)
            
            # Log statistics
            logger.info(f"Data manager stats: {self.stats}")
            logger.info(f"Write queue stats: {self.write_queue.stats}")
            
        except Exception as e:
            logger.error(f"Maintenance task failed: {e}")
        finally:
            # Schedule next maintenance
            self.maintenance_timer = threading.Timer(300, self._periodic_maintenance)
            self.maintenance_timer.daemon = True
            self.maintenance_timer.start()
    
    def get_storage_statistics(self) -> Dict[str, Any]:
        """Get comprehensive storage statistics"""
        stats = self.stats.copy()
        
        # Directory sizes
        dir_stats = {}
        for name, path in self.subdirs.items():
            if path.exists():
                size = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
                file_count = len(list(path.rglob('*')))
                dir_stats[name] = {'size_bytes': size, 'file_count': file_count}
        
        stats['directories'] = dir_stats
        stats['cache_size'] = len(self.read_cache)
        stats['queue_stats'] = self.write_queue.stats
        
        return stats
    
    def export_data(self, output_path: Path, session_ids: Optional[List[str]] = None,
                   format: str = 'json', compress: bool = True) -> bool:
        """Export data for thesis research"""
        try:
            output_path = Path(output_path)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Determine sessions to export
            if session_ids is None:
                session_ids = self.list_sessions()
            
            export_stats = {'sessions': 0, 'interactions': 0, 'drivers': 0, 'findings': 0}
            
            # Export each session and related data
            for session_id in session_ids:
                session = self.load_session(session_id)
                if not session:
                    continue
                
                session_dir = output_path / session_id
                session_dir.mkdir(exist_ok=True)
                
                # Export session
                if format == 'json':
                    session_file = session_dir / "session.json"
                    with open(session_file, 'w') as f:
                        fast_json.dump(asdict(session), f, indent=2, default=str)
                
                export_stats['sessions'] += 1
                
                # Export related interactions
                interaction_files = self.subdirs['interactions'].glob(f"*{session_id}*.json*")
                for int_file in interaction_files:
                    shutil.copy2(int_file, session_dir)
                    export_stats['interactions'] += 1
                
                # Export related drivers
                driver_files = self.subdirs['drivers'].glob(f"*{session_id}*.json*")
                for driver_file in driver_files:
                    shutil.copy2(driver_file, session_dir)
                    export_stats['drivers'] += 1
                
                # Export security findings
                finding_files = self.subdirs['security'].glob(f"*{session_id}*.json*")
                for finding_file in finding_files:
                    shutil.copy2(finding_file, session_dir)
                    export_stats['findings'] += 1
            
            # Create export metadata
            metadata = {
                'export_timestamp': datetime.now().isoformat(),
                'export_stats': export_stats,
                'session_count': len(session_ids),
                'format': format,
                'compressed': compress
            }
            
            with open(output_path / 'export_metadata.json', 'w') as f:
                fast_json.dump(metadata, f, indent=2)
            
            # Compress if requested
            if compress:
                archive_path = output_path.with_suffix('.tar.gz')
                with tarfile.open(archive_path, 'w:gz') as tar:
                    tar.add(output_path, arcname=output_path.name)
                
                # Remove uncompressed directory
                shutil.rmtree(output_path)
                logger.info(f"Export completed: {archive_path}")
            else:
                logger.info(f"Export completed: {output_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False
    
    def cleanup_temp_files(self):
        """Clean up temporary files"""
        try:
            temp_dir = self.subdirs['temp']
            if temp_dir.exists():
                for temp_file in temp_dir.rglob('*'):
                    if temp_file.is_file():
                        try:
                            # Remove files older than 1 hour
                            if time.time() - temp_file.stat().st_mtime > 3600:
                                temp_file.unlink()
                        except OSError:
                            pass
        except Exception as e:
            logger.warning(f"Temp file cleanup failed: {e}")
    
    def shutdown(self, timeout: float = 30.0):
        """Graceful shutdown with timeout"""
        logger.info("Shutting down data manager...")
        
        try:
            # Stop accepting new writes
            if hasattr(self, 'write_queue'):
                self.write_queue.shutdown()
            
            # Wait for pending writes
            start_time = time.time()
            while (hasattr(self, 'write_queue') and 
                   self.write_queue.qsize > 0 and 
                   time.time() - start_time < timeout):
                time.sleep(0.1)
            
            # Cancel maintenance timer
            if hasattr(self, 'maintenance_timer'):
                self.maintenance_timer.cancel()
            
            # Shutdown thread pools
            if hasattr(self, 'thread_pool'):
                self.thread_pool.shutdown(wait=True)
            
            if hasattr(self, 'process_pool'):
                self.process_pool.shutdown(wait=True)
            
            # Stop async loop
            if hasattr(self, '_loop'):
                self._loop.call_soon_threadsafe(self._loop.stop)
            
            # Clean up temp files
            self.cleanup_temp_files()
            
            logger.info("Data manager shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")

class ConcurrentSessionManager:
    """Manages multiple concurrent monitoring sessions"""
    
    def __init__(self, data_manager: AdvancedTextDataManager, max_sessions: int = 10):
        self.data_manager = data_manager
        self.max_sessions = max_sessions
        self.active_sessions: Dict[str, CIFuzzSparkSession] = {}
        self.session_locks: Dict[str, threading.RLock] = {}
        self.session_threads: Dict[str, threading.Thread] = {}
        self.global_lock = threading.RLock()
        
    @contextmanager
    def session_lock(self, session_id: str):
        """Thread-safe session access"""
        if session_id not in self.session_locks:
            with self.global_lock:
                if session_id not in self.session_locks:
                    self.session_locks[session_id] = threading.RLock()
        
        with self.session_locks[session_id]:
            yield
    
    def add_session(self, session: CIFuzzSparkSession) -> bool:
        """Add new session with capacity check"""
        with self.global_lock:
            if len(self.active_sessions) >= self.max_sessions:
                logger.warning(f"Maximum sessions ({self.max_sessions}) reached")
                return False
            
            self.active_sessions[session.session_id] = session
            logger.info(f"Added session {session.session_id} ({len(self.active_sessions)} active)")
            return True
    
    def remove_session(self, session_id: str):
        """Remove session and cleanup"""
        with self.global_lock:
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
                
                # Clean up thread reference
                if session_id in self.session_threads:
                    del self.session_threads[session_id]
                
                logger.info(f"Removed session {session_id} ({len(self.active_sessions)} active)")
    
    def get_session(self, session_id: str) -> Optional[CIFuzzSparkSession]:
        """Get session thread-safely"""
        with self.session_lock(session_id):
            return self.active_sessions.get(session_id)
    
    def update_session(self, session_id: str, **updates):
        """Update session attributes thread-safely"""
        with self.session_lock(session_id):
            session = self.active_sessions.get(session_id)
            if session:
                for key, value in updates.items():
                    if hasattr(session, key):
                        setattr(session, key, value)
                
                # Save updated session
                self.data_manager.save_session(session)
    
    def list_active_sessions(self) -> List[str]:
        """List active session IDs"""
        with self.global_lock:
            return list(self.active_sessions.keys())
    
    def get_session_count(self) -> int:
        """Get active session count"""
        with self.global_lock:
            return len(self.active_sessions)

# Performance monitoring
class PerformanceMonitor:
    """Monitor storage and I/O performance"""
    
    def __init__(self):
        self.metrics = {
            'write_latency': [],
            'read_latency': [],
            'queue_depth': [],
            'compression_ratio': [],
            'error_rate': []
        }
        self.start_time = time.time()
    
    def record_write_latency(self, latency_ms: float):
        """Record write operation latency"""
        self.metrics['write_latency'].append(latency_ms)
        self._trim_metrics('write_latency')
    
    def record_read_latency(self, latency_ms: float):
        """Record read operation latency"""
        self.metrics['read_latency'].append(latency_ms)
        self._trim_metrics('read_latency')
    
    def _trim_metrics(self, metric_name: str, max_samples: int = 1000):
        """Keep only recent metrics"""
        if len(self.metrics[metric_name]) > max_samples:
            self.metrics[metric_name] = self.metrics[metric_name][-max_samples:]
    
    def get_performance_summary(self) -> Dict[str, float]:
        """Get performance summary statistics"""
        summary = {}
        
        for metric_name, values in self.metrics.items():
            if values:
                summary[f"{metric_name}_avg"] = sum(values) / len(values)
                summary[f"{metric_name}_max"] = max(values)
                summary[f"{metric_name}_min"] = min(values)
        
        summary['uptime_hours'] = (time.time() - self.start_time) / 3600
        return summary

# Export public API
__all__ = [
    'AdvancedTextDataManager',
    'ConcurrentSessionManager', 
    'AsyncWriteQueue',
    'FileRotationManager',
    'CompressedStorageHandler',
    'PerformanceMonitor'
]