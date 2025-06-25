#!/usr/bin/env python3
"""
Comprehensive LLM Fuzzing Monitor - Main Runner Script
Master's Thesis Research: "Enhancing Automated Security Testing in CI/CD/CT Pipelines with Large Language Models"

Author: Morris Darren Babu
Date: 2025-06-25 17:23:42 UTC
User: DARREN-2000
Version: 3.0.0
License: MIT

This is the main entry point for the CI Fuzz LLM Monitor.
It provides a simple interface to run the comprehensive monitoring system.
"""

import os
import sys
import time
import signal
import argparse
import subprocess
import json
import threading
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

# Fix import paths - get the correct project root
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent  # This is llm_comparative_study/
MONITOR_DIR = SCRIPT_DIR          # This is llm_comparative_study/cifuzz_monitor/

# Add paths for imports
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(MONITOR_DIR))

# Try importing psutil for process management
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️  psutil not available - limited process management")

def safe_get_username():
    """Safely get username"""
    try:
        return os.getenv('USER') or os.getenv('USERNAME') or 'UNKNOWN'
    except:
        return 'UNKNOWN'

def print_banner():
    """Print welcome banner"""
    username = safe_get_username()
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🚀 CI Fuzz LLM Monitor v3.0.0                            ║
║                                                                              ║
║  Master's Thesis Research Tool                                              ║
║  "Enhancing Automated Security Testing in CI/CD/CT Pipelines with LLMs"    ║
║                                                                              ║
║  Author: Morris Darren Babu                                                 ║
║  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}                                        ║
║  User: {username.upper():<20}                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_quick_help():
    """Print quick help information"""
    help_text = """
🎯 Quick Start Commands:

  📍 Basic Operations:
    python cifuzz_monitor/run_monitor.py start                    # Start monitoring daemon
    python cifuzz_monitor/run_monitor.py status                   # Check daemon status  
    python cifuzz_monitor/run_monitor.py stop                     # Stop daemon
    python cifuzz_monitor/run_monitor.py logs                     # View recent logs

  🔍 Analysis Operations:
    python cifuzz_monitor/run_monitor.py analyze                  # Analyze recent data
    python cifuzz_monitor/run_monitor.py export                   # Export research data
    python cifuzz_monitor/run_monitor.py report                   # Generate summary report

  ⚙️  Advanced Options:
    python cifuzz_monitor/run_monitor.py start --foreground       # Run in foreground
    python cifuzz_monitor/run_monitor.py start --verbose          # Enable verbose logging
    python cifuzz_monitor/run_monitor.py start --project /path    # Custom project path

  📚 Help & Documentation:
    python cifuzz_monitor/run_monitor.py help                     # Show detailed help
    python cifuzz_monitor/run_monitor.py check                    # Check dependencies

"""
    print(help_text)

def check_dependencies():
    """Check if required dependencies are available"""
    required_modules = [
        ('os', 'Operating system interface'),
        ('sys', 'System-specific parameters'),
        ('json', 'JSON encoder/decoder'),
        ('subprocess', 'Subprocess management'),
        ('pathlib', 'Object-oriented filesystem paths'),
    ]
    
    optional_modules = [
        ('psutil', 'Process and system monitoring'),
        ('numpy', 'Numerical analysis'),
        ('requests', 'HTTP requests'),
        ('rich', 'Rich terminal output'),
        ('click', 'CLI framework'),
        ('watchdog', 'File system monitoring'),
        ('yaml', 'YAML parser'),
    ]
    
    print("🔍 Checking dependencies...")
    
    missing_required = []
    for module, description in required_modules:
        try:
            __import__(module)
            print(f"  ✅ {module:<12} - {description}")
        except ImportError:
            print(f"  ❌ {module:<12} - {description} (REQUIRED)")
            missing_required.append(module)
    
    missing_optional = []
    for module, description in optional_modules:
        try:
            __import__(module)
            print(f"  ✅ {module:<12} - {description}")
        except ImportError:
            print(f"  ⚠️  {module:<12} - {description} (OPTIONAL)")
            missing_optional.append(module)
    
    if missing_required:
        print(f"\n❌ Missing required dependencies: {', '.join(missing_required)}")
        return False
    
    if missing_optional:
        print(f"\n💡 Optional dependencies not found: {', '.join(missing_optional)}")
        print("📦 Install for enhanced features: pip install " + " ".join(missing_optional))
    
    print("✅ Dependency check completed\n")
    return True

def validate_environment():
    """Validate the runtime environment"""
    print("🔍 Validating environment...")
    
    # Check Python version
    python_version = sys.version_info
    if python_version < (3, 8):
        print(f"❌ Python 3.8+ required, found {python_version.major}.{python_version.minor}")
        return False
    else:
        print(f"✅ Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    # Check platform
    import platform
    system = platform.system()
    print(f"✅ Platform: {system} {platform.release()}")
    
    # Check available disk space
    try:
        disk_usage = shutil.disk_usage(PROJECT_ROOT)
        free_space_gb = disk_usage.free / (1024**3)
        print(f"✅ Available disk space: {free_space_gb:.1f} GB")
        
        if free_space_gb < 1.0:
            print("⚠️  Low disk space warning: Less than 1GB available")
    except Exception:
        print("⚠️  Could not check disk space")
    
    # Check write permissions
    test_file = PROJECT_ROOT / ".test_write_permission"
    try:
        test_file.write_text("test")
        test_file.unlink()
        print("✅ Write permissions: OK")
    except Exception as e:
        print(f"❌ Write permissions: FAILED - {e}")
        return False
    
    print("✅ Environment validation completed\n")
    return True

def create_data_directory():
    """Create the data directory for monitoring"""
    data_dir = PROJECT_ROOT / ".cifuzz_research_data"
    data_dir.mkdir(exist_ok=True)
    
    # Create subdirectories
    subdirs = ['logs', 'sessions', 'analysis', 'exports', 'temp']
    for subdir in subdirs:
        (data_dir / subdir).mkdir(exist_ok=True)
    
    return data_dir

def check_monitor_status():
    """Check if monitor is running"""
    data_dir = PROJECT_ROOT / ".cifuzz_research_data"
    status_file = data_dir / "monitor_status.json"
    pid_file = data_dir / "monitor.pid"
    
    if not status_file.exists() and not pid_file.exists():
        return False, None, "Not running"
    
    # Check PID file first
    if pid_file.exists():
        try:
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            if PSUTIL_AVAILABLE:
                if psutil.pid_exists(pid):
                    process = psutil.Process(pid)
                    if process.is_running():
                        return True, pid, "Running"
                
                # Remove stale PID file
                pid_file.unlink()
                if status_file.exists():
                    status_file.unlink()
                return False, None, "Stale PID file removed"
            else:
                # Without psutil, just check if PID file exists
                return True, pid, "Running (unverified)"
                
        except (ValueError, FileNotFoundError):
            if pid_file.exists():
                pid_file.unlink()
    
    # Check status file
    if status_file.exists():
        try:
            with open(status_file, 'r') as f:
                status_data = json.load(f)
            
            if status_data.get('active', False):
                return True, status_data.get('pid'), "Running"
            else:
                return False, None, "Inactive"
        except (json.JSONDecodeError, FileNotFoundError):
            if status_file.exists():
                status_file.unlink()
    
    return False, None, "Not running"

def start_monitor_simple(args):
    """Start monitor in simple mode"""
    print("🚀 Starting CI Fuzz Monitor (Simple Mode)...")
    print(f"📁 Project directory: {PROJECT_ROOT}")
    print(f"👤 User: {safe_get_username()}")
    print(f"🕐 Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    
    # Check if already running
    is_running, pid, status = check_monitor_status()
    if is_running:
        print(f"⚠️  Monitor already running (PID: {pid})")
        return 0
    
    # Create data directory
    data_dir = create_data_directory()
    
    # Create monitor status
    monitor_status = {
        "active": True,
        "mode": "simple",
        "start_time": datetime.now().isoformat(),
        "user": safe_get_username(),
        "pid": os.getpid(),
        "project_root": str(PROJECT_ROOT),
        "monitor_dir": str(MONITOR_DIR),
        "version": "3.0.0"
    }
    
    # Save status files
    status_file = data_dir / "monitor_status.json"
    pid_file = data_dir / "monitor.pid"
    
    with open(status_file, 'w') as f:
        json.dump(monitor_status, f, indent=2)
    
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    
    # Start log file
    log_file = data_dir / "logs" / f"monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file.parent.mkdir(exist_ok=True)
    
    def log_message(message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        log_entry = f"[{timestamp}] {message}"
        print(log_entry)
        with open(log_file, 'a') as f:
            f.write(log_entry + '\n')
    
    log_message("🚀 CI Fuzz Monitor started in simple mode")
    log_message(f"📁 Monitoring project: {PROJECT_ROOT}")
    log_message(f"💾 Data directory: {data_dir}")
    log_message(f"📋 Log file: {log_file}")
    
    if hasattr(args, 'foreground') and args.foreground:
        print("🔄 Running in foreground mode (Ctrl+C to stop)...")
        log_message("🔄 Running in foreground mode")
        
        try:
            # Simple monitoring loop
            session_count = 0
            while True:
                # Check for CI Fuzz processes
                if PSUTIL_AVAILABLE:
                    cifuzz_processes = [p for p in psutil.process_iter(['pid', 'name', 'cmdline']) 
                                      if p.info['name'] and 'cifuzz' in p.info['name'].lower()]
                    
                    if cifuzz_processes:
                        session_count += 1
                        log_message(f"🔍 Detected CI Fuzz session #{session_count}")
                        for proc in cifuzz_processes:
                            log_message(f"   Process: {proc.info['name']} (PID: {proc.info['pid']})")
                
                time.sleep(10)  # Check every 10 seconds
                
        except KeyboardInterrupt:
            log_message("⚠️  Monitor stopped by user")
            print("\n⚠️  Monitor stopped by user")
        finally:
            # Cleanup
            if status_file.exists():
                status_file.unlink()
            if pid_file.exists():
                pid_file.unlink()
            log_message("🛑 Monitor shutdown complete")
    else:
        print("✅ Monitor started in background mode")
        print(f"📊 PID: {os.getpid()}")
        print(f"📁 Data directory: {data_dir}")
        print(f"📋 Log file: {log_file}")
        print("📊 Check status with: python cifuzz_monitor/run_monitor.py status")
        log_message("✅ Monitor started in background mode")
    
    return 0

def handle_start_command(args):
    """Handle start command"""
    return start_monitor_simple(args)

def handle_status_command(args):
    """Handle status command"""
    print("📊 Checking monitor status...\n")
    
    is_running, pid, status = check_monitor_status()
    
    if is_running:
        print("✅ Monitor is running")
        print(f"   🔢 PID: {pid}")
        print(f"   📍 Status: {status}")
        
        # Try to get more info from status file
        data_dir = PROJECT_ROOT / ".cifuzz_research_data"
        status_file = data_dir / "monitor_status.json"
        
        if status_file.exists():
            try:
                with open(status_file, 'r') as f:
                    status_data = json.load(f)
                
                print(f"   🕐 Started: {status_data.get('start_time', 'Unknown')}")
                print(f"   👤 User: {status_data.get('user', 'Unknown')}")
                print(f"   📁 Project: {status_data.get('project_root', 'Unknown')}")
                print(f"   🔧 Mode: {status_data.get('mode', 'Unknown')}")
                
                if PSUTIL_AVAILABLE and pid:
                    try:
                        process = psutil.Process(pid)
                        print(f"   💻 CPU: {process.cpu_percent():.1f}%")
                        print(f"   🧠 Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB")
                    except:
                        pass
                
            except (json.JSONDecodeError, FileNotFoundError):
                pass
        
        # Check data directory
        data_dir = PROJECT_ROOT / ".cifuzz_research_data"
        if data_dir.exists():
            log_files = list((data_dir / "logs").glob("*.log")) if (data_dir / "logs").exists() else []
            print(f"   📋 Log files: {len(log_files)}")
        
        return 0
    else:
        print(f"❌ Monitor is not running ({status})")
        return 1

def handle_stop_command(args):
    """Handle stop command"""
    print("⏹️  Stopping CI Fuzz Monitor...")
    
    is_running, pid, status = check_monitor_status()
    
    if not is_running:
        print(f"⚠️  Monitor is not running ({status})")
        return 0
    
    data_dir = PROJECT_ROOT / ".cifuzz_research_data"
    status_file = data_dir / "monitor_status.json"
    pid_file = data_dir / "monitor.pid"
    
    if PSUTIL_AVAILABLE and pid:
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            # Wait for graceful shutdown
            try:
                process.wait(timeout=10)
                print("✅ Monitor stopped gracefully")
            except psutil.TimeoutExpired:
                print("⚠️  Graceful shutdown timeout, forcing termination...")
                process.kill()
                process.wait(timeout=5)
                print("✅ Monitor force stopped")
                
        except psutil.NoSuchProcess:
            print("⚠️  Process already terminated")
        except Exception as e:
            print(f"❌ Error stopping process: {e}")
    
    # Clean up files
    try:
        if status_file.exists():
            status_file.unlink()
        if pid_file.exists():
            pid_file.unlink()
        print("🧹 Cleaned up status files")
    except Exception as e:
        print(f"⚠️  Error cleaning up: {e}")
    
    return 0

def handle_logs_command(args):
    """Handle logs command"""
    data_dir = PROJECT_ROOT / ".cifuzz_research_data"
    logs_dir = data_dir / "logs"
    
    if not logs_dir.exists():
        print("❌ No logs directory found. Start the monitor first.")
        return 1
    
    log_files = list(logs_dir.glob("*.log"))
    if not log_files:
        print("❌ No log files found.")
        return 1
    
    # Get the most recent log file
    latest_log = max(log_files, key=lambda x: x.stat().st_mtime)
    
    print(f"📋 Monitor logs ({latest_log.name}):")
    print("=" * 80)
    
    try:
        lines_to_show = getattr(args, 'lines', 50)
        
        with open(latest_log, 'r') as f:
            all_lines = f.readlines()
            recent_lines = all_lines[-lines_to_show:]
            
            for line in recent_lines:
                print(line, end='')
    
    except Exception as e:
        print(f"❌ Error reading logs: {e}")
        return 1
    
    return 0

def create_argument_parser():
    """Create the argument parser"""
    parser = argparse.ArgumentParser(
        description="🚀 Comprehensive LLM Fuzzing Monitor Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cifuzz_monitor/run_monitor.py start                     # Start monitoring
  python cifuzz_monitor/run_monitor.py status                    # Check status  
  python cifuzz_monitor/run_monitor.py stop                      # Stop daemon
  python cifuzz_monitor/run_monitor.py logs                      # View logs
        """
    )
    
    # Global options
    parser.add_argument('--project', help='Project directory to monitor')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start the monitor')
    start_parser.add_argument('--foreground', action='store_true', help='Run in foreground')
    
    # Status command  
    subparsers.add_parser('status', help='Check monitor status')
    
    # Stop command
    subparsers.add_parser('stop', help='Stop the monitor')
    
    # Logs command
    logs_parser = subparsers.add_parser('logs', help='View monitor logs')
    logs_parser.add_argument('--lines', '-n', type=int, default=50, help='Number of recent lines to show')
    
    # Help commands
    subparsers.add_parser('help', help='Show detailed help')
    subparsers.add_parser('check', help='Check dependencies and environment')
    
    return parser

def main():
    """Main entry point"""
    # Parse arguments
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Handle no command case
    if not args.command:
        print_banner()
        print_quick_help()
        return 0
    
    # Handle special commands that don't need full validation
    if args.command == 'help':
        print_banner()
        parser.print_help()
        print_quick_help()
        return 0
    elif args.command == 'check':
        print_banner()
        if not check_dependencies():
            return 1
        if not validate_environment():
            return 1
        print("✅ All checks passed!")
        return 0
    
    # For operational commands, do basic validation
    print_banner()
    
    if not check_dependencies():
        return 1
    
    if not validate_environment():
        return 1
    
    # Route to appropriate handler
    command_handlers = {
        'start': handle_start_command,
        'status': handle_status_command,
        'stop': handle_stop_command,
        'logs': handle_logs_command,
    }
    
    handler = command_handlers.get(args.command)
    if handler:
        try:
            return handler(args)
        except KeyboardInterrupt:
            print("\n⚠️  Interrupted by user")
            return 0
        except Exception as e:
            print(f"❌ Command failed: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
            return 1
    else:
        print(f"❌ Unknown command: {args.command}")
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())