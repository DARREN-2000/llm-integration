#!/usr/bin/env python3
"""
Automated LLM Comparative Study Runner
Runs CI Fuzz Spark across all repo-model combinations
"""

import os
import sys
import subprocess
import shutil
import time
import json
from pathlib import Path
from datetime import datetime
import tempfile

# Your repositories organized by complexity
REPOSITORIES = {
    'small': [
        'miniz', 'zlib', 'stb', 'minimp3', 'tinyexpr', 'tinycrypto',
        'nlohmann/json', 'fmt', 'glm', 'spdlog', 're2', 'cereal',
        'rapidjson', 'yaml-cpp', 'tinyxml2', 'pugixml', 'Catch2',
        'doctest', 'flatbuffers', 'date', 'zxing-cpp', 'simdjson',
        'fast_float', 'cxxopts', 'ghc-filesystem'
    ],
    'big': [
        'protobuf', 'abseil-cpp', 'leveldb', 'rocksdb', 'opencv',
        'llvm-project', 'grpc', 'folly', 'arrow', 'libigl',
        'assimp', 'ceres-solver', 'eigen', 'oneTBB', 'ogre',
        'meshoptimizer', 'glslang', 'Vulkan-Hpp', 'aws-sdk-cpp',
        'cpprestsdk', 'libtorrent', 'magnum', 'draco', 's2geometry',
        'opendnp3'
    ],
    'wrapper': [
        'boost', 'qtbase', 'tensorflow', 'bitcoin', 'tesseract', 'tink'
    ]
}

# Your Ollama models
OLLAMA_MODELS = [
    'phi4:14b', 'magistral:24b', 'starcoder2:15b', 'deepseek-r1:32b',
    'gemma3:27b', 'devstral:latest', 'mixtral:latest', 'yi:34b',
    'qwen3:32b', 'wizardcoder:33b', 'deepseek-coder:33b', 
    'codellama:34b-instruct', 'qwen2.5-coder:32b', 'llama3:latest'
]

class ExperimentRunner:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.experiments_dir = base_dir / "experiments"
        self.results_dir = base_dir / "results"
        self.temp_dir = base_dir / "temp"
        
        # Create directories
        for d in [self.experiments_dir, self.results_dir, self.temp_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Start monitor
        self.start_monitor()
        
        # Experiment tracking
        self.experiment_log = []
        self.current_experiment = None
    
    def start_monitor(self):
        """Start the comprehensive monitor"""
        print("🚀 Starting CI Fuzz Monitor...")
        
        monitor_cmd = [
            sys.executable, "run_monitor.py", "start",
            "--project", str(self.base_dir),
            "--verbose"
        ]
        
        subprocess.Popen(monitor_cmd, cwd=self.base_dir / "cifuzz_monitor")
        time.sleep(5)  # Wait for monitor to start
        
        # Verify monitor is running
        status_cmd = [sys.executable, "run_monitor.py", "status"]
        result = subprocess.run(status_cmd, cwd=self.base_dir / "cifuzz_monitor", 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Monitor started successfully")
        else:
            print("❌ Monitor failed to start")
            sys.exit(1)
    
    def clone_or_update_repo(self, repo_name: str, category: str) -> Path:
        """Clone or update repository"""
        repo_dir = self.experiments_dir / category / "repos" / repo_name.replace('/', '_')
        
        if repo_dir.exists():
            print(f"📁 Repository {repo_name} already exists, pulling updates...")
            try:
                subprocess.run(['git', 'pull'], cwd=repo_dir, check=True, 
                             capture_output=True)
            except subprocess.CalledProcessError:
                print(f"⚠️  Failed to update {repo_name}, using existing version")
        else:
            print(f"📥 Cloning {repo_name}...")
            github_url = f"https://github.com/{repo_name}.git"
            try:
                subprocess.run(['git', 'clone', github_url, str(repo_dir)], 
                             check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to clone {repo_name}: {e}")
                return None
        
        return repo_dir
    
    def setup_cifuzz_for_repo(self, repo_dir: Path) -> bool:
        """Setup CI Fuzz for repository"""
        print(f"⚙️  Setting up CI Fuzz for {repo_dir.name}...")
        
        try:
            # Initialize CI Fuzz
            subprocess.run(['cifuzz', 'init'], cwd=repo_dir, check=True)
            
            # Check for existing fuzz targets
            cifuzz_dir = repo_dir / ".cifuzz-corpus"
            if not cifuzz_dir.exists():
                cifuzz_dir.mkdir()
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️  CI Fuzz setup failed for {repo_dir.name}: {e}")
            return False
        except FileNotFoundError:
            print("❌ CI Fuzz not installed. Install with: pip install cifuzz")
            return False
    
    def run_single_experiment(self, repo_name: str, category: str, model: str) -> dict:
        """Run single experiment: repo + model combination"""
        experiment_id = f"{category}_{repo_name.replace('/', '_')}_{model.replace(':', '_')}"
        timestamp = datetime.now().isoformat()
        
        print(f"\n🧪 Starting Experiment: {experiment_id}")
        print(f"📍 Repository: {repo_name} ({category})")
        print(f"🤖 Model: {model}")
        print(f"🕐 Time: {timestamp}")
        
        self.current_experiment = {
            'experiment_id': experiment_id,
            'repo_name': repo_name,
            'category': category,
            'model': model,
            'start_time': timestamp,
            'status': 'running',
            'results': {}
        }
        
        # Clone/update repository
        repo_dir = self.clone_or_update_repo(repo_name, category)
        if not repo_dir:
            self.current_experiment['status'] = 'failed'
            self.current_experiment['error'] = 'Repository clone failed'
            return self.current_experiment
        
        # Setup CI Fuzz
        if not self.setup_cifuzz_for_repo(repo_dir):
            self.current_experiment['status'] = 'failed'
            self.current_experiment['error'] = 'CI Fuzz setup failed'
            return self.current_experiment
        
        # Clean previous generated code
        self.clean_generated_code(repo_dir)
        
        # Set environment for this experiment
        env = os.environ.copy()
        env.update({
            'CIFUZZ_LLM_MODEL': model,
            'CIFUZZ_LLM_PROVIDER': 'ollama',
            'CIFUZZ_EXPERIMENT_ID': experiment_id,
            'OLLAMA_MODEL': model
        })
        
        try:
            # Run CI Fuzz Spark with specific model
            print(f"🔥 Running CI Fuzz Spark with {model}...")
            
            spark_cmd = [
                'cifuzz', 'spark', 
                '--llm-model', model,
                '--llm-provider', 'ollama',
                '--timeout', '300',  # 5 minutes per experiment
                '--trials', '5',     # 5 generation attempts
                '--verbose'
            ]
            
            start_time = time.time()
            result = subprocess.run(
                spark_cmd, 
                cwd=repo_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute total timeout
            )
            
            duration = time.time() - start_time
            
            # Record results
            self.current_experiment.update({
                'duration_seconds': duration,
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'status': 'completed' if result.returncode == 0 else 'failed'
            })
            
            # Analyze generated code
            self.analyze_generated_code(repo_dir, experiment_id)
            
            print(f"✅ Experiment completed in {duration:.1f}s")
            
        except subprocess.TimeoutExpired:
            self.current_experiment.update({
                'status': 'timeout',
                'error': 'Experiment timed out after 10 minutes'
            })
            print("⏰ Experiment timed out")
            
        except Exception as e:
            self.current_experiment.update({
                'status': 'error',
                'error': str(e)
            })
            print(f"❌ Experiment failed: {e}")
        
        # Save experiment results
        self.save_experiment_results()
        
        # Clean up for next experiment
        self.clean_generated_code(repo_dir)
        
        return self.current_experiment
    
    def clean_generated_code(self, repo_dir: Path):
        """Clean generated code from previous runs"""
        print("🧹 Cleaning generated code...")
        
        # Common CI Fuzz generated directories/files
        cleanup_patterns = [
            '.cifuzz-build',
            '.cifuzz-corpus', 
            'fuzz_targets',
            '*_fuzz_test.cpp',
            '*_fuzz_test.c',
            'cifuzz_*',
            'CMakeFiles',
            'build'
        ]
        
        for pattern in cleanup_patterns:
            for item in repo_dir.glob(pattern):
                try:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                except Exception as e:
                    print(f"⚠️  Failed to clean {item}: {e}")
    
    def analyze_generated_code(self, repo_dir: Path, experiment_id: str):
        """Analyze generated code and compilation results"""
        print("🔍 Analyzing generated code...")
        
        analysis = {
            'generated_files': [],
            'compilation_success': False,
            'compilation_errors': [],
            'code_metrics': {}
        }
        
        # Find generated fuzz targets
        fuzz_files = list(repo_dir.glob('**/*fuzz*'))
        fuzz_files.extend(repo_dir.glob('**/*test*.c*'))
        
        for fuzz_file in fuzz_files:
            if fuzz_file.is_file() and fuzz_file.suffix in ['.c', '.cpp', '.cc']:
                analysis['generated_files'].append(str(fuzz_file.relative_to(repo_dir)))
                
                # Basic code analysis
                try:
                    with open(fuzz_file, 'r') as f:
                        content = f.read()
                        
                    analysis['code_metrics'][str(fuzz_file.name)] = {
                        'lines': len(content.split('\n')),
                        'size_bytes': len(content),
                        'has_main': 'int main' in content,
                        'has_fuzz_target': 'LLVMFuzzerTestOneInput' in content,
                        'includes_count': content.count('#include')
                    }
                    
                except Exception as e:
                    print(f"⚠️  Failed to analyze {fuzz_file}: {e}")
        
        # Try to compile
        try:
            compile_result = subprocess.run(
                ['cifuzz', 'build'], 
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            analysis['compilation_success'] = compile_result.returncode == 0
            if compile_result.stderr:
                analysis['compilation_errors'] = compile_result.stderr.split('\n')
                
        except Exception as e:
            analysis['compilation_errors'] = [str(e)]
        
        self.current_experiment['code_analysis'] = analysis
    
    def save_experiment_results(self):
        """Save individual experiment results"""
        if not self.current_experiment:
            return
        
        # Save to individual file
        experiment_file = (self.results_dir / 
                          f"{self.current_experiment['experiment_id']}.json")
        
        with open(experiment_file, 'w') as f:
            json.dump(self.current_experiment, f, indent=2, default=str)
        
        # Add to experiment log
        self.experiment_log.append(self.current_experiment.copy())
        
        # Save cumulative log
        log_file = self.results_dir / "experiment_log.json"
        with open(log_file, 'w') as f:
            json.dump(self.experiment_log, f, indent=2, default=str)
        
        print(f"💾 Results saved: {experiment_file}")
    
    def run_all_experiments(self, categories=None, models=None):
        """Run all experiment combinations"""
        if categories is None:
            categories = ['small', 'big']  # Skip wrapper for now
        if models is None:
            models = OLLAMA_MODELS
        
        total_experiments = sum(len(REPOSITORIES[cat]) for cat in categories) * len(models)
        current_exp = 0
        
        print(f"🚀 Starting {total_experiments} experiments...")
        print(f"📊 Categories: {categories}")
        print(f"🤖 Models: {len(models)} models")
        
        for category in categories:
            print(f"\n📁 Category: {category.upper()}")
            
            for repo_name in REPOSITORIES[category]:
                print(f"\n📦 Repository: {repo_name}")
                
                for model in models:
                    current_exp += 1
                    print(f"\n[{current_exp}/{total_experiments}] Testing {repo_name} with {model}")
                    
                    try:
                        result = self.run_single_experiment(repo_name, category, model)
                        
                        status_emoji = {
                            'completed': '✅',
                            'failed': '❌', 
                            'timeout': '⏰',
                            'error': '💥'
                        }.get(result['status'], '❓')
                        
                        print(f"{status_emoji} {result['status'].upper()}")
                        
                        # Brief pause between experiments
                        time.sleep(2)
                        
                    except KeyboardInterrupt:
                        print("\n⚠️  Interrupted by user")
                        self.generate_final_report()
                        return
                    except Exception as e:
                        print(f"💥 Experiment failed: {e}")
                        continue
        
        print(f"\n🎉 All {total_experiments} experiments completed!")
        self.generate_final_report()
    
    def generate_final_report(self):
        """Generate comprehensive comparative report"""
        print("\n📊 Generating final comparative report...")
        
        # Export data using monitor
        export_cmd = [
            sys.executable, "run_monitor.py", "export",
            str(self.results_dir / "monitor_data")
        ]
        subprocess.run(export_cmd, cwd=self.base_dir / "cifuzz_monitor")
        
        # Generate thesis report
        report_cmd = [sys.executable, "run_monitor.py", "report", "thesis"]
        subprocess.run(report_cmd, cwd=self.base_dir / "cifuzz_monitor")
        
        # Create custom comparative analysis
        self.create_comparative_analysis()
        
        print("✅ Final report generated!")
    
    def create_comparative_analysis(self):
        """Create custom comparative analysis"""
        if not self.experiment_log:
            return
        
        analysis = {
            'total_experiments': len(self.experiment_log),
            'completion_rate': len([e for e in self.experiment_log if e['status'] == 'completed']) / len(self.experiment_log),
            'model_performance': {},
            'repo_difficulty': {},
            'category_analysis': {},
            'generated_at': datetime.now().isoformat()
        }
        
        # Analyze by model
        for model in OLLAMA_MODELS:
            model_experiments = [e for e in self.experiment_log if e['model'] == model]
            if model_experiments:
                success_rate = len([e for e in model_experiments if e['status'] == 'completed']) / len(model_experiments)
                avg_duration = sum(e.get('duration_seconds', 0) for e in model_experiments) / len(model_experiments)
                
                analysis['model_performance'][model] = {
                    'experiments': len(model_experiments),
                    'success_rate': success_rate,
                    'avg_duration_seconds': avg_duration,
                    'total_generated_files': sum(len(e.get('code_analysis', {}).get('generated_files', [])) for e in model_experiments)
                }
        
        # Analyze by repository
        all_repos = []
        for cat_repos in REPOSITORIES.values():
            all_repos.extend(cat_repos)
        
        for repo in all_repos:
            repo_key = repo.replace('/', '_')
            repo_experiments = [e for e in self.experiment_log if e['repo_name'] == repo]
            if repo_experiments:
                success_rate = len([e for e in repo_experiments if e['status'] == 'completed']) / len(repo_experiments)
                
                analysis['repo_difficulty'][repo] = {
                    'experiments': len(repo_experiments),
                    'success_rate': success_rate,
                    'difficulty_score': 1.0 - success_rate  # Higher = more difficult
                }
        
        # Save analysis
        analysis_file = self.results_dir / "comparative_analysis.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        print(f"📊 Comparative analysis saved: {analysis_file}")

def main():
    """Main experiment runner"""
    base_dir = Path.cwd()
    
    print("🧪 LLM Comparative Study Runner")
    print(f"📁 Base directory: {base_dir}")
    
    runner = ExperimentRunner(base_dir)
    
    # You can customize which experiments to run
    try:
        # Start with small repositories for testing
        runner.run_all_experiments(
            categories=['small'],  # Start with small repos
            models=['llama3:latest', 'codellama:34b-instruct', 'deepseek-coder:33b']  # Test with 3 models first
        )
        
        # Uncomment to run all experiments
        # runner.run_all_experiments()
        
    except KeyboardInterrupt:
        print("\n⚠️  Experiment interrupted by user")
    except Exception as e:
        print(f"❌ Experiment runner failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()