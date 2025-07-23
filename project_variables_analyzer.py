#!/usr/bin/env python3
"""
Project Variable Analyzer - Variable Analysis with Best Practice Categorization

Analyzes project variables in source code files and categorizes them based on industry best practices:
- 12-Factor App methodology for configuration management
- Domain-Driven Design for business logic separation  
- Clean Code principles for maintainability
- SRE Best Practices for observability
- Zero Trust Security for credential management
- And more established software engineering patterns

Intelligently filters files:
- Includes: Source code, configuration files, scripts
- Excludes: Documentation, notebooks, data files, binaries, media files
- Respects: .gitignore patterns

Performance optimized:
- Skips directories like node_modules, __pycache__, venv
- Ignores generated and compiled files
- Focuses only on human-written source code

Generates comprehensive reports in JSON, HTML, and CSV formats.
Output location: /users/timweber/dev/<project_name>/project_analysis/variables/
"""

import os
import re
import ast
import json
import csv
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import argparse
from typing import Dict, List, Set, Tuple, Optional
import fnmatch

class VariableAnalyzer:
    """Enhanced variable analysis with context and categorization based on best practices"""
    
    # Define usage categories based on industry best practices
    USAGE_CATEGORIES = {
        'configuration': {
            'description': 'Application configuration and environment settings (12-Factor App principle)',
            'patterns': ['env', 'config', 'setting', 'option', 'flag', 'feature'],
            'file_patterns': ['.env', 'config', 'settings'],
            'examples': 'DATABASE_URL, API_TIMEOUT, FEATURE_FLAG'
        },
        'infrastructure': {
            'description': 'Infrastructure and deployment configuration (Infrastructure as Code)',
            'patterns': ['host', 'port', 'server', 'cluster', 'region', 'zone', 'container'],
            'file_patterns': ['docker', 'k8s', 'terraform', 'ansible'],
            'examples': 'REDIS_HOST, SERVER_PORT, AWS_REGION'
        },
        'authentication': {
            'description': 'Authentication, authorization, and security credentials (Zero Trust Security)',
            'patterns': ['auth', 'token', 'key', 'secret', 'password', 'credential', 'jwt', 'oauth'],
            'context_patterns': ['authenticate', 'authorize', 'permission'],
            'examples': 'API_KEY, JWT_SECRET, OAUTH_TOKEN'
        },
        'database': {
            'description': 'Database connections, queries, and ORM objects (Repository Pattern)',
            'patterns': ['db', 'database', 'conn', 'cursor', 'session', 'engine', 'pool', 'query'],
            'context_patterns': ['select', 'insert', 'update', 'delete', 'create table'],
            'examples': 'db_connection, query_result, session_factory'
        },
        'api_integration': {
            'description': 'External API endpoints and integration points (Service-Oriented Architecture)',
            'patterns': ['api', 'endpoint', 'webhook', 'service', 'client', 'sdk'],
            'context_patterns': ['http', 'https', 'rest', 'graphql', 'soap'],
            'examples': 'payment_api, webhook_url, service_client'
        },
        'data_processing': {
            'description': 'Data transformation, ETL, and analytics variables (Data Pipeline Pattern)',
            'patterns': ['df', 'data', 'dataset', 'transform', 'pipeline', 'etl', 'batch'],
            'context_patterns': ['pandas', 'numpy', 'spark', 'extract', 'transform', 'load'],
            'examples': 'raw_data, transformed_df, pipeline_config'
        },
        'business_logic': {
            'description': 'Core business rules and domain logic (Domain-Driven Design)',
            'patterns': ['calc', 'compute', 'process', 'validate', 'rule', 'policy', 'strategy'],
            'context_patterns': ['calculate', 'validate', 'process', 'business'],
            'examples': 'price_calculator, validation_rules, business_policy'
        },
        'monitoring': {
            'description': 'Observability, metrics, and monitoring (SRE Best Practices)',
            'patterns': ['metric', 'counter', 'gauge', 'histogram', 'trace', 'span', 'monitor'],
            'context_patterns': ['prometheus', 'datadog', 'newrelic', 'telemetry'],
            'examples': 'request_counter, latency_histogram, trace_id'
        },
        'logging': {
            'description': 'Structured logging and debugging (Observability Pattern)',
            'patterns': ['log', 'logger', 'debug', 'trace', 'audit'],
            'context_patterns': ['logging', 'loguru', 'winston', 'log4j'],
            'examples': 'app_logger, audit_log, debug_flag'
        },
        'caching': {
            'description': 'Cache management and temporary storage (Performance Pattern)',
            'patterns': ['cache', 'redis', 'memcache', 'ttl', 'expire'],
            'context_patterns': ['cache', 'memoize', 'lru', 'ttl'],
            'examples': 'redis_cache, cache_key, ttl_seconds'
        },
        'messaging': {
            'description': 'Message queues and event streaming (Event-Driven Architecture)',
            'patterns': ['queue', 'topic', 'channel', 'publisher', 'subscriber', 'kafka', 'rabbit'],
            'context_patterns': ['publish', 'subscribe', 'message', 'event'],
            'examples': 'message_queue, event_topic, publisher_client'
        },
        'file_operations': {
            'description': 'File system operations and I/O handling (Clean Code Principle)',
            'patterns': ['path', 'file', 'dir', 'folder', 'stream', 'buffer'],
            'context_patterns': ['open(', 'read(', 'write(', 'exists('],
            'examples': 'input_file_path, output_dir, file_buffer'
        },
        'testing': {
            'description': 'Test fixtures, mocks, and test data (Test-Driven Development)',
            'patterns': ['test', 'mock', 'fixture', 'stub', 'fake', 'assert'],
            'file_patterns': ['test_', '_test', 'spec_', '_spec'],
            'examples': 'test_data, mock_service, fixture_user'
        },
        'error_handling': {
            'description': 'Exception handling and error management (Defensive Programming)',
            'patterns': ['error', 'exception', 'err', 'fault', 'failure'],
            'context_patterns': ['try', 'catch', 'except', 'raise', 'throw'],
            'examples': 'error_message, exception_handler, retry_count'
        },
        'state_management': {
            'description': 'Application state and session management (State Pattern)',
            'patterns': ['state', 'status', 'session', 'context', 'store'],
            'context_patterns': ['state', 'session', 'context'],
            'examples': 'app_state, user_session, request_context'
        },
        'scheduling': {
            'description': 'Task scheduling and time-based operations (Cron Pattern)',
            'patterns': ['cron', 'schedule', 'timer', 'interval', 'delay'],
            'context_patterns': ['schedule', 'cron', 'celery', 'airflow'],
            'examples': 'cron_expression, scheduled_task, retry_delay'
        },
        'validation': {
            'description': 'Input validation and data integrity (Guard Clause Pattern)',
            'patterns': ['valid', 'schema', 'constraint', 'regex', 'pattern'],
            'context_patterns': ['validate', 'schema', 'pydantic', 'joi'],
            'examples': 'validation_schema, regex_pattern, constraints'
        },
        'model_ml': {
            'description': 'Machine learning models and AI components (MLOps Best Practices)',
            'patterns': ['model', 'predict', 'train', 'feature', 'tensor', 'weight'],
            'context_patterns': ['sklearn', 'tensorflow', 'pytorch', 'ml', 'ai'],
            'examples': 'trained_model, feature_vector, predictions'
        },
        'networking': {
            'description': 'Network communication and protocols (OSI Model)',
            'patterns': ['socket', 'tcp', 'udp', 'http', 'grpc', 'websocket'],
            'context_patterns': ['socket', 'connect', 'bind', 'listen'],
            'examples': 'tcp_socket, http_client, ws_connection'
        },
        'utilities': {
            'description': 'Helper functions and utility variables (DRY Principle)',
            'patterns': ['util', 'helper', 'common', 'shared', 'tools'],
            'context_patterns': ['utility', 'helper', 'common'],
            'examples': 'string_utils, date_helper, common_regex'
        }
    }
    
    # File extensions to analyze (where variables are meaningful)
    ANALYZABLE_EXTENSIONS = {
        # Source code
        '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs', '.cpp', '.c',
        '.jsx', '.tsx', '.vue', '.swift', '.kt', '.scala', '.rs', '.r', '.m',
        # Configuration
        '.yml', '.yaml', '.ini', '.conf', '.cfg', '.env', '.toml',
        # Shell scripts
        '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
        # Build files
        '.gradle', '.sbt', '.cmake',
        # Special files without extensions
        'Makefile', 'Dockerfile', 'Jenkinsfile', 'Vagrantfile'
    }
    
    # File extensions to explicitly exclude
    EXCLUDED_EXTENSIONS = {
        # Documentation
        '.md', '.rst', '.txt', '.adoc', '.doc', '.docx', '.pdf',
        # Data files
        '.csv', '.xls', '.xlsx', '.json', '.xml', '.parquet', '.avro',
        # Notebooks (contain output, not just source)
        '.ipynb', '.rmd',
        # Logs and output
        '.log', '.out', '.err', '.dump',
        # Binary and compiled
        '.pyc', '.pyo', '.class', '.o', '.so', '.dll', '.exe', '.bin',
        '.whl', '.egg', '.jar', '.war',
        # Media
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.mp4', '.mp3',
        '.wav', '.avi', '.mov', '.webm', '.webp',
        # Archives
        '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
        # Database files
        '.db', '.sqlite', '.sqlite3',
        # Other
        '.lock', '.cache', '.tmp', '.temp', '.bak', '.swp'
    }
    
    # Directories to skip
    EXCLUDED_DIRS = {
        '__pycache__', '.pytest_cache', '.tox', '.eggs', 'egg-info',
        'node_modules', 'bower_components', 'jspm_packages',
        'vendor', 'venv', 'env', '.env', 'virtualenv',
        'build', 'dist', 'target', 'out', 'bin',
        '.git', '.svn', '.hg', '.bzr',
        'coverage', 'htmlcov', '.coverage',
        '.idea', '.vscode', '.eclipse'
    }
    
    def __init__(self):
        self.variables = {}
        
    def should_analyze_file(self, file_path: Path) -> bool:
        """Determine if a file should be analyzed for variables"""
        file_name = file_path.name.lower()
        extension = file_path.suffix.lower()
        
        # Check if in excluded directory
        parts = file_path.parts
        for part in parts:
            if part in self.EXCLUDED_DIRS:
                return False
        
        # Exclude specific extensions
        if extension in self.EXCLUDED_EXTENSIONS:
            return False
        
        # Exclude data files by name patterns
        if any(pattern in file_name for pattern in ['sample', 'example', 'test_data', 'mock_data']):
            if extension in {'.json', '.xml', '.csv'}:
                return False
        
        # Include if it has an analyzable extension
        if extension in self.ANALYZABLE_EXTENSIONS:
            return True
        
        # Include special files without extensions
        if file_name in ['makefile', 'dockerfile', 'jenkinsfile', 'vagrantfile', 'rakefile']:
            return True
        
        # Include if no extension but appears to be a script
        if not extension and file_path.is_file():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('#!'):  # Shebang line
                        return True
            except:
                pass
        
        # Exclude everything else
        return False
        
    def categorize_variable(self, var_name: str, context: str, file_path: str) -> str:
        """Categorize variable based on best practice patterns"""
        var_lower = var_name.lower()
        context_lower = context.lower()
        file_path_lower = file_path.lower()
        
        # Check each category in order of specificity
        for category, config in self.USAGE_CATEGORIES.items():
            # Check variable name patterns
            if any(pattern in var_lower for pattern in config['patterns']):
                return category
                
            # Check file path patterns
            if 'file_patterns' in config:
                if any(pattern in file_path_lower for pattern in config['file_patterns']):
                    return category
                    
            # Check context patterns
            if 'context_patterns' in config:
                if any(pattern in context_lower for pattern in config['context_patterns']):
                    return category
        
        # Special case: UPPERCASE variables are typically configuration
        if var_name.isupper() or ('_' in var_name and var_name.upper() == var_name):
            return 'configuration'
            
        # Default to utilities for general variables
        return 'utilities'
    
    def generate_description(self, var_name: str, context: str, category: str) -> str:
        """Generate a brief description based on variable name and context"""
        var_lower = var_name.lower()
        
        # Get category description if available
        if category in self.USAGE_CATEGORIES:
            base_description = self.USAGE_CATEGORIES[category]['description']
            
            # Add specific details based on variable name
            if 'url' in var_lower:
                return f"URL endpoint - {base_description}"
            elif 'path' in var_lower:
                return f"File system path - {base_description}"
            elif 'config' in var_lower:
                return f"Configuration value - {base_description}"
            elif 'logger' in var_lower:
                return f"Logger instance - {base_description}"
            elif 'client' in var_lower:
                return f"Client connection - {base_description}"
            elif 'df' in var_lower or 'dataframe' in var_lower:
                return f"DataFrame - {base_description}"
            elif 'conn' in var_lower or 'connection' in var_lower:
                return f"Connection object - {base_description}"
            elif 'key' in var_lower or 'secret' in var_lower:
                return f"Security credential - {base_description}"
            elif 'model' in var_lower:
                return f"ML model - {base_description}"
            elif 'metric' in var_lower:
                return f"Performance metric - {base_description}"
            elif 'queue' in var_lower:
                return f"Message queue - {base_description}"
            elif 'cache' in var_lower:
                return f"Cache instance - {base_description}"
            else:
                # Return the category description
                return base_description.split(' (')[0]  # Remove the pattern name in parentheses
        
        # Fallback to generic description
        return f"General purpose variable in {category} context"


class ProjectAnalyzer:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir).resolve()
        self.project_name = self.root_dir.name
        self.output_dir = Path(f"/users/timweber/dev/{self.project_name}/project_analysis/variables")
        self.files = []
        self.variable_analyzer = VariableAnalyzer()
        self.variables_detailed = {}
        self.functions = defaultdict(list)
        self.paths = {
            'filesystem': defaultdict(list),
            'url': defaultdict(list),
            'import': defaultdict(list)
        }
        self.gitignore_patterns = self._load_gitignore()
        # Add output files to ignore
        self.gitignore_patterns.extend([
            'project_variable_analyzer.py',
            'project_analysis.json',
            'project_analysis.html',
            'project_analysis_*.csv',
            'project_analysis/*'
        ])
        
    def _ensure_output_directory(self):
        """Create output directory if it doesn't exist"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        print(f"Output directory: {self.output_dir}")
        
    def _load_gitignore(self) -> List[str]:
        """Load .gitignore patterns"""
        patterns = []
        gitignore_path = self.root_dir / '.gitignore'
        if gitignore_path.exists():
            with open(gitignore_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.append(line)
        return patterns
    
    def _should_ignore(self, file_path: Path) -> bool:
        """Check if file should be ignored based on .gitignore patterns"""
        relative_path = file_path.relative_to(self.root_dir)
        path_str = str(relative_path).replace('\\', '/')
        
        for pattern in self.gitignore_patterns:
            if fnmatch.fnmatch(path_str, pattern):
                return True
            if fnmatch.fnmatch(os.path.basename(path_str), pattern):
                return True
        return False
    
    def scan_files(self):
        """Scan all files in the project directory"""
        print("Scanning project files (excluding docs, notebooks, binaries, data files)...")
        total_files = 0
        skipped_files = 0
        
        for root, dirs, files in os.walk(self.root_dir):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in self.variable_analyzer.EXCLUDED_DIRS 
                      and not self._should_ignore(Path(root) / d)]
            
            for file in files:
                total_files += 1
                file_path = Path(root) / file
                
                # Skip if in gitignore
                if self._should_ignore(file_path):
                    skipped_files += 1
                    continue
                
                # Skip if not analyzable
                if not self.variable_analyzer.should_analyze_file(file_path):
                    skipped_files += 1
                    continue
                
                relative_path = file_path.relative_to(self.root_dir)
                self.files.append({
                    'name': file,
                    'path': str(relative_path),
                    'absolute_path': str(file_path)
                })
        
        print(f"Found {len(self.files)} analyzable source files out of {total_files} total files")
        print(f"Skipped {skipped_files} files (docs, data, binaries, gitignored)")
    
    def analyze_python_file(self, file_path: str):
        """Analyze Python files using AST with enhanced variable analysis"""
        try:
            # Additional check for Python files (e.g., skip setup.py, __pycache__ files)
            path_obj = Path(file_path)
            if path_obj.name in ['setup.py', '__init__.py'] and path_obj.stat().st_size < 100:
                # Skip nearly empty init files
                return
                
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            relative_path = str(Path(file_path).relative_to(self.root_dir))
            lines = content.split('\n')
            
            # Extract variables with context
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            line_num = node.lineno - 1
                            
                            # Get context (surrounding lines)
                            start = max(0, line_num - 2)
                            end = min(len(lines), line_num + 3)
                            context = '\n'.join(lines[start:end])
                            
                            # Categorize and describe
                            category = self.variable_analyzer.categorize_variable(
                                var_name, context, relative_path
                            )
                            description = self.variable_analyzer.generate_description(
                                var_name, context, category
                            )
                            
                            # Create unique key for variable in this file
                            var_key = f"{var_name}_{relative_path}_{node.lineno}"
                            
                            self.variables_detailed[var_key] = {
                                'name': var_name,
                                'description': description,
                                'file_name': os.path.basename(file_path),
                                'file_path': relative_path,
                                'line': node.lineno,
                                'category': category,
                                'context_snippet': lines[line_num].strip() if line_num < len(lines) else ''
                            }
                
                # Also track function definitions
                elif isinstance(node, ast.FunctionDef):
                    self.functions[node.name].append({
                        'file': relative_path,
                        'line': node.lineno,
                        'type': 'definition'
                    })
            
            # Extract paths from strings
            self._extract_paths_from_content(content, relative_path)
            
        except Exception as e:
            print(f"Error analyzing Python file {file_path}: {e}")
    
    def analyze_generic_file(self, file_path: str):
        """Analyze non-Python files with enhanced variable detection"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            relative_path = str(Path(file_path).relative_to(self.root_dir))
            lines = content.split('\n')
            
            # Enhanced variable patterns for different file types
            file_ext = Path(file_path).suffix.lower()
            file_name = Path(file_path).name.lower()
            
            # Determine appropriate patterns based on file type
            if file_path.endswith('.env') or file_name == '.env':
                # Environment file pattern
                var_pattern = r'^([A-Z_][A-Z0-9_]*)\s*='
            elif file_ext in ['.yml', '.yaml']:
                # YAML pattern - captures top-level keys
                var_pattern = r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:'
            elif file_ext == '.json':
                # JSON pattern - captures object keys
                var_pattern = r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:'
            elif file_ext in ['.ini', '.conf', '.cfg']:
                # INI/Config file patterns
                var_pattern = r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*='
            elif file_ext in ['.sh', '.bash', '.zsh']:
                # Shell script variables
                var_pattern = r'^(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*='
            elif file_ext in ['.js', '.ts', '.jsx', '.tsx']:
                # JavaScript/TypeScript patterns
                var_pattern = r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*='
            elif file_ext == '.java':
                # Java variable declarations
                var_pattern = r'(?:private|public|protected|static|final)\s+\w+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*='
            elif file_ext == '.go':
                # Go variable declarations
                var_pattern = r'(?:var|const)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+'
            elif file_ext == '.rs':
                # Rust variable declarations
                var_pattern = r'(?:let|const|static)\s+(?:mut\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*='
            elif file_ext == '.rb':
                # Ruby variables and constants
                var_pattern = r'(?:^|\s)([A-Z_][A-Z0-9_]*|\$[a-zA-Z_][a-zA-Z0-9_]*|@{1,2}[a-zA-Z_][a-zA-Z0-9_]*)\s*='
            elif file_ext in ['.c', '.cpp', '.h', '.hpp']:
                # C/C++ variables
                var_pattern = r'(?:int|char|float|double|bool|string|auto)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*='
            else:
                # Generic pattern for other files
                var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*='
            
            # Extract variables with context
            for i, line in enumerate(lines):
                # Skip comments
                if file_ext in ['.py', '.rb', '.sh', '.bash', '.yml', '.yaml']:
                    if line.strip().startswith('#'):
                        continue
                elif file_ext in ['.js', '.ts', '.java', '.c', '.cpp', '.go', '.rs']:
                    if line.strip().startswith('//'):
                        continue
                
                match = re.search(var_pattern, line)
                if match:
                    var_name = match.group(1)
                    
                    # Skip language keywords and common non-variables
                    keywords = {
                        'function', 'class', 'if', 'else', 'for', 'while', 'return',
                        'import', 'export', 'package', 'module', 'namespace',
                        'true', 'false', 'null', 'undefined', 'none'
                    }
                    if var_name.lower() in keywords:
                        continue
                    
                    # Skip if it's likely a data value rather than a variable
                    if file_ext in ['.json', '.yml', '.yaml'] and var_name.lower() in ['id', 'name', 'type', 'value', 'description']:
                        # These are often data fields, not variables
                        continue
                    
                    # Get context
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    context = '\n'.join(lines[start:end])
                    
                    # Categorize and describe
                    category = self.variable_analyzer.categorize_variable(
                        var_name, context, relative_path
                    )
                    description = self.variable_analyzer.generate_description(
                        var_name, context, category
                    )
                    
                    # Create unique key
                    var_key = f"{var_name}_{relative_path}_{i+1}"
                    
                    self.variables_detailed[var_key] = {
                        'name': var_name,
                        'description': description,
                        'file_name': os.path.basename(file_path),
                        'file_path': relative_path,
                        'line': i + 1,
                        'category': category,
                        'context_snippet': line.strip()
                    }
            
            # Extract paths (still useful for non-Python files)
            self._extract_paths_from_content(content, relative_path)
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
    
    def _extract_paths_from_content(self, content: str, file_path: str):
        """Extract various types of paths from content"""
        # Filesystem paths
        fs_patterns = [
            r'["\']([./\\][^"\']+)["\']',
            r'["\']([a-zA-Z]:[/\\][^"\']+)["\']',
            r'["\'](/[^"\']+)["\']'
        ]
        
        for pattern in fs_patterns:
            for match in re.finditer(pattern, content):
                path = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                self.paths['filesystem'][path].append({
                    'file': file_path,
                    'line': line_num
                })
        
        # URLs
        url_pattern = r'["\']?(https?://[^\s"\']+)["\']?'
        for match in re.finditer(url_pattern, content):
            url = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            self.paths['url'][url].append({
                'file': file_path,
                'line': line_num
            })
    
    def analyze_project(self):
        """Analyze all files in the project"""
        print("Analyzing project files with best practice-based variable categorization...")
        print("Focusing on source code and configuration files...")
        
        analyzed_count = 0
        skipped_count = 0
        
        for file_info in self.files:
            file_path = file_info['absolute_path']
            
            if file_path.endswith('.py'):
                self.analyze_python_file(file_path)
                analyzed_count += 1
            else:
                self.analyze_generic_file(file_path)
                analyzed_count += 1
        
        # Print category summary
        vars_by_category = defaultdict(int)
        for var in self.variables_detailed.values():
            vars_by_category[var['category']] += 1
        
        print(f"\nAnalysis complete!")
        print(f"Analyzed {analyzed_count} source code files")
        print(f"Found {len(self.variables_detailed)} variable instances across {len(vars_by_category)} categories:")
        
        for category, count in sorted(vars_by_category.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {category.replace('_', ' ').title()}: {count} variables")
        
        print(f"\nFound {len(self.functions)} unique functions")
        print(f"Found {sum(len(p) for p in self.paths.values())} unique paths")
    
    def generate_json_report(self, filename: str = 'project_analysis.json'):
        """Generate JSON report with detailed variable analysis"""
        self._ensure_output_directory()
        output_file = self.output_dir / filename
        
        # Group variables by category
        vars_by_category = defaultdict(list)
        for var_data in self.variables_detailed.values():
            vars_by_category[var_data['category']].append(var_data)
        
        report = {
            'metadata': {
                'project_name': self.project_name,
                'project_root': str(self.root_dir),
                'analysis_date': datetime.now().isoformat(),
                'total_files': len(self.files),
                'total_variables': len(self.variables_detailed)
            },
            'files': self.files,
            'variables_detailed': list(self.variables_detailed.values()),
            'variables_by_category': dict(vars_by_category),
            'functions': dict(self.functions),
            'paths': dict(self.paths)
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"JSON report saved to {output_file}")
    
    def generate_csv_report(self, prefix: str = 'project_analysis'):
        """Generate CSV reports with detailed variable information"""
        self._ensure_output_directory()
        
        # Detailed Variables CSV
        vars_csv = self.output_dir / f"{prefix}_variables_detailed.csv"
        with open(vars_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Variable Name', 'Description', 'File Name', 'File Path', 
                'Line', 'Category', 'Context'
            ])
            
            # Sort by category then by name
            sorted_vars = sorted(
                self.variables_detailed.values(), 
                key=lambda x: (x['category'], x['name'])
            )
            
            for var in sorted_vars:
                writer.writerow([
                    var['name'],
                    var['description'],
                    var['file_name'],
                    var['file_path'],
                    var['line'],
                    var['category'],
                    var['context_snippet']
                ])
        
        # Summary by category with best practice descriptions
        summary_csv = self.output_dir / f"{prefix}_variables_summary.csv"
        with open(summary_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Category', 'Description', 'Best Practice Reference', 'Count', 'Examples'])
            
            vars_by_category = defaultdict(list)
            for var in self.variables_detailed.values():
                vars_by_category[var['category']].append(var['name'])
            
            for category, var_names in sorted(vars_by_category.items()):
                unique_names = list(set(var_names))[:5]  # First 5 examples
                
                # Get category info
                category_info = self.variable_analyzer.USAGE_CATEGORIES.get(category, {})
                description = category_info.get('description', 'General purpose variables')
                
                # Extract best practice reference from description
                if '(' in description and ')' in description:
                    parts = description.split('(')
                    desc_part = parts[0].strip()
                    practice_part = parts[1].rstrip(')').strip()
                else:
                    desc_part = description
                    practice_part = 'General Programming'
                
                writer.writerow([
                    category.replace('_', ' ').title(),
                    desc_part,
                    practice_part,
                    len(var_names),
                    ', '.join(unique_names)
                ])
        
        print(f"CSV reports saved:")
        print(f"  - {vars_csv}")
        print(f"  - {summary_csv}")
    
    def generate_html_report(self, filename: str = 'project_analysis.html'):
        """Generate HTML report with enhanced variable analysis"""
        self._ensure_output_directory()
        output_file = self.output_dir / filename
        
        # Group variables by category
        vars_by_category = defaultdict(list)
        for var_data in self.variables_detailed.values():
            vars_by_category[var_data['category']].append(var_data)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Variable Analysis Report - {self.project_name}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #333;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin-top: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .category-header {{
            background-color: #2196F3;
            color: white;
            padding: 10px;
            margin-top: 30px;
            border-radius: 5px;
        }}
        .summary {{
            background-color: #e8f4f8;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .category-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .category-card {{
            background-color: #f0f7ff;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ddd;
        }}
        .category-card h4 {{
            margin-top: 0;
            color: #1976D2;
        }}
        .category-description {{
            font-size: 0.9em;
            color: #666;
            margin: 5px 0;
        }}
        .category-examples {{
            font-family: monospace;
            font-size: 0.85em;
            color: #d73a49;
            background-color: #f6f8fa;
            padding: 4px 8px;
            border-radius: 3px;
            margin-top: 5px;
        }}
        .context {{
            font-family: monospace;
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
        }}
        .description {{
            font-style: italic;
            color: #666;
        }}
        .best-practices {{
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .best-practices h3 {{
            margin-top: 0;
            color: #856404;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Variable Analysis Report - {self.project_name}</h1>
        <div class="summary">
            <h3>Summary</h3>
            <p><strong>Project Name:</strong> {self.project_name}</p>
            <p><strong>Project Root:</strong> {self.root_dir}</p>
            <p><strong>Analysis Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Files Analyzed:</strong> {len(self.files)}</p>
            <p><strong>Total Variables Found:</strong> {len(self.variables_detailed)}</p>
            <p><em>Note: Analyzing source code and configuration files only</em></p>
            <p><em>Excluding: documentation, notebooks, data files, binaries, media</em></p>
        </div>
        
        <div class="best-practices">
            <h3>Variable Usage Categories - Based on Industry Best Practices</h3>
            <p>Variables are categorized according to established software engineering principles including:</p>
            <ul>
                <li><strong>12-Factor App</strong> methodology for configuration management</li>
                <li><strong>Domain-Driven Design</strong> for business logic separation</li>
                <li><strong>Clean Code</strong> principles for maintainability</li>
                <li><strong>SRE Best Practices</strong> for observability and monitoring</li>
                <li><strong>Zero Trust Security</strong> for credential management</li>
            </ul>
        </div>
        
        <h2>Variables by Category</h2>
        <div class="category-summary">
"""
        
        # Category summary cards with descriptions
        for category, vars_list in sorted(vars_by_category.items()):
            unique_vars = len(set(v['name'] for v in vars_list))
            
            # Get category info from USAGE_CATEGORIES
            category_info = self.variable_analyzer.USAGE_CATEGORIES.get(category, {})
            description = category_info.get('description', 'General purpose variables')
            examples = category_info.get('examples', '')
            
            html_content += f"""
            <div class="category-card">
                <h4>{category.replace('_', ' ').title()}</h4>
                <div class="category-description">{description}</div>
                <p><strong>{len(vars_list)}</strong> instances | <strong>{unique_vars}</strong> unique variables</p>
                {f'<div class="category-examples">Examples: {examples}</div>' if examples else ''}
            </div>
"""
        
        html_content += """
        </div>
        
        <h2>Detailed Variable Analysis</h2>
"""
        
        # Detailed tables by category
        for category, vars_list in sorted(vars_by_category.items()):
            category_info = self.variable_analyzer.USAGE_CATEGORIES.get(category, {})
            description = category_info.get('description', '')
            
            html_content += f"""
        <h3 class="category-header">{category.replace('_', ' ').upper()}</h3>
        <p style="margin: 10px 0; color: #666;">{description}</p>
        <table>
            <tr>
                <th>Variable Name</th>
                <th>Description</th>
                <th>File Name</th>
                <th>File Path</th>
                <th>Line</th>
                <th>Context</th>
            </tr>
"""
            
            # Sort variables within category
            sorted_vars = sorted(vars_list, key=lambda x: (x['name'], x['file_path']))
            
            for var in sorted_vars[:100]:  # Limit to 100 per category
                html_content += f"""
            <tr>
                <td><strong>{var['name']}</strong></td>
                <td class="description">{var['description']}</td>
                <td>{var['file_name']}</td>
                <td>{var['file_path']}</td>
                <td>{var['line']}</td>
                <td><code class="context">{var['context_snippet'][:80]}{'...' if len(var['context_snippet']) > 80 else ''}</code></td>
            </tr>
"""
            
            if len(vars_list) > 100:
                html_content += f"""
            <tr>
                <td colspan="6">... and {len(vars_list) - 100} more {category} variables</td>
            </tr>
"""
            
            html_content += """
        </table>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"HTML report saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze project variables with best practice categorization based on industry standards.\n'
                    'Output will be saved to: /users/timweber/dev/<project_name>/project_analysis/variables/',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('path', nargs='?', default='.', help='Project root directory (default: current directory)')
    
    args = parser.parse_args()
    
    analyzer = ProjectAnalyzer(args.path)
    
    print(f"\nProject Variable Analyzer")
    print(f"========================")
    print(f"Project: {analyzer.project_name}")
    print(f"Source: {analyzer.root_dir}")
    print(f"Output: {analyzer.output_dir}")
    print(f"\nFile Filtering:")
    print(f"  ✓ Including: Source code, configs, scripts")
    print(f"  ✗ Excluding: Docs, notebooks, data, binaries, media")
    print(f"  ✗ Respecting: .gitignore patterns\n")
    
    # Run analysis
    analyzer.scan_files()
    analyzer.analyze_project()
    
    # Generate reports
    analyzer.generate_json_report()
    analyzer.generate_html_report()
    analyzer.generate_csv_report()
    
    print(f"\nAnalysis complete! Reports generated in:")
    print(f"  {analyzer.output_dir}/")
    print(f"    - project_analysis.json")
    print(f"    - project_analysis.html")
    print(f"    - project_analysis_variables_detailed.csv")
    print(f"    - project_analysis_variables_summary.csv")
    print("\nVariable categories based on:")
    print("  • 12-Factor App methodology")
    print("  • Domain-Driven Design principles")
    print("  • Clean Code practices")
    print("  • SRE/DevOps best practices")
    print("  • Zero Trust Security model")


if __name__ == "__main__":
    main()