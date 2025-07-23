#!/usr/bin/env python3
"""
Project Functions Analyzer - Function Analysis with Best Practice Categorization

Analyzes functions and methods in source code files and categorizes them based on:
- Clean Architecture principles
- Domain-Driven Design patterns
- SOLID principles
- RESTful API design
- Test-Driven Development
- And more established software engineering patterns

Intelligently filters files:
- Includes: Source code files where functions are defined
- Excludes: Documentation, notebooks, data files, binaries, media files
- Respects: .gitignore patterns

Tracks:
- Function definitions and their locations
- Function calls and usage patterns
- Method definitions within classes
- Function categories and purposes
- Documentation status

Generates comprehensive reports in JSON, HTML, and CSV formats.
Output location: /users/timweber/dev/<project_name>/project_analysis/functions/
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

class FunctionAnalyzer:
    """Function analysis with categorization based on best practices"""
    
    # Define function categories based on software engineering patterns
    FUNCTION_CATEGORIES = {
        'api_endpoint': {
            'description': 'REST API endpoints and route handlers (RESTful Design)',
            'patterns': ['route', 'endpoint', 'handler', 'controller', 'resource'],
            'decorators': ['@app.route', '@router', '@api', '@get', '@post', '@put', '@delete'],
            'file_patterns': ['routes', 'endpoints', 'controllers', 'handlers', 'views'],
            'examples': 'get_user, create_order, update_profile'
        },
        'database_operation': {
            'description': 'Database queries and ORM operations (Repository Pattern)',
            'patterns': ['get', 'find', 'create', 'update', 'delete', 'save', 'query', 'fetch'],
            'context_patterns': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'session', 'cursor'],
            'file_patterns': ['models', 'repositories', 'dao', 'database', 'queries'],
            'examples': 'get_user_by_id, save_to_database, execute_query'
        },
        'business_logic': {
            'description': 'Core business rules and domain logic (Domain-Driven Design)',
            'patterns': ['calculate', 'process', 'validate', 'compute', 'analyze', 'evaluate'],
            'file_patterns': ['services', 'domain', 'business', 'logic', 'rules'],
            'examples': 'calculate_price, validate_order, process_payment'
        },
        'data_transformation': {
            'description': 'Data processing and transformation functions (ETL Pattern)',
            'patterns': ['transform', 'convert', 'parse', 'serialize', 'deserialize', 'map', 'filter'],
            'context_patterns': ['dataframe', 'json', 'xml', 'csv'],
            'file_patterns': ['transformers', 'converters', 'parsers', 'etl'],
            'examples': 'transform_data, parse_csv, serialize_to_json'
        },
        'utility': {
            'description': 'Helper functions and utilities (DRY Principle)',
            'patterns': ['util', 'helper', 'format', 'clean', 'sanitize', 'normalize'],
            'file_patterns': ['utils', 'helpers', 'common', 'shared', 'tools'],
            'examples': 'format_date, clean_string, generate_uuid'
        },
        'authentication': {
            'description': 'Authentication and authorization functions (Security Pattern)',
            'patterns': ['auth', 'login', 'logout', 'authenticate', 'authorize', 'verify'],
            'decorators': ['@login_required', '@requires_auth', '@jwt_required'],
            'file_patterns': ['auth', 'security', 'authentication', 'authorization'],
            'examples': 'authenticate_user, check_permissions, generate_token'
        },
        'error_handling': {
            'description': 'Error handling and exception management (Defensive Programming)',
            'patterns': ['handle', 'catch', 'error', 'exception', 'fallback', 'retry'],
            'context_patterns': ['try', 'except', 'catch', 'throw', 'raise'],
            'file_patterns': ['errors', 'exceptions', 'handlers'],
            'examples': 'handle_error, retry_operation, log_exception'
        },
        'testing': {
            'description': 'Test functions and assertions (Test-Driven Development)',
            'patterns': ['test', 'assert', 'mock', 'fixture', 'setup', 'teardown'],
            'decorators': ['@pytest', '@unittest', '@test', '@mock'],
            'file_patterns': ['test_', '_test', 'tests', 'spec'],
            'examples': 'test_user_creation, assert_equals, mock_database'
        },
        'event_handler': {
            'description': 'Event listeners and handlers (Event-Driven Architecture)',
            'patterns': ['on', 'handle', 'listen', 'emit', 'publish', 'subscribe'],
            'decorators': ['@on', '@event', '@listener'],
            'file_patterns': ['events', 'listeners', 'handlers', 'subscribers'],
            'examples': 'on_user_created, handle_message, emit_event'
        },
        'middleware': {
            'description': 'Middleware and interceptors (Chain of Responsibility)',
            'patterns': ['middleware', 'before', 'after', 'intercept', 'filter'],
            'decorators': ['@middleware', '@before_request', '@after_request'],
            'file_patterns': ['middleware', 'interceptors', 'filters'],
            'examples': 'auth_middleware, logging_middleware, cors_handler'
        },
        'configuration': {
            'description': 'Configuration and setup functions (Configuration Pattern)',
            'patterns': ['config', 'setup', 'init', 'bootstrap', 'register'],
            'file_patterns': ['config', 'setup', 'bootstrap', 'initialization'],
            'examples': 'setup_database, configure_app, init_logger'
        },
        'validation': {
            'description': 'Input validation and data verification (Guard Clause Pattern)',
            'patterns': ['validate', 'verify', 'check', 'ensure', 'assert'],
            'decorators': ['@validates', '@validator'],
            'file_patterns': ['validators', 'validation', 'schemas'],
            'examples': 'validate_email, check_permissions, verify_input'
        },
        'serialization': {
            'description': 'Object serialization and deserialization (Data Transfer Pattern)',
            'patterns': ['serialize', 'deserialize', 'encode', 'decode', 'marshal', 'unmarshal'],
            'file_patterns': ['serializers', 'schemas', 'codecs'],
            'examples': 'to_json, from_dict, encode_response'
        },
        'caching': {
            'description': 'Cache management functions (Performance Pattern)',
            'patterns': ['cache', 'memoize', 'invalidate', 'refresh'],
            'decorators': ['@cache', '@memoize', '@lru_cache'],
            'file_patterns': ['cache', 'caching', 'memoization'],
            'examples': 'get_from_cache, invalidate_cache, memoized_function'
        },
        'logging': {
            'description': 'Logging and monitoring functions (Observability Pattern)',
            'patterns': ['log', 'trace', 'debug', 'monitor', 'track'],
            'file_patterns': ['logging', 'monitoring', 'telemetry'],
            'examples': 'log_event, trace_request, monitor_performance'
        },
        'factory': {
            'description': 'Factory functions and builders (Factory Pattern)',
            'patterns': ['create', 'build', 'make', 'construct', 'factory'],
            'file_patterns': ['factories', 'builders', 'creators'],
            'examples': 'create_user, build_query, make_request'
        },
        'decorator': {
            'description': 'Decorator functions (Decorator Pattern)',
            'patterns': ['decorator', 'wrapper', 'wrap'],
            'context_patterns': ['@', 'functools', 'wraps'],
            'file_patterns': ['decorators', 'wrappers'],
            'examples': 'timing_decorator, auth_required, rate_limit'
        },
        'async_operation': {
            'description': 'Asynchronous operations and coroutines (Async Pattern)',
            'patterns': ['async', 'await', 'coroutine', 'future', 'promise'],
            'keywords': ['async def', 'await', 'asyncio'],
            'file_patterns': ['async', 'coroutines', 'futures'],
            'examples': 'async_fetch_data, await_response, handle_async'
        },
        'generator': {
            'description': 'Generator functions and iterators (Iterator Pattern)',
            'patterns': ['generate', 'yield', 'iterate', 'stream'],
            'keywords': ['yield', 'yield from'],
            'file_patterns': ['generators', 'iterators', 'streams'],
            'examples': 'generate_report, yield_items, stream_data'
        },
        'main_entry': {
            'description': 'Main entry points and CLI commands (Command Pattern)',
            'patterns': ['main', 'run', 'start', 'execute', 'cli'],
            'context_patterns': ['if __name__', 'argparse', 'click'],
            'file_patterns': ['main', 'cli', '__main__', 'app'],
            'examples': 'main, run_app, cli_command'
        }
    }
    
    # File extensions to analyze (where functions are meaningful)
    ANALYZABLE_EXTENSIONS = {
        # Source code
        '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs', '.cpp', '.c',
        '.jsx', '.tsx', '.vue', '.swift', '.kt', '.scala', '.rs', '.r', '.m',
        # Shell scripts
        '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
        # Special files
        'Makefile', 'Dockerfile', 'Jenkinsfile', 'Vagrantfile'
    }
    
    # File extensions to explicitly exclude
    EXCLUDED_EXTENSIONS = {
        # Documentation
        '.md', '.rst', '.txt', '.adoc', '.doc', '.docx', '.pdf',
        # Data files
        '.csv', '.xls', '.xlsx', '.json', '.xml', '.parquet', '.avro',
        # Notebooks
        '.ipynb', '.rmd',
        # Logs and output
        '.log', '.out', '.err', '.dump',
        # Binary and compiled
        '.pyc', '.pyo', '.class', '.o', '.so', '.dll', '.exe', '.bin',
        # Media
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.mp4', '.mp3',
        # Archives
        '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
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
        self.functions = {}
        
    def should_analyze_file(self, file_path: Path) -> bool:
        """Determine if a file should be analyzed for functions"""
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
        
        # Include if it has an analyzable extension
        if extension in self.ANALYZABLE_EXTENSIONS:
            return True
        
        # Include special files without extensions
        if file_name in ['makefile', 'dockerfile', 'jenkinsfile', 'vagrantfile']:
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
        
        return False
    
    def categorize_function(self, func_name: str, context: Dict[str, any], file_path: str) -> str:
        """Categorize a function based on its name, context, and location"""
        func_lower = func_name.lower()
        file_path_lower = file_path.lower()
        
        # Check decorators if available
        decorators = context.get('decorators', [])
        for decorator in decorators:
            for category, config in self.FUNCTION_CATEGORIES.items():
                if 'decorators' in config:
                    if any(dec in decorator for dec in config['decorators']):
                        return category
        
        # Check file path patterns
        for category, config in self.FUNCTION_CATEGORIES.items():
            if 'file_patterns' in config:
                if any(pattern in file_path_lower for pattern in config['file_patterns']):
                    # Double-check with name patterns
                    if 'patterns' in config:
                        if any(pattern in func_lower for pattern in config['patterns']):
                            return category
        
        # Check function name patterns
        for category, config in self.FUNCTION_CATEGORIES.items():
            if 'patterns' in config:
                if any(pattern in func_lower for pattern in config['patterns']):
                    return category
        
        # Check context patterns (function body content)
        body_content = context.get('body', '').lower()
        for category, config in self.FUNCTION_CATEGORIES.items():
            if 'context_patterns' in config:
                if any(pattern in body_content for pattern in config['context_patterns']):
                    return category
        
        # Special checks
        if 'async' in context.get('keywords', []):
            return 'async_operation'
        
        if 'yield' in body_content:
            return 'generator'
        
        if func_name == 'main' or func_name == '__main__':
            return 'main_entry'
        
        # Default to utility
        return 'utility'
    
    def get_function_description(self, func_name: str, category: str, context: Dict[str, any]) -> str:
        """Generate a description for a function based on its category and context"""
        category_info = self.FUNCTION_CATEGORIES.get(category, {})
        base_description = category_info.get('description', 'General purpose function')
        
        # Add specifics based on function characteristics
        if context.get('is_method'):
            class_name = context.get('class_name', 'Unknown')
            return f"Method in {class_name} - {base_description}"
        
        if context.get('is_async'):
            return f"Async function - {base_description}"
        
        if context.get('is_generator'):
            return f"Generator function - {base_description}"
        
        if context.get('is_decorator'):
            return f"Decorator function - {base_description}"
        
        return base_description


class ProjectFunctionsAnalyzer:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir).resolve()
        self.project_name = self.root_dir.name
        self.output_dir = Path(f"/users/timweber/dev/{self.project_name}/project_analysis/functions")
        self.function_analyzer = FunctionAnalyzer()
        self.functions_detailed = {}
        self.function_calls = defaultdict(list)
        self.files_analyzed = []
        self.gitignore_patterns = self._load_gitignore()
        # Add analysis output files to ignore
        self.gitignore_patterns.extend([
            'project_functions_analyzer.py',
            'project_variable_analyzer.py',
            'project_files_analyzer.py',
            'project_paths_analyzer.py',
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
        try:
            relative_path = file_path.relative_to(self.root_dir)
        except ValueError:
            return True
            
        path_str = str(relative_path).replace('\\', '/')
        
        for pattern in self.gitignore_patterns:
            if pattern.endswith('/'):
                if path_str.startswith(pattern) or f"/{pattern}" in f"/{path_str}/":
                    return True
            elif fnmatch.fnmatch(path_str, pattern):
                return True
            elif fnmatch.fnmatch(os.path.basename(path_str), pattern):
                return True
                
        return False
    
    def analyze_python_file(self, file_path: Path):
        """Analyze Python files using AST"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            relative_path = str(file_path.relative_to(self.root_dir))
            
            # Extract function definitions
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                    func_name = node.name
                    
                    # Get decorators
                    decorators = []
                    for decorator in node.decorator_list:
                        if isinstance(decorator, ast.Name):
                            decorators.append(f"@{decorator.id}")
                        elif isinstance(decorator, ast.Attribute):
                            decorators.append(f"@{decorator.attr}")
                    
                    # Get context
                    context = {
                        'decorators': decorators,
                        'is_async': isinstance(node, ast.AsyncFunctionDef),
                        'is_generator': any(isinstance(n, ast.Yield) for n in ast.walk(node)),
                        'is_method': False,
                        'class_name': None,
                        'parameters': [arg.arg for arg in node.args.args],
                        'docstring': ast.get_docstring(node),
                        'body': ast.unparse(node) if hasattr(ast, 'unparse') else '',
                        'line_start': node.lineno,
                        'line_end': node.end_lineno if hasattr(node, 'end_lineno') else node.lineno
                    }
                    
                    # Check if it's a method (inside a class)
                    for parent_node in ast.walk(tree):
                        if isinstance(parent_node, ast.ClassDef):
                            if node in parent_node.body:
                                context['is_method'] = True
                                context['class_name'] = parent_node.name
                                break
                    
                    # Categorize function
                    category = self.function_analyzer.categorize_function(
                        func_name, context, relative_path
                    )
                    
                    # Generate description
                    description = self.function_analyzer.get_function_description(
                        func_name, category, context
                    )
                    
                    # Create unique key
                    func_key = f"{func_name}_{relative_path}_{node.lineno}"
                    
                    self.functions_detailed[func_key] = {
                        'name': func_name,
                        'file_name': file_path.name,
                        'file_path': relative_path,
                        'category': category,
                        'description': description,
                        'line_start': context['line_start'],
                        'line_end': context['line_end'],
                        'is_async': context['is_async'],
                        'is_method': context['is_method'],
                        'class_name': context['class_name'],
                        'parameters': context['parameters'],
                        'decorators': decorators,
                        'has_docstring': bool(context['docstring']),
                        'docstring': context['docstring'][:200] if context['docstring'] else None
                    }
                
                # Track function calls
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        self.function_calls[func_name].append({
                            'file': relative_path,
                            'line': node.lineno if hasattr(node, 'lineno') else 0
                        })
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                        self.function_calls[func_name].append({
                            'file': relative_path,
                            'line': node.lineno if hasattr(node, 'lineno') else 0
                        })
                        
        except Exception as e:
            print(f"Error analyzing Python file {file_path}: {e}")
    
    def analyze_javascript_file(self, file_path: Path):
        """Analyze JavaScript/TypeScript files using regex patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            relative_path = str(file_path.relative_to(self.root_dir))
            lines = content.split('\n')
            
            # Function patterns for JavaScript/TypeScript
            patterns = [
                # Function declarations
                r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
                # Arrow functions assigned to variables
                r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:\([^)]*\)|[a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>',
                # Method definitions in classes
                r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)\s*{',
                # Async functions
                r'async\s+function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
                r'async\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)\s*{',
            ]
            
            for i, line in enumerate(lines):
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        func_name = match.group(1)
                        
                        # Skip common keywords
                        if func_name in ['if', 'for', 'while', 'switch', 'catch']:
                            continue
                        
                        # Simple context extraction
                        context = {
                            'decorators': [],
                            'is_async': 'async' in line,
                            'is_generator': 'function*' in line or 'yield' in ' '.join(lines[i:i+10]),
                            'is_method': not line.strip().startswith('function') and not '=' in line,
                            'class_name': None,
                            'parameters': [],
                            'docstring': None,
                            'body': ' '.join(lines[i:i+5])
                        }
                        
                        # Categorize function
                        category = self.function_analyzer.categorize_function(
                            func_name, context, relative_path
                        )
                        
                        # Generate description
                        description = self.function_analyzer.get_function_description(
                            func_name, category, context
                        )
                        
                        # Create unique key
                        func_key = f"{func_name}_{relative_path}_{i+1}"
                        
                        self.functions_detailed[func_key] = {
                            'name': func_name,
                            'file_name': file_path.name,
                            'file_path': relative_path,
                            'category': category,
                            'description': description,
                            'line_start': i + 1,
                            'line_end': i + 1,  # Approximate
                            'is_async': context['is_async'],
                            'is_method': context['is_method'],
                            'class_name': context['class_name'],
                            'parameters': context['parameters'],
                            'decorators': [],
                            'has_docstring': False,
                            'docstring': None
                        }
                        
        except Exception as e:
            print(f"Error analyzing JavaScript file {file_path}: {e}")
    
    def analyze_generic_file(self, file_path: Path):
        """Analyze other language files using pattern matching"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            relative_path = str(file_path.relative_to(self.root_dir))
            extension = file_path.suffix.lower()
            
            # Language-specific patterns
            if extension in ['.java', '.cs']:
                # Java/C# methods
                pattern = r'(?:public|private|protected|static|final|async|override|virtual)\s+[\w<>\[\]]+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            elif extension in ['.go']:
                # Go functions
                pattern = r'func\s+(?:\([^)]+\)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            elif extension in ['.rb']:
                # Ruby methods
                pattern = r'def\s+([a-zA-Z_][a-zA-Z0-9_?!]*)'
            elif extension in ['.php']:
                # PHP functions
                pattern = r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            elif extension in ['.rs']:
                # Rust functions
                pattern = r'fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:<[^>]+>)?\s*\('
            elif extension in ['.c', '.cpp', '.h', '.hpp']:
                # C/C++ functions
                pattern = r'(?:[\w\s\*]+\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*{'
            else:
                # Generic function pattern
                pattern = r'(?:function|def|func)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
            
            lines = content.split('\n')
            for i, line in enumerate(lines):
                match = re.search(pattern, line)
                if match:
                    func_name = match.group(1)
                    
                    # Basic context
                    context = {
                        'decorators': [],
                        'is_async': 'async' in line.lower(),
                        'is_generator': False,
                        'is_method': False,
                        'class_name': None,
                        'parameters': [],
                        'docstring': None,
                        'body': ' '.join(lines[i:i+3])
                    }
                    
                    # Categorize function
                    category = self.function_analyzer.categorize_function(
                        func_name, context, relative_path
                    )
                    
                    # Generate description
                    description = self.function_analyzer.get_function_description(
                        func_name, category, context
                    )
                    
                    # Create unique key
                    func_key = f"{func_name}_{relative_path}_{i+1}"
                    
                    self.functions_detailed[func_key] = {
                        'name': func_name,
                        'file_name': file_path.name,
                        'file_path': relative_path,
                        'category': category,
                        'description': description,
                        'line_start': i + 1,
                        'line_end': i + 1,
                        'is_async': context['is_async'],
                        'is_method': context['is_method'],
                        'class_name': context['class_name'],
                        'parameters': context['parameters'],
                        'decorators': [],
                        'has_docstring': False,
                        'docstring': None
                    }
                    
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
    
    def analyze_project(self):
        """Analyze all eligible files in the project"""
        print(f"Analyzing functions in project: {self.project_name}")
        print("Scanning source code files for function definitions...")
        print("Excluding: documentation, notebooks, data files, binaries")
        
        total_files = 0
        skipped_files = 0
        analyzed_files = 0
        
        for root, dirs, files in os.walk(self.root_dir):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in self.function_analyzer.EXCLUDED_DIRS 
                      and not self._should_ignore(Path(root) / d)]
            
            for file in files:
                total_files += 1
                file_path = Path(root) / file
                
                # Skip if in gitignore
                if self._should_ignore(file_path):
                    skipped_files += 1
                    continue
                
                # Skip if not analyzable
                if not self.function_analyzer.should_analyze_file(file_path):
                    skipped_files += 1
                    continue
                
                # Analyze the file
                analyzed_files += 1
                self.files_analyzed.append(str(file_path.relative_to(self.root_dir)))
                
                extension = file_path.suffix.lower()
                if extension == '.py':
                    self.analyze_python_file(file_path)
                elif extension in ['.js', '.ts', '.jsx', '.tsx']:
                    self.analyze_javascript_file(file_path)
                else:
                    self.analyze_generic_file(file_path)
        
        print(f"\nAnalysis complete!")
        print(f"Total files found: {total_files}")
        print(f"Files skipped: {skipped_files}")
        print(f"Files analyzed: {analyzed_files}")
        print(f"Functions found: {len(self.functions_detailed)}")
        
        # Print category summary
        funcs_by_category = defaultdict(int)
        for func_data in self.functions_detailed.values():
            funcs_by_category[func_data['category']] += 1
        
        if funcs_by_category:
            print(f"\nFunctions by category:")
            for category, count in sorted(funcs_by_category.items(), 
                                        key=lambda x: x[1], reverse=True):
                print(f"  - {category.replace('_', ' ').title()}: {count} functions")
    
    def calculate_statistics(self) -> Dict[str, any]:
        """Calculate various statistics about functions"""
        stats = {
            'total_functions': len(self.functions_detailed),
            'total_methods': sum(1 for f in self.functions_detailed.values() if f['is_method']),
            'total_async': sum(1 for f in self.functions_detailed.values() if f['is_async']),
            'documented_functions': sum(1 for f in self.functions_detailed.values() if f['has_docstring']),
            'categories': defaultdict(int),
            'files_with_most_functions': [],
            'most_called_functions': []
        }
        
        # Count by category
        for func in self.functions_detailed.values():
            stats['categories'][func['category']] += 1
        
        # Files with most functions
        funcs_per_file = defaultdict(int)
        for func in self.functions_detailed.values():
            funcs_per_file[func['file_path']] += 1
        
        stats['files_with_most_functions'] = sorted(
            funcs_per_file.items(), key=lambda x: x[1], reverse=True
        )[:10]
        
        # Most called functions
        stats['most_called_functions'] = sorted(
            [(name, len(calls)) for name, calls in self.function_calls.items()],
            key=lambda x: x[1], reverse=True
        )[:20]
        
        # Documentation percentage
        if stats['total_functions'] > 0:
            stats['documentation_percentage'] = round(
                (stats['documented_functions'] / stats['total_functions']) * 100, 2
            )
        else:
            stats['documentation_percentage'] = 0
        
        return stats
    
    def generate_json_report(self, filename: str = 'functions_analysis.json'):
        """Generate JSON report"""
        self._ensure_output_directory()
        output_file = self.output_dir / filename
        
        stats = self.calculate_statistics()
        
        report = {
            'metadata': {
                'project_name': self.project_name,
                'project_root': str(self.root_dir),
                'analysis_date': datetime.now().isoformat(),
                'files_analyzed': len(self.files_analyzed),
                'total_functions': len(self.functions_detailed)
            },
            'statistics': stats,
            'category_definitions': self.function_analyzer.FUNCTION_CATEGORIES,
            'functions': list(self.functions_detailed.values()),
            'function_calls': dict(self.function_calls),
            'files_analyzed': self.files_analyzed
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"JSON report saved to {output_file}")
    
    def generate_csv_report(self, prefix: str = 'functions_analysis'):
        """Generate CSV reports"""
        self._ensure_output_directory()
        
        # Detailed functions CSV
        funcs_csv = self.output_dir / f"{prefix}_detailed.csv"
        with open(funcs_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Function Name', 'Category', 'Description', 'File Name', 'File Path',
                'Line Start', 'Line End', 'Type', 'Class', 'Parameters', 
                'Decorators', 'Has Docs'
            ])
            
            # Sort by category then by name
            sorted_funcs = sorted(
                self.functions_detailed.values(), 
                key=lambda x: (x['category'], x['name'])
            )
            
            for func in sorted_funcs:
                func_type = 'Async Method' if func['is_async'] and func['is_method'] else \
                           'Method' if func['is_method'] else \
                           'Async Function' if func['is_async'] else 'Function'
                
                writer.writerow([
                    func['name'],
                    func['category'].replace('_', ' ').title(),
                    func['description'],
                    func['file_name'],
                    func['file_path'],
                    func['line_start'],
                    func['line_end'],
                    func_type,
                    func['class_name'] or '',
                    ', '.join(func['parameters']),
                    ', '.join(func['decorators']),
                    'Yes' if func['has_docstring'] else 'No'
                ])
        
        # Summary by category CSV
        summary_csv = self.output_dir / f"{prefix}_summary.csv"
        with open(summary_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Category', 'Description', 'Count', 'Percentage', 'Examples'
            ])
            
            stats = self.calculate_statistics()
            total = stats['total_functions']
            
            for category, count in sorted(stats['categories'].items(), 
                                        key=lambda x: x[1], reverse=True):
                category_info = self.function_analyzer.FUNCTION_CATEGORIES.get(category, {})
                percentage = round((count / total * 100), 2) if total > 0 else 0
                
                # Get example functions
                examples = [f['name'] for f in self.functions_detailed.values() 
                           if f['category'] == category][:3]
                
                writer.writerow([
                    category.replace('_', ' ').title(),
                    category_info.get('description', ''),
                    count,
                    f"{percentage}%",
                    ', '.join(examples)
                ])
        
        # Call frequency CSV
        calls_csv = self.output_dir / f"{prefix}_call_frequency.csv"
        with open(calls_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Function Name', 'Call Count', 'Called From Files'])
            
            for func_name, calls in sorted(self.function_calls.items(), 
                                          key=lambda x: len(x[1]), reverse=True)[:100]:
                unique_files = set(call['file'] for call in calls)
                writer.writerow([
                    func_name,
                    len(calls),
                    len(unique_files)
                ])
        
        print(f"CSV reports saved:")
        print(f"  - {funcs_csv}")
        print(f"  - {summary_csv}")
        print(f"  - {calls_csv}")
    
    def generate_html_report(self, filename: str = 'functions_analysis.html'):
        """Generate HTML report with visualizations"""
        self._ensure_output_directory()
        output_file = self.output_dir / filename
        
        stats = self.calculate_statistics()
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Functions Analysis Report - {self.project_name}</title>
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
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background-color: #f0f7ff;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ddd;
            text-align: center;
        }}
        .stat-card h3 {{
            margin-top: 0;
            color: #1976D2;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        .category-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .category-card {{
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ddd;
        }}
        .category-card h4 {{
            margin-top: 0;
            color: #1976D2;
        }}
        .progress-bar {{
            width: 100%;
            height: 20px;
            background-color: #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            height: 100%;
            background-color: #4CAF50;
            text-align: center;
            line-height: 20px;
            color: white;
            font-size: 12px;
        }}
        .function-item {{
            font-family: monospace;
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
        }}
        .method {{
            color: #e91e63;
        }}
        .async {{
            color: #ff9800;
        }}
        .documented {{
            color: #4caf50;
        }}
        .top-files {{
            background-color: #fff8e1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Functions Analysis Report - {self.project_name}</h1>
        <div class="summary">
            <h3>Summary</h3>
            <p><strong>Project Name:</strong> {self.project_name}</p>
            <p><strong>Project Root:</strong> {self.root_dir}</p>
            <p><strong>Analysis Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Files Analyzed:</strong> {len(self.files_analyzed)}</p>
            <p><strong>Total Functions Found:</strong> {stats['total_functions']}</p>
            <p><em>Note: Analyzing source code files only (excluding docs, notebooks, binaries)</em></p>
        </div>
        
        <h2>Function Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Functions</h3>
                <div class="stat-value">{stats['total_functions']}</div>
            </div>
            <div class="stat-card">
                <h3>Methods</h3>
                <div class="stat-value">{stats['total_methods']}</div>
                <p>{round(stats['total_methods']/stats['total_functions']*100, 1) if stats['total_functions'] > 0 else 0}% of total</p>
            </div>
            <div class="stat-card">
                <h3>Async Functions</h3>
                <div class="stat-value">{stats['total_async']}</div>
                <p>{round(stats['total_async']/stats['total_functions']*100, 1) if stats['total_functions'] > 0 else 0}% of total</p>
            </div>
            <div class="stat-card">
                <h3>Documented</h3>
                <div class="stat-value">{stats['documented_functions']}</div>
                <p>{stats['documentation_percentage']}% have docstrings</p>
            </div>
        </div>
        
        <h2>Documentation Coverage</h2>
        <div class="progress-bar">
            <div class="progress-fill" style="width: {stats['documentation_percentage']}%">
                {stats['documentation_percentage']}% Documented
            </div>
        </div>
        
        <h2>Functions by Category</h2>
        <div class="category-grid">
"""
        
        # Category cards
        for category, count in sorted(stats['categories'].items(), 
                                    key=lambda x: x[1], reverse=True):
            category_info = self.function_analyzer.FUNCTION_CATEGORIES.get(category, {})
            percentage = round((count / stats['total_functions'] * 100), 2) if stats['total_functions'] > 0 else 0
            
            html_content += f"""
            <div class="category-card">
                <h4>{category.replace('_', ' ').title()}</h4>
                <p>{category_info.get('description', '')}</p>
                <p><strong>{count}</strong> functions ({percentage}%)</p>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {percentage}%; background-color: #2196F3;">
                        {count}
                    </div>
                </div>
            </div>
"""
        
        html_content += """
        </div>
        
        <div class="top-files">
            <h3>Files with Most Functions</h3>
            <table>
                <tr>
                    <th>File</th>
                    <th>Function Count</th>
                </tr>
"""
        
        for file_path, count in stats['files_with_most_functions'][:10]:
            html_content += f"""
                <tr>
                    <td>{file_path}</td>
                    <td>{count}</td>
                </tr>
"""
        
        html_content += """
            </table>
        </div>
        
        <h2>Most Called Functions</h2>
        <table>
            <tr>
                <th>Function Name</th>
                <th>Call Count</th>
            </tr>
"""
        
        for func_name, call_count in stats['most_called_functions'][:20]:
            html_content += f"""
            <tr>
                <td class="function-item">{func_name}</td>
                <td>{call_count}</td>
            </tr>
"""
        
        html_content += """
        </table>
        
        <h2>Detailed Function List by Category</h2>
"""
        
        # Group functions by category
        funcs_by_category = defaultdict(list)
        for func in self.functions_detailed.values():
            funcs_by_category[func['category']].append(func)
        
        # Display functions by category
        for category in sorted(funcs_by_category.keys()):
            funcs = funcs_by_category[category]
            category_info = self.function_analyzer.FUNCTION_CATEGORIES.get(category, {})
            
            html_content += f"""
        <h3 class="category-header">{category.replace('_', ' ').upper()}</h3>
        <p style="margin: 10px 0; color: #666;">{category_info.get('description', '')}</p>
        <table>
            <tr>
                <th>Function</th>
                <th>Type</th>
                <th>File</th>
                <th>Line</th>
                <th>Parameters</th>
                <th>Docs</th>
            </tr>
"""
            
            # Sort and limit display
            sorted_funcs = sorted(funcs, key=lambda x: x['name'])[:50]
            for func in sorted_funcs:
                func_type = []
                if func['is_async']:
                    func_type.append('<span class="async">async</span>')
                if func['is_method']:
                    func_type.append(f'<span class="method">method of {func["class_name"]}</span>')
                if not func_type:
                    func_type.append('function')
                
                doc_status = '<span class="documented">✓</span>' if func['has_docstring'] else '✗'
                
                html_content += f"""
            <tr>
                <td class="function-item">{func['name']}</td>
                <td>{' '.join(func_type)}</td>
                <td>{func['file_path']}</td>
                <td>{func['line_start']}</td>
                <td>{len(func['parameters'])} params</td>
                <td style="text-align: center;">{doc_status}</td>
            </tr>
"""
            
            if len(funcs) > 50:
                html_content += f"""
            <tr>
                <td colspan="6" style="text-align: center; font-style: italic;">
                    ... and {len(funcs) - 50} more {category} functions
                </td>
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
        description='Analyze project functions and methods.\n'
                    'Output will be saved to: /users/timweber/dev/<project_name>/project_analysis/functions/',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('path', nargs='?', default='.', 
                       help='Project root directory (default: current directory)')
    
    args = parser.parse_args()
    
    analyzer = ProjectFunctionsAnalyzer(args.path)
    
    print(f"\nProject Functions Analyzer")
    print(f"=========================")
    print(f"Project: {analyzer.project_name}")
    print(f"Source: {analyzer.root_dir}")
    print(f"Output: {analyzer.output_dir}")
    print(f"\nFile Filtering:")
    print(f"  ✓ Including: Source code files")
    print(f"  ✗ Excluding: Docs, notebooks, data, binaries")
    print(f"  ✗ Respecting: .gitignore patterns\n")
    
    # Run analysis
    analyzer.analyze_project()
    
    # Generate reports
    analyzer.generate_json_report()
    analyzer.generate_html_report()
    analyzer.generate_csv_report()
    
    print(f"\nAnalysis complete! Reports generated in:")
    print(f"  {analyzer.output_dir}/")
    print(f"    - functions_analysis.json")
    print(f"    - functions_analysis.html") 
    print(f"    - functions_analysis_detailed.csv")
    print(f"    - functions_analysis_summary.csv")
    print(f"    - functions_analysis_call_frequency.csv")


if __name__ == "__main__":
    main()