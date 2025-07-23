#!/usr/bin/env python3
"""
Project Paths Analyzer - Path Analysis with Best Practice Categorization

Analyzes all paths in source code files including:
- File system paths (relative, absolute, dynamic)
- URLs and API endpoints
- Import/module paths
- Resource paths (static files, templates)
- Configuration paths (database URLs, service endpoints)

Excludes documentation (.md, .txt, .rst), notebooks (.ipynb), and binary files.
Respects .gitignore patterns.

Generates comprehensive reports in JSON, HTML, and CSV formats.
Output location: /users/timweber/dev/<project_name>/project_analysis/paths/
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
from urllib.parse import urlparse

class PathAnalyzer:
    """Path analysis with categorization based on best practices"""
    
    # Define path categories based on software engineering patterns
    PATH_CATEGORIES = {
        'filesystem_absolute': {
            'description': 'Absolute file system paths (Security Risk - should be configurable)',
            'patterns': [
                r'["\']\/[a-zA-Z0-9_\-\/\.]+["\']',  # Unix absolute paths
                r'["\'][A-Za-z]:\\[^"\']+["\']',      # Windows absolute paths
                r'["\']\\\\[^"\']+["\']'              # UNC paths
            ],
            'best_practice': 'Use relative paths or environment variables instead',
            'security_level': 'high'
        },
        'filesystem_relative': {
            'description': 'Relative file system paths (Best Practice)',
            'patterns': [
                r'["\']\.\.?\/[^"\']+["\']',          # Starts with ./ or ../
                r'["\'][a-zA-Z0-9_\-]+\/[^"\']+["\']', # Relative without ./
                r'os\.path\.join\([^)]+\)',           # os.path.join usage
                r'Path\([^)]+\)',                     # pathlib Path usage
                r'["\'][\w\-]+\.(txt|csv|json|xml|log|dat|db|sqlite)["\']'  # Data files
            ],
            'best_practice': 'Good practice for portability',
            'security_level': 'low'
        },
        'api_external': {
            'description': 'External API endpoints and webhooks',
            'patterns': [
                r'https?:\/\/[^\s"\']+api[^\s"\']*',  # URLs containing 'api'
                r'https?:\/\/api\.[^\s"\']+',         # Subdomains starting with api
                r'["\']https?:\/\/[^"\']+["\']',      # Any HTTP(S) URL
                r'webhook[s]?["\s]*[:=]["\s]*["\'][^"\']+["\']'  # Webhook URLs
            ],
            'best_practice': 'Store in environment variables or config files',
            'security_level': 'medium'
        },
        'api_internal': {
            'description': 'Internal API routes and endpoints',
            'patterns': [
                r'["\']\/api\/[^"\']*["\']',          # /api/ routes
                r'["\']\/v\d+\/[^"\']*["\']',         # Versioned endpoints /v1/
                r'@app\.route\(["\'][^"\']+["\']\)',  # Flask routes
                r'router\.(get|post|put|delete)\(["\'][^"\']+["\']\)',  # Express routes
                r'path\(["\'][^"\']+["\']\)',         # Django URL patterns
            ],
            'best_practice': 'Use constants or route configuration objects',
            'security_level': 'low'
        },
        'imports_internal': {
            'description': 'Internal module imports and project structure',
            'patterns': [
                r'from\s+[\w\.]+\s+import',           # Python from imports
                r'import\s+[\w\.]+',                  # Python imports
                r'require\(["\'][\.\/][^"\']+["\']\)', # Node.js relative requires
                r'import\s+.*\s+from\s+["\'][\.\/][^"\']+["\']',  # ES6 relative imports
            ],
            'best_practice': 'Indicates project structure and dependencies',
            'security_level': 'low'
        },
        'imports_external': {
            'description': 'External package imports and dependencies',
            'patterns': [
                r'import\s+[a-zA-Z][\w]*',            # Simple imports (likely external)
                r'from\s+[a-zA-Z][\w]*\s+import',     # From external packages
                r'require\(["\'][a-zA-Z][^"\']+["\']\)',  # Node.js packages
                r'import\s+.*\s+from\s+["\'][a-zA-Z][^"\']+["\']',  # ES6 packages
            ],
            'best_practice': 'Document in requirements/package files',
            'security_level': 'low'
        },
        'database_urls': {
            'description': 'Database connection strings and URLs',
            'patterns': [
                r'["\'](?:postgresql|postgres|mysql|sqlite|mongodb|redis):\/\/[^"\']+["\']',
                r'["\'].*\.db["\']',                  # SQLite files
                r'DATABASE_URL["\s]*[:=]["\s]*["\'][^"\']+["\']',
                r'connection["\s]*[:=]["\s]*["\'][^"\']+["\']'
            ],
            'best_practice': 'Always use environment variables for credentials',
            'security_level': 'critical'
        },
        'static_resources': {
            'description': 'Static files, assets, and resources',
            'patterns': [
                r'["\']\/static\/[^"\']+["\']',       # Static file paths
                r'["\']\/assets\/[^"\']+["\']',       # Asset paths
                r'["\']\/public\/[^"\']+["\']',       # Public file paths
                r'["\'].*\.(css|js|png|jpg|jpeg|gif|svg|ico)["\']',  # Common static files
                r'["\']templates\/[^"\']+["\']',      # Template paths
            ],
            'best_practice': 'Use asset management and versioning',
            'security_level': 'low'
        },
        'config_paths': {
            'description': 'Configuration file paths and references',
            'patterns': [
                r'["\']config\/[^"\']+["\']',         # Config directory
                r'["\']settings\/[^"\']+["\']',       # Settings directory
                r'["\'][^"\']+\.(ini|cfg|conf|yaml|yml|toml)["\']',  # Config files
                r'\.env["\']',                        # Environment files
                r'["\'][^"\']+\.config["\']'          # .config files
            ],
            'best_practice': 'Centralize configuration management',
            'security_level': 'medium'
        },
        'cloud_resources': {
            'description': 'Cloud service endpoints and resources',
            'patterns': [
                r's3:\/\/[^"\']+',                    # S3 buckets
                r'["\'][^"\']+\.amazonaws\.com[^"\']*["\']',  # AWS endpoints
                r'["\'][^"\']+\.azurewebsites\.net[^"\']*["\']',  # Azure
                r'["\'][^"\']+\.googleapis\.com[^"\']*["\']',  # Google Cloud
                r'gs:\/\/[^"\']+',                    # Google Storage
            ],
            'best_practice': 'Use IAM roles and service accounts',
            'security_level': 'high'
        },
        'environment_vars': {
            'description': 'Environment variable references',
            'patterns': [
                r'os\.environ\[["\'][A-Z_]+["\']\]',  # Python os.environ
                r'process\.env\.[A-Z_]+',             # Node.js process.env
                r'ENV\[["\'][A-Z_]+["\']\]',          # Ruby ENV
                r'\$\{[A-Z_]+\}',                     # Shell variable expansion
                r'getenv\(["\'][A-Z_]+["\']\)'        # C/C++ getenv
            ],
            'best_practice': 'Excellent practice for configuration',
            'security_level': 'low'
        },
        'hardcoded_secrets': {
            'description': 'Potential hardcoded secrets and credentials (CRITICAL)',
            'patterns': [
                r'["\'][^"\']*(?:api[_-]?key|apikey|secret|password|pwd|token|auth)[^"\']*["\'][\s]*[:=][\s]*["\'][^"\']+["\']',
                r'(?:api[_-]?key|apikey|secret|password|pwd|token|auth)[\s]*[:=][\s]*["\'][A-Za-z0-9+\/=]{20,}["\']',
                r'["\'](?:sk_|pk_|api_|key_|secret_|token_)[a-zA-Z0-9]{20,}["\']'
            ],
            'best_practice': 'NEVER hardcode secrets - use environment variables or secret management',
            'security_level': 'critical'
        }
    }
    
    # File extensions to analyze
    ANALYZABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs', '.cpp', '.c',
        '.jsx', '.tsx', '.vue', '.swift', '.kt', '.scala', '.rs', '.sh', '.bash',
        '.yml', '.yaml', '.json', '.xml', '.ini', '.conf', '.cfg', '.env',
        '.dockerfile', '.tf', '.tfvars', '.sql'
    }
    
    # File extensions to explicitly exclude
    EXCLUDED_EXTENSIONS = {
        '.md', '.txt', '.rst', '.adoc', '.ipynb', '.rmd', '.log', '.out',
        '.pdf', '.doc', '.docx', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.mp4', '.mp3', '.zip', '.tar', '.gz', '.pyc', '.class', '.o',
        '.so', '.dll', '.exe', '.bin'
    }
    
    def __init__(self):
        self.paths_found = defaultdict(list)
        
    def should_analyze_file(self, file_path: Path) -> bool:
        """Determine if a file should be analyzed for paths"""
        extension = file_path.suffix.lower()
        file_name = file_path.name.lower()
        
        # Exclude specific extensions
        if extension in self.EXCLUDED_EXTENSIONS:
            return False
            
        # Exclude specific file patterns
        excluded_patterns = ['readme', 'changelog', 'license', 'contributing', 'authors', 'notice']
        if any(pattern in file_name for pattern in excluded_patterns):
            return False
            
        # Include if it has an analyzable extension
        if extension in self.ANALYZABLE_EXTENSIONS:
            return True
            
        # Include makefiles and dockerfiles without extensions
        if file_name in ['makefile', 'dockerfile', 'jenkinsfile', 'rakefile']:
            return True
            
        # Exclude everything else
        return False
    
    def extract_paths(self, content: str, file_path: str) -> Dict[str, List[Dict]]:
        """Extract all types of paths from file content"""
        found_paths = defaultdict(list)
        lines = content.split('\n')
        
        for category, config in self.PATH_CATEGORIES.items():
            for pattern in config['patterns']:
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                        path_value = match.group(0)
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get context (line containing the path)
                        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ''
                        
                        # Clean up the path value
                        cleaned_path = self._clean_path(path_value)
                        
                        # Skip empty or invalid paths
                        if not cleaned_path or len(cleaned_path) < 3:
                            continue
                            
                        found_paths[category].append({
                            'path': cleaned_path,
                            'file': file_path,
                            'line': line_num,
                            'context': line_content[:200],  # Limit context length
                            'raw_match': path_value[:200]   # Store original match
                        })
                except Exception as e:
                    # Skip regex errors
                    continue
                    
        return dict(found_paths)
    
    def _clean_path(self, path_value: str) -> str:
        """Clean and normalize extracted path values"""
        # Remove quotes and common code artifacts
        cleaned = path_value.strip()
        for char in ['"', "'", '`', '(', ')', '[', ']', '{', '}', ';', ',']:
            cleaned = cleaned.strip(char)
        
        # Remove language-specific prefixes
        prefixes_to_remove = ['os.path.join', 'Path', 'require', 'import', 'from', '@app.route']
        for prefix in prefixes_to_remove:
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):].strip('(')
                
        return cleaned.strip()
    
    def categorize_security_risk(self, category: str) -> str:
        """Return security risk level for a category"""
        return self.PATH_CATEGORIES.get(category, {}).get('security_level', 'unknown')
    
    def get_best_practice(self, category: str) -> str:
        """Return best practice recommendation for a category"""
        return self.PATH_CATEGORIES.get(category, {}).get('best_practice', '')


class ProjectPathsAnalyzer:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir).resolve()
        self.project_name = self.root_dir.name
        self.output_dir = Path(f"/users/timweber/dev/{self.project_name}/project_analysis/paths")
        self.path_analyzer = PathAnalyzer()
        self.paths_by_category = defaultdict(list)
        self.files_analyzed = []
        self.gitignore_patterns = self._load_gitignore()
        # Add analysis output files to ignore
        self.gitignore_patterns.extend([
            'project_paths_analyzer.py',
            'project_variable_analyzer.py',
            'project_files_analyzer.py',
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
    
    def analyze_file(self, file_path: Path) -> Dict[str, List[Dict]]:
        """Analyze a single file for paths"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            relative_path = str(file_path.relative_to(self.root_dir))
            return self.path_analyzer.extract_paths(content, relative_path)
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
            return {}
    
    def analyze_project(self):
        """Analyze all eligible files in the project"""
        print(f"Analyzing paths in project: {self.project_name}")
        print("Scanning source code files for paths...")
        print("Excluding: documentation, notebooks, binary files")
        
        total_files = 0
        skipped_files = 0
        analyzed_files = 0
        
        for root, dirs, files in os.walk(self.root_dir):
            # Filter out directories based on gitignore
            dirs[:] = [d for d in dirs if not self._should_ignore(Path(root) / d)]
            
            for file in files:
                total_files += 1
                file_path = Path(root) / file
                
                # Skip if in gitignore
                if self._should_ignore(file_path):
                    skipped_files += 1
                    continue
                
                # Skip if not analyzable
                if not self.path_analyzer.should_analyze_file(file_path):
                    skipped_files += 1
                    continue
                
                # Analyze the file
                paths_found = self.analyze_file(file_path)
                if paths_found:
                    analyzed_files += 1
                    self.files_analyzed.append(str(file_path.relative_to(self.root_dir)))
                    
                    # Aggregate paths by category
                    for category, paths in paths_found.items():
                        self.paths_by_category[category].extend(paths)
        
        print(f"\nAnalysis complete!")
        print(f"Total files found: {total_files}")
        print(f"Files skipped: {skipped_files}")
        print(f"Files analyzed: {analyzed_files}")
        print(f"Total paths found: {sum(len(paths) for paths in self.paths_by_category.values())}")
        
        # Print category summary
        if self.paths_by_category:
            print(f"\nPaths by category:")
            for category, paths in sorted(self.paths_by_category.items(), 
                                        key=lambda x: len(x[1]), reverse=True):
                unique_paths = len(set(p['path'] for p in paths))
                security = self.path_analyzer.categorize_security_risk(category)
                print(f"  - {category.replace('_', ' ').title()}: {len(paths)} occurrences ({unique_paths} unique) [{security} risk]")
    
    def generate_json_report(self, filename: str = 'paths_analysis.json'):
        """Generate JSON report"""
        self._ensure_output_directory()
        output_file = self.output_dir / filename
        
        # Calculate statistics
        stats = {}
        for category, paths in self.paths_by_category.items():
            unique_paths = list(set(p['path'] for p in paths))
            stats[category] = {
                'total_occurrences': len(paths),
                'unique_paths': len(unique_paths),
                'security_level': self.path_analyzer.categorize_security_risk(category),
                'files_affected': len(set(p['file'] for p in paths))
            }
        
        report = {
            'metadata': {
                'project_name': self.project_name,
                'project_root': str(self.root_dir),
                'analysis_date': datetime.now().isoformat(),
                'files_analyzed': len(self.files_analyzed),
                'total_paths_found': sum(len(paths) for paths in self.paths_by_category.values())
            },
            'category_definitions': self.path_analyzer.PATH_CATEGORIES,
            'paths_by_category': dict(self.paths_by_category),
            'statistics': stats,
            'files_analyzed': self.files_analyzed
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"JSON report saved to {output_file}")
    
    def generate_csv_report(self, prefix: str = 'paths_analysis'):
        """Generate CSV reports"""
        self._ensure_output_directory()
        
        # Detailed paths CSV
        paths_csv = self.output_dir / f"{prefix}_detailed.csv"
        with open(paths_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Category', 'Path', 'File', 'Line', 'Security Risk', 
                'Best Practice', 'Context'
            ])
            
            for category, paths in sorted(self.paths_by_category.items()):
                security_risk = self.path_analyzer.categorize_security_risk(category)
                best_practice = self.path_analyzer.get_best_practice(category)
                
                # Sort paths by file and line
                sorted_paths = sorted(paths, key=lambda x: (x['file'], x['line']))
                
                for path_info in sorted_paths:
                    writer.writerow([
                        category.replace('_', ' ').title(),
                        path_info['path'],
                        path_info['file'],
                        path_info['line'],
                        security_risk,
                        best_practice,
                        path_info['context'][:100]
                    ])
        
        # Summary by category CSV
        summary_csv = self.output_dir / f"{prefix}_summary.csv"
        with open(summary_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Category', 'Description', 'Total Occurrences', 'Unique Paths', 
                'Security Risk', 'Best Practice', 'Example Paths'
            ])
            
            for category, paths in sorted(self.paths_by_category.items(), 
                                        key=lambda x: len(x[1]), reverse=True):
                unique_paths = list(set(p['path'] for p in paths))
                category_info = self.path_analyzer.PATH_CATEGORIES.get(category, {})
                
                examples = ', '.join(unique_paths[:3])
                if len(unique_paths) > 3:
                    examples += f' (and {len(unique_paths) - 3} more)'
                
                writer.writerow([
                    category.replace('_', ' ').title(),
                    category_info.get('description', ''),
                    len(paths),
                    len(unique_paths),
                    self.path_analyzer.categorize_security_risk(category),
                    self.path_analyzer.get_best_practice(category),
                    examples
                ])
        
        # Security-focused CSV
        security_csv = self.output_dir / f"{prefix}_security.csv"
        with open(security_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Security Level', 'Category', 'Path', 'File', 'Line', 'Recommendation'
            ])
            
            # Group by security level
            security_groups = defaultdict(list)
            for category, paths in self.paths_by_category.items():
                security_level = self.path_analyzer.categorize_security_risk(category)
                for path in paths:
                    security_groups[security_level].append({
                        'category': category,
                        'path': path,
                        'recommendation': self.path_analyzer.get_best_practice(category)
                    })
            
            # Write in order of severity
            for level in ['critical', 'high', 'medium', 'low']:
                if level in security_groups:
                    for item in sorted(security_groups[level], key=lambda x: x['path']['file']):
                        writer.writerow([
                            level.upper(),
                            item['category'].replace('_', ' ').title(),
                            item['path']['path'],
                            item['path']['file'],
                            item['path']['line'],
                            item['recommendation']
                        ])
        
        print(f"CSV reports saved:")
        print(f"  - {paths_csv}")
        print(f"  - {summary_csv}")
        print(f"  - {security_csv}")
    
    def generate_html_report(self, filename: str = 'paths_analysis.html'):
        """Generate HTML report with visualizations"""
        self._ensure_output_directory()
        output_file = self.output_dir / filename
        
        # Calculate statistics
        total_paths = sum(len(paths) for paths in self.paths_by_category.values())
        security_stats = defaultdict(int)
        for category, paths in self.paths_by_category.items():
            security_level = self.path_analyzer.categorize_security_risk(category)
            security_stats[security_level] += len(paths)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Paths Analysis Report - {self.project_name}</title>
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
        .security-critical {{
            background-color: #ffebee;
            color: #c62828;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border: 1px solid #ef5350;
        }}
        .security-high {{
            background-color: #fff3e0;
            color: #e65100;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border: 1px solid #ff9800;
        }}
        .security-medium {{
            background-color: #fffde7;
            color: #f57f17;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border: 1px solid #fdd835;
        }}
        .security-low {{
            background-color: #f1f8e9;
            color: #33691e;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border: 1px solid #8bc34a;
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
        .path-item {{
            font-family: monospace;
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
            word-break: break-all;
        }}
        .context {{
            font-size: 0.9em;
            color: #666;
            font-style: italic;
        }}
        .best-practice {{
            background-color: #e8f5e9;
            color: #2e7d32;
            padding: 8px;
            border-radius: 4px;
            margin: 5px 0;
            font-size: 0.9em;
        }}
        .category-description {{
            color: #666;
            margin: 10px 0;
            padding: 10px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Paths Analysis Report - {self.project_name}</h1>
        <div class="summary">
            <h3>Summary</h3>
            <p><strong>Project Name:</strong> {self.project_name}</p>
            <p><strong>Project Root:</strong> {self.root_dir}</p>
            <p><strong>Analysis Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Files Analyzed:</strong> {len(self.files_analyzed)}</p>
            <p><strong>Total Paths Found:</strong> {total_paths}</p>
            <p><em>Note: Analyzing source code files only (excluding docs, notebooks, binaries)</em></p>
        </div>
        
        <h2>Security Overview</h2>
        <div class="stats-grid">
"""
        
        # Security statistics cards
        security_colors = {
            'critical': '#c62828',
            'high': '#e65100',
            'medium': '#f57f17',
            'low': '#33691e'
        }
        
        for level in ['critical', 'high', 'medium', 'low']:
            count = security_stats.get(level, 0)
            color = security_colors.get(level, '#666')
            html_content += f"""
            <div class="stat-card">
                <h3 style="color: {color};">{level.upper()} Risk</h3>
                <div class="stat-value" style="color: {color};">{count}</div>
                <p>paths found</p>
            </div>
"""
        
        html_content += """
        </div>
        
        <h2>Path Categories Analysis</h2>
"""
        
        # Display critical and high-risk findings first
        for level in ['critical', 'high']:
            level_categories = [
                (cat, paths) for cat, paths in self.paths_by_category.items()
                if self.path_analyzer.categorize_security_risk(cat) == level
            ]
            
            if level_categories:
                html_content += f"""
        <div class="security-{level}">
            <h3>{level.upper()} Security Risk Paths</h3>
"""
                for category, paths in sorted(level_categories, key=lambda x: len(x[1]), reverse=True):
                    unique_paths = list(set(p['path'] for p in paths))
                    category_info = self.path_analyzer.PATH_CATEGORIES.get(category, {})
                    
                    html_content += f"""
            <h4>{category.replace('_', ' ').title()}</h4>
            <p>{category_info.get('description', '')}</p>
            <p><strong>{len(paths)}</strong> occurrences of <strong>{len(unique_paths)}</strong> unique paths</p>
            <div class="best-practice">
                <strong>Best Practice:</strong> {category_info.get('best_practice', '')}
            </div>
            <details>
                <summary>View paths...</summary>
                <ul>
"""
                    for path in unique_paths[:10]:
                        html_content += f'<li class="path-item">{path}</li>'
                    if len(unique_paths) > 10:
                        html_content += f'<li>... and {len(unique_paths) - 10} more</li>'
                    html_content += """
                </ul>
            </details>
"""
                html_content += """
        </div>
"""
        
        # Detailed tables by category
        html_content += """
        <h2>Detailed Path Analysis</h2>
"""
        
        for category, paths in sorted(self.paths_by_category.items(), 
                                    key=lambda x: len(x[1]), reverse=True):
            category_info = self.path_analyzer.PATH_CATEGORIES.get(category, {})
            security_level = self.path_analyzer.categorize_security_risk(category)
            unique_paths = list(set(p['path'] for p in paths))
            
            html_content += f"""
        <h3 class="category-header">{category.replace('_', ' ').upper()}</h3>
        <div class="category-description">
            <p><strong>Description:</strong> {category_info.get('description', '')}</p>
            <p><strong>Security Level:</strong> <span style="color: {security_colors.get(security_level, '#666')};">{security_level.upper()}</span></p>
            <p><strong>Best Practice:</strong> {category_info.get('best_practice', '')}</p>
            <p><strong>Statistics:</strong> {len(paths)} occurrences, {len(unique_paths)} unique paths, found in {len(set(p['file'] for p in paths))} files</p>
        </div>
        
        <table>
            <tr>
                <th>Path</th>
                <th>File</th>
                <th>Line</th>
                <th>Context</th>
            </tr>
"""
            
            # Show up to 50 paths per category
            display_paths = sorted(paths, key=lambda x: (x['path'], x['file']))[:50]
            for path_info in display_paths:
                html_content += f"""
            <tr>
                <td class="path-item">{path_info['path']}</td>
                <td>{path_info['file']}</td>
                <td>{path_info['line']}</td>
                <td class="context">{path_info['context'][:100]}...</td>
            </tr>
"""
            
            if len(paths) > 50:
                html_content += f"""
            <tr>
                <td colspan="4" style="text-align: center; font-style: italic;">
                    ... and {len(paths) - 50} more occurrences
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
        description='Analyze project paths and identify security risks.\n'
                    'Output will be saved to: /users/timweber/dev/<project_name>/project_analysis/paths/',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('path', nargs='?', default='.', 
                       help='Project root directory (default: current directory)')
    
    args = parser.parse_args()
    
    analyzer = ProjectPathsAnalyzer(args.path)
    
    print(f"\nProject Paths Analyzer")
    print(f"=====================")
    print(f"Project: {analyzer.project_name}")
    print(f"Source: {analyzer.root_dir}")
    print(f"Output: {analyzer.output_dir}\n")
    
    # Run analysis
    analyzer.analyze_project()
    
    # Generate reports
    analyzer.generate_json_report()
    analyzer.generate_html_report()
    analyzer.generate_csv_report()
    
    print(f"\nAnalysis complete! Reports generated in:")
    print(f"  {analyzer.output_dir}/")
    print(f"    - paths_analysis.json")
    print(f"    - paths_analysis.html") 
    print(f"    - paths_analysis_detailed.csv")
    print(f"    - paths_analysis_summary.csv")
    print(f"    - paths_analysis_security.csv")
    print("\nReview CRITICAL and HIGH risk findings immediately!")


if __name__ == "__main__":
    main()