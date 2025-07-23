#!/usr/bin/env python3
"""
Project Files Analyzer - File Inventory and Categorization

Creates a comprehensive inventory of project files with categorization.
Focuses on source code and configuration files while excluding:
- Documentation files (.md, .txt, .rst)
- Notebooks (.ipynb, .rmd)
- Binary and compiled files
- Media files
- Temporary and cache files

Respects .gitignore patterns.

Generates inventory reports in JSON, HTML, and CSV formats.
Output location: <project_root>/project_analysis/files/
"""

import os
import json
import csv
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import argparse
from typing import Dict, List, Set, Tuple, Optional
import fnmatch
import mimetypes

class FileAnalyzer:
    """File categorization and analysis"""
    
    # Define file categories for organization
    FILE_CATEGORIES = {
        'source_code': {
            'description': 'Application source code files',
            'extensions': {
                '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs', 
                '.cpp', '.c', '.rs', '.swift', '.kt', '.scala', '.r', '.m',
                '.jsx', '.tsx', '.vue', '.h', '.hpp', '.cc', '.cxx'
            }
        },
        'configuration': {
            'description': 'Configuration and settings files',
            'extensions': {'.yml', '.yaml', '.json', '.ini', '.conf', '.cfg', '.toml', '.properties'},
            'file_patterns': {'.env', 'config.*', 'settings.*'}
        },
        'testing': {
            'description': 'Test files and test fixtures',
            'patterns': ['test_*.py', '*_test.py', '*_test.go', '*.test.js', '*.spec.js', 
                        '*.test.ts', '*.spec.ts', '*Test.java', '*_spec.rb']
        },
        'build_deployment': {
            'description': 'Build, CI/CD, and deployment files',
            'files': {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'Jenkinsfile',
                     'Makefile', 'Rakefile', '.gitlab-ci.yml', '.travis.yml', 
                     'azure-pipelines.yml', 'buildspec.yml'},
            'extensions': {'.tf', '.tfvars', '.sh', '.bash', '.ps1', '.bat', '.cmd'}
        },
        'package_management': {
            'description': 'Package and dependency files',
            'files': {'package.json', 'package-lock.json', 'yarn.lock', 'requirements.txt',
                     'Pipfile', 'Pipfile.lock', 'pyproject.toml', 'poetry.lock', 'go.mod',
                     'go.sum', 'Cargo.toml', 'Cargo.lock', 'pom.xml', 'build.gradle',
                     'composer.json', 'composer.lock', 'Gemfile', 'Gemfile.lock', 'setup.py'}
        },
        'web_assets': {
            'description': 'Web assets and stylesheets',
            'extensions': {'.css', '.scss', '.less', '.sass'}
        },
        'data_files': {
            'description': 'Data and database files',
            'extensions': {'.sql', '.csv', '.xml', '.db', '.sqlite', '.sqlite3'}
        },
        'other': {
            'description': 'Other project files',
            'extensions': set()
        }
    }
    
    # File extensions to analyze (same as other analyzers)
    ANALYZABLE_EXTENSIONS = {
        # Source code
        '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs', '.cpp', '.c',
        '.jsx', '.tsx', '.vue', '.swift', '.kt', '.scala', '.rs', '.r', '.m',
        '.h', '.hpp', '.cc', '.cxx',
        # Configuration
        '.yml', '.yaml', '.ini', '.conf', '.cfg', '.env', '.toml', '.properties',
        # Shell scripts
        '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
        # Build files
        '.gradle', '.sbt', '.cmake',
        # Web assets
        '.css', '.scss', '.less', '.sass',
        # Data files
        '.sql', '.xml', '.csv',
        # Special files without extensions
        'Makefile', 'Dockerfile', 'Jenkinsfile', 'Vagrantfile', 'Rakefile'
    }
    
    # File extensions to explicitly exclude (same as other analyzers)
    EXCLUDED_EXTENSIONS = {
        # Documentation
        '.md', '.rst', '.txt', '.adoc', '.doc', '.docx', '.pdf',
        # Notebooks
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
        # Database files (large binaries)
        '.db', '.sqlite', '.sqlite3',
        # Other
        '.lock', '.cache', '.tmp', '.temp', '.bak', '.swp'
    }
    
    # Directories to skip (same as other analyzers)
    EXCLUDED_DIRS = {
        '__pycache__', '.pytest_cache', '.tox', '.eggs', 'egg-info',
        'node_modules', 'bower_components', 'jspm_packages',
        'vendor', 'venv', 'env', '.env', 'virtualenv',
        'build', 'dist', 'target', 'out', 'bin',
        '.git', '.svn', '.hg', '.bzr',
        'coverage', 'htmlcov', '.coverage',
        '.idea', '.vscode', '.eclipse',
        'tmp', 'temp', 'cache', '.cache'
    }
    
    def __init__(self):
        self.file_inventory = []
        
    def should_analyze_file(self, file_path: Path) -> bool:
        """Determine if a file should be included in the inventory"""
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
        
        # Include any file with extension (not explicitly excluded)
        return bool(extension) or file_name in self.ANALYZABLE_EXTENSIONS
    
    def categorize_file(self, file_path: Path) -> str:
        """Categorize a file based on its type and purpose"""
        file_name = file_path.name
        extension = file_path.suffix.lower()
        
        # Check each category
        for category, config in self.FILE_CATEGORIES.items():
            # Check by extension
            if 'extensions' in config and extension in config['extensions']:
                return category
            
            # Check by exact filename
            if 'files' in config and file_name in config['files']:
                return category
            
            # Check by file patterns
            if 'file_patterns' in config:
                for pattern in config['file_patterns']:
                    if fnmatch.fnmatch(file_name.lower(), pattern.lower()):
                        return category
            
            # Check by name patterns
            if 'patterns' in config:
                for pattern in config['patterns']:
                    if fnmatch.fnmatch(file_name, pattern):
                        return category
        
        # Check if it's a test file by directory
        if any(test_dir in file_path.parts for test_dir in ['tests', 'test', '__tests__', 'spec']):
            return 'testing'
        
        # Default to 'other'
        return 'other'
    
    def get_file_info(self, file_path: Path, root_dir: Path) -> Dict:
        """Get detailed information about a file"""
        try:
            stat = file_path.stat()
            relative_path = file_path.relative_to(root_dir)
            
            # Get MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            
            return {
                'name': file_path.name,
                'path': str(relative_path),
                'directory': str(relative_path.parent),
                'extension': file_path.suffix.lower() if file_path.suffix else '',
                'size': stat.st_size,
                'size_readable': self._format_size(stat.st_size),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'category': self.categorize_file(file_path),
                'mime_type': mime_type or 'unknown'
            }
        except Exception as e:
            return None
    
    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"


class ProjectFilesAnalyzer:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir).resolve()
        self.project_name = self.root_dir.name
        self.output_dir = self.root_dir / "project_analysis" / "files"
        self.file_analyzer = FileAnalyzer()
        self.files_inventory = []
        self.gitignore_patterns = self._load_gitignore()
        # Add output files to ignore
        self.gitignore_patterns.extend([
            'project_files_analyzer.py',
            'project_variable_analyzer.py',
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
    
    def analyze_project(self):
        """Analyze all files in the project"""
        print(f"Analyzing files in project: {self.project_name}")
        print("Creating file inventory...")
        print("Excluding: documentation, notebooks, binaries, media files")
        
        total_files = 0
        analyzed_files = 0
        skipped_files = 0
        total_size = 0
        
        for root, dirs, files in os.walk(self.root_dir):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in self.file_analyzer.EXCLUDED_DIRS 
                      and not self._should_ignore(Path(root) / d)]
            
            for file in files:
                total_files += 1
                file_path = Path(root) / file
                
                # Skip if in gitignore
                if self._should_ignore(file_path):
                    skipped_files += 1
                    continue
                
                # Skip if not analyzable
                if not self.file_analyzer.should_analyze_file(file_path):
                    skipped_files += 1
                    continue
                
                # Get file info
                file_info = self.file_analyzer.get_file_info(file_path, self.root_dir)
                if file_info:
                    self.files_inventory.append(file_info)
                    total_size += file_info['size']
                    analyzed_files += 1
        
        print(f"\nAnalysis complete!")
        print(f"Total files found: {total_files}")
        print(f"Files skipped: {skipped_files}")
        print(f"Files analyzed: {analyzed_files}")
        print(f"Total size: {self.file_analyzer._format_size(total_size)}")
        
        # Print category summary
        files_by_category = defaultdict(int)
        size_by_category = defaultdict(int)
        for file_info in self.files_inventory:
            files_by_category[file_info['category']] += 1
            size_by_category[file_info['category']] += file_info['size']
        
        print(f"\nFiles by category:")
        for category in sorted(files_by_category.keys()):
            count = files_by_category[category]
            size = self.file_analyzer._format_size(size_by_category[category])
            print(f"  - {category.replace('_', ' ').title()}: {count} files ({size})")
    
    def generate_json_report(self, filename: str = 'files_inventory.json'):
        """Generate JSON report"""
        self._ensure_output_directory()
        output_file = self.output_dir / filename
        
        # Calculate statistics
        files_by_category = defaultdict(list)
        for file_info in self.files_inventory:
            files_by_category[file_info['category']].append(file_info)
        
        stats = {}
        for category, files in files_by_category.items():
            stats[category] = {
                'count': len(files),
                'total_size': sum(f['size'] for f in files),
                'total_size_readable': self.file_analyzer._format_size(sum(f['size'] for f in files))
            }
        
        report = {
            'metadata': {
                'project_name': self.project_name,
                'project_root': str(self.root_dir),
                'analysis_date': datetime.now().isoformat(),
                'total_files': len(self.files_inventory),
                'total_size': sum(f['size'] for f in self.files_inventory),
                'total_size_readable': self.file_analyzer._format_size(
                    sum(f['size'] for f in self.files_inventory)
                )
            },
            'category_definitions': {
                cat: config['description'] 
                for cat, config in self.file_analyzer.FILE_CATEGORIES.items()
            },
            'statistics': stats,
            'files': sorted(self.files_inventory, key=lambda x: x['path'])
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"JSON report saved to {output_file}")
    
    def generate_csv_report(self, prefix: str = 'files_inventory'):
        """Generate CSV reports"""
        self._ensure_output_directory()
        
        # Detailed files CSV
        files_csv = self.output_dir / f"{prefix}_detailed.csv"
        with open(files_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'File Name', 'Directory', 'Extension', 'Category', 
                'Size', 'Size (Readable)', 'Modified', 'MIME Type', 'Full Path'
            ])
            
            # Sort by category then by path
            sorted_files = sorted(self.files_inventory, 
                                key=lambda x: (x['category'], x['path']))
            
            for file_info in sorted_files:
                writer.writerow([
                    file_info['name'],
                    file_info['directory'],
                    file_info['extension'],
                    file_info['category'].replace('_', ' ').title(),
                    file_info['size'],
                    file_info['size_readable'],
                    file_info['modified'],
                    file_info['mime_type'],
                    file_info['path']
                ])
        
        # Summary by category CSV
        summary_csv = self.output_dir / f"{prefix}_summary.csv"
        with open(summary_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Category', 'Description', 'File Count', 'Total Size', 
                'Average Size', 'File Extensions'
            ])
            
            files_by_category = defaultdict(list)
            for file_info in self.files_inventory:
                files_by_category[file_info['category']].append(file_info)
            
            for category in sorted(files_by_category.keys()):
                files = files_by_category[category]
                total_size = sum(f['size'] for f in files)
                avg_size = total_size / len(files) if files else 0
                
                # Get unique extensions
                extensions = set(f['extension'] for f in files if f['extension'])
                ext_list = ', '.join(sorted(extensions)[:10])
                if len(extensions) > 10:
                    ext_list += f' (and {len(extensions) - 10} more)'
                
                writer.writerow([
                    category.replace('_', ' ').title(),
                    self.file_analyzer.FILE_CATEGORIES.get(category, {}).get('description', ''),
                    len(files),
                    self.file_analyzer._format_size(total_size),
                    self.file_analyzer._format_size(int(avg_size)),
                    ext_list
                ])
        
        # Directory structure CSV
        directory_csv = self.output_dir / f"{prefix}_directories.csv"
        with open(directory_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Directory', 'File Count', 'Total Size', 'File Types'
            ])
            
            files_by_dir = defaultdict(list)
            for file_info in self.files_inventory:
                files_by_dir[file_info['directory']].append(file_info)
            
            for directory in sorted(files_by_dir.keys()):
                files = files_by_dir[directory]
                total_size = sum(f['size'] for f in files)
                
                # Get file type summary
                type_counts = defaultdict(int)
                for f in files:
                    type_counts[f['category']] += 1
                
                type_summary = ', '.join(
                    f"{cat}: {count}" 
                    for cat, count in sorted(type_counts.items(), 
                                           key=lambda x: x[1], reverse=True)
                )
                
                writer.writerow([
                    directory,
                    len(files),
                    self.file_analyzer._format_size(total_size),
                    type_summary
                ])
        
        print(f"CSV reports saved:")
        print(f"  - {files_csv}")
        print(f"  - {summary_csv}")
        print(f"  - {directory_csv}")
    
    def generate_html_report(self, filename: str = 'files_inventory.html'):
        """Generate HTML report"""
        self._ensure_output_directory()
        output_file = self.output_dir / filename
        
        # Calculate statistics
        total_size = sum(f['size'] for f in self.files_inventory)
        files_by_category = defaultdict(list)
        for file_info in self.files_inventory:
            files_by_category[file_info['category']].append(file_info)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Files Inventory Report - {self.project_name}</title>
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
            cursor: pointer;
        }}
        th:hover {{
            background-color: #45a049;
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
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
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
        .file-extension {{
            font-family: monospace;
            background-color: #e8e8e8;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .file-path {{
            font-family: monospace;
            font-size: 0.9em;
            color: #666;
        }}
        .size {{
            white-space: nowrap;
        }}
        .category-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .category-source_code {{ background-color: #e3f2fd; color: #1565c0; }}
        .category-configuration {{ background-color: #fff3e0; color: #e65100; }}
        .category-testing {{ background-color: #f3e5f5; color: #6a1b9a; }}
        .category-build_deployment {{ background-color: #e8f5e9; color: #2e7d32; }}
        .category-package_management {{ background-color: #fce4ec; color: #c2185b; }}
        .category-web_assets {{ background-color: #e0f2f1; color: #00695c; }}
        .category-data_files {{ background-color: #f1f8e9; color: #558b2f; }}
        .category-other {{ background-color: #f5f5f5; color: #616161; }}
    </style>
    <script>
        function sortTable(n, tableId) {{
            var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
            table = document.getElementById(tableId);
            switching = true;
            dir = "asc";
            while (switching) {{
                switching = false;
                rows = table.rows;
                for (i = 1; i < (rows.length - 1); i++) {{
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName("TD")[n];
                    y = rows[i + 1].getElementsByTagName("TD")[n];
                    if (dir == "asc") {{
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {{
                            shouldSwitch = true;
                            break;
                        }}
                    }} else if (dir == "desc") {{
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {{
                            shouldSwitch = true;
                            break;
                        }}
                    }}
                }}
                if (shouldSwitch) {{
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                }} else {{
                    if (switchcount == 0 && dir == "asc") {{
                        dir = "desc";
                        switching = true;
                    }}
                }}
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <h1>Files Inventory Report - {self.project_name}</h1>
        <div class="summary">
            <h3>Summary</h3>
            <p><strong>Project Name:</strong> {self.project_name}</p>
            <p><strong>Project Root:</strong> {self.root_dir}</p>
            <p><strong>Analysis Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Files Analyzed:</strong> {len(self.files_inventory)}</p>
            <p><strong>Total Size:</strong> {self.file_analyzer._format_size(total_size)}</p>
            <p><em>Note: Excluding documentation, notebooks, binaries, and media files</em></p>
        </div>
        
        <h2>Category Overview</h2>
        <div class="stats-grid">
"""
        
        # Category statistics cards
        for category in sorted(files_by_category.keys()):
            files = files_by_category[category]
            total_cat_size = sum(f['size'] for f in files)
            
            html_content += f"""
            <div class="stat-card">
                <h3>{category.replace('_', ' ').title()}</h3>
                <div class="stat-value">{len(files)}</div>
                <p>files</p>
                <p>{self.file_analyzer._format_size(total_cat_size)}</p>
            </div>
"""
        
        html_content += """
        </div>
        
        <h2>File Inventory by Category</h2>
"""
        
        # Detailed tables by category
        for category in sorted(files_by_category.keys()):
            files = sorted(files_by_category[category], key=lambda x: x['path'])
            category_desc = self.file_analyzer.FILE_CATEGORIES.get(category, {}).get('description', '')
            
            html_content += f"""
        <h3 class="category-header">{category.replace('_', ' ').upper()}</h3>
        <p style="margin: 10px 0; color: #666;">{category_desc}</p>
        <p style="margin: 10px 0;"><strong>{len(files)}</strong> files, 
           <strong>{self.file_analyzer._format_size(sum(f['size'] for f in files))}</strong> total size</p>
        
        <table id="table_{category}">
            <tr>
                <th onclick="sortTable(0, 'table_{category}')">File Name ⇅</th>
                <th onclick="sortTable(1, 'table_{category}')">Directory ⇅</th>
                <th onclick="sortTable(2, 'table_{category}')">Extension ⇅</th>
                <th onclick="sortTable(3, 'table_{category}')">Size ⇅</th>
                <th onclick="sortTable(4, 'table_{category}')">Modified ⇅</th>
            </tr>
"""
            
            # Show up to 100 files per category
            display_files = files[:100]
            for file_info in display_files:
                html_content += f"""
            <tr>
                <td><strong>{file_info['name']}</strong></td>
                <td class="file-path">{file_info['directory']}</td>
                <td><span class="file-extension">{file_info['extension'] or 'none'}</span></td>
                <td class="size">{file_info['size_readable']}</td>
                <td>{file_info['modified'][:10]}</td>
            </tr>
"""
            
            if len(files) > 100:
                html_content += f"""
            <tr>
                <td colspan="5" style="text-align: center; font-style: italic;">
                    ... and {len(files) - 100} more files
                </td>
            </tr>
"""
            
            html_content += """
        </table>
"""
        
        # Add largest files section
        largest_files = sorted(self.files_inventory, key=lambda x: x['size'], reverse=True)[:20]
        
        html_content += """
        <h2>Largest Files</h2>
        <table id="table_largest">
            <tr>
                <th>File Name</th>
                <th>Category</th>
                <th>Size</th>
                <th>Path</th>
            </tr>
"""
        
        for file_info in largest_files:
            cat_class = f"category-{file_info['category']}"
            html_content += f"""
            <tr>
                <td><strong>{file_info['name']}</strong></td>
                <td><span class="category-badge {cat_class}">{file_info['category'].replace('_', ' ').title()}</span></td>
                <td class="size">{file_info['size_readable']}</td>
                <td class="file-path">{file_info['path']}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"HTML report saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Create an inventory of project files.\n'
                    'Output will be saved to: <project_root>/project_analysis/files/',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('path', nargs='?', default='.', 
                       help='Project root directory (default: current directory)')
    
    args = parser.parse_args()
    
    analyzer = ProjectFilesAnalyzer(args.path)
    
    print(f"\nProject Files Analyzer")
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
    
    print(f"\nFile inventory complete! Reports generated in:")
    print(f"  {analyzer.output_dir}/")
    print(f"    - files_inventory.json")
    print(f"    - files_inventory.html") 
    print(f"    - files_inventory_detailed.csv")
    print(f"    - files_inventory_summary.csv")
    print(f"    - files_inventory_directories.csv")


if __name__ == "__main__":
    main()