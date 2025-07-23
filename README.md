# Project Analyzer Suite

A comprehensive Python-based tool suite for analyzing codebases and generating detailed reports on project structure, functions, variables, and file paths.

## Overview

The Project Analyzer Suite provides deep insights into your codebase by analyzing:
- **File Structure**: Categorizes and inventories all project files
- **Functions**: Identifies and categorizes functions/methods by purpose
- **Variables**: Analyzes variable usage patterns and naming conventions
- **Paths**: Detects file paths, URLs, and API endpoints with security risk assessment

All analysis results are generated in three formats: HTML (interactive reports), CSV (spreadsheet analysis), and JSON (programmatic access).

## Features

- 🔍 **Smart File Filtering**: Respects `.gitignore` patterns and excludes non-source files
- 📊 **Multiple Output Formats**: HTML, CSV, and JSON reports
- 🏗️ **Best Practice Analysis**: Categorizes code elements based on industry standards
- 🔒 **Security Awareness**: Identifies potential security risks in paths and configurations
- 🚀 **Zero Dependencies**: Uses only Python standard library modules
- 🎯 **Interactive CLI**: User-friendly command-line interface

## Requirements

- Python 3.9 or higher (required for AST features)
- No external dependencies required!

## Project Setup Instructions

### 1. Clone from Git Repository

```bash
# Clone the repository
git clone https://github.com/yourusername/project-analyzer.git

# Navigate to the project directory
cd project-analyzer

# Verify Python version (must be 3.9+)
python --version
```

### 2. Set Up Python Environment (Optional but Recommended)

```bash
# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# No pip install needed - uses only standard library!
```

### 3. Verify Installation

```bash
# List the analyzer files
ls *.py

# You should see:
# - analyze_my_project.py
# - project_files_analyzer.py
# - project_functions_analyzer.py
# - project_paths_analyzer.py
# - project_variables_analyzer.py
```

## How to Use

### Interactive Mode (Recommended)

1. **Launch the interactive analyzer:**
   ```bash
   python analyze_my_project.py
   ```

2. **Follow the prompts:**
   - Enter your project name
   - Enter the path to your project (or press Enter for current directory)
   - Select which analyzers to run (or press Enter to run all)
   - Confirm and start analysis

### Direct Analyzer Usage

You can also run individual analyzers directly:

```bash
# Analyze files in current directory
python project_files_analyzer.py

# Analyze a specific project
python project_files_analyzer.py /path/to/your/project

# Run all analyzers on a project
python project_functions_analyzer.py /path/to/project
python project_variables_analyzer.py /path/to/project
python project_paths_analyzer.py /path/to/project
```

### Output Location

All analysis results are saved to:
```
<project_root>/project_analysis/
├── files/
│   ├── files_inventory.html
│   ├── files_inventory.json
│   └── files_inventory_*.csv
├── functions/
│   ├── functions_analysis.html
│   ├── functions_analysis.json
│   └── functions_analysis_*.csv
├── variables/
│   ├── project_analysis.html
│   ├── project_analysis.json
│   └── project_analysis_*.csv
└── paths/
    ├── paths_analysis.html
    ├── paths_analysis.json
    └── paths_analysis_*.csv
```

## What to Expect

### Analysis Process
1. **File Scanning**: The analyzers scan your project respecting `.gitignore` patterns
2. **Smart Filtering**: Excludes documentation, binaries, media files, and temporary files
3. **Deep Analysis**: Parses source code to extract meaningful information
4. **Categorization**: Classifies findings based on software engineering best practices
5. **Report Generation**: Creates comprehensive reports in multiple formats

### Report Contents

**Files Analyzer Output:**
- Complete file inventory with sizes and modification dates
- Files grouped by category (source code, configuration, tests, etc.)
- Directory structure analysis
- Largest files identification

**Functions Analyzer Output:**
- All functions/methods with their locations
- Categorization by purpose (API endpoints, business logic, utilities, etc.)
- Documentation coverage statistics
- Most frequently called functions
- Files with the most functions

**Variables Analyzer Output:**
- Variable inventory with usage context
- Categorization by purpose (configuration, database, authentication, etc.)
- Best practice recommendations
- Variable naming pattern analysis

**Paths Analyzer Output:**
- All file paths, URLs, and API endpoints
- Security risk assessment (critical, high, medium, low)
- Categorization by type (filesystem, API, database URLs, etc.)
- Best practice recommendations for each finding

### Performance Expectations
- Small projects (<1000 files): 5-30 seconds
- Medium projects (1000-10000 files): 30 seconds - 2 minutes
- Large projects (>10000 files): 2-10 minutes

## Use Cases

### 1. **Code Review and Auditing**
- Quickly understand unfamiliar codebases
- Identify potential security risks
- Assess code organization and structure
- Find undocumented functions

### 2. **Project Documentation**
- Generate comprehensive project reports
- Create file structure documentation
- Export function lists for API documentation
- Identify missing documentation

### 3. **Refactoring Planning**
- Identify duplicate function patterns
- Find inconsistent variable naming
- Locate hardcoded values that should be configuration
- Discover unused or rarely called functions

### 4. **Security Assessment**
- Find hardcoded credentials or API keys
- Identify absolute file paths
- Locate sensitive configuration files
- Assess exposure of internal APIs

### 5. **Onboarding New Team Members**
- Provide comprehensive project overview
- Show code organization patterns
- Highlight important files and functions
- Demonstrate project conventions

### 6. **Migration Planning**
- Inventory all project dependencies
- Identify external service integrations
- Map database connections
- List all API endpoints

### 7. **Compliance and Governance**
- Verify coding standards compliance
- Check documentation coverage
- Ensure proper file organization
- Validate security best practices

## Example Output

### HTML Report Preview
The HTML reports include:
- Interactive tables with sorting
- Visual categorization with color coding
- Progress bars for statistics
- Expandable sections for detailed views

### CSV Files Include
- `*_detailed.csv`: Complete raw data for custom analysis
- `*_summary.csv`: Aggregated statistics by category
- `*_security.csv`: Security-focused findings (paths analyzer)

## Tips and Best Practices

1. **Pre-Analysis Cleanup**: Run on a clean repository state for most accurate results
2. **Review .gitignore**: Ensure your `.gitignore` properly excludes build artifacts
3. **Large Projects**: Consider running individual analyzers separately for very large codebases
4. **Security Reviews**: Pay special attention to the paths analyzer's security findings
5. **Regular Analysis**: Run periodically to track project evolution

## Troubleshooting

**Python Version Error:**
```bash
# Check Python version
python --version
# If < 3.9, upgrade Python or use pyenv/conda
```

**Permission Errors:**
```bash
# Ensure read permissions on project files
# On Unix-like systems:
chmod -R +r /path/to/project
```

**Memory Issues on Large Projects:**
- Run analyzers individually instead of all at once
- Close other applications to free memory
- Consider analyzing subdirectories separately

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is open source and available under the MIT License.

## Author

**Tim Weber**  

---

*Built with Python 🐍 | Zero Dependencies 📦 | Best Practices First 🎯*