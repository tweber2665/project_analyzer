#!/usr/bin/env python3
"""
Analyze My Project - Interactive Project Analysis Tool

This script provides an interactive command-line interface to run various
project analyzers on your codebase. It coordinates the execution of:
- Files Analyzer
- Functions Analyzer
- Paths Analyzer
- Variables Analyzer

Results are saved to: /users/timweber/dev/<project_name>/project_analysis/
"""

import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime
import time

class Colors:
    """ANSI color codes for terminal output"""
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_header():
    """Print the application header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}         PROJECT ANALYZER - Interactive Tool{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")
    print("This tool will analyze your project's structure, functions,")
    print("variables, and paths to provide comprehensive insights.\n")

def print_section(title):
    """Print a section header"""
    print(f"\n{Colors.BOLD}{Colors.YELLOW}--- {title} ---{Colors.END}")

def get_project_name():
    """Get the project name from user"""
    print_section("Project Name")
    while True:
        project_name = input(f"{Colors.GREEN}Enter project name: {Colors.END}").strip()
        if project_name:
            # Sanitize project name (remove special characters)
            sanitized = "".join(c for c in project_name if c.isalnum() or c in ['-', '_'])
            if sanitized != project_name:
                print(f"{Colors.YELLOW}Note: Project name sanitized to: {sanitized}{Colors.END}")
            return sanitized
        print(f"{Colors.RED}Project name cannot be empty. Please try again.{Colors.END}")

def get_project_path():
    """Get the project path from user"""
    print_section("Project Location")
    while True:
        project_path = input(f"{Colors.GREEN}Enter project path (or press Enter for current directory): {Colors.END}").strip()
        if not project_path:
            project_path = "."
        
        path = Path(project_path).resolve()
        if path.exists() and path.is_dir():
            print(f"{Colors.CYAN}Project path: {path}{Colors.END}")
            return str(path)
        else:
            print(f"{Colors.RED}Invalid path. Please enter a valid directory path.{Colors.END}")

def select_analyzers():
    """Let user select which analyzers to run"""
    print_section("Select Analyzers")
    print("Which analyzers would you like to run?")
    print(f"(Press {Colors.BOLD}Enter{Colors.END} to accept defaults, or type Y/N for each)\n")
    
    analyzers = [
        {
            'name': 'Files Analyzer',
            'script': 'project_files_analyzer.py',
            'description': 'Analyzes file structure and categorizes files by type',
            'output_dir': 'files'
        },
        {
            'name': 'Functions Analyzer',
            'script': 'project_functions_analyzer.py',
            'description': 'Identifies and categorizes all functions/methods',
            'output_dir': 'functions'
        },
        {
            'name': 'Paths Analyzer',
            'script': 'project_paths_analyzer.py',
            'description': 'Detects file paths, URLs, and API endpoints',
            'output_dir': 'paths'
        },
        {
            'name': 'Variables Analyzer',
            'script': 'project_variables_analyzer.py',
            'description': 'Analyzes variables and their usage patterns',
            'output_dir': 'variables'
        }
    ]
    
    selected = []
    
    for i, analyzer in enumerate(analyzers):
        print(f"{Colors.BOLD}{i+1}. {analyzer['name']}{Colors.END}")
        print(f"   {analyzer['description']}")
        
        response = input(f"   Run this analyzer? [{Colors.GREEN}Y{Colors.END}/n]: ").strip().lower()
        
        if response in ['', 'y', 'yes']:
            selected.append(analyzer)
            print(f"   {Colors.GREEN}✓ Selected{Colors.END}")
        else:
            print(f"   {Colors.YELLOW}✗ Skipped{Colors.END}")
        print()
    
    if not selected:
        print(f"{Colors.YELLOW}No analyzers selected. Selecting all by default.{Colors.END}")
        selected = analyzers
    
    return selected

def check_analyzer_scripts(selected_analyzers):
    """Check if the required analyzer scripts exist"""
    print_section("Checking Requirements")
    script_dir = Path(__file__).parent
    missing_scripts = []
    
    for analyzer in selected_analyzers:
        script_path = script_dir / analyzer['script']
        if script_path.exists():
            print(f"{Colors.GREEN}✓{Colors.END} Found: {analyzer['script']}")
        else:
            print(f"{Colors.RED}✗{Colors.END} Missing: {analyzer['script']}")
            missing_scripts.append(analyzer['script'])
    
    if missing_scripts:
        print(f"\n{Colors.RED}Error: The following analyzer scripts are missing:{Colors.END}")
        for script in missing_scripts:
            print(f"  - {script}")
        print(f"\n{Colors.YELLOW}Please ensure all analyzer scripts are in the same directory as this script.{Colors.END}")
        return False
    
    return True

def run_analyzer(analyzer, project_path, project_name):
    """Run a single analyzer"""
    script_path = Path(__file__).parent / analyzer['script']
    
    print(f"\n{Colors.CYAN}Running {analyzer['name']}...{Colors.END}")
    start_time = time.time()
    
    try:
        # Run the analyzer script
        result = subprocess.run(
            [sys.executable, str(script_path), project_path],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            elapsed_time = time.time() - start_time
            print(f"{Colors.GREEN}✓ {analyzer['name']} completed in {elapsed_time:.2f} seconds{Colors.END}")
            
            # Extract key information from output if available
            output_lines = result.stdout.strip().split('\n')
            for line in output_lines[-10:]:  # Check last 10 lines for summary info
                if 'found' in line.lower() or 'analyzed' in line.lower():
                    print(f"  {line.strip()}")
            
            return True
        else:
            print(f"{Colors.RED}✗ {analyzer['name']} failed with error:{Colors.END}")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"{Colors.RED}✗ Error running {analyzer['name']}: {str(e)}{Colors.END}")
        return False

def print_summary(project_name, selected_analyzers, results):
    """Print analysis summary"""
    print_section("Analysis Complete")
    
    # Results summary
    successful = sum(1 for r in results if r)
    total = len(results)
    
    if successful == total:
        print(f"{Colors.GREEN}✓ All analyzers completed successfully!{Colors.END}")
    else:
        print(f"{Colors.YELLOW}⚠ {successful}/{total} analyzers completed successfully.{Colors.END}")
    
    # Output location
    output_base = f"/users/timweber/dev/{project_name}/project_analysis"
    print(f"\n{Colors.BOLD}Results saved to:{Colors.END}")
    print(f"{Colors.CYAN}{output_base}/{Colors.END}")
    
    print(f"\n{Colors.BOLD}Output directories:{Colors.END}")
    for i, analyzer in enumerate(selected_analyzers):
        if results[i]:
            output_dir = f"{output_base}/{analyzer['output_dir']}/"
            print(f"  {Colors.GREEN}✓{Colors.END} {analyzer['name']}: {output_dir}")
        else:
            print(f"  {Colors.RED}✗{Colors.END} {analyzer['name']}: Failed")
    
    # Report files
    print(f"\n{Colors.BOLD}Generated reports:{Colors.END}")
    print("  - HTML reports for visual analysis")
    print("  - CSV files for spreadsheet analysis")
    print("  - JSON files for programmatic access")
    
    # Tips
    print(f"\n{Colors.BOLD}Tips:{Colors.END}")
    print(f"  • Open the HTML files in a web browser for interactive reports")
    print(f"  • Import CSV files into Excel or Google Sheets for custom analysis")
    print(f"  • Use JSON files for further processing or integration")

def confirm_execution(project_name, project_path, selected_analyzers):
    """Confirm execution details with user"""
    print_section("Confirm Execution")
    print(f"{Colors.BOLD}Project:{Colors.END} {project_name}")
    print(f"{Colors.BOLD}Path:{Colors.END} {project_path}")
    print(f"{Colors.BOLD}Analyzers:{Colors.END}")
    for analyzer in selected_analyzers:
        print(f"  • {analyzer['name']}")
    
    response = input(f"\n{Colors.GREEN}Proceed with analysis? [Y/n]: {Colors.END}").strip().lower()
    return response in ['', 'y', 'yes']

def main():
    """Main interactive function"""
    try:
        # Print header
        print_header()
        
        # Get project information
        project_name = get_project_name()
        project_path = get_project_path()
        
        # Select analyzers
        selected_analyzers = select_analyzers()
        
        # Check if analyzer scripts exist
        if not check_analyzer_scripts(selected_analyzers):
            return
        
        # Confirm execution
        if not confirm_execution(project_name, project_path, selected_analyzers):
            print(f"\n{Colors.YELLOW}Analysis cancelled.{Colors.END}")
            return
        
        # Run analyzers
        print_section("Running Analysis")
        print(f"Starting analysis at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        results = []
        total_start = time.time()
        
        for analyzer in selected_analyzers:
            success = run_analyzer(analyzer, project_path, project_name)
            results.append(success)
        
        total_elapsed = time.time() - total_start
        print(f"\n{Colors.BOLD}Total analysis time: {total_elapsed:.2f} seconds{Colors.END}")
        
        # Print summary
        print_summary(project_name, selected_analyzers, results)
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}Analysis complete! Thank you for using Project Analyzer.{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Analysis interrupted by user.{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}An unexpected error occurred: {str(e)}{Colors.END}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()