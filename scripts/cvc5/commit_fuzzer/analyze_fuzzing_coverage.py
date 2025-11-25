#!/usr/bin/env python3
"""
Analyze fuzzing coverage to determine which changed functions were triggered.

Inputs:
- Changed functions list (JSON file from prepare_commit_fuzzer)
- Fastcov JSON (from fuzzing run)

Output:
- Statistics JSON with function_id, triggered (bool), execution_count (int)
"""

import json
import subprocess
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional


def demangle_function_name(mangled_name: str) -> str:
    """Demangle C++ function names using c++filt"""
    if not mangled_name:
        return mangled_name
    
    try:
        result = subprocess.run(['c++filt', mangled_name], 
                              capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
    except Exception:
        pass
    
    return mangled_name


def normalize_file_path(file_path: str) -> str:
    """Normalize file path to match fastcov format (src/... or absolute path)"""
    # If path doesn't start with src/, try to find src/ in it
    if '/src/' in file_path:
        parts = file_path.split('/src/')
        if len(parts) > 1:
            return 'src/' + parts[1]
    
    # If it already starts with src/, return as is
    if file_path.startswith('src/'):
        return file_path
    
    # Otherwise return as is (might be absolute path)
    return file_path


def parse_changed_function(function_id: str) -> tuple[str, str, int]:
    """Parse changed function ID into (file_path, signature, line_number)
    
    Format: path/to/file.cpp:function_signature:line_number
    """
    parts = function_id.rsplit(':', 2)
    if len(parts) == 3:
        file_path, signature, line_str = parts
        try:
            line_num = int(line_str)
            return (file_path, signature, line_num)
        except ValueError:
            pass
    
    # Fallback: try to extract what we can
    if ':' in function_id:
        parts = function_id.split(':', 1)
        return (parts[0], parts[1] if len(parts) > 1 else '', 0)
    
    return (function_id, '', 0)


def find_function_in_fastcov(fastcov_data: Dict, file_path: str, 
                            signature: str, line_num: int) -> Optional[int]:
    """Find function in fastcov JSON and return execution count.
    
    Returns execution_count if found, None if not found.
    """
    # Fastcov uses 'sources' key, not 'files'
    if 'sources' not in fastcov_data:
        return None
    
    # Normalize file path for lookup
    normalized_path = normalize_file_path(file_path)
    
    # Try exact match first
    file_data = fastcov_data['sources'].get(normalized_path)
    if not file_data:
        # Try with absolute path
        file_data = fastcov_data['sources'].get(file_path)
    
    if not file_data:
        return None
    
    # Functions are stored under '' key in file_data
    if '' not in file_data or 'functions' not in file_data['']:
        return None
    
    functions = file_data['']['functions']
    
    # Try to match by signature
    # Fastcov stores functions with mangled names, so we need to demangle
    for mangled_name, func_data in functions.items():
        demangled = demangle_function_name(mangled_name)
        
        # Match signature (may need normalization)
        # Remove line number from signature for matching
        sig_base = signature.split(':')[0] if ':' in signature else signature
        demangled_base = demangled.split(':')[0] if ':' in demangled else demangled
        
        # Try exact match first
        if sig_base == demangled_base:
            return func_data.get('execution_count', 0)
        
        # Try normalized match (remove whitespace differences)
        sig_normalized = ' '.join(sig_base.split())
        demangled_normalized = ' '.join(demangled_base.split())
        if sig_normalized == demangled_normalized:
            return func_data.get('execution_count', 0)
    
    return None


def analyze_coverage(changed_functions_file: Path, fastcov_json_file: Path) -> Dict:
    """Analyze coverage and return statistics"""
    # Load changed functions
    with open(changed_functions_file, 'r') as f:
        changed_functions_data = json.load(f)
    
    # Get changed functions list
    if isinstance(changed_functions_data, list):
        changed_functions = changed_functions_data
    elif isinstance(changed_functions_data, dict):
        changed_functions = changed_functions_data.get('changed_functions', [])
    else:
        print(f"Error: Unexpected format in changed_functions file", file=sys.stderr)
        sys.exit(1)
    
    # Load fastcov JSON
    with open(fastcov_json_file, 'r') as f:
        fastcov_data = json.load(f)
    
    # Analyze each function
    function_stats = []
    for func_id in changed_functions:
        file_path, signature, line_num = parse_changed_function(func_id)
        
        execution_count = find_function_in_fastcov(fastcov_data, file_path, signature, line_num)
        
        if execution_count is None:
            execution_count = 0
        
        function_stats.append({
            "function_id": func_id,
            "triggered": execution_count > 0,
            "execution_count": execution_count
        })
    
    return {
        "functions": function_stats
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze fuzzing coverage to determine which changed functions were triggered"
    )
    parser.add_argument(
        '--changed-functions',
        required=True,
        type=Path,
        help='JSON file with changed functions list'
    )
    parser.add_argument(
        '--fastcov-json',
        required=True,
        type=Path,
        help='Fastcov JSON output file'
    )
    parser.add_argument(
        '--output',
        required=True,
        type=Path,
        help='Output statistics JSON file'
    )
    parser.add_argument(
        '--job-id',
        type=str,
        help='Job ID for statistics output'
    )
    parser.add_argument(
        '--commit-hash',
        type=str,
        help='Commit hash for statistics output'
    )
    
    args = parser.parse_args()
    
    # Analyze coverage
    stats = analyze_coverage(args.changed_functions, args.fastcov_json)
    
    # Add metadata
    if args.job_id:
        stats['job_id'] = args.job_id
    if args.commit_hash:
        stats['commit_hash'] = args.commit_hash
    
    # Write output
    with open(args.output, 'w') as f:
        json.dump(stats, f, indent=2)
    
    # Print summary
    total = len(stats['functions'])
    triggered = sum(1 for f in stats['functions'] if f['triggered'])
    total_executions = sum(f['execution_count'] for f in stats['functions'])
    
    print(f"Analyzed {total} functions")
    print(f"Triggered: {triggered} ({triggered/total*100:.1f}%)" if total > 0 else "Triggered: 0")
    print(f"Total executions: {total_executions}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

