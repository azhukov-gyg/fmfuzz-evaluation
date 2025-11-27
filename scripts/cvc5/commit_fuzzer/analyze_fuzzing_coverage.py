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
    The signature may contain '::' so we need to be careful about splitting.
    """
    # Find the last ':' that's followed by a number (the line number)
    # Work backwards to find where the line number starts
    last_colon_idx = -1
    for i in range(len(function_id) - 1, -1, -1):
        if function_id[i] == ':':
            # Check if what follows is a number
            remaining = function_id[i+1:]
            if remaining and remaining.isdigit():
                last_colon_idx = i
                break
    
    if last_colon_idx >= 0:
        # Split at the last colon before the line number
        before_line = function_id[:last_colon_idx]
        line_str = function_id[last_colon_idx+1:]
        try:
            line_num = int(line_str)
            # Now split before_line into file_path and signature
            # Find the first ':' to separate them
            first_colon_idx = before_line.find(':')
            if first_colon_idx >= 0:
                file_path = before_line[:first_colon_idx]
                signature = before_line[first_colon_idx+1:]
                return (file_path, signature, line_num)
        except ValueError:
            pass
    
    # Fallback: try to extract what we can
    if ':' in function_id:
        parts = function_id.split(':', 1)
        return (parts[0], parts[1] if len(parts) > 1 else '', 0)
    
    return (function_id, '', 0)


def find_function_in_fastcov(fastcov_data: Dict, file_path: str, 
                            signature: str, line_num: int, debug: bool = False) -> Optional[int]:
    """Find function in fastcov JSON and return execution count.
    
    Returns execution_count if found, None if not found.
    """
    if debug:
        print(f"  [DEBUG] Looking for function: {signature}")
        print(f"  [DEBUG] In file: {file_path}")
        print(f"  [DEBUG] At line: {line_num}")
    
    # Fastcov uses 'sources' key, not 'files'
    if 'sources' not in fastcov_data:
        if debug:
            print(f"  [DEBUG] ERROR: 'sources' key not found in fastcov data")
            print(f"  [DEBUG] Available keys: {list(fastcov_data.keys())}")
        return None
    
    # Normalize file path for lookup
    normalized_path = normalize_file_path(file_path)
    if debug:
        print(f"  [DEBUG] Normalized path: {normalized_path}")
    
    # Try exact match first
    file_data = fastcov_data['sources'].get(normalized_path)
    if not file_data:
        # Try with absolute path
        file_data = fastcov_data['sources'].get(file_path)
        if debug and not file_data:
            print(f"  [DEBUG] File not found with normalized or original path")
            print(f"  [DEBUG] Available files (first 10): {list(fastcov_data['sources'].keys())[:10]}")
            # Try to find similar paths
            matching_files = [f for f in fastcov_data['sources'].keys() if file_path.split('/')[-1] in f]
            if matching_files:
                print(f"  [DEBUG] Files with matching basename: {matching_files[:5]}")
    
    if not file_data:
        return None
    
    if debug:
        print(f"  [DEBUG] Found file data, keys: {list(file_data.keys())}")
    
    # Functions are stored under '' key in file_data
    if '' not in file_data or 'functions' not in file_data['']:
        if debug:
            print(f"  [DEBUG] No functions found in file data")
            if '' in file_data:
                print(f"  [DEBUG] Empty key exists but no 'functions': {list(file_data[''].keys())}")
        return None
    
    functions = file_data['']['functions']
    if debug:
        print(f"  [DEBUG] Found {len(functions)} functions in file")
        print(f"  [DEBUG] Function names (first 5): {list(functions.keys())[:5]}")
    
    # Try to match by signature
    # Fastcov stores functions with mangled names, so we need to demangle
    sig_base = signature.split(':')[0] if ':' in signature else signature
    sig_normalized = ' '.join(sig_base.split())
    
    if debug:
        print(f"  [DEBUG] Looking for signature: {sig_base}")
        print(f"  [DEBUG] Normalized signature: {sig_normalized}")
    
    for mangled_name, func_data in functions.items():
        demangled = demangle_function_name(mangled_name)
        demangled_base = demangled.split(':')[0] if ':' in demangled else demangled
        demangled_normalized = ' '.join(demangled_base.split())
        
        if debug and len(functions) <= 10:  # Only print all if few functions
            print(f"  [DEBUG]   Comparing with: {demangled_base[:80]}...")
        
        # Try exact match first
        if sig_base == demangled_base:
            exec_count = func_data.get('execution_count', 0)
            if debug:
                print(f"  [DEBUG] ✓ EXACT MATCH! Execution count: {exec_count}")
            return exec_count
        
        # Try normalized match (remove whitespace differences)
        if sig_normalized == demangled_normalized:
            exec_count = func_data.get('execution_count', 0)
            if debug:
                print(f"  [DEBUG] ✓ NORMALIZED MATCH! Execution count: {exec_count}")
            return exec_count
    
    if debug:
        print(f"  [DEBUG] ✗ No match found")
    
    return None


def analyze_coverage(changed_functions_file: Path, fastcov_json_file: Path, debug: bool = False) -> Dict:
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
    
    if debug:
        print(f"[DEBUG] Loaded {len(changed_functions)} changed functions")
        print(f"[DEBUG] Changed functions:")
        for func_id in changed_functions[:5]:
            print(f"  - {func_id}")
        if len(changed_functions) > 5:
            print(f"  ... and {len(changed_functions) - 5} more")
    
    # Load fastcov JSON
    with open(fastcov_json_file, 'r') as f:
        fastcov_data = json.load(f)
    
    if debug:
        print(f"[DEBUG] Loaded fastcov data")
        if 'sources' in fastcov_data:
            print(f"[DEBUG] Found {len(fastcov_data['sources'])} source files in fastcov")
            print(f"[DEBUG] Sample files (first 5): {list(fastcov_data['sources'].keys())[:5]}")
    
    # Analyze each function
    function_stats = []
    for i, func_id in enumerate(changed_functions):
        if debug:
            print(f"\n[DEBUG] Analyzing function {i+1}/{len(changed_functions)}: {func_id}")
        
        file_path, signature, line_num = parse_changed_function(func_id)
        
        execution_count = find_function_in_fastcov(fastcov_data, file_path, signature, line_num, debug=debug)
        
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
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )
    
    args = parser.parse_args()
    
    # Analyze coverage
    stats = analyze_coverage(args.changed_functions, args.fastcov_json, debug=args.debug)
    
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

