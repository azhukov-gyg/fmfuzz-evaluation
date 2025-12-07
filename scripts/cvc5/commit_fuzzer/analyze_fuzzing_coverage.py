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
import time
from pathlib import Path
from typing import Dict, List, Optional

# Timing stats for demangle
_demangle_call_count = 0
_demangle_total_time = 0.0

def demangle_function_name(mangled_name: str) -> str:
    """Demangle C++ function names using c++filt"""
    global _demangle_call_count, _demangle_total_time
    
    if not mangled_name:
        return mangled_name
    
    _demangle_call_count += 1
    start = time.time()
    
    try:
        result = subprocess.run(['c++filt', mangled_name], 
                              capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout:
            _demangle_total_time += time.time() - start
            return result.stdout.strip()
    except Exception:
        pass
    
    _demangle_total_time += time.time() - start
    return mangled_name

def print_demangle_stats():
    """Print demangle timing statistics"""
    print(f"[TIMING] demangle_function_name called {_demangle_call_count} times", file=sys.stderr)
    print(f"[TIMING] Total demangle time: {_demangle_total_time:.2f}s", file=sys.stderr)
    if _demangle_call_count > 0:
        print(f"[TIMING] Average per call: {_demangle_total_time/_demangle_call_count*1000:.2f}ms", file=sys.stderr)


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
        # Try with original path
        file_data = fastcov_data['sources'].get(file_path)
    
    if not file_data:
        # Try to find by matching the end of the path (fastcov uses absolute paths)
        # e.g., match "src/prop/cadical/cadical.cpp" in "/home/runner/.../cvc5/src/prop/cadical/cadical.cpp"
        # First try normalized path
        matching_files = [f for f in fastcov_data['sources'].keys() if f.endswith('/' + normalized_path) or f.endswith('\\' + normalized_path)]
        if not matching_files:
            # Then try original path
            matching_files = [f for f in fastcov_data['sources'].keys() if f.endswith('/' + file_path) or f.endswith('\\' + file_path)]
        
        if not matching_files:
            # Fallback: try by basename only
            basename = file_path.split('/')[-1]
            matching_files = [f for f in fastcov_data['sources'].keys() if f.endswith('/' + basename) or f.endswith('\\' + basename)]
        
        if debug:
            print(f"  [DEBUG] File not found with normalized or original path")
            print(f"  [DEBUG] Available files (first 10): {list(fastcov_data['sources'].keys())[:10]}")
            if matching_files:
                print(f"  [DEBUG] Files with matching basename: {matching_files[:5]}")
        
        if matching_files:
            # When multiple files have the same basename, prefer the one that matches the directory path
            # Extract directory from original file_path (e.g., "prop/cadical" from "src/prop/cadical/util.cpp")
            file_dir = '/'.join(file_path.split('/')[:-1]) if '/' in file_path else ''
            
            # Simple fix: prefer files that contain the directory path as a substring
            if file_dir:
                # Get the key part of the directory (last 2 parts, e.g., "prop/cadical" from "src/prop/cadical")
                dir_parts = [p for p in file_dir.split('/') if p]
                if len(dir_parts) >= 2:
                    key_path = '/'.join(dir_parts[-2:])  # e.g., "prop/cadical"
                else:
                    key_path = dir_parts[-1] if dir_parts else ''
                
                # Find files that contain this key path
                preferred = [f for f in matching_files if key_path in f]
                
                if preferred:
                    file_data = fastcov_data['sources'].get(preferred[0])
                    if debug:
                        print(f"  [DEBUG] Using file (matched by '{key_path}'): {preferred[0]}")
                else:
                    # Fallback: use first matching file
                    file_data = fastcov_data['sources'].get(matching_files[0])
                    if debug:
                        print(f"  [DEBUG] Using file (no directory match, first file): {matching_files[0]}")
            else:
                # No directory info, use first matching file
                file_data = fastcov_data['sources'].get(matching_files[0])
                if debug:
                    print(f"  [DEBUG] Using file (no directory info): {matching_files[0]}")
    
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
        print(f"  [DEBUG] Raw file_data structure keys: {list(file_data.keys())}")
        if '' in file_data:
            print(f"  [DEBUG] Raw file_data[''] keys: {list(file_data[''].keys())}")
        
        # Show execution counts for all functions in this file (sorted by count)
        all_funcs_with_counts = []
        for mangled, data in functions.items():
            count = data.get('execution_count', 0)
            if count > 0:
                all_funcs_with_counts.append((mangled, count, data.get('start_line', 0)))
        all_funcs_with_counts.sort(key=lambda x: x[1], reverse=True)  # Sort by execution count
        
        print(f"  [DEBUG] Functions with execution_count > 0 in this file ({len(all_funcs_with_counts)} total):")
        for i, (mangled, count, line) in enumerate(all_funcs_with_counts[:10]):  # Show top 10
            demangled = demangle_function_name(mangled)
            print(f"    [{i+1}] exec={count:>8} line={line:>4} | {demangled[:100]}...")
        if len(all_funcs_with_counts) > 10:
            print(f"    ... and {len(all_funcs_with_counts) - 10} more functions with executions")
    
    # Try to match by signature only (no line numbers)
    # Fastcov stores functions with mangled names, so we need to demangle
    # The signature from prepare_commit_fuzzer is the full demangled function signature
    # We match on signature only - line numbers are unreliable (libclang vs fastcov can differ)
    # This matches how coverage_mapper creates function IDs: src/file.cpp:FullDemangledSignature:line
    # but we only use the signature part for matching
    sig_full = signature
    sig_normalized = ' '.join(sig_full.split())
    
    if debug:
        print(f"  [DEBUG] Looking for signature: {sig_full}")
        print(f"  [DEBUG] Normalized signature: {sig_normalized}")
        print(f"  [DEBUG] Expected line: {line_num} (not used for matching, only for reference)")
    
    # Collect all candidate functions for debug output if no match found
    candidates = []
    
    for mangled_name, func_data in functions.items():
        demangled = demangle_function_name(mangled_name)
        # The demangled name from fastcov is the full function signature
        # (c++filt returns the complete signature, matching what coverage_mapper stores)
        demangled_full = demangled
        demangled_normalized = ' '.join(demangled_full.split())
        
        # Get line number from fastcov for reference/debugging only
        fastcov_line = func_data.get('start_line', 0)
        exec_count = func_data.get('execution_count', 0)
        
        # Store candidate for debug output
        candidates.append({
            'demangled': demangled_full,
            'line': fastcov_line,
            'exec_count': exec_count
        })
        
        if debug and len(functions) <= 10:  # Only print all if few functions
            print(f"  [DEBUG]   Comparing with: {demangled_full} (line {fastcov_line}, exec={exec_count})")
        
        # Try exact match first (signature only, no line number check)
        if sig_full == demangled_full:
            if debug:
                print(f"  [DEBUG] ✓ EXACT MATCH!")
                print(f"  [DEBUG]   Raw fastcov data:")
                print(f"  [DEBUG]     - Mangled name: {mangled_name}")
                print(f"  [DEBUG]     - Demangled: {demangled_full}")
                print(f"  [DEBUG]     - Execution count: {exec_count}")
                print(f"  [DEBUG]     - Start line (fastcov): {fastcov_line}")
                print(f"  [DEBUG]     - Expected line (libclang): {line_num}")
                print(f"  [DEBUG]     - Full func_data: {json.dumps(func_data, indent=8)}")
            return exec_count
        
        # Try normalized match (remove whitespace differences)
        if sig_normalized == demangled_normalized:
            if debug:
                print(f"  [DEBUG] ✓ NORMALIZED MATCH!")
                print(f"  [DEBUG]   Raw fastcov data:")
                print(f"  [DEBUG]     - Mangled name: {mangled_name}")
                print(f"  [DEBUG]     - Demangled: {demangled_full}")
                print(f"  [DEBUG]     - Execution count: {exec_count}")
                print(f"  [DEBUG]     - Start line (fastcov): {fastcov_line}")
                print(f"  [DEBUG]     - Expected line (libclang): {line_num}")
                print(f"  [DEBUG]     - Full func_data: {json.dumps(func_data, indent=8)}")
            return exec_count
    
    if debug:
        print(f"  [DEBUG] ✗ No match found")
        print(f"  [DEBUG] All candidates in this file ({len(candidates)} functions):")
        for i, cand in enumerate(candidates[:20]):  # Show first 20 candidates
            print(f"    [{i+1}] {cand['demangled'][:120]}... (line {cand['line']}, exec={cand['exec_count']})")
        if len(candidates) > 20:
            print(f"    ... and {len(candidates) - 20} more functions")
    
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
        
        if debug:
            print(f"  [DEBUG] Final result for this function:")
            print(f"  [DEBUG]   - Function ID: {func_id}")
            print(f"  [DEBUG]   - File: {file_path}")
            print(f"  [DEBUG]   - Signature: {signature}")
            print(f"  [DEBUG]   - Line number: {line_num}")
            print(f"  [DEBUG]   - Execution count: {execution_count}")
            print(f"  [DEBUG]   - Triggered: {execution_count > 0}")
            if execution_count > 0:
                print(f"  [DEBUG]   - Note: Execution count is cumulative across all fuzzing inputs and jobs")
                print(f"  [DEBUG]   - This represents total times the function was called during the entire fuzzing run")
        
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
    
    # Print timing stats
    print_demangle_stats()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

