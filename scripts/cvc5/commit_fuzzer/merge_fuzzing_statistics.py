#!/usr/bin/env python3
"""
Merge fuzzing statistics from multiple jobs.

Inputs:
- Multiple statistics JSON files (one per job)

Output:
- Merged statistics JSON
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List
from collections import defaultdict


def _load_changed_function_suffixes(changed_functions_json: Path) -> List[str]:
    """
    Build a list of function identifiers for matching.

    We intentionally do NOT rely on the trailing ":0" suffix that appears in some
    outputs (historical baseline compatibility). Matching is done on:
      - "<file>:<signature>" (preferred)
      - "<signature>" (fallback)

    changed_functions.json uses "file:signature" keys and also stores file/signature
    separately in function_info_map. We intentionally match by suffix so we handle
    both absolute and relative file paths in function_id.
    """
    try:
        data = json.loads(changed_functions_json.read_text())
    except Exception as e:
        print(f"[WARN] Could not read changed functions json {changed_functions_json}: {e}", file=sys.stderr)
        return []

    function_info_map = data.get("function_info_map", {}) or {}
    keys: List[str] = []

    for _, info in function_info_map.items():
        file_rel = (info.get("file") or "").strip()
        sig = (info.get("signature") or "").strip()
        if not file_rel or not sig:
            continue
        # Keep both file+signature and signature-only keys.
        keys.append(f"{file_rel}:{sig}")
        keys.append(sig)

    # De-dup, stable order
    seen = set()
    uniq = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq


def _strip_trailing_index(func_id: str) -> str:
    """
    Normalize function_id by removing a trailing ":<digits>" suffix if present.
    Example:
      "/abs/path/file.cpp:ns::f(int):0" -> "/abs/path/file.cpp:ns::f(int)"
    """
    if not func_id:
        return ""
    # Fast path: common ":0"
    if func_id.endswith(":0"):
        return func_id[:-2]
    # Generic digits
    i = func_id.rfind(":")
    if i == -1:
        return func_id
    tail = func_id[i + 1 :]
    if tail.isdigit():
        return func_id[:i]
    return func_id


def _extract_signature(func_id_no_index: str) -> str:
    """Given '<file>:<signature>' return '<signature>' (best-effort)."""
    if not func_id_no_index:
        return ""
    i = func_id_no_index.find(":")
    if i == -1:
        return ""
    return func_id_no_index[i + 1 :]


def _matches_changed(func_id: str, changed_keys: List[str]) -> bool:
    """
    Match by:
      - file:signature (suffix match to handle absolute paths)
      - signature-only
    """
    if not changed_keys:
        return True
    base = _strip_trailing_index(func_id)
    sig = _extract_signature(base)
    for k in changed_keys:
        if not k:
            continue
        if ":" in k:
            # file:signature
            if base.endswith(k) or base.endswith("/" + k):
                return True
        else:
            # signature-only
            if sig == k:
                return True
    return False


def merge_statistics(statistics_files: List[Path], commit_hash: str = None, 
                    coverage_map_commit: str = None,
                    changed_function_suffixes: List[str] = None) -> Dict:
    """Merge statistics from multiple job files"""
    changed_function_suffixes = changed_function_suffixes or []
    # Collect data per function
    function_data = defaultdict(lambda: {
        'total_executions': 0,
        'jobs_triggered': []
    })
    
    # Process each statistics file
    for stats_file in statistics_files:
        with open(stats_file, 'r') as f:
            stats = json.load(f)
        
        job_id = stats.get('job_id', 'unknown')
        
        # Process each function
        for func in stats.get('functions', []):
            func_id = func['function_id']
            if changed_function_suffixes:
                # Keep only "changed" functions for parity with other RQ2 variants.
                if not _matches_changed(func_id, changed_function_suffixes):
                    continue
            execution_count = func.get('execution_count', 0)
            triggered = func.get('triggered', False)
            
            function_data[func_id]['total_executions'] += execution_count
            if triggered:
                if job_id not in function_data[func_id]['jobs_triggered']:
                    function_data[func_id]['jobs_triggered'].append(job_id)
    
    # Convert to final format
    functions = []
    for func_id, data in sorted(function_data.items()):
        functions.append({
            'function_id': func_id,
            'triggered': data['total_executions'] > 0,
            'total_executions': data['total_executions'],
            'jobs_triggered': sorted(data['jobs_triggered'])
        })
    
    # Calculate totals
    total_functions = len(functions)
    functions_triggered = sum(1 for f in functions if f['triggered'])
    functions_not_triggered = total_functions - functions_triggered
    
    result = {
        'total_functions': total_functions,
        'functions_triggered': functions_triggered,
        'functions_not_triggered': functions_not_triggered,
        'functions': functions
    }
    
    if commit_hash:
        result['commit_hash'] = commit_hash
    if coverage_map_commit:
        result['coverage_map_commit'] = coverage_map_commit
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Merge fuzzing statistics from multiple jobs"
    )
    parser.add_argument(
        'statistics_files',
        nargs='+',
        type=Path,
        help='Statistics JSON files to merge'
    )
    parser.add_argument(
        '--output',
        required=True,
        type=Path,
        help='Output merged statistics JSON file'
    )
    parser.add_argument(
        '--commit-hash',
        type=str,
        help='Commit hash for merged statistics'
    )
    parser.add_argument(
        '--coverage-map-commit',
        type=str,
        help='Coverage map commit hash'
    )
    parser.add_argument(
        '--changed-functions-json',
        type=Path,
        help='Optional changed_functions.json to filter output to changed functions only'
    )
    
    args = parser.parse_args()
    
    # Validate files exist
    for f in args.statistics_files:
        if not f.exists():
            print(f"Error: Statistics file not found: {f}", file=sys.stderr)
            sys.exit(1)
    
    # Merge statistics
    changed_suffixes = []
    if args.changed_functions_json:
        changed_suffixes = _load_changed_function_suffixes(args.changed_functions_json)
        print(f"Filtering to changed functions: {len(changed_suffixes)//2} function(s)")

    merged = merge_statistics(
        args.statistics_files,
        args.commit_hash,
        args.coverage_map_commit,
        changed_function_suffixes=changed_suffixes,
    )
    
    # Write output
    with open(args.output, 'w') as f:
        json.dump(merged, f, indent=2)
    
    # Print summary
    print(f"Merged statistics from {len(args.statistics_files)} job(s)")
    print(f"Total functions: {merged['total_functions']}")
    print(f"Functions triggered: {merged['functions_triggered']} ({merged['functions_triggered']/merged['total_functions']*100:.1f}%)" if merged['total_functions'] > 0 else "Functions triggered: 0")
    print(f"Functions not triggered: {merged['functions_not_triggered']}")
    total_executions = sum(f['total_executions'] for f in merged['functions'])
    print(f"Total executions: {total_executions}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

