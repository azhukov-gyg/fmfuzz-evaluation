#!/usr/bin/env python3
"""
Merge coverage statistics and function counts from multiple fuzzing jobs.
Supports two modes:
1. Merge function counts (from function_counts_*.json)
2. Merge coverage stats (from coverage_stats_*.json) when function counts unavailable

IMPORTANT: Filters output to only include changed functions from changed_functions.json
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional, Set, Dict, List


def load_changed_functions(changed_functions_file: Optional[Path]) -> Optional[Set[str]]:
    """Load changed function signatures from changed_functions.json.
    
    Returns a set of function name patterns to match against, or None if no file provided.
    """
    if not changed_functions_file or not changed_functions_file.exists():
        return None
    
    try:
        with open(changed_functions_file) as f:
            data = json.load(f)
        
        # Extract function patterns from changed_functions.json
        # Format: {"functions": [{"file": "...", "function": "...", "mangled_name": "...", ...}]}
        patterns = set()
        for func in data.get('functions', []):
            # Add the demangled function name
            if 'function' in func:
                patterns.add(func['function'])
            # Also add short name (last part after ::)
            if 'function' in func and '::' in func['function']:
                short_name = func['function'].split('::')[-1]
                # Remove parameters for matching
                if '(' in short_name:
                    short_name = short_name.split('(')[0]
                patterns.add(short_name)
            # Add file:function pattern
            if 'file' in func and 'function' in func:
                patterns.add(f"{func['file']}:{func['function']}")
        
        print(f"📋 Loaded {len(data.get('functions', []))} changed functions, {len(patterns)} match patterns")
        return patterns
    except Exception as e:
        print(f"⚠️ Error loading changed_functions.json: {e}", file=sys.stderr)
        return None


def function_matches_changed(function_id: str, changed_patterns: Optional[Set[str]]) -> bool:
    """Check if a function_id matches any of the changed function patterns."""
    if changed_patterns is None:
        return True  # No filter, include all
    
    # function_id format: "filepath:function_name:line"
    # e.g., "/path/to/file.cpp:namespace::Class::method(args):123"
    
    for pattern in changed_patterns:
        if pattern in function_id:
            return True
    
    return False


def merge_function_counts(input_dir: Path, commit: str, output_file: str, 
                          changed_patterns: Optional[Set[str]] = None) -> bool:
    """Merge function count files into a single statistics file.
    
    If changed_patterns is provided, only include functions that match.
    """
    pattern = f"function_counts_{commit}_*.json"
    files = list(input_dir.rglob(pattern))
    
    if not files:
        return False
    
    # Collect ALL functions first (for debugging)
    all_functions = defaultdict(lambda: {'triggered': False, 'execution_count': 0})
    jobs_processed = 0
    
    for stats_file in files:
        try:
            with open(stats_file) as f:
                data = json.load(f)
                for func in data.get('functions', []):
                    fid = func.get('function_id', '')
                    if func.get('execution_count', 0) > 0:
                        all_functions[fid]['triggered'] = True
                        all_functions[fid]['execution_count'] += func.get('execution_count', 0)
                jobs_processed += 1
        except Exception as e:
            print(f"Error reading {stats_file}: {e}", file=sys.stderr)
    
    # Filter to only changed functions if patterns provided
    if changed_patterns:
        filtered_functions = {
            fid: data for fid, data in all_functions.items()
            if function_matches_changed(fid, changed_patterns)
        }
        print(f"🔍 Filtered: {len(all_functions)} total → {len(filtered_functions)} changed functions")
    else:
        filtered_functions = all_functions
        print(f"⚠️ No changed_functions.json, including all {len(all_functions)} functions")
    
    result = {
        'commit': commit,
        'jobs_processed': jobs_processed,
        'functions': [
            {
                'function_id': fid,
                'triggered': data['triggered'],
                'execution_count': data['execution_count']
            }
            for fid, data in filtered_functions.items()
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    triggered_count = sum(1 for f in result['functions'] if f['triggered'])
    print(f"✅ Merged {jobs_processed} jobs, {len(result['functions'])} changed functions ({triggered_count} triggered)")
    return True


def merge_coverage_stats(input_dir: Path, commit: str, output_file: str) -> bool:
    """Merge coverage stats files (fallback when function counts unavailable)."""
    pattern = f"coverage_stats_{commit}_*.json"
    files = list(input_dir.rglob(pattern))
    
    if not files:
        return False
    
    merged = {
        'commit': commit,
        'functions': [],
        'total_edges': 0,
        'total_tests_processed': 0,
        'jobs_processed': 0
    }
    
    for stats_file in files:
        try:
            with open(stats_file) as f:
                data = json.load(f)
                merged['total_edges'] = max(merged['total_edges'], data.get('total_edges', 0))
                merged['total_tests_processed'] += data.get('tests_processed', 0)
                merged['jobs_processed'] += 1
        except Exception as e:
            print(f"Error reading {stats_file}: {e}", file=sys.stderr)
    
    with open(output_file, 'w') as f:
        json.dump(merged, f, indent=2)
    
    print(f"✅ Merged {merged['jobs_processed']} jobs, {merged['total_edges']} edges")
    return True


def main():
    parser = argparse.ArgumentParser(description="Merge fuzzing statistics")
    parser.add_argument("input_dir", help="Directory containing result artifacts")
    parser.add_argument("--commit", required=True, help="Commit hash")
    parser.add_argument("--output", required=True, help="Output file")
    parser.add_argument("--changed-functions", type=Path, 
                        help="Path to changed_functions.json for filtering (default: ./changed_functions.json)")
    
    args = parser.parse_args()
    
    input_dir = Path(args.input_dir)
    
    if not input_dir.exists():
        print(f"❌ Input directory not found: {input_dir}", file=sys.stderr)
        return 1
    
    # Load changed functions for filtering
    changed_functions_file = args.changed_functions
    if not changed_functions_file:
        # Default: look for changed_functions.json in current directory
        default_path = Path("changed_functions.json")
        if default_path.exists():
            changed_functions_file = default_path
    
    changed_patterns = load_changed_functions(changed_functions_file)
    
    # Try to merge function counts first
    if merge_function_counts(input_dir, args.commit, args.output, changed_patterns):
        return 0
    
    # Fall back to coverage stats
    print("No function count files found, trying coverage stats...", file=sys.stderr)
    if merge_coverage_stats(input_dir, args.commit, args.output):
        return 0
    
    print("⚠️ No results found to merge", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
