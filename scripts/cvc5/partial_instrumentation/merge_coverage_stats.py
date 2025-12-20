#!/usr/bin/env python3
"""
Merge coverage statistics and function counts from multiple fuzzing jobs.
Supports two modes:
1. Merge function counts (from function_counts_*.json)
2. Merge coverage stats (from coverage_stats_*.json) when function counts unavailable
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def merge_function_counts(input_dir: Path, commit: str, output_file: str) -> bool:
    """Merge function count files into a single statistics file."""
    pattern = f"function_counts_{commit}_*.json"
    files = list(input_dir.rglob(pattern))
    
    if not files:
        return False
    
    merged_functions = defaultdict(lambda: {'triggered': False, 'execution_count': 0})
    jobs_processed = 0
    
    for stats_file in files:
        try:
            with open(stats_file) as f:
                data = json.load(f)
                for func in data.get('functions', []):
                    fid = func.get('function_id', '')
                    if func.get('execution_count', 0) > 0:
                        merged_functions[fid]['triggered'] = True
                        merged_functions[fid]['execution_count'] += func.get('execution_count', 0)
                jobs_processed += 1
        except Exception as e:
            print(f"Error reading {stats_file}: {e}", file=sys.stderr)
    
    result = {
        'commit': commit,
        'jobs_processed': jobs_processed,
        'functions': [
            {
                'function_id': fid,
                'triggered': data['triggered'],
                'execution_count': data['execution_count']
            }
            for fid, data in merged_functions.items()
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"✅ Merged {jobs_processed} jobs, {len(result['functions'])} functions")
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
    
    args = parser.parse_args()
    
    input_dir = Path(args.input_dir)
    
    if not input_dir.exists():
        print(f"❌ Input directory not found: {input_dir}", file=sys.stderr)
        return 1
    
    # Try to merge function counts first
    if merge_function_counts(input_dir, args.commit, args.output):
        return 0
    
    # Fall back to coverage stats
    print("No function count files found, trying coverage stats...", file=sys.stderr)
    if merge_coverage_stats(input_dir, args.commit, args.output):
        return 0
    
    print("⚠️ No results found to merge", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
