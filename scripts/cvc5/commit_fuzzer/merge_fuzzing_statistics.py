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


def merge_statistics(statistics_files: List[Path], commit_hash: str = None, 
                    coverage_map_commit: str = None) -> Dict:
    """Merge statistics from multiple job files"""
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
    
    args = parser.parse_args()
    
    # Validate files exist
    for f in args.statistics_files:
        if not f.exists():
            print(f"Error: Statistics file not found: {f}", file=sys.stderr)
            sys.exit(1)
    
    # Merge statistics
    merged = merge_statistics(args.statistics_files, args.commit_hash, args.coverage_map_commit)
    
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

