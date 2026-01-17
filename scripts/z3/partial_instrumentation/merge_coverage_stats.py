#!/usr/bin/env python3
"""
Merge coverage statistics from multiple fuzzing jobs for Z3.

Reads coverage_stats.json files from multiple jobs and merges them into a single
statistics file for upload to S3.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List


def load_coverage_stats(json_path: Path) -> Dict:
    """Load coverage statistics from JSON file."""
    try:
        with open(json_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not load {json_path}: {e}", file=sys.stderr)
        return {}


def merge_stats(stats_list: List[Dict]) -> Dict:
    """Merge multiple coverage statistics dictionaries."""
    if not stats_list:
        return {}
    
    merged = {
        'total_instrumented_edges': 0,
        'edges_covered': 0,
        'coverage_percentage': 0.0,
        'new_edges_discovered': 0,
        'mutants_with_new_coverage': 0,
        'mutants_with_existing_coverage': 0,
        'mutants_created': 0,
        'mutants_discarded_no_coverage': 0,
        'mutants_discarded_disk_space': 0,
        'generations_completed': 0,
        'tests_processed': 0,
        'bugs_found': 0,
        'runtime_seconds': 0.0,
    }
    
    # Sum numeric values
    for stats in stats_list:
        if not stats:
            continue
        
        merged['total_instrumented_edges'] = max(
            merged['total_instrumented_edges'],
            stats.get('total_instrumented_edges', 0)
        )
        merged['edges_covered'] = max(
            merged['edges_covered'],
            stats.get('edges_covered', 0)
        )
        merged['new_edges_discovered'] = max(
            merged['new_edges_discovered'],
            stats.get('new_edges_discovered', 0)
        )
        merged['mutants_with_new_coverage'] += stats.get('mutants_with_new_coverage', 0)
        merged['mutants_with_existing_coverage'] += stats.get('mutants_with_existing_coverage', 0)
        merged['mutants_created'] += stats.get('mutants_created', 0)
        merged['mutants_discarded_no_coverage'] += stats.get('mutants_discarded_no_coverage', 0)
        merged['mutants_discarded_disk_space'] += stats.get('mutants_discarded_disk_space', 0)
        merged['generations_completed'] = max(
            merged['generations_completed'],
            stats.get('generations_completed', 0)
        )
        merged['tests_processed'] += stats.get('tests_processed', 0)
        merged['bugs_found'] += stats.get('bugs_found', 0)
        merged['runtime_seconds'] += stats.get('runtime_seconds', 0.0)
    
    # Calculate coverage percentage
    if merged['total_instrumented_edges'] > 0:
        merged['coverage_percentage'] = (
            merged['edges_covered'] / merged['total_instrumented_edges'] * 100.0
        )
    
    return merged


def main():
    parser = argparse.ArgumentParser(
        description="Merge coverage statistics from multiple fuzzing jobs"
    )
    parser.add_argument(
        '--input',
        nargs='+',
        required=True,
        help='Input coverage_stats.json files to merge'
    )
    parser.add_argument(
        '--output',
        type=Path,
        required=True,
        help='Output merged statistics JSON file'
    )
    
    args = parser.parse_args()
    
    # Load all statistics
    stats_list = []
    for input_path in args.input:
        path = Path(input_path)
        if path.exists():
            stats = load_coverage_stats(path)
            if stats:
                stats_list.append(stats)
        else:
            print(f"Warning: Input file not found: {path}", file=sys.stderr)
    
    if not stats_list:
        print("Error: No valid statistics files found", file=sys.stderr)
        sys.exit(1)
    
    # Merge statistics
    merged = merge_stats(stats_list)
    
    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(merged, f, indent=2)
    
    print(f"Merged {len(stats_list)} statistics files")
    print(f"Output: {args.output}")
    print(f"Total edges covered: {merged['edges_covered']}")
    print(f"Coverage percentage: {merged['coverage_percentage']:.2f}%")
    print(f"Tests processed: {merged['tests_processed']}")
    print(f"Mutants created: {merged['mutants_created']}")


if __name__ == '__main__':
    main()
