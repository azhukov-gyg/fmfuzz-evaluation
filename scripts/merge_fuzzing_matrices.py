#!/usr/bin/env python3
"""
Merge multiple fuzzing matrix files into a single matrix.

Usage:
    python3 merge_fuzzing_matrices.py <output_file> <pattern> [--minimal-output <minimal_file>]

Reads all matrix files matching the pattern and merges them into a single
matrix file. Also creates a minimal version (commit + job_id only) for
job outputs to avoid GitHub Actions size limits.
"""

import json
import sys
import argparse
from pathlib import Path
from glob import glob


def load_matrix_file(file_path):
    """Load a matrix file, handling both object and array formats."""
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Handle both formats: {"include": [...]} or [...]
    if isinstance(data, dict) and 'include' in data:
        return data['include']
    elif isinstance(data, list):
        return data
    else:
        raise ValueError(f"Unexpected matrix format in {file_path}")


def merge_matrices(matrix_files, output_file, minimal_output_file=None):
    """
    Merge multiple matrix files into one.
    
    Args:
        matrix_files: List of matrix file paths
        output_file: Path to write the full merged matrix
        minimal_output_file: Optional path to write minimal matrix (commit + job_id only)
    """
    all_entries = []
    
    for matrix_file in sorted(matrix_files):
        try:
            entries = load_matrix_file(matrix_file)
            # Filter out non-object entries
            valid_entries = [e for e in entries if isinstance(e, dict)]
            all_entries.extend(valid_entries)
            print(f"  Loaded {len(valid_entries)} entries from {matrix_file}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Failed to load {matrix_file}: {e}", file=sys.stderr)
            continue
    
    # Create full matrix structure
    full_matrix = {'include': all_entries}
    
    with open(output_file, 'w') as f:
        json.dump(full_matrix, f, separators=(',', ':'))
    
    print(f"✅ Merged {len(all_entries)} total fuzzing jobs", file=sys.stderr)
    print(f"   Full matrix written to: {output_file}", file=sys.stderr)
    
    # Create minimal matrix if requested
    if minimal_output_file:
        minimal_entries = []
        for entry in all_entries:
            if not isinstance(entry, dict):
                continue
            
            # Handle both fuzzing matrix format (nested fuzzer_job) and measurement matrix format (flat)
            if 'fuzzer_job' in entry:
                # Fuzzing matrix format: {"commit": ..., "fuzzer_job": {"job_id": ...}}
                job_id = entry['fuzzer_job'].get('job_id')
            else:
                # Measurement/flat format: {"commit": ..., "job_id": ...}
                job_id = entry.get('job_id')
            
            # Validate job_id
            if job_id is None:
                print(f"Warning: entry missing job_id: {entry}", file=sys.stderr)
            
            minimal_entries.append({
                'commit': entry.get('commit'),
                'job_id': job_id
            })
        
        minimal_matrix = {'include': minimal_entries}
        
        with open(minimal_output_file, 'w') as f:
            json.dump(minimal_matrix, f, separators=(',', ':'))
        
        print(f"   Minimal matrix written to: {minimal_output_file}", file=sys.stderr)
    
    return len(all_entries)


def main():
    parser = argparse.ArgumentParser(
        description='Merge multiple fuzzing matrix files into a single matrix'
    )
    parser.add_argument('output_file', type=Path, help='Output file for full merged matrix')
    parser.add_argument('pattern', help='Glob pattern to find matrix files (e.g., "matrices/*/combined_matrix.json")')
    parser.add_argument('--minimal-output', type=Path, help='Optional: output file for minimal matrix (commit + job_id only)')
    
    args = parser.parse_args()
    
    # Find all matrix files matching the pattern
    matrix_files = glob(args.pattern, recursive=True)
    
    if not matrix_files:
        print(f"Warning: No matrix files found matching pattern: {args.pattern}", file=sys.stderr)
        # Create empty matrix
        with open(args.output_file, 'w') as f:
            json.dump({'include': []}, f)
        if args.minimal_output:
            with open(args.minimal_output, 'w') as f:
                json.dump({'include': []}, f)
        print("0", file=sys.stdout)  # Output count for GitHub Actions
        return 0
    
    print(f"Found {len(matrix_files)} matrix files to merge", file=sys.stderr)
    
    # Merge matrices
    total_jobs = merge_matrices(matrix_files, args.output_file, args.minimal_output)
    
    # Output total count for GitHub Actions
    print(str(total_jobs), file=sys.stdout)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

