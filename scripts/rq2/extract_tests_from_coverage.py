#!/usr/bin/env python3
"""Extract unique tests from coverage mapping

This script reads a coverage mapping JSON file and extracts all unique test names
that successfully ran (didn't timeout or crash). This ensures we only fuzz with
tests that are known to work in the setup.
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Set

def extract_tests_from_coverage(coverage_file: Path) -> Set[str]:
    """Extract all unique test names from coverage mapping"""
    try:
        with open(coverage_file, 'r') as f:
            coverage_map = json.load(f)
        
        all_tests = set()
        for tests in coverage_map.values():
            if isinstance(tests, (list, set)):
                all_tests.update(tests)
            elif isinstance(tests, str):
                all_tests.add(tests)
        
        return all_tests
    except Exception as e:
        print(f"Error reading coverage mapping: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return set()

def main():
    parser = argparse.ArgumentParser(description='Extract unique tests from coverage mapping')
    parser.add_argument('--coverage-mapping', required=True, help='Path to coverage mapping JSON file')
    parser.add_argument('--output', required=True, help='Output JSON file with test list')
    parser.add_argument('--seed', type=int, default=42, help='Random seed for reproducibility (default: 42)')
    
    args = parser.parse_args()
    
    coverage_file = Path(args.coverage_mapping)
    if not coverage_file.exists():
        print(f"Error: Coverage mapping file not found: {coverage_file}", file=sys.stderr)
        sys.exit(1)
    
    print(f"🔍 Extracting tests from coverage mapping: {coverage_file}", file=sys.stderr)
    all_tests = extract_tests_from_coverage(coverage_file)
    
    if not all_tests:
        print("❌ No tests found in coverage mapping", file=sys.stderr)
        sys.exit(1)
    
    # Convert to sorted list for consistent ordering
    sorted_tests = sorted(all_tests)
    print(f"✅ Found {len(sorted_tests)} unique tests from coverage mapping", file=sys.stderr)
    
    # Shuffle tests in random order (for reproducibility with seed)
    import random
    random.seed(args.seed)
    shuffled_tests = sorted_tests.copy()
    random.shuffle(shuffled_tests)
    
    print(f"✅ Shuffled {len(shuffled_tests)} tests in random order (seed: {args.seed})", file=sys.stderr)
    
    # Create matrix structure (similar to pick_random_tests.py output)
    # Split into 4 jobs (same as variant1)
    tests_per_job = (len(shuffled_tests) + 3) // 4  # Ceil division
    jobs = []
    
    for i in range(0, len(shuffled_tests), tests_per_job):
        job_tests = shuffled_tests[i:i + tests_per_job]
        job_id = i // tests_per_job
        jobs.append({
            'job_id': job_id,
            'tests': job_tests
        })
    
    output = {
        'matrix': {'include': jobs},
        'total_tests': len(shuffled_tests),
        'total_jobs': len(jobs),
        'tests_per_job': tests_per_job
    }
    
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"✅ Wrote matrix to {args.output} with {len(shuffled_tests)} tests in {len(jobs)} jobs", file=sys.stderr)

if __name__ == '__main__':
    main()

