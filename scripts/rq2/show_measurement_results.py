#!/usr/bin/env python3
"""
Display measurement results summary.

Usage:
    python show_measurement_results.py <results_file>
    
Displays:
- Recipes processed
- Success/failure counts
- Total function calls
- Top 10 functions by call count
"""

import argparse
import json
import sys
from pathlib import Path


def show_results(results_file: str) -> bool:
    """
    Display measurement results summary.
    
    Returns True if file exists and was shown, False otherwise.
    """
    path = Path(results_file)
    
    if not path.exists():
        print(f"⚠️ Results file not found: {results_file}", file=sys.stderr)
        return False
    
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading results: {e}", file=sys.stderr)
        return False
    
    print("=" * 60)
    print("MEASUREMENT RESULTS")
    print("=" * 60)
    
    # Basic stats
    recipes = data.get('recipes_processed', 'N/A')
    successful = data.get('successful_runs', 'N/A')
    failed = data.get('failed_runs', 'N/A')
    total_calls = data.get('total_function_calls', 0)
    
    print(f"Recipes processed: {recipes}")
    print(f"Successful runs:   {successful}")
    print(f"Failed runs:       {failed}")
    
    if isinstance(total_calls, (int, float)):
        print(f"Total function calls: {total_calls:,}")
    else:
        print(f"Total function calls: {total_calls}")
    
    # Function breakdown
    counts = data.get('function_counts', {})
    if counts:
        print()
        print("Top 10 functions by call count:")
        sorted_funcs = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for func, count in sorted_funcs:
            print(f"  {count:>12,}  {func}")
    
    # Additional info
    elapsed = data.get('elapsed_seconds')
    if elapsed:
        rate = data.get('recipes_per_second', 0)
        print()
        print(f"Elapsed time: {elapsed:.1f}s ({rate:.1f} recipes/sec)")
    
    print("=" * 60)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Display measurement results summary"
    )
    parser.add_argument(
        "results_file",
        help="Path to measurement results JSON file"
    )
    
    args = parser.parse_args()
    
    success = show_results(args.results_file)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
