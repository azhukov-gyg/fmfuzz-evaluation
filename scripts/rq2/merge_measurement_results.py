#!/usr/bin/env python3
"""
Merge measurement results from multiple parallel jobs.

This script merges measurement JSON files from separate jobs into a single result.
"""

import argparse
import glob
import json
import sys
from pathlib import Path


def merge_measurement_results(result_files: list, output_file: str) -> dict:
    """
    Merge measurement results from multiple parallel jobs.
    
    Function counts are summed across all jobs.
    """
    if not result_files:
        print("Error: No result files provided", file=sys.stderr)
        return {}
    
    merged = {
        "merged_from_jobs": len(result_files),
        "source_files": [],
        "recipes_processed": 0,
        "successful_runs": 0,
        "failed_runs": 0,
        "function_counts": {},
        "total_function_calls": 0,
        "changed_functions_tracked": 0,
        "elapsed_seconds": 0,
    }
    
    for result_file in result_files:
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)
            
            merged["source_files"].append(result_file)
            merged["recipes_processed"] += data.get("recipes_processed", 0)
            merged["successful_runs"] += data.get("successful_runs", 0)
            merged["failed_runs"] += data.get("failed_runs", 0)
            merged["elapsed_seconds"] = max(
                merged["elapsed_seconds"],
                data.get("elapsed_seconds", 0)
            )
            
            # Track changed functions count
            if data.get("changed_functions_tracked", 0) > merged["changed_functions_tracked"]:
                merged["changed_functions_tracked"] = data["changed_functions_tracked"]
            
            # Sum function counts
            for func, count in data.get("function_counts", {}).items():
                merged["function_counts"][func] = merged["function_counts"].get(func, 0) + count
            
            print(f"✓ Merged: {result_file} ({data.get('recipes_processed', 0)} recipes)")
            
        except Exception as e:
            print(f"⚠ Error reading {result_file}: {e}", file=sys.stderr)
    
    merged["total_function_calls"] = sum(merged["function_counts"].values())
    
    # Calculate rate
    if merged["elapsed_seconds"] > 0:
        merged["recipes_per_second"] = merged["recipes_processed"] / merged["elapsed_seconds"]
    
    # Save merged results
    with open(output_file, 'w') as f:
        json.dump(merged, f, indent=2)
    
    print(f"\n✅ Merged {len(merged['source_files'])} result files")
    print(f"   Total recipes: {merged['recipes_processed']}")
    print(f"   Total function calls: {merged['total_function_calls']:,}")
    print(f"   Saved to: {output_file}")
    
    return merged


def main():
    parser = argparse.ArgumentParser(description="Merge measurement results from parallel jobs")
    parser.add_argument("output_file", help="Output merged JSON file")
    parser.add_argument("result_patterns", nargs="+", help="Glob patterns or paths to result JSON files")
    
    args = parser.parse_args()
    
    # Expand glob patterns
    result_files = []
    for pattern in args.result_patterns:
        matches = glob.glob(pattern)
        if matches:
            result_files.extend(matches)
        elif Path(pattern).exists():
            result_files.append(pattern)
    
    result_files = sorted(set(result_files))
    
    if not result_files:
        print(f"Error: No result files found matching patterns", file=sys.stderr)
        sys.exit(1)
    
    print(f"Found {len(result_files)} result files to merge")
    merge_measurement_results(result_files, args.output_file)


if __name__ == "__main__":
    main()
