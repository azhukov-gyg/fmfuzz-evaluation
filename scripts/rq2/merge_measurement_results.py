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
        # Line coverage
        "line_coverage": {},
        "lines_hit": 0,
        "lines_total": 0,
        # Branch coverage
        "branch_coverage": {},
        "branches_taken": 0,
        "branches_total": 0,
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
            
            # Merge line coverage (sum hit counts per line)
            for line_key, hit_count in data.get("line_coverage", {}).items():
                merged["line_coverage"][line_key] = merged["line_coverage"].get(line_key, 0) + hit_count
            
            # Merge branch coverage (sum taken counts per branch)
            for branch_key, taken_count in data.get("branch_coverage", {}).items():
                merged["branch_coverage"][branch_key] = merged["branch_coverage"].get(branch_key, 0) + taken_count
            
            print(f"✓ Merged: {result_file} ({data.get('recipes_processed', 0)} recipes)")
            
        except Exception as e:
            print(f"⚠ Error reading {result_file}: {e}", file=sys.stderr)
    
    merged["total_function_calls"] = sum(merged["function_counts"].values())
    
    # Compute line coverage aggregates (unique lines hit vs total unique lines)
    merged["lines_hit"] = sum(1 for v in merged["line_coverage"].values() if v > 0)
    merged["lines_total"] = len(merged["line_coverage"])
    
    # Compute branch coverage aggregates (unique branches taken vs total unique branches)
    merged["branches_taken"] = sum(1 for v in merged["branch_coverage"].values() if v > 0)
    merged["branches_total"] = len(merged["branch_coverage"])
    
    # Calculate rate
    if merged["elapsed_seconds"] > 0:
        merged["recipes_per_second"] = merged["recipes_processed"] / merged["elapsed_seconds"]
    
    # Save merged results
    with open(output_file, 'w') as f:
        json.dump(merged, f, indent=2)
    
    # Calculate percentages for display
    lines_pct = 100.0 * merged["lines_hit"] / merged["lines_total"] if merged["lines_total"] > 0 else 0
    branches_pct = 100.0 * merged["branches_taken"] / merged["branches_total"] if merged["branches_total"] > 0 else 0
    
    print(f"\n✅ Merged {len(merged['source_files'])} result files")
    print(f"   Total recipes: {merged['recipes_processed']}")
    print(f"   Total function calls: {merged['total_function_calls']:,}")
    print(f"   Lines hit: {merged['lines_hit']}/{merged['lines_total']} ({lines_pct:.1f}%)")
    print(f"   Branches taken: {merged['branches_taken']}/{merged['branches_total']} ({branches_pct:.1f}%)")
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
