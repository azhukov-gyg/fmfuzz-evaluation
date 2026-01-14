#!/usr/bin/env python3
"""
Compare measurement results across baseline, variant1, and variant2.

Usage:
    python compare_measurements.py <measurements_dir> --output <output_file>
    
    measurements_dir: Directory containing measurements/{baseline,variant1,variant2}/*.json
    --output: Output JSON file for comparison results

Used by measurement comparison workflow.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path


def load_measurements(folder: Path) -> dict:
    """Load all measurement results from a folder."""
    results = {}
    
    for f in folder.glob("measurement-*.json"):
        # Extract commit hash from filename
        commit = f.stem.replace("measurement-", "")
        try:
            with open(f, 'r') as fp:
                results[commit] = json.load(fp)
        except Exception as e:
            print(f"Warning: Failed to load {f}: {e}", file=sys.stderr)
    
    return results


def compare_measurements(measurements_dir: str) -> dict:
    """Compare measurements across all variants."""
    base_path = Path(measurements_dir)
    
    # Load all measurements
    print("Loading measurements...", file=sys.stderr)
    baseline = load_measurements(base_path / "baseline")
    variant1 = load_measurements(base_path / "variant1")
    variant2 = load_measurements(base_path / "variant2")
    
    print(f"Baseline: {len(baseline)} commits", file=sys.stderr)
    print(f"Variant1: {len(variant1)} commits", file=sys.stderr)
    print(f"Variant2: {len(variant2)} commits", file=sys.stderr)
    
    # Find common commits
    common_commits = set(baseline.keys()) & set(variant1.keys()) & set(variant2.keys())
    print(f"Common commits (all 3 variants): {len(common_commits)}", file=sys.stderr)
    
    if not common_commits:
        return {
            "status": "partial",
            "baseline_commits": len(baseline),
            "variant1_commits": len(variant1),
            "variant2_commits": len(variant2),
            "common_commits": 0,
            "results": []
        }
    
    results = []
    
    for commit in sorted(common_commits):
        b = baseline[commit]
        v1 = variant1[commit]
        v2 = variant2[commit]
        
        # Calculate totals
        b_total = b.get('total_function_calls', 0)
        v1_total = v1.get('total_function_calls', 0)
        v2_total = v2.get('total_function_calls', 0)
        
        # Calculate recipes processed
        b_recipes = b.get('recipes_processed', 0)
        v1_recipes = v1.get('recipes_processed', 0)
        v2_recipes = v2.get('recipes_processed', 0)
        
        # Per-function comparison
        all_functions = set()
        all_functions.update(b.get('function_counts', {}).keys())
        all_functions.update(v1.get('function_counts', {}).keys())
        all_functions.update(v2.get('function_counts', {}).keys())
        
        total_functions = len(all_functions)
        
        # Count functions covered (non-zero calls) - CAN'T BE GAMED BY ITERATIONS
        b_funcs_covered = sum(1 for f in all_functions if b.get('function_counts', {}).get(f, 0) > 0)
        v1_funcs_covered = sum(1 for f in all_functions if v1.get('function_counts', {}).get(f, 0) > 0)
        v2_funcs_covered = sum(1 for f in all_functions if v2.get('function_counts', {}).get(f, 0) > 0)
        
        # Functions ONLY covered by each variant (exclusive coverage)
        b_only = sum(1 for f in all_functions if 
                     b.get('function_counts', {}).get(f, 0) > 0 and
                     v1.get('function_counts', {}).get(f, 0) == 0 and
                     v2.get('function_counts', {}).get(f, 0) == 0)
        v1_only = sum(1 for f in all_functions if 
                      v1.get('function_counts', {}).get(f, 0) > 0 and
                      b.get('function_counts', {}).get(f, 0) == 0 and
                      v2.get('function_counts', {}).get(f, 0) == 0)
        v2_only = sum(1 for f in all_functions if 
                      v2.get('function_counts', {}).get(f, 0) > 0 and
                      b.get('function_counts', {}).get(f, 0) == 0 and
                      v1.get('function_counts', {}).get(f, 0) == 0)
        
        function_comparison = []
        for func in sorted(all_functions):
            b_count = b.get('function_counts', {}).get(func, 0)
            v1_count = v1.get('function_counts', {}).get(func, 0)
            v2_count = v2.get('function_counts', {}).get(func, 0)
            
            function_comparison.append({
                "function": func,
                "baseline": b_count,
                "variant1": v1_count,
                "variant2": v2_count,
                "v1_vs_baseline": v1_count - b_count if b_count > 0 else None,
                "v2_vs_baseline": v2_count - b_count if b_count > 0 else None,
                "v2_vs_v1": v2_count - v1_count if v1_count > 0 else None,
            })
        
        # Line coverage metrics
        b_lines_hit = b.get('lines_hit', 0)
        b_lines_total = b.get('lines_total', 0)
        v1_lines_hit = v1.get('lines_hit', 0)
        v1_lines_total = v1.get('lines_total', 0)
        v2_lines_hit = v2.get('lines_hit', 0)
        v2_lines_total = v2.get('lines_total', 0)
        
        # Branch coverage metrics
        b_branches_taken = b.get('branches_taken', 0)
        b_branches_total = b.get('branches_total', 0)
        v1_branches_taken = v1.get('branches_taken', 0)
        v1_branches_total = v1.get('branches_total', 0)
        v2_branches_taken = v2.get('branches_taken', 0)
        v2_branches_total = v2.get('branches_total', 0)
        
        results.append({
            "commit": commit,
            "total_changed_functions": total_functions,
            "baseline": {
                "total_function_calls": b_total,
                "recipes_processed": b_recipes,
                "successful_runs": b.get('successful_runs', 0),
                "failed_runs": b.get('failed_runs', 0),
                # Function coverage metrics
                "functions_covered": b_funcs_covered,
                "coverage_breadth_pct": round(100.0 * b_funcs_covered / total_functions, 1) if total_functions > 0 else 0,
                "exclusive_functions": b_only,
                "calls_per_recipe": round(b_total / b_recipes, 2) if b_recipes > 0 else 0,
                # Line coverage
                "lines_hit": b_lines_hit,
                "lines_total": b_lines_total,
                "line_coverage_pct": round(100.0 * b_lines_hit / b_lines_total, 1) if b_lines_total > 0 else 0,
                # Branch coverage
                "branches_taken": b_branches_taken,
                "branches_total": b_branches_total,
                "branch_coverage_pct": round(100.0 * b_branches_taken / b_branches_total, 1) if b_branches_total > 0 else 0,
            },
            "variant1": {
                "total_function_calls": v1_total,
                "recipes_processed": v1_recipes,
                "successful_runs": v1.get('successful_runs', 0),
                "failed_runs": v1.get('failed_runs', 0),
                # Function coverage metrics
                "functions_covered": v1_funcs_covered,
                "coverage_breadth_pct": round(100.0 * v1_funcs_covered / total_functions, 1) if total_functions > 0 else 0,
                "exclusive_functions": v1_only,
                "calls_per_recipe": round(v1_total / v1_recipes, 2) if v1_recipes > 0 else 0,
                # Line coverage
                "lines_hit": v1_lines_hit,
                "lines_total": v1_lines_total,
                "line_coverage_pct": round(100.0 * v1_lines_hit / v1_lines_total, 1) if v1_lines_total > 0 else 0,
                # Branch coverage
                "branches_taken": v1_branches_taken,
                "branches_total": v1_branches_total,
                "branch_coverage_pct": round(100.0 * v1_branches_taken / v1_branches_total, 1) if v1_branches_total > 0 else 0,
            },
            "variant2": {
                "total_function_calls": v2_total,
                "recipes_processed": v2_recipes,
                "successful_runs": v2.get('successful_runs', 0),
                "failed_runs": v2.get('failed_runs', 0),
                # Function coverage metrics
                "functions_covered": v2_funcs_covered,
                "coverage_breadth_pct": round(100.0 * v2_funcs_covered / total_functions, 1) if total_functions > 0 else 0,
                "exclusive_functions": v2_only,
                "calls_per_recipe": round(v2_total / v2_recipes, 2) if v2_recipes > 0 else 0,
                # Line coverage
                "lines_hit": v2_lines_hit,
                "lines_total": v2_lines_total,
                "line_coverage_pct": round(100.0 * v2_lines_hit / v2_lines_total, 1) if v2_lines_total > 0 else 0,
                # Branch coverage
                "branches_taken": v2_branches_taken,
                "branches_total": v2_branches_total,
                "branch_coverage_pct": round(100.0 * v2_branches_taken / v2_branches_total, 1) if v2_branches_total > 0 else 0,
            },
            "function_comparison": function_comparison,
        })
    
    # Generate summary statistics
    n = len(results) if results else 1
    summary = {
        "total_commits": len(results),
        # Traditional metrics (can be gamed by iterations)
        "avg_baseline_calls": sum(r['baseline']['total_function_calls'] for r in results) / n if results else 0,
        "avg_variant1_calls": sum(r['variant1']['total_function_calls'] for r in results) / n if results else 0,
        "avg_variant2_calls": sum(r['variant2']['total_function_calls'] for r in results) / n if results else 0,
        # Function coverage breadth (CAN'T be gamed - measures diversity)
        "avg_baseline_coverage_pct": sum(r['baseline']['coverage_breadth_pct'] for r in results) / n if results else 0,
        "avg_variant1_coverage_pct": sum(r['variant1']['coverage_breadth_pct'] for r in results) / n if results else 0,
        "avg_variant2_coverage_pct": sum(r['variant2']['coverage_breadth_pct'] for r in results) / n if results else 0,
        # Exclusive coverage (functions ONLY covered by this variant)
        "total_baseline_exclusive": sum(r['baseline']['exclusive_functions'] for r in results) if results else 0,
        "total_variant1_exclusive": sum(r['variant1']['exclusive_functions'] for r in results) if results else 0,
        "total_variant2_exclusive": sum(r['variant2']['exclusive_functions'] for r in results) if results else 0,
        # Efficiency (calls per recipe)
        "avg_baseline_calls_per_recipe": sum(r['baseline']['calls_per_recipe'] for r in results) / n if results else 0,
        "avg_variant1_calls_per_recipe": sum(r['variant1']['calls_per_recipe'] for r in results) / n if results else 0,
        "avg_variant2_calls_per_recipe": sum(r['variant2']['calls_per_recipe'] for r in results) / n if results else 0,
        # Line coverage
        "avg_baseline_line_coverage_pct": sum(r['baseline']['line_coverage_pct'] for r in results) / n if results else 0,
        "avg_variant1_line_coverage_pct": sum(r['variant1']['line_coverage_pct'] for r in results) / n if results else 0,
        "avg_variant2_line_coverage_pct": sum(r['variant2']['line_coverage_pct'] for r in results) / n if results else 0,
        # Branch coverage
        "avg_baseline_branch_coverage_pct": sum(r['baseline']['branch_coverage_pct'] for r in results) / n if results else 0,
        "avg_variant1_branch_coverage_pct": sum(r['variant1']['branch_coverage_pct'] for r in results) / n if results else 0,
        "avg_variant2_branch_coverage_pct": sum(r['variant2']['branch_coverage_pct'] for r in results) / n if results else 0,
    }
    
    # Calculate ratios (traditional)
    if summary['avg_baseline_calls'] > 0:
        summary['v1_vs_baseline_ratio'] = summary['avg_variant1_calls'] / summary['avg_baseline_calls']
        summary['v2_vs_baseline_ratio'] = summary['avg_variant2_calls'] / summary['avg_baseline_calls']
    
    # Determine winner for each metric
    summary['winner_by_calls'] = max(['baseline', 'variant1', 'variant2'], 
                                      key=lambda v: summary[f'avg_{v}_calls'])
    summary['winner_by_coverage'] = max(['baseline', 'variant1', 'variant2'], 
                                         key=lambda v: summary[f'avg_{v}_coverage_pct'])
    summary['winner_by_exclusive'] = max(['baseline', 'variant1', 'variant2'], 
                                          key=lambda v: summary[f'total_{v}_exclusive'])
    summary['winner_by_line_coverage'] = max(['baseline', 'variant1', 'variant2'], 
                                              key=lambda v: summary[f'avg_{v}_line_coverage_pct'])
    summary['winner_by_branch_coverage'] = max(['baseline', 'variant1', 'variant2'], 
                                                key=lambda v: summary[f'avg_{v}_branch_coverage_pct'])
    
    return {
        "status": "complete",
        "baseline_commits": len(baseline),
        "variant1_commits": len(variant1),
        "variant2_commits": len(variant2),
        "common_commits": len(common_commits),
        "summary": summary,
        "results": results
    }


def print_summary(comparison: dict):
    """Print human-readable summary."""
    print("\n" + "="*70, file=sys.stderr)
    print("MEASUREMENT COMPARISON SUMMARY", file=sys.stderr)
    print("="*70, file=sys.stderr)
    
    if 'summary' in comparison:
        s = comparison['summary']
        print(f"Commits compared: {s['total_commits']}", file=sys.stderr)
        
        print(f"\n📊 METRIC 1: Total Function Calls (can be inflated by iterations)", file=sys.stderr)
        print(f"  Baseline:  {s['avg_baseline_calls']:,.0f}", file=sys.stderr)
        print(f"  Variant1:  {s['avg_variant1_calls']:,.0f}", file=sys.stderr)
        print(f"  Variant2:  {s['avg_variant2_calls']:,.0f}", file=sys.stderr)
        print(f"  🏆 Winner: {s.get('winner_by_calls', 'N/A')}", file=sys.stderr)
        
        if 'v1_vs_baseline_ratio' in s:
            print(f"\n  Ratios vs Baseline:", file=sys.stderr)
            print(f"    Variant1: {s['v1_vs_baseline_ratio']:.2f}x", file=sys.stderr)
            print(f"    Variant2: {s['v2_vs_baseline_ratio']:.2f}x", file=sys.stderr)
        
        print(f"\n📊 METRIC 2: Coverage Breadth % (CAN'T be gamed - measures diversity)", file=sys.stderr)
        print(f"  Baseline:  {s.get('avg_baseline_coverage_pct', 0):.1f}%", file=sys.stderr)
        print(f"  Variant1:  {s.get('avg_variant1_coverage_pct', 0):.1f}%", file=sys.stderr)
        print(f"  Variant2:  {s.get('avg_variant2_coverage_pct', 0):.1f}%", file=sys.stderr)
        print(f"  🏆 Winner: {s.get('winner_by_coverage', 'N/A')}", file=sys.stderr)
        
        print(f"\n📊 METRIC 3: Exclusive Functions (unique coverage not found by others)", file=sys.stderr)
        print(f"  Baseline:  {s.get('total_baseline_exclusive', 0)}", file=sys.stderr)
        print(f"  Variant1:  {s.get('total_variant1_exclusive', 0)}", file=sys.stderr)
        print(f"  Variant2:  {s.get('total_variant2_exclusive', 0)}", file=sys.stderr)
        print(f"  🏆 Winner: {s.get('winner_by_exclusive', 'N/A')}", file=sys.stderr)
        
        print(f"\n📊 METRIC 4: Calls per Recipe (efficiency)", file=sys.stderr)
        print(f"  Baseline:  {s.get('avg_baseline_calls_per_recipe', 0):.1f}", file=sys.stderr)
        print(f"  Variant1:  {s.get('avg_variant1_calls_per_recipe', 0):.1f}", file=sys.stderr)
        print(f"  Variant2:  {s.get('avg_variant2_calls_per_recipe', 0):.1f}", file=sys.stderr)
        
        print(f"\n📊 METRIC 5: Line Coverage % (depth within changed functions)", file=sys.stderr)
        print(f"  Baseline:  {s.get('avg_baseline_line_coverage_pct', 0):.1f}%", file=sys.stderr)
        print(f"  Variant1:  {s.get('avg_variant1_line_coverage_pct', 0):.1f}%", file=sys.stderr)
        print(f"  Variant2:  {s.get('avg_variant2_line_coverage_pct', 0):.1f}%", file=sys.stderr)
        print(f"  🏆 Winner: {s.get('winner_by_line_coverage', 'N/A')}", file=sys.stderr)
        
        print(f"\n📊 METRIC 6: Branch Coverage % (decision paths)", file=sys.stderr)
        print(f"  Baseline:  {s.get('avg_baseline_branch_coverage_pct', 0):.1f}%", file=sys.stderr)
        print(f"  Variant1:  {s.get('avg_variant1_branch_coverage_pct', 0):.1f}%", file=sys.stderr)
        print(f"  Variant2:  {s.get('avg_variant2_branch_coverage_pct', 0):.1f}%", file=sys.stderr)
        print(f"  🏆 Winner: {s.get('winner_by_branch_coverage', 'N/A')}", file=sys.stderr)
        
        print("\n" + "="*70, file=sys.stderr)
    else:
        print(f"Status: {comparison.get('status', 'unknown')}", file=sys.stderr)
        print(f"Baseline commits: {comparison.get('baseline_commits', 0)}", file=sys.stderr)
        print(f"Variant1 commits: {comparison.get('variant1_commits', 0)}", file=sys.stderr)
        print(f"Variant2 commits: {comparison.get('variant2_commits', 0)}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Compare measurement results across variants"
    )
    parser.add_argument(
        "measurements_dir",
        help="Directory containing measurements/{baseline,variant1,variant2}/*.json"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output JSON file for comparison results"
    )
    
    args = parser.parse_args()
    
    comparison = compare_measurements(args.measurements_dir)
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(comparison, f, indent=2)
    
    print(f"\nComparison saved to {args.output}", file=sys.stderr)
    
    # Print summary
    print_summary(comparison)


if __name__ == "__main__":
    main()
