#!/usr/bin/env python3
"""Aggregate comparison statistics from multiple commit comparisons

This script reads individual comparison JSON files and aggregates them
into a single report with overall statistics.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List


def load_comparison_files(comparisons_dir: Path) -> List[Dict]:
    """Load all comparison JSON files from a directory"""
    comparisons = []
    
    for comp_file in comparisons_dir.rglob("comparison_*.json"):
        try:
            with open(comp_file, 'r') as f:
                comp = json.load(f)
                comparisons.append(comp)
        except Exception as e:
            print(f"Warning: Failed to load {comp_file}: {e}", file=sys.stderr)
    
    return comparisons


def aggregate_comparisons(comparisons: List[Dict]) -> Dict:
    """Aggregate multiple comparison results into summary statistics"""
    if not comparisons:
        return {
            'aggregate': {
                'total_commits': 0,
                'baseline_better_commits': 0,
                'variant1_better_commits': 0,
                'total_baseline_better_functions': 0,
                'total_variant1_better_functions': 0,
                'total_both_triggered_functions': 0,
                'total_baseline_executions': 0,
                'total_variant1_executions': 0
            },
            'commits': []
        }
    
    aggregate = {
        'total_commits': len(comparisons),
        'baseline_better_commits': 0,
        'variant1_better_commits': 0,
        'total_baseline_better_functions': 0,
        'total_variant1_better_functions': 0,
        'total_both_triggered_functions': 0,
        'total_baseline_executions': 0,
        'total_variant1_executions': 0
    }
    
    for comp in comparisons:
        summary = comp.get('summary', {})
        
        # Count commits where one approach is better
        baseline_better = summary.get('baseline_better', 0)
        variant1_better = summary.get('variant1_better', 0)
        
        if baseline_better > variant1_better:
            aggregate['baseline_better_commits'] += 1
        elif variant1_better > baseline_better:
            aggregate['variant1_better_commits'] += 1
        
        # Sum up function counts
        aggregate['total_baseline_better_functions'] += baseline_better
        aggregate['total_variant1_better_functions'] += variant1_better
        aggregate['total_both_triggered_functions'] += summary.get('both_triggered', 0)
        aggregate['total_baseline_executions'] += summary.get('total_baseline_executions', 0)
        aggregate['total_variant1_executions'] += summary.get('total_variant1_executions', 0)
    
    return {
        'aggregate': aggregate,
        'commits': comparisons
    }


def print_statistics(aggregated: Dict):
    """Print all statistics to console"""
    aggregate = aggregated['aggregate']
    commits = aggregated['commits']
    
    print("=" * 60, file=sys.stderr)
    print("📊 AGGREGATED COMPARISON STATISTICS", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("", file=sys.stderr)
    
    # Print aggregate statistics
    print("🔢 Aggregate Statistics:", file=sys.stderr)
    print(f"  Total commits: {aggregate['total_commits']}", file=sys.stderr)
    print(f"  Baseline better commits: {aggregate['baseline_better_commits']}", file=sys.stderr)
    print(f"  Variant1 better commits: {aggregate['variant1_better_commits']}", file=sys.stderr)
    print(f"  Total baseline better functions: {aggregate['total_baseline_better_functions']}", file=sys.stderr)
    print(f"  Total variant1 better functions: {aggregate['total_variant1_better_functions']}", file=sys.stderr)
    print(f"  Total both triggered functions: {aggregate['total_both_triggered_functions']}", file=sys.stderr)
    print(f"  Total baseline executions: {aggregate['total_baseline_executions']:,}", file=sys.stderr)
    print(f"  Total variant1 executions: {aggregate['total_variant1_executions']:,}", file=sys.stderr)
    
    print("", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("📋 Per-Commit Statistics:", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("", file=sys.stderr)
    
    # Print per-commit statistics
    for comp in commits:
        commit_hash = comp.get('commit_hash', 'unknown')
        summary = comp.get('summary', {})
        functions = comp.get('functions', [])
        
        print(f"Commit: {commit_hash}", file=sys.stderr)
        print(f"  Total functions: {summary.get('total_functions', 0)}", file=sys.stderr)
        print(f"  Baseline triggered: {summary.get('baseline_triggered', 0)}", file=sys.stderr)
        print(f"  Variant1 triggered: {summary.get('variant1_triggered', 0)}", file=sys.stderr)
        print(f"  Both triggered: {summary.get('both_triggered', 0)}", file=sys.stderr)
        print(f"  Neither triggered: {summary.get('neither_triggered', 0)}", file=sys.stderr)
        print(f"  Baseline better: {summary.get('baseline_better', 0)}", file=sys.stderr)
        print(f"  Variant1 better: {summary.get('variant1_better', 0)}", file=sys.stderr)
        print(f"  Baseline more executions: {summary.get('baseline_more_executions', 0)}", file=sys.stderr)
        print(f"  Variant1 more executions: {summary.get('variant1_more_executions', 0)}", file=sys.stderr)
        print(f"  Total baseline executions: {summary.get('total_baseline_executions', 0):,}", file=sys.stderr)
        print(f"  Total variant1 executions: {summary.get('total_variant1_executions', 0):,}", file=sys.stderr)
        print("", file=sys.stderr)
        
        # Print per-function details
        if functions:
            print(f"  📝 Per-Function Details:", file=sys.stderr)
            for func in functions:
                func_id = func.get('function_id', 'unknown')
                baseline = func.get('baseline', {})
                variant1 = func.get('variant1', {})
                better = func.get('better', 'neither')
                
                baseline_triggered = baseline.get('triggered', False)
                variant1_triggered = variant1.get('triggered', False)
                baseline_exec = baseline.get('total_executions', 0)
                variant1_exec = variant1.get('total_executions', 0)
                
                status_icon = "✓" if (baseline_triggered or variant1_triggered) else "✗"
                better_icon = ""
                if better == "baseline":
                    better_icon = " [BASELINE BETTER]"
                elif better == "variant1":
                    better_icon = " [VARIANT1 BETTER]"
                
                # Print full function ID
                print(f"    {status_icon} {func_id}{better_icon}", file=sys.stderr)
                print(f"      Baseline: triggered={baseline_triggered}, executions={baseline_exec:,}", file=sys.stderr)
                print(f"      Variant1: triggered={variant1_triggered}, executions={variant1_exec:,}", file=sys.stderr)
                if baseline_triggered and variant1_triggered:
                    diff = baseline_exec - variant1_exec
                    if diff > 0:
                        print(f"      Difference: baseline has {diff:,} more executions", file=sys.stderr)
                    elif diff < 0:
                        print(f"      Difference: variant1 has {abs(diff):,} more executions", file=sys.stderr)
                    else:
                        print(f"      Difference: equal executions", file=sys.stderr)
            print("", file=sys.stderr)
    
    print("✅ Aggregated comparison complete", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description='Aggregate comparison statistics from multiple commits')
    parser.add_argument('--comparisons-dir', required=True, help='Directory containing comparison JSON files')
    parser.add_argument('--output', required=True, help='Output JSON file for aggregated results')
    
    args = parser.parse_args()
    
    comparisons_dir = Path(args.comparisons_dir)
    if not comparisons_dir.exists():
        print(f"Error: Comparisons directory not found: {comparisons_dir}", file=sys.stderr)
        sys.exit(1)
    
    print(f"🔍 Loading comparison files from {comparisons_dir}...", file=sys.stderr)
    comparisons = load_comparison_files(comparisons_dir)
    
    if not comparisons:
        print("❌ No comparison files found", file=sys.stderr)
        sys.exit(1)
    
    print(f"✅ Loaded {len(comparisons)} comparison files", file=sys.stderr)
    
    aggregated = aggregate_comparisons(comparisons)
    
    # Write to output file
    with open(args.output, 'w') as f:
        json.dump(aggregated, f, indent=2)
    
    print(f"✅ Aggregated comparison written to {args.output}", file=sys.stderr)
    
    # Print all statistics
    print_statistics(aggregated)


if __name__ == '__main__':
    main()

