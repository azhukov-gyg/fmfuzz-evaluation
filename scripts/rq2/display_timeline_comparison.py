#!/usr/bin/env python3
"""
Display timeline comparison summary from comparison JSON file.
"""

import argparse
import json
import sys


def display_summary(comparison_file: str):
    """Display a summary of timeline comparison results."""
    try:
        with open(comparison_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading comparison file: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Status: {data['status']}")
    print(f"Time axis: {data.get('time_axis', 'unknown')}")
    print(f"Common commits: {data['common_commits']}")

    if not data.get('results'):
        print("\nNo results to display")
        return

    print("\n" + "=" * 100)
    print("TIMELINE PROGRESSION PER COMMIT")
    print("=" * 100)

    # Show timeline progression for all commits
    for result in data['results']:
        commit = result['commit']
        print(f"\nCommit: {commit}")
        print("=" * 100)

        baseline_timeline = result.get('baseline_timeline', [])
        variant1_timeline = result.get('variant1_timeline', [])
        variant2_timeline = result.get('variant2_timeline', [])

        if not (baseline_timeline or variant1_timeline or variant2_timeline):
            print("  No timeline data available")
            continue

        # Collect all unique time points
        all_times = set()
        for checkpoint in baseline_timeline:
            all_times.add(checkpoint.get('time', 0))
        for checkpoint in variant1_timeline:
            all_times.add(checkpoint.get('time', 0))
        for checkpoint in variant2_timeline:
            all_times.add(checkpoint.get('time', 0))

        # Show table header
        print(f"\n{'Time':>6s}  {'Baseline Lines':>15s}  {'Baseline Branches':>17s}  {'Variant1 Lines':>15s}  {'Variant1 Branches':>17s}  {'Variant2 Lines':>15s}  {'Variant2 Branches':>17s}")
        print(f"{'(s)':>6s}  {'(hit/total/%)':>15s}  {'(taken/total/%)':>17s}  {'(hit/total/%)':>15s}  {'(taken/total/%)':>17s}  {'(hit/total/%)':>15s}  {'(taken/total/%)':>17s}")
        print("-" * 100)

        # Create lookup dictionaries for each variant
        baseline_by_time = {c.get('time', 0): c for c in baseline_timeline}
        variant1_by_time = {c.get('time', 0): c for c in variant1_timeline}
        variant2_by_time = {c.get('time', 0): c for c in variant2_timeline}

        # Show progression at each time point
        for time_point in sorted(all_times):
            b_ck = baseline_by_time.get(time_point, {})
            v1_ck = variant1_by_time.get(time_point, {})
            v2_ck = variant2_by_time.get(time_point, {})

            # Format baseline
            b_lines = f"{b_ck.get('lines_hit', 0)}/{b_ck.get('lines_total', 0)} ({b_ck.get('lines_coverage_pct', 0):.1f}%)" if b_ck else "-"
            b_branches = f"{b_ck.get('branches_taken', 0)}/{b_ck.get('branches_total', 0)} ({b_ck.get('branches_coverage_pct', 0):.1f}%)" if b_ck else "-"

            # Format variant1
            v1_lines = f"{v1_ck.get('lines_hit', 0)}/{v1_ck.get('lines_total', 0)} ({v1_ck.get('lines_coverage_pct', 0):.1f}%)" if v1_ck else "-"
            v1_branches = f"{v1_ck.get('branches_taken', 0)}/{v1_ck.get('branches_total', 0)} ({v1_ck.get('branches_coverage_pct', 0):.1f}%)" if v1_ck else "-"

            # Format variant2
            v2_lines = f"{v2_ck.get('lines_hit', 0)}/{v2_ck.get('lines_total', 0)} ({v2_ck.get('lines_coverage_pct', 0):.1f}%)" if v2_ck else "-"
            v2_branches = f"{v2_ck.get('branches_taken', 0)}/{v2_ck.get('branches_total', 0)} ({v2_ck.get('branches_coverage_pct', 0):.1f}%)" if v2_ck else "-"

            print(f"{time_point:6.0f}  {b_lines:>15s}  {b_branches:>17s}  {v1_lines:>15s}  {v1_branches:>17s}  {v2_lines:>15s}  {v2_branches:>17s}")

        # Show final comparison
        final = result.get('final_comparison')
        if final:
            v1_vs_b = final.get('variant1_vs_baseline', {})
            v2_vs_b = final.get('variant2_vs_baseline', {})

            print("\n" + "-" * 100)
            print("FINAL IMPROVEMENTS:")
            if v1_vs_b:
                print(f"  Variant1 vs Baseline: {v1_vs_b.get('lines_diff', 0):+.2f}% lines, "
                      f"{v1_vs_b.get('branches_diff', 0):+.2f}% branches")
            if v2_vs_b:
                print(f"  Variant2 vs Baseline: {v2_vs_b.get('lines_diff', 0):+.2f}% lines, "
                      f"{v2_vs_b.get('branches_diff', 0):+.2f}% branches")


def main():
    parser = argparse.ArgumentParser(
        description="Display timeline comparison summary"
    )
    parser.add_argument(
        "comparison_file",
        help="Timeline comparison JSON file"
    )
    args = parser.parse_args()

    display_summary(args.comparison_file)


if __name__ == "__main__":
    main()
