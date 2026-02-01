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
        print("No results to display")
        return

    # Show example from first commit
    example = data['results'][0]
    print(f"\nExample commit: {example['commit'][:8]}")

    final = example.get('final_comparison')
    if not final:
        print("  No final comparison data available")
        return

    baseline = final.get('baseline', {})
    variant1 = final.get('variant1', {})
    variant2 = final.get('variant2', {})

    print(f"  Baseline final:  {baseline.get('lines_coverage_pct', 0):.2f}% lines, "
          f"{baseline.get('branches_coverage_pct', 0):.2f}% branches")
    print(f"  Variant1 final:  {variant1.get('lines_coverage_pct', 0):.2f}% lines, "
          f"{variant1.get('branches_coverage_pct', 0):.2f}% branches")
    print(f"  Variant2 final:  {variant2.get('lines_coverage_pct', 0):.2f}% lines, "
          f"{variant2.get('branches_coverage_pct', 0):.2f}% branches")

    # Show improvements
    v1_vs_b = final.get('variant1_vs_baseline', {})
    v2_vs_b = final.get('variant2_vs_baseline', {})

    if v1_vs_b:
        print(f"\n  Variant1 vs Baseline:")
        print(f"    Lines: {v1_vs_b.get('lines_diff', 0):+.2f}%")
        print(f"    Branches: {v1_vs_b.get('branches_diff', 0):+.2f}%")

    if v2_vs_b:
        print(f"\n  Variant2 vs Baseline:")
        print(f"    Lines: {v2_vs_b.get('lines_diff', 0):+.2f}%")
        print(f"    Branches: {v2_vs_b.get('branches_diff', 0):+.2f}%")


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
