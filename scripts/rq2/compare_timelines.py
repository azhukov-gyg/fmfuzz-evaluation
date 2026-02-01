#!/usr/bin/env python3
"""
Compare timeline data across baseline, variant1, and variant2 to show coverage growth over time.

Usage:
    python compare_timelines.py <timelines_dir> --output <output_file>

    timelines_dir: Directory containing timelines/{baseline,variant1,variant2}/*.json
    --output: Output JSON file for timeline comparison results

Shows how coverage evolves over time for each variant, useful for understanding:
- Which variant reaches X% coverage faster?
- How does coverage growth rate differ between variants?
- Does baseline saturate quickly while variants continue growing?
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List


def load_timelines(folder: Path) -> Dict[str, dict]:
    """Load all cumulative timeline files from a folder."""
    results = {}

    for f in folder.glob("timeline-*.json"):
        # Extract commit hash from filename
        commit = f.stem.replace("timeline-", "")
        try:
            with open(f, 'r') as fp:
                results[commit] = json.load(fp)
        except Exception as e:
            print(f"Warning: Failed to load {f}: {e}", file=sys.stderr)

    return results


def align_checkpoints_by_time(checkpoints: List[dict], time_key: str = 'fuzzing_time_seconds') -> List[dict]:
    """Sort and return checkpoints by time."""
    return sorted(checkpoints, key=lambda c: c.get(time_key, 0))


def compare_timelines(timelines_dir: str, time_key: str = 'fuzzing_time_seconds') -> dict:
    """
    Compare timeline data across all variants.

    Args:
        timelines_dir: Directory containing timeline subdirectories
        time_key: Which timestamp to use ('fuzzing_time_seconds' or 'avg_wall_time_seconds')
    """
    base_path = Path(timelines_dir)

    # Load all timelines
    print("Loading timelines...", file=sys.stderr)
    baseline = load_timelines(base_path / "baseline")
    variant1 = load_timelines(base_path / "variant1")
    variant2 = load_timelines(base_path / "variant2")

    print(f"Baseline: {len(baseline)} commits", file=sys.stderr)
    print(f"Variant1: {len(variant1)} commits", file=sys.stderr)
    print(f"Variant2: {len(variant2)} commits", file=sys.stderr)

    # Find common commits
    common_commits = set(baseline.keys()) & set(variant1.keys()) & set(variant2.keys())
    print(f"Common commits (all 3 variants): {len(common_commits)}", file=sys.stderr)

    if not common_commits:
        return {
            "status": "partial",
            "time_axis": time_key,
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

        # Get checkpoint lists
        b_checkpoints = b.get('cumulative_checkpoints', [])
        v1_checkpoints = v1.get('cumulative_checkpoints', [])
        v2_checkpoints = v2.get('cumulative_checkpoints', [])

        # Align by time
        b_timeline = align_checkpoints_by_time(b_checkpoints, time_key)
        v1_timeline = align_checkpoints_by_time(v1_checkpoints, time_key)
        v2_timeline = align_checkpoints_by_time(v2_checkpoints, time_key)

        # Extract key metrics at each checkpoint
        def extract_metrics(checkpoints):
            return [{
                'time': c.get(time_key, 0),
                'recipes_processed': c.get('recipes_processed', 0),
                'lines_hit': c.get('lines_hit', 0),
                'lines_total': c.get('lines_total', 0),
                'lines_coverage_pct': c.get('lines_coverage_pct', 0),
                'branches_taken': c.get('branches_taken', 0),
                'branches_total': c.get('branches_total', 0),
                'branches_coverage_pct': c.get('branches_coverage_pct', 0),
            } for c in checkpoints]

        result = {
            'commit': commit,
            'baseline_timeline': extract_metrics(b_timeline),
            'variant1_timeline': extract_metrics(v1_timeline),
            'variant2_timeline': extract_metrics(v2_timeline),
        }

        # Add final coverage comparison
        if b_timeline and v1_timeline and v2_timeline:
            b_final = b_timeline[-1]
            v1_final = v1_timeline[-1]
            v2_final = v2_timeline[-1]

            result['final_comparison'] = {
                'baseline': {
                    'lines_coverage_pct': b_final.get('lines_coverage_pct', 0),
                    'branches_coverage_pct': b_final.get('branches_coverage_pct', 0),
                    'recipes_processed': b_final.get('recipes_processed', 0),
                },
                'variant1': {
                    'lines_coverage_pct': v1_final.get('lines_coverage_pct', 0),
                    'branches_coverage_pct': v1_final.get('branches_coverage_pct', 0),
                    'recipes_processed': v1_final.get('recipes_processed', 0),
                },
                'variant2': {
                    'lines_coverage_pct': v2_final.get('lines_coverage_pct', 0),
                    'branches_coverage_pct': v2_final.get('branches_coverage_pct', 0),
                    'recipes_processed': v2_final.get('recipes_processed', 0),
                },
                # Calculate improvements
                'variant1_vs_baseline': {
                    'lines_diff': v1_final.get('lines_coverage_pct', 0) - b_final.get('lines_coverage_pct', 0),
                    'branches_diff': v1_final.get('branches_coverage_pct', 0) - b_final.get('branches_coverage_pct', 0),
                },
                'variant2_vs_baseline': {
                    'lines_diff': v2_final.get('lines_coverage_pct', 0) - b_final.get('lines_coverage_pct', 0),
                    'branches_diff': v2_final.get('branches_coverage_pct', 0) - b_final.get('branches_coverage_pct', 0),
                },
            }

        results.append(result)

    return {
        "status": "complete",
        "time_axis": time_key,
        "baseline_commits": len(baseline),
        "variant1_commits": len(variant1),
        "variant2_commits": len(variant2),
        "common_commits": len(common_commits),
        "results": results
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compare timeline data across baseline and variants"
    )
    parser.add_argument(
        "timelines_dir",
        help="Directory containing timeline subdirectories (baseline, variant1, variant2)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file for comparison results"
    )
    parser.add_argument(
        "--time-axis",
        choices=["fuzzing_time_seconds", "avg_wall_time_seconds"],
        default="fuzzing_time_seconds",
        help="Which time axis to use for alignment (default: fuzzing_time_seconds)"
    )

    args = parser.parse_args()

    comparison = compare_timelines(args.timelines_dir, args.time_axis)

    # Save comparison
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(comparison, f, indent=2)

    print(f"\n✅ Timeline comparison saved to: {args.output}")
    print(f"   Status: {comparison['status']}")
    print(f"   Time axis: {comparison['time_axis']}")
    print(f"   Common commits: {comparison['common_commits']}")


if __name__ == "__main__":
    main()
