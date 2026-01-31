#!/usr/bin/env python3
"""
Merge timeline data from multiple parallel jobs into a cumulative timeline.

Each job processes different recipes in parallel and records checkpoints at regular intervals.
This script merges checkpoints from all jobs, sorted by wall time, to create a unified timeline
showing cumulative coverage growth across all parallel jobs.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any


def load_timeline_checkpoints(timeline_files: List[str]) -> List[Dict[str, Any]]:
    """
    Load all checkpoints from timeline JSONL files.

    Args:
        timeline_files: List of paths to *_timeline.jsonl files

    Returns:
        List of checkpoint dictionaries from all files
    """
    all_checkpoints = []

    for timeline_file in timeline_files:
        try:
            with open(timeline_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        checkpoint = json.loads(line)
                        # Track source file for debugging
                        checkpoint['source_file'] = Path(timeline_file).name
                        all_checkpoints.append(checkpoint)
        except Exception as e:
            print(f"ERROR loading {timeline_file}: {e}", file=sys.stderr)
            continue

    return all_checkpoints


def merge_checkpoints_by_time(
    checkpoints: List[Dict[str, Any]],
    checkpoint_interval: int
) -> List[Dict[str, Any]]:
    """
    Merge checkpoints from parallel jobs into time-aligned cumulative checkpoints.

    Since jobs run in parallel on different recipes, we align checkpoints to common
    time intervals (e.g., 60s, 120s, 180s) and aggregate metrics.

    IMPORTANT: Coverage metrics (lines_hit, branches_taken) are summed across jobs.
    This is an approximation that assumes minimal overlap in which lines/branches
    are covered by different jobs' recipes. The true merged coverage can only be
    determined by merging .gcda files at the end, which the workflow does separately.

    The cumulative timeline shows:
    - Total recipes processed (exact)
    - Approximate combined coverage (may slightly overestimate if there's overlap)

    Args:
        checkpoints: All checkpoints from all jobs
        checkpoint_interval: Interval in seconds (e.g., 60)

    Returns:
        List of cumulative checkpoints aligned to time intervals
    """
    # Group checkpoints by time bucket
    time_buckets = {}

    for checkpoint in checkpoints:
        wall_time = checkpoint.get('wall_time_seconds', 0)
        # Round to nearest interval (e.g., 65s -> 60s bucket)
        time_bucket = round(wall_time / checkpoint_interval) * checkpoint_interval

        if time_bucket not in time_buckets:
            time_buckets[time_bucket] = []

        time_buckets[time_bucket].append(checkpoint)

    # Create cumulative checkpoints for each time bucket
    cumulative_checkpoints = []

    for time_bucket in sorted(time_buckets.keys()):
        bucket_checkpoints = time_buckets[time_bucket]

        # Sum metrics from all jobs at this time point
        cumulative = {
            'time_seconds': time_bucket,
            'num_jobs': len(bucket_checkpoints),
            'recipes_processed': sum(c.get('recipes_processed', 0) for c in bucket_checkpoints),
            'lines_hit': sum(c.get('lines_hit', 0) for c in bucket_checkpoints),
            'branches_taken': sum(c.get('branches_taken', 0) for c in bucket_checkpoints),
            'function_calls': sum(c.get('function_calls', 0) for c in bucket_checkpoints),
        }

        # Take static totals from first checkpoint (should be same across all jobs)
        first_checkpoint = bucket_checkpoints[0]
        if 'lines_total' in first_checkpoint:
            cumulative['lines_total'] = first_checkpoint['lines_total']
            cumulative['lines_coverage_pct'] = (
                100.0 * cumulative['lines_hit'] / cumulative['lines_total']
                if cumulative['lines_total'] > 0 else 0.0
            )

        if 'branches_total' in first_checkpoint:
            cumulative['branches_total'] = first_checkpoint['branches_total']
            cumulative['branches_coverage_pct'] = (
                100.0 * cumulative['branches_taken'] / cumulative['branches_total']
                if cumulative['branches_total'] > 0 else 0.0
            )

        # Mark final checkpoints
        has_final = any(c.get('is_final', False) for c in bucket_checkpoints)
        if has_final:
            cumulative['is_final'] = True
            cumulative['time_limit_reached'] = any(
                c.get('time_limit_reached', False) for c in bucket_checkpoints
            )

        cumulative_checkpoints.append(cumulative)

    return cumulative_checkpoints


def main():
    parser = argparse.ArgumentParser(
        description="Merge timeline checkpoints from parallel jobs"
    )
    parser.add_argument(
        "timeline_files",
        nargs="+",
        help="Timeline JSONL files to merge (one per job)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output file for merged cumulative timeline (JSON)"
    )
    parser.add_argument(
        "--checkpoint-interval",
        type=int,
        default=60,
        help="Checkpoint interval in seconds (default: 60)"
    )

    args = parser.parse_args()

    print(f"Loading checkpoints from {len(args.timeline_files)} timeline files...")
    checkpoints = load_timeline_checkpoints(args.timeline_files)
    print(f"Loaded {len(checkpoints)} checkpoints total")

    if not checkpoints:
        print("ERROR: No checkpoints loaded", file=sys.stderr)
        sys.exit(1)

    print(f"Merging checkpoints with {args.checkpoint_interval}s interval...")
    cumulative_timeline = merge_checkpoints_by_time(
        checkpoints,
        args.checkpoint_interval
    )
    print(f"Created {len(cumulative_timeline)} cumulative checkpoints")

    # Create output structure
    output = {
        "checkpoint_interval_seconds": args.checkpoint_interval,
        "num_timeline_files": len(args.timeline_files),
        "total_checkpoints_merged": len(checkpoints),
        "cumulative_checkpoints": cumulative_timeline
    }

    # Save merged timeline
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"✅ Saved cumulative timeline to: {args.output}")

    # Print summary
    if cumulative_timeline:
        final = cumulative_timeline[-1]
        print("")
        print("FINAL CUMULATIVE COVERAGE:")
        print(f"  Time: {final.get('time_seconds', 0):.0f}s")
        print(f"  Recipes processed: {final.get('recipes_processed', 0):,}")
        if 'lines_coverage_pct' in final:
            print(f"  Lines: {final.get('lines_hit', 0):,}/{final.get('lines_total', 0):,} "
                  f"({final.get('lines_coverage_pct', 0):.2f}%)")
        if 'branches_coverage_pct' in final:
            print(f"  Branches: {final.get('branches_taken', 0):,}/{final.get('branches_total', 0):,} "
                  f"({final.get('branches_coverage_pct', 0):.2f}%)")


if __name__ == "__main__":
    main()
