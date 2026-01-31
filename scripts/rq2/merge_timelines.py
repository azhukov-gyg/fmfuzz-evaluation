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

    Since jobs run in parallel on different seed groups, we align checkpoints to common
    FUZZING time intervals (e.g., fuzzing t=60s, 120s, 180s) and aggregate metrics.

    Each job processes recipes from its assigned seeds in fuzzing timestamp order.
    All jobs checkpoint when they reach the same fuzzing timestamp (e.g., all jobs
    checkpoint at fuzzing t=60s when they finish processing recipes discovered by t=60s).

    Coverage metrics (lines_hit, branches_taken) are summed across jobs, representing
    the combined coverage from all parallel fuzzing workers' discoveries up to that time.

    Args:
        checkpoints: All checkpoints from all jobs
        checkpoint_interval: Interval in fuzzing-time seconds (e.g., 60)

    Returns:
        List of cumulative checkpoints aligned to fuzzing time intervals
    """
    # Group checkpoints by fuzzing time bucket
    time_buckets = {}

    for checkpoint in checkpoints:
        # Use fuzzing_time_seconds (new) or fall back to wall_time_seconds (old)
        fuzzing_time = checkpoint.get('fuzzing_time_seconds', checkpoint.get('wall_time_seconds', 0))
        # Round to nearest interval (e.g., 62s -> 60s bucket)
        time_bucket = round(fuzzing_time / checkpoint_interval) * checkpoint_interval

        if time_bucket not in time_buckets:
            time_buckets[time_bucket] = []

        time_buckets[time_bucket].append(checkpoint)

    # Create cumulative checkpoints for each time bucket
    cumulative_checkpoints = []

    for time_bucket in sorted(time_buckets.keys()):
        bucket_checkpoints = time_buckets[time_bucket]

        # Merge coverage dictionaries from all jobs (union, not sum)
        merged_line_coverage = {}
        merged_branch_coverage = {}

        for checkpoint in bucket_checkpoints:
            # Merge line coverage (take union - any line hit by any job counts)
            for line_key, hit_count in checkpoint.get('line_coverage', {}).items():
                merged_line_coverage[line_key] = merged_line_coverage.get(line_key, 0) + hit_count

            # Merge branch coverage (take union - any branch taken by any job counts)
            for branch_key, taken_count in checkpoint.get('branch_coverage', {}).items():
                merged_branch_coverage[branch_key] = merged_branch_coverage.get(branch_key, 0) + taken_count

        # Count unique lines/branches with >0 hits (proper union)
        lines_hit = sum(1 for v in merged_line_coverage.values() if v > 0)
        branches_taken = sum(1 for v in merged_branch_coverage.values() if v > 0)

        # Aggregate metrics across jobs
        cumulative = {
            'fuzzing_time_seconds': time_bucket,
            'num_jobs': len(bucket_checkpoints),
            'recipes_processed': sum(c.get('recipes_processed', 0) for c in bucket_checkpoints),
            'lines_hit': lines_hit,
            'branches_taken': branches_taken,
            'function_calls': sum(c.get('function_calls', 0) for c in bucket_checkpoints),
            'avg_wall_time_seconds': sum(c.get('wall_time_seconds', 0) for c in bucket_checkpoints) / len(bucket_checkpoints),
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
        print(f"  Fuzzing time: {final.get('fuzzing_time_seconds', 0):.0f}s")
        print(f"  Avg wall time: {final.get('avg_wall_time_seconds', 0):.0f}s")
        print(f"  Recipes processed: {final.get('recipes_processed', 0):,}")
        if 'lines_coverage_pct' in final:
            print(f"  Lines: {final.get('lines_hit', 0):,}/{final.get('lines_total', 0):,} "
                  f"({final.get('lines_coverage_pct', 0):.2f}%)")
        if 'branches_coverage_pct' in final:
            print(f"  Branches: {final.get('branches_taken', 0):,}/{final.get('branches_total', 0):,} "
                  f"({final.get('branches_coverage_pct', 0):.2f}%)")


if __name__ == "__main__":
    main()
