#!/usr/bin/env python3
"""
Split recipes into multiple jobs for parallel measurement.

This script splits a recipe file into N chunks for parallel measurement.
Each chunk is processed by a separate GitHub Actions job.

IMPORTANT: Splits by SEED BOUNDARIES to ensure all iterations of a seed
stay together. This is critical for efficient replay (avoids regenerating
iterations just to get RNG state).

Output: JSON with matrix structure for GitHub Actions.
"""

import argparse
import gzip
import json
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Tuple


def split_recipes(recipe_file: str, num_jobs: int = 4, output_file: str = "measurement_matrix.json"):
    """
    Split recipes into jobs by SEED BOUNDARIES and generate GitHub Actions matrix.
    
    All recipes for a given seed stay in the same job to avoid inefficient
    replay (regenerating mutations just to advance RNG state).
    """
    # Check if file exists
    recipe_path = Path(recipe_file)
    if not recipe_path.exists():
        print(f"Error: Recipe file not found: {recipe_file}", file=sys.stderr)
        result = {
            "total_recipes": 0,
            "num_jobs": 0,
            "matrix": {"include": []}
        }
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        print("0")
        return
    
    # Check file size
    file_size = recipe_path.stat().st_size
    print(f"Recipe file: {recipe_file} ({file_size} bytes)", file=sys.stderr)
    
    if file_size == 0:
        print(f"Warning: Recipe file is empty: {recipe_file}", file=sys.stderr)
        result = {
            "total_recipes": 0,
            "num_jobs": 0,
            "matrix": {"include": []}
        }
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        print("0")
        return
    
    # Load recipes and group by seed (including chain for deterministic replay)
    recipes: List[dict] = []
    # Group key: (seed_path, rng_seed, chain_tuple)
    # Chain is important: recipes with different chains are different mutation lineages
    seed_groups: Dict[Tuple[str, int, Tuple[int, ...]], List[int]] = OrderedDict()
    parse_errors = 0
    
    def parse_jsonl(f):
        nonlocal parse_errors
        for line_num, line in enumerate(f, 1):
            stripped = line.strip()
            # Skip empty lines and comments
            if not stripped or stripped.startswith('#'):
                continue
            try:
                recipe = json.loads(stripped)

                # Skip metadata markers (seed_start, seed_end) — they are not recipes
                # RecipeReader in replay_recipes.py also filters these out
                if recipe.get('type') in ('seed_start', 'seed_end'):
                    continue

                recipe_idx = len(recipes)
                recipes.append(recipe)

                # Group by (seed_path, rng_seed, chain)
                # NOTE: Default rng_seed must match replay_recipes.py (42)
                # Chain is a list of iterations that led to the parent seed
                seed_path = recipe.get('seed_path', '')
                rng_seed = recipe.get('rng_seed', 42)
                chain = tuple(recipe.get('chain', []))  # Convert to tuple for hashability
                key = (seed_path, rng_seed, chain)
                
                if key not in seed_groups:
                    seed_groups[key] = []
                seed_groups[key].append(recipe_idx)
                
            except json.JSONDecodeError as e:
                parse_errors += 1
                if parse_errors <= 5:
                    print(f"Warning: Failed to parse line {line_num}: {e}", file=sys.stderr)
                    print(f"  Line content (first 100 chars): {repr(stripped[:100])}", file=sys.stderr)
    
    try:
        if recipe_file.endswith('.gz'):
            with gzip.open(recipe_file, 'rt') as f:
                parse_jsonl(f)
        else:
            with open(recipe_file, 'r') as f:
                parse_jsonl(f)
    except Exception as e:
        print(f"Error reading recipe file: {e}", file=sys.stderr)
        result = {
            "total_recipes": 0,
            "num_jobs": 0,
            "matrix": {"include": []}
        }
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        print("0")
        return
    
    if parse_errors > 0:
        print(f"Warning: {parse_errors} lines failed to parse", file=sys.stderr)
    
    total_recipes = len(recipes)
    total_seeds = len(seed_groups)
    
    print(f"Total recipes: {total_recipes}, unique seeds: {total_seeds}", file=sys.stderr)
    
    if total_recipes == 0:
        print(f"Warning: No recipes found in {recipe_file}", file=sys.stderr)
        result = {
            "total_recipes": 0,
            "num_jobs": 0,
            "matrix": {"include": []}
        }
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        print("0")
        return
    
    # Distribute seed groups across jobs (balanced by recipe count)
    # Sort seeds by size (largest first) for better balancing
    sorted_seeds = sorted(seed_groups.items(), key=lambda x: -len(x[1]))
    
    # Greedy bin packing: assign each seed to the job with fewest recipes
    # Key is now (seed_path, rng_seed, chain)
    job_seeds: List[List[Tuple[str, int, Tuple[int, ...]]]] = [[] for _ in range(num_jobs)]
    job_counts: List[int] = [0] * num_jobs
    
    for seed_key, indices in sorted_seeds:
        # Find job with minimum recipes
        min_job = min(range(num_jobs), key=lambda j: job_counts[j])
        job_seeds[min_job].append(seed_key)
        job_counts[min_job] += len(indices)
    
    # Build matrix entries with seed lists and write seeds files
    matrix_entries = []
    output_dir = Path(output_file).parent
    
    for job_id in range(num_jobs):
        if job_counts[job_id] == 0:
            continue
        
        # Collect all recipe indices for this job's seeds
        job_recipe_indices = []
        # Store (seed_path, rng_seed, chain) info for precise filtering
        job_seed_keys = []
        for seed_key in job_seeds[job_id]:
            job_recipe_indices.extend(seed_groups[seed_key])
            # seed_key is (seed_path, rng_seed, chain_tuple)
            job_seed_keys.append({
                "seed_path": seed_key[0],
                "rng_seed": seed_key[1],
                "chain": list(seed_key[2])  # Convert tuple back to list for JSON
            })
        
        # Write seeds file for this job (includes rng_seed and chain for precise filtering)
        seeds_file = output_dir / f"seeds_job_{job_id}.json"
        with open(seeds_file, 'w') as f:
            json.dump({"seed_keys": job_seed_keys, "job_id": job_id}, f, indent=2)
        
        matrix_entries.append({
            "job_id": job_id,
            "recipe_count": len(job_recipe_indices),
            "seed_count": len(job_seed_keys),
            "seeds_file": str(seeds_file.name),  # Just the filename
        })
    
    # Log distribution
    print(f"Split into {len(matrix_entries)} jobs:", file=sys.stderr)
    for entry in matrix_entries:
        print(f"  Job {entry['job_id']}: {entry['recipe_count']} recipes, {entry['seed_count']} seeds", file=sys.stderr)
    
    result = {
        "total_recipes": total_recipes,
        "total_seeds": total_seeds,
        "num_jobs": len(matrix_entries),
        "matrix": {"include": matrix_entries}
    }
    
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    # Output job count for shell capture
    print(f"{len(matrix_entries)}")


def main():
    parser = argparse.ArgumentParser(description="Split recipes for parallel measurement")
    parser.add_argument("recipe_file", help="Recipe JSONL file (can be .gz)")
    parser.add_argument("--num-jobs", type=int, default=4, help="Number of parallel jobs")
    parser.add_argument("--output", default="measurement_matrix.json", help="Output matrix JSON file")
    
    args = parser.parse_args()
    split_recipes(args.recipe_file, args.num_jobs, args.output)


if __name__ == "__main__":
    main()
