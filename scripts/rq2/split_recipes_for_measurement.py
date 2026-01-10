#!/usr/bin/env python3
"""
Split recipes into multiple jobs for parallel measurement.

This script splits a recipe file into N chunks for parallel measurement.
Each chunk is processed by a separate GitHub Actions job.

Output: JSON with matrix structure for GitHub Actions.
"""

import argparse
import gzip
import json
import sys
from pathlib import Path


def split_recipes(recipe_file: str, num_jobs: int = 4, output_file: str = "measurement_matrix.json"):
    """
    Split recipes into jobs and generate GitHub Actions matrix.
    """
    # Load recipes
    recipes = []
    
    if recipe_file.endswith('.gz'):
        with gzip.open(recipe_file, 'rt') as f:
            for line in f:
                if line.strip():
                    recipes.append(json.loads(line))
    else:
        with open(recipe_file, 'r') as f:
            for line in f:
                if line.strip():
                    recipes.append(json.loads(line))
    
    total_recipes = len(recipes)
    
    if total_recipes == 0:
        print(f"Warning: No recipes found in {recipe_file}", file=sys.stderr)
        # Return empty matrix
        result = {
            "total_recipes": 0,
            "num_jobs": 0,
            "matrix": {"include": []}
        }
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"0")  # Output for shell capture
        return
    
    # Split into chunks
    chunk_size = (total_recipes + num_jobs - 1) // num_jobs  # Ceiling division
    
    matrix_entries = []
    for job_id in range(num_jobs):
        start_idx = job_id * chunk_size
        end_idx = min(start_idx + chunk_size, total_recipes)
        
        if start_idx >= total_recipes:
            break
        
        matrix_entries.append({
            "job_id": job_id,
            "start_idx": start_idx,
            "end_idx": end_idx,
            "recipe_count": end_idx - start_idx
        })
    
    result = {
        "total_recipes": total_recipes,
        "num_jobs": len(matrix_entries),
        "chunk_size": chunk_size,
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
