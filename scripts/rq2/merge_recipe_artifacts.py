#!/usr/bin/env python3
"""
Merge recipe artifacts from multiple fuzzing jobs.

Usage:
    python merge_recipe_artifacts.py <artifacts_dir> <commit> <output_file>
    
    artifacts_dir: Directory containing recipe artifacts from jobs
    commit: Commit hash to filter recipes
    output_file: Output merged JSONL file

Used by fuzzing workflows to merge recipes from parallel jobs.
"""

import argparse
import json
import os
import sys
from pathlib import Path


def find_recipe_files(artifacts_dir: str, commit: str) -> list:
    """Find all recipe files for a given commit."""
    recipe_files = []
    artifacts_path = Path(artifacts_dir)
    
    # Search for recipe files matching the commit
    for recipe_file in artifacts_path.rglob(f"recipes_{commit}_job_*.jsonl"):
        recipe_files.append(recipe_file)
    
    return sorted(recipe_files)


def merge_recipes(recipe_files: list, output_file: str) -> int:
    """Merge multiple recipe JSONL files into one."""
    total_recipes = 0
    
    with open(output_file, 'w') as out:
        for recipe_file in recipe_files:
            with open(recipe_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        out.write(line + '\n')
                        total_recipes += 1
    
    return total_recipes


def main():
    parser = argparse.ArgumentParser(
        description="Merge recipe artifacts from multiple fuzzing jobs"
    )
    parser.add_argument(
        "artifacts_dir",
        help="Directory containing recipe artifacts"
    )
    parser.add_argument(
        "commit",
        help="Commit hash to filter recipes"
    )
    parser.add_argument(
        "output_file",
        help="Output merged JSONL file"
    )
    
    args = parser.parse_args()
    
    recipe_files = find_recipe_files(args.artifacts_dir, args.commit)
    
    if not recipe_files:
        print(f"⚠️ No recipe files found for commit {args.commit}", file=sys.stderr)
        sys.exit(0)
    
    print(f"Found {len(recipe_files)} recipe files", file=sys.stderr)
    
    total_recipes = merge_recipes(recipe_files, args.output_file)
    
    print(f"✅ Merged {total_recipes} recipes from {len(recipe_files)} job files", file=sys.stderr)
    print(total_recipes)  # Output for shell capture


if __name__ == "__main__":
    main()
