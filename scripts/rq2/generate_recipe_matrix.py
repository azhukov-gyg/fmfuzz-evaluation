#!/usr/bin/env python3
"""
Generate commit matrix from S3 recipes for measurement workflows.

Usage:
    python generate_recipe_matrix.py <variant> [--debug-commit <commit>]
    
    variant: baseline, variant1, or variant2
    --debug-commit: Optional specific commit to use (for testing)

Output: JSON matrix for GitHub Actions
"""

import argparse
import json
import os
import sys

import boto3


def list_commits_with_recipes(bucket: str, variant: str) -> list:
    """List all commits that have recipes for the given variant."""
    s3 = boto3.client('s3')
    prefix = f"evaluation/rq2/cvc5/fuzzing-recipes/{variant}/"
    
    commits = set()
    paginator = s3.get_paginator('list_objects_v2')
    
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get('Contents', []):
            key = obj['Key']
            # Extract commit hash from recipes-{commit}.jsonl.gz
            if 'recipes-' in key and key.endswith('.jsonl.gz'):
                filename = key.split('/')[-1]
                commit = filename.replace('recipes-', '').replace('.jsonl.gz', '')
                commits.add(commit)
    
    return sorted(commits)


def generate_matrix(commits: list) -> dict:
    """Generate GitHub Actions matrix from commit list."""
    return {
        "include": [{"commit": commit} for commit in commits]
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate commit matrix from S3 recipes"
    )
    parser.add_argument(
        "variant",
        choices=["baseline", "variant1", "variant2"],
        help="Fuzzing variant (baseline, variant1, variant2)"
    )
    parser.add_argument(
        "--debug-commit",
        help="Specific commit hash for debugging"
    )
    parser.add_argument(
        "--output",
        help="Output file (default: stdout)"
    )
    
    args = parser.parse_args()
    
    bucket = os.environ.get('AWS_S3_BUCKET')
    if not bucket:
        print("Error: AWS_S3_BUCKET environment variable not set", file=sys.stderr)
        sys.exit(1)
    
    if args.debug_commit:
        commits = [args.debug_commit]
        print(f"Debug mode: using commit {args.debug_commit}", file=sys.stderr)
    else:
        commits = list_commits_with_recipes(bucket, args.variant)
        print(f"Found {len(commits)} commits with {args.variant} recipes", file=sys.stderr)
    
    matrix = generate_matrix(commits)
    
    result = {
        "matrix": matrix,
        "total_commits": len(commits)
    }
    
    output = json.dumps(result, separators=(',', ':'))
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
