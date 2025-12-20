#!/usr/bin/env python3
"""Compare baseline vs variant fuzzing statistics

This script downloads both baseline and variant statistics for each commit
and compares them to determine which approach is better.

Supports comparing baseline with:
- variant1 (simple commit fuzzing)
- coverage-guided (coverage-guided fuzzing)
"""

import os
import sys
import json
import boto3
import gzip
import argparse
from botocore.exceptions import ClientError
from typing import Dict, List, Optional

def download_statistics(s3_client, bucket: str, solver: str, commit_hash: str, variant: str) -> Optional[Dict]:
    """Download statistics from S3"""
    s3_key = f"evaluation/rq2/{solver}/fuzzing-statistics/{variant}/fuzzing_statistics-{commit_hash}.json.gz"
    
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json.gz') as tmp_file:
            tmp_path = tmp_file.name
        
        s3_client.download_file(bucket, s3_key, tmp_path)
        
        with gzip.open(tmp_path, 'rt') as f:
            stats = json.load(f)
        
        os.unlink(tmp_path)
        return stats
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            return None
        raise

def compare_statistics(baseline: Dict, variant: Dict, variant_name: str = "variant") -> Dict:
    """Compare two statistics files and return comparison results"""
    baseline_funcs = {f['function_id']: f for f in baseline.get('functions', [])}
    variant_funcs = {f['function_id']: f for f in variant.get('functions', [])}
    
    all_function_ids = set(baseline_funcs.keys()) | set(variant_funcs.keys())
    
    comparison = {
        'total_functions': len(all_function_ids),
        'variant_name': variant_name,
        'functions': [],
        'summary': {
            'total_functions': len(all_function_ids),
            'baseline_triggered': 0,
            'variant_triggered': 0,
            'both_triggered': 0,
            'neither_triggered': 0,
            'baseline_better': 0,  # Baseline triggered but variant didn't
            'variant_better': 0,  # Variant triggered but baseline didn't
            'baseline_more_executions': 0,  # Both triggered, baseline has more
            'variant_more_executions': 0,  # Both triggered, variant has more
            'total_baseline_executions': 0,
            'total_variant_executions': 0
        }
    }
    
    for func_id in sorted(all_function_ids):
        baseline_func = baseline_funcs.get(func_id, {'triggered': False, 'total_executions': 0})
        variant_func = variant_funcs.get(func_id, {'triggered': False, 'total_executions': 0})
        
        baseline_triggered = baseline_func.get('triggered', False)
        variant_triggered = variant_func.get('triggered', False)
        baseline_exec = baseline_func.get('total_executions', 0)
        variant_exec = variant_func.get('total_executions', 0)
        
        comparison['summary']['total_baseline_executions'] += baseline_exec
        comparison['summary']['total_variant_executions'] += variant_exec
        
        if baseline_triggered:
            comparison['summary']['baseline_triggered'] += 1
        if variant_triggered:
            comparison['summary']['variant_triggered'] += 1
        if baseline_triggered and variant_triggered:
            comparison['summary']['both_triggered'] += 1
            if baseline_exec > variant_exec:
                comparison['summary']['baseline_more_executions'] += 1
            elif variant_exec > baseline_exec:
                comparison['summary']['variant_more_executions'] += 1
        elif baseline_triggered and not variant_triggered:
            comparison['summary']['baseline_better'] += 1
        elif variant_triggered and not baseline_triggered:
            comparison['summary']['variant_better'] += 1
        else:
            comparison['summary']['neither_triggered'] += 1
        
        comparison['functions'].append({
            'function_id': func_id,
            'baseline': {
                'triggered': baseline_triggered,
                'total_executions': baseline_exec
            },
            'variant': {
                'triggered': variant_triggered,
                'total_executions': variant_exec
            },
            'better': 'baseline' if (baseline_triggered and not variant_triggered) or (baseline_triggered and variant_triggered and baseline_exec > variant_exec) else ('variant' if (variant_triggered and not baseline_triggered) or (baseline_triggered and variant_triggered and variant_exec > baseline_exec) else 'neither')
        })
    
    return comparison

def main():
    parser = argparse.ArgumentParser(description='Compare baseline vs variant fuzzing statistics')
    parser.add_argument('--solver', required=True, choices=['cvc5', 'z3'], help='Solver name (cvc5 or z3)')
    parser.add_argument('--commit', required=True, help='Commit hash to compare')
    parser.add_argument('--output', required=True, help='Output JSON file')
    parser.add_argument('--variant', default='variant1', help='Variant to compare against baseline (default: variant1)')
    parser.add_argument('--max-commits', type=int, help='Maximum number of commits to process (for testing)')
    
    args = parser.parse_args()
    variant_name = args.variant
    
    bucket = os.getenv('AWS_S3_BUCKET')
    if not bucket:
        raise RuntimeError("AWS_S3_BUCKET environment variable not set")
    
    s3_client = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'eu-north-1'))
    
    # If commit is provided, compare single commit
    if args.commit:
        print(f"🔍 Comparing baseline vs {variant_name} for commit: {args.commit}", file=sys.stderr)
        
        baseline = download_statistics(s3_client, bucket, args.solver, args.commit, 'baseline')
        variant = download_statistics(s3_client, bucket, args.solver, args.commit, variant_name)
        
        if not baseline:
            print(f"❌ Baseline statistics not found for commit {args.commit}", file=sys.stderr)
            sys.exit(1)
        if not variant:
            print(f"❌ {variant_name} statistics not found for commit {args.commit}", file=sys.stderr)
            sys.exit(1)
        
        comparison = compare_statistics(baseline, variant, variant_name)
        comparison['commit_hash'] = args.commit
        
        with open(args.output, 'w') as f:
            json.dump(comparison, f, indent=2)
        
        print(f"✅ Comparison written to {args.output}", file=sys.stderr)
        print(f"📊 Summary:", file=sys.stderr)
        print(f"   Total functions: {comparison['summary']['total_functions']}", file=sys.stderr)
        print(f"   Baseline triggered: {comparison['summary']['baseline_triggered']}", file=sys.stderr)
        print(f"   {variant_name} triggered: {comparison['summary']['variant_triggered']}", file=sys.stderr)
        print(f"   Both triggered: {comparison['summary']['both_triggered']}", file=sys.stderr)
        print(f"   Neither triggered: {comparison['summary']['neither_triggered']}", file=sys.stderr)
        print(f"   Baseline better: {comparison['summary']['baseline_better']}", file=sys.stderr)
        print(f"   {variant_name} better: {comparison['summary']['variant_better']}", file=sys.stderr)
        print(f"   Total baseline executions: {comparison['summary']['total_baseline_executions']:,}", file=sys.stderr)
        print(f"   Total {variant_name} executions: {comparison['summary']['total_variant_executions']:,}", file=sys.stderr)
        print(f"   Baseline more executions (when both triggered): {comparison['summary']['baseline_more_executions']}", file=sys.stderr)
        print(f"   {variant_name} more executions (when both triggered): {comparison['summary']['variant_more_executions']}", file=sys.stderr)
    else:
        # Compare all commits
        print(f"🔍 Comparing all commits (baseline vs {variant_name})...", file=sys.stderr)
        
        # List all commits with variant statistics
        prefix = f"evaluation/rq2/{args.solver}/fuzzing-statistics/{variant_name}/"
        commits = []
        
        try:
            paginator = s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=bucket, Prefix=prefix)
            
            for page in pages:
                if 'Contents' not in page:
                    continue
                for obj in page['Contents']:
                    key = obj['Key']
                    if 'fuzzing_statistics-' in key and key.endswith('.json.gz'):
                        commit = key.split('fuzzing_statistics-')[1].replace('.json.gz', '')
                        commits.append(commit)
        except Exception as e:
            print(f"❌ Error listing commits: {e}", file=sys.stderr)
            sys.exit(1)
        
        commits = sorted(set(commits))
        
        if args.max_commits:
            commits = commits[:args.max_commits]
        
        print(f"✅ Found {len(commits)} commits to compare", file=sys.stderr)
        
        all_comparisons = []
        for commit in commits:
            baseline = download_statistics(s3_client, bucket, args.solver, commit, 'baseline')
            variant = download_statistics(s3_client, bucket, args.solver, commit, variant_name)
            
            if not baseline or not variant:
                print(f"⚠️ Skipping commit {commit} (missing statistics)", file=sys.stderr)
                continue
            
            comparison = compare_statistics(baseline, variant, variant_name)
            comparison['commit_hash'] = commit
            all_comparisons.append(comparison)
        
        output = {
            'variant_name': variant_name,
            'commits': all_comparisons,
            'total_commits': len(all_comparisons)
        }
        
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ Comparison written to {args.output}", file=sys.stderr)

if __name__ == '__main__':
    main()

