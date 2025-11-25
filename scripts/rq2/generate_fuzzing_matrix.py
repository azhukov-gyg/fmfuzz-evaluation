#!/usr/bin/env python3
"""Generate matrix of commits from S3 coverage mappings for fuzzing

This script reads coverage mappings from S3 and generates a matrix of commits
that have coverage mappings available.
"""

import os
import sys
import json
import boto3
from botocore.exceptions import ClientError

def main():
    solver = sys.argv[1] if len(sys.argv) > 1 else "cvc5"
    max_commits = None
    if len(sys.argv) > 2:
        try:
            max_commits = int(sys.argv[2])
        except ValueError:
            pass
    
    bucket = os.getenv('AWS_S3_BUCKET')
    if not bucket:
        raise RuntimeError("AWS_S3_BUCKET environment variable not set")
    
    s3_client = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'eu-north-1'))
    
    # List coverage mappings from S3
    prefix = f"evaluation/rq2/{solver}/coverage-mappings/variant1/"
    
    print(f"🔍 Listing coverage mappings from s3://{bucket}/{prefix}", file=sys.stderr)
    
    commits = []
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket, Prefix=prefix)
        
        for page in pages:
            if 'Contents' not in page:
                continue
            
            for obj in page['Contents']:
                key = obj['Key']
                # Extract commit hash from filename: coverage_mapping-{commit}.json.gz
                if 'coverage_mapping-' in key and key.endswith('.json.gz'):
                    commit = key.split('coverage_mapping-')[1].replace('.json.gz', '')
                    commits.append(commit)
        
        # Sort commits (newest first by default, or we could sort by date)
        commits = sorted(set(commits), reverse=True)
        
        if max_commits and max_commits > 0:
            commits = commits[:max_commits]
            print(f"📝 Limited to {len(commits)} commits (max_commits={max_commits})", file=sys.stderr)
        
        print(f"✅ Found {len(commits)} coverage mappings", file=sys.stderr)
        
    except ClientError as e:
        print(f"❌ Error listing S3 objects: {e}", file=sys.stderr)
        sys.exit(1)
    
    if not commits:
        print("⚠️ No coverage mappings found", file=sys.stderr)
        output = {
            'include': [],
            'total_commits': 0
        }
        print(json.dumps(output, separators=(',', ':')))
        return
    
    # Generate matrix: one entry per commit
    matrix = [{'commit': commit} for commit in commits]
    
    output = {
        'include': matrix,
        'total_commits': len(commits)
    }
    
    print(json.dumps(output, separators=(',', ':')))
    print(f"Generated matrix: {len(matrix)} commits", file=sys.stderr)

if __name__ == '__main__':
    main()

