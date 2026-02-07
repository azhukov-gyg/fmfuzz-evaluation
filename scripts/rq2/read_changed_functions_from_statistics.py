#!/usr/bin/env python3
"""Read changed functions from commit statistics

This script reads changed functions for a given commit from the
commit-statistics.json file in S3.
"""

import os
import sys
import json
import boto3
from botocore.exceptions import ClientError

def main():
    if len(sys.argv) < 3:
        print("Usage: read_changed_functions_from_statistics.py <solver> <commit_hash>", file=sys.stderr)
        sys.exit(1)

    solver = sys.argv[1]
    commit_hash = sys.argv[2]

    bucket = os.getenv('AWS_S3_BUCKET')
    if not bucket:
        raise RuntimeError("AWS_S3_BUCKET environment variable not set")

    s3_client = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'eu-north-1'))

    # Download commit-statistics.json
    s3_key = f"evaluation/rq2/{solver}/commit-statistics.json"

    print(f"🔍 Downloading commit statistics from s3://{bucket}/{s3_key}", file=sys.stderr)

    try:
        response = s3_client.get_object(Bucket=bucket, Key=s3_key)
        stats = json.loads(response['Body'].read().decode('utf-8'))
    except ClientError as e:
        print(f"❌ Error downloading commit-statistics.json: {e}", file=sys.stderr)
        sys.exit(1)

    # Find the commit (exact or prefix match)
    commit_data = None
    for entry in stats['commits']:
        h = entry['hash']
        if h == commit_hash or h.startswith(commit_hash) or commit_hash.startswith(h):
            commit_data = entry
            break

    if commit_data is None:
        print(f"❌ Commit {commit_hash} not found in commit-statistics.json", file=sys.stderr)
        sys.exit(1)

    # Build function IDs in the same format as variant1 stats: "file:function:line"
    changed_functions = []
    for func in commit_data.get('changed_functions', []):
        func_id = f"{func['file']}:{func['function']}:{func['line']}"
        changed_functions.append(func_id)

    # Output as JSON
    output = {
        'commit_hash': commit_hash,
        'changed_functions': changed_functions,
        'total_functions': len(changed_functions)
    }

    print(json.dumps(output, indent=2))
    print(f"✅ Extracted {len(changed_functions)} changed functions for {commit_data['hash'][:12]}", file=sys.stderr)

if __name__ == '__main__':
    main()
