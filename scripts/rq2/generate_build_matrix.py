#!/usr/bin/env python3
"""Generate build matrix from selected commits in S3

This script reads selected commits from S3 and generates a GitHub Actions matrix.
"""

import os
import sys
import json
import boto3
from botocore.exceptions import ClientError

def main():
    solver = sys.argv[1]
    bucket = os.getenv('AWS_S3_BUCKET')
    if not bucket:
        raise RuntimeError("AWS_S3_BUCKET environment variable not set")
    
    s3_client = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'eu-north-1'))
    s3_key = f"evaluation/rq2/{solver}/selected-commits.json"
    
    try:
        response = s3_client.get_object(Bucket=bucket, Key=s3_key)
        selected_commits = json.loads(response['Body'].read().decode('utf-8'))
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            raise RuntimeError(f"Selected commits not found at {s3_key}. Run commit selection first.")
        raise
    
    if not selected_commits:
        raise RuntimeError("No commits selected")
    
    # Generate matrix with commit hashes
    matrix = {
        'include': [{'commit': commit} for commit in selected_commits]
    }
    
    # Output compact JSON for GitHub Actions
    print(json.dumps(matrix, separators=(',', ':')))
    print(f"Generated matrix with {len(selected_commits)} commits", file=sys.stderr)

if __name__ == '__main__':
    main()

