#!/usr/bin/env python3
"""Generate combined matrix of (commit, chunk) for coverage mapping

This script generates a matrix combining commits with test chunks for parallel coverage mapping.
Adapted to work from this repo while referencing fmfuzz-dev scripts.
"""

import os
import sys
import json
import boto3
import argparse
import subprocess
from pathlib import Path
from botocore.exceptions import ClientError

def main():
    parser = argparse.ArgumentParser(description='Generate combined matrix for coverage mapping')
    parser.add_argument('solver', choices=['cvc5', 'z3'], help='Solver name (cvc5 or z3)')
    parser.add_argument('--max-commits', type=int, help='Maximum number of commits to process')
    parser.add_argument('--commit', type=str, help='Specific commit hash to process (filters to only this commit)')

    args = parser.parse_args()
    solver = args.solver
    max_commits = args.max_commits

    # Read specific commit from argument or environment variable
    specific_commit = args.commit or os.getenv('COMMIT_HASH', '').strip()

    # Log what we're processing
    if specific_commit:
        print(f"📌 Running coverage mapping for specific commit: {specific_commit}", file=sys.stderr)
    else:
        print(f"📊 Running coverage mapping for all commits", file=sys.stderr)

    bucket = os.getenv('AWS_S3_BUCKET')
    if not bucket:
        raise RuntimeError("AWS_S3_BUCKET environment variable not set")
    
    s3_client = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'eu-north-1'))
    s3_key = f"evaluation/rq2/{solver}/selected-commits.json"
    
    # Read selected commits
    try:
        response = s3_client.get_object(Bucket=bucket, Key=s3_key)
        selected_commits = json.loads(response['Body'].read().decode('utf-8'))
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            raise RuntimeError(f"Selected commits not found at {s3_key}. Run commit selection first.")
        raise
    
    if not selected_commits:
        raise RuntimeError("No commits selected")

    # Filter to specific commit if provided
    if specific_commit:
        # Check if specific_commit is in the list
        if specific_commit in selected_commits:
            selected_commits = [specific_commit]
            print(f"📌 Filtered to specific commit: {specific_commit}", file=sys.stderr)
        else:
            # Try matching by prefix (short hash)
            matching = [c for c in selected_commits if c.startswith(specific_commit)]
            if matching:
                selected_commits = matching
                print(f"📌 Filtered to {len(matching)} commit(s) matching prefix: {specific_commit}", file=sys.stderr)
                for c in matching:
                    print(f"   - {c}", file=sys.stderr)
            else:
                raise RuntimeError(f"Commit {specific_commit} not found in selected commits")
    # Limit commits if specified
    elif max_commits and max_commits > 0:
        selected_commits = selected_commits[:max_commits]
        print(f"📝 Limited to {len(selected_commits)} commits (max_commits={max_commits})", file=sys.stderr)
    
    # Download coverage binary for first commit to discover tests
    # (We assume all commits have similar test counts)
    first_commit = selected_commits[0]
    coverage_key = f"evaluation/rq2/{solver}/builds/coverage/{first_commit}.tar.gz"
    
    print(f"📥 Downloading coverage binary for test discovery...", file=sys.stderr)
    os.makedirs('artifacts', exist_ok=True)
    s3_client.download_file(bucket, coverage_key, 'artifacts/artifacts.tar.gz')
    
    # Extract binary
    solver_dir = solver
    build_dir = f"{solver_dir}/build"
    os.makedirs(build_dir, exist_ok=True)
    
    # Reference fmfuzz-dev scripts
    repo_root = Path(__file__).parent.parent.parent
    fmfuzz_scripts = repo_root / "fmfuzz-dev" / "scripts"
    extract_script = fmfuzz_scripts / solver / "extract_build_artifacts.sh"
    
    if not extract_script.exists():
        raise RuntimeError(f"Extract script not found: {extract_script}")
    
    result = subprocess.run(
        ['bash', str(extract_script), 'artifacts/artifacts.tar.gz', build_dir, 'true'],
        capture_output=True,
        text=True,
        check=True
    )
    print(result.stdout, file=sys.stderr)
    
    # Discover tests and generate chunks
    if solver == 'z3':
        # Clone z3test if needed
        if not os.path.exists('z3test'):
            subprocess.run(['git', 'clone', 'https://github.com/z3prover/z3test.git', 'z3test'], check=True)
        
        # Generate matrix using fmfuzz-dev script
        generate_matrix_script = fmfuzz_scripts / "z3" / "coverage" / "generate_matrix.py"
        if not generate_matrix_script.exists():
            raise RuntimeError(f"Generate matrix script not found: {generate_matrix_script}")
        
        result = subprocess.run(
            ['python3', str(generate_matrix_script),
             '--z3test-dir', 'z3test',
             '--max-job-time', '300',
             '--buffer', '60',
             '--output', 'matrix.json'],
            capture_output=True,
            text=True,
            check=True
        )
    else:  # cvc5
        generate_matrix_script = fmfuzz_scripts / "cvc5" / "coverage" / "generate_matrix.py"
        if not generate_matrix_script.exists():
            raise RuntimeError(f"Generate matrix script not found: {generate_matrix_script}")
        
        result = subprocess.run(
            ['python3', str(generate_matrix_script),
             '--build-dir', build_dir,
             '--max-job-time', '300',
             '--buffer', '60',
             '--output', 'matrix.json'],
            capture_output=True,
            text=True,
            check=True
        )
    
    with open('matrix.json', 'r') as f:
        chunk_matrix = json.load(f)
    
    chunks = chunk_matrix['matrix']['include']
    print(f"📊 Discovered {chunk_matrix['total_tests']} tests, {len(chunks)} chunks", file=sys.stderr)
    
    # Generate combined matrix: (commit, chunk)
    combined_matrix = []
    for commit in selected_commits:
        for chunk in chunks:
            combined_matrix.append({
                'commit': commit,
                'chunk': chunk
            })
    
    output = {
        'include': combined_matrix,
        'total_commits': len(selected_commits),
        'total_chunks': len(chunks),
        'chunks_per_commit': len(chunks)
    }
    
    print(json.dumps(output, separators=(',', ':')))
    print(f"Generated combined matrix: {len(combined_matrix)} jobs ({len(selected_commits)} commits × {len(chunks)} chunks)", file=sys.stderr)

if __name__ == '__main__':
    main()

