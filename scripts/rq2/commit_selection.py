#!/usr/bin/env python3
"""RQ2 Commit Selection: Discover commits, analyze changed functions, select commits

Changes from fmfuzz-dev version:
- Updated thresholds: small (<10), medium (10-50), large (50+)
- Default to small counts for testing (1-2 commits)
- Option to read commits from S3 bugs folder (commits that were fuzzed)
  - Always uses S3, no local folder option
"""

import os
import sys
import json
import argparse
import subprocess
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Set
from pathlib import Path

# Add fmfuzz-dev scripts to path
fmfuzz_dev_scripts = Path(__file__).parent.parent.parent / "fmfuzz-dev" / "scripts"
sys.path.insert(0, str(fmfuzz_dev_scripts))

try:
    import requests
    import boto3
    from botocore.exceptions import ClientError
    import git
    from tree_sitter import Parser
except ImportError as e:
    print(f"Error: Missing dependency: {e}", file=sys.stderr)
    sys.exit(1)

from scheduling.detect_cpp_changes import detect_cpp_changes


class EvaluationS3Manager:
    def __init__(self, bucket: str, solver: str, region: Optional[str] = None):
        self.bucket = bucket
        self.base_path = f"evaluation/rq2/{solver}"
        self.s3_client = boto3.client('s3', region_name=region or os.getenv('AWS_REGION', 'eu-north-1'))
    
    def write_json(self, filename: str, data: any) -> None:
        s3_key = f"{self.base_path}/{filename}"
        self.s3_client.put_object(
            Bucket=self.bucket,
            Key=s3_key,
            Body=json.dumps(data, indent=2).encode('utf-8'),
            ContentType='application/json'
        )
        print(f"✅ Wrote {filename} to S3")
    
    def read_json(self, filename: str, default: Optional[any] = None) -> any:
        try:
            response = self.s3_client.get_object(Bucket=self.bucket, Key=f"{self.base_path}/{filename}")
            return json.loads(response['Body'].read().decode('utf-8'))
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'NoSuchKey':
                return default
            raise


def get_commits_from_s3_bugs(bucket: str, solver: str, region: Optional[str] = None) -> List[Dict]:
    """Extract commit hashes from bug file names in S3.
    
    Bug files are stored at: solvers/{solver}/bugs/bugs-{commit}-{timestamp}.tar.gz
    Pattern: bugs-{7-40-char-commit}-{timestamp}.tar.gz
    
    Returns list of commit dicts with hash. Handles deduplication:
    - If both short and full hash exist for same commit, prefer full hash
    - Deduplicates by checking if short hash matches prefix of full hash
    """
    s3_client = boto3.client('s3', region_name=region or os.getenv('AWS_REGION', 'eu-north-1'))
    bugs_prefix = f"solvers/{solver}/bugs/"
    
    commits_dict = {}  # Map short_hash -> full_hash (or short_hash if no full hash found)
    commit_pattern = re.compile(r'bugs-([0-9a-f]{7,40})-', re.IGNORECASE)
    
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket, Prefix=bugs_prefix)
        
        for page in pages:
            if 'Contents' not in page:
                continue
            
            for obj in page['Contents']:
                key = obj['Key']
                filename = key.split('/')[-1]
                
                # Extract commit hash from filename pattern: bugs-{commit}-{timestamp}.tar.gz
                match = commit_pattern.match(filename)
                if match:
                    commit_hash = match.group(1)
                    short_hash = commit_hash[:7] if len(commit_hash) >= 7 else commit_hash
                    
                    # If we have a full hash (40 chars), prefer it
                    # If we have a short hash, keep it unless we later find a full hash
                    if len(commit_hash) == 40:
                        # Full hash - always use it
                        commits_dict[short_hash] = commit_hash
                    elif short_hash not in commits_dict:
                        # Short hash - only add if we don't have it yet
                        commits_dict[short_hash] = commit_hash
                    elif len(commits_dict[short_hash]) < 40 and len(commit_hash) > len(commits_dict[short_hash]):
                        # We have a short hash, but this one is longer (but not full), prefer longer
                        commits_dict[short_hash] = commit_hash
        
        # Convert to list of dicts
        commits = [{'hash': h} for h in commits_dict.values()]
        print(f"📋 Found {len(commits)} unique commits in S3 bugs folder: {bugs_prefix}")
        return commits
        
    except ClientError as e:
        print(f"⚠️  Error listing S3 bugs: {e}", file=sys.stderr)
        return []


def get_commits_from_last_n_years(repo_url: str, years: int = 2, token: Optional[str] = None) -> List[Dict]:
    repo_path = repo_url.replace('https://github.com/', '').replace('.git', '')
    api_url = f"https://api.github.com/repos/{repo_path}/commits"
    headers = {'Authorization': f'token {token}'} if token else {}
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=years * 365)
    
    commits = []
    page = 1
    params = {'per_page': 100, 'since': cutoff_date.isoformat(), 'page': page}
    
    while True:
        response = requests.get(api_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        if not data:
            break
        
        for commit in data:
            commit_date = datetime.fromisoformat(commit['commit']['author']['date'].replace('Z', '+00:00'))
            if commit_date < cutoff_date and page > 1:
                return commits
            commits.append({
                'hash': commit['sha'],
                'date': commit_date.isoformat(),
                'message': commit['commit']['message'].split('\n')[0]
            })
        
        if len(data) < 100:
            break
        page += 1
        params['page'] = page
    
    return commits


def filter_cpp_commits(commits: List[Dict], repo_url: str, token: Optional[str] = None) -> List[Dict]:
    cpp_commits = []
    for commit in commits:
        try:
            has_cpp, changed_files = detect_cpp_changes(repo_url, commit['hash'], token)
            if has_cpp:
                commit['changed_files'] = changed_files
                cpp_commits.append(commit)
                print(f"✅ {commit['hash'][:8]} has C++ changes")
        except Exception as e:
            print(f"⚠️  {commit['hash'][:8]}: {e}")
    return cpp_commits


def init_tree_sitter():
    """Initialize tree-sitter parser for C++.
    
    Tries multiple approaches:
    1. tree-sitter-cpp directly (most reliable)
    2. tree-sitter-languages (if available)
    """
    try:
        # Approach 1: Use tree-sitter-cpp directly
        from tree_sitter import Language, Parser
        import tree_sitter_cpp as cpp
        
        # Create Language object from the language definition
        language = Language(cpp.language())
        # Create Parser with the language
        parser = Parser(language)
        return language, parser
    except (ImportError, AttributeError, TypeError) as e:
        try:
            # Approach 2: Try tree-sitter-languages (may have API issues)
            from tree_sitter_languages import get_language, get_parser
            language = get_language('cpp')
            parser = get_parser('cpp')
            return language, parser
        except (ImportError, TypeError, AttributeError):
            raise RuntimeError(f"Failed to initialize tree-sitter. Install: pip install tree-sitter tree-sitter-cpp. Error: {e}")


def parse_diff(diff_text: str) -> Dict[str, set]:
    changed_files_lines = {}
    current_file = None
    new_line = None
    
    for line in diff_text.split('\n'):
        if line.startswith('+++ b/'):
            current_file = line[6:].strip()
            changed_files_lines.setdefault(current_file, set())
            new_line = None
        elif line.startswith('@@ '):
            match = re.search(r'@@ -\d+(?:,\d+)? \+(\d+)', line)
            if match and current_file:
                new_line = int(match.group(1))
        elif line.startswith('+') and not line.startswith('+++') and current_file and new_line:
            changed_files_lines[current_file].add(new_line)
            new_line += 1
        elif line.startswith(' ') and new_line is not None:
            new_line += 1
    
    return changed_files_lines


FUNCTION_QUERY = """
(
  [
    (function_definition)
    (declaration)
    (field_declaration)
  ] @func.node
  .
  (function_declarator
    declarator: [
      (identifier)
      (field_identifier)
      (qualified_identifier)
      (operator_name)
      (destructor_name)
    ] @func.name)
)
"""


def analyze_commit_functions(commit_hash: str, repo_path: str, solver: str) -> Dict:
    repo = git.Repo(repo_path)
    
    diff_result = subprocess.run(['git', 'show', '-U0', '--no-color', commit_hash],
                                 capture_output=True, text=True, cwd=repo_path)
    if diff_result.returncode != 0:
        raise RuntimeError(f"Failed to get diff for {commit_hash}")
    
    changed_files_lines = parse_diff(diff_result.stdout)
    cpp_language, parser = init_tree_sitter()
    
    # Create Query - try Query constructor first, fallback to language.query()
    try:
        from tree_sitter import Query
        query = Query(cpp_language, FUNCTION_QUERY)
    except (ImportError, TypeError, AttributeError):
        # Fallback to deprecated API
        query = cpp_language.query(FUNCTION_QUERY)
    
    function_details = []
    files_with_no_functions = []
    cpp_exts = {'.cpp', '.cc', '.cxx', '.c', '.h', '.hpp', '.hxx', '.hh'}
    
    for file_path, changed_lines in changed_files_lines.items():
        if not any(file_path.endswith(ext) for ext in cpp_exts):
            continue
        
        file_result = subprocess.run(['git', 'show', f'{commit_hash}:{file_path}'],
                                     capture_output=True, text=True, cwd=repo_path)
        if file_result.returncode != 0:
            files_with_no_functions.append(file_path)
            continue
        
        file_bytes = bytes(file_result.stdout, 'utf8')
        try:
            tree = parser.parse(file_bytes)
        except Exception:
            files_with_no_functions.append(file_path)
            continue
        
        # Use QueryCursor to execute the query
        from tree_sitter import QueryCursor
        cursor = QueryCursor(query)
        # captures() returns dict {capture_name: [nodes]} - convert to list of (node, capture_name) tuples
        captures_dict = cursor.captures(tree.root_node)
        captures = []
        for capture_name, nodes in captures_dict.items():
            for node in nodes:
                captures.append((node, capture_name))
        func_map = {}
        
        for node, tag in captures:
            if tag == "func.name":
                func_node = node.parent
                while func_node and func_node.type not in ("function_definition", "declaration", "field_declaration"):
                    func_node = func_node.parent
                if func_node:
                    func_map[func_node] = file_bytes[node.start_byte:node.end_byte].decode('utf8', errors='ignore')
        
        found_functions = set()
        for func_node, func_name in func_map.items():
            start_line = func_node.start_point[0] + 1
            end_line = func_node.end_point[0] + 1
            if changed_lines & set(range(start_line, end_line + 1)):
                func_key = (file_path, func_name, start_line)
                if func_key not in found_functions:
                    found_functions.add(func_key)
                    function_details.append({'file': file_path, 'function': func_name, 'line': start_line})
        
        if not found_functions:
            files_with_no_functions.append(file_path)
    
    return {
        'changed_functions_count': len(function_details),
        'changed_functions': function_details,
        'files_with_no_functions': files_with_no_functions
    }


def categorize_commits(commits: List[Dict], small_threshold: int = 10, medium_threshold: int = 50) -> Dict:
    """Categorize commits by changed function count.
    
    Updated thresholds from Slack discussion:
    - Small: < 10 functions
    - Medium: 10-50 functions  
    - Large: > 50 functions
    """
    small, medium, large = [], [], []
    for commit in commits:
        count = commit.get('changed_functions_count', 0)
        if count < small_threshold:
            small.append(commit)
        elif count < medium_threshold:
            medium.append(commit)
        else:
            large.append(commit)
    
    return {
        'small': small, 'medium': medium, 'large': large,
        'statistics': {'total': len(commits), 'small': len(small), 'medium': len(medium), 'large': len(large)}
    }


def select_commits(categorized: Dict, small_count: int, medium_count: int, large_count: int) -> List[str]:
    return ([c['hash'] for c in categorized['small'][:small_count]] +
            [c['hash'] for c in categorized['medium'][:medium_count]] +
            [c['hash'] for c in categorized['large'][:large_count]])


def main():
    parser = argparse.ArgumentParser(description='RQ2 Commit Selection')
    parser.add_argument('solver', choices=['z3', 'cvc5'])
    parser.add_argument('repo_url')
    parser.add_argument('--years', type=int, default=2)
    parser.add_argument('--token', default=os.getenv('GITHUB_TOKEN'))
    parser.add_argument('--repo-path', default='.')
    parser.add_argument('--small-count', type=int, default=1, help='Number of small commits (default: 1 for testing)')
    parser.add_argument('--medium-count', type=int, default=1, help='Number of medium commits (default: 1 for testing)')
    parser.add_argument('--large-count', type=int, default=0, help='Number of large commits (default: 0 for testing)')
    parser.add_argument('--small-threshold', type=int, default=10, help='Max functions for "small" (default: 10)')
    parser.add_argument('--medium-threshold', type=int, default=50, help='Max functions for "medium" (default: 50)')
    parser.add_argument('--max-commits', type=int, help='Maximum total commits to select (for testing, limits selection)')
    parser.add_argument('--skip-analysis', action='store_true')
    parser.add_argument('--skip-selection', action='store_true')
    args = parser.parse_args()
    
    bucket = os.getenv('AWS_S3_BUCKET')
    if not bucket:
        raise RuntimeError("AWS_S3_BUCKET environment variable not set")
    
    s3 = EvaluationS3Manager(bucket, args.solver)
    
    # Read commits from S3 bugs folder (default)
    print(f"🔍 Reading commits from S3 bugs folder: solvers/{args.solver}/bugs/")
    all_commits = get_commits_from_s3_bugs(bucket, args.solver, os.getenv('AWS_REGION', 'eu-north-1'))
    
    if all_commits:
        print(f"✅ Found {len(all_commits)} commits from S3 bugs folder")
        # Deduplicate: remove commits where short hash matches prefix of another commit's hash
        seen_short = {}
        deduplicated = []
        for commit in all_commits:
            commit_hash = commit['hash']
            short_hash = commit_hash[:7] if len(commit_hash) >= 7 else commit_hash
            
            if short_hash in seen_short:
                # We've seen this short hash before
                existing = seen_short[short_hash]
                existing_hash = existing['hash']
                
                # Prefer full hash (40 chars) over short hash
                if len(commit_hash) == 40 and len(existing_hash) < 40:
                    # Replace short hash with full hash
                    deduplicated.remove(existing)
                    deduplicated.append(commit)
                    seen_short[short_hash] = commit
                elif len(existing_hash) == 40 and len(commit_hash) < 40:
                    # Existing is full hash, skip this short one
                    continue
                # Both are same length or both short - keep first one
            else:
                deduplicated.append(commit)
                seen_short[short_hash] = commit
        
        all_commits = deduplicated
        print(f"✅ After deduplication: {len(all_commits)} unique commits")
    else:
        # Fallback: Discover commits from GitHub API if no bugs found
        print(f"⚠️  No commits found in S3 bugs folder, falling back to GitHub API...")
        print(f"🔍 Discovering commits from last {args.years} years...")
        all_commits = get_commits_from_last_n_years(args.repo_url, args.years, args.token)
        print(f"✅ Found {len(all_commits)} commits")
    
    print(f"🔍 Filtering commits with C++ changes...")
    cpp_commits = filter_cpp_commits(all_commits, args.repo_url, args.token)
    print(f"✅ Found {len(cpp_commits)} commits with C++ changes")
    s3.write_json('raw-commits.json', cpp_commits)
    
    if not args.skip_analysis:
        print(f"🔍 Analyzing changed functions...")
        existing_stats = s3.read_json('commit-statistics.json')
        analyzed_commits = existing_stats.get('commits', []) if existing_stats else []
        analyzed_hashes = {c['hash'] for c in analyzed_commits}
        
        for commit in cpp_commits:
            if commit['hash'] in analyzed_hashes:
                print(f"⏭️  Skipping {commit['hash'][:8]} (already analyzed)")
                continue
            
            print(f"🔍 Analyzing {commit['hash'][:8]}...")
            commit.update(analyze_commit_functions(commit['hash'], args.repo_path, args.solver))
            analyzed_commits.append(commit)
            analyzed_hashes.add(commit['hash'])
        
        categorized = categorize_commits(analyzed_commits, args.small_threshold, args.medium_threshold)
        s3.write_json('commit-statistics.json', {
            'commits': analyzed_commits,
            'statistics': categorized['statistics']
        })
        print(f"✅ Statistics: {categorized['statistics']}")
    else:
        stats = s3.read_json('commit-statistics.json')
        if not stats:
            raise RuntimeError("No existing statistics found")
        analyzed_commits = stats['commits']
        categorized = categorize_commits(analyzed_commits, args.small_threshold, args.medium_threshold)
    
    if not args.skip_selection:
        selected = select_commits(categorized, args.small_count, args.medium_count, args.large_count)
        
        # Limit total commits if specified
        if args.max_commits and args.max_commits > 0:
            original_count = len(selected)
            selected = selected[:args.max_commits]
            print(f"📝 Limited selection from {original_count} to {len(selected)} commits (max_commits={args.max_commits})")
        
        print(f"✅ Selected {len(selected)} commits")
        s3.write_json('selected-commits.json', selected)
    
    print("✅ Commit selection complete!")


if __name__ == '__main__':
    main()

