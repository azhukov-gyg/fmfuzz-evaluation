#!/usr/bin/env python3
"""
Generate allowlist for sancov instrumentation from changed functions.

This script reads changed functions from a JSON file (produced by prepare_commit_fuzzer.py)
and generates a sancov allowlist file.

The allowlist uses the format expected by LLVM:
  fun:function_name
  src:source_file.cpp
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Set


def load_changed_functions(json_path: Path) -> Dict:
    """Load changed functions from JSON file."""
    with open(json_path, 'r') as f:
        data = json.load(f)
    return data


def extract_function_names(changed_functions: Dict) -> Set[str]:
    """Extract all function names (signatures) from changed functions.
    
    Z3's prepare_commit_fuzzer.py outputs changed_functions as a list of strings
    in the format: "file:signature:line" (e.g., "src/nlsat/nlsat_explain.cpp:nlsat::explain::imp::cell_root_info::reset():296")
    """
    function_names = set()
    
    if 'changed_functions' in changed_functions:
        for func in changed_functions['changed_functions']:
            # In Z3, changed_functions is a list of strings (not dicts)
            if isinstance(func, str):
                # Function signature is already the full identifier
                # Format: "file:signature:line"
                function_names.add(func)
            elif isinstance(func, dict):
                # Fallback: if it's a dict, extract signature
                signature = func.get('signature', '')
                if signature:
                    function_names.add(signature)
    
    return function_names


def generate_sancov_allowlist(function_names: Set[str], source_files: Set[str] = None) -> str:
    """
    Generate sancov allowlist content.
    
    Format:
      fun:function_name
      src:source_file.cpp
    """
    lines = []
    
    # Add function entries
    for func_name in sorted(function_names):
        lines.append(f"fun:{func_name}")
    
    # Add source file entries if provided
    if source_files:
        for src_file in sorted(source_files):
            lines.append(f"src:{src_file}")
    
    return '\n'.join(lines) + '\n'


def extract_source_files(changed_functions: Dict) -> Set[str]:
    """Extract source file paths from changed functions.
    
    For Z3, changed_functions are strings in format "file:signature:line",
    so we extract the file part before the first colon.
    """
    source_files = set()
    
    if 'changed_functions' in changed_functions:
        for func in changed_functions['changed_functions']:
            if isinstance(func, str):
                # Format: "file:signature:line" - extract file part
                if ':' in func:
                    file_path = func.split(':', 1)[0]
                    if file_path:
                        source_files.add(file_path)
            elif isinstance(func, dict):
                # Fallback: if it's a dict, extract file
                file_path = func.get('file', '')
                if file_path:
                    source_files.add(file_path)
    
    return source_files


def main():
    parser = argparse.ArgumentParser(
        description="Generate sancov allowlist from changed functions"
    )
    parser.add_argument(
        '--input',
        type=Path,
        required=True,
        help='Input JSON file with changed functions'
    )
    parser.add_argument(
        '--output-sancov',
        type=Path,
        required=True,
        help='Output path for sancov allowlist'
    )
    parser.add_argument(
        '--include-sources',
        action='store_true',
        help='Include source file entries in allowlist'
    )
    
    args = parser.parse_args()
    
    # Load changed functions
    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    changed_functions = load_changed_functions(args.input)
    
    # Extract function names
    function_names = extract_function_names(changed_functions)
    
    if not function_names:
        print("Warning: No function names found in input file", file=sys.stderr)
        # Create empty allowlist
        args.output_sancov.write_text("")
        sys.exit(0)
    
    print(f"Found {len(function_names)} changed functions")
    
    # Extract source files if requested
    source_files = None
    if args.include_sources:
        source_files = extract_source_files(changed_functions)
        if source_files:
            print(f"Found {len(source_files)} source files")
    
    # Generate allowlist
    sancov_content = generate_sancov_allowlist(function_names, source_files)
    
    # Write allowlist
    args.output_sancov.write_text(sancov_content)
    
    entry_count = len(function_names) + (len(source_files) if source_files else 0)
    
    print(f"Generated sancov allowlist: {args.output_sancov} ({entry_count} entries)")


if __name__ == '__main__':
    main()
