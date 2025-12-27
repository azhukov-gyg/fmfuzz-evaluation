#!/usr/bin/env python3
"""
Generate Allowlists from Changed Functions
==========================================

Generates sancov and PGO allowlists from the changed_functions.json output
of prepare_commit_fuzzer_sancov.py.

Input format (changed_functions.json):
{
  "commit_hash": "...",
  "changed_functions": ["file:signature", ...],
  "function_info_map": {
    "file:signature": {
      "signature": "...",
      "file": "...",
      "start": 123,
      "end": 456,
      "mangled_name": "_ZN4cvc5..."
    }
  }
}

Output formats:

Sancov Allowlist (-fsanitize-coverage-allowlist):
    src:*
    fun:_ZN4cvc5...
    fun:_ZN4cvc5...

PGO Allowlist (-fprofile-list):
    [clang]
    fun:_ZN4cvc5...
    fun:_ZN4cvc5...

Usage:
    python generate_allowlists.py \\
        --input changed_functions.json \\
        --output-sancov sancov_allowlist.txt \\
        --output-pgo pgo_allowlist.txt
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


def load_changed_functions(input_file: str) -> Tuple[List[str], Dict]:
    """
    Load changed functions from JSON file.
    
    Returns:
        (changed_functions list, function_info_map dict)
    """
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    changed_functions = data.get('changed_functions', [])
    function_info_map = data.get('function_info_map', {})
    
    return changed_functions, function_info_map


def extract_mangled_names(
    changed_functions: List[str],
    function_info_map: Dict
) -> Set[str]:
    """
    Extract mangled function names from function_info_map.
    
    Args:
        changed_functions: List of "file:signature" strings
        function_info_map: Dict mapping "file:signature" to function info
        
    Returns:
        Set of mangled function names
    """
    mangled_names = set()
    
    for func_key in changed_functions:
        if func_key in function_info_map:
            info = function_info_map[func_key]
            mangled_name = info.get('mangled_name')
            if mangled_name:
                mangled_names.add(mangled_name)
    
    return mangled_names


def generate_sancov_allowlist(
    mangled_names: Set[str],
    source_files: Optional[Set[str]] = None
) -> str:
    """
    Generate sancov allowlist content.
    
    Format:
        src:*  (or src:<file> for each file)
        fun:<mangled_name>
        
    Args:
        mangled_names: Set of mangled function names
        source_files: Optional set of source files (if None, uses src:*)
        
    Returns:
        Allowlist content as string
    """
    lines = [
        "# Sancov Allowlist - Auto-generated",
        "# Format: -fsanitize-coverage-allowlist=<this_file>",
        "#",
        "# Source filter (required for fun: patterns to work)",
        "src:*",
        "",
        "# Functions to instrument",
    ]
    
    # Add function entries
    for name in sorted(mangled_names):
        lines.append(f"fun:{name}")
    
    return '\n'.join(lines) + '\n'


def generate_pgo_allowlist(mangled_names: Set[str]) -> str:
    """
    Generate PGO profile list content.
    
    Format:
        [clang]
        fun:<mangled_name>
        
    Args:
        mangled_names: Set of mangled function names
        
    Returns:
        Profile list content as string
    """
    lines = [
        "# PGO Profile List - Auto-generated",
        "# Format: -fprofile-list=<this_file>",
        "#",
        "[clang]",
        "",
    ]
    
    # Add function entries
    for name in sorted(mangled_names):
        lines.append(f"fun:{name}")
    
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(
        description='Generate sancov and PGO allowlists from changed functions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--input', '-i', required=True,
                        help='Path to changed_functions.json')
    parser.add_argument('--output-sancov', '-s',
                        help='Output path for sancov allowlist')
    parser.add_argument('--output-pgo', '-p',
                        help='Output path for PGO allowlist')
    parser.add_argument('--output-dir', '-o',
                        help='Output directory (creates sancov_allowlist.txt and pgo_allowlist.txt)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate input
    if not Path(args.input).exists():
        print(f"❌ Input file not found: {args.input}")
        return 1
    
    # Determine output paths
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        sancov_path = output_dir / "sancov_allowlist.txt"
        pgo_path = output_dir / "pgo_allowlist.txt"
    else:
        sancov_path = Path(args.output_sancov) if args.output_sancov else None
        pgo_path = Path(args.output_pgo) if args.output_pgo else None
    
    if not sancov_path and not pgo_path:
        print("❌ No output specified. Use --output-dir, --output-sancov, or --output-pgo")
        return 1
    
    # Load changed functions
    print(f"📂 Loading: {args.input}")
    changed_functions, function_info_map = load_changed_functions(args.input)
    
    if not changed_functions:
        print("⚠️  No changed functions found in input file")
        return 0
    
    print(f"   Found {len(changed_functions)} changed functions")
    
    # Extract mangled names
    mangled_names = extract_mangled_names(changed_functions, function_info_map)
    print(f"   Extracted {len(mangled_names)} mangled names")
    
    if not mangled_names:
        print("⚠️  No mangled names found. Allowlists will be empty.")
    
    if args.verbose:
        print("\n   Mangled names:")
        for name in sorted(mangled_names):
            print(f"     {name}")
        print()
    
    # Generate and write sancov allowlist
    if sancov_path:
        sancov_content = generate_sancov_allowlist(mangled_names)
        with open(sancov_path, 'w') as f:
            f.write(sancov_content)
        print(f"✅ Sancov allowlist: {sancov_path} ({len(mangled_names)} functions)")
    
    # Generate and write PGO allowlist
    if pgo_path:
        pgo_content = generate_pgo_allowlist(mangled_names)
        with open(pgo_path, 'w') as f:
            f.write(pgo_content)
        print(f"✅ PGO allowlist: {pgo_path} ({len(mangled_names)} functions)")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
