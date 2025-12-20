#!/usr/bin/env python3
"""
Convert function counts from extract_function_counts.py format to baseline-compatible format.
Adds commit and job_id metadata.
"""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description="Convert function counts to baseline format")
    parser.add_argument("input_file", help="Input function counts JSON file")
    parser.add_argument("--commit", required=True, help="Commit hash")
    parser.add_argument("--job-id", required=True, help="Job ID")
    parser.add_argument("--output", help="Output file (default: overwrite input)")
    
    args = parser.parse_args()
    
    try:
        with open(args.input_file) as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error reading {args.input_file}: {e}", file=sys.stderr)
        return 1
    
    # Add metadata
    data['commit'] = args.commit
    data['job_id'] = args.job_id
    
    # Convert to baseline-compatible format
    functions = []
    for func in data.get('cvc5_functions', []):
        functions.append({
            'function_id': f"{func.get('file', '')}:{func.get('name', '')}:0",
            'triggered': func.get('count', 0) > 0,
            'execution_count': func.get('count', 0)
        })
    
    data['functions'] = functions
    
    # Write output
    output_file = args.output or args.input_file
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"✅ Converted {len(functions)} functions to baseline format")
    return 0


if __name__ == "__main__":
    sys.exit(main())
