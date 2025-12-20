#!/usr/bin/env python3
"""
Extract function call counts from LLVM PGO profile data.

This script:
1. Merges multiple .profraw files into a single .profdata
2. Uses llvm-cov to export function execution counts as JSON
3. Outputs a summary of function call frequencies

Usage:
    python extract_function_counts.py /path/to/cvc5 --profile-dir /path/to/profiles
    python extract_function_counts.py /path/to/cvc5 --profdata combined.profdata
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple


def find_llvm_tool(tool_name: str) -> str:
    """Find LLVM tool, trying versioned names first."""
    candidates = []
    
    # Try versioned names (common on Ubuntu/Debian)
    for version in range(18, 10, -1):
        candidates.append(f"{tool_name}-{version}")
    
    # Try unversioned
    candidates.append(tool_name)
    
    # Also try common paths directly
    candidates.extend([
        f"/usr/bin/{tool_name}",
        f"/usr/bin/{tool_name}-14",
        f"/usr/lib/llvm-14/bin/{tool_name}",
    ])
    
    for candidate in candidates:
        try:
            result = subprocess.run([candidate, "--version"], capture_output=True, timeout=5)
            if result.returncode == 0:
                return candidate
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass
    
    # Debug: show what's available
    print(f"DEBUG: Could not find {tool_name}. Checking what's available...")
    try:
        result = subprocess.run(["ls", "-la", "/usr/bin/llvm*"], capture_output=True, text=True, shell=False)
        # Use shell to expand glob
        result = subprocess.run("ls -la /usr/bin/llvm* 2>/dev/null | head -20", capture_output=True, text=True, shell=True)
        print(f"DEBUG: /usr/bin/llvm* files:\n{result.stdout}")
    except Exception as e:
        print(f"DEBUG: Could not list files: {e}")
    
    raise FileNotFoundError(f"Could not find {tool_name}. Install LLVM tools.")


def merge_profiles(profile_dir: str, output_profdata: str) -> bool:
    """Merge all .profraw files in directory into a single .profdata."""
    profraw_files = list(Path(profile_dir).glob("*.profraw"))
    
    if not profraw_files:
        print(f"❌ No .profraw files found in {profile_dir}")
        return False
    
    print(f"📊 Found {len(profraw_files)} .profraw files")
    
    llvm_profdata = find_llvm_tool("llvm-profdata")
    
    cmd = [llvm_profdata, "merge", "-sparse", "-o", output_profdata]
    cmd.extend(str(f) for f in profraw_files)
    
    print(f"🔧 Running: {' '.join(cmd[:4])} ... ({len(profraw_files)} files)")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"✅ Merged profiles into {output_profdata}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to merge profiles: {e.stderr}")
        return False


def export_coverage(binary: str, profdata: str) -> Dict:
    """Export coverage data as JSON using llvm-cov."""
    llvm_cov = find_llvm_tool("llvm-cov")
    
    # llvm-cov export outputs JSON by default
    cmd = [
        llvm_cov, "export",
        f"-instr-profile={profdata}",
        binary
    ]
    
    print(f"🔧 Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to export coverage: {e.stderr}")
        return {}
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON output: {e}")
        return {}


def demangle_names(names: List[str]) -> Dict[str, str]:
    """Demangle C++ names using c++filt."""
    if not names:
        return {}
    
    try:
        # Use c++filt to demangle all names at once (efficient)
        result = subprocess.run(
            ["c++filt"],
            input="\n".join(names),
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            demangled = result.stdout.strip().split("\n")
            return dict(zip(names, demangled))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    # Fallback: return original names
    return {n: n for n in names}


def extract_function_counts(coverage_data: Dict) -> List[Tuple[str, int, str]]:
    """Extract function names and execution counts from llvm-cov JSON."""
    functions = []
    
    if not coverage_data:
        return functions
    
    # llvm-cov export format has 'data' array with coverage info
    raw_names = []
    for data in coverage_data.get("data", []):
        for func in data.get("functions", []):
            name = func.get("name", "unknown")
            count = func.get("count", 0)
            
            # Get filename from regions if available
            filenames = func.get("filenames", [])
            filename = filenames[0] if filenames else "unknown"
            
            functions.append((name, count, filename))
            raw_names.append(name)
    
    # Demangle all names
    demangled = demangle_names(raw_names)
    functions = [(demangled.get(n, n), c, f) for n, c, f in functions]
    
    # Sort by count (descending)
    functions.sort(key=lambda x: -x[1])
    
    return functions


def is_cvc5_function(name: str, filename: str) -> bool:
    """Check if function is CVC5-specific (not STL/system)."""
    # Check demangled name
    if "cvc5::" in name or "cvc5_" in name:
        return True
    # Check filename
    if "/cvc5/" in filename or "/src/" in filename:
        return True
    # Skip obvious STL/system functions
    if name.startswith("std::") or name.startswith("__"):
        return False
    return False


def main():
    parser = argparse.ArgumentParser(description="Extract function call counts from LLVM PGO data")
    parser.add_argument("binary", help="Path to instrumented binary")
    parser.add_argument("--profile-dir", help="Directory containing .profraw files")
    parser.add_argument("--profdata", help="Path to merged .profdata file")
    parser.add_argument("--output", help="Output JSON file for results")
    parser.add_argument("--top", type=int, default=50, help="Show top N functions in console (default: 50)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.binary):
        print(f"❌ Binary not found: {args.binary}")
        return 1
    
    # Determine profdata path
    if args.profdata:
        profdata = args.profdata
    elif args.profile_dir:
        profdata = os.path.join(args.profile_dir, "merged.profdata")
        if not merge_profiles(args.profile_dir, profdata):
            return 1
    else:
        # Default: look for profiles in binary directory
        binary_dir = os.path.dirname(args.binary)
        profile_dir = os.path.join(binary_dir, "..", "profiles")
        if os.path.exists(profile_dir):
            profdata = os.path.join(profile_dir, "merged.profdata")
            if not merge_profiles(profile_dir, profdata):
                return 1
        else:
            print(f"❌ No profile directory found. Use --profile-dir or --profdata")
            return 1
    
    if not os.path.exists(profdata):
        print(f"❌ Profile data not found: {profdata}")
        return 1
    
    # Export coverage
    coverage_data = export_coverage(args.binary, profdata)
    if not coverage_data:
        return 1
    
    # Extract function counts
    functions = extract_function_counts(coverage_data)
    
    if not functions:
        print("⚠️  No function data found in coverage export")
        return 1
    
    # Separate CVC5 and other functions
    cvc5_funcs = [(n, c, f) for n, c, f in functions if is_cvc5_function(n, f)]
    other_funcs = [(n, c, f) for n, c, f in functions if not is_cvc5_function(n, f)]
    
    # Build output data
    total_cvc5_calls = sum(c for _, c, _ in cvc5_funcs)
    total_other_calls = sum(c for _, c, _ in other_funcs)
    
    output = {
        "cvc5_functions": [{"name": n, "count": c, "file": f} for n, c, f in cvc5_funcs],
        "other_functions": [{"name": n, "count": c, "file": f} for n, c, f in other_funcs],
        "summary": {
            "total_cvc5_functions": len(cvc5_funcs),
            "total_cvc5_calls": total_cvc5_calls,
            "total_other_functions": len(other_funcs),
            "total_other_calls": total_other_calls,
        }
    }
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"✅ Report saved to: {args.output}")
    
    # Print summary
    print(f"\n{'='*80}")
    print(f"Function Call Count Report")
    print(f"{'='*80}")
    print(f"CVC5 functions: {len(cvc5_funcs):,} ({total_cvc5_calls:,} total calls)")
    print(f"Other functions: {len(other_funcs):,} ({total_other_calls:,} total calls)")
    print(f"{'='*80}\n")
    
    print(f"Top {args.top} CVC5 Functions by Call Count:")
    print("-" * 80)
    for name, count, filename in cvc5_funcs[:args.top]:
        short_name = name[:70] + "..." if len(name) > 70 else name
        print(f"  {count:>10,}x  {short_name}")
    
    if len(cvc5_funcs) > args.top:
        print(f"\n  ... and {len(cvc5_funcs) - args.top} more functions")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

