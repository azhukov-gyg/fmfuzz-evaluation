#!/usr/bin/env python3
"""
Timeline Recipe Replay for Z3 - Processes recipes in exact timestamp order with periodic coverage checkpoints.

TIMELINE MODE: Recipes processed one-by-one in exact fuzzing timestamp order.
- Recipes sorted by their 'timestamp' field (fuzzing time when generated)
- Coverage extracted every N seconds of wall-clock measurement time
- No grouping/batching - trades efficiency for accurate timeline replay

Used for generating cumulative coverage timelines to compare fuzzing strategies.
"""

import argparse
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class MutationTimeout(Exception):
    """Raised when a mutation operation times out."""
    pass


@contextmanager
def mutation_timeout(seconds: int):
    """Context manager for timing out mutation operations."""
    def timeout_handler(signum, frame):
        raise MutationTimeout(f"Mutation timed out after {seconds}s")
    
    if hasattr(signal, 'SIGALRM'):
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        yield


MUTATION_TIMEOUT = 30
PARSE_TIMEOUT = 60

# Add script directories to path
SCRIPT_DIR = Path(__file__).parent
RQ2_DIR = Path(__file__).parent.parent.parent / "rq2"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if str(RQ2_DIR) not in sys.path:
    sys.path.insert(0, str(RQ2_DIR))

from recipe_recorder import RecipeReader, compute_content_hash

# Try to import yinyang
YINYANG_AVAILABLE = False
InlineTypeFuzz = None

try:
    from inline_typefuzz import InlineTypeFuzz as _InlineTypeFuzz, YINYANG_AVAILABLE as _YY_AVAIL
    InlineTypeFuzz = _InlineTypeFuzz
    YINYANG_AVAILABLE = _YY_AVAIL
except ImportError:
    pass


def log(msg: str, flush: bool = True):
    """Print with timestamp and flush."""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}", flush=flush)


def load_changed_functions(changed_functions_file: str) -> tuple:
    """
    Load changed function names and their exact line ranges from JSON file.
    
    Returns:
        (functions: Set[str], function_ranges: Dict[str, tuple])
        - functions: Set of function keys like "src/file.cpp:func_name:123"
        - function_ranges: Dict mapping "src/file.cpp:123" -> (start_line, end_line)
    """
    try:
        with open(changed_functions_file, 'r') as f:
            data = json.load(f)
        
        functions = set()
        function_ranges = {}  # Maps "file:start_line" -> (start, end)
        
        # Load function_info_map if available (has exact start/end lines)
        function_info_map = data.get('function_info_map', {})
        
        if 'functions' in data:
            for fn in data['functions']:
                if isinstance(fn, dict):
                    name = fn.get('function') or fn.get('name') or fn.get('mangled_name')
                    if name:
                        functions.add(name)
                elif isinstance(fn, str):
                    functions.add(fn)
        elif 'changed_functions' in data:
            for fn in data['changed_functions']:
                if isinstance(fn, dict):
                    name = fn.get('function') or fn.get('name')
                    if name:
                        functions.add(name)
                elif isinstance(fn, str):
                    functions.add(fn)
        
        # Extract exact line ranges from function_info_map
        for func_key, info in function_info_map.items():
            if isinstance(info, dict):
                file_path = info.get('file', '')
                start = info.get('start', 0)
                end = info.get('end', 0)
                if file_path and start and end:
                    # Normalize path to relative format (strip /z3/ prefix if present)
                    normalized_path = file_path
                    if '/z3/' in file_path:
                        normalized_path = file_path.split('/z3/', 1)[1]
                    # Key format: "file_path:start_line"
                    range_key = f"{normalized_path}:{start}"
                    function_ranges[range_key] = (start, end)
        
        if function_ranges:
            log(f"Loaded {len(function_ranges)} exact function ranges from function_info_map")
        else:
            log("No function_info_map found - will use GCOV heuristics for line ranges")
        
        return functions, function_ranges
    except Exception as e:
        log(f"Error loading changed functions: {e}")
        return set(), {}


def reset_gcda_files(build_dir: str):
    """Remove existing .gcda files to start fresh."""
    count = 0
    for gcda in Path(build_dir).rglob("*.gcda"):
        try:
            gcda.unlink()
            count += 1
        except Exception:
            pass
    return count


def extract_static_branch_counts(
    build_dir: str,
    source_files: Set[str],
    exact_function_ranges: Dict[str, tuple],
    filter_system_branches: bool = True
) -> Dict[str, int]:
    """
    Extract static branch counts from .gcno files using gcov intermediate format.
    
    Args:
        build_dir: Directory containing .gcno/.gcda files
        source_files: Set of source file paths (relative, like "src/math/lp/nra_solver.cpp")
        exact_function_ranges: Dict mapping "file:start_line" -> (start, end)
        filter_system_branches: If True, exclude branches from system headers (default: True)
    
    Returns:
        Dict mapping "file:start_line" -> total_branches_in_function
    """
    import subprocess
    import os
    from pathlib import Path
    
    log(f"[BRANCH DEBUG] ========================================")
    log(f"[BRANCH DEBUG] FUNCTION CALLED: extract_static_branch_counts")
    log(f"[BRANCH DEBUG] ========================================")
    
    branch_counts = {}
    
    # Find the source root by going up from build_dir
    # build_dir is typically /path/to/z3/build, source root is /path/to/z3
    source_root = os.path.dirname(build_dir)
    
    log(f"[BRANCH DEBUG] Source root: {source_root}")
    log(f"[BRANCH DEBUG] Build dir: {build_dir}")
    log(f"[BRANCH DEBUG] Input source_files ({len(source_files)}): {source_files}")
    log(f"[BRANCH DEBUG] Input exact_function_ranges ({len(exact_function_ranges)} entries)")
    for key in list(exact_function_ranges.keys())[:5]:
        log(f"[BRANCH DEBUG]   {key} -> {exact_function_ranges[key]}")
    
    # Build a map of source filenames to their .gcno files
    # .gcno files are in CMake subdirs like: build/src/math/lp/CMakeFiles/lp.dir/nra_solver.cpp.gcno
    log(f"[BRANCH DEBUG] Searching for .gcno files in: {build_dir}")
    gcno_map = {}
    build_path = Path(build_dir)
    gcno_count = 0
    for gcno_file in build_path.rglob("*.gcno"):
        gcno_count += 1
        # Extract the source filename (e.g., "nra_solver.cpp" from "nra_solver.cpp.gcno")
        source_name = gcno_file.name
        if source_name.endswith('.gcno'):
            source_name = source_name[:-5]  # Remove .gcno
        gcno_map[source_name] = gcno_file
        if gcno_count <= 3:
            log(f"[BRANCH DEBUG]   Sample .gcno: {gcno_file} -> {source_name}")
    
    log(f"[BRANCH DEBUG] Found {len(gcno_map)} .gcno files (iterated {gcno_count} total)")
    if len(gcno_map) > 0:
        log(f"[BRANCH DEBUG] Sample entries from gcno_map:")
        for key in list(gcno_map.keys())[:5]:
            log(f"[BRANCH DEBUG]   '{key}' -> {gcno_map[key]}")
    
    log(f"[BRANCH DEBUG] Starting to process {len(source_files)} source files...")
    for idx, source_file in enumerate(source_files):
        log(f"[BRANCH DEBUG] [{idx+1}/{len(source_files)}] Processing: {source_file}")
        try:
            # Construct full path to source file
            full_source_path = os.path.join(source_root, source_file)
            log(f"[BRANCH DEBUG]   Full path: {full_source_path}")
            log(f"[BRANCH DEBUG]   Exists: {os.path.exists(full_source_path)}")
            
            if not os.path.exists(full_source_path):
                log(f"[BRANCH DEBUG] Source file not found: {full_source_path}")
                continue
            
            # Find the corresponding .gcno file
            source_filename = os.path.basename(source_file)
            log(f"[BRANCH DEBUG]   Basename: {source_filename}")
            log(f"[BRANCH DEBUG]   In gcno_map: {source_filename in gcno_map}")
            
            if source_filename not in gcno_map:
                log(f"[BRANCH DEBUG] No .gcno file found for {source_filename}")
                log(f"[BRANCH DEBUG]   Available keys: {list(gcno_map.keys())[:10]}")
                continue
            
            gcno_file = gcno_map[source_filename]
            gcno_dir = str(gcno_file.parent)
            
            log(f"[BRANCH DEBUG] Running gcov on: {full_source_path}")
            log(f"[BRANCH DEBUG]   .gcno location: {gcno_file}")
            
            # Run gcov with JSON format to get static branch structure  
            # -t: output to stdout (not file)
            # -b: include branch probabilities (required for branch data in JSON)
            # --json-format: machine-readable JSON output
            # --object-file: specify the .gcno file directly (avoids naming issues)
            result = subprocess.run(
                ['gcov', '-t', '-b', '--json-format', '--object-file', str(gcno_file), full_source_path],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=source_root
            )
            
            if result.returncode != 0:
                log(f"[BRANCH DEBUG] gcov failed (rc={result.returncode}) for {source_file}")
                if result.stderr:
                    log(f"[BRANCH DEBUG] stderr: {result.stderr[:200]}")
                continue
            
            log(f"[BRANCH DEBUG] gcov succeeded, parsing output ({len(result.stdout)} bytes)")
            
            # Show sample of actual gcov output for debugging
            log(f"[BRANCH DEBUG] First 500 chars of gcov output:")
            log(f"[BRANCH DEBUG] {result.stdout[:500]}")
            
            # Parse JSON format output
            import json
            function_branches = {}  # {range_key: count}
            total_branches = 0
            total_branches_unfiltered = 0
            system_branches_filtered = 0
            
            try:
                gcov_data = json.loads(result.stdout)
                log(f"[BRANCH DEBUG] Successfully parsed JSON, keys: {list(gcov_data.keys())}")
                
                # JSON format has 'files' array
                files = gcov_data.get('files', [])
                log(f"[BRANCH DEBUG] Found {len(files)} files in JSON")
                
                for file_data in files:
                    file_path = file_data.get('file', '')
                    
                    # Check if this is a system/library file that should be filtered
                    is_system_file = False
                    if filter_system_branches:
                        # Filter out system headers, standard library, compiler internals
                        if any(pattern in file_path for pattern in [
                            '/usr/include/',
                            '/usr/lib/',
                            '/usr/local/include/',
                            'bits/',  # STL implementation details
                            'c++/',   # C++ standard library (when not in /usr/include)
                        ]):
                            is_system_file = True
                    
                    # Normalize to relative path
                    current_file = file_path
                    if '/cvc5/' in file_path:
                        current_file = file_path.split('/cvc5/', 1)[1]
                    elif '/z3/' in file_path:
                        current_file = file_path.split('/z3/', 1)[1]
                    
                    log(f"[BRANCH DEBUG]   Processing file from JSON: {current_file}")
                    
                    # Get lines data which includes branch information
                    lines = file_data.get('lines', [])
                    log(f"[BRANCH DEBUG]     {len(lines)} lines in file")
                    
                    for line_data in lines:
                        line_number = line_data.get('line_number')
                        branches = line_data.get('branches', [])
                        
                        if branches:
                            total_branches_unfiltered += len(branches)
                            
                            # Skip system branches if filtering is enabled
                            if is_system_file:
                                system_branches_filtered += len(branches)
                                continue
                            
                            total_branches += len(branches)
                            
                            # Find which function this line belongs to
                            for range_key, (start, end) in exact_function_ranges.items():
                                file_path_key, start_str = range_key.rsplit(':', 1)
                                if current_file == file_path_key and start <= line_number <= end:
                                    if range_key not in function_branches:
                                        function_branches[range_key] = 0
                                    function_branches[range_key] += len(branches)
                                    break
                
            except json.JSONDecodeError as e:
                log(f"[BRANCH DEBUG] Failed to parse JSON: {e}")
                log(f"[BRANCH DEBUG] Output was not JSON, trying standard format parse...")
                # Fallback: count from summary line if available
                for line in result.stdout.split('\n'):
                    if 'Branches executed:' in line and '% of' in line:
                        # Extract total from "Branches executed:31.57% of 1552"
                        try:
                            parts = line.split('of')
                            if len(parts) > 1:
                                total_in_file = int(parts[1].strip())
                                log(f"[BRANCH DEBUG] Found {total_in_file} total branches from summary")
                                # Assign all to the main source file's functions
                                # This is approximate but better than 0
                                for range_key in exact_function_ranges.keys():
                                    file_path_key = range_key.rsplit(':', 1)[0]
                                    if source_file in file_path_key:
                                        if range_key not in function_branches:
                                            function_branches[range_key] = 0
                                        # Distribute evenly (rough approximation)
                                total_branches = total_in_file
                        except (ValueError, IndexError):
                            pass
            
            branch_counts.update(function_branches)
            log(f"[BRANCH DEBUG] Parsing complete for {source_file}:")
            if filter_system_branches:
                log(f"[BRANCH DEBUG]   Total branches (unfiltered): {total_branches_unfiltered}")
                log(f"[BRANCH DEBUG]   System branches filtered out: {system_branches_filtered}")
                log(f"[BRANCH DEBUG]   Total branches (filtered): {total_branches}")
            else:
                log(f"[BRANCH DEBUG]   Total branches in file: {total_branches}")
            log(f"[BRANCH DEBUG]   Branches mapped to changed functions: {sum(function_branches.values())}")
            log(f"[BRANCH DEBUG]   Changed functions with branches: {len(function_branches)}")
            
        except subprocess.TimeoutExpired:
            log(f"[BRANCH DEBUG] gcov timeout for {source_file}")
            continue
        except Exception as e:
            log(f"[BRANCH DEBUG] Error processing {source_file}: {e}")
            import traceback
            log(f"[BRANCH DEBUG] Traceback: {traceback.format_exc()}")
            continue
    
    return branch_counts


def extract_coverage_fastcov(
    build_dir: str,
    gcov_cmd: str,
    changed_functions: Set[str],
    exact_function_ranges: Dict[str, tuple] = None
) -> Dict[str, any]:
    """
    Extract function, line, and branch coverage from gcov data using fastcov.
    
    Returns dict with:
        - function_counts: {func_key: call_count}
        - line_coverage: {file:line: hit_count}
        - branch_coverage: {file:line:branch_id: taken_count}
        - summary: {lines_hit, lines_total, branches_taken, branches_total}
    """
    result = {
        "function_counts": {},
        "line_coverage": {},
        "branch_coverage": {},
        "summary": {
            "lines_hit": 0,
            "lines_total": 0,
            "branches_taken": 0,
            "branches_total": 0,
        }
    }
    fastcov_output = None
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            fastcov_output = f.name
        
        cmd_result = subprocess.run(
            [
                "fastcov",
                "--gcov", gcov_cmd,
                "--search-directory", build_dir,
                "--branch-coverage",
                "--output", fastcov_output,
                "--exclude", "/usr/include/*",
                "--exclude", "*/deps/*",
                "--jobs", "4"
            ],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if cmd_result.returncode == 0 and os.path.exists(fastcov_output):
            with open(fastcov_output, 'r') as f:
                fastcov_data = json.load(f)
            
            # Parse changed_functions to extract file:line for matching
            changed_file_lines = {}
            for func_key in changed_functions:
                parts = func_key.rsplit(':', 2)
                if len(parts) >= 2:
                    try:
                        line_num = int(parts[-1])
                        file_path = parts[0].split(':')[0]
                        changed_file_lines[(file_path, line_num)] = func_key
                    except ValueError:
                        pass
            
            target_files = set(fp for fp, ln in changed_file_lines.keys())
            func_line_ranges = {}
            
            # Pre-populate with exact function ranges
            if exact_function_ranges:
                for range_key, (start, end) in exact_function_ranges.items():
                    parts = range_key.rsplit(':', 1)
                    if len(parts) == 2:
                        file_path = parts[0]
                        if file_path not in func_line_ranges:
                            func_line_ranges[file_path] = []
                        func_line_ranges[file_path].append((start, end))
            
            # Process source files
            sources = fastcov_data.get('sources', {})
            for source_file, source_data in sources.items():
                inner_data = source_data.get('', {})
                funcs = inner_data.get('functions', {}) if isinstance(inner_data, dict) else {}
                lines_data = inner_data.get('lines', {}) if isinstance(inner_data, dict) else {}
                branches_data = inner_data.get('branches', []) if isinstance(inner_data, dict) else []
                
                # Extract relative path
                source_relative = source_file
                if '/z3/' in source_file:
                    source_relative = source_file.split('/z3/', 1)[1]
                
                is_target_file = source_relative in target_files
                
                # Get function ranges
                all_func_starts = sorted(set(fd.get('start_line', 0) for fd in funcs.values()))
                max_file_line = max((int(ln) for ln in lines_data.keys()), default=0) if lines_data else 0
                
                def get_end_line(file_path: str, start: int) -> int:
                    if exact_function_ranges:
                        range_key = f"{file_path}:{start}"
                        if range_key in exact_function_ranges:
                            return exact_function_ranges[range_key][1]
                    for next_start in all_func_starts:
                        if next_start > start:
                            return next_start - 1
                    return max_file_line if max_file_line > start else start + 200
                
                # Extract function counts
                for func_name, func_data in funcs.items():
                    exec_count = func_data.get('execution_count', 0)
                    start_line = func_data.get('start_line', 0)
                    end_line = func_data.get('end_line') or get_end_line(source_relative, start_line)
                    
                    match_key = (source_relative, start_line)
                    if match_key in changed_file_lines:
                        full_key = changed_file_lines[match_key]
                        result["function_counts"][full_key] = result["function_counts"].get(full_key, 0) + exec_count
                        
                        if source_relative not in func_line_ranges:
                            func_line_ranges[source_relative] = []
                        range_tuple = (start_line, end_line)
                        if range_tuple not in func_line_ranges[source_relative]:
                            func_line_ranges[source_relative].append(range_tuple)
                
                # Extract line coverage
                if is_target_file and source_relative in func_line_ranges:
                    # Count ALL lines in function ranges
                    for start_line, end_line in func_line_ranges[source_relative]:
                        for line_num in range(start_line, end_line + 1):
                            line_key = f"{source_relative}:{line_num}"
                            if line_key not in result["line_coverage"]:
                                result["line_coverage"][line_key] = 0
                                result["summary"]["lines_total"] += 1
                    
                    # Overlay execution data
                    if lines_data:
                        for line_num_str, hit_count in lines_data.items():
                            try:
                                line_num = int(line_num_str)
                                line_key = f"{source_relative}:{line_num}"
                                if line_key in result["line_coverage"]:
                                    result["line_coverage"][line_key] = hit_count
                                    if hit_count > 0:
                                        result["summary"]["lines_hit"] += 1
                            except (ValueError, TypeError):
                                pass
                
                # Extract branch coverage
                if is_target_file and source_relative in func_line_ranges:
                    def line_in_changed_function(file_path: str, line: int) -> bool:
                        ranges = func_line_ranges.get(file_path, [])
                        for start, end in ranges:
                            if start <= line <= end:
                                return True
                        return False
                    
                    if branches_data and isinstance(branches_data, dict):
                        for line_num_str, branch_counts in branches_data.items():
                            try:
                                line_num = int(line_num_str)
                                if line_in_changed_function(source_relative, line_num):
                                    for branch_idx, taken_count in enumerate(branch_counts):
                                        branch_key = f"{source_relative}:{line_num}:{branch_idx}"
                                        result["branch_coverage"][branch_key] = taken_count
                                        result["summary"]["branches_total"] += 1
                                        if taken_count > 0:
                                            result["summary"]["branches_taken"] += 1
                            except (ValueError, TypeError):
                                pass
            
            # Extract static branch counts from .gcno files
            if exact_function_ranges:
                source_files_for_branches = set()
                for range_key in exact_function_ranges.keys():
                    file_path = range_key.rsplit(':', 1)[0]
                    source_files_for_branches.add(file_path)
                
                static_branch_counts = extract_static_branch_counts(
                    build_dir,
                    source_files_for_branches,
                    exact_function_ranges,
                    filter_system_branches=True
                )
                
                if static_branch_counts:
                    # Use static counts for total, keep execution data for taken
                    result["summary"]["branches_total"] = sum(static_branch_counts.values())
    
    except Exception as e:
        log(f"WARNING: fastcov error: {e}")
    finally:
        if fastcov_output and os.path.exists(fastcov_output):
            try:
                os.unlink(fastcov_output)
            except:
                pass
    
    return result


def regenerate_chain_content(seed_path: str, rng_seed: int, chain: List[int]) -> Optional[str]:
    """
    Regenerate intermediate mutant content by replaying the mutation chain.
    
    Args:
        seed_path: Path to original seed file
        rng_seed: RNG seed used for mutations
        chain: List of iterations, e.g., [10, 20] means gen1 at iter 10, gen2 at iter 20
    
    Returns:
        The content of the final mutant in the chain, or None if regeneration fails.
    """
    if not YINYANG_AVAILABLE:
        return None
    
    # Read original seed content
    try:
        with open(seed_path, 'r') as f:
            content = f.read()
    except Exception as e:
        log(f"  Chain: failed to read seed {seed_path}: {e}")
        return None
    
    # If no chain, return original content
    if not chain:
        return content
    
    # Process each chain step
    for step_idx, target_iter in enumerate(chain):
        # Initialize RNG fresh for each chain step
        random.seed(rng_seed)
        
        # Create fuzzer from current content
        try:
            fuzzer = InlineTypeFuzz.from_string(content) if hasattr(InlineTypeFuzz, 'from_string') else None
            if fuzzer is None:
                # Fallback: write to temp file and parse
                with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                    f.write(content)
                    temp_path = f.name
                try:
                    fuzzer = InlineTypeFuzz(Path(temp_path))
                    try:
                        with mutation_timeout(PARSE_TIMEOUT):
                            parse_ok = fuzzer.parse()
                    except MutationTimeout:
                        log(f"  Chain step {step_idx+1}: PARSE TIMEOUT")
                        return None
                    if not parse_ok:
                        log(f"  Chain step {step_idx+1}: parse failed")
                        return None
                finally:
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
        except Exception as e:
            log(f"  Chain step {step_idx+1}: failed to create fuzzer: {e}")
            return None
        
        # Generate mutations up to target_iter
        try:
            with mutation_timeout(MUTATION_TIMEOUT):
                for i in range(1, target_iter + 1):
                    mutant, success = fuzzer.mutate()
                    if i == target_iter:
                        if success and mutant:
                            content = mutant
                        else:
                            log(f"  Chain step {step_idx+1}: mutation {target_iter} failed")
                            return None
        except MutationTimeout:
            log(f"  Chain step {step_idx+1}: MUTATION TIMEOUT at iter {target_iter}")
            return None
    
    return content


def regenerate_mutation(seed_path: str, rng_seed: int, iteration: int, chain: List[int] = None) -> Optional[str]:
    """Regenerate a mutation from a recipe, including chain support."""
    if not YINYANG_AVAILABLE:
        return None
    
    try:
        # If chain exists, regenerate chain content first
        if chain:
            start_content = regenerate_chain_content(seed_path, rng_seed, chain)
            if start_content is None:
                return None
            # Create fuzzer from chain content
            fuzzer = InlineTypeFuzz.from_string(start_content) if hasattr(InlineTypeFuzz, 'from_string') else None
            if fuzzer is None:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                    f.write(start_content)
                    temp_path = f.name
                try:
                    fuzzer = InlineTypeFuzz(Path(temp_path))
                    try:
                        with mutation_timeout(PARSE_TIMEOUT):
                            parse_ok = fuzzer.parse()
                    except MutationTimeout:
                        log(f"  PARSE TIMEOUT (chain content)")
                        return None
                    if not parse_ok:
                        log(f"  PARSE FAILED (chain content)")
                        return None
                finally:
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
        else:
            # No chain - create fuzzer from seed file
            fuzzer = InlineTypeFuzz(Path(seed_path))
            try:
                with mutation_timeout(PARSE_TIMEOUT):
                    parse_ok = fuzzer.parse()
            except MutationTimeout:
                log(f"  PARSE TIMEOUT {seed_path}")
                return None
            if not parse_ok:
                log(f"  PARSE FAILED {seed_path}")
                return None
        
        # Initialize RNG
        random.seed(rng_seed)
        
        # Generate mutations up to target iteration
        mutant = None
        success = False
        try:
            with mutation_timeout(MUTATION_TIMEOUT):
                for i in range(iteration + 1):
                    mutant, success = fuzzer.mutate()
        except MutationTimeout:
            log(f"  MUTATION TIMEOUT iter={iteration}")
            return None
        
        if success and mutant:
            return mutant
        else:
            return None
    
    except Exception as e:
        log(f"  ERROR regenerating: {e}")
        return None


def run_solver_with_coverage(test_file: str, solver_path: str, timeout: int, z3_memory_mb: int) -> bool:
    """Run solver on test file to generate coverage data."""
    try:
        env = os.environ.copy()
        env['Z3_MAX_MEMORY'] = str(z3_memory_mb)
        
        result = subprocess.run(
            [solver_path, test_file],
            capture_output=True,
            timeout=timeout,
            env=env
        )
        return True
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        log(f"  ERROR running solver: {e}")
        return False


def replay_recipes_timeline(
    recipe_file: str,
    solver_path: str,
    build_dir: str,
    changed_functions_file: str,
    output_file: str,
    gcov_cmd: str = "gcov",
    timeout: int = 60,
    seeds_file: Optional[str] = None,
    z3_memory_mb: int = 4096,
    checkpoint_interval: int = 60
) -> dict:
    """
    Replay recipes in exact timestamp order with periodic coverage extraction.
    """
    log("=" * 60)
    log(f"TIMELINE RECIPE REPLAY")
    log(f"Checkpoint interval: {checkpoint_interval}s (wall-clock time)")
    log("=" * 60)
    
    solver_path = os.path.abspath(solver_path)
    build_dir = os.path.abspath(build_dir)
    log(f"Solver: {solver_path}")
    log(f"Build dir: {build_dir}")
    
    if not YINYANG_AVAILABLE:
        log("ERROR: yinyang not available")
        return {"error": "yinyang not available"}
    
    # Load recipes
    log(f"Loading recipes from: {recipe_file}")
    reader = RecipeReader(recipe_file)
    all_recipes = reader.recipes
    log(f"Total recipes: {len(all_recipes)}")
    
    # Filter by seeds if specified
    if seeds_file:
        log(f"Loading seed filter from: {seeds_file}")
        with open(seeds_file, 'r') as f:
            seeds_data = json.load(f)
        
        if isinstance(seeds_data, dict) and 'seed_keys' in seeds_data:
            allowed_keys = set()
            for sk in seeds_data['seed_keys']:
                chain = tuple(sk.get('chain', []))
                allowed_keys.add((sk['seed_path'], sk['rng_seed'], chain))
            
            def recipe_to_key(r):
                return (r.get('seed_path'), r.get('rng_seed', 42), tuple(r.get('chain', [])))
            
            recipes = [r for r in all_recipes if recipe_to_key(r) in allowed_keys]
            log(f"After seed filter: {len(recipes)} recipes")
        else:
            recipes = all_recipes
    else:
        recipes = all_recipes
    
    if len(recipes) == 0:
        log("WARNING: No recipes to process!")
        return {"error": "No recipes"}
    
    # Sort by timestamp
    recipes_with_ts = [r for r in recipes if 'timestamp' in r]
    if not recipes_with_ts:
        log("ERROR: No timestamps in recipes!")
        return {"error": "No timestamps"}
    
    recipes_with_ts.sort(key=lambda r: r['timestamp'])
    log(f"Sorted {len(recipes_with_ts)} recipes by timestamp")
    log(f"Fuzzing timespan: {recipes_with_ts[0]['timestamp']:.1f}s - {recipes_with_ts[-1]['timestamp']:.1f}s")
    
    # Load changed functions
    log(f"Loading changed functions from: {changed_functions_file}")
    changed_functions, exact_function_ranges = load_changed_functions(changed_functions_file)
    log(f"Tracking {len(changed_functions)} changed functions")
    
    # Reset coverage
    log("Resetting gcda files...")
    reset_gcda_files(build_dir)
    
    # Create temp directory for test files
    test_output_dir = tempfile.mkdtemp(prefix='timeline_tests_')
    log(f"Test directory: {test_output_dir}")
    
    # Shared state for monitoring
    recipes_processed = {'count': 0}
    checkpoints = []
    stop_monitoring = threading.Event()
    start_time = time.time()
    
    def checkpoint_monitor():
        """Background thread that extracts coverage every checkpoint_interval seconds"""
        checkpoint_num = 0
        while not stop_monitoring.is_set():
            time.sleep(checkpoint_interval)
            
            if stop_monitoring.is_set():
                break
            
            checkpoint_num += 1
            wall_elapsed = time.time() - start_time
            
            log(f"\n[CHECKPOINT {checkpoint_num}] at wall-time {wall_elapsed:.1f}s")
            log(f"[CHECKPOINT {checkpoint_num}] Extracting coverage...")
            
            extract_start = time.time()
            try:
                coverage_data = extract_coverage_fastcov(
                    build_dir=build_dir,
                    gcov_cmd=gcov_cmd,
                    changed_functions=changed_functions,
                    exact_function_ranges=exact_function_ranges
                )
                
                extract_time = time.time() - extract_start
                
                checkpoint = {
                    'checkpoint_number': checkpoint_num,
                    'wall_time_seconds': wall_elapsed,
                    'recipes_processed': recipes_processed['count'],
                    'lines_hit': coverage_data['summary']['lines_hit'],
                    'lines_total': coverage_data['summary']['lines_total'],
                    'branches_taken': coverage_data['summary']['branches_taken'],
                    'branches_total': coverage_data['summary']['branches_total'],
                    'function_calls': sum(coverage_data['function_counts'].values()),
                    'extract_time_seconds': extract_time
                }
                
                checkpoints.append(checkpoint)
                
                branches_pct = 100.0 * checkpoint['branches_taken'] / checkpoint['branches_total'] if checkpoint['branches_total'] > 0 else 0
                lines_pct = 100.0 * coverage_data['summary']['lines_hit'] / checkpoint['lines_total'] if checkpoint['lines_total'] > 0 else 0
                log(f"[CHECKPOINT {checkpoint_num}] Lines: {coverage_data['summary']['lines_hit']}/{checkpoint['lines_total']} ({lines_pct:.1f}%)")
                log(f"[CHECKPOINT {checkpoint_num}] Branches: {checkpoint['branches_taken']}/{checkpoint['branches_total']} ({branches_pct:.1f}%)")
                log(f"[CHECKPOINT {checkpoint_num}] Recipes processed: {recipes_processed['count']}/{len(recipes_with_ts)}")
                log(f"[CHECKPOINT {checkpoint_num}] Extraction took {extract_time:.1f}s\n")
            except Exception as e:
                log(f"[CHECKPOINT {checkpoint_num}] ERROR: {e}")
    
    # Start monitoring thread
    monitor_thread = threading.Thread(target=checkpoint_monitor, daemon=True)
    monitor_thread.start()
    log(f"Started background checkpoint monitor (every {checkpoint_interval}s)")
    
    # Process recipes in exact timestamp order
    log("")
    log("=" * 60)
    log("Processing recipes in timestamp order...")
    log("=" * 60)
    
    successful = 0
    failed = 0
    
    for idx, recipe in enumerate(recipes_with_ts):
        seed_path = recipe.get('seed_path')
        rng_seed = recipe.get('rng_seed', 42)
        iteration = recipe.get('iteration', 0)
        chain = recipe.get('chain', [])
        
        if (idx + 1) % 100 == 0:
            log(f"Processing recipe {idx+1}/{len(recipes_with_ts)} (t={recipe['timestamp']:.1f}s)...")
        
        # Regenerate mutation (with chain support)
        mutated_content = regenerate_mutation(seed_path, rng_seed, iteration, chain)
        if mutated_content is None:
            failed += 1
            continue
        
        # Write to temp file
        test_file = Path(test_output_dir) / f"test_{idx}.smt2"
        try:
            with open(test_file, 'w') as f:
                f.write(mutated_content)
        except Exception as e:
            log(f"  ERROR writing test file: {e}")
            failed += 1
            continue
        
        # Run solver to generate coverage
        success = run_solver_with_coverage(str(test_file), solver_path, timeout, z3_memory_mb)
        if success:
            successful += 1
        else:
            failed += 1
        
        recipes_processed['count'] = idx + 1
        
        # Clean up test file
        try:
            test_file.unlink()
        except:
            pass
    
    # Stop monitoring and get final checkpoint
    stop_monitoring.set()
    monitor_thread.join(timeout=5)
    
    log("")
    log("=" * 60)
    log("Extracting final coverage...")
    log("=" * 60)
    
    final_coverage = extract_coverage_fastcov(
        build_dir=build_dir,
        gcov_cmd=gcov_cmd,
        changed_functions=changed_functions,
        exact_function_ranges=exact_function_ranges
    )
    
    final_checkpoint = {
        'checkpoint_number': len(checkpoints) + 1,
        'wall_time_seconds': time.time() - start_time,
        'recipes_processed': len(recipes_with_ts),
        'lines_hit': final_coverage['summary']['lines_hit'],
        'lines_total': final_coverage['summary']['lines_total'],
        'branches_taken': final_coverage['summary']['branches_taken'],
        'branches_total': final_coverage['summary']['branches_total'],
        'function_calls': sum(final_coverage['function_counts'].values()),
        'is_final': True
    }
    checkpoints.append(final_checkpoint)
    
    elapsed = time.time() - start_time
    
    # Save results
    results = {
        "recipe_file": recipe_file,
        "timeline_mode": True,
        "checkpoint_interval_seconds": checkpoint_interval,
        "recipes_processed": len(recipes_with_ts),
        "successful_runs": successful,
        "failed_runs": failed,
        "num_checkpoints": len(checkpoints),
        "checkpoints": checkpoints,
        "elapsed_seconds": elapsed,
        "recipes_per_second": len(recipes_with_ts) / elapsed if elapsed > 0 else 0,
        "final_coverage": {
            "lines_hit": final_checkpoint['lines_hit'],
            "lines_total": final_checkpoint['lines_total'],
            "branches_taken": final_checkpoint['branches_taken'],
            "branches_total": final_checkpoint['branches_total'],
            "function_calls": final_checkpoint['function_calls']
        }
    }
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    log("")
    log("=" * 60)
    log("✅ TIMELINE REPLAY COMPLETE")
    log(f"Processed: {len(recipes_with_ts)} recipes ({successful} ok, {failed} failed)")
    log(f"Checkpoints: {len(checkpoints)}")
    log(f"Total time: {elapsed/60:.1f} minutes")
    log(f"Final coverage: {final_checkpoint['branches_taken']}/{final_checkpoint['branches_total']} branches")
    log(f"Results saved to: {output_file}")
    log("=" * 60)
    
    # Cleanup
    try:
        shutil.rmtree(test_output_dir)
    except:
        pass
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Timeline recipe replay for Z3")
    parser.add_argument("--recipe-file", required=True, help="Path to recipe JSONL file")
    parser.add_argument("--solver-path", required=True, help="Path to solver binary")
    parser.add_argument("--build-dir", required=True, help="Path to build directory with gcno files")
    parser.add_argument("--changed-functions", required=True, help="Path to changed_functions.json")
    parser.add_argument("--output", required=True, help="Path to output JSON file")
    parser.add_argument("--gcov-cmd", default="gcov", help="Path to gcov command")
    parser.add_argument("--timeout", type=int, default=60, help="Solver timeout in seconds")
    parser.add_argument("--seeds-file", help="Optional seeds file to filter recipes")
    parser.add_argument("--z3-memory-mb", type=int, default=4096, help="Z3 memory limit in MB")
    parser.add_argument("--checkpoint-interval", type=int, default=60, help="Coverage checkpoint interval in seconds")
    
    args = parser.parse_args()
    
    result = replay_recipes_timeline(
        recipe_file=args.recipe_file,
        solver_path=args.solver_path,
        build_dir=args.build_dir,
        changed_functions_file=args.changed_functions,
        output_file=args.output,
        gcov_cmd=args.gcov_cmd,
        timeout=args.timeout,
        seeds_file=args.seeds_file,
        z3_memory_mb=args.z3_memory_mb,
        checkpoint_interval=args.checkpoint_interval
    )
    
    if "error" in result:
        sys.exit(1)


if __name__ == "__main__":
    main()
