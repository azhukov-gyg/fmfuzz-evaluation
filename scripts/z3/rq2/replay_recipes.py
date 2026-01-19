#!/usr/bin/env python3
"""
Recipe Replay for Z3 - Regenerates mutations from recipes and measures function calls using gcov.

OPTIMIZED: Recipes are grouped by (seed_path, rng_seed, chain) and processed sequentially.
- Before: O(N²) - for each recipe, regenerate all previous iterations
- After: O(N) - parse seed once, generate mutations in order, reuse RNG state

CHAIN SUPPORT: Recipes may include a 'chain' field for multi-generation mutations.
- chain=[] : Direct mutation from original seed (gen0)
- chain=[10] : Mutation of a gen1 mutant (created at iter 10 of original seed)
- chain=[10, 20] : Mutation of gen2 (gen1 at iter 10, gen2 at iter 20)
- Chains are regenerated WITHOUT solver calls (dry mutations) before measuring

PARALLEL: Multiple workers process different seed groups simultaneously.
- Workers share the same build directory (gcda files accumulate)
- Main thread periodically extracts counts and resets gcda files

Used by Z3 measurement workflows for: Baseline, Variant1, Variant2
"""

import argparse
import json
import multiprocessing
import os
import queue
import random
import signal
import subprocess
import sys
import tempfile
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
    """Context manager for timing out mutation operations.
    
    Uses signal.SIGALRM on Unix systems. Falls back to no timeout on Windows.
    Note: Only works in the main thread of a process.
    """
    def timeout_handler(signum, frame):
        raise MutationTimeout(f"Mutation timed out after {seconds}s")
    
    if hasattr(signal, 'SIGALRM'):
        # Unix: use signal alarm
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # Windows: no timeout support (signal.SIGALRM not available)
        yield


# Timeout for individual mutation operations (seconds)
MUTATION_TIMEOUT = 30

# Timeout for parsing operations (seconds)
# Deeply nested formulas cause copy.deepcopy to take forever in yinyang's get_unique_subterms
PARSE_TIMEOUT = 60

# Add script directories to path for imports
SCRIPT_DIR = Path(__file__).parent
RQ2_DIR = Path(__file__).parent.parent.parent / "rq2"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if str(RQ2_DIR) not in sys.path:
    sys.path.insert(0, str(RQ2_DIR))

from recipe_recorder import RecipeReader, compute_content_hash

# Try to import yinyang components
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


def load_changed_functions(changed_functions_file: str) -> Set[str]:
    """Load changed function names from JSON file."""
    try:
        with open(changed_functions_file, 'r') as f:
            data = json.load(f)
        
        functions = set()
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
        
        return functions
    except Exception as e:
        log(f"Error loading changed functions: {e}")
        return set()


def extract_coverage_fastcov(
    build_dir: str,
    gcov_cmd: str,
    changed_functions: Set[str]
) -> Dict[str, any]:
    """
    Extract function, line, and branch coverage from gcov data using fastcov.
    
    Returns dict with:
        - function_counts: {func_key: call_count}
        - line_coverage: {file:line: hit_count} for lines in changed functions
        - branch_coverage: {file:line:branch_id: taken_count}
        - summary: {lines_hit, branches_taken, total_lines, total_branches}
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
    
    # Debug: count .gcda files
    gcda_files = list(Path(build_dir).rglob("*.gcda"))
    log(f"[GCOV DEBUG] Found {len(gcda_files)} .gcda files in {build_dir}")
    if gcda_files[:3]:
        for f in gcda_files[:3]:
            log(f"[GCOV DEBUG]   - {f}")
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            fastcov_output = f.name
        
        cmd_result = subprocess.run(
            [
                "fastcov",
                "--gcov", gcov_cmd,
                "--search-directory", build_dir,
                "--branch-coverage",  # Enable branch coverage collection
                "--output", fastcov_output,
                "--exclude", "/usr/include/*",
                "--exclude", "*/deps/*",
                "--jobs", "4"
            ],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        log(f"[GCOV DEBUG] fastcov return code: {cmd_result.returncode}")
        if cmd_result.stderr:
            log(f"[GCOV DEBUG] fastcov stderr: {cmd_result.stderr[:500]}")
        
        if cmd_result.returncode == 0 and os.path.exists(fastcov_output):
            with open(fastcov_output, 'r') as f:
                fastcov_data = json.load(f)
            
            total_sources = len(fastcov_data.get('sources', {}))
            log(f"[GCOV DEBUG] fastcov found {total_sources} source files")
            
            # Debug: show sample source file structure
            sample_shown = False
            total_funcs_found = 0
            
            # Show first source file structure regardless of functions
            sources = fastcov_data.get('sources', {})
            if sources:
                first_source = list(sources.items())[0]
                log(f"[GCOV DEBUG] First source file: {first_source[0]}")
                log(f"[GCOV DEBUG]   Keys available: {list(first_source[1].keys())}")
            
            # Parse changed_functions to extract file:line for matching
            # Format: "src/path/file.cpp:function_name:line_number"
            changed_file_lines = {}  # {(relative_path, line): full_function_key}
            func_line_ranges = {}    # {relative_path: [(start_line, end_line, func_key), ...]}
            for func_key in changed_functions:
                parts = func_key.rsplit(':', 2)
                if len(parts) >= 2:
                    try:
                        line_num = int(parts[-1])
                        file_path = parts[0].split(':')[0]  # Get file path before function name
                        # Use the relative path (e.g., "src/nlsat/nlsat_explain.cpp")
                        changed_file_lines[(file_path, line_num)] = func_key
                        # Track files with changed functions for line/branch filtering
                        if file_path not in func_line_ranges:
                            func_line_ranges[file_path] = []
                        func_line_ranges[file_path].append((line_num, func_key))
                    except ValueError:
                        pass
            
            log(f"[GCOV DEBUG] Parsed {len(changed_file_lines)} changed functions for matching")
            for (fp, ln), fk in list(changed_file_lines.items())[:4]:
                log(f"[GCOV DEBUG]   {fp}:{ln} -> {fk[:60]}...")
            
            # Build a set of files we're looking for (for targeted debugging)
            target_files = set(fp for fp, ln in changed_file_lines.keys())
            log(f"[GCOV DEBUG] Looking for files: {target_files}")
            
            # Show sample of functions found
            all_funcs = []
            for source_file, source_data in sources.items():
                # fastcov structure: source_data['']['functions'] (empty string key!)
                inner_data = source_data.get('', {})
                funcs = inner_data.get('functions', {}) if isinstance(inner_data, dict) else {}
                lines_data = inner_data.get('lines', {}) if isinstance(inner_data, dict) else {}
                branches_data = inner_data.get('branches', []) if isinstance(inner_data, dict) else []
                total_funcs_found += len(funcs)
                
                # Extract relative path from /z3/ (e.g., "src/nlsat/...")
                # Full path: /home/runner/.../z3/src/nlsat/nlsat_explain.cpp
                # We want: src/nlsat/nlsat_explain.cpp
                source_relative = source_file
                if '/z3/' in source_file:
                    source_relative = source_file.split('/z3/', 1)[1]
                
                # Show first source with functions as sample
                if not sample_shown and funcs:
                    log(f"[GCOV DEBUG] Sample source with funcs: {source_file}")
                    log(f"[GCOV DEBUG]   Relative path: {source_relative}")
                    sample_func = list(funcs.items())[0]
                    log(f"[GCOV DEBUG]   Sample func: {sample_func[0][:60]}")
                    log(f"[GCOV DEBUG]   Sample func_data: {sample_func[1]}")
                    sample_shown = True
                
                # Check if this is a target file with changed functions
                is_target_file = source_relative in target_files
                
                # If this is one of our target files, show all its functions and lines
                if is_target_file:
                    log(f"[GCOV DEBUG] FOUND TARGET FILE: {source_relative}")
                    log(f"[GCOV DEBUG]   Full path: {source_file}")
                    log(f"[GCOV DEBUG]   Functions in file ({len(funcs)}):")
                    for fn, fd in sorted(funcs.items(), key=lambda x: x[1].get('start_line', 0)):
                        sl = fd.get('start_line', 0)
                        ec = fd.get('execution_count', 0)
                        # Show which lines we're looking for
                        wanted = [ln for fp, ln in changed_file_lines.keys() if fp == source_relative]
                        marker = " <-- WANTED" if sl in wanted else ""
                        log(f"[GCOV DEBUG]     line {sl}: {ec} calls{marker}")
                
                # Extract function counts
                for func_name, func_data in funcs.items():
                    exec_count = func_data.get('execution_count', 0)
                    start_line = func_data.get('start_line', 0)
                    
                    if exec_count > 0:
                        all_funcs.append((func_name, exec_count))
                    
                    # Match by relative path + line number
                    match_key = (source_relative, start_line)
                    if match_key in changed_file_lines:
                        full_key = changed_file_lines[match_key]
                        result["function_counts"][full_key] = result["function_counts"].get(full_key, 0) + exec_count
                        if exec_count > 0:
                            log(f"[GCOV DEBUG] MATCHED: {source_relative}:{start_line} -> {exec_count} calls")
                
                # Extract line coverage for target files
                if is_target_file and lines_data:
                    for line_num_str, hit_count in lines_data.items():
                        try:
                            line_num = int(line_num_str)
                            line_key = f"{source_relative}:{line_num}"
                            result["line_coverage"][line_key] = hit_count
                            result["summary"]["lines_total"] += 1
                            if hit_count > 0:
                                result["summary"]["lines_hit"] += 1
                        except (ValueError, TypeError):
                            pass
                
                # Extract branch coverage for target files
                if is_target_file and branches_data and isinstance(branches_data, dict):
                    for line_num_str, branch_counts in branches_data.items():
                        try:
                            line_num = int(line_num_str)
                            for branch_idx, taken_count in enumerate(branch_counts):
                                branch_key = f"{source_relative}:{line_num}:{branch_idx}"
                                result["branch_coverage"][branch_key] = taken_count
                                result["summary"]["branches_total"] += 1
                                if taken_count > 0:
                                    result["summary"]["branches_taken"] += 1
                        except (ValueError, TypeError):
                            pass
            
            log(f"[GCOV DEBUG] Total functions found: {total_funcs_found}")
            log(f"[GCOV DEBUG] Found {len(all_funcs)} functions with >0 execution count")
            log(f"[GCOV DEBUG] Line coverage: {result['summary']['lines_hit']}/{result['summary']['lines_total']} lines hit")
            log(f"[GCOV DEBUG] Branch coverage: {result['summary']['branches_taken']}/{result['summary']['branches_total']} branches taken")
            # Show top 5 by execution count
            if all_funcs:
                top_funcs = sorted(all_funcs, key=lambda x: -x[1])[:5]
                for name, count in top_funcs:
                    log(f"[GCOV DEBUG]   {count:>10}  {name[:80]}")
        else:
            log(f"[GCOV DEBUG] fastcov failed or no output")
        
    except Exception as e:
        log(f"Error extracting coverage: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if fastcov_output and os.path.exists(fastcov_output):
            try:
                os.unlink(fastcov_output)
            except:
                pass
    
    return result


def reset_gcda_files(build_dir: str):
    """Remove existing .gcda files to start fresh."""
    count = 0
    for gcda in Path(build_dir).rglob("*.gcda"):
        try:
            gcda.unlink()
            count += 1
        except:
            pass
    return count


def group_recipes_by_seed(recipes: List[dict]) -> Dict[Tuple[str, int, Tuple[int, ...]], List[dict]]:
    """
    Group recipes by (seed_path, rng_seed, chain) and sort each group by iteration.
    
    Chain support:
    - Recipes with 'chain' field contain the mutation lineage
    - chain=[10] means parent was gen1 created at iteration 10
    - chain=[10, 20] means gen1 at iter 10, gen2 at iter 20
    - Empty or missing chain means fuzzing directly from original seed
    """
    groups = defaultdict(list)
    
    for recipe in recipes:
        seed_path = recipe.get('seed_path')
        rng_seed = recipe.get('rng_seed', 42)
        # Convert chain list to tuple for hashability (empty list becomes empty tuple)
        chain = tuple(recipe.get('chain', []))
        if seed_path:
            key = (seed_path, rng_seed, chain)
            groups[key].append(recipe)
    
    # Sort each group by iteration
    for key in groups:
        groups[key].sort(key=lambda r: r.get('iteration', 0))
    
    return dict(groups)


def regenerate_chain_content(
    seed_path: str,
    rng_seed: int,
    chain: Tuple[int, ...],
    worker_id: int,
    chain_cache: Optional[Dict[Tuple[str, int, Tuple[int, ...]], str]] = None
) -> Optional[str]:
    """
    Regenerate intermediate mutant content by replaying the mutation chain.
    
    Args:
        seed_path: Path to original seed file
        rng_seed: RNG seed used for mutations
        chain: Tuple of iterations, e.g., (10, 20) means gen1 at iter 10, gen2 at iter 20
        worker_id: For logging
        chain_cache: Optional cache mapping (seed_path, rng_seed, chain_prefix) -> content
    
    Returns:
        The content of the final mutant in the chain, or None if regeneration fails.
        For empty chain, returns the original seed content.
    """
    # Check cache for this exact chain
    if chain_cache is not None:
        cache_key = (seed_path, rng_seed, chain)
        if cache_key in chain_cache:
            log(f"[W{worker_id}] Chain {list(chain)} found in cache")
            return chain_cache[cache_key]
    
    # Read original seed content
    try:
        with open(seed_path, 'r') as f:
            content = f.read()
    except Exception as e:
        log(f"[W{worker_id}] Failed to read seed {seed_path}: {e}")
        return None
    
    # If no chain, return original content
    if not chain:
        return content
    
    # Find longest cached prefix to start from
    start_step = 0
    if chain_cache is not None:
        for prefix_len in range(len(chain) - 1, 0, -1):
            prefix = chain[:prefix_len]
            prefix_key = (seed_path, rng_seed, prefix)
            if prefix_key in chain_cache:
                content = chain_cache[prefix_key]
                start_step = prefix_len
                log(f"[W{worker_id}] Chain prefix {list(prefix)} found in cache, starting from step {start_step+1}")
                break
    
    remaining_steps = len(chain) - start_step
    log(f"[W{worker_id}] Chain has {len(chain)} steps: {list(chain)}" + 
        (f" (skipping {start_step} cached)" if start_step > 0 else ""))
    for step_idx, target_iter in enumerate(chain):
        # Skip steps we got from cache
        if step_idx < start_step:
            continue
        log(f"[W{worker_id}] Chain step {step_idx+1}/{len(chain)}: target_iter={target_iter}")
        # Initialize RNG fresh for each chain step (same as during fuzzing)
        random.seed(rng_seed)
        
        # Create fuzzer from current content
        try:
            # InlineTypeFuzz can accept content string directly via from_string
            log(f"[W{worker_id}] Chain step {step_idx+1}: creating fuzzer (content len={len(content)})")
            fuzzer = InlineTypeFuzz.from_string(content) if hasattr(InlineTypeFuzz, 'from_string') else None
            if fuzzer is None:
                # Fallback: write to temp file and parse
                log(f"[W{worker_id}] Chain step {step_idx+1}: from_string N/A, using temp file")
                with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                    f.write(content)
                    temp_path = f.name
                try:
                    fuzzer = InlineTypeFuzz(Path(temp_path))
                    log(f"[W{worker_id}] Chain step {step_idx+1}: parsing temp file (timeout={PARSE_TIMEOUT}s)")
                    try:
                        with mutation_timeout(PARSE_TIMEOUT):
                            parse_ok = fuzzer.parse()
                    except MutationTimeout:
                        log(f"[W{worker_id}] Chain step {step_idx+1}: PARSE TIMEOUT after {PARSE_TIMEOUT}s (content={len(content)} bytes)")
                        return None
                    if not parse_ok:
                        log(f"[W{worker_id}] Chain step {step_idx+1}: parse failed")
                        return None
                    log(f"[W{worker_id}] Chain step {step_idx+1}: parse OK")
                finally:
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
            else:
                log(f"[W{worker_id}] Chain step {step_idx+1}: from_string OK")
        except Exception as e:
            log(f"[W{worker_id}] Chain step {step_idx}: failed to create fuzzer: {e}")
            return None
        
        # Generate mutations up to target_iter (dry - no solver) with timeout
        log(f"[W{worker_id}] Chain step {step_idx+1}: running {target_iter} mutations (timeout={MUTATION_TIMEOUT}s)")
        mutation_start = time.time()
        try:
            with mutation_timeout(MUTATION_TIMEOUT):
                for i in range(1, target_iter + 1):
                    mutant, success = fuzzer.mutate()
                    # Log progress every 50 iterations
                    if i % 50 == 0:
                        elapsed = time.time() - mutation_start
                        log(f"[W{worker_id}] Chain step {step_idx+1}: mutation {i}/{target_iter} ({elapsed:.1f}s)")
                    if i == target_iter:
                        if success and mutant:
                            content = mutant
                            content_hash = compute_content_hash(content)
                            log(f"[W{worker_id}] Chain step {step_idx+1}: COMPLETE len={len(content)} hash={content_hash}")
                            # Cache this intermediate result
                            if chain_cache is not None:
                                prefix = chain[:step_idx+1]
                                cache_key = (seed_path, rng_seed, prefix)
                                chain_cache[cache_key] = content
                        else:
                            log(f"[W{worker_id}] Chain step {step_idx}: mutation {target_iter} failed")
                            return None
        except MutationTimeout:
            log(f"[W{worker_id}] Chain step {step_idx}: MUTATION TIMEOUT after {MUTATION_TIMEOUT}s at iter {target_iter}")
            return None
    
    log(f"[W{worker_id}] Chain regeneration complete, final content len={len(content)}")
    return content


def process_seed_group(
    seed_path: str,
    rng_seed: int,
    chain: Tuple[int, ...],
    group_recipes: List[dict],
    solver_path: str,
    build_dir: str,
    timeout: int,
    worker_id: int,
    progress_queue: multiprocessing.Queue,
    z3_memory_mb: int = 4096
) -> Tuple[int, int, int]:
    """
    Process all recipes for a single seed group (with optional chain).
    Returns (successful_runs, failed_runs, mutations_generated).
    
    Chain support:
    - Empty chain: fuzz directly from original seed
    - chain=(10,): regenerate gen1 at iter 10, then fuzz from that
    - chain=(10, 20): regenerate gen1->gen2, then fuzz from gen2
    """
    successful = 0
    failed = 0
    mutations = 0
    
    seed_name = Path(seed_path).name
    chain_str = f" chain={list(chain)}" if chain else ""
    
    # Debug: log entry into process_seed_group
    progress_queue.put(('debug', worker_id, f'ENTER process_seed_group: {seed_name}, chain={list(chain) if chain else []}, recipes={len(group_recipes)}'))
    
    # Don't set GCOV_PREFIX - let gcov use embedded absolute paths
    gcov_env = os.environ.copy()
    
    # Check if seed file exists
    if not os.path.exists(seed_path):
        progress_queue.put(('skip', worker_id, seed_name, 'not found', len(group_recipes)))
        return 0, len(group_recipes), 0
    
    progress_queue.put(('debug', worker_id, f'seed file exists: {seed_path}'))
    
    # Regenerate chain content if needed (dry mutations - no solver)
    if chain:
        progress_queue.put(('debug', worker_id, f'STARTING chain regeneration: {list(chain)}'))
        log(f"[W{worker_id}] {seed_name}: regenerating chain {list(chain)}")
        start_content = regenerate_chain_content(seed_path, rng_seed, chain, worker_id)
        if start_content is None:
            progress_queue.put(('skip', worker_id, seed_name, f'chain regeneration failed{chain_str}', len(group_recipes)))
            return 0, len(group_recipes), 0
        progress_queue.put(('debug', worker_id, f'chain regeneration SUCCESS, content len={len(start_content)}'))
        # Count chain mutations (not counted toward solver runs)
        mutations += sum(chain)
    else:
        progress_queue.put(('debug', worker_id, f'no chain, using original file'))
        start_content = None  # Will read from file directly
    
    # Z3 doesn't use COMMAND-LINE directives like CVC5
    # Use standard flags: smt.threads=1, memory limit, model validation
    progress_queue.put(('debug', worker_id, f'setting up Z3 flags'))
    base_flags = [f"smt.threads=1", f"memory_max_size={z3_memory_mb}", "model_validate=true"]
    
    # Initialize RNG and create fuzzer
    progress_queue.put(('debug', worker_id, f'initializing RNG and fuzzer'))
    random.seed(rng_seed)
    
    # Create fuzzer from chain content or original file
    if start_content is not None:
        # We have regenerated chain content - use it
        progress_queue.put(('debug', worker_id, f'creating fuzzer from chain content'))
        try:
            fuzzer = InlineTypeFuzz.from_string(start_content) if hasattr(InlineTypeFuzz, 'from_string') else None
            if fuzzer is None:
                # Fallback: write to temp file
                progress_queue.put(('debug', worker_id, f'from_string not available, using temp file'))
                with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                    f.write(start_content)
                    temp_path = f.name
                try:
                    progress_queue.put(('debug', worker_id, f'parsing temp file: {temp_path} (timeout={PARSE_TIMEOUT}s)'))
                    fuzzer = InlineTypeFuzz(Path(temp_path))
                    try:
                        with mutation_timeout(PARSE_TIMEOUT):
                            parse_ok = fuzzer.parse()
                    except MutationTimeout:
                        progress_queue.put(('parse_timeout', worker_id, seed_name, f'chain content parse timeout{chain_str}', len(group_recipes), len(start_content)))
                        return 0, len(group_recipes), 0
                    if not parse_ok:
                        progress_queue.put(('skip', worker_id, seed_name, f'chain content parse failed{chain_str}', len(group_recipes)))
                        return 0, len(group_recipes), 0
                    progress_queue.put(('debug', worker_id, f'temp file parse SUCCESS'))
                finally:
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
            else:
                progress_queue.put(('debug', worker_id, f'from_string SUCCESS'))
        except Exception as e:
            progress_queue.put(('skip', worker_id, seed_name, f'chain fuzzer init failed: {e}', len(group_recipes)))
            return 0, len(group_recipes), 0
    else:
        # No chain - parse original file
        progress_queue.put(('debug', worker_id, f'creating fuzzer from original file'))
        fuzzer = InlineTypeFuzz(Path(seed_path))
        progress_queue.put(('debug', worker_id, f'parsing original file (timeout={PARSE_TIMEOUT}s)'))
        try:
            with mutation_timeout(PARSE_TIMEOUT):
                parse_ok = fuzzer.parse()
        except MutationTimeout:
            progress_queue.put(('parse_timeout', worker_id, seed_name, 'original file parse timeout', len(group_recipes), 0))
            return 0, len(group_recipes), 0
        if not parse_ok:
            progress_queue.put(('skip', worker_id, seed_name, 'parse failed', len(group_recipes)))
            return 0, len(group_recipes), 0
        progress_queue.put(('debug', worker_id, f'original file parse SUCCESS'))
    
    progress_queue.put(('debug', worker_id, f'fuzzer ready, starting recipe processing'))
    
    # Process iterations sequentially
    current_iteration = 0
    last_progress_time = time.time()
    recipes_since_progress = 0
    
    mutation_timeout_hit = False
    
    for recipe in group_recipes:
        if mutation_timeout_hit:
            break  # Skip remaining recipes for this seed
            
        target_iteration = recipe.get('iteration', 0)
        
        # Generate mutations up to target (reusing RNG state!) with timeout protection
        try:
            with mutation_timeout(MUTATION_TIMEOUT):
                while current_iteration < target_iteration:
                    current_iteration += 1
                    mutant, success = fuzzer.mutate()
                    mutations += 1
        except MutationTimeout:
            progress_queue.put(('mutation_timeout', worker_id, seed_name, current_iteration, len(group_recipes)))
            mutation_timeout_hit = True
            continue
            
        if current_iteration == target_iteration:
            if success and mutant:
                # Validate content hash if available (determinism check)
                expected_hash = recipe.get('hash')
                if expected_hash:
                    actual_hash = compute_content_hash(mutant)
                    if actual_hash != expected_hash:
                        progress_queue.put(('hash_mismatch', worker_id, seed_name, 
                                          current_iteration, expected_hash, actual_hash))
                        # Continue anyway but log the mismatch
                
                # Run solver
                mutant_path = None
                try:
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                        f.write(mutant)
                        mutant_path = f.name
                    
                    # Z3 command line format
                    solver_cmd = [solver_path] + base_flags + [mutant_path]
                    result = subprocess.run(
                        solver_cmd,
                        capture_output=True,
                        timeout=timeout,
                        cwd=build_dir,
                        env=gcov_env
                    )
                    successful += 1
                    recipes_since_progress += 1
                    
                    # Log progress every 60 seconds or every 50 mutations
                    now = time.time()
                    if now - last_progress_time > 60 or recipes_since_progress >= 50:
                        progress_queue.put(('progress', worker_id, seed_name, successful, len(group_recipes)))
                        last_progress_time = now
                        recipes_since_progress = 0
                    
                except subprocess.TimeoutExpired:
                    successful += 1  # Still counts as processed
                    remaining = len(group_recipes) - successful
                    progress_queue.put(('timeout', worker_id, seed_name, current_iteration, remaining, len(group_recipes)))
                except FileNotFoundError as e:
                    if mutations == 1:  # Only log once per seed
                        progress_queue.put(('error', worker_id, seed_name, f'Solver not found: {solver_path}'))
                    failed += 1
                except Exception as e:
                    if mutations == 1:  # Only log once per seed
                        progress_queue.put(('error', worker_id, seed_name, str(e)))
                    failed += 1
                finally:
                    if mutant_path and os.path.exists(mutant_path):
                        try:
                            os.unlink(mutant_path)
                        except:
                            pass
            else:
                failed += 1
    
    # Get iteration range for reporting
    iterations = [r.get('iteration', 0) for r in group_recipes]
    min_iter = min(iterations) if iterations else 0
    max_iter = max(iterations) if iterations else 0
    
    progress_queue.put(('done', worker_id, seed_name, len(group_recipes), successful, min_iter, max_iter))
    return successful, failed, mutations


def worker_process(
    worker_id: int,
    task_queue: multiprocessing.Queue,
    solver_path: str,
    build_dir: str,
    timeout: int,
    progress_queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    z3_memory_mb: int = 4096
):
    """Worker that pulls seed groups from queue for dynamic load balancing."""
    total_successful = 0
    total_failed = 0
    total_mutations = 0
    seeds_done = 0
    worker_start = time.time()
    
    # Send worker start message
    progress_queue.put(('worker_start', worker_id, 0, os.getpid()))
    
    while True:
        try:
            task = task_queue.get(timeout=1)
        except:
            # Check if queue is empty and all work is done
            if task_queue.empty():
                break
            continue
        
        if task is None:  # Poison pill
            break
        
        (seed_path, rng_seed, chain), group_recipes = task
        seed_name = Path(seed_path).name
        seed_start = time.time()
        
        # Send seed start message
        progress_queue.put(('seed_start', worker_id, seed_name, seeds_done + 1, 0, len(group_recipes)))
        
        try:
            successful, failed, mutations = process_seed_group(
                seed_path, rng_seed, chain, group_recipes,
                solver_path, build_dir, timeout,
                worker_id, progress_queue, z3_memory_mb
            )
            total_successful += successful
            total_failed += failed
            total_mutations += mutations
            seeds_done += 1
            
            seed_elapsed = time.time() - seed_start
            progress_queue.put(('seed_complete', worker_id, seed_name, seeds_done, 0, seed_elapsed))
            
        except Exception as e:
            # Catch any unexpected exceptions in seed processing
            seed_elapsed = time.time() - seed_start
            progress_queue.put(('seed_error', worker_id, seed_name, str(e), seed_elapsed))
            seeds_done += 1
    
    worker_elapsed = time.time() - worker_start
    
    # Send worker complete message before putting result
    progress_queue.put(('worker_complete', worker_id, seeds_done, seeds_done, worker_elapsed))
    
    result_queue.put({
        'worker_id': worker_id,
        'successful_runs': total_successful,
        'failed_runs': total_failed,
        'mutations_generated': total_mutations,
        'seeds_processed': seeds_done
    })


# =============================================================================
# TWO-PHASE REPLAY: Generate tests first, then execute in parallel
# =============================================================================

def generation_worker(
    worker_id: int,
    task_queue: multiprocessing.Queue,
    output_queue: multiprocessing.Queue,
    progress_queue: multiprocessing.Queue,
    output_dir: str
):
    """
    Phase 1 worker: Generate test files from seed groups.
    Uses chain prefix caching to avoid redundant chain regeneration.
    """
    tests_generated = 0
    tests_failed = 0
    
    # Cache for chain prefix content: (seed_path, rng_seed, chain_prefix) -> content
    chain_cache: Dict[Tuple[str, int, Tuple[int, ...]], str] = {}
    
    progress_queue.put(('gen_worker_start', worker_id, os.getpid()))
    
    while True:
        try:
            task = task_queue.get(timeout=1)
        except queue.Empty:
            continue
        
        if task is None:
            break
        
        seed_path, rng_seed, chain, group_recipes = task
        seed_name = Path(seed_path).name
        chain_str = f" chain={list(chain)}" if chain else ""
        
        progress_queue.put(('gen_start', worker_id, seed_name, len(group_recipes)))
        
        if not os.path.exists(seed_path):
            progress_queue.put(('gen_skip', worker_id, seed_name, 'seed not found'))
            tests_failed += len(group_recipes)
            continue
        
        if chain:
            start_content = regenerate_chain_content(seed_path, rng_seed, chain, worker_id, chain_cache)
            if start_content is None:
                progress_queue.put(('gen_skip', worker_id, seed_name, f'chain regeneration failed{chain_str}'))
                tests_failed += len(group_recipes)
                continue
        else:
            try:
                with open(seed_path, 'r') as f:
                    start_content = f.read()
            except Exception as e:
                progress_queue.put(('gen_skip', worker_id, seed_name, f'read failed: {e}'))
                tests_failed += len(group_recipes)
                continue
        
        random.seed(rng_seed)
        
        try:
            fuzzer = InlineTypeFuzz.from_string(start_content) if hasattr(InlineTypeFuzz, 'from_string') else None
            if fuzzer is None:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                    f.write(start_content)
                    temp_path = f.name
                try:
                    fuzzer = InlineTypeFuzz(Path(temp_path))
                    with mutation_timeout(PARSE_TIMEOUT):
                        if not fuzzer.parse():
                            progress_queue.put(('gen_skip', worker_id, seed_name, 'parse failed'))
                            tests_failed += len(group_recipes)
                            continue
                except MutationTimeout:
                    progress_queue.put(('gen_skip', worker_id, seed_name, f'parse timeout ({PARSE_TIMEOUT}s)'))
                    tests_failed += len(group_recipes)
                    continue
                finally:
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
        except Exception as e:
            progress_queue.put(('gen_skip', worker_id, seed_name, f'fuzzer init failed: {e}'))
            tests_failed += len(group_recipes)
            continue
        
        current_iteration = 0
        mutation_timeout_hit = False
        
        for recipe in sorted(group_recipes, key=lambda r: r.get('iteration', 0)):
            if mutation_timeout_hit:
                tests_failed += 1
                continue
            
            target_iteration = recipe.get('iteration', 0)
            
            try:
                with mutation_timeout(MUTATION_TIMEOUT):
                    while current_iteration < target_iteration:
                        current_iteration += 1
                        mutant, success = fuzzer.mutate()
            except MutationTimeout:
                progress_queue.put(('gen_mutation_timeout', worker_id, seed_name, current_iteration))
                mutation_timeout_hit = True
                tests_failed += 1
                continue
            
            if current_iteration == target_iteration and success and mutant:
                # Validate content hash if available (determinism check)
                expected_hash = recipe.get('hash')
                if expected_hash:
                    actual_hash = compute_content_hash(mutant)
                    if actual_hash != expected_hash:
                        progress_queue.put(('hash_mismatch', worker_id, seed_name, 
                                          current_iteration, expected_hash, actual_hash))
                        # Continue anyway but log the mismatch
                
                test_id = f"{worker_id}_{tests_generated}"
                test_path = os.path.join(output_dir, f"test_{test_id}.smt2")
                try:
                    with open(test_path, 'w') as f:
                        f.write(mutant)
                    
                    output_queue.put({
                        'test_path': test_path,
                        'seed_path': seed_path,
                        'recipe': recipe
                    })
                    tests_generated += 1
                except Exception as e:
                    progress_queue.put(('gen_write_error', worker_id, seed_name, str(e)))
                    tests_failed += 1
            else:
                tests_failed += 1
        
        progress_queue.put(('gen_done', worker_id, seed_name, len(group_recipes)))
    
    progress_queue.put(('gen_worker_done', worker_id, tests_generated, tests_failed))


def execution_worker(
    worker_id: int,
    test_queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    progress_queue: multiprocessing.Queue,
    solver_path: str,
    timeout: int,
    z3_memory_mb: int
):
    """
    Phase 2 worker: Execute solver on generated test files.
    """
    tests_run = 0
    tests_success = 0
    tests_failed = 0
    
    progress_queue.put(('exec_worker_start', worker_id, os.getpid()))
    
    while True:
        try:
            test = test_queue.get(timeout=1)
        except queue.Empty:
            continue
        
        if test is None:
            break
        
        test_path = test['test_path']
        
        # Z3 command with memory limit
        cmd = [solver_path, f"-memory:{z3_memory_mb}", test_path]
        test_name = os.path.basename(test_path)
        
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True
            )
            tests_success += 1
            elapsed = time.time() - start_time
            progress_queue.put(('exec_test', worker_id, test_name, elapsed, 'ok'))
        except subprocess.TimeoutExpired:
            tests_failed += 1
            progress_queue.put(('exec_test', worker_id, test_name, timeout, 'TIMEOUT'))
        except Exception as e:
            tests_failed += 1
            progress_queue.put(('exec_test', worker_id, test_name, 0, f'ERROR: {e}'))
        
        tests_run += 1
        
        try:
            os.unlink(test_path)
        except:
            pass
    
    result_queue.put({
        'worker_id': worker_id,
        'tests_run': tests_run,
        'tests_success': tests_success,
        'tests_failed': tests_failed
    })
    progress_queue.put(('exec_worker_done', worker_id, tests_run, tests_success, tests_failed))


def replay_recipes_two_phase(
    recipe_file: str,
    solver_path: str,
    build_dir: str,
    changed_functions_file: str,
    output_file: str,
    gcov_cmd: str = "gcov",
    timeout: int = 60,
    num_workers: int = 4,
    seeds_file: Optional[str] = None,
    z3_memory_mb: int = 4096
) -> dict:
    """
    Two-phase recipe replay for Z3.
    """
    log("=" * 60)
    log(f"RECIPE REPLAY (TWO-PHASE)")
    log("=" * 60)
    
    solver_path = os.path.abspath(solver_path)
    build_dir = os.path.abspath(build_dir)
    log(f"Solver: {solver_path}")
    log(f"Build dir: {build_dir}")
    
    if not YINYANG_AVAILABLE:
        log("ERROR: yinyang not available for mutation regeneration")
        return {"error": "yinyang not available"}
    
    allowed_seed_keys: Optional[Set[Tuple[str, int, Tuple[int, ...]]]] = None
    if seeds_file:
        log(f"Loading seed filter from: {seeds_file}")
        with open(seeds_file, 'r') as f:
            seeds_data = json.load(f)
        
        if isinstance(seeds_data, dict) and 'seed_keys' in seeds_data:
            allowed_seed_keys = set()
            for sk in seeds_data['seed_keys']:
                chain = tuple(sk.get('chain', []))
                allowed_seed_keys.add((sk['seed_path'], sk['rng_seed'], chain))
            log(f"Filtering to {len(allowed_seed_keys)} seed groups")
    
    log(f"Loading recipes from: {recipe_file}")
    reader = RecipeReader(recipe_file)
    all_recipes = reader.recipes
    log(f"Total recipes in file: {len(all_recipes)}")
    
    if allowed_seed_keys is not None:
        def recipe_to_key(r):
            return (r.get('seed_path'), r.get('rng_seed', 42), tuple(r.get('chain', [])))
        recipes = [r for r in all_recipes if recipe_to_key(r) in allowed_seed_keys]
        log(f"After seed filter: {len(recipes)} recipes")
    else:
        recipes = all_recipes
    
    if len(recipes) == 0:
        log("WARNING: No recipes to process!")
        results = {
            "recipe_file": recipe_file,
            "recipes_processed": 0,
            "successful_runs": 0,
            "failed_runs": 0,
            "function_counts": {},
            "total_function_calls": 0,
        }
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        return results
    
    log(f"Loading changed functions from: {changed_functions_file}")
    changed_functions = load_changed_functions(changed_functions_file)
    log(f"Tracking {len(changed_functions)} changed functions")
    
    log("Grouping recipes by seed...")
    seed_groups = group_recipes_by_seed(recipes)
    seed_groups_list = list(seed_groups.items())
    total_seeds = len(seed_groups_list)
    total_recipes = sum(len(g) for _, g in seed_groups_list)
    log(f"Found {total_seeds} unique seed groups, {total_recipes} total recipes")
    
    test_output_dir = tempfile.mkdtemp(prefix='replay_tests_')
    log(f"Test output directory: {test_output_dir}")
    
    log("Resetting gcda files...")
    reset_gcda_files(build_dir)
    
    start_time = time.time()
    
    # Phase 1: Generate
    log("")
    log("=" * 60)
    log("PHASE 1: Generating test files")
    log("=" * 60)
    
    task_queue = multiprocessing.Queue()
    test_queue = multiprocessing.Queue()
    progress_queue = multiprocessing.Queue()
    
    # Sort tasks by (seed_path, rng_seed, chain_length) so shorter chains are processed first
    # This maximizes cache hits for chain prefixes
    sorted_tasks = sorted(seed_groups_list, key=lambda x: (x[0][0], x[0][1], len(x[0][2])))
    log(f"Sorted {len(sorted_tasks)} tasks by chain length for optimal caching")
    
    for (seed_path, rng_seed, chain), group_recipes in sorted_tasks:
        task_queue.put((seed_path, rng_seed, chain, group_recipes))
    
    for _ in range(num_workers):
        task_queue.put(None)
    
    gen_processes = []
    for i in range(num_workers):
        p = multiprocessing.Process(
            target=generation_worker,
            args=(i, task_queue, test_queue, progress_queue, test_output_dir)
        )
        p.start()
        gen_processes.append(p)
    
    log(f"Started {num_workers} generation workers")
    
    # Monitor generation progress - track completion by messages, not just process state
    gen_done = 0
    workers_done = set()
    
    # Keep processing until all workers have reported done
    while len(workers_done) < num_workers:
        try:
            # Use timeout to avoid blocking forever
            msg = progress_queue.get(timeout=1.0)
            if msg[0] == 'gen_worker_start':
                _, wid, pid = msg
                log(f"[G{wid}] Worker started (pid={pid})")
            elif msg[0] == 'gen_start':
                _, wid, seed_name, num_recipes = msg
                log(f"[G{wid}] Generating: {seed_name} ({num_recipes} recipes)")
            elif msg[0] == 'gen_done':
                _, wid, seed_name, num_recipes = msg
                gen_done += 1
                log(f"[G{wid}] Done: {seed_name} [{gen_done}/{total_seeds}]")
            elif msg[0] == 'gen_skip':
                _, wid, seed_name, reason = msg
                gen_done += 1
                log(f"[G{wid}] Skip: {seed_name} - {reason} [{gen_done}/{total_seeds}]")
            elif msg[0] == 'gen_mutation_timeout':
                _, wid, seed_name, iteration = msg
                log(f"[G{wid}] Mutation timeout: {seed_name} at iter {iteration}")
            elif msg[0] == 'hash_mismatch':
                _, wid, seed_name, iteration, expected, actual = msg
                log(f"[G{wid}] ⚠️ HASH MISMATCH {seed_name} iter {iteration}: expected={expected} actual={actual}")
            elif msg[0] == 'gen_worker_done':
                _, wid, generated, failed = msg
                workers_done.add(wid)
                log(f"[G{wid}] Worker done: {generated} generated, {failed} failed ({len(workers_done)}/{num_workers} workers complete)")
            elif msg[0].startswith('gen_'):
                log(f"[GEN] {msg}")
        except queue.Empty:
            # Log status periodically when waiting
            alive_workers = [i for i, p in enumerate(gen_processes) if p.is_alive()]
            if alive_workers:
                log(f"[STATUS] Waiting for workers {alive_workers}, {len(workers_done)}/{num_workers} reported done")
    
    log(f"All {num_workers} workers reported done, cleaning up...")
    
    # Wait for processes to actually exit (with timeout)
    for i, p in enumerate(gen_processes):
        p.join(timeout=5.0)
        if p.is_alive():
            log(f"[WARNING] Worker {i} still alive after join, terminating")
            p.terminate()
            p.join(timeout=2.0)
    
    tests_generated = test_queue.qsize()
    phase1_time = time.time() - start_time
    log(f"\nPhase 1 complete: {tests_generated} tests generated in {phase1_time:.1f}s")
    
    if tests_generated == 0:
        log("WARNING: No tests generated!")
        try:
            import shutil
            shutil.rmtree(test_output_dir)
        except:
            pass
        
        results = {
            "recipe_file": recipe_file,
            "recipes_processed": 0,
            "successful_runs": 0,
            "failed_runs": total_recipes,
            "function_counts": {},
            "total_function_calls": 0,
        }
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        return results
    
    # Phase 2: Execute
    log("")
    log("=" * 60)
    log("PHASE 2: Executing solver on test files")
    log("=" * 60)
    
    for _ in range(num_workers):
        test_queue.put(None)
    
    result_queue = multiprocessing.Queue()
    
    exec_processes = []
    for i in range(num_workers):
        p = multiprocessing.Process(
            target=execution_worker,
            args=(i, test_queue, result_queue, progress_queue, solver_path, timeout, z3_memory_mb)
        )
        p.start()
        exec_processes.append(p)
    
    log(f"Started {num_workers} execution workers")
    
    while any(p.is_alive() for p in exec_processes):
        try:
            while True:
                msg = progress_queue.get_nowait()
                if msg[0] == 'exec_worker_start':
                    _, wid, pid = msg
                    log(f"[E{wid}] Worker started (pid={pid})")
                elif msg[0] == 'exec_test':
                    _, wid, test_name, elapsed, status = msg
                    log(f"[E{wid}] {test_name}: {status} ({elapsed:.1f}s)")
                elif msg[0] == 'exec_worker_done':
                    _, wid, tests_run, tests_success, tests_failed = msg
                    log(f"[E{wid}] Worker done: {tests_run} run, {tests_success} ok, {tests_failed} failed")
        except queue.Empty:
            pass
        time.sleep(0.1)
    
    for p in exec_processes:
        p.join()
    
    total_run = 0
    total_success = 0
    total_failed = 0
    
    try:
        while True:
            result = result_queue.get_nowait()
            total_run += result['tests_run']
            total_success += result['tests_success']
            total_failed += result['tests_failed']
    except queue.Empty:
        pass
    
    phase2_time = time.time() - start_time - phase1_time
    log(f"\nPhase 2 complete: {total_run} tests executed in {phase2_time:.1f}s")
    
    # Extract coverage
    log("")
    log("=" * 60)
    log("Extracting coverage data")
    log("=" * 60)
    
    coverage_data = extract_coverage_fastcov(build_dir, gcov_cmd, changed_functions)
    function_counts = coverage_data.get("function_counts", {})
    total_function_calls = sum(function_counts.values())
    
    log(f"Extracted counts for {len(function_counts)} functions")
    log(f"Total function calls: {total_function_calls}")
    
    try:
        import shutil
        shutil.rmtree(test_output_dir)
        log(f"Cleaned up test directory: {test_output_dir}")
    except Exception as e:
        log(f"WARNING: Failed to clean up test directory: {e}")
    
    total_time = time.time() - start_time
    
    results = {
        "recipe_file": recipe_file,
        "recipes_processed": total_recipes,
        "tests_generated": tests_generated,
        "successful_runs": total_success,
        "failed_runs": total_failed,
        "function_counts": function_counts,
        "total_function_calls": total_function_calls,
        "phase1_time": phase1_time,
        "phase2_time": phase2_time,
        "total_time": total_time
    }
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    log(f"\nResults written to: {output_file}")
    log(f"Total time: {total_time:.1f}s")
    
    return results


# =============================================================================
# Legacy single-phase replay (kept for compatibility)
# =============================================================================

def replay_recipes_optimized(
    recipe_file: str,
    solver_path: str,
    build_dir: str,
    changed_functions_file: str,
    output_file: str,
    gcov_cmd: str = "gcov",
    timeout: int = 60,
    batch_size: int = 100,
    num_workers: int = 4,
    start_idx: int = 0,
    end_idx: Optional[int] = None,
    seeds_file: Optional[str] = None,
    z3_memory_mb: int = 4096
) -> dict:
    """
    Replay recipes with OPTIMIZED batching by seed and PARALLEL workers.
    
    Can filter by:
    - start_idx/end_idx: process a slice of recipes (may split seeds!)
    - seeds_file: process only recipes for specific seeds (keeps seeds intact)
    """
    log("=" * 60)
    log(f"Z3 RECIPE REPLAY (OPTIMIZED + PARALLEL)")
    log("=" * 60)
    
    # Convert paths to absolute to avoid cwd issues
    solver_path = os.path.abspath(solver_path)
    build_dir = os.path.abspath(build_dir)
    log(f"Solver: {solver_path}")
    log(f"Build dir: {build_dir}")
    log(f"GCOV: Using embedded absolute paths (no GCOV_PREFIX)")
    
    if not YINYANG_AVAILABLE:
        log("ERROR: yinyang not available for mutation regeneration")
        return {"error": "yinyang not available"}
    
    # Load allowed seed keys if provided
    # Can be either:
    #   - Dict with seed_keys (new format with chain): {"seed_keys": [{"seed_path": "...", "rng_seed": 42, "chain": [10, 20]}, ...]}
    #   - Dict with seed_keys (old format): {"seed_keys": [{"seed_path": "...", "rng_seed": 42}, ...]}
    #   - List of seed paths (old format): ["path1", "path2"]
    #   - Dict with seeds list (old format): {"seeds": ["path1", "path2"]}
    allowed_seed_keys: Optional[Set[Tuple[str, int, Tuple[int, ...]]]] = None
    allowed_seed_paths: Optional[Set[str]] = None
    
    if seeds_file:
        log(f"Loading seed filter from: {seeds_file}")
        with open(seeds_file, 'r') as f:
            seeds_data = json.load(f)
        
        if isinstance(seeds_data, dict) and 'seed_keys' in seeds_data:
            # New format: list of {seed_path, rng_seed, chain} objects
            allowed_seed_keys = set()
            for sk in seeds_data['seed_keys']:
                chain = tuple(sk.get('chain', []))  # Default to empty chain for backward compat
                allowed_seed_keys.add((sk['seed_path'], sk['rng_seed'], chain))
            log(f"Filtering to {len(allowed_seed_keys)} seed groups (path + rng_seed + chain)")
        elif isinstance(seeds_data, list):
            # Old format: list of seed paths (no rng_seed filtering)
            allowed_seed_paths = set(seeds_data)
            log(f"Filtering to {len(allowed_seed_paths)} seed paths (legacy mode)")
        elif isinstance(seeds_data, dict) and 'seeds' in seeds_data:
            # Old format: dict with seeds list
            allowed_seed_paths = set(seeds_data['seeds'])
            log(f"Filtering to {len(allowed_seed_paths)} seed paths (legacy mode)")
    
    # Load recipes
    log(f"Loading recipes from: {recipe_file}")
    reader = RecipeReader(recipe_file)
    all_recipes = reader.recipes
    log(f"Total recipes in file: {len(all_recipes)}")
    
    # Apply filtering
    if allowed_seed_keys is not None:
        # Filter by (seed_path, rng_seed, chain) tuples - precise filtering with chain
        def recipe_to_key(r):
            return (r.get('seed_path'), r.get('rng_seed', 42), tuple(r.get('chain', [])))
        recipes = [r for r in all_recipes if recipe_to_key(r) in allowed_seed_keys]
        log(f"After seed filter: {len(recipes)} recipes")
    elif allowed_seed_paths is not None:
        recipes = [r for r in all_recipes if r.get('seed_path') in allowed_seed_paths]
        log(f"After seed filter: {len(recipes)} recipes")
    elif end_idx is not None:
        recipes = all_recipes[start_idx:end_idx]
        log(f"Processing slice [{start_idx}:{end_idx}] = {len(recipes)} recipes")
    else:
        recipes = all_recipes[start_idx:]
        log(f"Processing from index {start_idx} = {len(recipes)} recipes")
    
    if len(recipes) == 0:
        log("WARNING: No recipes to process!")
        results = {
            "recipe_file": recipe_file,
            "recipes_processed": 0,
            "successful_runs": 0,
            "failed_runs": 0,
            "function_counts": {},
            "total_function_calls": 0,
        }
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        return results
    
    # Load changed functions
    log(f"Loading changed functions from: {changed_functions_file}")
    changed_functions = load_changed_functions(changed_functions_file)
    log(f"Tracking {len(changed_functions)} changed functions")
    
    # Group recipes by seed for efficient processing
    log("Grouping recipes by seed...")
    seed_groups = group_recipes_by_seed(recipes)
    seed_groups_list = list(seed_groups.items())
    log(f"Found {len(seed_groups_list)} unique seed groups")
    
    # Show sample of groups
    for (seed_path, rng_seed, chain), group_recipes in seed_groups_list[:3]:
        seed_name = Path(seed_path).name
        iterations = [r.get('iteration', 0) for r in group_recipes]
        log(f"  - {seed_name}: {len(group_recipes)} recipes, iterations {min(iterations)}-{max(iterations)}")
    
    # Adjust workers if fewer seed groups
    actual_workers = min(num_workers, len(seed_groups_list))
    log(f"\nUsing {actual_workers} workers for {len(seed_groups_list)} seed groups")
    
    start_time = time.time()
    
    # Reset gcda files
    log("Resetting gcda files...")
    reset_gcda_files(build_dir)
    
    log("")
    log("Starting parallel replay...")
    log("-" * 60)
    
    # Create task queue and add all seed groups
    task_queue = multiprocessing.Queue()
    for seed_group in seed_groups_list:
        task_queue.put(seed_group)
    
    # Add poison pills for workers
    for _ in range(actual_workers):
        task_queue.put(None)
    
    log(f"  {len(seed_groups_list)} seed groups queued for {actual_workers} workers")
    
    # Create queues and start workers
    progress_queue = multiprocessing.Queue()
    result_queue = multiprocessing.Queue()
    
    processes = []
    for i in range(actual_workers):
        p = multiprocessing.Process(
            target=worker_process,
            args=(i, task_queue, solver_path, build_dir, timeout, progress_queue, result_queue, z3_memory_mb)
        )
        p.start()
        processes.append(p)
    
    # Monitor progress (extraction happens once at end)
    seeds_done = 0
    total_seeds = len(seed_groups_list)
    workers_complete = set()  # Track which workers have finished
    last_status_time = time.time()
    STATUS_INTERVAL = 60  # Log status every 60 seconds even if no progress
    
    log("")
    while any(p.is_alive() for p in processes):
        # Process progress messages
        messages_processed = 0
        try:
            while True:
                msg = progress_queue.get_nowait()
                messages_processed += 1
                
                if msg[0] == 'worker_start':
                    _, worker_id, num_seeds, pid = msg
                    log(f"[W{worker_id}] WORKER_START: pid={pid}, {num_seeds} seeds to process")
                elif msg[0] == 'seed_start':
                    _, worker_id, seed_name, seed_idx, total_worker_seeds, num_recipes = msg
                    log(f"[W{worker_id}] SEED_START: {seed_name} ({seed_idx}/{total_worker_seeds}), {num_recipes} recipes")
                elif msg[0] == 'seed_complete':
                    _, worker_id, seed_name, seed_idx, total_worker_seeds, elapsed_sec = msg
                    log(f"[W{worker_id}] SEED_COMPLETE: {seed_name} ({seed_idx}/{total_worker_seeds}) in {elapsed_sec:.1f}s")
                elif msg[0] == 'seed_error':
                    _, worker_id, seed_name, error_msg, elapsed_sec = msg
                    log(f"[W{worker_id}] SEED_ERROR: {seed_name} after {elapsed_sec:.1f}s - {error_msg}")
                elif msg[0] == 'debug':
                    _, worker_id, debug_msg = msg
                    log(f"[W{worker_id}] DEBUG: {debug_msg}")
                elif msg[0] == 'worker_complete':
                    _, worker_id, seeds_processed, total_worker_seeds, elapsed_sec = msg
                    workers_complete.add(worker_id)
                    log(f"[W{worker_id}] WORKER_COMPLETE: {seeds_processed}/{total_worker_seeds} seeds in {elapsed_sec:.1f}s")
                elif msg[0] == 'done':
                    # Format: ('done', worker_id, seed_name, recipe_count, successful, min_iter, max_iter)
                    worker_id = msg[1]
                    seed_name = msg[2]
                    recipe_count = msg[3]
                    successful = msg[4]
                    min_iter = msg[5] if len(msg) > 5 else 0
                    max_iter = msg[6] if len(msg) > 6 else 0
                    seeds_done += 1
                    elapsed = time.time() - start_time
                    rate = seeds_done / elapsed if elapsed > 0 else 0
                    log(f"[W{worker_id}] [{seeds_done}/{total_seeds}] {seed_name}: {recipe_count} recipes (iter {min_iter}-{max_iter}), {successful} ok ({rate:.1f} seeds/s)")
                elif msg[0] == 'skip':
                    _, worker_id, seed_name, reason, recipe_count = msg
                    seeds_done += 1
                    log(f"[W{worker_id}] [{seeds_done}/{total_seeds}] SKIP {seed_name}: {reason}")
                elif msg[0] == 'progress':
                    _, worker_id, seed_name, done, total = msg
                    log(f"[W{worker_id}] ... {seed_name}: {done}/{total} recipes")
                elif msg[0] == 'timeout':
                    _, worker_id, seed_name, iteration, remaining, total = msg
                    log(f"[W{worker_id}] TIMEOUT {seed_name} iter {iteration} ({remaining} remaining of {total})")
                elif msg[0] == 'mutation_timeout':
                    _, worker_id, seed_name, iteration, total = msg
                    log(f"[W{worker_id}] MUTATION_TIMEOUT {seed_name} at iter {iteration} - skipping remaining {total} recipes")
                elif msg[0] == 'parse_timeout':
                    _, worker_id, seed_name, reason, recipe_count, content_len = msg
                    log(f"[W{worker_id}] PARSE_TIMEOUT {seed_name}: {reason} (content={content_len} bytes) - skipping {recipe_count} recipes")
                elif msg[0] == 'hash_mismatch':
                    _, worker_id, seed_name, iteration, expected, actual = msg
                    log(f"[W{worker_id}] ⚠️ HASH MISMATCH {seed_name} iter {iteration}: expected={expected} actual={actual}")
                elif msg[0] == 'error':
                    _, worker_id, seed_name, error_msg = msg
                    log(f"[W{worker_id}] ERROR {seed_name}: {error_msg}")
                else:
                    log(f"[DEBUG] Unknown message type: {msg[0]}, full msg: {msg}")
        except queue.Empty:
            pass  # No more messages, continue loop
        except Exception as e:
            log(f"WARNING: Error processing progress message: {e}")
        
        # Periodic status update even if no messages (to detect hangs)
        now = time.time()
        if now - last_status_time >= STATUS_INTERVAL:
            elapsed = now - start_time
            alive_workers = [i for i, p in enumerate(processes) if p.is_alive()]
            dead_workers = [i for i, p in enumerate(processes) if not p.is_alive()]
            complete_workers = list(workers_complete)
            
            log(f"")
            log(f"[STATUS] Elapsed: {elapsed:.0f}s, Seeds done: {seeds_done}/{total_seeds}")
            log(f"[STATUS] Workers alive: {alive_workers}, dead: {dead_workers}, complete: {complete_workers}")
            for i, p in enumerate(processes):
                status = "ALIVE" if p.is_alive() else "DEAD"
                exit_code = p.exitcode if p.exitcode is not None else "N/A"
                log(f"[STATUS]   Worker {i}: {status}, pid={p.pid}, exitcode={exit_code}")
            log(f"")
            
            last_status_time = now
        
        time.sleep(0.5)
    
    # Final status before draining
    log("")
    log(f"[DEBUG] All workers exited. Final process status:")
    for i, p in enumerate(processes):
        log(f"[DEBUG]   Worker {i}: pid={p.pid}, exitcode={p.exitcode}")
    
    # Drain remaining progress messages after workers exit
    drained_count = 0
    try:
        while True:
            msg = progress_queue.get_nowait()
            drained_count += 1
            if msg[0] == 'done':
                # Format: ('done', worker_id, seed_name, recipe_count, successful, min_iter, max_iter)
                worker_id = msg[1]
                seed_name = msg[2]
                recipe_count = msg[3]
                successful = msg[4]
                seeds_done += 1
                log(f"[W{worker_id}] [{seeds_done}/{total_seeds}] {seed_name}: {recipe_count} recipes, {successful} ok (drain)")
            elif msg[0] == 'skip':
                _, worker_id, seed_name, reason, recipe_count = msg
                seeds_done += 1
                log(f"[W{worker_id}] [{seeds_done}/{total_seeds}] SKIP {seed_name}: {reason} (drain)")
            elif msg[0] == 'worker_complete':
                _, worker_id, seeds_processed, total_worker_seeds, elapsed_sec = msg
                workers_complete.add(worker_id)
                log(f"[W{worker_id}] WORKER_COMPLETE: {seeds_processed}/{total_worker_seeds} seeds in {elapsed_sec:.1f}s (drain)")
            elif msg[0] == 'seed_complete':
                _, worker_id, seed_name, seed_idx, total_worker_seeds, elapsed_sec = msg
                log(f"[W{worker_id}] SEED_COMPLETE: {seed_name} ({seed_idx}/{total_worker_seeds}) in {elapsed_sec:.1f}s (drain)")
            # Log any other messages during drain
            elif msg[0] not in ('progress', 'seed_start'):
                log(f"[DEBUG] Drained message: {msg[0]}")
    except queue.Empty:
        pass
    except Exception as e:
        log(f"WARNING: Error draining progress queue: {e}")
    
    log(f"[DEBUG] Drained {drained_count} messages from progress queue")
    log(f"[DEBUG] Final seeds_done: {seeds_done}/{total_seeds}")
    log(f"[DEBUG] Workers that sent WORKER_COMPLETE: {sorted(workers_complete)}")
    
    # Collect final results from workers with timeout to avoid hanging
    successful_runs = 0
    failed_runs = 0
    total_mutations = 0
    results_collected = 0
    
    log(f"[DEBUG] Joining processes...")
    
    # First, join all processes with a timeout
    for i, p in enumerate(processes):
        log(f"[DEBUG]   Joining worker {i} (pid={p.pid})...")
        p.join(timeout=30)  # Give each process 30s to finish cleanup
        if p.is_alive():
            log(f"WARNING: Worker {i} (pid={p.pid}) still alive after join timeout, terminating")
            p.terminate()
            p.join(timeout=5)
            if p.is_alive():
                log(f"ERROR: Worker {i} (pid={p.pid}) STILL alive after terminate!")
        else:
            log(f"[DEBUG]   Worker {i} joined, exitcode={p.exitcode}")
    
    log(f"[DEBUG] All processes joined. Collecting results from result_queue...")
    
    # Now collect results with timeout (processes should be done)
    for i in range(len(processes)):
        try:
            log(f"[DEBUG]   Getting result {i+1}/{len(processes)}...")
            result = result_queue.get(timeout=5)
            log(f"[DEBUG]   Got result from worker {result.get('worker_id', '?')}: {result}")
            successful_runs += result['successful_runs']
            failed_runs += result['failed_runs']
            total_mutations += result['mutations_generated']
            results_collected += 1
        except Exception as e:
            log(f"WARNING: Failed to get result {i+1}/{len(processes)}: {e}")
    
    if results_collected < len(processes):
        log(f"WARNING: Only collected {results_collected}/{len(processes)} worker results")
    
    # Extract coverage once at the end
    log("")
    log("All workers finished. Extracting coverage (functions, lines, branches)...")
    coverage_data = extract_coverage_fastcov(build_dir, gcov_cmd, changed_functions)
    
    # Initialize function counts with zeros for all tracked functions
    function_counts: Dict[str, int] = {fn: 0 for fn in changed_functions}
    for func, count in coverage_data["function_counts"].items():
        function_counts[func] = function_counts.get(func, 0) + count
    
    line_coverage = coverage_data["line_coverage"]
    branch_coverage = coverage_data["branch_coverage"]
    coverage_summary = coverage_data["summary"]
    
    log(f"Total function calls: {sum(function_counts.values()):,}")
    log(f"Line coverage: {coverage_summary['lines_hit']}/{coverage_summary['lines_total']} lines hit")
    log(f"Branch coverage: {coverage_summary['branches_taken']}/{coverage_summary['branches_total']} branches taken")
    
    elapsed = time.time() - start_time
    
    # Build results
    results = {
        "recipe_file": recipe_file,
        "rng_seed": reader.get_rng_seed(),
        "total_recipes": len(reader),
        "recipes_processed": len(recipes),
        "successful_runs": successful_runs,
        "failed_runs": failed_runs,
        "total_mutations_generated": total_mutations,
        "unique_seeds": len(seed_groups_list),
        "num_workers": actual_workers,
        # Function coverage
        "function_counts": function_counts,
        "total_function_calls": sum(function_counts.values()),
        "changed_functions_tracked": len(changed_functions),
        # Line coverage
        "line_coverage": line_coverage,
        "lines_hit": coverage_summary["lines_hit"],
        "lines_total": coverage_summary["lines_total"],
        # Branch coverage
        "branch_coverage": branch_coverage,
        "branches_taken": coverage_summary["branches_taken"],
        "branches_total": coverage_summary["branches_total"],
        # Timing
        "elapsed_seconds": elapsed,
        "recipes_per_second": len(recipes) / elapsed if elapsed > 0 else 0
    }
    
    # Save results
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    log("")
    log("=" * 60)
    log("RESULTS")
    log("=" * 60)
    log(f"Recipes processed: {results['recipes_processed']}")
    log(f"Successful runs: {results['successful_runs']}")
    log(f"Failed runs: {results['failed_runs']}")
    log(f"Total mutations generated: {results['total_mutations_generated']}")
    log(f"Unique seeds: {results['unique_seeds']}")
    log(f"Workers used: {results['num_workers']}")
    log(f"")
    log(f"COVERAGE METRICS:")
    log(f"  Function calls: {results['total_function_calls']:,}")
    lines_pct = 100.0 * results['lines_hit'] / results['lines_total'] if results['lines_total'] > 0 else 0
    log(f"  Lines hit: {results['lines_hit']:,}/{results['lines_total']:,} ({lines_pct:.1f}%)")
    branches_pct = 100.0 * results['branches_taken'] / results['branches_total'] if results['branches_total'] > 0 else 0
    log(f"  Branches taken: {results['branches_taken']:,}/{results['branches_total']:,} ({branches_pct:.1f}%)")
    log(f"")
    log(f"Time: {elapsed:.1f}s ({results['recipes_per_second']:.1f} recipes/sec)")
    log(f"\nTop 10 functions by call count:")
    sorted_funcs = sorted(function_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    for func, count in sorted_funcs:
        log(f"  {count:>12,}  {func}")
    log(f"\nResults saved to: {output_file}")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Z3 Recipe Replay - Measure function calls using gcov"
    )
    parser.add_argument("recipe_file", help="Recipe JSONL file to replay")
    parser.add_argument("--solver", required=True, help="Path to gcov-instrumented Z3 binary")
    parser.add_argument("--build-dir", required=True, help="Build directory with .gcno files")
    parser.add_argument("--changed-functions", required=True, help="Path to changed_functions.json")
    parser.add_argument("--output", required=True, help="Output JSON file for results")
    parser.add_argument("--gcov", default="gcov", help="gcov command (e.g., gcov-14)")
    parser.add_argument("--timeout", type=int, default=120, help="Per-mutation timeout (seconds)")
    parser.add_argument("--batch-size", type=int, default=100, help="Mutations per gcov extraction batch")
    parser.add_argument("--num-workers", type=int, default=4, help="Number of parallel workers")
    parser.add_argument("--start-idx", type=int, default=0, help="Start index for recipe slice (legacy)")
    parser.add_argument("--end-idx", type=int, help="End index for recipe slice (legacy)")
    parser.add_argument("--seeds-file", help="JSON file with list of seed paths to process (recommended)")
    parser.add_argument("--z3-memory-mb", type=int, default=4096, help="Z3 memory limit in MB")
    parser.add_argument("--legacy", action="store_true", help="Use legacy single-phase replay")
    
    args = parser.parse_args()
    
    if args.legacy:
        replay_recipes_optimized(
            recipe_file=args.recipe_file,
            solver_path=args.solver,
            build_dir=args.build_dir,
            changed_functions_file=args.changed_functions,
            output_file=args.output,
            gcov_cmd=args.gcov,
            timeout=args.timeout,
            batch_size=args.batch_size,
            num_workers=args.num_workers,
            start_idx=args.start_idx,
            end_idx=args.end_idx,
            seeds_file=args.seeds_file,
            z3_memory_mb=args.z3_memory_mb
        )
    else:
        replay_recipes_two_phase(
            recipe_file=args.recipe_file,
            solver_path=args.solver,
            build_dir=args.build_dir,
            changed_functions_file=args.changed_functions,
            output_file=args.output,
            gcov_cmd=args.gcov,
            timeout=args.timeout,
            num_workers=args.num_workers,
            seeds_file=args.seeds_file,
            z3_memory_mb=args.z3_memory_mb
        )


if __name__ == "__main__":
    main()
