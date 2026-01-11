#!/usr/bin/env python3
"""
Recipe Replay - Regenerates mutations from recipes and measures function calls using gcov.

OPTIMIZED: Recipes are grouped by (seed_path, rng_seed) and processed sequentially.
- Before: O(N²) - for each recipe, regenerate all previous iterations
- After: O(N) - parse seed once, generate mutations in order, reuse RNG state

PARALLEL: Multiple workers process different seed groups simultaneously.
- Workers share the same build directory (gcda files accumulate)
- Main thread periodically extracts counts and resets gcda files

Used by measurement workflows for: Baseline, Variant1, Variant2
"""

import argparse
import json
import multiprocessing
import os
import random
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Add current directory to path for imports
SCRIPT_DIR = Path(__file__).parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from recipe_recorder import RecipeReader

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


def extract_function_counts_fastcov(
    build_dir: str,
    gcov_cmd: str,
    changed_functions: Set[str]
) -> Dict[str, int]:
    """Extract function call counts from gcov data using fastcov."""
    counts = {}
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
        
        result = subprocess.run(
            [
                "fastcov",
                "--gcov", gcov_cmd,
                "--search-directory", build_dir,
                "--output", fastcov_output,
                "--exclude", "/usr/include/*",
                "--exclude", "*/deps/*",
                "--jobs", "4"
            ],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        log(f"[GCOV DEBUG] fastcov return code: {result.returncode}")
        if result.stderr:
            log(f"[GCOV DEBUG] fastcov stderr: {result.stderr[:500]}")
        
        if result.returncode == 0 and os.path.exists(fastcov_output):
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
                # Show first few items of each key
                for key, value in first_source[1].items():
                    if isinstance(value, dict):
                        sample_items = list(value.items())[:2]
                        log(f"[GCOV DEBUG]   {key}: {len(value)} items, sample: {sample_items}")
                    elif isinstance(value, list):
                        log(f"[GCOV DEBUG]   {key}: {len(value)} items, first: {value[:2] if value else 'empty'}")
                    else:
                        log(f"[GCOV DEBUG]   {key}: {value}")
            
            # Parse changed_functions to extract file:line for matching
            # Format: "src/path/file.cpp:function_name:line_number"
            changed_file_lines = {}  # {(relative_path, line): full_function_key}
            for func_key in changed_functions:
                parts = func_key.rsplit(':', 2)
                if len(parts) >= 2:
                    try:
                        line_num = int(parts[-1])
                        file_path = parts[0].split(':')[0]  # Get file path before function name
                        # Use the relative path (e.g., "src/theory/arith/rewriter/addition.cpp")
                        changed_file_lines[(file_path, line_num)] = func_key
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
                total_funcs_found += len(funcs)
                
                # Extract relative path from /cvc5/ (e.g., "src/theory/arith/...")
                # Full path: /home/runner/.../cvc5/src/theory/arith/rewriter/addition.cpp
                # We want: src/theory/arith/rewriter/addition.cpp
                source_relative = source_file
                if '/cvc5/' in source_file:
                    source_relative = source_file.split('/cvc5/', 1)[1]
                
                # Show first source with functions as sample
                if not sample_shown and funcs:
                    log(f"[GCOV DEBUG] Sample source with funcs: {source_file}")
                    log(f"[GCOV DEBUG]   Relative path: {source_relative}")
                    sample_func = list(funcs.items())[0]
                    log(f"[GCOV DEBUG]   Sample func: {sample_func[0][:60]}")
                    log(f"[GCOV DEBUG]   Sample func_data: {sample_func[1]}")
                    sample_shown = True
                
                # If this is one of our target files, show all its functions and lines
                if source_relative in target_files:
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
                
                for func_name, func_data in funcs.items():
                    exec_count = func_data.get('execution_count', 0)
                    start_line = func_data.get('start_line', 0)
                    
                    if exec_count > 0:
                        all_funcs.append((func_name, exec_count))
                    
                    # Match by relative path + line number
                    match_key = (source_relative, start_line)
                    if match_key in changed_file_lines:
                        full_key = changed_file_lines[match_key]
                        counts[full_key] = counts.get(full_key, 0) + exec_count
                        if exec_count > 0:
                            log(f"[GCOV DEBUG] MATCHED: {source_relative}:{start_line} -> {exec_count} calls")
            
            log(f"[GCOV DEBUG] Total functions found: {total_funcs_found}")
            log(f"[GCOV DEBUG] Found {len(all_funcs)} functions with >0 execution count")
            # Show top 5 by execution count
            if all_funcs:
                top_funcs = sorted(all_funcs, key=lambda x: -x[1])[:5]
                for name, count in top_funcs:
                    log(f"[GCOV DEBUG]   {count:>10}  {name[:80]}")
        else:
            log(f"[GCOV DEBUG] fastcov failed or no output")
        
    except Exception as e:
        log(f"Error extracting function counts: {e}")
    finally:
        if fastcov_output and os.path.exists(fastcov_output):
            try:
                os.unlink(fastcov_output)
            except:
                pass
    
    return counts


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


def group_recipes_by_seed(recipes: List[dict]) -> Dict[Tuple[str, int], List[dict]]:
    """
    Group recipes by (seed_path, rng_seed) and sort each group by iteration.
    """
    groups = defaultdict(list)
    
    for recipe in recipes:
        seed_path = recipe.get('seed_path')
        rng_seed = recipe.get('rng_seed', 42)
        if seed_path:
            key = (seed_path, rng_seed)
            groups[key].append(recipe)
    
    # Sort each group by iteration
    for key in groups:
        groups[key].sort(key=lambda r: r.get('iteration', 0))
    
    return dict(groups)


def process_seed_group(
    seed_path: str,
    rng_seed: int,
    group_recipes: List[dict],
    solver_path: str,
    build_dir: str,
    timeout: int,
    worker_id: int,
    progress_queue: multiprocessing.Queue
) -> Tuple[int, int, int]:
    """
    Process all recipes for a single seed group.
    Returns (successful_runs, failed_runs, mutations_generated).
    """
    successful = 0
    failed = 0
    mutations = 0
    
    seed_name = Path(seed_path).name
    
    # Don't set GCOV_PREFIX - let gcov use embedded absolute paths
    # The binary was compiled with absolute paths, and we're running on the same CI
    # Setting GCOV_PREFIX would cause doubled paths like /build/path/build/path/...
    gcov_env = os.environ.copy()
    
    # Check if seed file exists
    if not os.path.exists(seed_path):
        progress_queue.put(('skip', worker_id, seed_name, 'not found', len(group_recipes)))
        return 0, len(group_recipes), 0
    
    # Initialize RNG and parse seed ONCE
    random.seed(rng_seed)
    fuzzer = InlineTypeFuzz(Path(seed_path))
    
    if not fuzzer.parse():
        progress_queue.put(('skip', worker_id, seed_name, 'parse failed', len(group_recipes)))
        return 0, len(group_recipes), 0
    
    # Process iterations sequentially
    current_iteration = 0
    last_progress_time = time.time()
    recipes_since_progress = 0
    
    for recipe in group_recipes:
        target_iteration = recipe.get('iteration', 0)
        
        # Generate mutations up to target (reusing RNG state!)
        while current_iteration < target_iteration:
            current_iteration += 1
            mutant, success = fuzzer.mutate()
            mutations += 1
            
            if current_iteration == target_iteration:
                if success and mutant:
                    # Run solver
                    mutant_path = None
                    try:
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                            f.write(mutant)
                            mutant_path = f.name
                        
                        result = subprocess.run(
                            [solver_path, mutant_path],
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
                        # Log timeout with remaining count so user knows what's left
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
    seed_groups_chunk: List[Tuple[Tuple[str, int], List[dict]]],
    solver_path: str,
    build_dir: str,
    timeout: int,
    progress_queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue
):
    """Worker that processes a chunk of seed groups."""
    total_successful = 0
    total_failed = 0
    total_mutations = 0
    seeds_done = 0
    
    for (seed_path, rng_seed), group_recipes in seed_groups_chunk:
        successful, failed, mutations = process_seed_group(
            seed_path, rng_seed, group_recipes,
            solver_path, build_dir, timeout,
            worker_id, progress_queue
        )
        total_successful += successful
        total_failed += failed
        total_mutations += mutations
        seeds_done += 1
    
    result_queue.put({
        'worker_id': worker_id,
        'successful_runs': total_successful,
        'failed_runs': total_failed,
        'mutations_generated': total_mutations,
        'seeds_processed': seeds_done
    })


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
    seeds_file: Optional[str] = None
) -> dict:
    """
    Replay recipes with OPTIMIZED batching by seed and PARALLEL workers.
    
    Can filter by:
    - start_idx/end_idx: process a slice of recipes (may split seeds!)
    - seeds_file: process only recipes for specific seeds (keeps seeds intact)
    """
    log("=" * 60)
    log(f"RECIPE REPLAY (OPTIMIZED + PARALLEL)")
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
    #   - Dict with seed_keys (new format): {"seed_keys": [{"seed_path": "...", "rng_seed": 42}, ...]}
    #   - List of seed paths (old format): ["path1", "path2"]
    #   - Dict with seeds list (old format): {"seeds": ["path1", "path2"]}
    allowed_seed_keys: Optional[Set[Tuple[str, int]]] = None
    allowed_seed_paths: Optional[Set[str]] = None
    
    if seeds_file:
        log(f"Loading seed filter from: {seeds_file}")
        with open(seeds_file, 'r') as f:
            seeds_data = json.load(f)
        
        if isinstance(seeds_data, dict) and 'seed_keys' in seeds_data:
            # New format: list of {seed_path, rng_seed} objects
            allowed_seed_keys = set()
            for sk in seeds_data['seed_keys']:
                allowed_seed_keys.add((sk['seed_path'], sk['rng_seed']))
            log(f"Filtering to {len(allowed_seed_keys)} seed groups (path + rng_seed)")
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
        # Filter by (seed_path, rng_seed) tuples - precise filtering
        recipes = [r for r in all_recipes 
                   if (r.get('seed_path'), r.get('rng_seed', 42)) in allowed_seed_keys]
        log(f"After seed filter: {len(recipes)} recipes")
    elif allowed_seed_paths is not None:
        # Legacy: filter by seed_path only
        recipes = [r for r in all_recipes if r.get('seed_path') in allowed_seed_paths]
        log(f"After seed filter: {len(recipes)} recipes")
    elif end_idx is not None:
        # Apply index slice (legacy mode - may split seeds)
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
    for (seed_path, rng_seed), group_recipes in seed_groups_list[:3]:
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
    
    # Split seed groups among workers
    chunk_size = (len(seed_groups_list) + actual_workers - 1) // actual_workers
    chunks = []
    for i in range(actual_workers):
        start = i * chunk_size
        end = min(start + chunk_size, len(seed_groups_list))
        if start < len(seed_groups_list):
            chunks.append(seed_groups_list[start:end])
    
    # Show chunk distribution
    for i, chunk in enumerate(chunks):
        total_recipes = sum(len(recipes) for _, recipes in chunk)
        log(f"  Worker {i}: {len(chunk)} seeds, {total_recipes} recipes")
    
    # Create queues and start workers
    progress_queue = multiprocessing.Queue()
    result_queue = multiprocessing.Queue()
    
    processes = []
    for i, chunk in enumerate(chunks):
        p = multiprocessing.Process(
            target=worker_process,
            args=(i, chunk, solver_path, build_dir, timeout, progress_queue, result_queue)
        )
        p.start()
        processes.append(p)
    
    # Monitor progress (extraction happens once at end)
    seeds_done = 0
    total_seeds = len(seed_groups_list)
    
    log("")
    while any(p.is_alive() for p in processes):
        # Process progress messages
        try:
            while True:
                msg = progress_queue.get_nowait()
                if msg[0] == 'done':
                    _, worker_id, seed_name, recipe_count, successful = msg
                    seeds_done += 1
                    elapsed = time.time() - start_time
                    rate = seeds_done / elapsed if elapsed > 0 else 0
                    min_iter = msg[5] if len(msg) > 5 else 0
                    max_iter = msg[6] if len(msg) > 6 else 0
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
                elif msg[0] == 'error':
                    _, worker_id, seed_name, error_msg = msg
                    log(f"[W{worker_id}] ERROR {seed_name}: {error_msg}")
        except:
            pass
        
        time.sleep(0.5)
    
    # Collect final results from workers
    successful_runs = 0
    failed_runs = 0
    total_mutations = 0
    
    for _ in range(len(processes)):
        result = result_queue.get()
        successful_runs += result['successful_runs']
        failed_runs += result['failed_runs']
        total_mutations += result['mutations_generated']
    
    for p in processes:
        p.join()
    
    # Extract function counts once at the end (all .gcda files have accumulated)
    log("")
    log("All workers finished. Extracting function counts...")
    function_counts: Dict[str, int] = {fn: 0 for fn in changed_functions}
    counts = extract_function_counts_fastcov(build_dir, gcov_cmd, changed_functions)
    for func, count in counts.items():
        function_counts[func] = function_counts.get(func, 0) + count
    log(f"Total function calls: {sum(function_counts.values()):,}")
    
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
        "function_counts": function_counts,
        "total_function_calls": sum(function_counts.values()),
        "changed_functions_tracked": len(changed_functions),
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
    log(f"Total function calls: {results['total_function_calls']:,}")
    log(f"Time: {elapsed:.1f}s ({results['recipes_per_second']:.1f} recipes/sec)")
    log(f"\nTop 10 functions by call count:")
    sorted_funcs = sorted(function_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    for func, count in sorted_funcs:
        log(f"  {count:>12,}  {func}")
    log(f"\nResults saved to: {output_file}")
    
    return results


def merge_results(result_files: List[str], output_file: str) -> dict:
    """Merge results from multiple parallel runs."""
    merged = {
        "merged_from": result_files,
        "recipes_processed": 0,
        "successful_runs": 0,
        "failed_runs": 0,
        "function_counts": {},
        "total_function_calls": 0,
    }
    
    for result_file in result_files:
        with open(result_file, 'r') as f:
            data = json.load(f)
        
        merged["recipes_processed"] += data.get("recipes_processed", 0)
        merged["successful_runs"] += data.get("successful_runs", 0)
        merged["failed_runs"] += data.get("failed_runs", 0)
        
        for func, count in data.get("function_counts", {}).items():
            merged["function_counts"][func] = merged["function_counts"].get(func, 0) + count
    
    merged["total_function_calls"] = sum(merged["function_counts"].values())
    
    with open(output_file, 'w') as f:
        json.dump(merged, f, indent=2)
    
    return merged


def main():
    parser = argparse.ArgumentParser(
        description="Replay mutation recipes and measure function calls using gcov (OPTIMIZED + PARALLEL)"
    )
    parser.add_argument("recipe_file", help="Recipe JSONL file to replay")
    parser.add_argument("--solver", required=True, help="Path to gcov-instrumented solver binary")
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
    
    args = parser.parse_args()
    
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
        seeds_file=args.seeds_file
    )


if __name__ == "__main__":
    main()
