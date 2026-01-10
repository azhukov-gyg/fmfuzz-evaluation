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
        
        if result.returncode == 0 and os.path.exists(fastcov_output):
            with open(fastcov_output, 'r') as f:
                fastcov_data = json.load(f)
            
            for source_file, source_data in fastcov_data.get('sources', {}).items():
                for func_name, func_data in source_data.get('functions', {}).items():
                    if func_name in changed_functions:
                        exec_count = func_data.get('execution_count', 0)
                        counts[func_name] = counts.get(func_name, 0) + exec_count
        
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
                            cwd=build_dir
                        )
                        successful += 1
                        
                    except subprocess.TimeoutExpired:
                        successful += 1  # Still counts as processed
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
    
    progress_queue.put(('done', worker_id, seed_name, len(group_recipes), successful))
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
    end_idx: Optional[int] = None
) -> dict:
    """
    Replay recipes with OPTIMIZED batching by seed and PARALLEL workers.
    """
    log("=" * 60)
    log(f"RECIPE REPLAY (OPTIMIZED + PARALLEL)")
    log("=" * 60)
    
    # Convert paths to absolute to avoid cwd issues
    solver_path = os.path.abspath(solver_path)
    build_dir = os.path.abspath(build_dir)
    log(f"Solver: {solver_path}")
    log(f"Build dir: {build_dir}")
    
    if not YINYANG_AVAILABLE:
        log("ERROR: yinyang not available for mutation regeneration")
        return {"error": "yinyang not available"}
    
    # Load recipes
    log(f"Loading recipes from: {recipe_file}")
    reader = RecipeReader(recipe_file)
    all_recipes = reader.recipes
    log(f"Total recipes in file: {len(all_recipes)}")
    
    # Apply slice for parallel job distribution
    if end_idx is not None:
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
    
    # Monitor progress and periodically extract counts
    function_counts: Dict[str, int] = {fn: 0 for fn in changed_functions}
    seeds_done = 0
    total_seeds = len(seed_groups_list)
    last_extract_time = time.time()
    extract_interval = 30  # Extract every 30 seconds
    
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
                    log(f"[W{worker_id}] [{seeds_done}/{total_seeds}] {seed_name}: {recipe_count} recipes, {successful} ok ({rate:.1f} seeds/s)")
                elif msg[0] == 'skip':
                    _, worker_id, seed_name, reason, recipe_count = msg
                    seeds_done += 1
                    log(f"[W{worker_id}] [{seeds_done}/{total_seeds}] SKIP {seed_name}: {reason}")
                elif msg[0] == 'error':
                    _, worker_id, seed_name, error_msg = msg
                    log(f"[W{worker_id}] ERROR {seed_name}: {error_msg}")
        except:
            pass
        
        # Periodically extract counts
        if time.time() - last_extract_time > extract_interval:
            log(f"  → Extracting function counts...")
            counts = extract_function_counts_fastcov(build_dir, gcov_cmd, changed_functions)
            for func, count in counts.items():
                function_counts[func] = function_counts.get(func, 0) + count
            total_calls = sum(function_counts.values())
            log(f"  → Total function calls so far: {total_calls:,}")
            reset_gcda_files(build_dir)
            last_extract_time = time.time()
        
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
    
    # Final extraction
    log("Final extraction...")
    counts = extract_function_counts_fastcov(build_dir, gcov_cmd, changed_functions)
    for func, count in counts.items():
        function_counts[func] = function_counts.get(func, 0) + count
    
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
    parser.add_argument("--start-idx", type=int, default=0, help="Start index for recipe slice")
    parser.add_argument("--end-idx", type=int, help="End index for recipe slice")
    
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
        end_idx=args.end_idx
    )


if __name__ == "__main__":
    main()
