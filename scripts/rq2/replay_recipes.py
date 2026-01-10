#!/usr/bin/env python3
"""
Recipe Replay - Regenerates mutations from recipes and measures function calls using gcov.

This script:
1. Reads recipe JSONL files from fuzzing phase
2. Regenerates each mutation deterministically (using seed_path + iteration + rng_seed)
3. Runs mutations on gcov-instrumented binary
4. Extracts function call counts for ALL changed functions

Parallel support:
- Can run multiple replay workers in parallel (--num-workers)
- Each worker processes a chunk of recipes
- Results are merged at the end
- Proper cleanup after each mutation to avoid filling disk

Used by measurement workflows for:
- Baseline
- Variant1
- Variant2
"""

import argparse
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Import from shared modules
from recipe_recorder import RecipeReader
from inline_typefuzz import regenerate_mutation, YINYANG_AVAILABLE


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
        print(f"Error loading changed functions: {e}")
        return set()


def replay_single_recipe(
    recipe: dict,
    solver_path: str,
    build_dir: str,
    timeout: int
) -> Tuple[Optional[str], bool]:
    """
    Replay a single recipe: regenerate mutation, run solver, cleanup.
    
    Returns:
        (mutant_content, success)
    """
    mutant = regenerate_mutation(
        recipe['seed_path'],
        recipe['iteration'],
        recipe['rng_seed']
    )
    
    if not mutant:
        return None, False
    
    # Create temp file, run, cleanup immediately
    mutant_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
            f.write(mutant)
            mutant_path = f.name
        
        subprocess.run(
            [solver_path, mutant_path],
            capture_output=True,
            timeout=timeout,
            cwd=build_dir
        )
        return mutant, True
        
    except subprocess.TimeoutExpired:
        return mutant, True  # Still count it, just timed out
    except Exception:
        return None, False
    finally:
        # ALWAYS cleanup temp file
        if mutant_path and os.path.exists(mutant_path):
            try:
                os.unlink(mutant_path)
            except:
                pass


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
        print(f"Error extracting function counts: {e}")
    finally:
        if fastcov_output and os.path.exists(fastcov_output):
            try:
                os.unlink(fastcov_output)
            except:
                pass
    
    return counts


def reset_gcda_files(build_dir: str):
    """Remove existing .gcda files to start fresh."""
    for gcda in Path(build_dir).rglob("*.gcda"):
        try:
            gcda.unlink()
        except:
            pass


def replay_worker(
    worker_id: int,
    recipes: List[dict],
    solver_path: str,
    build_dir: str,
    changed_functions: Set[str],
    gcov_cmd: str,
    timeout: int,
    batch_size: int,
    result_queue: multiprocessing.Queue
):
    """
    Worker function for parallel replay.
    Processes a chunk of recipes and returns function counts.
    """
    function_counts: Dict[str, int] = {fn: 0 for fn in changed_functions}
    successful_runs = 0
    failed_runs = 0
    
    # Reset gcda files at start
    reset_gcda_files(build_dir)
    
    for i, recipe in enumerate(recipes):
        # Run single recipe with cleanup
        mutant_path = None
        try:
            mutant = regenerate_mutation(
                recipe['seed_path'],
                recipe['iteration'],
                recipe['rng_seed']
            )
            
            if not mutant:
                failed_runs += 1
                continue
            
            # Create temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                f.write(mutant)
                mutant_path = f.name
            
            # Run solver
            subprocess.run(
                [solver_path, mutant_path],
                capture_output=True,
                timeout=timeout,
                cwd=build_dir
            )
            successful_runs += 1
            
        except subprocess.TimeoutExpired:
            successful_runs += 1  # Still ran
        except Exception:
            failed_runs += 1
        finally:
            # ALWAYS cleanup temp file immediately
            if mutant_path and os.path.exists(mutant_path):
                try:
                    os.unlink(mutant_path)
                except:
                    pass
        
        # Extract counts every batch_size mutations
        if (i + 1) % batch_size == 0:
            counts = extract_function_counts_fastcov(build_dir, gcov_cmd, changed_functions)
            for func, count in counts.items():
                function_counts[func] = function_counts.get(func, 0) + count
            reset_gcda_files(build_dir)
            
            print(f"  [Worker {worker_id}] Processed {i+1}/{len(recipes)}")
    
    # Final extraction
    counts = extract_function_counts_fastcov(build_dir, gcov_cmd, changed_functions)
    for func, count in counts.items():
        function_counts[func] = function_counts.get(func, 0) + count
    
    # Send results back
    result_queue.put({
        'worker_id': worker_id,
        'function_counts': function_counts,
        'successful_runs': successful_runs,
        'failed_runs': failed_runs,
        'recipes_processed': len(recipes)
    })


def replay_recipes(
    recipe_file: str,
    solver_path: str,
    build_dir: str,
    changed_functions_file: str,
    output_file: str,
    gcov_cmd: str = "gcov",
    timeout: int = 60,
    max_recipes: Optional[int] = None,
    num_workers: int = 1,
    batch_size: int = 100,
    start_idx: int = 0,
    end_idx: Optional[int] = None
) -> dict:
    """
    Replay recipes and measure function calls.
    Supports parallel execution with proper cleanup.
    
    Args:
        start_idx: Start index for slicing recipes (for parallel job distribution)
        end_idx: End index for slicing recipes (None = all remaining)
    """
    if not YINYANG_AVAILABLE:
        print("Error: yinyang not available for mutation regeneration")
        return {}
    
    print(f"\n{'='*60}")
    print(f"Replaying: {recipe_file}")
    print(f"Workers: {num_workers}")
    print(f"{'='*60}")
    
    # Load recipes
    reader = RecipeReader(recipe_file)
    all_recipes = reader.recipes
    
    # Apply slice for parallel job distribution
    if end_idx is not None:
        recipes = all_recipes[start_idx:end_idx]
        print(f"Processing slice [{start_idx}:{end_idx}] of {len(all_recipes)} total recipes")
    else:
        recipes = all_recipes[start_idx:]
    
    if max_recipes:
        recipes = recipes[:max_recipes]
    
    print(f"Processing {len(recipes)} recipes (rng_seed={reader.get_rng_seed()})")
    
    # Load changed functions
    changed_functions = load_changed_functions(changed_functions_file)
    print(f"Tracking {len(changed_functions)} changed functions")
    
    start_time = time.time()
    
    if num_workers == 1:
        # Single-threaded mode
        function_counts: Dict[str, int] = {fn: 0 for fn in changed_functions}
        successful_runs = 0
        failed_runs = 0
        
        reset_gcda_files(build_dir)
        
        for i, recipe in enumerate(recipes):
            mutant_path = None
            try:
                mutant = regenerate_mutation(
                    recipe['seed_path'],
                    recipe['iteration'],
                    recipe['rng_seed']
                )
                
                if not mutant:
                    failed_runs += 1
                    continue
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                    f.write(mutant)
                    mutant_path = f.name
                
                subprocess.run(
                    [solver_path, mutant_path],
                    capture_output=True,
                    timeout=timeout,
                    cwd=build_dir
                )
                successful_runs += 1
                
            except subprocess.TimeoutExpired:
                successful_runs += 1
            except Exception:
                failed_runs += 1
            finally:
                if mutant_path and os.path.exists(mutant_path):
                    try:
                        os.unlink(mutant_path)
                    except:
                        pass
            
            if (i + 1) % batch_size == 0:
                counts = extract_function_counts_fastcov(build_dir, gcov_cmd, changed_functions)
                for func, count in counts.items():
                    function_counts[func] = function_counts.get(func, 0) + count
                reset_gcda_files(build_dir)
                print(f"  Processed {i+1}/{len(recipes)}")
        
        # Final extraction
        counts = extract_function_counts_fastcov(build_dir, gcov_cmd, changed_functions)
        for func, count in counts.items():
            function_counts[func] = function_counts.get(func, 0) + count
        
    else:
        # Parallel mode
        chunk_size = len(recipes) // num_workers
        chunks = []
        for i in range(num_workers):
            start = i * chunk_size
            end = start + chunk_size if i < num_workers - 1 else len(recipes)
            chunks.append(recipes[start:end])
        
        result_queue = multiprocessing.Queue()
        processes = []
        
        for i, chunk in enumerate(chunks):
            p = multiprocessing.Process(
                target=replay_worker,
                args=(i, chunk, solver_path, build_dir, changed_functions, 
                      gcov_cmd, timeout, batch_size, result_queue)
            )
            p.start()
            processes.append(p)
        
        # Collect results
        function_counts: Dict[str, int] = {fn: 0 for fn in changed_functions}
        successful_runs = 0
        failed_runs = 0
        
        for _ in range(num_workers):
            result = result_queue.get()
            for func, count in result['function_counts'].items():
                function_counts[func] = function_counts.get(func, 0) + count
            successful_runs += result['successful_runs']
            failed_runs += result['failed_runs']
        
        for p in processes:
            p.join()
    
    elapsed = time.time() - start_time
    
    # Build results
    results = {
        "recipe_file": recipe_file,
        "rng_seed": reader.get_rng_seed(),
        "total_recipes": len(reader),
        "recipes_processed": len(recipes),
        "successful_runs": successful_runs,
        "failed_runs": failed_runs,
        "function_counts": function_counts,
        "total_function_calls": sum(function_counts.values()),
        "changed_functions_tracked": len(changed_functions),
        "num_workers": num_workers,
        "elapsed_seconds": elapsed,
        "recipes_per_second": len(recipes) / elapsed if elapsed > 0 else 0
    }
    
    # Save results
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"RESULTS")
    print(f"{'='*60}")
    print(f"Recipes processed: {results['recipes_processed']}")
    print(f"Successful runs: {results['successful_runs']}")
    print(f"Failed runs: {results['failed_runs']}")
    print(f"Total function calls: {results['total_function_calls']:,}")
    print(f"Time: {elapsed:.1f}s ({results['recipes_per_second']:.1f} recipes/sec)")
    print(f"\nTop 10 functions by call count:")
    sorted_funcs = sorted(function_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    for func, count in sorted_funcs:
        print(f"  {count:>12,}  {func}")
    print(f"\nResults saved to: {output_file}")
    
    return results


def merge_results(result_files: List[str], output_file: str) -> dict:
    """
    Merge results from multiple parallel runs (e.g., from different workers or runs).
    """
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
        description="Replay mutation recipes and measure function calls using gcov"
    )
    parser.add_argument("recipe_file", help="Recipe JSONL file to replay")
    parser.add_argument("--solver", required=True, help="Path to gcov-instrumented solver binary")
    parser.add_argument("--build-dir", required=True, help="Build directory with .gcno files")
    parser.add_argument("--changed-functions", required=True, help="Path to changed_functions.json")
    parser.add_argument("--output", required=True, help="Output JSON file for results")
    parser.add_argument("--gcov", default="gcov", help="gcov command (e.g., gcov-14)")
    parser.add_argument("--timeout", type=int, default=60, help="Per-mutation timeout (seconds)")
    parser.add_argument("--max-recipes", type=int, help="Maximum recipes to process (for testing)")
    parser.add_argument("--num-workers", type=int, default=1, help="Number of parallel workers")
    parser.add_argument("--batch-size", type=int, default=100, help="Mutations per gcov extraction batch")
    parser.add_argument("--start-idx", type=int, default=0, help="Start index for recipe slice (for parallel jobs)")
    parser.add_argument("--end-idx", type=int, help="End index for recipe slice (for parallel jobs)")
    
    args = parser.parse_args()
    
    replay_recipes(
        recipe_file=args.recipe_file,
        solver_path=args.solver,
        build_dir=args.build_dir,
        changed_functions_file=args.changed_functions,
        output_file=args.output,
        gcov_cmd=args.gcov,
        timeout=args.timeout,
        max_recipes=args.max_recipes,
        num_workers=args.num_workers,
        batch_size=args.batch_size,
        start_idx=args.start_idx,
        end_idx=args.end_idx
    )


if __name__ == "__main__":
    main()
