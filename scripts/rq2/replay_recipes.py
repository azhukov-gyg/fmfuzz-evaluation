#!/usr/bin/env python3
"""
Recipe Replay - Regenerates mutations from recipes and measures function calls using gcov.

OPTIMIZED: Recipes are grouped by (seed_path, rng_seed) and processed sequentially.
- Before: O(N²) - for each recipe, regenerate all previous iterations
- After: O(N) - parse seed once, generate mutations in order, reuse RNG state

This script:
1. Groups recipes by seed_path + rng_seed
2. For each group, sorts by iteration and processes sequentially
3. Runs mutations on gcov-instrumented binary
4. Extracts function call counts for ALL changed functions

Used by measurement workflows for: Baseline, Variant1, Variant2
"""

import argparse
import json
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
    This enables efficient sequential processing.
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


def replay_recipes_optimized(
    recipe_file: str,
    solver_path: str,
    build_dir: str,
    changed_functions_file: str,
    output_file: str,
    gcov_cmd: str = "gcov",
    timeout: int = 60,
    batch_size: int = 100,
    start_idx: int = 0,
    end_idx: Optional[int] = None
) -> dict:
    """
    Replay recipes with OPTIMIZED batching by seed.
    
    Instead of regenerating all previous iterations for each recipe,
    we group by (seed_path, rng_seed), sort by iteration, and process
    sequentially - reusing the parsed seed and RNG state.
    """
    log("=" * 60)
    log(f"RECIPE REPLAY (OPTIMIZED)")
    log("=" * 60)
    
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
    log(f"Found {len(seed_groups)} unique seed groups")
    
    # Show sample of groups
    sample_groups = list(seed_groups.items())[:3]
    for (seed_path, rng_seed), group_recipes in sample_groups:
        seed_name = Path(seed_path).name
        iterations = [r.get('iteration', 0) for r in group_recipes]
        log(f"  - {seed_name}: {len(group_recipes)} recipes, iterations {min(iterations)}-{max(iterations)}")
    
    # Initialize counters
    function_counts: Dict[str, int] = {fn: 0 for fn in changed_functions}
    successful_runs = 0
    failed_runs = 0
    total_mutations_generated = 0
    seeds_processed = 0
    
    start_time = time.time()
    
    # Reset gcda files
    log("Resetting gcda files...")
    reset_gcda_files(build_dir)
    
    log("")
    log("Starting optimized replay...")
    log("-" * 60)
    
    mutations_since_extract = 0
    
    for (seed_path, rng_seed), group_recipes in seed_groups.items():
        seeds_processed += 1
        seed_name = Path(seed_path).name
        
        # Check if seed file exists
        if not os.path.exists(seed_path):
            log(f"[{seeds_processed}/{len(seed_groups)}] SKIP {seed_name}: file not found")
            failed_runs += len(group_recipes)
            continue
        
        # Initialize RNG and parse seed ONCE
        random.seed(rng_seed)
        fuzzer = InlineTypeFuzz(Path(seed_path))
        
        if not fuzzer.parse():
            log(f"[{seeds_processed}/{len(seed_groups)}] SKIP {seed_name}: parse failed")
            failed_runs += len(group_recipes)
            continue
        
        # Process iterations sequentially
        current_iteration = 0
        recipes_done_for_seed = 0
        
        for recipe in group_recipes:
            target_iteration = recipe.get('iteration', 0)
            
            # Generate mutations up to target (reusing RNG state!)
            while current_iteration < target_iteration:
                current_iteration += 1
                mutant, success = fuzzer.mutate()
                total_mutations_generated += 1
                
                if current_iteration == target_iteration:
                    # This is the mutation we want
                    if success and mutant:
                        # Run solver
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
                            successful_runs += 1
                            recipes_done_for_seed += 1
                            
                        except subprocess.TimeoutExpired:
                            successful_runs += 1
                            recipes_done_for_seed += 1
                        except Exception as e:
                            failed_runs += 1
                        finally:
                            if mutant_path and os.path.exists(mutant_path):
                                try:
                                    os.unlink(mutant_path)
                                except:
                                    pass
                    else:
                        failed_runs += 1
                    
                    mutations_since_extract += 1
        
        # Log progress for this seed
        elapsed = time.time() - start_time
        rate = (successful_runs + failed_runs) / elapsed if elapsed > 0 else 0
        log(f"[{seeds_processed}/{len(seed_groups)}] {seed_name}: {recipes_done_for_seed} recipes, "
            f"total={successful_runs + failed_runs}, rate={rate:.1f}/s")
        
        # Extract counts periodically
        if mutations_since_extract >= batch_size:
            log(f"  → Extracting function counts (batch of {mutations_since_extract})...")
            counts = extract_function_counts_fastcov(build_dir, gcov_cmd, changed_functions)
            for func, count in counts.items():
                function_counts[func] = function_counts.get(func, 0) + count
            reset_gcda_files(build_dir)
            mutations_since_extract = 0
    
    # Final extraction
    if mutations_since_extract > 0:
        log(f"Final extraction ({mutations_since_extract} remaining)...")
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
        "total_mutations_generated": total_mutations_generated,
        "unique_seeds": len(seed_groups),
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
        description="Replay mutation recipes and measure function calls using gcov (OPTIMIZED)"
    )
    parser.add_argument("recipe_file", help="Recipe JSONL file to replay")
    parser.add_argument("--solver", required=True, help="Path to gcov-instrumented solver binary")
    parser.add_argument("--build-dir", required=True, help="Build directory with .gcno files")
    parser.add_argument("--changed-functions", required=True, help="Path to changed_functions.json")
    parser.add_argument("--output", required=True, help="Output JSON file for results")
    parser.add_argument("--gcov", default="gcov", help="gcov command (e.g., gcov-14)")
    parser.add_argument("--timeout", type=int, default=120, help="Per-mutation timeout (seconds)")
    parser.add_argument("--batch-size", type=int, default=100, help="Mutations per gcov extraction batch")
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
        start_idx=args.start_idx,
        end_idx=args.end_idx
    )


if __name__ == "__main__":
    main()
