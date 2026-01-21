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


def load_changed_functions(json_file: str) -> Tuple[Set[str], Dict[str, tuple]]:
    """
    Load changed functions and their exact line ranges from changed_functions.json.
    
    Returns:
        - Set of function keys in format "file:function"
        - Dict of exact function ranges: "file:start_line" -> (start, end)
    """
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    changed_functions = set()
    exact_function_ranges = {}
    
    for entry in data:
        file_path = entry['file']
        function_name = entry['function']
        func_key = f"{file_path}:{function_name}"
        changed_functions.add(func_key)
        
        if 'start_line' in entry and 'end_line' in entry:
            range_key = f"{file_path}:{entry['start_line']}"
            exact_function_ranges[range_key] = (entry['start_line'], entry['end_line'])
    
    return changed_functions, exact_function_ranges


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
        - lines_hit, lines_total
        - branches_taken, branches_total
    """
    result = {
        "function_counts": {},
        "lines_hit": 0,
        "lines_total": 0,
        "branches_taken": 0,
        "branches_total": 0,
    }
    
    # Run fastcov
    try:
        cmd = [
            "fastcov",
            "--gcov", gcov_cmd,
            "--search-directory", build_dir,
            "--branch-coverage",
            "--exceptional-branch-coverage",
            "--lcov",
            "-o", "/dev/stdout"
        ]
        
        result_proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result_proc.returncode != 0:
            log(f"WARNING: fastcov failed: {result_proc.stderr}")
            return result
        
        fastcov_output = result_proc.stdout
    except Exception as e:
        log(f"WARNING: fastcov error: {e}")
        return result
    
    # Parse LCOV format
    current_file = None
    file_functions = defaultdict(lambda: {"lines": set(), "branches": set()})
    
    for line in fastcov_output.split('\n'):
        line = line.strip()
        
        if line.startswith('SF:'):
            current_file = line[3:]
        elif line.startswith('FN:'):
            parts = line[3:].split(',', 1)
            if len(parts) == 2 and current_file:
                line_num = parts[0]
                func_name = parts[1]
                func_key = f"{current_file}:{func_name}"
                if func_key in changed_functions:
                    result["function_counts"][func_key] = 0
        elif line.startswith('FNDA:'):
            parts = line[5:].split(',', 1)
            if len(parts) == 2 and current_file:
                count = int(parts[0])
                func_name = parts[1]
                func_key = f"{current_file}:{func_name}"
                if func_key in changed_functions:
                    result["function_counts"][func_key] = count
        elif line.startswith('DA:'):
            parts = line[3:].split(',')
            if len(parts) >= 2 and current_file:
                line_num = int(parts[0])
                hit_count = int(parts[1])
                if hit_count > 0:
                    file_functions[current_file]["lines"].add(line_num)
        elif line.startswith('BRDA:'):
            parts = line[5:].split(',')
            if len(parts) >= 4 and current_file:
                line_num = int(parts[0])
                taken = parts[3]
                if taken != '-' and taken != '0':
                    file_functions[current_file]["branches"].add(f"{line_num}:{parts[1]}:{parts[2]}")
    
    # Filter to changed functions using exact ranges
    if exact_function_ranges:
        for file_path, data in file_functions.items():
            for range_key, (start, end) in exact_function_ranges.items():
                if not range_key.startswith(file_path + ":"):
                    continue
                
                for line_num in data["lines"]:
                    if start <= line_num <= end:
                        result["lines_hit"] += 1
                        result["lines_total"] += 1
                
                for branch_key in data["branches"]:
                    branch_line = int(branch_key.split(':')[0])
                    if start <= branch_line <= end:
                        result["branches_taken"] += 1
                        result["branches_total"] += 1
    
    return result


def regenerate_mutation(seed_path: str, rng_seed: int, iteration: int, chain: List[int]) -> Optional[str]:
    """Regenerate a mutation from a recipe."""
    if not YINYANG_AVAILABLE:
        return None
    
    try:
        with mutation_timeout(MUTATION_TIMEOUT):
            # Parse seed
            with open(seed_path, 'r') as f:
                seed_content = f.read()
            
            formula = InlineTypeFuzz.parse_formula_cached(seed_content, seed_path)
            if formula is None:
                return None
            
            # If chain exists, regenerate chain first
            if chain:
                formula = InlineTypeFuzz.regenerate_chain(formula, seed_path, rng_seed, chain, dry=True)
                if formula is None:
                    return None
            
            # Generate the target mutation
            mutator = InlineTypeFuzz(str(seed_path))
            random.seed(rng_seed)
            mutator.rng = random.Random(rng_seed)
            
            for _ in range(iteration):
                mutator.rng.randint(0, 1000000)
            
            mutated = mutator.mutate_formula(formula, is_typed=True)
            if mutated is None:
                return None
            
            return str(mutated)
    
    except MutationTimeout:
        log(f"  TIMEOUT regenerating {seed_path} iter={iteration}")
        return None
    except Exception as e:
        log(f"  ERROR regenerating {seed_path}: {e}")
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
                    'lines_hit': coverage_data['lines_hit'],
                    'lines_total': coverage_data['lines_total'],
                    'branches_taken': coverage_data['branches_taken'],
                    'branches_total': coverage_data['branches_total'],
                    'function_calls': sum(coverage_data['function_counts'].values()),
                    'extract_time_seconds': extract_time
                }
                
                checkpoints.append(checkpoint)
                
                branches_pct = 100.0 * checkpoint['branches_taken'] / checkpoint['branches_total'] if checkpoint['branches_total'] > 0 else 0
                log(f"[CHECKPOINT {checkpoint_num}] Coverage: {checkpoint['branches_taken']}/{checkpoint['branches_total']} branches ({branches_pct:.1f}%)")
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
        
        # Regenerate mutation
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
        'lines_hit': final_coverage['lines_hit'],
        'lines_total': final_coverage['lines_total'],
        'branches_taken': final_coverage['branches_taken'],
        'branches_total': final_coverage['branches_total'],
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
