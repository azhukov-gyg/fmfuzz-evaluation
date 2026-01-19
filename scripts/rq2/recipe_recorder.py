#!/usr/bin/env python3
"""
Recipe Recorder - Records mutation recipes for deterministic replay.

A "recipe" captures the minimal information needed to reproduce a mutation:
- seed_path: Full path to the parent seed file
- iteration: Which iteration of mutation (1-indexed)
- rng_seed: The random seed used for this mutation sequence
- worker_id: Which parallel worker generated this recipe
- content_hash: MD5 hash of the mutant content (for determinism validation)

This enables fair comparison of fuzzing strategies by:
1. Recording recipes during fuzzing (with strategy-specific overhead)
2. Replaying ALL recipes on the SAME measurement binary (identical overhead)

Determinism validation:
- During fuzzing: calculate MD5 hash of mutant content and store in recipe
- During replay: regenerate mutation and compare hash
- Mismatches indicate non-determinism (different yinyang versions, PYTHONHASHSEED, etc.)

Parallel support:
- Each fuzzing worker records to its own file: recipes_worker_0.jsonl, recipes_worker_1.jsonl, etc.
- After fuzzing, merge all worker files into one combined file
- Replay can also run in parallel

Used by:
- Baseline: simple_commit_fuzzer.py
- Variant1: simple_commit_fuzzer.py  
- Variant2: coverage_guided_fuzzer.py
"""

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Optional, TextIO, List


def compute_content_hash(content: str) -> str:
    """Compute MD5 hash of content string for determinism validation."""
    return hashlib.md5(content.encode('utf-8', errors='replace')).hexdigest()[:16]


class RecipeRecorder:
    """Thread-safe recorder for mutation recipes."""
    
    def __init__(self, output_path: str, rng_seed: int, worker_id: int = 0, buffer_size: int = 100):
        """
        Initialize recipe recorder.
        
        Args:
            output_path: Path to JSONL output file
            rng_seed: The random seed used for this fuzzing session
            worker_id: ID of the parallel worker (0-indexed)
            buffer_size: Number of recipes to buffer before flushing
        """
        self.output_path = Path(output_path)
        self.rng_seed = rng_seed
        self.worker_id = worker_id
        self.buffer_size = buffer_size
        
        self._buffer = []
        self._lock = threading.Lock()
        self._file: Optional[TextIO] = None
        self._recipe_count = 0
        self._start_time = time.time()
        
        # Ensure output directory exists
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Open file for APPENDING (critical: don't overwrite on worker restart!)
        # Check if file exists and has content to decide whether to write header
        file_exists = self.output_path.exists() and self.output_path.stat().st_size > 0
        self._file = open(self.output_path, 'a')
        
        # Write header comment only if file is new
        if not file_exists:
            self._file.write(f"# Recipe log - worker={worker_id}, rng_seed={rng_seed}, started={time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        else:
            # Add restart marker for debugging
            self._file.write(f"# Worker {worker_id} restarted at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._file.flush()
    
    def record(self, seed_path: str, iteration: int, 
               extra_data: Optional[dict] = None,
               original_seed_path: Optional[str] = None,
               mutation_chain: Optional[List[int]] = None,
               content_hash: Optional[str] = None) -> None:
        """
        Record a single mutation recipe.
        
        Args:
            seed_path: Full path to the seed file that was mutated
            iteration: Which iteration of mutation (1-indexed)
            extra_data: Optional additional data (e.g., coverage info, bug found)
            original_seed_path: Original test file path (for coverage-guided fuzzing
                               where mutants can be seeds). If None, seed_path is used.
            mutation_chain: List of iterations that produced the parent seed.
                           For gen1: [] (empty, seed is original)
                           For gen2: [10] (parent was gen1 created at iter 10)
                           For gen3: [10, 20] (gen1 at 10, gen2 at 20)
            content_hash: MD5 hash (16 chars) of mutant content for determinism validation.
                         Use compute_content_hash(content) to generate.
        """
        recipe = {
            "seed_path": str(original_seed_path or seed_path),
            "iteration": iteration,
            "rng_seed": self.rng_seed,
            "worker_id": self.worker_id,
            "timestamp": time.time() - self._start_time,
        }
        
        # Only include chain if non-empty (saves space for gen1 recipes)
        if mutation_chain:
            recipe["chain"] = mutation_chain
        
        # Include content hash for determinism validation
        if content_hash:
            recipe["hash"] = content_hash
        
        if extra_data:
            recipe.update(extra_data)
        
        with self._lock:
            self._buffer.append(recipe)
            self._recipe_count += 1
            
            if len(self._buffer) >= self.buffer_size:
                self._flush_buffer()
    
    def record_seed_start(self, seed_path: str, total_iterations: int) -> None:
        """Record when we start processing a new seed (optional metadata)."""
        meta = {
            "type": "seed_start",
            "seed_path": str(seed_path),
            "total_iterations": total_iterations,
            "worker_id": self.worker_id,
            "timestamp": time.time() - self._start_time,
        }
        
        with self._lock:
            self._buffer.append(meta)
            if len(self._buffer) >= self.buffer_size:
                self._flush_buffer()
    
    def record_seed_end(self, seed_path: str, actual_iterations: int,
                        reason: str = "completed") -> None:
        """Record when we finish processing a seed (optional metadata)."""
        meta = {
            "type": "seed_end",
            "seed_path": str(seed_path),
            "actual_iterations": actual_iterations,
            "reason": reason,
            "worker_id": self.worker_id,
            "timestamp": time.time() - self._start_time,
        }
        
        with self._lock:
            self._buffer.append(meta)
            if len(self._buffer) >= self.buffer_size:
                self._flush_buffer()
    
    def _flush_buffer(self) -> None:
        """Flush buffer to file. Must be called with lock held."""
        if not self._buffer or not self._file:
            return
        
        for recipe in self._buffer:
            self._file.write(json.dumps(recipe) + '\n')
        self._file.flush()
        self._buffer.clear()
    
    def flush(self) -> None:
        """Manually flush buffer to file."""
        with self._lock:
            self._flush_buffer()
    
    def close(self) -> None:
        """Close recorder and flush remaining buffer."""
        with self._lock:
            self._flush_buffer()
            if self._file:
                self._file.write(f"# End - worker={self.worker_id}, total={self._recipe_count}, "
                               f"duration={time.time() - self._start_time:.1f}s\n")
                self._file.close()
                self._file = None
    
    @property
    def recipe_count(self) -> int:
        """Number of mutation recipes recorded."""
        return self._recipe_count
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class RecipeReader:
    """Reader for replaying mutation recipes."""
    
    def __init__(self, recipe_path: str):
        """
        Initialize recipe reader.
        
        Args:
            recipe_path: Path to JSONL recipe file (single or merged)
        """
        self.recipe_path = Path(recipe_path)
        self._recipes = []
        self._metadata = []
        self._load()
    
    def _load(self) -> None:
        """Load recipes from file."""
        with open(self.recipe_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    data = json.loads(line)
                    if data.get('type') in ('seed_start', 'seed_end'):
                        self._metadata.append(data)
                    else:
                        self._recipes.append(data)
                except json.JSONDecodeError:
                    continue
    
    @property
    def recipes(self) -> list:
        """List of mutation recipes."""
        return self._recipes
    
    @property
    def metadata(self) -> list:
        """List of metadata entries (seed_start, seed_end)."""
        return self._metadata
    
    def __len__(self) -> int:
        return len(self._recipes)
    
    def __iter__(self):
        return iter(self._recipes)
    
    def get_unique_seeds(self) -> set:
        """Get set of unique seed paths in recipes."""
        return {r['seed_path'] for r in self._recipes}
    
    def get_rng_seed(self) -> Optional[int]:
        """Get the RNG seed used for these recipes."""
        if self._recipes:
            return self._recipes[0].get('rng_seed')
        return None
    
    def group_by_seed(self) -> dict:
        """Group recipes by seed path."""
        groups = {}
        for recipe in self._recipes:
            seed = recipe['seed_path']
            if seed not in groups:
                groups[seed] = []
            groups[seed].append(recipe)
        return groups
    
    def group_by_worker(self) -> dict:
        """Group recipes by worker_id."""
        groups = {}
        for recipe in self._recipes:
            worker = recipe.get('worker_id', 0)
            if worker not in groups:
                groups[worker] = []
            groups[worker].append(recipe)
        return groups


def merge_recipe_files(input_files: List[str], output_file: str) -> int:
    """
    Merge multiple recipe files from parallel workers into one.
    
    Args:
        input_files: List of paths to worker recipe files
        output_file: Path to merged output file
        
    Returns:
        Total number of recipes merged
    """
    total_recipes = 0
    
    with open(output_file, 'w') as out:
        out.write(f"# Merged recipes from {len(input_files)} workers, {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        for input_file in input_files:
            if not os.path.exists(input_file):
                continue
                
            with open(input_file, 'r') as inp:
                for line in inp:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    out.write(line + '\n')
                    
                    # Count only actual recipes (not metadata)
                    try:
                        data = json.loads(line)
                        if data.get('type') not in ('seed_start', 'seed_end'):
                            total_recipes += 1
                    except json.JSONDecodeError:
                        pass
        
        out.write(f"# End merged - total_recipes={total_recipes}\n")
    
    return total_recipes


def get_worker_recipe_path(base_path: str, worker_id: int) -> str:
    """
    Get recipe file path for a specific worker.
    
    Args:
        base_path: Base path like "recipes.jsonl" or "recipes"
        worker_id: Worker ID (0-indexed)
        
    Returns:
        Path like "recipes_worker_0.jsonl"
    """
    base = Path(base_path)
    if base.suffix == '.jsonl':
        return str(base.parent / f"{base.stem}_worker_{worker_id}.jsonl")
    else:
        return f"{base_path}_worker_{worker_id}.jsonl"
