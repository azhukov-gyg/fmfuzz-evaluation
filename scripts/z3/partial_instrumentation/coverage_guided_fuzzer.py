#!/usr/bin/env python3
"""
Coverage-Guided Fuzzer for Z3
Runs typefuzz with coverage-guided multi-generation mutant management.
Based on CVC5 coverage_guided_fuzzer.py, adapted for Z3.
"""

import argparse
import gc
import json
import math
import mmap
import multiprocessing
from multiprocessing import Queue
import os
import psutil
import random
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Import shared InlineTypeFuzz and RecipeRecorder from scripts/rq2
SCRIPT_DIR = Path(__file__).parent
RQ2_PATH = SCRIPT_DIR.parent.parent / "rq2"
if str(RQ2_PATH) not in sys.path:
    sys.path.insert(0, str(RQ2_PATH))

# Import InlineTypeFuzz from shared location
try:
    from inline_typefuzz import InlineTypeFuzz
    INLINE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: InlineTypeFuzz not available: {e}", file=sys.stderr)
    INLINE_AVAILABLE = False

# Recipe recording (lazy import)
_RecipeRecorder = None
_get_worker_recipe_path = None
_merge_recipe_files = None

def _import_recipes():
    global _RecipeRecorder, _get_worker_recipe_path, _merge_recipe_files
    if _RecipeRecorder is None:
        from recipe_recorder import RecipeRecorder, get_worker_recipe_path, merge_recipe_files
        _RecipeRecorder = RecipeRecorder
        _get_worker_recipe_path = get_worker_recipe_path
        _merge_recipe_files = merge_recipe_files
    return _RecipeRecorder, _get_worker_recipe_path, _merge_recipe_files


# AFL-style coverage map size (1KB bitmap)
AFL_MAP_SIZE = 1024


class CoverageGuidedFuzzer:
    """Coverage-guided fuzzer with multi-generation mutant management."""
    
    EXIT_CODE_BUGS_FOUND = 10
    EXIT_CODE_UNSUPPORTED = 3
    EXIT_CODE_SUCCESS = 0
    
    RESOURCE_CONFIG = {
        'cpu_warning': 85.0,
        'cpu_critical': 95.0,
        'memory_warning_available_gb': 2.0,
        'memory_critical_available_gb': 0.5,
        'check_interval': 2,
        'pause_duration': 10,
        'max_process_memory_mb': 4096,
        'max_process_memory_mb_warning': 3072,
        'z3_memory_limit_mb': 2048,
        'max_tests_per_worker': 200,  # Restart worker after N tests to prevent memory leaks
    }
    
    def __init__(
        self,
        tests: List[str],
        tests_root: str,
        bugs_folder: str = "bugs",
        num_workers: int = 4,
        modulo: int = 2,
        max_pending_mutants: int = 10000,  # Disk space protection
        min_disk_space_mb: int = 500,  # Minimum free disk space to continue
        seed: int = 42,
        time_remaining: Optional[int] = None,
        job_start_time: Optional[float] = None,
        stop_buffer_minutes: int = 5,
        z3_path: str = "./build/z3",
        job_id: Optional[str] = None,
        profraw_dir: str = "./profraw",
        profdata_merge_interval: int = 100,
        output_dir: str = "./output",
        total_instrumented_edges: int = 0,  # From coverage agent
        use_inline_mode: bool = False,
        hours_budget: float = 1.0,  # Time budget in hours for iteration range calculation
        per_test_timeout: int = 120,  # Per-test timeout in seconds (2 minutes default)
        recipe_output: Optional[str] = None,  # Path to recipe output (enables recording)
    ):
        self.tests = tests
        self.tests_root = Path(tests_root)
        self.bugs_folder = Path(bugs_folder)
        self.modulo = modulo
        self.seed = seed
        self.job_id = job_id
        self.recipe_output = recipe_output
        
        # Set random seed for reproducible mutations (must be before any random usage)
        random.seed(seed)
        self.start_time = time.time()
        self.output_dir = Path(output_dir)
        self.max_pending_mutants = max_pending_mutants
        self.min_disk_space_mb = min_disk_space_mb
        self.total_instrumented_edges = total_instrumented_edges
        self.use_inline_mode = use_inline_mode and INLINE_AVAILABLE
        self.hours_budget = hours_budget
        self.per_test_timeout = per_test_timeout
        
        try:
            self.cpu_count = psutil.cpu_count()
        except Exception:
            self.cpu_count = 4
        
        self.num_workers = min(num_workers, self.cpu_count) if num_workers > 0 else self.cpu_count
        if num_workers > self.cpu_count:
            print(f"[WARN] Requested {num_workers} workers but only {self.cpu_count} CPU cores available, using {self.num_workers} workers", file=sys.stderr)
        
        # Time calculation
        if job_start_time is not None:
            self.time_remaining = self._compute_time_remaining(job_start_time, stop_buffer_minutes)
            build_time = self.start_time - job_start_time
            print(f"[INFO] Timeout: {self.time_remaining}s ({self.time_remaining // 60}min), build took {build_time:.0f}s")
        elif time_remaining is not None:
            self.time_remaining = time_remaining
            print(f"[INFO] Timeout: {time_remaining}s ({time_remaining // 60}min)")
        else:
            self.time_remaining = None
            print("[INFO] No timeout (running indefinitely)")
        
        # Solvers: z3 + cvc5
        z3_memory_mb = self.RESOURCE_CONFIG['z3_memory_limit_mb']
        self.z3_path = Path(z3_path)
        self.z3_cmd = f"{self.z3_path} smt.threads=1 memory_max_size={z3_memory_mb} model_validate=true"
        # CVC5 for differential testing (use system cvc5 if available)
        self.cvc5_path = None
        try:
            cvc5_which = subprocess.run(["which", "cvc5"], capture_output=True, text=True)
            if cvc5_which.returncode == 0:
                self.cvc5_path = Path(cvc5_which.stdout.strip())
        except Exception:
            pass
        
        self._validate_solvers()
        self.bugs_folder.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Multiprocessing primitives - use Queue instead of Manager.list for better performance
        self.manager = multiprocessing.Manager()
        
        # ---------------------------------------------------------------------
        # AFL++-style calibration phase:
        # 1. First, run each seed ONCE with iterations=1 (no mutations) to
        #    measure baseline timing and coverage. This establishes avg_runtime
        #    and avg_coverage for accurate AFL-style scoring.
        # 2. After calibration, re-queue seeds with proper score-based iterations.
        # 3. Do NOT execute any mutants until all seeds have been calibrated.
        # ---------------------------------------------------------------------
        self.calibration_done = multiprocessing.Event()
        self.seeds_remaining = multiprocessing.Value('i', len(self.tests))
        # Track calibrated seeds for re-queuing
        self._calibrated_seeds = self.manager.list()
        self._calibrated_seeds_lock = multiprocessing.Lock()
        
        # Legacy alias for compatibility
        self.seed_phase_done = self.calibration_done
        # Buffer of gen1 mutants produced during the initial calibration phase.
        self._seed_phase_mutants = self.manager.list()
        self._seed_phase_lock = multiprocessing.Lock()
        self._seed_phase_flushed = False
        self._calibration_seeds_requeued = False

        # Global mutant buffer: workers append here; main loop flushes in sorted order.
        self._mutant_buffer = self.manager.list()
        self._mutant_buffer_lock = multiprocessing.Lock()

        # Monotonic sequence for total ordering (prevents tuple compare from falling back to Path objects).
        self._queue_seq = multiprocessing.Value('L', 0)
        self._queue_seq_lock = multiprocessing.Lock()
        
        # Single work queue (items are enqueued in sorted order during buffer flushes).
        # Queue item format: (runtime, new_cov_rank, generation, seq, path_str)
        #   - runtime (ascending): fast tests first
        #   - new_cov_rank: 0=new coverage, 1=existing coverage, 2=seed
        #   - generation: 0=seed, 1+=mutant
        #   - seq: monotonic sequence for stable ordering
        #   - path_str: test path as string
        self._work_queue = Queue()
        self._queue_size = multiprocessing.Value('i', 0)
        
        self.bugs_lock = multiprocessing.Lock()
        self.shutdown_event = multiprocessing.Event()
        
        self.resource_state = self.manager.dict({
            'cpu_percent': [0.0] * self.cpu_count,
            'memory_percent': 0.0,
            'status': 'normal',
            'paused': False,
            'last_update': time.time(),
        })
        self.resource_lock = multiprocessing.Lock()
        
        # Track which test each worker is currently processing (for idle detection)
        # worker_id -> test_name or None if idle
        self.worker_status = self.manager.dict()
        for i in range(1, num_workers + 1):
            self.worker_status[i] = None  # All start idle
        
        # Stats: use individual Value objects instead of Manager.dict (5-10x faster)
        self.stats_tests_processed = multiprocessing.Value('i', 0)
        self.stats_bugs_found = multiprocessing.Value('i', 0)
        self.stats_tests_removed_unsupported = multiprocessing.Value('i', 0)
        self.stats_tests_removed_timeout = multiprocessing.Value('i', 0)
        self.stats_mutants_created = multiprocessing.Value('i', 0)
        self.stats_mutants_with_new_coverage = multiprocessing.Value('i', 0)
        self.stats_mutants_with_existing_coverage = multiprocessing.Value('i', 0)
        self.stats_mutants_discarded_no_coverage = multiprocessing.Value('i', 0)
        self.stats_mutants_discarded_disk_space = multiprocessing.Value('i', 0)
        self.stats_total_new_edges = multiprocessing.Value('i', 0)
        self.stats_generations_completed = multiprocessing.Value('i', 0)
        
        # Track excluded tests (unsupported/timeout) so we don't re-add them on queue refill
        self.excluded_tests = self.manager.list()
        
        # Coverage-guided: Shared coverage map (shared across all workers)
        # Tracks which edges have been seen (0xFF = unseen, 0x00 = seen)
        # Created in run() using multiprocessing.Array
        # All workers atomically check/update it using a lock
        
        # Pending mutants folder - mutants waiting to be executed
        self.pending_mutants_dir = self.output_dir / "pending_mutants"
        self.pending_mutants_dir.mkdir(parents=True, exist_ok=True)
        
        # PGO profiling
        self.profraw_dir = Path(profraw_dir)
        self.profraw_dir.mkdir(parents=True, exist_ok=True)
        self.profdata_merge_interval = profdata_merge_interval
        self.profraw_merge_counter = multiprocessing.Value('i', 0)
        
        # -------------------------------------------------------------------------
        # AFL-style scoring: tracking for perf_score calculation
        # -------------------------------------------------------------------------
        # Simple running averages (like AFL: total/count, no EMA)
        self.total_runtime_ms = multiprocessing.Value('d', 0.0)
        self.total_coverage = multiprocessing.Value('d', 0.0)
        self.sample_count = multiprocessing.Value('i', 0)
        self.avg_lock = multiprocessing.Lock()
        
        # Newcomer tracking: test_path -> bonus value (decremented each time processed)
        # New tests start with bonus=4 for initial boost
        self.test_newcomer = self.manager.dict()
        self.newcomer_proc_count = self.manager.dict()  # Track processing count for slower decay
        self.newcomer_lock = multiprocessing.Lock()
        
        # Path frequency tracking (AFL's n_fuzz): coverage_hash -> times_seen
        # Used for F (rarity) factor - rare paths get priority
        self.path_frequency = self.manager.dict()
        self.path_frequency_lock = multiprocessing.Lock()
        self.max_path_frequency = multiprocessing.Value('i', 1)
        
        # Test -> path_frequency mapping (for score lookup)
        self.test_path_freq = self.manager.dict()
        
        # Owned edges tracking (AFL's tc_ref): edge_id -> (test_path, best_runtime_ms)
        # Used for U (unique) factor - tests that own more edges get priority
        self.edge_owner = self.manager.dict()
        self.edge_owner_lock = multiprocessing.Lock()
        # Test -> owned_edges_count mapping (for score lookup)
        self.test_owned_edges = self.manager.dict()
        
        # -------------------------------------------------------------------------
        # AFL++ style queue management
        # -------------------------------------------------------------------------
        # Calibration data: test_path -> (runtime_sec, edges_hit, perf_score, weight)
        self.calibration_data = self.manager.dict()
        self.calibration_data_lock = multiprocessing.Lock()
        
        # Favored tests (AFL's favored flag): tests that own unique coverage
        self.test_favored = self.manager.dict()  # test_path -> bool
        self.favored_lock = multiprocessing.Lock()
        
        # Counters for probabilistic skipping
        self.pending_favored = multiprocessing.Value('i', 0)  # favored tests not yet fuzzed in current cycle
        self.queued_favored = multiprocessing.Value('i', 0)   # favored tests in queue
        
        # Top-rated per edge (AFL's top_rated[]): edge_id -> test_path
        # Stores the "best" test for each edge (fastest × smallest)
        self.top_rated = self.manager.dict()
        self.top_rated_lock = multiprocessing.Lock()
        
        # Track fuzz_level per test (how many times it's been fuzzed)
        self.test_fuzz_level = self.manager.dict()  # test_path -> int
        
        # Slow test handling - don't skip, but give very few iterations
        # Tests slower than this get minimum iterations (5) instead of being excluded
        self.SLOW_TEST_THRESHOLD_S = 10.0  # seconds - tests slower than this get min iterations
        self.MIN_SLOW_TEST_ITERATIONS = 5  # Minimum iterations for very slow tests
        
    def _validate_solvers(self):
        if not self.z3_path.exists():
            raise ValueError(f"z3 not found at: {self.z3_path}")
        # CVC5 is optional (for differential testing)
        if self.cvc5_path and not self.cvc5_path.exists():
            print(f"[WARN] cvc5 not found at: {self.cvc5_path}, continuing without differential testing", file=sys.stderr)
            self.cvc5_path = None
    
    # -------------------------------------------------------------------------
    # AFL-style Scoring System (adapted from AFL++ calculate_score)
    # -------------------------------------------------------------------------
    
    def _get_speed_base(self, runtime_ms: float) -> int:
        """
        AFL-style speed-based starting score.
        Faster tests get higher base score (more iterations).
        Very slow tests (>10s) get minimal score to ensure ~5 iterations.
        
        Returns base score in [2, 300].
        """
        avg_runtime = self._get_avg_runtime_ms()
        
        # VERY SLOW tests (>10s absolute) get minimal iterations regardless of average
        # Score of 2 gives ~5 iterations after _score_to_iterations calculation
        if runtime_ms > self.SLOW_TEST_THRESHOLD_S * 1000:
            return 2  # Minimal score for extremely slow tests
        
        ratio = runtime_ms / avg_runtime
        
        if ratio > 10:    return 10    # Very slow: minimal iterations
        if ratio > 4:     return 25
        if ratio > 2:     return 50
        if ratio > 1.33:  return 75
        if ratio < 0.25:  return 300   # Very fast: maximum iterations
        if ratio < 0.33:  return 200
        if ratio < 0.5:   return 150
        return 100                      # Average speed
    
    def _get_coverage_multiplier(self, edges_hit: int) -> float:
        """
        AFL-style coverage factor.
        Tests hitting more edges get higher multiplier.
        
        Returns multiplier in [1.0, 5.0].
        NO PENALTY for low coverage - we want to exercise changed functions,
        not maximize total edge coverage.
        """
        avg_cov = self._get_avg_coverage()
        
        # Prevent division by zero
        if avg_cov <= 0:
            return 1.0
        
        ratio = edges_hit / avg_cov
        
        # Big bonuses for high coverage, NO penalty for low coverage
        if ratio > 3.3:   return 5.0    # Much more coverage: maximum boost
        if ratio > 2:     return 3.0
        if ratio > 1.33:  return 2.0
        if ratio > 1.0:   return 1.5
        # No penalty - tests hitting ANY edges should get full iterations
        # This ensures CaDiCaL tests (which may hit fewer total edges) aren't penalized
        return 1.0
    
    def _get_newcomer_multiplier(self, test_path: str) -> tuple:
        """
        AFL-style newcomer bonus.
        Newly discovered tests get temporary boost, decremented each processing.
        
        Returns (multiplier, should_update_bonus).
        - multiplier in [1.0, 8.0]
        
        Tests that discover NEW coverage get 8x bonus (decays by 4 each time).
        Tests with existing coverage get 2x bonus (decays by 1 each time).
        """
        with self.newcomer_lock:
            bonus = self.test_newcomer.get(test_path, 0)
            
            if bonus >= 8:
                return 8.0, True  # Maximum boost for NEW coverage discoverers
            elif bonus >= 4:
                return 4.0, True  # Big boost, will decrement by 4
            elif bonus > 0:
                return 2.0, True  # Medium boost, will decrement by 1
            return 1.0, False     # No boost
    
    def _decrement_newcomer(self, test_path: str):
        """
        Decrement newcomer bonus after processing (slower decay for slow targets).
        
        For slow targets (120s timeout), we only decay every 3rd processing.
        This keeps rare new-coverage discoverers prioritized longer since
        we process fewer tests per hour than fast binary targets.
        """
        with self.newcomer_lock:
            bonus = self.test_newcomer.get(test_path, 0)
            if bonus <= 0:
                return
            
            # Track processing count for this test
            proc_count = self.newcomer_proc_count.get(test_path, 0) + 1
            self.newcomer_proc_count[test_path] = proc_count
            
            # Only decay every 3rd processing (slower decay for slow targets)
            if proc_count % 3 != 0:
                return
            
            # Gentler decay: -2 for high bonus, -1 for low
            if bonus >= 6:
                self.test_newcomer[test_path] = bonus - 2
            elif bonus > 0:
                self.test_newcomer[test_path] = bonus - 1
    
    def _set_newcomer(self, test_path: str, bonus: int = 4):
        """Set initial newcomer bonus for a new test."""
        with self.newcomer_lock:
            self.test_newcomer[test_path] = bonus
    
    def _get_depth_multiplier(self, generation: int) -> float:
        """
        AFL-style depth factor (adjusted for slow targets with 120s timeout).
        Deeper tests (more mutations from original) get higher multiplier
        because they represent productive lineages worth exploring further.
        
        Original AFL thresholds (gen 4+ for bonus) are too high for slow targets
        where we rarely reach gen 4 in 1-hour budget. Lowered to give bonus
        starting at gen 2.
        
        Returns multiplier in [1.0, 4.5].
        """
        if generation <= 1:   return 1.0   # seed + first mutations
        if generation <= 3:   return 1.8   # early interesting depth
        if generation <= 6:   return 2.5
        if generation <= 10:  return 3.5
        return 4.5
    
    def _hash_coverage(self, trace_bits: bytes) -> str:
        """
        Hash coverage bitmap to identify unique paths (AFL's coverage signature).
        Uses a simple hash of non-zero positions and their hit counts.
        """
        import hashlib
        # Create a compact representation: positions with hits
        sig = []
        for i, b in enumerate(trace_bits):
            if b:
                # Bucket hit counts: 1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+
                if b == 1: bucket = 0
                elif b == 2: bucket = 1
                elif b == 3: bucket = 2
                elif b <= 7: bucket = 3
                elif b <= 15: bucket = 4
                elif b <= 31: bucket = 5
                elif b <= 127: bucket = 6
                else: bucket = 7
                sig.append(f"{i}:{bucket}")
        
        sig_str = ",".join(sig)
        return hashlib.md5(sig_str.encode()).hexdigest()[:16]
    
    def _update_path_frequency(self, coverage_hash: str, test_path: str = None) -> int:
        """
        Update path frequency counter. Returns current frequency for this path.
        Optionally stores the frequency for the test path (for later score lookups).
        """
        with self.path_frequency_lock:
            freq = self.path_frequency.get(coverage_hash, 0) + 1
            self.path_frequency[coverage_hash] = freq
            
            # Update max frequency
            if freq > self.max_path_frequency.value:
                self.max_path_frequency.value = freq
            
            # Store for test path lookup
            if test_path:
                self.test_path_freq[test_path] = freq
            
            return freq
    
    def _get_test_path_frequency(self, test_path: str) -> int:
        """Get stored path frequency for a test (default 1 if unknown)."""
        return self.test_path_freq.get(test_path, 1)
    
    def _get_rarity_multiplier(self, path_frequency: int) -> float:
        """
        AFL-style rarity factor (n_fuzz).
        Rare paths (seen fewer times) get higher multiplier.
        
        Returns multiplier in [0.25, 4.0].
        """
        max_freq = max(1, self.max_path_frequency.value)
        
        # Ratio of this path's frequency to max frequency
        ratio = path_frequency / max_freq
        
        if ratio <= 0.01:  return 4.0   # Very rare (≤1% of max)
        if ratio <= 0.05:  return 3.0   # Rare
        if ratio <= 0.1:   return 2.0   # Uncommon
        if ratio <= 0.25:  return 1.5   # Below average
        if ratio <= 0.5:   return 1.0   # Average
        if ratio <= 0.75:  return 0.75  # Common
        return 0.5                       # Very common (>75% of max)
    
    def _update_edge_ownership(self, trace_bits: bytes, runtime_ms: float, test_path: str):
        """
        Update edge ownership tracking (AFL's tc_ref).
        A test "owns" an edge if it's the fastest test to reach that edge.
        """
        with self.edge_owner_lock:
            owned_count = 0
            for edge_id, hit_count in enumerate(trace_bits):
                if hit_count == 0:
                    continue
                
                current_owner = self.edge_owner.get(edge_id)
                if current_owner is None:
                    # First test to hit this edge - owns it
                    self.edge_owner[edge_id] = (test_path, runtime_ms)
                    owned_count += 1
                else:
                    owner_path, owner_runtime = current_owner
                    if owner_path == test_path:
                        # Already owns it, update runtime if faster
                        if runtime_ms < owner_runtime:
                            self.edge_owner[edge_id] = (test_path, runtime_ms)
                        owned_count += 1
                    elif runtime_ms < owner_runtime:
                        # Steal ownership - this test is faster
                        # Decrement old owner's count
                        old_count = self.test_owned_edges.get(owner_path, 0)
                        if old_count > 0:
                            self.test_owned_edges[owner_path] = old_count - 1
                        # Take ownership
                        self.edge_owner[edge_id] = (test_path, runtime_ms)
                        owned_count += 1
            
            # Update this test's owned edge count
            self.test_owned_edges[test_path] = owned_count
    
    def _get_owned_edges_count(self, test_path: str) -> int:
        """Get number of edges owned by this test."""
        return self.test_owned_edges.get(test_path, 0)
    
    def _get_owned_edges_multiplier(self, owned_edges: int) -> float:
        """
        AFL-style owned edges factor (tc_ref).
        Tests owning more edges get higher multiplier (they're "favored").
        
        NOTE: With limited instrumentation scope (~69 edges), most tests hit all edges
        so none "own" unique edges. Changed to only give BONUSES, no penalties.
        
        Returns multiplier in [1.0, 4.0] (no penalty for unfavored tests).
        """
        if owned_edges >= 100: return 4.0   # Owns many edges
        if owned_edges >= 50:  return 3.0
        if owned_edges >= 20:  return 2.0
        if owned_edges >= 10:  return 1.5
        if owned_edges >= 5:   return 1.25
        if owned_edges >= 1:   return 1.1
        return 1.0                           # No penalty - baseline iterations
    
    def _calculate_perf_score(
        self,
        runtime_ms: float,
        edges_hit: int,
        generation: int,
        test_path: str,
        path_frequency: int = 1,
        owned_edges: int = 0,
    ) -> float:
        """
        Calculate AFL-style performance score.
        Higher score = more iterations deserved.
        
        Score = S(speed) × C(coverage) × N(newcomer) × D(depth) × F(rarity) × U(owned)
        
        Factors:
          S: [10, 300]   - base score from speed (fast=300, slow=10)
          C: [1.0, 5.0]  - coverage relative to average (no penalty, only bonus)
          N: [1.0, 8.0]  - newcomer bonus (8x for NEW coverage, decays over processing)
          D: [1, 5]      - depth/generation bonus (deep lineages get more)
          F: [0.5, 4.0]  - path rarity (rare paths get priority)
          U: [1.0, 4.0]  - owned edges (favored tests get bonus, no penalty)
        
        Theoretical range: [1.0, 288000], but clamped to [10, 1600] for iteration mapping.
        Typical scores: 
          - Bad test (slow, common, no edges): 5-15
          - Average test: 100-300
          - Good newcomer: 500-2000
          - Exceptional newcomer: 2000+
        """
        S = self._get_speed_base(runtime_ms)
        C = self._get_coverage_multiplier(edges_hit)
        N, _ = self._get_newcomer_multiplier(test_path)
        D = self._get_depth_multiplier(generation)
        F = self._get_rarity_multiplier(path_frequency)
        U = self._get_owned_edges_multiplier(owned_edges)
        
        return S * C * N * D * F * U
    
    def _score_to_iterations(self, score: float) -> int:
        """
        Map AFL-style perf_score to iteration count.
        
        For ≤1.5h budget: [25, 500] iterations (increased min for more recipes)
        For >1.5h budget: [25, 500] iterations
        
        Linear mapping: low score → few iterations, high score → many iterations.
        Very low scores (≤5) are treated as slow tests and get MIN_SLOW_TEST_ITERATIONS.
        """
        # Increased minimum from 5 to 25 to generate more recipes
        # This ensures even low-scoring tests contribute to recipe count
        if self.hours_budget <= 1.5:
            min_iter, max_iter = 25, 500
        else:
            min_iter, max_iter = 25, 500
        
        # Very low scores (slow tests) get minimum iterations
        if score <= 5:
            return self.MIN_SLOW_TEST_ITERATIONS
        
        # Clamp score to expected range [10, 1600]
        score = max(10, min(score, 1600))
        
        # Linear map: score 10 → min_iter, score 1600 → max_iter
        normalized = (score - 10) / (1600 - 10)
        return int(min_iter + normalized * (max_iter - min_iter))
    
    def _update_running_averages(self, runtime_ms: float, edges_hit: int):
        """Update running averages for score calculation (AFL-style: total/count)."""
        with self.avg_lock:
            self.total_runtime_ms.value += runtime_ms
            self.total_coverage.value += edges_hit
            self.sample_count.value += 1
    
    def _get_avg_runtime_ms(self) -> float:
        """Get average runtime in ms (default 1000 if no samples)."""
        with self.avg_lock:
            if self.sample_count.value == 0:
                return 1000.0
            return self.total_runtime_ms.value / self.sample_count.value
    
    def _get_avg_coverage(self) -> float:
        """Get average coverage (default 10 if no samples)."""
        with self.avg_lock:
            if self.sample_count.value == 0:
                return 10.0
            return self.total_coverage.value / self.sample_count.value
    
    # -------------------------------------------------------------------------
    # AFL++ style queue management
    # -------------------------------------------------------------------------
    
    def _calculate_weight(self, test_path: str) -> float:
        """
        Calculate weight for weighted random selection.
        Higher weight = more likely to be selected.
        
        Simplified from AFL++ - we prioritize FAST tests for recipe generation.
        """
        with self.calibration_data_lock:
            data = self.calibration_data.get(test_path)
        
        if not data:
            return 1.0  # Default weight for uncalibrated tests
        
        runtime_sec, edges_hit, perf_score, _ = data
        runtime_ms = runtime_sec * 1000
        
        weight = 1.0
        avg_runtime = self._get_avg_runtime_ms()
        
        if avg_runtime > 0:
            t = runtime_ms / avg_runtime
            
            # Simple speed-based weighting: faster = higher weight
            # This prioritizes fast tests for more recipe generation
            if t < 0.25:
                weight = 4.0    # Very fast: big bonus
            elif t < 0.5:
                weight = 2.0    # Fast: bonus
            elif t < 1.0:
                weight = 1.0    # Average: neutral
            elif t < 2.0:
                weight = 0.5    # Slow: penalty
            elif t < 5.0:
                weight = 0.2    # Very slow: big penalty
            else:
                weight = 0.05   # Extremely slow: severe penalty
        
        # Bonus for favored tests (own unique edges)
        if self.test_favored.get(test_path, False):
            weight *= 2.0
        
        # Penalty for already-fuzzed tests (encourage diversity)
        fuzz_level = self.test_fuzz_level.get(test_path, 0)
        if fuzz_level > 0:
            weight /= (1 + math.log10(fuzz_level + 1))
        
        return max(0.01, weight)  # Ensure positive weight
    
    def _update_top_rated(self, test_path: str, trace_bits: bytes, runtime_ms: float):
        """
        Update top_rated[] for each edge hit by this test.
        A test becomes top_rated for an edge if it's the fastest to hit it.
        
        Based on AFL++ update_bitmap_score() in afl-fuzz-queue.c
        """
        # Get test length (use path length as proxy, or could use actual file size)
        test_len = len(test_path)
        fav_factor = runtime_ms * test_len  # Faster × smaller = better
        
        # First, collect edges we might update (only non-zero edges for efficiency)
        candidate_edges = [(i, b) for i, b in enumerate(trace_bits) if b != 0]
        if not candidate_edges:
            return
        
        # Pre-fetch calibration data outside the lock to avoid nested locking
        with self.calibration_data_lock:
            cal_data_snapshot = dict(self.calibration_data)
        
        edges_to_update = []
        
        with self.top_rated_lock:
            for edge_id, hit_count in candidate_edges:
                current_top = self.top_rated.get(edge_id)
                
                if current_top is None:
                    # No existing top_rated for this edge
                    edges_to_update.append((edge_id, test_path))
                else:
                    # Compare with existing top_rated (using pre-fetched data)
                    top_data = cal_data_snapshot.get(current_top)
                    
                    if top_data:
                        top_runtime_ms = top_data[0] * 1000
                        top_len = len(current_top)
                        top_fav_factor = top_runtime_ms * top_len
                        
                        if fav_factor < top_fav_factor:
                            # This test is better - take over
                            edges_to_update.append((edge_id, test_path))
                    else:
                        # No calibration data for current top - take over
                        edges_to_update.append((edge_id, test_path))
            
            # Apply updates
            for edge_id, path in edges_to_update:
                self.top_rated[edge_id] = path
    
    def _cull_queue(self):
        """
        Mark tests as 'favored' based on top_rated[].
        A test is favored if it's the best way to hit some edge.
        
        Based on AFL++ cull_queue() in afl-fuzz-queue.c
        """
        # Reset all favored flags
        with self.favored_lock:
            for test_path in list(self.test_favored.keys()):
                self.test_favored[test_path] = False
        
        # Collect all tests that are top_rated for at least one edge
        favored_tests = set()
        with self.top_rated_lock:
            for edge_id, test_path in self.top_rated.items():
                if test_path:
                    favored_tests.add(test_path)
        
        # Mark them as favored
        with self.favored_lock:
            for test_path in favored_tests:
                self.test_favored[test_path] = True
        
        # Update pending_favored counter
        pending = 0
        for test_path in favored_tests:
            fuzz_level = self.test_fuzz_level.get(test_path, 0)
            if fuzz_level == 0:
                pending += 1
        
        with self.pending_favored.get_lock():
            self.pending_favored.value = pending
        
        print(f"[CULL] Marked {len(favored_tests)} tests as favored ({pending} pending)", flush=True)
    
    def _recalculate_queue_weights(self):
        """
        Recalculate weights for all queued items using current averages.
        
        AFL++ does this every iteration. We do it every 10 tests or 5 minutes
        since Python is slower. This ensures:
        - Running averages affect existing queue items
        - Favored status changes propagate
        - Parent success rate (when implemented) affects queue
        
        Cost: O(n log n) where n = queue size. ~50ms for n=200.
        """
        # Drain the current queue
        items = []
        drained = 0
        while not self._queue_empty():
            item = self._queue_pop(timeout=0.01)
            if item:
                items.append(item)
                drained += 1
            else:
                break
        
        if not items:
            return
        
        # Recalculate scores with current state
        new_items = []
        for runtime_priority, new_cov_rank, generation, seq, path in items:
            # Get calibration data if available
            with self.calibration_data_lock:
                cal_data = self.calibration_data.get(path)
            
            if cal_data:
                runtime_ms = cal_data[0] * 1000
                edges = cal_data[1]
            else:
                # Use current averages for uncalibrated items
                runtime_ms = self._get_avg_runtime_ms()
                edges = max(1, int(self._get_avg_coverage()))
            
            # Recalculate score with current averages and state
            path_freq = self._get_test_path_frequency(path)
            owned_edges = self._get_owned_edges_count(path)
            new_score = self._calculate_perf_score(
                runtime_ms, edges, generation, path, path_freq, owned_edges
            )
            
            # Convert score to priority (lower = higher priority)
            # Invert score: high score -> low runtime_priority -> picked first
            new_runtime_priority = 1.0 / max(1.0, new_score / 100.0)
            
            new_items.append((new_runtime_priority, new_cov_rank, generation, seq, path))
        
        # Re-sort and push back
        new_items.sort()
        self._queue_push_batch(new_items)
        
        print(f"[RECALC] Recalculated weights for {len(new_items)} queued items", flush=True)
    
    def _weighted_random_select(self, tests: list, count: int) -> list:
        """
        Select tests using weighted random selection (AFL++ alias table style).
        Returns up to 'count' tests, selected with probability proportional to weight.
        """
        if not tests:
            return []
        
        # Calculate weights for all tests
        weights = []
        valid_tests = []
        
        for test in tests:
            if test in self.excluded_tests:
                continue
            weight = self._calculate_weight(test)
            if weight > 0:
                weights.append(weight)
                valid_tests.append(test)
        
        if not valid_tests:
            return []
        
        # Normalize weights
        total_weight = sum(weights)
        if total_weight == 0:
            weights = [1.0] * len(valid_tests)
            total_weight = len(valid_tests)
        
        # Select tests using weighted random choice
        # Use random.choices for weighted selection (with replacement)
        # Then deduplicate to get unique tests
        selected = set()
        attempts = 0
        max_attempts = count * 3  # Avoid infinite loop
        
        while len(selected) < count and attempts < max_attempts:
            chosen = random.choices(valid_tests, weights=weights, k=min(count, len(valid_tests)))
            selected.update(chosen)
            attempts += 1
        
        return list(selected)[:count]
    
    def _store_calibration_data(self, test_path: str, runtime_sec: float, edges_hit: int):
        """Store calibration data for a test."""
        runtime_ms = runtime_sec * 1000
        path_freq = self._get_test_path_frequency(test_path)
        owned_edges = self._get_owned_edges_count(test_path)
        perf_score = self._calculate_perf_score(runtime_ms, edges_hit, 0, test_path, path_freq, owned_edges)
        weight = self._calculate_weight(test_path)
        
        with self.calibration_data_lock:
            self.calibration_data[test_path] = (runtime_sec, edges_hit, perf_score, weight)
    
    # -------------------------------------------------------------------------
    # Work queue helpers (sorted FIFO enqueue via periodic buffer flush)
    # -------------------------------------------------------------------------
    
    def _queue_push(self, item: tuple):
        """Push item to work queue. Item is a sortable tuple."""
        self._work_queue.put(item)
        with self._queue_size.get_lock():
            self._queue_size.value += 1
    
    def _queue_push_batch(self, items: list):
        """Push multiple items efficiently."""
        for item in items:
            self._work_queue.put(item)
        with self._queue_size.get_lock():
            self._queue_size.value += len(items)
    
    def _queue_push_initial(self, test_name: str):
        """Push initial test (seed)."""
        # Queue item format: (runtime, new_cov_rank, generation, seq, path_str)
        self._queue_push((0.0, 2, 0, self._next_seq(), test_name))
    
    def _queue_push_initial_batch(self, test_names: list, use_calibration: bool = True):
        """
        Push multiple initial tests efficiently, filtering out excluded tests.
        
        If use_calibration=True (after calibration), uses stored runtime data and
        weighted selection. If False (initial calibration), uses uniform weights.
        """
        excluded_list = list(self.excluded_tests)
        excluded_set = set(excluded_list)
        filtered_tests = [name for name in test_names if name not in excluded_set]
        skipped_count = len(test_names) - len(filtered_tests)
        
        # If we have calibration data, use it for proper ordering
        if use_calibration and len(self.calibration_data) > 0:
            # Re-run cull_queue to update favored status
            self._cull_queue()
            
            # Build queue items with calibration data
            items = []
            for name in filtered_tests:
                with self.calibration_data_lock:
                    cal_data = self.calibration_data.get(name)
                
                if cal_data:
                    runtime_sec, edges_hit, perf_score, weight = cal_data
                    is_favored = self.test_favored.get(name, False)
                    # Favored tests get priority (runtime=0), others use actual runtime
                    effective_runtime = 0.0 if is_favored else runtime_sec
                else:
                    # No calibration data - use default
                    effective_runtime = 0.0
                
                items.append((effective_runtime, 2, 0, self._next_seq(), name))
            
            # Sort by runtime (favored first, then fast)
            items.sort()
            
            favored_count = sum(1 for _, _, _, _, p in items if self.test_favored.get(p, False))
            print(f"[QUEUE] Refilling with {len(items)} tests ({favored_count} favored, {skipped_count} excluded)")
        else:
            # Initial calibration - uniform ordering
            items = [(0.0, 2, 0, self._next_seq(), name) for name in filtered_tests]
        
        queue_size_before = self._get_queue_size()
        self._queue_push_batch(items)
        
        if skipped_count > 0:
            print(f"[QUEUE] Loaded {len(items)} initial tests, skipped {skipped_count} excluded (queue: {queue_size_before} -> {self._get_queue_size()})")
        else:
            print(f"[QUEUE] Loaded {len(items)} initial tests (queue: {queue_size_before} -> {self._get_queue_size()})")
        
        if len(excluded_list) > 0:
            print(f"[QUEUE] [DEBUG] Excluded list has {len(excluded_list)} items: {excluded_list[:3]}...")
        sys.stdout.flush()

    def _seed_phase_buffer_mutants(self, mutant_items: list):
        """Buffer gen1 mutant queue items during seed phase; flushed once seeds are done."""
        if not mutant_items:
            return
        with self._seed_phase_lock:
            for item in mutant_items:
                self._seed_phase_mutants.append(item)

    def _flush_seed_phase_mutants(self):
        """Flush buffered gen1 mutants after seed phase completes, sorted by priority."""
        with self._seed_phase_lock:
            buffered = list(self._seed_phase_mutants)
            if buffered:
                self._seed_phase_mutants[:] = []
        if not buffered:
            return
        buffered.sort()
        self._queue_push_batch(buffered)
        print(f"[INFO] Flushed {len(buffered)} gen1 mutants from seed phase buffer")

    def _requeue_calibrated_seeds(self):
        """Re-queue calibrated seeds with proper AFL-style scoring after calibration."""
        with self._calibrated_seeds_lock:
            seeds = list(self._calibrated_seeds)
            self._calibrated_seeds[:] = []
        
        if not seeds:
            return
        
        items_to_queue = []
        slow_tests_count = 0
        
        for runtime, edges_hit, test_path_str in seeds:
            # Store calibration data for weighted selection and future refills
            self._store_calibration_data(test_path_str, runtime, edges_hit)
            
            # Track slow tests (they'll get very low iterations via scoring, not excluded)
            if runtime > self.SLOW_TEST_THRESHOLD_S:
                slow_tests_count += 1
            
            # Calculate perf_score using calibrated averages and path frequency
            runtime_ms = runtime * 1000
            path_freq = self._get_test_path_frequency(test_path_str)
            owned_edges = self._get_owned_edges_count(test_path_str)
            perf_score = self._calculate_perf_score(runtime_ms, edges_hit, 0, test_path_str, path_freq, owned_edges)
            iterations = self._score_to_iterations(perf_score)
            
            # NOTE: Do NOT set newcomer bonus for seeds.
            # Seeds are known inputs, not discoveries. Newcomer bonus (N factor)
            # is only for mutants that find new coverage.
            # Previously this caused all seeds to get iter=250 due to N=4 boost.
            
            # Queue item format: (runtime, new_cov_rank, generation, seq, path_str)
            # Use runtime as sort key so fast seeds are processed first
            items_to_queue.append((runtime, 2, 0, self._next_seq(), test_path_str))
        
        if slow_tests_count > 0:
            print(f"[INFO] {slow_tests_count} slow tests (>{self.SLOW_TEST_THRESHOLD_S}s) will get minimum iterations ({self.MIN_SLOW_TEST_ITERATIONS})")
        
        # Mark favored tests based on edge ownership (AFL's cull_queue)
        self._cull_queue()
        
        # Sort by runtime (fast first), but also prioritize favored tests
        # Favored tests get runtime=0 to be processed first
        def sort_key(item):
            runtime, rank, gen, seq, path = item
            is_favored = self.test_favored.get(path, False)
            # Favored tests: use 0.0 runtime, non-favored: use actual runtime
            effective_runtime = 0.0 if is_favored else runtime
            return (effective_runtime, rank, gen, seq)
        
        items_to_queue.sort(key=sort_key)
        self._queue_push_batch(items_to_queue)
        
        favored_count = sum(1 for _, _, _, _, p in items_to_queue if self.test_favored.get(p, False))
        
        # Debug: show calibration data statistics
        with self.calibration_data_lock:
            cal_size = len(self.calibration_data)
            nonzero_edges = sum(1 for data in self.calibration_data.values() if data[1] > 0)
            max_edges = max((data[1] for data in self.calibration_data.values()), default=0)
            edges_list = sorted([data[1] for data in self.calibration_data.values() if data[1] > 0], reverse=True)[:5]
        
        print(f"[INFO] Re-queued {len(items_to_queue)} calibrated seeds ({favored_count} favored, {slow_tests_count} slow) for fuzzing")
        print(f"[DEBUG-CAL] calibration_data: {cal_size} entries, {nonzero_edges} with edges>0, max={max_edges}, top5={edges_list}")

    def _buffer_mutants(self, mutant_items: list):
        """Buffer mutant queue items to be flushed in sorted order by main loop."""
        if not mutant_items:
            return
        with self._mutant_buffer_lock:
            for item in mutant_items:
                self._mutant_buffer.append(item)

    def _flush_mutant_buffer(self):
        """Flush buffered mutants, sorted by priority (ascending)."""
        with self._mutant_buffer_lock:
            buffered = list(self._mutant_buffer)
            if buffered:
                self._mutant_buffer[:] = []
        if not buffered:
            return
        buffered.sort()
        self._queue_push_batch(buffered)

    def _queue_pop(self, timeout: float = 1.0) -> Optional[tuple]:
        """Pop item from queue."""
        try:
            item = self._work_queue.get(timeout=timeout)
            with self._queue_size.get_lock():
                self._queue_size.value -= 1
            return item
        except:
            return None
    
    def _queue_empty(self) -> bool:
        """Check if queue is empty."""
        return self._queue_size.value <= 0
    
    def _get_queue_size(self) -> int:
        """Get total queue size."""
        return self._queue_size.value

    def _next_seq(self) -> int:
        """Monotonic sequence number used for total ordering in queue items."""
        with self._queue_seq_lock:
            self._queue_seq.value += 1
            return int(self._queue_seq.value)
    
    # -------------------------------------------------------------------------
    # Stats helpers (atomic operations on Value objects)
    # -------------------------------------------------------------------------
    
    def _get_stat(self, name: str) -> int:
        """Get stat value by name."""
        attr = getattr(self, f'stats_{name}', None)
        return attr.value if attr else 0
    
    def _inc_stat(self, name: str, delta: int = 1):
        """Increment stat by delta."""
        attr = getattr(self, f'stats_{name}', None)
        if attr:
            with attr.get_lock():
                attr.value += delta
    
    # -------------------------------------------------------------------------
    # Disk Space Management (TOP PRIORITY)
    # -------------------------------------------------------------------------
    
    def _get_free_disk_space_mb(self) -> float:
        """Get free disk space in MB for the output directory."""
        try:
            stat = os.statvfs(self.output_dir)
            free_bytes = stat.f_bavail * stat.f_frsize
            return free_bytes / (1024 * 1024)
        except Exception:
            return float('inf')  # Assume enough space if can't check
    
    def _count_pending_mutants(self) -> int:
        """Count number of pending mutant files."""
        try:
            return len(list(self.pending_mutants_dir.glob("*.smt2"))) + \
                   len(list(self.pending_mutants_dir.glob("*.smt")))
        except Exception:
            return 0
    
    def _can_queue_mutants(self, count: int = 1) -> bool:
        """Check if we can safely queue more mutants (disk space + count limits)."""
        # Check pending mutants limit
        current_pending = self._count_pending_mutants()
        if current_pending + count > self.max_pending_mutants:
            return False
        
        # Check disk space
        free_mb = self._get_free_disk_space_mb()
        if free_mb < self.min_disk_space_mb:
            return False
        
        return True
    
    def _cleanup_old_pending_mutants(self, max_to_keep: int = None):
        """Remove oldest pending mutants if over limit."""
        if max_to_keep is None:
            max_to_keep = self.max_pending_mutants
        
        try:
            mutant_files = list(self.pending_mutants_dir.glob("*.smt2")) + \
                          list(self.pending_mutants_dir.glob("*.smt"))
            
            if len(mutant_files) <= max_to_keep:
                return 0
            
            # Sort by modification time (oldest first)
            mutant_files.sort(key=lambda f: f.stat().st_mtime)
            
            to_remove = len(mutant_files) - max_to_keep
            removed = 0
            for f in mutant_files[:to_remove]:
                try:
                    f.unlink()
                    removed += 1
                except Exception:
                    pass
            
            if removed > 0:
                print(f"[DISK] Cleaned up {removed} old pending mutants")
            return removed
        except Exception as e:
            print(f"[DISK] Error cleaning pending mutants: {e}", file=sys.stderr)
            return 0
    
    def _compute_time_remaining(self, job_start_time: float, stop_buffer_minutes: int) -> int:
        GITHUB_TIMEOUT = 21600
        MIN_REMAINING = 600
        
        build_time = self.start_time - job_start_time
        stop_buffer_seconds = stop_buffer_minutes * 60
        available_time = GITHUB_TIMEOUT - build_time
        remaining = available_time - stop_buffer_seconds
        
        if remaining < MIN_REMAINING:
            print(f"[DEBUG] Computed remaining time ({remaining}s) is less than minimum ({MIN_REMAINING}s), using {MIN_REMAINING}s")
            remaining = MIN_REMAINING
        
        return int(remaining)
    
    def _get_time_remaining(self) -> float:
        if self.time_remaining is None:
            return float('inf')
        return max(0.0, self.time_remaining - (time.time() - self.start_time))
    
    def _is_time_expired(self) -> bool:
        return self.time_remaining is not None and self._get_time_remaining() <= 0
    
    # -------------------------------------------------------------------------
    # Resource Management (same as simple_commit_fuzzer_sancov.py)
    # -------------------------------------------------------------------------
    
    def _monitor_resources(self):
        while not self.shutdown_event.is_set():
            try:
                try:
                    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
                    memory = psutil.virtual_memory()
                    memory_percent = memory.percent
                    memory_available_gb = memory.available / (1024**3)
                    
                    max_cpu = max(cpu_percent) if cpu_percent else 0.0
                    avg_cpu = sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0.0
                    
                    status = 'normal'
                    
                    if (avg_cpu >= self.RESOURCE_CONFIG['cpu_critical'] or 
                        memory_available_gb < self.RESOURCE_CONFIG['memory_critical_available_gb']):
                        status = 'critical'
                    elif (avg_cpu >= self.RESOURCE_CONFIG['cpu_warning'] or 
                          memory_available_gb < self.RESOURCE_CONFIG['memory_warning_available_gb']):
                        status = 'warning'
                    
                    with self.resource_lock:
                        self.resource_state['cpu_percent'] = cpu_percent
                        self.resource_state['memory_percent'] = memory_percent
                        self.resource_state['memory_available_gb'] = memory_available_gb
                        self.resource_state['status'] = status
                        self.resource_state['last_update'] = time.time()
                        self.resource_state['max_cpu'] = max_cpu
                        self.resource_state['avg_cpu'] = avg_cpu
                        self.resource_state['memory_total_gb'] = memory.total / (1024**3)
                        self.resource_state['memory_used_gb'] = memory.used / (1024**3)
                    
                    threshold = (self.RESOURCE_CONFIG['max_process_memory_mb_warning'] 
                                if memory_available_gb < self.RESOURCE_CONFIG['memory_warning_available_gb']
                                else self.RESOURCE_CONFIG['max_process_memory_mb'])
                    self._kill_high_memory_processes(threshold_mb=threshold)
                    
                    if status == 'critical':
                        self._handle_critical_resources(cpu_percent, max_cpu, avg_cpu, memory_percent, memory_available_gb, memory.total, memory.used)
                    elif status == 'warning':
                        self._handle_warning_resources()
                        self._log_cpu_usage_by_process_type()
                    
                except (ImportError, AttributeError) as e:
                    print(f"[WARN] psutil not available, skipping resource monitoring: {e}", file=sys.stderr)
                    break
                
                time.sleep(self.RESOURCE_CONFIG['check_interval'])
            except Exception as e:
                print(f"[WARN] Error in resource monitoring: {e}", file=sys.stderr)
                time.sleep(self.RESOURCE_CONFIG['check_interval'])
    
    def _kill_high_memory_processes(self, threshold_mb: Optional[float] = None):
        if threshold_mb is None:
            threshold_mb = self.RESOURCE_CONFIG['max_process_memory_mb']
        
        HIGH_MEMORY_REPORT_THRESHOLD_MB = 14336
        
        try:
            main_pid = os.getpid()
            worker_pids = {}
            if hasattr(self, 'workers'):
                for worker_id, w in enumerate(self.workers, start=1):
                    try:
                        worker_pids[w.pid] = worker_id
                    except (AttributeError, ValueError):
                        pass
            
            pid_to_worker = {}
            tracked_pids = {main_pid}
            tracked_pids.update(worker_pids.keys())
            for pid in list(tracked_pids):
                worker_id = worker_pids.get(pid)
                descendants = self._get_all_descendant_pids(pid)
                tracked_pids.update(descendants)
                if worker_id:
                    for desc_pid in descendants:
                        pid_to_worker[desc_pid] = worker_id
            
            killed_count = 0
            for pid in tracked_pids:
                if pid == main_pid:
                    continue  # Never kill the main fuzzer process
                try:
                    proc = psutil.Process(pid)
                    rss_mb = proc.memory_info().rss / (1024 * 1024)
                    
                    if rss_mb > threshold_mb:
                        name = proc.name()
                        cmdline = ' '.join(proc.cmdline()[:3])
                        print(f"[RESOURCE] Killing process {pid} ({name}) using {rss_mb:.1f}MB RAM (threshold: {threshold_mb}MB)", file=sys.stderr)
                        print(f"  Command: {cmdline}...", file=sys.stderr)
                        
                        if rss_mb >= HIGH_MEMORY_REPORT_THRESHOLD_MB:
                            worker_id = pid_to_worker.get(pid)
                            if worker_id and self.worker_status.get(worker_id):
                                test_name = self.worker_status[worker_id]
                                print(f"  ⚠️  HIGH RAM USAGE: Process used {rss_mb:.1f}MB RAM while processing test: {test_name}", file=sys.stderr)
                            else:
                                print(f"  ⚠️  HIGH RAM USAGE: Process used {rss_mb:.1f}MB RAM (could not determine test)", file=sys.stderr)
                        
                        proc.kill()
                        killed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError, AttributeError):
                    pass
            
            if killed_count > 0:
                print(f"[RESOURCE] Killed {killed_count} process(es) exceeding {threshold_mb}MB RAM threshold", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Error killing high RAM processes: {e}", file=sys.stderr)
    
    def _handle_warning_resources(self):
        pass
    
    def _get_all_descendant_pids(self, pid):
        descendant_pids = set()
        try:
            proc = psutil.Process(pid)
            for child in proc.children(recursive=True):
                try:
                    descendant_pids.add(child.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return descendant_pids
    
    def _log_cpu_usage_by_process_type(self):
        try:
            main_pid = os.getpid()
            worker_pids = set()
            if hasattr(self, 'workers'):
                for w in self.workers:
                    try:
                        worker_pids.add(w.pid)
                    except (AttributeError, ValueError):
                        pass
            
            tracked_pids = {main_pid}
            tracked_pids.update(worker_pids)
            for pid in list(tracked_pids):
                tracked_pids.update(self._get_all_descendant_pids(pid))
            
            process_stats = {
                'typefuzz': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
                'z3': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
                'cvc5': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
                'python': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
                'other': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
            }
            
            cpu_cache = {}
            for pid in tracked_pids:
                try:
                    proc = psutil.Process(pid)
                    proc.cpu_percent()
                    cpu_cache[pid] = proc
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            time.sleep(0.1)
            
            for pid in tracked_pids:
                try:
                    proc = cpu_cache.get(pid)
                    if not proc:
                        proc = psutil.Process(pid)
                    
                    proc_info = proc.as_dict(['name', 'memory_info', 'cmdline'])
                    
                    try:
                        cpu_pct = proc.cpu_percent(interval=None)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        cpu_pct = 0.0
                    
                    rss_mb = proc_info.get('memory_info', {}).rss / (1024 * 1024) if proc_info.get('memory_info') else 0.0
                    cmdline = ' '.join(proc_info.get('cmdline', [])) if proc_info.get('cmdline') else ''
                    name = (proc_info.get('name') or '').lower()
                    
                    if 'typefuzz' in cmdline.lower() or 'typefuzz' in name:
                        process_stats['typefuzz']['count'] += 1
                        process_stats['typefuzz']['cpu_total'] += cpu_pct
                        process_stats['typefuzz']['memory_total_mb'] += rss_mb
                    elif 'z3' in cmdline.lower() or 'z3' in name:
                        process_stats['z3']['count'] += 1
                        process_stats['z3']['cpu_total'] += cpu_pct
                        process_stats['z3']['memory_total_mb'] += rss_mb
                    elif 'cvc5' in cmdline.lower() or 'cvc5' in name:
                        process_stats['cvc5']['count'] += 1
                        process_stats['cvc5']['cpu_total'] += cpu_pct
                        process_stats['cvc5']['memory_total_mb'] += rss_mb
                    elif 'python' in name or 'python' in cmdline.lower():
                        process_stats['python']['count'] += 1
                        process_stats['python']['cpu_total'] += cpu_pct
                        process_stats['python']['memory_total_mb'] += rss_mb
                    else:
                        process_stats['other']['count'] += 1
                        process_stats['other']['cpu_total'] += cpu_pct
                        process_stats['other']['memory_total_mb'] += rss_mb
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError, AttributeError):
                    pass
            
            memory = psutil.virtual_memory()
            system_memory_used_gb = memory.used / (1024**3)
            tracked_memory_mb = sum(stats['memory_total_mb'] for stats in process_stats.values())
            
            print(f"[RESOURCE] CPU usage by process type:", file=sys.stderr)
            total_cpu = 0.0
            for proc_type, stats in process_stats.items():
                if stats['count'] > 0:
                    print(f"  {proc_type}: {stats['count']} process(es), {stats['cpu_total']:.1f}% CPU, {stats['memory_total_mb']:.1f} MB", file=sys.stderr)
                    total_cpu += stats['cpu_total']
            print(f"  Total tracked: {total_cpu:.1f}% CPU, {tracked_memory_mb:.1f} MB RAM", file=sys.stderr)
            print(f"  System total: {system_memory_used_gb:.2f} GB RAM used ({memory.percent:.1f}%)", file=sys.stderr)
            
        except Exception as e:
            print(f"[WARN] Error logging CPU usage by process type: {e}", file=sys.stderr)
    
    def _handle_critical_resources(self, cpu_percent: List[float], max_cpu: float, avg_cpu: float, memory_percent: float, memory_available_gb: float, memory_total: int, memory_used: int):
        try:
            memory_total_gb = memory_total / (1024**3)
            memory_used_gb = memory_used / (1024**3)
            
            issues = []
            if avg_cpu >= self.RESOURCE_CONFIG['cpu_critical']:
                cpu_details = ", ".join([f"core{i+1}:{p:.1f}%" for i, p in enumerate(cpu_percent)])
                issues.append(f"CPU: {avg_cpu:.1f}% avg, {max_cpu:.1f}% max ({cpu_details})")
            if memory_available_gb < self.RESOURCE_CONFIG['memory_critical_available_gb']:
                issues.append(f"RAM: {memory_available_gb:.2f}GB available ({memory_percent:.1f}% used)")
            
            if issues:
                print(f"[RESOURCE] Critical resource usage detected - {', '.join(issues)} - taking action", file=sys.stderr)
            
            self._log_cpu_usage_by_process_type()
        except Exception as e:
            print(f"[RESOURCE] Critical resource usage detected - error formatting details: {e}", file=sys.stderr)
        
        if memory_available_gb < self.RESOURCE_CONFIG['memory_critical_available_gb']:
            self._log_bugs_summary_and_stop()
            return
        
        with self.resource_lock:
            self.resource_state['paused'] = True
        
        try:
            gc.collect()
        except Exception:
            pass
        
        time.sleep(self.RESOURCE_CONFIG['pause_duration'])
        
        with self.resource_lock:
            self.resource_state['paused'] = False
    
    def _calculate_folder_size_mb(self, folder_path: Path) -> float:
        try:
            if folder_path.exists():
                size_bytes = sum(f.stat().st_size for f in folder_path.rglob('*') if f.is_file())
                return size_bytes / (1024 * 1024)
            else:
                return 0.0
        except Exception:
            return 0.0
    
    def _log_bugs_summary_and_stop(self):
        print("\n" + "=" * 60, file=sys.stderr)
        print("CRITICAL RAM DETECTED - STOPPING TO PRESERVE BUGS", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        
        main_bugs = self._collect_bug_files(self.bugs_folder)
        main_bug_count = len(main_bugs)
        main_bugs_size_mb = self._calculate_folder_size_mb(self.bugs_folder)
        
        total_worker_bugs = 0
        worker_folders_info = []
        for worker_id in range(1, self.num_workers + 1):
            worker_bugs_folder = self.bugs_folder / f"worker_{worker_id}"
            worker_bugs = self._collect_bug_files(worker_bugs_folder)
            worker_bug_count = len(worker_bugs)
            total_worker_bugs += worker_bug_count
            
            bugs_size_mb = self._calculate_folder_size_mb(worker_bugs_folder)
            scratch_folder = self.output_dir / f"scratch_{worker_id}"
            scratch_size_mb = self._calculate_folder_size_mb(scratch_folder)
            log_folder = self.output_dir / f"logs_{worker_id}"
            log_size_mb = self._calculate_folder_size_mb(log_folder)
            
            worker_folders_info.append({
                'id': worker_id,
                'bugs': worker_bug_count,
                'bugs_size_mb': bugs_size_mb,
                'scratch_size_mb': scratch_size_mb,
                'log_size_mb': log_size_mb,
                'total_size_mb': bugs_size_mb + scratch_size_mb + log_size_mb
            })
        
        total_bugs = main_bug_count + total_worker_bugs
        
        print(f"\nBUGS SUMMARY:", file=sys.stderr)
        print(f"  Total bugs found: {total_bugs}", file=sys.stderr)
        print(f"  Main bugs folder: {main_bug_count} bugs, {main_bugs_size_mb:.2f} MB", file=sys.stderr)
        print(f"  Worker folders:", file=sys.stderr)
        for info in worker_folders_info:
            print(f"    worker_{info['id']}: {info['bugs']} bugs, {info['total_size_mb']:.2f} MB total", file=sys.stderr)
        
        print(f"\nSTATISTICS:", file=sys.stderr)
        print(f"  Tests processed: {self._get_stat('tests_processed')}", file=sys.stderr)
        print(f"  Bugs found: {self._get_stat('bugs_found')}", file=sys.stderr)
        print(f"  Mutants with new coverage: {self._get_stat('mutants_with_new_coverage')}", file=sys.stderr)
        print(f"  Total new edges: {self._get_stat('total_new_edges')}", file=sys.stderr)
        print(f"  Generations completed: {self._get_stat('generations_completed')}", file=sys.stderr)
        
        print("\n" + "=" * 60, file=sys.stderr)
        print("Stopping fuzzer to preserve found bugs...", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        
        self.shutdown_event.set()
    
    def _check_resource_state(self) -> str:
        with self.resource_lock:
            return self.resource_state.get('status', 'normal')
    
    def _is_paused(self) -> bool:
        with self.resource_lock:
            return self.resource_state.get('paused', False)
    
    def _log_periodic_status(self, global_coverage_map=None):
        """Log periodic status summary for monitoring."""
        elapsed = time.time() - self.start_time
        remaining = self._get_time_remaining()
        
        # Gather worker status
        active_workers = []
        idle_workers = []
        for w_id in range(1, self.num_workers + 1):
            status = self.worker_status.get(w_id)
            if status:
                active_workers.append((w_id, status))
            else:
                idle_workers.append(w_id)
        
        # Queue stats
        queue_size = self._get_queue_size()
        
        # Coverage stats from shared map
        total_edges = 0
        if global_coverage_map is not None:
            try:
                total_edges = sum(1 for b in global_coverage_map if b == 0x00)
            except Exception:
                pass
        
        # Resource stats
        with self.resource_lock:
            cpu_avg = self.resource_state.get('avg_cpu', 0.0)
            mem_used_gb = self.resource_state.get('memory_used_gb', 0.0)
            mem_avail_gb = self.resource_state.get('memory_available_gb', 0.0)
            resource_status = self.resource_state.get('status', 'unknown')
        
        # Calculate rates
        tests_per_min = (self._get_stat('tests_processed') / elapsed * 60) if elapsed > 0 else 0
        edges_per_min = (self._get_stat('total_new_edges') / elapsed * 60) if elapsed > 0 else 0
        
        # Print status block
        print()
        print(f"[STATUS] ═══════════════════════════════════════════════════════")
        print(f"[STATUS] Time: {elapsed:.0f}s elapsed, {remaining:.0f}s remaining ({elapsed/60:.1f}m / {(elapsed+remaining)/60:.1f}m)")
        print(f"[STATUS] Resources: CPU {cpu_avg:.1f}%, Mem {mem_used_gb:.1f}GB used / {mem_avail_gb:.1f}GB avail [{resource_status}]")
        print(f"[STATUS] Queue: {queue_size} total")
        # Check actual process alive status
        workers_alive = 0
        workers_dead = 0
        if hasattr(self, 'workers'):
            for w in self.workers:
                if w.is_alive():
                    workers_alive += 1
                else:
                    workers_dead += 1
        
        print(f"[STATUS] Workers: {len(active_workers)} active, {len(idle_workers)} idle (alive: {workers_alive}, dead: {workers_dead})")
        
        for w_id, test in active_workers:
            print(f"[STATUS]   Worker {w_id}: {test}")
        
        # Disk space info
        free_mb = self._get_free_disk_space_mb()
        pending_mutants = self._count_pending_mutants()
        
        print(f"[STATUS] Coverage: {total_edges} total edges, {self._get_stat('total_new_edges')} new this run")
        print(f"[STATUS] Mutants: {self._get_stat('mutants_created')} created | {self._get_stat('mutants_with_new_coverage')} new cov | {self._get_stat('mutants_with_existing_coverage')} exist cov")
        print(f"[STATUS] Discarded: {self._get_stat('mutants_discarded_no_coverage')} no-cov | {self._get_stat('mutants_discarded_disk_space')} disk-limit")
        print(f"[STATUS] Disk: {free_mb:.0f}MB free, {pending_mutants} pending mutants (max: {self.max_pending_mutants})")
        print(f"[STATUS] Tests: {self._get_stat('tests_processed')} processed, {len(self.excluded_tests)} excluded")
        print(f"[STATUS] Favored: {self.pending_favored.value} pending, {sum(1 for v in self.test_favored.values() if v)} total")
        print(f"[STATUS] Generations: {self._get_stat('generations_completed')} completed")
        print(f"[STATUS] Bugs: {self._get_stat('bugs_found')} found")
        print(f"[STATUS] Rate: {tests_per_min:.1f} tests/min, {edges_per_min:.1f} new edges/min")
        print(f"[STATUS] ═══════════════════════════════════════════════════════")
        print()
        sys.stdout.flush()
    
    # -------------------------------------------------------------------------
    # AFL-style Coverage Tracking
    # -------------------------------------------------------------------------
    
    def _create_shared_memory(self, name: str) -> mmap.mmap:
        """Create a shared memory region for trace_bits (where CVC5 writes edge hits).
        
        This is the trace_bits buffer where coverage_agent.cpp writes edge hits.
        Initialize to 0x00 (no hits). Non-zero bytes after running = edges hit.
        
        Note: This is NOT the global_coverage_map. The global_coverage_map is shared
        across all workers and tracks which edges have ever been seen.
        """
        shm_path = f"/dev/shm/{name}"
        
        # Create the shared memory file
        fd = os.open(shm_path, os.O_CREAT | os.O_RDWR, 0o666)
        try:
            # Initialize to all 0x00 (no coverage yet)
            # coverage_agent.cpp increments bytes when edges are hit
            os.ftruncate(fd, AFL_MAP_SIZE)
            mm = mmap.mmap(fd, AFL_MAP_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
            mm.write(b'\x00' * AFL_MAP_SIZE)
            mm.seek(0)
            return mm
        finally:
            os.close(fd)
    
    def _read_shared_memory(self, name: str) -> Optional[bytes]:
        """Read coverage bitmap from shared memory."""
        shm_path = f"/dev/shm/{name}"
        try:
            fd = os.open(shm_path, os.O_RDONLY)
            try:
                mm = mmap.mmap(fd, AFL_MAP_SIZE, mmap.MAP_SHARED, mmap.PROT_READ)
                data = mm.read(AFL_MAP_SIZE)
                mm.close()
                return data
            finally:
                os.close(fd)
        except (OSError, ValueError) as e:
            return None
    
    def _cleanup_shared_memory(self, name: str):
        """Remove shared memory file."""
        shm_path = f"/dev/shm/{name}"
        try:
            os.unlink(shm_path)
        except OSError:
            pass
    
    def _has_new_bits(self, trace_bits: bytes, coverage_map: bytes) -> Tuple[bool, int, bytes]:
        """
        Check if trace_bits has any new coverage compared to coverage_map.
        Returns (has_new, new_edge_count, updated_coverage_map).
        
        coverage_map: 0xFF = edge not seen, 0x00 = edge seen
        trace_bits: 0x00 = edge not hit, non-zero = edge hit (count)
        """
        new_edges = 0
        updated = bytearray(coverage_map)
        
        for i in range(AFL_MAP_SIZE):
            if trace_bits[i] and coverage_map[i] == 0xff:
                # New edge found
                updated[i] = 0x00
                new_edges += 1
        
        return new_edges > 0, new_edges, bytes(updated)
    
    def _count_edges(self, coverage_map: bytes) -> int:
        """Count number of covered edges (0x00 bytes = seen edges)."""
        return sum(1 for b in coverage_map if b == 0x00)
    
    # -------------------------------------------------------------------------
    # Typefuzz Execution
    # -------------------------------------------------------------------------
    
    # Z3 SMT2 files don't have CVC5-style headers (COMMAND-LINE, DISABLE-TESTER)
    # So we don't need to extract directives from test files
    
    def _get_solver_clis(self, test_path: Optional[Path] = None) -> str:
        """Get solver CLI string for typefuzz (z3 + cvc5).
        
        Z3 is the primary solver. CVC5 is used for differential testing if available.
        Z3 uses: smt.threads=1 memory_max_size=2048 model_validate=true
        CVC5 uses: --check-models --check-proofs --strings-exp
        
        Note: Z3 SMT2 files don't have headers, so we don't extract directives.
        """
        solvers = [self.z3_cmd]
        
        # Add CVC5 for differential testing if available
        if self.cvc5_path:
            # Base CVC5 flags for differential testing
            base_flags = "--check-models --check-proofs --strings-exp"
            solvers.append(f"{self.cvc5_path} {base_flags}")
        
        return ";".join(solvers)
    
    def _collect_bug_files(self, folder: Path) -> List[Path]:
        if not folder.exists():
            return []
        return list(folder.glob("*.smt2")) + list(folder.glob("*.smt"))
    
    def _run_seed_calibration(
        self,
        test_path: Path,
        shm_id: int,
    ) -> Tuple[int, float]:
        """
        Run seed directly on Z3 for calibration (no mutations).
        Returns (exit_code, runtime_seconds).
        """
        import subprocess
        
        # Build Z3 command with the seed file
        cmd = self._get_solver_clis(test_path).split(";")[0]  # Get Z3 command (first solver)
        cmd_parts = cmd.strip().split() + [str(test_path)]
        
        # Set up environment with shared memory ID for coverage
        env = os.environ.copy()
        env['__AFL_SHM_ID'] = str(shm_id)
        
        # Use configured per-test timeout
        timeout = self.per_test_timeout
        
        # Run Z3 with timeout
        t0 = time.time()
        try:
            result = subprocess.run(
                cmd_parts,
                env=env,
                capture_output=True,
                timeout=timeout,
            )
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            exit_code = -1
        except Exception:
            exit_code = -1
        
        runtime = time.time() - t0
        return exit_code, runtime
    
    def _run_inline_typefuzz(
        self,
        test_path: Path,
        worker_id: int,
        scratch_folder: Path,
        bugs_folder: Path,
        generation: int,
        shm_id: str,
        shm,
        global_coverage_map: multiprocessing.Array,
        coverage_map_lock: multiprocessing.Lock,
        timeout: int = 120,
        iterations: int = None,  # Dynamic iterations based on AFL score
        recipe_recorder=None,  # Optional recipe recorder
    ) -> Tuple[int, List[Path], float, List[Path]]:
        """
        Run typefuzz inline (no subprocess).
        IMPORTANT: for iterations>1, we measure coverage per mutant execution.
        This function clears/reads the AFL shm bitmap for each mutant,
        and queues each mutant immediately based on its own coverage outcome.
        Returns (exit_code, bug_files, runtime_seconds_total, []).
        """
        if not test_path.exists():
            return (1, [], 0.0, [])
        
        # Use provided iterations or fall back to max for time budget
        max_iterations = 500  # Increased from 250 for more recipes
        num_iterations = iterations if iterations is not None else max_iterations
        
        scratch_folder.mkdir(parents=True, exist_ok=True)
        bugs_folder.mkdir(parents=True, exist_ok=True)
        
        start_time = time.time()
        bug_files = []
        
        # Set random seed BEFORE parsing for reproducibility
        # Each test gets the same seed, so mutation sequence depends only on test content
        random.seed(self.seed)
        
        mutator = InlineTypeFuzz(test_path)
        if not mutator.parse():
            return (0, [], time.time() - start_time, [])
        
        env = os.environ.copy()
        env['__AFL_SHM_ID'] = shm_id
        env['LLVM_PROFILE_FILE'] = str(self.profraw_dir / f"worker_{worker_id}_%p_%m.profraw")
        env['ASAN_OPTIONS'] = 'abort_on_error=0:detect_leaks=0'
        
        solver_clis = self._get_solver_clis(test_path)
        solver_list = solver_clis.split(";")
        z3_cmd = solver_list[0]
        cvc5_cmd = solver_list[1] if len(solver_list) > 1 else None

        # Per-test summary (avoid logging per-iteration unless it matters).
        produced = 0
        queued_new = 0
        queued_existing = 0
        discarded_no_cov = 0
        new_edges_total = 0
        
        # Track consecutive timeouts to stop early if test keeps timing out
        consecutive_timeouts = 0
        MAX_CONSECUTIVE_TIMEOUTS = 3
        
        for i in range(num_iterations):
            formula_str, success = mutator.mutate()
            if not success:
                continue

            produced += 1
            iteration = i + 1  # 1-indexed for consistency with yinyang
            
            # Only run solver every modulo iterations (like typefuzz -m flag)
            if iteration % self.modulo != 0:
                continue
            
            # Record recipe ONLY for mutations where solver actually runs
            if recipe_recorder:
                recipe_recorder.record(str(test_path), iteration)

            mutant_path = scratch_folder / f"mutant_{worker_id}_{i}.smt2"
            with open(mutant_path, 'w') as f:
                f.write(formula_str)

            # Per-mutant coverage: clear shm before running solvers.
            try:
                shm.seek(0)
                shm.write(b'\x00' * AFL_MAP_SIZE)
                shm.seek(0)
            except Exception:
                pass

            t0 = time.time()
            # Build solver list (Z3 required, CVC5 optional)
            solvers_list = [z3_cmd]
            if cvc5_cmd:
                solvers_list.append(cvc5_cmd)
            is_bug, bug_type, all_timeout = mutator.run_solvers_differential(mutant_path, solvers_list, timeout, env)
            t1 = time.time()
            runtime_i = t1 - t0
            
            # Track consecutive timeouts
            if all_timeout:
                consecutive_timeouts += 1
                if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
                    print(f"[WORKER {worker_id}] [INLINE] Stopping {test_path.name} early: {consecutive_timeouts} consecutive timeouts (iter={iteration}/{num_iterations})", flush=True)
                    break
            else:
                consecutive_timeouts = 0  # Reset counter on successful run

            if is_bug:
                # Match typefuzz naming: {bugtype}-{solver}-{seed}-{random}.smt2
                seed_name = test_path.stem  # e.g., "arith-eq" from "arith-eq.smt2"
                random_suffix = uuid.uuid4().hex[:8]
                bug_filename = f"{bug_type}-cvc5-{seed_name}-{random_suffix}.smt2"
                bug_path = bugs_folder / bug_filename
                shutil.copy(mutant_path, bug_path)
                bug_files.append(bug_path)
                self._inc_stat('bugs_found')
                # Match yinyang behavior: stop mutating this seed when bug found
                # to avoid finding duplicate/similar bugs from same seed
                print(f"[WORKER {worker_id}] [INLINE] Bug found ({bug_type}) - stopping iteration for {test_path.name}")
                try:
                    mutant_path.unlink()
                except Exception:
                    pass
                break

            # Read coverage from shared memory (trace_bits) for this mutant execution.
            try:
                shm.seek(0)
                trace_bits = shm.read(AFL_MAP_SIZE)
            except Exception:
                trace_bits = b'\x00' * AFL_MAP_SIZE

            edges_hit = sum(1 for b in trace_bits if b != 0)
            
            # Hash coverage pattern for path frequency tracking (AFL's n_fuzz)
            coverage_hash = self._hash_coverage(trace_bits) if edges_hit > 0 else None

            # Check for new coverage using SHARED global_coverage_map (with lock)
            has_new = False
            new_edges = 0

            with coverage_map_lock:
                coverage_bytes = bytes(global_coverage_map[:])
                for j in range(AFL_MAP_SIZE):
                    if trace_bits[j] and coverage_bytes[j] == 0xff:
                        global_coverage_map[j] = 0x00
                        new_edges += 1
                        has_new = True

            if has_new:
                self._inc_stat('total_new_edges', new_edges)
                new_edges_total += new_edges

            # Decide coverage outcome and queue the mutant
            if has_new:
                cov_rank = 0  # NEW coverage gets priority
                queued_new += 1
            elif edges_hit > 0:
                cov_rank = 1  # EXISTING coverage
                queued_existing += 1
            else:
                # No coverage at all - discard
                discarded_no_cov += 1
                self._inc_stat('mutants_discarded_no_coverage')
                try:
                    mutant_path.unlink()
                except Exception:
                    pass
                continue

            # Queue the mutant: (runtime, new_cov_rank, generation, seq, path_str)
            pending_name = f"gen{generation+1}_w{worker_id}_iter{i}_{mutant_path.name}"
            pending_path = self.pending_mutants_dir / pending_name
            try:
                shutil.move(str(mutant_path), str(pending_path))
            except Exception:
                continue

            self._inc_stat('mutants_created')
            if cov_rank == 0:
                self._inc_stat('mutants_with_new_coverage')
            else:
                self._inc_stat('mutants_with_existing_coverage')

            # Track path frequency (AFL's n_fuzz) using coverage hash
            path_freq = 1
            if coverage_hash:
                path_freq = self._update_path_frequency(coverage_hash, str(pending_path))
            
            # Update edge ownership (AFL's tc_ref) using trace_bits
            if edges_hit > 0:
                self._update_edge_ownership(trace_bits, runtime_i * 1000, str(pending_path))

            # Set newcomer bonus for new mutants
            # Mutants with NEW coverage get big bonus (8x) to encourage exploration
            # Mutants with existing coverage get smaller bonus (2x)
            newcomer_bonus = 8 if has_new else 2
            self._set_newcomer(str(pending_path), newcomer_bonus)
            
            # Update running averages for score calculation
            self._update_running_averages(runtime_i * 1000, edges_hit)
            
            # Store calibration data for scoring (S and C factors)
            self._store_calibration_data(str(pending_path), runtime_i, edges_hit)

            mutant_item = (runtime_i, cov_rank, generation + 1, self._next_seq(), str(pending_path))

            # Buffer mutants: seed phase or regular buffer
            if generation == 0 and not self.seed_phase_done.is_set():
                self._seed_phase_buffer_mutants([mutant_item])
            else:
                self._buffer_mutants([mutant_item])
        
        # Explicit cleanup to prevent ANTLR memory leak
        del mutator

        # CRITICAL: Merge and cleanup profraw files after each inline test
        # Each test generates 250 iterations × 2 solvers × ~16MB = ~8GB of profraw files
        # Without cleanup, disk fills up after just 1-2 tests
        # Note: PGO is disabled by default, so this cleanup may not be needed
        self._cleanup_worker_profraw(worker_id)

        # Log summary for this test
        if produced > 0:
            print(f"[WORKER {worker_id}] [INLINE] {test_path.name}: iter={num_iterations}, produced={produced}, new={queued_new} (+{new_edges_total} edges), existing={queued_existing}, discarded={discarded_no_cov}")
        
        # Return empty mutant_files since mutants are already queued individually
        return (0, bug_files, time.time() - start_time, [])
    
    def _run_typefuzz(
        self,
        test_path: Path,
        worker_id: int,
        scratch_folder: Path,
        log_folder: Path,
        bugs_folder: Path,
        shm_id: str,
        per_test_timeout: Optional[float] = None,
        keep_mutants: bool = True,
        iterations: int = None,  # Dynamic iterations based on AFL score
    ) -> Tuple[int, List[Path], float, List[Path]]:
        """
        Run typefuzz on a test file.
        Returns (exit_code, bug_files, runtime, mutant_files).
        """
        if not test_path.exists():
            print(f"[WORKER {worker_id}] Error: Test file not found: {test_path}", file=sys.stderr)
            return (1, [], 0.0, [])
        
        # Use provided iterations or fall back to max for time budget
        max_iterations = 500  # Increased from 250 for more recipes
        num_iterations = iterations if iterations is not None else max_iterations
        
        # Clean scratch/log folders but keep bugs
        for folder in [scratch_folder, log_folder]:
            shutil.rmtree(folder, ignore_errors=True)
            folder.mkdir(parents=True, exist_ok=True)
        bugs_folder.mkdir(parents=True, exist_ok=True)
        
        # Build solver command (Z3 SMT2 files don't have headers)
        solver_clis = self._get_solver_clis(test_path)
        
        # typefuzz -i N -k (N iterations, keep mutants)
        cmd = [
            "typefuzz",
            "-i", str(num_iterations),
            "-m", str(self.modulo),
            "--seed", str(self.seed),
            "--timeout", str(self.per_test_timeout),
            "--bugs", str(bugs_folder),
            "--scratch", str(scratch_folder),
            "--logfolder", str(log_folder),
        ]
        if keep_mutants:
            cmd.append("-k")  # Keep mutants
        cmd.extend([solver_clis, str(test_path)])
        
        print(f"[WORKER {worker_id}] Running typefuzz on: {test_path.name} (timeout: {per_test_timeout:.0f}s)" if per_test_timeout else f"[WORKER {worker_id}] Running typefuzz on: {test_path.name}")
        
        start_time = time.time()
        
        try:
            env = os.environ.copy()
            # Set shared memory ID for coverage agent (afl_shm_{ID})
            env['__AFL_SHM_ID'] = shm_id
            # PGO profiling - use %p (pid) and %m (merge pool) for unique files per solver invocation
            # typefuzz runs solvers multiple times, each needs its own profraw file
            # Use %c for continuous mode - writes profile data continuously (survives crashes/kills)
            # Note: PGO is disabled by default, so profraw files won't be generated
            profraw_pattern = self.profraw_dir / f"worker_{worker_id}_%p_%m.profraw"
            env['LLVM_PROFILE_FILE'] = str(profraw_pattern)
            # Disable ASAN leak detection
            env['ASAN_OPTIONS'] = 'abort_on_error=0:detect_leaks=0'
            
            # DEBUG: Count profraw files before running test
            profraw_before = len(list(self.profraw_dir.glob("*.profraw")))
            if self._get_stat('tests_processed') < 5:  # Only log first few tests
                print(f"[WORKER {worker_id}] [PGO DEBUG] LLVM_PROFILE_FILE={profraw_pattern}, profraw_files_before={profraw_before}")
            
            if per_test_timeout and per_test_timeout > 0:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=per_test_timeout, env=env, start_new_session=True)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, env=env, start_new_session=True)
            
            exit_code = result.returncode
            runtime = time.time() - start_time
            bug_files = self._collect_bug_files(bugs_folder)
            
            # Collect mutant files from scratch folder
            mutant_files = list(scratch_folder.glob("*.smt2")) + list(scratch_folder.glob("*.smt"))
            
            # DEBUG: Count profraw files after running test
            profraw_after = len(list(self.profraw_dir.glob("*.profraw")))
            profraw_new = profraw_after - profraw_before
            if profraw_new > 0 or self._get_stat('tests_processed') < 5:
                # List new profraw files for debugging
                new_files = list(self.profraw_dir.glob(f"worker_{worker_id}_*.profraw"))
                sizes = [(f.name, f.stat().st_size) for f in new_files[-3:]]  # Last 3
                print(f"[WORKER {worker_id}] [PGO DEBUG] profraw_after={profraw_after} (new:{profraw_new}), recent_files={sizes}")
            
            # Cleanup profraw files after each test to prevent disk exhaustion
            self._cleanup_worker_profraw(worker_id)
            
            return (exit_code, bug_files, runtime, mutant_files)
            
        except subprocess.TimeoutExpired:
            runtime = time.time() - start_time
            self._cleanup_worker_profraw(worker_id)  # Cleanup even on timeout
            return (124, [], runtime, [])
        except Exception as e:
            print(f"[WORKER {worker_id}] Error running typefuzz: {e}", file=sys.stderr)
            runtime = time.time() - start_time
            self._cleanup_worker_profraw(worker_id)  # Cleanup even on error
            return (1, [], runtime, [])
    
    def _handle_exit_code(
        self,
        test_name: str,
        exit_code: int,
        bug_files: List[Path],
        runtime: float,
        worker_id: int,
    ) -> str:
        """Handle typefuzz exit code. Returns action: 'requeue', 'remove', or 'continue'."""
        if exit_code == self.EXIT_CODE_BUGS_FOUND:
            if bug_files:
                print(f"[WORKER {worker_id}] ✓ Exit code 10: Found {len(bug_files)} bug(s) on {test_name}")
                with self.bugs_lock:
                    for bug_file in bug_files:
                        try:
                            dest = self.bugs_folder / bug_file.name
                            if dest.exists():
                                timestamp = int(time.time())
                                dest = self.bugs_folder / f"{bug_file.stem}_{timestamp}{bug_file.suffix}"
                            shutil.move(str(bug_file), str(dest))
                            self._inc_stat('bugs_found')
                        except Exception as e:
                            print(f"[WORKER {worker_id}] Warning: Failed to move bug file {bug_file}: {e}", file=sys.stderr)
            else:
                print(f"[WORKER {worker_id}] Warning: Exit code 10 but no bugs found for {test_name}", file=sys.stderr)
            return 'requeue'
        
        elif exit_code == self.EXIT_CODE_UNSUPPORTED:
            print(f"[WORKER {worker_id}] ⚠ Exit code 3: {test_name} (unsupported operation - removing)")
            self._inc_stat('tests_removed_unsupported')
            return 'remove'
        
        elif exit_code == self.EXIT_CODE_SUCCESS:
            print(f"[WORKER {worker_id}] Exit code 0: {test_name} (runtime: {runtime:.1f}s)")
            return 'continue'
        
        elif exit_code == 124:
            print(f"[WORKER {worker_id}] ⏱ Timeout: {test_name}")
            self._inc_stat('tests_removed_timeout')
            return 'remove'
        
        else:
            print(f"[WORKER {worker_id}] Exit code {exit_code}: {test_name}")
            return 'continue'
    
    # -------------------------------------------------------------------------
    # Worker Process
    # -------------------------------------------------------------------------
    
    def _worker_process(self, worker_id: int, global_coverage_map: multiprocessing.Array, 
                        coverage_map_lock: multiprocessing.Lock, recipe_output_path: Optional[str] = None):
        """
        Worker process that processes tests and tracks coverage.
        Uses per-worker shared memory for trace_bits (where CVC5 writes edge hits).
        Uses SHARED global_coverage_map across all workers for tracking unique edges seen.
        
        global_coverage_map: array where 0xFF = edge not seen yet, 0x00 = edge seen
        
        OPTIMIZATION: Shared memory is created ONCE per worker and reused (cleared between tests).
        """
        print(f"[WORKER {worker_id}] Started", flush=True)
        
        # Initialize recipe recorder if enabled
        recipe_recorder = None
        if recipe_output_path:
            RecipeRecorder, get_worker_recipe_path, _ = _import_recipes()
            worker_recipe_path = get_worker_recipe_path(recipe_output_path, worker_id - 1)
            recipe_recorder = RecipeRecorder(worker_recipe_path, self.seed, worker_id=worker_id - 1)
            print(f"[WORKER {worker_id}] Recording recipes to: {worker_recipe_path}", file=sys.stderr)
        
        # Counter for periodic GC and worker restart
        tests_processed_this_worker = 0
        tests_since_gc = 0
        GC_INTERVAL = 50
        MAX_TESTS = self.RESOURCE_CONFIG['max_tests_per_worker']
        
        # Create per-worker folders
        scratch_folder = self.output_dir / f"scratch_{worker_id}"
        log_folder = self.output_dir / f"logs_{worker_id}"
        bugs_folder = self.bugs_folder / f"worker_{worker_id}"
        
        for folder in [scratch_folder, log_folder, bugs_folder]:
            folder.mkdir(parents=True, exist_ok=True)
        
        # Create per-worker shared memory ONCE (reused for all tests)
        shm_id = f"{worker_id}"
        shm_name = f"afl_shm_{shm_id}"
        shm_path = f"/dev/shm/{shm_name}"
        
        try:
            shm = self._create_shared_memory(shm_name)
        except Exception as e:
            print(f"[WORKER {worker_id}] Fatal: Could not create shared memory: {e}", file=sys.stderr)
            return
        
        try:
            while not self.shutdown_event.is_set():
                try:
                    # Mark worker as idle while waiting for work
                    self.worker_status[worker_id] = None
                    
                    if self._is_paused():
                        resource_status = self._check_resource_state()
                        print(f"[WORKER {worker_id}] Paused due to {resource_status} resource usage", file=sys.stderr)
                        time.sleep(self.RESOURCE_CONFIG['pause_duration'])
                        continue
                    
                    # Get test from work queue
                    test_item = self._queue_pop(timeout=1.0)
                    if test_item is None:
                        if self.shutdown_event.is_set() or self._is_time_expired():
                            break
                        continue
                    
                    if self._is_time_expired():
                        # Put back and exit
                        self._queue_push(test_item)
                        break
                    
                    # Check resource state
                    resource_status = self._check_resource_state()
                    if resource_status == 'warning':
                        time.sleep(2)
                    elif resource_status == 'critical':
                        self._queue_push(test_item)
                        time.sleep(self.RESOURCE_CONFIG['pause_duration'])
                        continue
                    
                    # Parse test item: (runtime, new_cov_rank, generation, seq, test_path_str)
                    runtime_priority, new_cov_rank, generation, seq, test_path = test_item
                    original_test_path = test_path  # Keep original for re-queueing
                    
                    # Handle string paths:
                    # - Seeds (generation==0): relative to tests_root
                    # - Mutants (generation>0): stored as full path string
                    if isinstance(test_path, str):
                        if generation == 0:
                            test_path = self.tests_root / test_path
                        else:
                            test_path = Path(test_path)
                    
                    test_name = test_path.name if isinstance(test_path, Path) else Path(test_path).name
                    test_path_str = str(test_path)
                    is_mutant = generation > 0
                    is_calibration = generation == 0 and not self.calibration_done.is_set()
                    
                    # ---------------------------------------------------------------
                    # AFL-style scoring: calculate iterations based on perf_score
                    # ---------------------------------------------------------------
                    if is_calibration:
                        # CALIBRATION PHASE: Run seed directly (no mutations!)
                        # Just execute CVC5 to get timing and coverage baseline
                        perf_score = 100.0  # Neutral score for calibration
                        dynamic_iterations = 0  # No mutations during calibration
                    elif generation == 0:
                        # POST-CALIBRATION: Seeds re-queued with proper score
                        # Use ACTUAL edges from calibration data, not average!
                        runtime_ms = runtime_priority * 1000  # Convert to ms
                        
                        # Look up actual edge count from calibration
                        with self.calibration_data_lock:
                            cal_data = self.calibration_data.get(test_path_str)
                        if cal_data:
                            actual_edges = cal_data[1]  # (runtime_sec, edges_hit, perf_score, weight)
                        else:
                            # Seed not found in calibration_data - use avg_coverage as fallback
                            # Use max(1, round()) to avoid 0 edges which would make C=1.0
                            actual_edges = max(1, int(round(self._get_avg_coverage())))
                        
                        path_freq = self._get_test_path_frequency(test_path_str)
                        owned_edges = self._get_owned_edges_count(test_path_str)
                        
                        # Get individual factors for debug logging
                        S = self._get_speed_base(runtime_ms)
                        C = self._get_coverage_multiplier(actual_edges)
                        N, _ = self._get_newcomer_multiplier(test_path_str)
                        D = self._get_depth_multiplier(generation)
                        F = self._get_rarity_multiplier(path_freq)
                        U = self._get_owned_edges_multiplier(owned_edges)
                        perf_score = S * C * N * D * F * U
                        dynamic_iterations = self._score_to_iterations(perf_score)
                    else:
                        # Mutants: use parent's edges from calibration if available, else average
                        runtime_ms = runtime_priority * 1000  # Convert to ms
                        
                        # Try to get actual edges from calibration (for mutants from known seeds)
                        with self.calibration_data_lock:
                            cal_data = self.calibration_data.get(test_path_str)
                        if cal_data:
                            actual_edges = cal_data[1]  # Has been calibrated
                        else:
                            # New mutant without calibration - use avg_coverage directly
                            # Don't convert to int (which would round 0.6 to 0)
                            actual_edges = max(1, int(round(self._get_avg_coverage())))  # At least 1
                        
                        path_freq = self._get_test_path_frequency(test_path_str)
                        owned_edges = self._get_owned_edges_count(test_path_str)
                        
                        # Get individual factors for debug logging
                        S = self._get_speed_base(runtime_ms)
                        C = self._get_coverage_multiplier(actual_edges)
                        N, _ = self._get_newcomer_multiplier(test_path_str)
                        D = self._get_depth_multiplier(generation)
                        F = self._get_rarity_multiplier(path_freq)
                        U = self._get_owned_edges_multiplier(owned_edges)
                        perf_score = S * C * N * D * F * U
                        dynamic_iterations = self._score_to_iterations(perf_score)
                    
                    # Log test pickup with AFL score factors
                    # Log EVERY seed to see all decision points, but only some mutants
                    queue_size = self._get_queue_size()
                    should_log = (generation == 0) or is_mutant  # Log all seeds, all mutants
                    if should_log:
                        if is_calibration:
                            test_type = "seed[CAL]"
                            print(f"[W{worker_id}] {test_type} {test_name} iter=0 q={queue_size}", flush=True)
                        else:
                            test_type = f"gen{generation}" if is_mutant else "seed"
                            # Show AFL score factors: S(speed) C(cov) N(new) D(depth) F(rare) U(own) + actual edges (e)
                            print(f"[W{worker_id}] {test_type} {test_name} e={actual_edges} S={S} C={C:.1f} N={N:.0f} D={D} F={F:.1f} U={U:.1f} → score={perf_score:.0f} iter={dynamic_iterations} q={queue_size}", flush=True)
                    
                    # Mark worker as busy
                    self.worker_status[worker_id] = test_name
                    
                    # Decrement newcomer bonus after processing (skip during calibration)
                    if not is_calibration:
                        self._decrement_newcomer(test_path_str)
                    
                    # Clear shared memory for this test (fast memset, no syscalls)
                    shm.seek(0)
                    shm.write(b'\x00' * AFL_MAP_SIZE)
                    shm.seek(0)
                    
                    test_path_obj = test_path if isinstance(test_path, Path) else Path(test_path)
                    
                    if is_calibration:
                        # CALIBRATION: Run seed directly on CVC5 (no mutations!)
                        exit_code, runtime = self._run_seed_calibration(test_path_obj, shm_id)
                        bug_files = []
                        mutant_files = []
                        # Only exclude tests with unsupported operations or timeouts
                        # Exit code 1 is common for many valid CVC5 tests (e.g., expected failures)
                        # Match simple_commit_fuzzer behavior: only exclude on UNSUPPORTED (3) or timeout
                        if exit_code == self.EXIT_CODE_UNSUPPORTED:
                            action = 'remove'
                            print(f"[WORKER {worker_id}] [CAL] {test_name} (runtime: {runtime:.1f}s) - exit code {exit_code} (unsupported)", flush=True)
                        elif exit_code == -1:  # Timeout
                            action = 'remove'
                            print(f"[WORKER {worker_id}] [CAL] {test_name} (runtime: {runtime:.1f}s) - timeout", flush=True)
                        else:
                            action = 'keep'
                            print(f"[WORKER {worker_id}] [CAL] {test_name} (runtime: {runtime:.1f}s) - exit code {exit_code}", flush=True)
                    else:
                        # Run typefuzz (inline or subprocess) with dynamic iterations
                        time_remaining = self._get_time_remaining()
                        
                        if self.use_inline_mode:
                            # Inline mode handles coverage per-mutant and queues directly
                            exit_code, bug_files, runtime, mutant_files = self._run_inline_typefuzz(
                                test_path_obj, worker_id, scratch_folder, bugs_folder,
                                generation, shm_id, shm, global_coverage_map, coverage_map_lock,
                                timeout=self.per_test_timeout,
                                iterations=dynamic_iterations,
                                recipe_recorder=recipe_recorder,
                            )
                        else:
                            exit_code, bug_files, runtime, mutant_files = self._run_typefuzz(
                                test_path_obj, worker_id, scratch_folder, log_folder, bugs_folder, shm_id,
                                per_test_timeout=time_remaining if self.time_remaining and time_remaining > 0 else None,
                                keep_mutants=True,
                                iterations=dynamic_iterations,
                            )
                        
                        # Handle exit code
                        action = self._handle_exit_code(test_name, exit_code, bug_files, runtime, worker_id)
                    self._inc_stat('tests_processed')
                    
                    # Track fuzz_level for AFL++ probabilistic skipping
                    # Increment only after actual fuzzing (not calibration)
                    if not is_calibration:
                        current_level = self.test_fuzz_level.get(test_path_str, 0)
                        self.test_fuzz_level[test_path_str] = current_level + 1
                        
                        # Update pending_favored if this was a favored test
                        if self.test_favored.get(test_path_str, False) and current_level == 0:
                            with self.pending_favored.get_lock():
                                self.pending_favored.value = max(0, self.pending_favored.value - 1)

                    # AFL++-style calibration phase accounting
                    if is_calibration:
                        # Read coverage from shm to get edges_hit for this seed
                        shm.seek(0)
                        trace_bits_calib = shm.read(AFL_MAP_SIZE)
                        edges_hit_calib = sum(1 for b in trace_bits_calib if b != 0)
                        
                        # Hash coverage pattern and track frequency
                        if edges_hit_calib > 0:
                            coverage_hash = self._hash_coverage(trace_bits_calib)
                            self._update_path_frequency(coverage_hash, test_path_str)
                            # Update edge ownership (AFL's tc_ref)
                            self._update_edge_ownership(trace_bits_calib, runtime * 1000, test_path_str)
                            # Update top_rated for favored marking (AFL's update_bitmap_score)
                            self._update_top_rated(test_path_str, trace_bits_calib, runtime * 1000)
                        
                        # Update running averages with calibration data
                        self._update_running_averages(runtime * 1000, edges_hit_calib)
                        
                        # Store seed info for re-queuing after calibration
                        # Format: (runtime, edges_hit, test_path_str)
                        with self._calibrated_seeds_lock:
                            self._calibrated_seeds.append((runtime, edges_hit_calib, test_path_str))
                        
                        # Decrement seeds remaining
                        remaining = None
                        with self.seeds_remaining.get_lock():
                            if self.seeds_remaining.value > 0:
                                self.seeds_remaining.value -= 1
                            remaining = self.seeds_remaining.value
                        
                        # Log calibration progress every 10 seeds or for slow tests (>2s)
                        if remaining % 10 == 0 or runtime > 2.0:
                            print(f"[CAL] {test_name}: {runtime:.2f}s, {edges_hit_calib} edges, {remaining} left")
                        
                        if remaining == 0:
                            self.calibration_done.set()
                            avg_rt = self._get_avg_runtime_ms()
                            avg_cov = self._get_avg_coverage()
                            print(f"[INFO] Calibration complete: avg_runtime={avg_rt:.1f}ms, avg_coverage={avg_cov:.1f} edges", flush=True)
                            
                            # Warn if no coverage detected during calibration
                            if avg_cov < 0.01:
                                print(f"[WARNING] ⚠️  No coverage detected during calibration!", flush=True)
                                print(f"[WARNING] This may indicate:", flush=True)
                                print(f"[WARNING]   - Instrumented functions are not on the hot path for seed tests", flush=True)
                                print(f"[WARNING]   - Tests may require specific flags that aren't being used", flush=True)
                                print(f"[WARNING] AFL-style scoring will have limited effectiveness.", flush=True)
                                print(f"[WARNING] Mutations may still discover coverage - continuing...", flush=True)
                            
                            print(f"[INFO] Re-queuing {len(self._calibrated_seeds)} seeds with AFL-style scoring...", flush=True)
                    
                    # Periodic garbage collection to prevent memory bloat
                    tests_since_gc += 1
                    tests_processed_this_worker += 1
                    if tests_since_gc >= GC_INTERVAL:
                        gc.collect()
                        tests_since_gc = 0
                    
                    # Exit worker after MAX_TESTS to prevent memory leaks
                    if tests_processed_this_worker >= MAX_TESTS:
                        print(f"[WORKER {worker_id}] Restarting after {MAX_TESTS} tests (memory leak prevention)")
                        break
                    
                    # Track excluded seed tests (unsupported/timeout) to avoid re-adding on refill
                    if action == 'remove' and generation == 0:
                        original_test_id = test_item[4]  # path_str is at index 4 in new format
                        current_excluded = list(self.excluded_tests)
                        if original_test_id not in current_excluded:
                            self.excluded_tests.append(original_test_id)
                            print(f"[WORKER {worker_id}] [EXCLUDE] {test_name} (id={original_test_id}) added to exclusion list ({len(current_excluded)+1} total)")
                            sys.stdout.flush()
                    elif action == 'remove':
                        print(f"[WORKER {worker_id}] [DEBUG] Not excluding {test_name}: generation={generation}, action={action}")
                        sys.stdout.flush()
                    
                    # Coverage tracking and mutant processing
                    # NOTE: Inline mode handles its own per-mutant coverage tracking
                    if not self.use_inline_mode:
                        # Read coverage from shared memory (trace_bits)
                        shm.seek(0)
                        trace_bits = shm.read(AFL_MAP_SIZE)
                        
                        # Count edges hit in this execution
                        edges_hit = sum(1 for b in trace_bits if b != 0)
                        
                        # Debug: log if we're getting any coverage at all (first few tests only)
                        if edges_hit == 0 and self._get_stat('tests_processed') < 5:
                            nonzero_sample = [(i, trace_bits[i]) for i in range(min(100, len(trace_bits))) if trace_bits[i] != 0]
                            print(f"[DEBUG] SHM {shm_name}: edges_hit={edges_hit}, sample_nonzero={nonzero_sample[:10]}, __AFL_SHM_ID={shm_id}")
                        
                        # Check for new coverage using SHARED global_coverage_map (with lock)
                        has_new = False
                        new_edges = 0
                        total_edges_before = 0
                        
                        with coverage_map_lock:
                            coverage_bytes = bytes(global_coverage_map[:])
                            total_edges_before = sum(1 for b in coverage_bytes if b == 0x00)
                            
                            for i in range(AFL_MAP_SIZE):
                                if trace_bits[i] and coverage_bytes[i] == 0xff:
                                    global_coverage_map[i] = 0x00
                                    new_edges += 1
                                    has_new = True
                        
                        total_edges_after = total_edges_before + new_edges
                        # Only log coverage for new edges (reduce verbosity)
                        # print(f"[W{worker_id}] {test_name}: hit={edges_hit} new={new_edges} total={total_edges_after}")
                        
                        # Update edge ownership (AFL's tc_ref) and path frequency
                        if edges_hit > 0:
                            coverage_hash = self._hash_coverage(trace_bits)
                            self._update_path_frequency(coverage_hash, test_path_str)
                            self._update_edge_ownership(trace_bits, runtime * 1000, test_path_str)
                        
                        # Decide what to do with mutants based on coverage.
                        # Queue item format: (runtime, new_cov_rank, generation, seq, path_str)
                        #   - runtime (ascending): fast tests first
                        #   - new_cov_rank: 0=new coverage, 1=existing coverage
                        if has_new:
                            self._inc_stat('total_new_edges', new_edges)
                            runtime_sort = runtime
                            cov_rank = 0  # NEW coverage gets priority
                            coverage_type = "NEW"
                            print(f"[W{worker_id}] ✨ +{new_edges} new edges (total: {total_edges_after})")
                        elif edges_hit > 0:
                            runtime_sort = runtime
                            cov_rank = 1  # EXISTING coverage
                            coverage_type = "EXISTING"
                            # Don't log existing coverage hits (too verbose)
                        else:
                            # No coverage at all - discard mutants
                            if mutant_files:
                                print(f"[WORKER {worker_id}] [MUTANT] No coverage at all, discarding {len(mutant_files)} mutant(s)")
                                self._inc_stat('mutants_discarded_no_coverage', len(mutant_files))
                                
                                # DIAGNOSTIC: Log zero coverage timing to evaluate two-stage timeout
                                # If runtime is close to timeout (>100s), two-stage timeout would help
                                print(f"[ZERO-COV] parent={test_name} runtime={runtime:.1f}s mutants={len(mutant_files)}", flush=True)
                                
                            for mutant_file in mutant_files:
                                try:
                                    mutant_file.unlink()
                                except Exception:
                                    pass
                            # Skip to next test
                            coverage_type = None
                        
                        # Process mutants if they hit any coverage
                        if coverage_type is not None and mutant_files:
                            # Check disk space before queuing (TOP PRIORITY)
                            can_queue = self._can_queue_mutants(len(mutant_files))
                            
                            if not can_queue:
                                # Disk space or pending limit exceeded
                                free_mb = self._get_free_disk_space_mb()
                                pending = self._count_pending_mutants()
                                
                                if coverage_type == "NEW":
                                    # For new coverage, try cleanup first
                                    self._cleanup_old_pending_mutants(self.max_pending_mutants // 2)
                                    can_queue = self._can_queue_mutants(len(mutant_files))
                                
                                if not can_queue:
                                    print(f"[WORKER {worker_id}] [DISK] Cannot queue mutants: free={free_mb:.0f}MB, pending={pending}, discarding {len(mutant_files)}")
                                    self._inc_stat('mutants_discarded_disk_space', len(mutant_files))
                                    for mutant_file in mutant_files:
                                        try:
                                            mutant_file.unlink()
                                        except Exception:
                                            pass
                                    coverage_type = None  # Skip queuing
                            
                            if coverage_type is not None:
                                mutants_to_queue = []
                                # Only log mutant processing for new coverage
                                if coverage_type == "NEW":
                                    print(f"[W{worker_id}] +{len(mutant_files)} mutants ({coverage_type})")
                                
                                for mutant_file in mutant_files:
                                    try:
                                        pending_name = f"gen{generation+1}_w{worker_id}_{mutant_file.name}"
                                        pending_path = self.pending_mutants_dir / pending_name
                                        shutil.move(str(mutant_file), str(pending_path))
                                        
                                        # Set newcomer bonus for new mutants
                                        # NEW coverage gets big bonus (8x) to encourage exploration
                                        newcomer_bonus = 8 if coverage_type == "NEW" else 2
                                        self._set_newcomer(str(pending_path), newcomer_bonus)
                                        
                                        # Store calibration data for scoring (S and C factors)
                                        self._store_calibration_data(str(pending_path), runtime_sort, edges_hit)
                                        
                                        # Queue item: (runtime, new_cov_rank, generation, seq, path_str)
                                        mutants_to_queue.append(
                                            (runtime_sort, cov_rank, generation + 1, self._next_seq(), str(pending_path))
                                        )
                                        self._inc_stat('mutants_created')
                                    except Exception as e:
                                        print(f"[WORKER {worker_id}] Warning: Failed to move mutant {mutant_file}: {e}", file=sys.stderr)
                                
                                # Update running averages for score calculation
                                self._update_running_averages(runtime * 1000, edges_hit)
                                
                                if mutants_to_queue:
                                    if coverage_type == "NEW":
                                        self._inc_stat('mutants_with_new_coverage')
                                    else:
                                        self._inc_stat('mutants_with_existing_coverage')
                                    
                                    # DIAGNOSTIC: Log parent success rate for analysis
                                    # This helps evaluate if certain parents consistently produce valid mutants
                                    print(f"[PARENT-STAT] parent={test_name} valid={len(mutants_to_queue)} cov_type={coverage_type}", flush=True)

                                    # Sort by (runtime, new_cov_rank, generation, seq, path).
                                    mutants_to_queue.sort()

                                    # Seed phase: buffer gen1 mutants and only enqueue after all seeds are done.
                                    if generation == 0 and not self.seed_phase_done.is_set():
                                        self._seed_phase_buffer_mutants(mutants_to_queue)
                                    else:
                                        # Buffer and let main loop flush in sorted order across ALL workers.
                                        self._buffer_mutants(mutants_to_queue)
                    
                    # Delete executed mutant if it's from pending folder
                    test_path_obj = test_path if isinstance(test_path, Path) else Path(test_path)
                    if self.pending_mutants_dir in test_path_obj.parents or test_path_obj.parent == self.pending_mutants_dir:
                        try:
                            test_path_obj.unlink()
                        except Exception:
                            pass
                    
                    # Clear scratch folder
                    shutil.rmtree(scratch_folder, ignore_errors=True)
                    scratch_folder.mkdir(parents=True, exist_ok=True)
                    
                    # Periodic profraw merge
                    with self.profraw_merge_counter.get_lock():
                        self.profraw_merge_counter.value += 1
                        if self.profraw_merge_counter.value >= self.profdata_merge_interval:
                            self._periodic_profraw_merge()
                            self.profraw_merge_counter.value = 0
                    
                except Exception as e:
                    print(f"[WORKER {worker_id}] Error in worker: {e}", file=sys.stderr)
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    continue
        
        finally:
            # Cleanup shared memory ONCE at worker exit
            shm.close()
            self._cleanup_shared_memory(shm_name)
            
            # Mark worker as stopped and cleanup folders
            self.worker_status[worker_id] = None
            for folder in [scratch_folder, log_folder]:
                shutil.rmtree(folder, ignore_errors=True)
            
            # Close recipe recorder
            if recipe_recorder:
                recipe_recorder.close()
                print(f"[WORKER {worker_id}] Closed recipe recorder ({recipe_recorder.recipe_count} recipes)", file=sys.stderr)
        
        print(f"[WORKER {worker_id}] Stopped")
    
    # -------------------------------------------------------------------------
    # Main Run Loop
    # -------------------------------------------------------------------------
    
    def run(self):
        if not self.tests:
            print(f"No tests provided{' for job ' + self.job_id if self.job_id else ''}")
            return
        
        print(f"Running coverage-guided fuzzer on {len(self.tests)} test(s){' for job ' + self.job_id if self.job_id else ''}")
        print(f"Tests root: {self.tests_root}")
        print(f"Timeout: {self.time_remaining}s ({self.time_remaining // 60} minutes)" if self.time_remaining else "No timeout")
        iter_range = "[5-500]" if self.hours_budget <= 1.5 else "[10-500]"
        print(f"Iterations per test: {iter_range} (AFL-scored), Modulo: {self.modulo}")
        print(f"CPU cores: {self.cpu_count}")
        print(f"Workers: {self.num_workers}")
        cvc5_str = str(self.cvc5_path) if self.cvc5_path else "None"
        print(f"Solvers: z3={self.z3_path}, cvc5={cvc5_str}")
        print(f"Output directory: {self.output_dir}")
        print(f"Disk limits: max_pending={self.max_pending_mutants}, min_free={self.min_disk_space_mb}MB")
        print(f"Free disk space: {self._get_free_disk_space_mb():.0f}MB")
        print()
        
        # Initialize priority queue with initial tests (runtime=0 for initial tests)
        # use_calibration=False because we don't have calibration data yet
        print(f"[INFO] Loading {len(self.tests)} initial tests into priority queue...")
        self._queue_push_initial_batch(self.tests, use_calibration=False)
        
        # SHARED global_coverage_map across all workers (0xFF = unseen, 0x00 = seen)
        # Using multiprocessing.Array for cross-process sharing
        # 'B' = unsigned char (1 byte), initialized to 255 (0xFF = not seen yet)
        global_coverage_map = multiprocessing.Array('B', [0xff] * AFL_MAP_SIZE)
        coverage_map_lock = multiprocessing.Lock()  # Protects coverage map updates
        
        # Start workers (no result_queue needed - workers push directly to priority queue)
        workers = []
        for worker_id in range(1, self.num_workers + 1):
            worker = multiprocessing.Process(
                target=self._worker_process,
                args=(worker_id, global_coverage_map, coverage_map_lock, self.recipe_output)
            )
            worker.start()
            workers.append(worker)
        
        self.workers = workers
        print(f"[INFO] Started {len(workers)} worker processes")
        
        # Start resource monitor
        monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        monitor_thread.start()
        print("[DEBUG] Resource monitoring started")
        
        # Log initial state
        print(f"[INFO] Initialization complete. Coverage bitmap: {AFL_MAP_SIZE} bytes ({AFL_MAP_SIZE // 1024}KB)")
        print(f"[INFO] Starting fuzzing loop...")
        
        # Signal handlers
        def signal_handler(signum, frame):
            sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
            print(f"\n⏰ Signal {sig_name} ({signum}) received, stopping workers...", flush=True)
            sys.stdout.flush()
            sys.stderr.flush()
            self.shutdown_event.set()
        
        # Handle termination signals
        # Only handle SIGTERM - ignore SIGINT to prevent spurious interrupts in CI
        # (SIGINT can be sent unexpectedly in GitHub Actions/containerized environments)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ignore SIGINT
        
        # Main loop: monitor workers and refill queue when needed
        try:
            end_time = self.start_time + self.time_remaining if self.time_remaining else None
            last_refill_check = time.time()
            last_status_log = time.time()
            status_log_interval = 30  # Log status every 30 seconds
            
            # Periodic weight recalculation (AFL++ does every iteration, we do every 10 tests or 5 min)
            last_recalc_time = time.time()
            last_recalc_tests = 0
            recalc_test_interval = 10   # Recalculate every 10 tests
            recalc_time_interval = 300  # Or every 5 minutes
            
            while not self.shutdown_event.is_set():
                # Check timeout
                if end_time and time.time() >= end_time:
                    print("⏰ Timeout reached, stopping workers...")
                    self.shutdown_event.set()
                    break
                
                current_time = time.time()
                
                # Periodic status logging
                if current_time - last_status_log >= status_log_interval:
                    self._log_periodic_status(global_coverage_map)
                    last_status_log = current_time
                
                # Refill when queue is empty AND at least one worker is idle
                # This prevents idle workers from waiting for slow tests to finish
                # Don't refill too frequently (min 2 seconds between checks)
                if current_time - last_refill_check >= 2.0:
                    idle_workers = sum(1 for w_id in range(1, self.num_workers + 1) 
                                      if self.worker_status.get(w_id) is None)

                    # Flush buffered mutants frequently so workers see sorted work.
                    self._flush_mutant_buffer()

                    # After calibration completes, re-queue seeds with proper scoring
                    if (not self._calibration_seeds_requeued) and self.calibration_done.is_set():
                        self._requeue_calibrated_seeds()
                        self._calibration_seeds_requeued = True
                    
                    # After the initial seed-only phase completes, flush buffered gen1 mutants once.
                    if (not self._seed_phase_flushed) and self.seed_phase_done.is_set():
                        self._flush_seed_phase_mutants()
                        self._seed_phase_flushed = True
                    
                    # Periodic weight recalculation (AFL++ style, but less frequent)
                    # This ensures queue priorities reflect current averages and state
                    if self.calibration_done.is_set():
                        tests_processed = self._get_stat('tests_processed')
                        tests_since_recalc = tests_processed - last_recalc_tests
                        time_since_recalc = current_time - last_recalc_time
                        
                        if tests_since_recalc >= recalc_test_interval or time_since_recalc >= recalc_time_interval:
                            self._recalculate_queue_weights()
                            self._cull_queue()
                            last_recalc_tests = tests_processed
                            last_recalc_time = current_time

                    # IMPORTANT: during calibration phase, do NOT refill seeds (we want exactly one pass).
                    if self.calibration_done.is_set() and self._queue_empty() and idle_workers > 0:
                        gen = self._get_stat('generations_completed') + 1
                        print(f"[INFO] Queue empty with {idle_workers} idle worker(s), refilling (generation {gen})...")
                        self._queue_push_initial_batch(self.tests)
                        self._inc_stat('generations_completed')
                    
                    last_refill_check = current_time
                
                # Restart dead workers (they exit after MAX_TESTS to prevent memory leaks)
                for i, worker in enumerate(workers):
                    alive = worker.is_alive()
                    if not alive:
                        worker_id = i + 1
                        print(f"[INFO] Worker {worker_id} (pid={worker.pid}) is dead, restarting...", flush=True)
                        worker.join(timeout=1)
                        new_worker = multiprocessing.Process(
                            target=self._worker_process,
                            args=(worker_id, global_coverage_map, coverage_map_lock, self.recipe_output)
                        )
                        new_worker.start()
                        workers[i] = new_worker
                        print(f"[INFO] Restarted worker {worker_id} (new pid={new_worker.pid})", flush=True)
                
                time.sleep(0.5)
        
        except KeyboardInterrupt:
            print("\n⏰ Interrupted, stopping workers...")
            self.shutdown_event.set()
        except Exception as e:
            print(f"\n❌ Main loop exception: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            self.shutdown_event.set()
        
        # Detailed exit diagnostics
        print(f"\n{'='*60}", flush=True)
        print(f"[DEBUG] MAIN LOOP EXIT DIAGNOSTICS", flush=True)
        print(f"[DEBUG]   shutdown_event: {self.shutdown_event.is_set()}", flush=True)
        print(f"[DEBUG]   time_remaining: {self._get_time_remaining():.1f}s", flush=True)
        print(f"[DEBUG]   queue_size: {self._get_queue_size()}", flush=True)
        print(f"[DEBUG]   tests_processed: {self._get_stat('tests_processed')}", flush=True)
        print(f"[DEBUG]   bugs_found: {self._get_stat('bugs_found')}", flush=True)
        print(f"[DEBUG]   workers_alive: {sum(1 for w in workers if w.is_alive())}/{len(workers)}", flush=True)
        for i, w in enumerate(workers):
            status = self.worker_status.get(i+1, 'unknown')
            print(f"[DEBUG]   worker_{i+1}: alive={w.is_alive()}, pid={w.pid}, status={status}", flush=True)
        print(f"{'='*60}", flush=True)
        sys.stdout.flush()
        sys.stderr.flush()
        
        # Wait for workers to finish
        for worker in workers:
            worker.join(timeout=5)
            if worker.is_alive():
                worker_pid = getattr(worker, 'pid', 'unknown')
                print(f"Warning: Worker {worker_pid} did not terminate, killing...")
                worker.terminate()
                worker.join(timeout=2)
                if worker.is_alive():
                    worker.kill()
        
        # Collect bugs from worker folders
        for worker_id in range(1, self.num_workers + 1):
            worker_bugs = self.bugs_folder / f"worker_{worker_id}"
            for bug_file in self._collect_bug_files(worker_bugs):
                try:
                    dest = self.bugs_folder / bug_file.name
                    if dest.exists():
                        timestamp = int(time.time())
                        dest = self.bugs_folder / f"{bug_file.stem}_{timestamp}{bug_file.suffix}"
                    shutil.move(str(bug_file), str(dest))
                except Exception:
                    pass
        
        # Final statistics - read from shared coverage map
        total_edges = self._count_edges(bytes(global_coverage_map[:]))
        
        print()
        # Merge recipe files from all workers
        if self.recipe_output:
            _, get_worker_recipe_path, merge_recipe_files = _import_recipes()
            worker_files = [
                get_worker_recipe_path(self.recipe_output, i)
                for i in range(self.num_workers)
            ]
            existing_files = [f for f in worker_files if Path(f).exists()]
            if existing_files:
                merged_path = self.recipe_output if self.recipe_output.endswith('.jsonl') else f"{self.recipe_output}.jsonl"
                total_recipes = merge_recipe_files(existing_files, merged_path)
                print(f"\n📝 Merged {total_recipes} recipes from {len(existing_files)} workers → {merged_path}")
        
        print("=" * 60)
        print(f"COVERAGE-GUIDED FUZZING COMPLETE{' FOR JOB ' + self.job_id if self.job_id else ''}")
        print("=" * 60)
        
        bug_files = self._collect_bug_files(self.bugs_folder)
        if bug_files:
            print(f"\nFound {len(bug_files)} bug(s):")
            for i, bug_file in enumerate(bug_files[:10], 1):  # Show first 10
                print(f"  Bug #{i}: {bug_file.name}")
            if len(bug_files) > 10:
                print(f"  ... and {len(bug_files) - 10} more")
        else:
            print("\nNo bugs found.")
        
        print()
        print("Coverage Statistics:")
        print(f"  Total edges covered: {total_edges}")
        print(f"  Total new edges found: {self._get_stat('total_new_edges')}")
        print(f"  Mutants with new coverage: {self._get_stat('mutants_with_new_coverage')}")
        print(f"  Mutants with existing coverage: {self._get_stat('mutants_with_existing_coverage')}")
        print(f"  Mutants created: {self._get_stat('mutants_created')}")
        print(f"  Generations completed: {self._get_stat('generations_completed')}")
        
        print()
        print("Mutant Management:")
        print(f"  Discarded (no coverage): {self._get_stat('mutants_discarded_no_coverage')}")
        print(f"  Discarded (disk space): {self._get_stat('mutants_discarded_disk_space')}")
        print(f"  Final pending mutants: {self._count_pending_mutants()}")
        print(f"  Final free disk space: {self._get_free_disk_space_mb():.0f}MB")
        
        print()
        print("Fuzzing Statistics:")
        print(f"  Tests processed: {self._get_stat('tests_processed')}")
        print(f"  Bugs found: {self._get_stat('bugs_found')}")
        print(f"  Tests removed (unsupported): {self._get_stat('tests_removed_unsupported')}")
        print(f"  Tests removed (timeout): {self._get_stat('tests_removed_timeout')}")
        
        # Merge profdata if PGO was enabled
        self._merge_profdata()
        
        print("=" * 60)
        
        # Save coverage statistics to output file
        stats_output = self.output_dir / "coverage_stats.json"
        coverage_pct = (total_edges / self.total_instrumented_edges * 100) if self.total_instrumented_edges > 0 else 0
        with open(stats_output, 'w') as f:
            json.dump({
                'total_instrumented_edges': self.total_instrumented_edges,
                'edges_covered': total_edges,
                'coverage_percentage': round(coverage_pct, 2),
                'new_edges_discovered': self._get_stat('total_new_edges'),
                'mutants_with_new_coverage': self._get_stat('mutants_with_new_coverage'),
                'mutants_with_existing_coverage': self._get_stat('mutants_with_existing_coverage'),
                'mutants_created': self._get_stat('mutants_created'),
                'mutants_discarded_no_coverage': self._get_stat('mutants_discarded_no_coverage'),
                'mutants_discarded_disk_space': self._get_stat('mutants_discarded_disk_space'),
                'generations_completed': self._get_stat('generations_completed'),
                'tests_processed': self._get_stat('tests_processed'),
                'bugs_found': self._get_stat('bugs_found'),
                'runtime_seconds': time.time() - self.start_time,
            }, f, indent=2)
        print(f"[INFO] Coverage statistics saved to: {stats_output}")
    
    def _cleanup_worker_profraw(self, worker_id: int):
        """Merge and cleanup profraw files from a specific worker after each test.
        
        This is CRITICAL for inline mode where each test generates hundreds of 
        profraw files (~16MB each). Without cleanup, disk fills up after 1-2 tests.
        """
        # Find profraw files for this worker
        worker_pattern = f"worker_{worker_id}_*.profraw"
        worker_profraw_files = list(self.profraw_dir.glob(worker_pattern))
        
        if not worker_profraw_files:
            return  # Nothing to cleanup
        
        # Calculate size for logging
        total_size_mb = sum(f.stat().st_size for f in worker_profraw_files) / (1024 * 1024)
        
        accumulated_profdata = self.output_dir / "accumulated.profdata"
        temp_profdata = self.output_dir / f"temp_merge_w{worker_id}.profdata"
        
        try:
            # Build merge command
            cmd = ["llvm-profdata", "merge", "-sparse", "-o", str(temp_profdata)]
            
            # Include existing accumulated profdata if it exists
            if accumulated_profdata.exists():
                cmd.append(str(accumulated_profdata))
            
            cmd.extend([str(f) for f in worker_profraw_files])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                # Replace accumulated with new merged file (atomic-ish)
                if accumulated_profdata.exists():
                    accumulated_profdata.unlink()
                temp_profdata.rename(accumulated_profdata)
                
                # Delete merged profraw files to recover disk space
                deleted_count = 0
                for f in worker_profraw_files:
                    try:
                        f.unlink()
                        deleted_count += 1
                    except Exception:
                        pass
                
                print(f"[WORKER {worker_id}] [PGO] Merged {len(worker_profraw_files)} profraw files ({total_size_mb:.1f}MB), deleted {deleted_count}")
            else:
                # Merge failed - still try to delete files to save disk space
                print(f"[WORKER {worker_id}] [PGO WARN] Merge failed: {result.stderr[:200]}", file=sys.stderr)
                # Delete profraw files anyway to prevent disk exhaustion
                for f in worker_profraw_files:
                    try:
                        f.unlink()
                    except Exception:
                        pass
                print(f"[WORKER {worker_id}] [PGO] Deleted {len(worker_profraw_files)} profraw files ({total_size_mb:.1f}MB) despite merge failure")
                
        except subprocess.TimeoutExpired:
            print(f"[WORKER {worker_id}] [PGO WARN] Merge timed out, deleting profraw files", file=sys.stderr)
            for f in worker_profraw_files:
                try:
                    f.unlink()
                except Exception:
                    pass
        except Exception as e:
            print(f"[WORKER {worker_id}] [PGO WARN] Error in profraw cleanup: {e}", file=sys.stderr)
            # Emergency cleanup - delete files to prevent disk exhaustion
            for f in worker_profraw_files:
                try:
                    f.unlink()
                except Exception:
                    pass
    
    def _periodic_profraw_merge(self):
        """Periodically merge profraw files to save disk space."""
        profraw_files = list(self.profraw_dir.glob("*.profraw"))
        if len(profraw_files) < 10:  # Don't bother if few files
            return
        
        accumulated_profdata = self.output_dir / "accumulated.profdata"
        temp_profdata = self.output_dir / "temp_merge.profdata"
        
        # DEBUG: Show profraw file details before merge
        total_size = sum(f.stat().st_size for f in profraw_files)
        nonzero_files = [f for f in profraw_files if f.stat().st_size > 0]
        print(f"[PGO DEBUG] Periodic merge: {len(profraw_files)} files, {len(nonzero_files)} non-empty, total size: {total_size / 1024:.1f}KB")
        
        try:
            # Build merge command
            cmd = ["llvm-profdata", "merge", "-sparse", "-o", str(temp_profdata)]
            
            # Include existing accumulated profdata if it exists
            if accumulated_profdata.exists():
                cmd.append(str(accumulated_profdata))
                print(f"[PGO DEBUG] Including existing accumulated.profdata ({accumulated_profdata.stat().st_size / 1024:.1f}KB)")
            
            cmd.extend([str(f) for f in profraw_files])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                # Replace accumulated with new merged file
                if accumulated_profdata.exists():
                    accumulated_profdata.unlink()
                temp_profdata.rename(accumulated_profdata)
                
                # DEBUG: Show result size
                merged_size = accumulated_profdata.stat().st_size
                print(f"[PGO DEBUG] Merge successful: accumulated.profdata is now {merged_size / 1024:.1f}KB")
                
                # Delete merged profraw files to save disk space
                for f in profraw_files:
                    try:
                        f.unlink()
                    except Exception:
                        pass
                
                print(f"[INFO] Periodic merge: merged {len(profraw_files)} profraw files, disk space recovered")
            else:
                print(f"[WARN] Periodic profraw merge failed: {result.stderr}", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print("[WARN] Periodic profraw merge timed out", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Error in periodic profraw merge: {e}", file=sys.stderr)
    
    def _merge_profdata(self):
        """Merge all .profraw files into a single .profdata file (final merge)."""
        profraw_files = list(self.profraw_dir.glob("*.profraw"))
        accumulated_profdata = self.output_dir / "accumulated.profdata"
        
        # DEBUG: Show detailed state
        print(f"[PGO DEBUG] Final merge state:")
        print(f"[PGO DEBUG]   profraw_dir: {self.profraw_dir}")
        print(f"[PGO DEBUG]   profraw files: {len(profraw_files)}")
        if profraw_files:
            total_size = sum(f.stat().st_size for f in profraw_files)
            nonzero = [f for f in profraw_files if f.stat().st_size > 0]
            print(f"[PGO DEBUG]   profraw total size: {total_size / 1024:.1f}KB, non-empty: {len(nonzero)}")
            for f in profraw_files[:5]:  # Show first 5
                print(f"[PGO DEBUG]     - {f.name}: {f.stat().st_size}B")
            if len(profraw_files) > 5:
                print(f"[PGO DEBUG]     ... and {len(profraw_files) - 5} more")
        
        if accumulated_profdata.exists():
            print(f"[PGO DEBUG]   accumulated.profdata exists: {accumulated_profdata.stat().st_size / 1024:.1f}KB")
        else:
            print(f"[PGO DEBUG]   accumulated.profdata: does not exist")
        
        if not profraw_files and not accumulated_profdata.exists():
            print("[INFO] No profraw files to merge")
            return
        
        files_to_merge = []
        if accumulated_profdata.exists():
            files_to_merge.append(str(accumulated_profdata))
        files_to_merge.extend([str(f) for f in profraw_files])
        
        print(f"[INFO] Final merge: {len(files_to_merge)} files...")
        
        profdata_output = self.output_dir / "merged.profdata"
        
        try:
            cmd = ["llvm-profdata", "merge", "-sparse", "-o", str(profdata_output)]
            cmd.extend(files_to_merge)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                merged_size = profdata_output.stat().st_size
                print(f"[INFO] Merged profdata saved to: {profdata_output} ({merged_size / 1024:.1f}KB)")
                
                # DEBUG: Try to show summary of merged profdata
                try:
                    show_result = subprocess.run(
                        ["llvm-profdata", "show", str(profdata_output)],
                        capture_output=True, text=True, timeout=10
                    )
                    if show_result.returncode == 0:
                        # Extract key lines from output
                        lines = show_result.stdout.split('\n')[:20]
                        print(f"[PGO DEBUG] merged.profdata summary (first 20 lines):")
                        for line in lines:
                            if line.strip():
                                print(f"[PGO DEBUG]   {line}")
                except Exception as e:
                    print(f"[PGO DEBUG] Could not show profdata summary: {e}")
            else:
                print(f"[WARN] Failed to merge profdata: {result.stderr}", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Error merging profdata: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Coverage-guided fuzzer that runs typefuzz with AFL-style coverage tracking"
    )
    
    tests_group = parser.add_mutually_exclusive_group(required=True)
    tests_group.add_argument(
        "--tests-json",
        help="JSON array of test names (relative to --tests-root)",
    )
    tests_group.add_argument(
        "--tests-file",
        help="Path to JSON file containing array of test names",
    )
    
    parser.add_argument(
        "--job-id",
        help="Job identifier (optional, for logging)",
    )
    parser.add_argument(
        "--tests-root",
        default="z3test",
        help="Root directory for tests (default: z3test)",
    )
    parser.add_argument(
        "--time-remaining",
        type=int,
        help="Remaining time until job timeout in seconds",
    )
    parser.add_argument(
        "--job-start-time",
        type=float,
        help="Unix timestamp when the job started",
    )
    parser.add_argument(
        "--stop-buffer-minutes",
        type=int,
        default=5,
        help="Minutes before timeout to stop (default: 5)",
    )
    parser.add_argument(
        "--modulo",
        type=int,
        default=2,
        help="Modulo parameter for typefuzz -m flag (default: 2)",
    )
    parser.add_argument(
        "--max-pending-mutants",
        type=int,
        default=10000,
        help="Maximum pending mutants to prevent disk exhaustion (default: 10000)",
    )
    parser.add_argument(
        "--min-disk-space-mb",
        type=int,
        default=500,
        help="Minimum free disk space in MB before stopping mutant queueing (default: 500)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for typefuzz --seed flag (default: 42)",
    )
    parser.add_argument(
        "--z3-path",
        default="./build/z3",
        help="Path to z3 binary (default: ./build/z3)",
    )
    
    try:
        default_workers = psutil.cpu_count()
    except Exception:
        default_workers = 4
    
    parser.add_argument(
        "--workers",
        type=int,
        default=default_workers,
        help=f"Number of worker processes (default: {default_workers})",
    )
    parser.add_argument(
        "--bugs-folder",
        default="bugs",
        help="Folder to store bugs (default: bugs)",
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Output directory for logs, scratch, and stats (default: ./output)",
    )
    parser.add_argument(
        "--profraw-dir",
        default="./profraw",
        help="Directory for profraw files (default: ./profraw)",
    )
    parser.add_argument(
        "--fuzzing-duration-minutes",
        type=float,
        default=60.0,
        help="Fuzzing duration in minutes (default: 60.0)",
    )
    parser.add_argument(
        "--total-edges",
        type=int,
        default=0,
        help="Total instrumented edges (from coverage agent, 0 = unknown)",
    )
    parser.add_argument(
        "--inline",
        action="store_true",
        help="Use inline typefuzz (faster, no subprocess)",
    )
    parser.add_argument(
        "--per-test-timeout",
        type=int,
        default=120,
        help="Per-test timeout in seconds (default: 120 = 2 minutes)",
    )
    parser.add_argument(
        "--recipe-output",
        help="Path to recipe output file (enables recipe recording mode). "
             "Each worker writes to {path}_worker_N.jsonl, merged at end.",
    )
    
    args = parser.parse_args()
    
    # Parse tests
    try:
        if args.tests_file:
            with open(args.tests_file, 'r') as f:
                tests = json.load(f)
            print(f"[INFO] Loaded tests from file: {args.tests_file}")
        else:
            tests = json.loads(args.tests_json)
        if not isinstance(tests, list):
            raise ValueError("tests must be a JSON array")
    except FileNotFoundError as e:
        print(f"Error: Tests file not found: {args.tests_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Calculate time_remaining from fuzzing duration if not provided
    if args.time_remaining is None and args.job_start_time is None:
        args.time_remaining = int(args.fuzzing_duration_minutes * 60)
        print(f"[INFO] Setting fuzzing duration to {args.fuzzing_duration_minutes} minutes ({args.time_remaining} seconds)")
    
    # Calculate hours_budget for AFL-style iteration scaling
    hours_budget = args.fuzzing_duration_minutes / 60.0
    print(f"[INFO] AFL scoring: hours_budget={hours_budget:.2f}h, iteration range=[{5 if hours_budget <= 1.5 else 10}, 500]")
    
    try:
        fuzzer = CoverageGuidedFuzzer(
            tests=tests,
            tests_root=args.tests_root,
            bugs_folder=args.bugs_folder,
            num_workers=args.workers,
            modulo=args.modulo,
            seed=args.seed,
            time_remaining=args.time_remaining,
            job_start_time=args.job_start_time,
            stop_buffer_minutes=args.stop_buffer_minutes,
            z3_path=args.z3_path,
            job_id=args.job_id,
            profraw_dir=args.profraw_dir,
            output_dir=args.output_dir,
            max_pending_mutants=args.max_pending_mutants,
            min_disk_space_mb=args.min_disk_space_mb,
            total_instrumented_edges=args.total_edges,
            use_inline_mode=args.inline,
            hours_budget=hours_budget,
            per_test_timeout=args.per_test_timeout,
            recipe_output=args.recipe_output,
        )
        
        fuzzer.run()
        
        print("[INFO] Fuzzing complete, forcing exit", flush=True)
        os._exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        os._exit(1)


if __name__ == "__main__":
    main()
