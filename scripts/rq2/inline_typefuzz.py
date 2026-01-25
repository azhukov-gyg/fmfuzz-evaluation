#!/usr/bin/env python3
"""
Shared InlineTypeFuzz - Parses seed once, allows multiple mutations.

This is a shared implementation used by:
- Baseline (simple_commit_fuzzer)
- Variant1 (simple_commit_fuzzer)
- Variant2 (coverage_guided_fuzzer)
- Future z3 evaluation

Designed to produce deterministic mutation streams when seeded with random.seed().
"""

import copy
import re
import subprocess
import sys
from pathlib import Path
from typing import Tuple, Optional, List

# Find yinyang relative to this file
SCRIPT_DIR = Path(__file__).parent
ROOT_DIR = SCRIPT_DIR.parent.parent
YINYANG_PATH = ROOT_DIR / "yinyang"
if str(YINYANG_PATH) not in sys.path:
    sys.path.insert(0, str(YINYANG_PATH))

# Import yinyang components
try:
    from yinyang.src.parsing.Parse import parse_file
    from yinyang.src.parsing.Typechecker import typecheck
    from yinyang.src.mutators.GenTypeAwareMutation.GenTypeAwareMutation import GenTypeAwareMutation
    from yinyang.src.mutators.GenTypeAwareMutation.Util import get_unique_subterms
    from yinyang.config.Config import crash_list, ignore_list
    from yinyang.src.base.Utils import random_string
    YINYANG_AVAILABLE = True
except ImportError as e:
    print(f"Warning: yinyang not available: {e}", file=sys.stderr)
    YINYANG_AVAILABLE = False
    crash_list = []
    ignore_list = []


class InlineTypeFuzz:
    """
    Parses seed once, allows multiple mutations.
    
    Usage:
        import random
        random.seed(42)  # Set seed BEFORE creating InlineTypeFuzz
        
        fuzzer = InlineTypeFuzz(seed_path)
        if fuzzer.parse():
            for i in range(iterations):
                mutant, success = fuzzer.mutate()
                if success:
                    # Use mutant string...
    
    The mutation stream is deterministic when random.seed() is called before parse().
    """
    
    # Expose yinyang's crash/ignore patterns for bug detection
    crash_list = crash_list
    ignore_list = ignore_list
    
    def __init__(self, seed_path: Path, config_path: Optional[Path] = None):
        """
        Initialize with seed file path.
        
        Args:
            seed_path: Path to the .smt2 seed file
            config_path: Optional path to typefuzz config (defaults to yinyang's config)
        """
        self.seed_path = Path(seed_path)
        self.config_path = config_path or (YINYANG_PATH / "yinyang/config/typefuzz_config.txt")
        self._formula = None
        self._mutator = None
        self._header = ""
        self._parsed = False
    
    def parse(self) -> bool:
        """
        Parse and typecheck seed. Must be called before mutate().
        
        Returns:
            True on success, False on parse/typecheck failure.
        """
        if not YINYANG_AVAILABLE:
            return False
            
        try:
            # Extract header comments (preserve them in mutations)
            self._header = ""
            with open(self.seed_path, 'r') as f:
                for line in f:
                    if line.strip().startswith(';'):
                        self._header += line
                    elif line.strip():
                        break
            
            # Parse and typecheck
            self._formula, glob = parse_file(str(self.seed_path), silent=True)
            if not self._formula:
                return False
            
            typecheck(self._formula, glob)
            unique_expr = get_unique_subterms(copy.deepcopy(self._formula))
            
            # Create mutator
            class Args:
                def __init__(self, cfg):
                    self.config = str(cfg)
            
            self._mutator = GenTypeAwareMutation(self._formula, Args(self.config_path), unique_expr)
            
            # yinyang's Fuzzer.__init__ consumes RNG once via random_string() to create a fuzzer name.
            # This call keeps the global RNG stream aligned with subprocess typefuzz runs.
            _ = random_string()
            
            self._parsed = True
            return True
            
        except Exception as e:
            # Just log the error message, not full traceback (to avoid log spam)
            print(f"[InlineTypeFuzz] Parse failed for {self.seed_path}: {e}", file=sys.stderr)
            return False
    
    def mutate(self) -> Tuple[Optional[str], bool]:
        """
        Generate one mutant. Mutations are cumulative (like yinyang's typefuzz).
        
        Returns:
            (mutant_string, success) - mutant_string is None if mutation failed
        """
        if not self._mutator:
            return None, False
            
        try:
            mutant, success, _ = self._mutator.mutate()
            if success:
                # yinyang consumes RNG once per successful iteration when creating scratch filename.
                # This call keeps the global RNG stream aligned with subprocess typefuzz runs.
                _ = random_string()
                return self._header + str(mutant), True
            return None, False
        except Exception:
            return None, False
    
    @property
    def is_parsed(self) -> bool:
        """Whether parse() was successful."""
        return self._parsed
    
    # ========================================
    # Solver execution helpers (for bug detection)
    # ========================================
    
    def _in_list(self, stdout: str, stderr: str, patterns: list) -> bool:
        """Check if stdout/stderr matches any pattern (matches yinyang's in_list)."""
        combined = stdout + " " + stderr
        return any(p in combined for p in patterns)
    
    def _grep_results(self, stdout: str) -> List[str]:
        """Extract ALL sat/unsat/unknown from stdout (for incremental benchmarks)."""
        results = []
        for line in stdout.splitlines():
            if re.match(r"^unsat$", line):
                results.append("unsat")
            elif re.match(r"^sat$", line):
                results.append("sat")
            elif re.match(r"^unknown$", line):
                results.append("unknown")
        return results
    
    def _results_equal(self, r1: List[str], r2: List[str]) -> bool:
        """Compare result lists (unknown is wildcard, matches yinyang's SolverResult.equals)."""
        if len(r1) != len(r2):
            return False
        for a, b in zip(r1, r2):
            if a != "unknown" and b != "unknown" and a != b:
                return False
        return True
    
    def run_solver(self, mutant_path: Path, cmd: str, timeout: int,
                   env: Optional[dict] = None) -> Tuple[str, str, int]:
        """
        Run a single solver on mutant.
        
        Args:
            mutant_path: Path to mutant file
            cmd: Solver command (e.g., "z3" or "cvc5 --check-models")
            timeout: Timeout in seconds
            env: Optional environment dict
            
        Returns:
            (stdout, stderr, exitcode) - exitcode 137 means timeout
        """
        try:
            r = subprocess.run(
                cmd.split() + [str(mutant_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                start_new_session=True
            )
            
            # Print only coverage_agent debug lines (suppress solver warnings)
            if r.stderr and env and env.get('COVERAGE_AGENT_DEBUG') == '1':
                for line in r.stderr.splitlines():
                    if line.startswith('[coverage_agent]'):
                        print(line, flush=True, file=sys.stderr)
            
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired as te:
            stdout = te.stdout.decode() if te.stdout else ""
            stderr = te.stderr.decode() if te.stderr else ""
            return stdout, stderr, 137
        except Exception as e:
            return "", str(e), 1
    
    def run_solvers_differential(self, mutant_path: Path, solvers: List[str],
                                 timeout: int, env: Optional[dict] = None) -> Tuple[bool, str, bool]:
        """
        Run multiple solvers for differential testing (matches yinyang logic).
        
        Args:
            mutant_path: Path to mutant file
            solvers: List of solver commands (e.g., ["z3", "cvc5 --check-models"])
            timeout: Timeout per solver in seconds
            env: Optional environment dict
            
        Returns:
            (is_bug, bug_type, all_timeout) - bug_type is "crash", "segfault", "soundness", or ""
            all_timeout is True if all solvers timed out
        """
        oracle = None
        all_timeout = True  # Track if all solvers timed out
        
        for cmd in solvers:
            stdout, stderr, exitcode = self.run_solver(mutant_path, cmd, timeout, env)
            
            # Check crash_list patterns
            if self._in_list(stdout, stderr, self.crash_list):
                return True, "crash", False
            
            # Check ignore_list - skip this solver
            if self._in_list(stdout, stderr, self.ignore_list):
                all_timeout = False  # At least one solver didn't timeout
                continue
            
            # Check segfault
            if exitcode == -11 or exitcode == 245:
                return True, "segfault", False
            
            # Check timeout - skip this solver
            if exitcode == 137:
                continue  # Keep all_timeout = True if all timeout
            
            # If we get here, this solver didn't timeout
            all_timeout = False
            
            # Get all results (for incremental benchmarks)
            results = self._grep_results(stdout)
            if not results:
                continue
            
            # Filter out unknown-only results for oracle setting
            non_unknown = [r for r in results if r != "unknown"]
            if not non_unknown:
                continue
            
            # Differential testing: first valid result = oracle
            if oracle is None:
                oracle = results
            elif not self._results_equal(oracle, results):
                return True, "soundness", False
        
        return False, "", all_timeout


def regenerate_mutation(seed_path: str, iteration: int, rng_seed: int,
                        config_path: Optional[str] = None) -> Optional[str]:
    """
    Regenerate a specific mutation deterministically (for recipe replay).
    
    This is a convenience function that:
    1. Sets random.seed(rng_seed)
    2. Parses the seed
    3. Generates mutations up to the target iteration
    4. Returns the mutation at that iteration
    
    Args:
        seed_path: Path to the seed file
        iteration: Which iteration to return (1-indexed)
        rng_seed: Random seed to use
        config_path: Optional path to typefuzz config
        
    Returns:
        The mutant string at the given iteration, or None if failed
    """
    import random
    
    # Set random seed BEFORE any operations
    random.seed(rng_seed)
    
    config = Path(config_path) if config_path else None
    fuzzer = InlineTypeFuzz(Path(seed_path), config)
    
    if not fuzzer.parse():
        return None
    
    # Generate mutations up to target iteration
    for i in range(1, iteration + 1):
        mutant, success = fuzzer.mutate()
        if i == iteration:
            return mutant if success else None
    
    return None
