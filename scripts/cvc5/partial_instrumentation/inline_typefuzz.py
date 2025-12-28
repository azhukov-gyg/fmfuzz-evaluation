"""Inline typefuzz mutator - parses once, mutates many times."""

import copy
import re
import subprocess
import sys
from pathlib import Path
from typing import Tuple, Optional

# Add yinyang to path
YINYANG_PATH = Path(__file__).parent.parent.parent.parent / "yinyang"
if str(YINYANG_PATH) not in sys.path:
    sys.path.insert(0, str(YINYANG_PATH))

from yinyang.src.parsing.Parse import parse_file
from yinyang.src.parsing.Typechecker import typecheck
from yinyang.src.mutators.GenTypeAwareMutation.GenTypeAwareMutation import GenTypeAwareMutation
from yinyang.src.mutators.GenTypeAwareMutation.Util import get_unique_subterms
from yinyang.config.Config import crash_list, ignore_list


class InlineTypeFuzz:
    """Parses seed once, allows multiple mutations and solver runs."""
    
    def __init__(self, seed_path: Path, config_path: Path = None):
        self.seed_path = Path(seed_path)
        self.config_path = config_path or (YINYANG_PATH / "yinyang/config/typefuzz_config.txt")
        self._formula = None
        self._mutator = None
        self._header = ""
    
    def parse(self) -> bool:
        """Parse and typecheck seed. Returns True on success."""
        try:
            # Extract header comments
            self._header = ""
            with open(self.seed_path, 'r') as f:
                for line in f:
                    if line.strip().startswith(';'):
                        self._header += line
                    elif line.strip():
                        break
            
            self._formula, glob = parse_file(str(self.seed_path), silent=True)
            if not self._formula:
                return False
            
            typecheck(self._formula, glob)
            unique_expr = get_unique_subterms(copy.deepcopy(self._formula))
            
            class Args:
                def __init__(self, cfg): self.config = str(cfg)
            
            self._mutator = GenTypeAwareMutation(self._formula, Args(self.config_path), unique_expr)
            return True
        except Exception:
            return False
    
    def mutate(self) -> Tuple[Optional[str], bool]:
        """Generate one mutant. Mutations are cumulative (like yinyang)."""
        if not self._mutator:
            return None, False
        try:
            mutant, success, _ = self._mutator.mutate()
            if success:
                return self._header + str(mutant), True
            return None, False
        except Exception:
            return None, False
    
    def _in_list(self, stdout: str, stderr: str, patterns: list) -> bool:
        """Check if stdout/stderr matches any pattern (matches yinyang's in_list)."""
        combined = stdout + " " + stderr  # yinyang uses space separator
        return any(p in combined for p in patterns)
    
    def _grep_results(self, stdout: str) -> list:
        """Extract ALL sat/unsat/unknown from stdout (for incremental benchmarks)."""
        results = []
        for line in stdout.splitlines():
            if re.search(r"^unsat$", line):
                results.append("unsat")
            elif re.search(r"^sat$", line):
                results.append("sat")
            elif re.search(r"^unknown$", line):
                results.append("unknown")
        return results
    
    def _results_equal(self, r1: list, r2: list) -> bool:
        """Compare result lists (unknown is wildcard, matches yinyang's SolverResult.equals)."""
        if len(r1) != len(r2):
            return False
        for a, b in zip(r1, r2):
            if a != "unknown" and b != "unknown" and a != b:
                return False
        return True
    
    def run_solvers(self, mutant_path: Path, z3_cmd: str, cvc5_cmd: str, 
                    timeout: int, env: dict) -> Tuple[bool, str]:
        """Run solvers on mutant (matches yinyang logic). Returns (is_bug, bug_type)."""
        oracle = None
        
        for cmd in [z3_cmd, cvc5_cmd]:
            try:
                r = subprocess.run(cmd.split() + [str(mutant_path)], 
                                   capture_output=True, text=True, timeout=timeout, 
                                   env=env, shell=False, start_new_session=True)
                stdout, stderr, exitcode = r.stdout, r.stderr, r.returncode
            except subprocess.TimeoutExpired as te:
                # Match yinyang: timeout = exitcode 137
                stdout = te.stdout.decode() if te.stdout else ""
                stderr = te.stderr.decode() if te.stderr else ""
                exitcode = 137
            except Exception:
                continue
            
            # Check crash_list patterns
            if self._in_list(stdout, stderr, crash_list):
                return True, "crash"
            
            # Check ignore_list - skip this solver
            if self._in_list(stdout, stderr, ignore_list):
                continue
            
            # Check segfault
            if exitcode == -11 or exitcode == 245:
                return True, "segfault"
            
            # Check timeout
            if exitcode == 137:
                continue
            
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
                return True, "soundness"
        
        return False, ""
