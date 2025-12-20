# Production Workflow Plan: Coverage-Guided Fuzzing Strategy

## Overview

This document outlines the plan for implementing a new production fuzzing workflow that uses coverage-guided test prioritization and multi-generation mutant management.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Prepare Commit Fuzzer Job                               │
│    - Analyze commit changes                                 │
│    - Generate 2 allowlists (PGO + Edge Coverage)            │
│    - Prepare test list                                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Fuzzing Job                                              │
│    - Build instrumented binary from scratch                 │
│      (with sancov + PGO flags + allowlists)                 │
│    - Run coverage-guided fuzzing with mutant generations    │
│    - Collect function execution statistics                  │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Statistics Upload (End of Fuzzing Job)                   │
│    - Upload function execution statistics to S3             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Comparison Workflow (SEPARATE)                           │
│    - Download baseline statistics from S3                   │
│    - Download coverage-guided statistics from S3            │
│    - Run comparison, upload results                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Fuzzing Logic (IMPORTANT)

### The Correct Algorithm

The fuzzing process works in **distinct phases** with **dynamically created queues**:

```
┌────────────────────────────────────────────────────────────────────────┐
│ INITIALIZATION                                                         │
│                                                                        │
│   current_queue = initial_tests (as heap sorted by time=0)             │
│   next_queue = empty heap                                              │
│   generation = 0                                                       │
└────────────────────────────────────────────────────────────────────────┘
                                   ↓
┌────────────────────────────────────────────────────────────────────────┐
│ MAIN LOOP (repeat until timeout ONLY - never stop early!)              │
│                                                                        │
│   while not timeout:                                                   │
│       1. Pop item from queue (4 workers in parallel)                   │
│       2. Run test/mutant with typefuzz (-i 1 -k, 2 solvers: z3+cvc5)   │
│       3. Record execution time                                         │
│       4. Check edge coverage (per-worker AFL++ virgin map)             │
│       5. IF new coverage found:                                        │
│            → Keep mutant, push (exec_time, mutant_path) to next_queue  │
│       6. ELSE (no new coverage):                                       │
│            → DELETE mutant immediately (save disk space)               │
│                                                                        │
│   # When queue is exhausted:                                           │
│   IF next_queue not empty:                                             │
│       current_queue = next_queue                                       │
│       next_queue = new empty heap                                      │
│       generation += 1                                                  │
│       → Continue loop                                                  │
│   ELSE:                                                                │
│       # Queue empty but NOT timeout → RESTART with initial tests!      │
│       current_queue = initial_tests                                    │
│       generation += 1                                                  │
│       → Continue loop (keep fuzzing until timeout!)                    │
└────────────────────────────────────────────────────────────────────────┘
                                   ↓
┌────────────────────────────────────────────────────────────────────────┐
│ FINAL: Collect Statistics                                              │
│                                                                        │
│   - Merge all PGO profiles (profraw → profdata)                        │
│   - Extract function execution counts                                   │
│   - Output statistics in baseline-compatible format                    │
└────────────────────────────────────────────────────────────────────────┘
```

### Pseudocode

```python
def run_fuzzing(initial_tests, timeout):
    # Dynamic queue management - no hardcoded queue numbers
    current_queue = []  # heap: (time, path)
    next_queue = []     # heap: (time, path)
    generation = 0
    
    # Initialize with all tests (time=0 since unknown)
    for test in initial_tests:
        heapq.heappush(current_queue, (0, test))
    
    start_time = time.time()
    
    while time.time() - start_time < timeout:  # ONLY stop on timeout!
        # Process current generation
        while current_queue and time.time() - start_time < timeout:
            exec_time_est, path = heapq.heappop(current_queue)
            
            result = run_test(path)
            
            if result.has_new_coverage and result.mutant_path:
                # Add to NEXT queue (not current!)
                heapq.heappush(next_queue, (result.exec_time, result.mutant_path))
            else:
                # No new coverage - DELETE mutant to save disk space
                if generation > 0:
                    delete_file(path)
        
        # Move to next generation
        if next_queue:
            current_queue = next_queue
            next_queue = []
            generation += 1
            print(f"Starting generation {generation} with {len(current_queue)} mutants")
        else:
            # Queue empty but NOT timeout - restart with initial tests!
            print(f"Queue empty, restarting with initial tests (gen {generation})")
            for test in initial_tests:
                heapq.heappush(current_queue, (0, test))
            generation += 1
    
    return collect_statistics()
```

### Key Points

1. **Dynamic queues**: Only two queue variables (`current_queue`, `next_queue`), swapped between generations
2. **Tests first, then mutants**: Generation 0 = initial tests, Generation 1+ = mutants
3. **Time-sorted heaps**: Always process fastest items first (better coverage discovery)
4. **Delete after fuzzing**: Only mutants (generation > 0) are deleted, original tests are kept
5. **Stop condition**: Timeout ONLY (never stop early!)
6. **Queue restart**: When queue is empty, restart with initial tests (continuous fuzzing until timeout)
7. **4 workers**: Each with separate scratch/log folder and shared memory for thread-safe coverage tracking
8. **2 solvers**: z3 + cvc5 (like simple_commit_fuzzer)

---

## Phase 1: Prepare Commit Fuzzer Job

### 1.1 Current State
- Downloads coverage mapping from S3
- Runs `prepare_commit_fuzzer_sancov.py`
- Generates `changed_functions.json`
- Currently tries to generate allowlist (but script missing)

### 1.2 Required Changes

#### A. Modify `prepare_commit_fuzzer_sancov.py`

**New Outputs:**
- `changed_functions.json` (existing)
- `pgo_allowlist.txt` (NEW) - for function call count instrumentation
- `edge_coverage_allowlist.txt` (NEW) - for edge coverage instrumentation

**Implementation:**
```python
def generate_allowlists(changed_functions: List[Dict], output_dir: Path):
    """
    Generate two allowlists from changed functions.
    
    PGO Allowlist format (for -fprofile-instr-generate):
        fun:_ZN4cvc5...  (mangled function names)
    
    Edge Coverage Allowlist format (for -fsanitize-coverage):
        src:src/path/to/file.cpp
        fun:_ZN4cvc5...
    """
    pgo_functions = set()
    edge_sources = set()
    edge_functions = set()
    
    for func in changed_functions:
        mangled_name = func.get('mangled_name', '')
        file_path = func.get('file', '')
        
        if mangled_name:
            pgo_functions.add(f"fun:{mangled_name}")
            edge_functions.add(f"fun:{mangled_name}")
        
        if file_path:
            # Normalize path to src/...
            if '/src/' in file_path:
                file_path = 'src/' + file_path.split('/src/')[-1]
            edge_sources.add(f"src:{file_path}")
    
    # Write PGO allowlist
    with open(output_dir / "pgo_allowlist.txt", "w") as f:
        f.write("\n".join(sorted(pgo_functions)))
    
    # Write Edge coverage allowlist  
    with open(output_dir / "edge_coverage_allowlist.txt", "w") as f:
        lines = sorted(edge_sources) + sorted(edge_functions)
        f.write("\n".join(lines))
    
    return len(pgo_functions), len(edge_sources)
```

**CLI Flags:**
```
--output-pgo-allowlist PATH      Output PGO allowlist file
--output-edge-allowlist PATH     Output edge coverage allowlist file
```

---

## Phase 2: Build Instrumented Binary

### 2.1 Concept

Build the instrumented binary from scratch with coverage instrumentation. This is simpler and more reliable than incremental instrumentation.

**Key components:**
1. **SanitizerCoverage** (`-fsanitize-coverage=trace-pc-guard`) - Edge coverage for fuzzing guidance
2. **PGO instrumentation** (`-fprofile-instr-generate`) - Function execution counts for statistics
3. **Allowlists** - Limit instrumentation to changed functions only (optional optimization)
4. **Coverage agent** - Custom runtime that writes coverage to shared memory
5. **Profile runtime** - LLVM compiler-rt for PGO `.profraw` file generation

### 2.2 Build Script

```bash
#!/bin/bash
# build_instrumented_cvc5.sh - Build CVC5 with coverage instrumentation

set -e

COMMIT_HASH="${1:?Usage: $0 <commit_hash> [edge_allowlist] [pgo_allowlist]}"
EDGE_ALLOWLIST="${2:-}"
PGO_ALLOWLIST="${3:-}"

WORKSPACE="/workspace"
CVC5_DIR="${WORKSPACE}/cvc5"
BUILD_DIR="${CVC5_DIR}/build"

# Clone and checkout
git clone --depth 100 https://github.com/cvc5/cvc5.git "$CVC5_DIR"
cd "$CVC5_DIR"
git fetch --depth 100 origin "$COMMIT_HASH"
git checkout "$COMMIT_HASH"

# Setup Python venv for CVC5 build
python3 -m venv ~/.venv
source ~/.venv/bin/activate
pip install --quiet --upgrade pip

# Build flags
SANCOV_FLAGS="-fsanitize-coverage=trace-pc-guard"
PGO_FLAGS="-fprofile-instr-generate -fcoverage-mapping"

# Add allowlists if provided
if [ -n "$EDGE_ALLOWLIST" ] && [ -f "$EDGE_ALLOWLIST" ]; then
    SANCOV_FLAGS="$SANCOV_FLAGS -fsanitize-coverage-allowlist=$EDGE_ALLOWLIST"
fi

# Configure with instrumentation
export CC=clang
export CXX=clang++
export CFLAGS="$SANCOV_FLAGS $PGO_FLAGS"
export CXXFLAGS="$SANCOV_FLAGS $PGO_FLAGS"

./configure.sh production --static --auto-download

# Build
cd "$BUILD_DIR"
make -j$(nproc)

# Find and link profile runtime
ARCH=$(uname -m)
[ "$ARCH" = "arm64" ] && ARCH="aarch64"
PROFILE_RT=$(find /usr/lib -name "libclang_rt.profile-${ARCH}.a" 2>/dev/null | head -1)

if [ -n "$PROFILE_RT" ]; then
    echo "Linking profile runtime: $PROFILE_RT"
    # Profile runtime is automatically linked when using -fprofile-instr-generate
fi

# Verify instrumentation
echo "Verifying instrumentation..."
SANCOV_SYM=$(nm "${BUILD_DIR}/bin/cvc5" 2>/dev/null | grep -c "__sanitizer_cov" || echo "0")
PGO_SYM=$(nm "${BUILD_DIR}/bin/cvc5" 2>/dev/null | grep -c "__llvm_profile" || echo "0")
echo "  Sancov symbols: $SANCOV_SYM"
echo "  PGO symbols: $PGO_SYM"

# Test binary works
"${BUILD_DIR}/bin/cvc5" --version
echo "Build complete: ${BUILD_DIR}/bin/cvc5"
```

### 2.3 Instrumentation Details

**SanitizerCoverage (Edge Coverage):**
- Each edge (branch transition) gets a unique guard ID
- Guard callback: `__sanitizer_cov_trace_pc_guard(uint32_t *guard)`
- Our custom `coverage_agent.cpp` writes hits to shared memory bitmap
- AFL++-compatible 64KB bitmap for fuzzing guidance

**PGO (Function Counts):**
- Compiler inserts counters at function entries
- Profile runtime writes `.profraw` on exit
- `llvm-profdata merge` combines multiple runs
- `llvm-profdata show --all-functions` extracts counts

**Allowlists (Optional):**
- `-fsanitize-coverage-allowlist=file.txt` limits sancov to specific functions
- Format: `src:*` (all sources) + `fun:_ZN...` (mangled function names)
- Reduces overhead when only testing specific changed code

---

## Phase 3: Coverage-Guided Fuzzer Implementation

### 3.1 Corrected Core Algorithm

```python
#!/usr/bin/env python3
"""
Coverage-Guided Fuzzer with Multi-Generation Mutant Management
"""

import heapq
import os
import struct
import subprocess
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# AFL++ constants
BITMAP_SIZE = 65536  # 64KB bitmap


class CoverageGuidedFuzzer:
    """
    Fuzzer that processes tests in phases:
    1. Fuzz all initial tests
    2. Fuzz mutants_queue_1 (from tests with new coverage)
    3. Fuzz mutants_queue_2, etc.
    Continue until timeout.
    """
    
    def __init__(
        self,
        cvc5_path: Path,
        cov_agent_path: Path,
        scratch_dir: Path,
        num_workers: int = 4,
        profile_merge_interval: int = 100,
    ):
        self.cvc5_path = cvc5_path
        self.cov_agent_path = cov_agent_path
        self.scratch_dir = scratch_dir
        self.num_workers = num_workers
        self.profile_merge_interval = profile_merge_interval
        
        # AFL++-style coverage tracking
        self.virgin_map = bytearray([0xFF] * BITMAP_SIZE)
        self.total_edges_found = 0
        
        # Statistics
        self.function_executions: Dict[str, int] = defaultdict(int)
        self.tests_processed = 0
        self.mutants_processed = 0
        self.profraw_files: List[Path] = []
        
        # Setup directories
        self.scratch_dir.mkdir(parents=True, exist_ok=True)
        for i in range(num_workers):
            (self.scratch_dir / f"worker_{i}").mkdir(exist_ok=True)
    
    def run(self, initial_tests: List[str], timeout_seconds: int) -> Dict:
        """
        Main fuzzing loop with dynamic multi-generation mutant management.
        
        Uses two queues (current_queue, next_queue) that are swapped between generations.
        No hardcoded queue numbers - generations are created dynamically.
        """
        start_time = time.time()
        
        print(f"=== Starting Coverage-Guided Fuzzing ===")
        print(f"Initial tests: {len(initial_tests)}")
        print(f"Timeout: {timeout_seconds}s ({timeout_seconds/60:.1f} min)")
        print(f"Workers: {self.num_workers}")
        
        # Dynamic queue management - only two queues, swapped between generations
        current_queue = []  # heap: (time, path)
        next_queue = []     # heap: (time, path)
        generation = 0
        
        # Initialize current_queue with all initial tests (time=0 since unknown)
        for test in initial_tests:
            heapq.heappush(current_queue, (0.0, test))
        
        # Main loop - process generations until timeout or no more work
        while current_queue and time.time() - start_time < timeout_seconds:
            gen_start = len(current_queue)
            print(f"\n=== Generation {generation}: Processing {gen_start} items ===")
            
            items_processed = 0
            new_coverage_count = 0
            
            # Process all items in current generation
            while current_queue and time.time() - start_time < timeout_seconds:
                # Pop item with lowest execution time (fastest first)
                exec_time_est, path = heapq.heappop(current_queue)
                
                # Skip if file was already deleted (shouldn't happen, but safety check)
                if not Path(path).exists():
                    continue
                
                result = self._run_single_test(path, generation=generation)
                items_processed += 1
                
                if generation == 0:
                    self.tests_processed += 1
                else:
                    self.mutants_processed += 1
                
                # If new coverage found and mutant was created, add to NEXT queue
                if result['has_new_coverage'] and result['mutant_path']:
                    heapq.heappush(next_queue, (result['time'], result['mutant_path']))
                    new_coverage_count += 1
                
                # DELETE fuzzed mutants (not original tests) to save disk space
                if generation > 0:
                    try:
                        Path(path).unlink()
                    except Exception:
                        pass
                
                # Progress update every 10 items
                if items_processed % 10 == 0:
                    elapsed = time.time() - start_time
                    print(f"  Progress: {items_processed}/{gen_start} | "
                          f"New coverage: {new_coverage_count} | "
                          f"Time: {elapsed:.0f}s/{timeout_seconds}s")
            
            print(f"Generation {generation} complete: "
                  f"{items_processed} processed, {new_coverage_count} with new coverage")
            
            # Move to next generation (swap queues)
            if not next_queue:
                print(f"No more items with new coverage. Stopping.")
                break
            
            current_queue = next_queue
            next_queue = []  # Create fresh empty queue for next generation
            generation += 1
        
        # Final statistics
        elapsed = time.time() - start_time
        print(f"\n=== Fuzzing Complete ===")
        print(f"Total time: {elapsed:.1f}s ({elapsed/60:.1f} min)")
        print(f"Tests processed: {self.tests_processed}")
        print(f"Mutants processed: {self.mutants_processed}")
        print(f"Total generations: {generation + 1}")
        print(f"Total edges found: {self.total_edges_found}")
        
        # Merge final PGO profiles
        self._merge_all_pgo_profiles()
        
        return self._collect_statistics()
    
    def _run_single_test(self, test_path: str, generation: int) -> Dict:
        """
        Run a single test with typefuzz and track coverage.
        
        Returns:
            dict with keys: has_new_coverage, time, mutant_path
        """
        worker_id = self.tests_processed % self.num_workers
        shm_name = f"cvc5_cov_{worker_id}_{uuid.uuid4().hex[:8]}"
        worker_scratch = self.scratch_dir / f"worker_{worker_id}"
        
        # Environment for coverage tracking
        env = os.environ.copy()
        env.update({
            'COVERAGE_SHM_NAME': shm_name,
            'LLVM_PROFILE_FILE': str(worker_scratch / f"profile_%4m.profraw"),
            'LD_PRELOAD': str(self.cov_agent_path),
            'ASAN_OPTIONS': 'abort_on_error=0:detect_leaks=0',
        })
        
        # Run typefuzz with -i 1 -k (1 iteration, keep mutants)
        # Typefuzz syntax: typefuzz SOLVER_CLI SEED_FILES...
        start = time.time()
        try:
            result = subprocess.run(
                [
                    'typefuzz',
                    '-i', '1',              # 1 iteration
                    '-k',                   # keep mutants
                    '-s', str(worker_scratch),  # scratch folder for mutants
                    '-q',                   # quiet mode
                    f'cvc5={self.cvc5_path}',
                    test_path,
                ],
                env=env,
                capture_output=True,
                timeout=60,  # 60s timeout per test
            )
        except subprocess.TimeoutExpired:
            exec_time = 60.0
            return {'has_new_coverage': False, 'time': exec_time, 'mutant_path': None}
        
        exec_time = time.time() - start
        
        # Read coverage bitmap from shared memory
        bitmap = self._read_bitmap(shm_name)
        has_new_coverage = self._has_new_bits(bitmap)
        
        if has_new_coverage:
            self._update_virgin_map(bitmap)
            self.total_edges_found = self._count_covered_edges()
        
        # Find mutant created by typefuzz
        # Pattern: {seed_stem}-{fuzzer_name}-{random}.smt2
        seed_stem = Path(test_path).stem
        mutants = list(worker_scratch.glob(f"*{seed_stem}*.smt2"))
        # Filter out the original test file
        mutants = [m for m in mutants if str(m) != test_path]
        mutant_path = str(mutants[0]) if mutants else None
        
        # Track profraw files
        profraw_files = list(worker_scratch.glob("*.profraw"))
        self.profraw_files.extend(profraw_files)
        
        # Periodic PGO merge
        if len(self.profraw_files) >= self.profile_merge_interval:
            self._merge_pgo_profiles_batch()
        
        # Cleanup shared memory
        self._cleanup_shm(shm_name)
        
        return {
            'has_new_coverage': has_new_coverage,
            'time': exec_time,
            'mutant_path': mutant_path,
        }
    
    def _read_bitmap(self, shm_name: str) -> bytearray:
        """Read coverage bitmap from shared memory."""
        shm_path = f"/dev/shm/{shm_name}"
        bitmap = bytearray(BITMAP_SIZE)
        
        try:
            if os.path.exists(shm_path):
                with open(shm_path, 'rb') as f:
                    data = f.read(BITMAP_SIZE)
                    bitmap[:len(data)] = data
        except Exception:
            pass
        
        return bitmap
    
    def _has_new_bits(self, current: bytearray) -> bool:
        """
        AFL++-style new coverage detection.
        
        Checks if current bitmap has any edges that are not yet in virgin_map.
        Virgin map: 0xFF = unseen, lower values = seen with hit count buckets.
        
        Algorithm (from AFL++ coverage-64.h):
        1. Fast path: check if (current & virgin) has any overlap
        2. If overlap, check byte-by-byte for truly NEW edges (virgin == 0xFF)
        """
        # Convert to 64-bit words for fast comparison
        current_words = struct.unpack('Q' * (BITMAP_SIZE // 8), bytes(current))
        virgin_words = struct.unpack('Q' * (BITMAP_SIZE // 8), bytes(self.virgin_map))
        
        for i, (curr, virg) in enumerate(zip(current_words, virgin_words)):
            # Fast path: check if there's any overlap
            if curr & virg:
                # Slow path: check byte-by-byte for NEW edges
                for j in range(8):
                    curr_byte = (curr >> (j * 8)) & 0xFF
                    virg_byte = (virg >> (j * 8)) & 0xFF
                    # New edge: current has hit AND virgin is 0xFF (unseen)
                    if curr_byte != 0 and virg_byte == 0xFF:
                        return True
        
        return False
    
    def _update_virgin_map(self, current: bytearray):
        """
        Update virgin map to mark seen edges.
        AFL++ style: virgin &= ~current (clear bits that were hit)
        """
        for i in range(BITMAP_SIZE):
            if current[i] != 0:
                # Mark as seen (clear the bits)
                self.virgin_map[i] &= ~current[i]
    
    def _count_covered_edges(self) -> int:
        """Count number of covered edges (non-0xFF bytes in virgin map)."""
        count = 0
        for byte in self.virgin_map:
            if byte != 0xFF:
                count += 1
        return count
    
    def _cleanup_shm(self, shm_name: str):
        """Remove shared memory file."""
        try:
            shm_path = f"/dev/shm/{shm_name}"
            if os.path.exists(shm_path):
                os.unlink(shm_path)
        except Exception:
            pass
    
    def _merge_pgo_profiles_batch(self):
        """Merge accumulated profraw files into profdata."""
        if not self.profraw_files:
            return
        
        profdata_path = self.scratch_dir / "merged.profdata"
        
        try:
            if profdata_path.exists():
                # Incremental merge
                subprocess.run(
                    ['llvm-profdata', 'merge', '-o', str(profdata_path),
                     str(profdata_path)] + [str(f) for f in self.profraw_files],
                    check=False, capture_output=True,
                )
            else:
                # Initial merge
                subprocess.run(
                    ['llvm-profdata', 'merge', '-o', str(profdata_path)]
                    + [str(f) for f in self.profraw_files],
                    check=False, capture_output=True,
                )
            
            # Delete merged profraw files
            for f in self.profraw_files:
                try:
                    f.unlink()
                except Exception:
                    pass
            
            self.profraw_files.clear()
        except Exception as e:
            print(f"Warning: PGO merge failed: {e}")
    
    def _merge_all_pgo_profiles(self):
        """Final merge of all remaining profraw files."""
        # Collect all remaining profraw files
        for i in range(self.num_workers):
            worker_scratch = self.scratch_dir / f"worker_{i}"
            self.profraw_files.extend(worker_scratch.glob("*.profraw"))
        
        self._merge_pgo_profiles_batch()
        
        # Extract function counts from merged profdata
        self._extract_function_counts()
    
    def _extract_function_counts(self):
        """Extract function execution counts from merged profdata."""
        profdata_path = self.scratch_dir / "merged.profdata"
        if not profdata_path.exists():
            return
        
        try:
            result = subprocess.run(
                ['llvm-profdata', 'show', '--all-functions', str(profdata_path)],
                capture_output=True, text=True, check=False,
            )
            
            # Parse output for function counts
            # Format varies, but generally: function_name: count
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' '):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        func_name = parts[0].strip()
                        try:
                            count = int(parts[1].strip().split()[0])
                            self.function_executions[func_name] = count
                        except (ValueError, IndexError):
                            pass
        except Exception as e:
            print(f"Warning: Function count extraction failed: {e}")
    
    def _collect_statistics(self) -> Dict:
        """Collect final statistics in baseline-compatible format."""
        return {
            'tests_processed': self.tests_processed,
            'mutants_processed': self.mutants_processed,
            'total_edges_found': self.total_edges_found,
            'function_executions': dict(self.function_executions),
        }
```

### 3.2 Statistics Output Format

**MUST match baseline format exactly** (from `analyze_fuzzing_coverage.py`):

```json
{
  "functions": [
    {
      "function_id": "src/path/file.cpp:cvc5::ClassName::methodName(args):123",
      "triggered": true,
      "execution_count": 1234
    },
    {
      "function_id": "src/path/file.cpp:cvc5::OtherClass::method():456", 
      "triggered": false,
      "execution_count": 0
    }
  ]
}
```

**Key fields:**
- `function_id`: Format is `file_path:demangled_signature:line_number`
- `triggered`: Boolean, true if `execution_count > 0`
- `execution_count`: Integer, total times function was called

---

## Phase 4: Workflow Updates

### 4.1 Fuzzing Workflow

```yaml
# .github/workflows/cvc5-evaluation-rq2-fuzzing-sancov.yml

fuzzing-job:
  runs-on: ubuntu-latest
  steps:
    # ... setup steps ...
    
    - name: Clone CVC5 and checkout commit
      run: |
        COMMIT_HASH="${{ steps.get-commit.outputs.commit_hash }}"
        git clone --depth 100 https://github.com/cvc5/cvc5.git cvc5
        cd cvc5
        git fetch --depth 100 origin "$COMMIT_HASH"
        git checkout "$COMMIT_HASH"
    
    - name: Build instrumented binary
      working-directory: cvc5
      run: |
        # Setup
        python3 -m venv ~/.venv
        source ~/.venv/bin/activate
        pip install --quiet --upgrade pip
        
        # Instrumentation flags
        export CC=clang
        export CXX=clang++
        SANCOV_FLAGS="-fsanitize-coverage=trace-pc-guard"
        PGO_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
        
        # Add allowlist if provided
        if [ -f ../edge_coverage_allowlist.txt ]; then
          SANCOV_FLAGS="$SANCOV_FLAGS -fsanitize-coverage-allowlist=../edge_coverage_allowlist.txt"
        fi
        
        export CFLAGS="$SANCOV_FLAGS $PGO_FLAGS"
        export CXXFLAGS="$SANCOV_FLAGS $PGO_FLAGS"
        
        # Configure and build
        ./configure.sh production --static --auto-download
        cd build && make -j$(nproc)
    
    - name: Run coverage-guided fuzzing
      run: |
        python3 scripts/cvc5/partial_instrumentation/coverage_guided_fuzzer.py \
          --cvc5-path=cvc5/build/bin/cvc5 \
          --tests-file=tests.txt \
          --timeout=${{ inputs.fuzzing_duration_minutes * 60 }} \
          --workers=4 \
          --output-stats=fuzzing_statistics.json
    
    - name: Upload statistics to S3
      run: |
        aws s3 cp fuzzing_statistics.json \
          s3://${{ secrets.AWS_S3_BUCKET }}/evaluation/rq2/cvc5/fuzzing-stats/sancov/${COMMIT_HASH}.json
```

### 4.2 Comparison Workflow (Separate)

```yaml
# .github/workflows/cvc5-evaluation-rq2-comparison.yml

name: Compare Fuzzing Results

on:
  workflow_dispatch:
    inputs:
      commit_hash:
        description: 'Commit to compare'
        required: true

jobs:
  compare:
    runs-on: ubuntu-latest
    steps:
      - name: Download baseline statistics
        run: |
          aws s3 cp s3://${{ secrets.AWS_S3_BUCKET }}/evaluation/rq2/cvc5/fuzzing-stats/baseline/${{ inputs.commit_hash }}.json baseline.json
      
      - name: Download sancov statistics
        run: |
          aws s3 cp s3://${{ secrets.AWS_S3_BUCKET }}/evaluation/rq2/cvc5/fuzzing-stats/sancov/${{ inputs.commit_hash }}.json sancov.json
      
      - name: Run comparison
        run: |
          python3 scripts/rq2/compare_fuzzing_statistics.py \
            baseline.json sancov.json \
            --output comparison_results.json
      
      - name: Upload comparison results
        run: |
          aws s3 cp comparison_results.json \
            s3://${{ secrets.AWS_S3_BUCKET }}/evaluation/rq2/cvc5/comparison/${{ inputs.commit_hash }}.json
```

---

## Phase 5: Implementation Tasks

### Task 1: Instrumented Build Script
- [x] Create `build_instrumented_cvc5.sh` (full build with sancov + PGO)
- [x] Test sancov instrumentation locally (PASSED - 23 edges with allowlist)
- [x] Test PGO instrumentation locally (PASSED - 8 functions with counts)
- [x] Verify allowlists work correctly (CRITICAL - see learnings below)
- [ ] Integrate into CI workflow

#### Debugging Learnings (Local Test Results)

**Without allowlists:** ~35,000 edges (full binary instrumented)
**With allowlists:** 23 edges (only ~10 specified functions instrumented)

**Final verified results:**
```
Edge coverage:
  Test 1 (LIA): 21 edges (+21 new)
  Test 2 (BV):  22 edges (+1 new)
  Test 3 (Strings): 23 edges (+1 new)
  Total unique edges: 23

Function counts (PGO):
  dec(): 280,777x
  inc(): 231,910x
  isIntegral(): 4,761x
  getPostRewriteCache(): 2,268x
  isLeafMember(): 2,094x
  String(): 3x
  needsEqualityEngine(): 3x
  BvInverter(): 3x
```

### Task 2: Coverage-Guided Fuzzer
- [x] Create `coverage_guided_fuzzer.py` (based on `simple_commit_fuzzer_sancov.py`)
- [x] Implement multi-generation mutant management (current_queue/next_queue swap)
- [x] Implement AFL++-style virgin map (per-worker shared memory)
- [x] Two solvers (z3 + cvc5) like simple_commit_fuzzer
- [x] 4 workers with separate scratch/log folders
- [x] Delete mutants without new coverage (disk space management)
- [x] Restart with initial tests when queue empty (stop only on timeout)
- [ ] Test with typefuzz `-i 1 -k` flags
- [ ] Verify mutant detection from scratch folder

### Task 3: Prepare Commit Fuzzer Updates
- [ ] Add `generate_allowlists()` function
- [ ] Add `--output-pgo-allowlist` and `--output-edge-allowlist` flags
- [ ] Test allowlist generation

### Task 4: Statistics Collection
- [x] Implement PGO profile merging (`llvm-profdata merge`)
- [x] Implement function count extraction (`extract_function_counts.py` using `llvm-cov export`)
- [ ] Match baseline format exactly (verify with `analyze_fuzzing_coverage.py`)
- [ ] Test end-to-end with baseline comparison

### Task 5: Workflow Updates
- [ ] Update fuzzing workflow
- [ ] Create comparison workflow
- [ ] Test end-to-end

---

## Key Design Decisions

### 1. Fuzzing Logic: Dynamic Multi-Generation Queues
- **Decision**: Use two queue variables (`current_queue`, `next_queue`) swapped between generations
- **Rationale**: No hardcoded queue numbers, unlimited generations, clean memory management
- **Queue sorting**: By execution time (fast → slow) using heap for O(log n) operations
- **Generation 0**: Initial tests (not deleted after fuzzing)
- **Generation 1+**: Mutants (deleted after fuzzing to save disk space)

### 2. Typefuzz Integration
- **Command**: `typefuzz -i 1 -m 2 --timeout 120 --bugs <bugs> --scratch <scratch> --logfolder <logs> -k "z3 smt.threads=1 memory_max_size=2048;cvc5 --check-models --check-proofs --strings-exp" <test>`
- **Flags**: `-i 1` (1 iteration), `-k` (keep mutants), `-m 2` (modulo)
- **Solvers**: z3 (with memory limit) + cvc5 (with --check-models --check-proofs --strings-exp)
- **Mutant location**: `<scratch>/*.smt2` (collected after each run)

### 3. Instrumentation Strategy
- **Decision**: Build from scratch with instrumentation flags (simpler and more reliable)
- **Flags**: `-fsanitize-coverage=trace-pc-guard` (sancov) + `-fprofile-instr-generate` (PGO)
- **Allowlists**: CRITICAL for selective instrumentation (see detailed format below)
- **Tested locally**: Sancov ✓ (23 edges with allowlist), PGO ✓ (8 functions with counts)

#### CRITICAL: Allowlist Configuration (Learned from Debugging)

**Sancov Allowlist** (`-fsanitize-coverage-allowlist=<file>`):
```
# Format: src:* first, then fun: entries with mangled names
src:*
fun:_ZN4cvc58internal4expr9NodeValue3decEv
fun:_ZN4cvc58internal4expr9NodeValue3incEv
# ... more functions
```

**PGO Allowlist** (`-fprofile-list=<file>`):
```
# Format: [clang] section with fun: entries
[clang]
fun:_ZN4cvc58internal4expr9NodeValue3decEv
fun:_ZN4cvc58internal4expr9NodeValue3incEv
# ... more functions
```

**Build script MUST pass both allowlists:**
```bash
SANCOV_FLAGS="-fsanitize-coverage=trace-pc-guard"
PGO_FLAGS="-fprofile-instr-generate -fcoverage-mapping"

if [ -f "$SANCOV_ALLOWLIST" ]; then
    SANCOV_FLAGS="$SANCOV_FLAGS -fsanitize-coverage-allowlist=$SANCOV_ALLOWLIST"
fi

if [ -f "$PGO_ALLOWLIST" ]; then
    PGO_FLAGS="$PGO_FLAGS -fprofile-list=$PGO_ALLOWLIST"
fi
```

**Impact of allowlists:**
| Metric | Without Allowlist | With Allowlist |
|--------|-------------------|----------------|
| Edges instrumented | ~35,000 | 23 |
| Functions with PGO | ~25,000 | 8 |
| Build overhead | High | Minimal |

### 4. Coverage Tracking: AFL++ Virgin Map
- **Bitmap size**: 64KB (65536 bytes)
- **Virgin map**: 0xFF = unseen, lower = seen (0x00 after coverage)
- **Algorithm**: Byte-level comparison for new edge detection
- **Per-worker shared memory**: Each worker has `/dev/shm/afl_shm_{worker_id}`
- **Worker count**: 4 workers, each with its own SHM, scratch, and log folder

#### Incremental Edge Tracking (Learned from Debugging)

Use `coverage_tracker.py` for proper incremental tracking:

```python
# coverage_tracker.py handles:
# 1. Initialize SHM file (/dev/shm/afl_shm_{ID})
# 2. Run test, read bitmap
# 3. Compare with cumulative bitmap to find NEW edges
# 4. Merge into cumulative, reset for next test
# 5. Report per-test and total unique edges

tracker = CoverageTracker(binary_path)
for test in tests:
    result = tracker.run_test(test)
    print(f"Edges: {result['total_edges']} (+{result['new_edges_count']} new)")
```

**Output format:**
```
[1/3] ✅ test1.smt2
     Time: 17ms | Edges: 21 (+21 new)
[2/3] ✅ test2.smt2
     Time: 20ms | Edges: 22 (+1 new)
[3/3] ✅ test3.smt2
     Time: 20ms | Edges: 23 (+1 new)

Total edges discovered: 23
```

### 5. PGO Profile Handling
- **Merge interval**: Every 100 tests (or after all tests complete)
- **Format**: `.profraw` → `llvm-profdata merge` → `.profdata`
- **Extraction**: `llvm-cov export` (NOT `llvm-profdata show` - see below)

#### CRITICAL: Use llvm-cov export for Function Counts (Learned from Debugging)

**Wrong approach** (`llvm-profdata show`):
- Shows raw counters per function
- Format is hard to parse
- Function counts often show 0

**Correct approach** (`llvm-cov export`):
```bash
# Merge profraw files
llvm-profdata merge -sparse -o merged.profdata *.profraw

# Export function counts as JSON
llvm-cov export -instr-profile=merged.profdata /path/to/binary
```

**Python script `extract_function_counts.py` handles this correctly:**
- Uses `llvm-cov export` to get JSON with function counts
- Demangles C++ names using `c++filt`
- Separates CVC5 functions from STL/system functions
- Outputs in baseline-compatible format

### 6. Statistics Format
- **Must match**: `analyze_fuzzing_coverage.py` baseline format
- **Key fields**: `function_id`, `triggered`, `execution_count`

### 7. Comparison
- **Separate workflow**: Decouples fuzzing from analysis
- **Trigger**: Manual or after fuzzing completes
- **Uses**: Existing comparison scripts

---

## Debugging Learnings & Common Issues

### Issue 1: Too Many Edges (35,000+ instead of ~20)
**Cause**: Allowlists not being passed to build script
**Solution**: Ensure test script passes allowlists:
```bash
/scripts/build_cvc5_sancov.sh "" "$SANCOV_ALLOWLIST" "$PGO_ALLOWLIST"
```

### Issue 2: Function Counts All Zero
**Cause**: Using `llvm-profdata show` instead of `llvm-cov export`
**Solution**: Use `extract_function_counts.py` which uses `llvm-cov export`

### Issue 3: Binary Crashes on Startup
**Cause**: Missing coverage agent linkage
**Solution**: Build `coverage_agent.o` and link via `CMAKE_EXE_LINKER_FLAGS`:
```bash
clang++ -c -o coverage_agent.o coverage_agent.cpp -O2 -fno-sanitize-coverage=trace-pc-guard
cmake -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS} ${AGENT_OBJ}" .
```

### Issue 4: PGO Allowlist Not Working
**Cause**: Wrong flag (`-fsanitize-coverage-allowlist` only works for sancov)
**Solution**: Use `-fprofile-list=<file>` for PGO with `[clang]` section format

### Issue 5: Shared Memory Not Found
**Cause**: Mismatch between expected SHM path and actual path
**Solution**: Coverage agent expects `/dev/shm/afl_shm_{__AFL_SHM_ID}` when using AFL-style SHM

### Issue 6: Edge Count Not Incremental
**Cause**: Bash script manually counting edges incorrectly
**Solution**: Use `coverage_tracker.py` which properly tracks cumulative coverage

---

## Local Testing Plan

### Step 1: Test Instrumented Build (COMPLETED ✓)
```bash
cd scripts/cvc5/partial_instrumentation/local_test

# Build Docker image and run full sancov + PGO test
./test_sancov_docker.sh

# For subsequent runs (skip build, use cached binary):
./test_sancov_docker.sh --skip-build

# Clean cache and rebuild from scratch:
docker volume rm cvc5-sancov-cache
./test_sancov_docker.sh

# Results achieved (with allowlists):
# - Build time: ~8-9 minutes (cached in Docker volume)
# - Sancov symbols: 32 (coverage agent runtime)
# - PGO symbols: 54 (profile runtime)
# - Edges discovered: 23 (selective instrumentation working!)
# - Profraw files: 3 (one per test)
# - CVC5 functions called: 5,547
# - Total CVC5 calls: 521,819
# - dec() called: 280,777x
# - inc() called: 231,910x
```

### Key Scripts (in local_test/):
- `test_sancov_docker.sh` - Builds Docker image and runs test
- `test_sancov_local.sh` - Main test script (runs inside container)
- `build_cvc5_sancov.sh` - Builds CVC5 with sancov + PGO + allowlists
- `coverage_tracker.py` - Python script for incremental edge tracking
- `extract_function_counts.py` - Python script for PGO function counts
- `sancov_allowlist.txt` - Sancov allowlist (src:* + fun: entries)
- `pgo_allowlist.txt` - PGO allowlist ([clang] + fun: entries)

### Step 2: Test Fuzzer Locally
```bash
# Create test list
echo '["regress0/arith/arith.smt2", "regress0/bv/test.smt2"]' > tests.json

# Run coverage-guided fuzzer (short test)
python3 coverage_guided_fuzzer.py \
  --cvc5-path=./cvc5/build/bin/cvc5 \
  --tests-root=./cvc5/test/regress/cli \
  --tests-json='["regress0/arith/arith.smt2"]' \
  --fuzzing-duration-minutes=5 \
  --workers=4 \
  --output-dir=./output \
  --bugs-folder=./bugs

# Verify:
# - 4 workers running in parallel
# - Each worker has separate scratch/log/SHM
# - Mutants with new coverage are kept
# - Mutants without new coverage are deleted
# - Queue restarts with initial tests when empty
# - Statistics are generated in output/coverage_stats.json
```

### Step 3: Test Statistics Format
```bash
# Compare with baseline format
python3 -c "
import json
with open('test_stats.json') as f:
    stats = json.load(f)
    
# Verify structure
assert 'functions' in stats
for func in stats['functions']:
    assert 'function_id' in func
    assert 'triggered' in func
    assert 'execution_count' in func
print('Format OK!')
"
```

---

## File Structure

```
scripts/cvc5/
├── partial_instrumentation/
│   ├── coverage_agent.cpp (custom sancov runtime - writes to SHM)
│   ├── coverage_guided_fuzzer.py (MAIN - multiprocessing fuzzer based on simple_commit_fuzzer)
│   ├── run_fuzzing.py (orchestration - loads config, runs fuzzer, collects stats)
│   ├── generate_allowlists.py (generates sancov + PGO allowlists from changed_functions.json)
│   ├── coverage_tracker.py (Python - incremental edge tracking via SHM)
│   ├── extract_function_counts.py (Python - PGO function counts via llvm-cov export)
│   ├── PRODUCTION_WORKFLOW_PLAN.md (this file)
│   └── local_test/
│       ├── Dockerfile.test-sancov (Docker image for testing)
│       ├── test_sancov_docker.sh (wrapper - builds image, runs test)
│       ├── test_sancov_local.sh (main test script - runs inside container)
│       ├── build_cvc5_sancov.sh (builds CVC5 with sancov + PGO + allowlists)
│       ├── sancov_allowlist.txt (sancov allowlist: src:* + fun:)
│       └── pgo_allowlist.txt (PGO allowlist: [clang] + fun:)
├── commit_fuzzer/
│   ├── simple_commit_fuzzer.py (original - gcov-based)
│   ├── simple_commit_fuzzer_sancov.py (reference - sancov-enabled, used as base for coverage_guided_fuzzer)
│   ├── prepare_commit_fuzzer_sancov.py (to be updated with allowlist generation)
│   └── analyze_fuzzing_coverage.py (reference for output format)
```

### Coverage-Guided Fuzzer Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Main Process                                                            │
│   ├── Resource Monitor Thread (CPU/RAM monitoring, kills high-mem procs)│
│   ├── Global Virgin Map (merged from workers)                           │
│   ├── Virgin Map Queue (receives worker coverage updates)               │
│   ├── Result Queue (receives mutants with new coverage)                 │
│   └── Test Queue (shared, workers pop items)                            │
└─────────────────────────────────────────────────────────────────────────┘
          │                                        │
          ▼                                        ▼
┌─────────────────────┐                  ┌─────────────────────┐
│ Worker 1            │                  │ Worker 2            │
│ ├── scratch_1/      │                  │ ├── scratch_2/      │
│ ├── logs_1/         │                  │ ├── logs_2/         │
│ ├── bugs/worker_1/  │                  │ ├── bugs/worker_2/  │
│ └── SHM: afl_shm_1  │                  │ └── SHM: afl_shm_2  │
└─────────────────────┘                  └─────────────────────┘
          │                                        │
          ▼                                        ▼
┌─────────────────────┐                  ┌─────────────────────┐
│ Worker 3            │                  │ Worker 4            │
│ ├── scratch_3/      │                  │ ├── scratch_4/      │
│ ├── logs_3/         │                  │ ├── logs_4/         │
│ ├── bugs/worker_3/  │                  │ ├── bugs/worker_4/  │
│ └── SHM: afl_shm_3  │                  │ └── SHM: afl_shm_4  │
└─────────────────────┘                  └─────────────────────┘
```

### Per-Worker Resources
- **Shared Memory**: `/dev/shm/afl_shm_{worker_id}` (64KB AFL-style bitmap)
- **Scratch Folder**: `output/scratch_{worker_id}/` (typefuzz mutants, cleared after each test)
- **Log Folder**: `output/logs_{worker_id}/` (typefuzz logs, cleared after each test)
- **Bugs Folder**: `bugs/worker_{worker_id}/` (found bugs, moved to main folder at end)

### Coverage Agent Details (`coverage_agent.cpp`)

The coverage agent provides custom implementations of:
- `__sanitizer_cov_trace_pc_guard_init()` - Initializes guard IDs
- `__sanitizer_cov_trace_pc_guard()` - Writes edge hits to shared memory

**Shared memory naming:**
- If `__AFL_SHM_ID` is set: `/dev/shm/afl_shm_{ID}`
- Otherwise if `COVERAGE_SHM_NAME` is set: `/dev/shm/{NAME}`

**Example usage:**
```bash
export __AFL_SHM_ID="0x12345678"
dd if=/dev/zero of="/dev/shm/afl_shm_0x12345678" bs=65536 count=1
./cvc5 test.smt2
# Coverage bitmap written to /dev/shm/afl_shm_0x12345678
```
