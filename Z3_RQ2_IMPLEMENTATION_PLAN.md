# Z3 RQ2 Implementation Plan

## Overview
This document outlines the plan to implement Z3 RQ2 evaluation to match CVC5's implementation, using coverage-guided fuzzing with partial instrumentation.

## Current State Analysis

### CVC5 RQ2 Implementation
**Location:** `scripts/cvc5/partial_instrumentation/`

**Key Components:**
1. **`coverage_guided_fuzzer.py`** - Main fuzzer with inline typefuzz and coverage tracking
2. **`coverage_agent.cpp`** - Coverage tracking agent (AFL-style bitmap)
3. **`build_cvc5_instrumented.sh`** - Build script for instrumented binary
4. **`generate_allowlists.py`** - Generates sancov/PGO allowlists from changed functions
5. **`extract_function_counts.py`** - Extracts function execution counts
6. **`convert_function_counts.py`** - Converts function counts format

**Workflows:**
- `cvc5-evaluation-rq2-fuzzing-baseline.yml` - Random test selection
- `cvc5-evaluation-rq2-fuzzing-variant1.yml` - Coverage mapping (perfect)
- `cvc5-evaluation-rq2-fuzzing-variant2.yml` - Coverage-guided fuzzing
- `cvc5-evaluation-rq2-measure-baseline.yml` - Measure baseline coverage
- `cvc5-evaluation-rq2-measure-variant1.yml` - Measure variant1 coverage
- `cvc5-evaluation-rq2-measure-variant2.yml` - Measure variant2 coverage
- `cvc5-evaluation-rq2-measurement-comparison.yml` - Compare measurements

### Z3 RQ2 Current State
**Location:** `scripts/z3/commit_fuzzer/`

**Key Components:**
1. **`simple_commit_fuzzer.py`** - Basic fuzzer using typefuzz subprocess
2. **`prepare_commit_fuzzer.py`** - Prepares fuzzing matrix from coverage mapping
3. **`analyze_fuzzing_coverage.py`** - Post-fuzzing coverage analysis (fastcov)

**Workflows:**
- `z3-evaluation-rq2-fuzzing-baseline.yml` - Random test selection
- `z3-evaluation-rq2-fuzzing-coverage.yml` - Uses coverage mapping (different from variant1)
- `z3-evaluation-rq2-fuzzing-comparison.yml` - Comparison workflow

**Missing:**
- No `partial_instrumentation` directory
- No coverage-guided fuzzing (variant2)
- No measurement workflows
- No inline typefuzz mode
- No real-time coverage tracking

## Implementation Plan

### Phase 1: Create Z3 Partial Instrumentation Infrastructure

#### 1.1 Create Directory Structure
```
scripts/z3/partial_instrumentation/
├── coverage_agent.cpp          # Copy from cvc5, adapt for Z3
├── build_z3_instrumented.sh     # Adapt from build_cvc5_instrumented.sh
├── coverage_guided_fuzzer.py    # Copy from cvc5, adapt for Z3
├── generate_allowlists.py        # Copy from cvc5 (should work as-is)
├── extract_function_counts.py    # Copy from cvc5, adapt for Z3
├── convert_function_counts.py    # Copy from cvc5 (should work as-is)
└── merge_coverage_stats.py       # Copy from cvc5, adapt for Z3
```

#### 1.2 Adapt `coverage_agent.cpp` for Z3
**Changes needed:**
- Update binary path detection (Z3 vs CVC5)
- Ensure AFL-style shared memory works with Z3
- Test coverage tracking with Z3 binary

**Files to modify:**
- `scripts/z3/partial_instrumentation/coverage_agent.cpp`

#### 1.3 Create `build_z3_instrumented.sh`
**Based on:** `scripts/cvc5/partial_instrumentation/build_cvc5_instrumented.sh`

**Changes needed:**
- Replace CVC5 build commands with Z3 build commands
- Update paths (cvc5/ → z3/)
- Update CMake configuration for Z3
- Ensure sancov instrumentation flags are correct
- Link coverage_agent.cpp

**Key differences:**
- Z3 uses different build system (may need to check)
- Z3 binary location: `build/z3` vs `build/bin/cvc5`
- Z3 test directory: `z3test/` vs `test/regress/cli/`

#### 1.4 Adapt `coverage_guided_fuzzer.py` for Z3
**Based on:** `scripts/cvc5/partial_instrumentation/coverage_guided_fuzzer.py`

**Changes needed:**
1. **Binary paths:**
   - `cvc5_path` → `z3_path`
   - Default: `./build/z3` vs `./build/bin/cvc5`

2. **Test discovery:**
   - Z3 test directory: `z3test/` vs `test/regress/cli/`
   - Update test file patterns if needed

3. **Solver commands:**
   - Z3: `z3 smt.threads=1 memory_max_size=2048 model_validate=true`
   - CVC5: `cvc5 --check-models --check-proofs --strings-exp`
   - Update `_get_solver_clis()` method

4. **Build directory:**
   - Z3: `build/` vs CVC5: `build/`
   - Update paths in coverage extraction

5. **Coverage agent:**
   - Update path to `coverage_agent.cpp`
   - Ensure shared memory ID format matches

6. **Profraw handling:**
   - Z3 may use different profiling setup
   - Verify LLVM_PROFILE_FILE works with Z3

**Files to modify:**
- `scripts/z3/partial_instrumentation/coverage_guided_fuzzer.py`

#### 1.5 Adapt `extract_function_counts.py` for Z3
**Based on:** `scripts/cvc5/partial_instrumentation/extract_function_counts.py`

**Changes needed:**
- Update build directory paths
- Verify profraw file locations for Z3
- Update function name demangling if Z3 uses different format

**Files to modify:**
- `scripts/z3/partial_instrumentation/extract_function_counts.py`

### Phase 2: Create Z3 Fuzzing Workflows

#### 2.1 Create `z3-evaluation-rq2-fuzzing-variant1.yml`
**Based on:** `cvc5-evaluation-rq2-fuzzing-variant1.yml`

**Changes needed:**
- Update solver references (cvc5 → z3)
- Update paths (cvc5/ → z3/)
- Update S3 paths (`evaluation/rq2/cvc5/` → `evaluation/rq2/z3/`)
- Update test directory references
- Remove partial_instrumentation steps (variant1 uses coverage mapping only)

#### 2.2 Create `z3-evaluation-rq2-fuzzing-variant2.yml`
**Based on:** `cvc5-evaluation-rq2-fuzzing-variant2.yml`

**Changes needed:**
- Update solver references
- Update paths to use `scripts/z3/partial_instrumentation/`
- Update build script: `build_z3_instrumented.sh`
- Update fuzzer script: `coverage_guided_fuzzer.py`
- Update S3 paths
- Update test directory: `z3test/` vs `test/regress/cli/`
- Update binary paths: `build/z3` vs `build/bin/cvc5`

**Key steps to adapt:**
1. Generate allowlists (sancov + PGO)
2. Build instrumented Z3 binary
3. Run coverage-guided fuzzer
4. Extract function counts
5. Upload statistics

### Phase 3: Create Z3 Measurement Workflows

#### 3.1 Create `z3-evaluation-rq2-measure-baseline.yml`
**Based on:** `cvc5-evaluation-rq2-measure-baseline.yml`

**Changes needed:**
- Update solver path: `build/z3` vs `build/bin/cvc5`
- Update S3 paths
- Update recipe replay script paths (should work as-is in `scripts/rq2/`)

#### 3.2 Create `z3-evaluation-rq2-measure-variant1.yml`
**Based on:** `cvc5-evaluation-rq2-measure-variant1.yml`

**Changes needed:**
- Same as baseline, but uses variant1 recipes
- Update S3 paths for variant1 recipes

#### 3.3 Create `z3-evaluation-rq2-measure-variant2.yml`
**Based on:** `cvc5-evaluation-rq2-measure-variant2.yml`

**Changes needed:**
- Same as baseline, but uses variant2 recipes
- Update S3 paths for variant2 recipes

#### 3.4 Create `z3-evaluation-rq2-measurement-comparison.yml`
**Based on:** `cvc5-evaluation-rq2-measurement-comparison.yml`

**Changes needed:**
- Update S3 paths
- Update solver references in comparison script

### Phase 4: Testing and Validation

#### 4.1 Local Testing
1. **Test coverage_agent.cpp:**
   - Build Z3 with coverage agent
   - Run a test and verify coverage tracking works
   - Check shared memory is created correctly

2. **Test build_z3_instrumented.sh:**
   - Build instrumented Z3 binary
   - Verify sancov instrumentation is present
   - Verify coverage_agent is linked

3. **Test coverage_guided_fuzzer.py:**
   - Run on a small test set
   - Verify coverage tracking works
   - Verify mutants are generated
   - Verify statistics are collected

4. **Test workflows:**
   - Run variant2 fuzzing on a single commit
   - Verify recipes are generated
   - Verify statistics are uploaded to S3

#### 4.2 Integration Testing
1. **End-to-end test:**
   - Run full RQ2 pipeline for 1-2 commits
   - Verify all stages work:
     - Build
     - Coverage mapping (variant1)
     - Fuzzing (baseline, variant1, variant2)
     - Measurement (all variants)
     - Comparison

## Detailed File-by-File Changes

### Files to Create (New)

1. **`scripts/z3/partial_instrumentation/coverage_agent.cpp`**
   - Copy from: `scripts/cvc5/partial_instrumentation/coverage_agent.cpp`
   - Changes: Minimal (should work as-is, just verify)

2. **`scripts/z3/partial_instrumentation/build_z3_instrumented.sh`**
   - Copy from: `scripts/cvc5/partial_instrumentation/build_cvc5_instrumented.sh`
   - Changes: Replace CVC5 build commands with Z3

3. **`scripts/z3/partial_instrumentation/coverage_guided_fuzzer.py`**
   - Copy from: `scripts/cvc5/partial_instrumentation/coverage_guided_fuzzer.py`
   - Changes: Update paths, solver commands, test directories

4. **`scripts/z3/partial_instrumentation/generate_allowlists.py`**
   - Copy from: `scripts/cvc5/partial_instrumentation/generate_allowlists.py`
   - Changes: None (should work as-is)

5. **`scripts/z3/partial_instrumentation/extract_function_counts.py`**
   - Copy from: `scripts/cvc5/partial_instrumentation/extract_function_counts.py`
   - Changes: Update paths, verify profraw locations

6. **`scripts/z3/partial_instrumentation/convert_function_counts.py`**
   - Copy from: `scripts/cvc5/partial_instrumentation/convert_function_counts.py`
   - Changes: None (should work as-is)

7. **`scripts/z3/partial_instrumentation/merge_coverage_stats.py`**
   - Copy from: `scripts/cvc5/partial_instrumentation/merge_coverage_stats.py`
   - Changes: Update S3 paths

### Workflows to Create (New)

1. **`.github/workflows/z3-evaluation-rq2-fuzzing-variant1.yml`**
   - Copy from: `cvc5-evaluation-rq2-fuzzing-variant1.yml`
   - Changes: Update all cvc5 → z3 references

2. **`.github/workflows/z3-evaluation-rq2-fuzzing-variant2.yml`**
   - Copy from: `cvc5-evaluation-rq2-fuzzing-variant2.yml`
   - Changes: Update all cvc5 → z3 references, paths

3. **`.github/workflows/z3-evaluation-rq2-measure-baseline.yml`**
   - Copy from: `cvc5-evaluation-rq2-measure-baseline.yml`
   - Changes: Update solver paths, S3 paths

4. **`.github/workflows/z3-evaluation-rq2-measure-variant1.yml`**
   - Copy from: `cvc5-evaluation-rq2-measure-variant1.yml`
   - Changes: Update solver paths, S3 paths

5. **`.github/workflows/z3-evaluation-rq2-measure-variant2.yml`**
   - Copy from: `cvc5-evaluation-rq2-measure-variant2.yml`
   - Changes: Update solver paths, S3 paths

6. **`.github/workflows/z3-evaluation-rq2-measurement-comparison.yml`**
   - Copy from: `cvc5-evaluation-rq2-measurement-comparison.yml`
   - Changes: Update S3 paths

## Key Differences: CVC5 vs Z3

| Aspect | CVC5 | Z3 |
|--------|------|-----|
| Binary path | `build/bin/cvc5` | `build/z3` |
| Test directory | `test/regress/cli/` | `z3test/` |
| Solver command | `cvc5 --check-models ...` | `z3 smt.threads=1 ...` |
| Build system | CMake | CMake (verify) |
| Coverage agent | `coverage_agent.cpp` | Same (adapt paths) |
| Profraw location | `build/` | `build/` (verify) |
| S3 prefix | `evaluation/rq2/cvc5/` | `evaluation/rq2/z3/` |

## Implementation Order

1. **Phase 1.1-1.2:** Create directory structure and adapt coverage_agent.cpp
2. **Phase 1.3:** Create build_z3_instrumented.sh and test locally
3. **Phase 1.4:** Adapt coverage_guided_fuzzer.py (most complex)
4. **Phase 1.5:** Adapt remaining scripts (extract_function_counts, etc.)
5. **Phase 2:** Create fuzzing workflows (variant1, variant2)
6. **Phase 3:** Create measurement workflows
7. **Phase 4:** Test end-to-end

## Testing Checklist

- [ ] Coverage agent compiles and links with Z3
- [ ] Instrumented Z3 binary runs and tracks coverage
- [ ] Coverage-guided fuzzer runs on Z3 tests
- [ ] Mutants are generated correctly
- [ ] Coverage statistics are collected
- [ ] Function counts are extracted
- [ ] Recipes are generated and can be replayed
- [ ] All workflows run successfully
- [ ] S3 uploads/downloads work correctly
- [ ] Measurement workflows produce correct results

## Notes

- The `scripts/rq2/` directory contains shared scripts that should work for both Z3 and CVC5
- The `inline_typefuzz.py` in `scripts/rq2/` is shared and should work for both
- Most adaptation will be in paths, solver commands, and build processes
- The core fuzzing logic should be very similar between Z3 and CVC5
