#!/bin/bash
# Test sancov + PGO instrumented CVC5 build
# Uses Python scripts for proper coverage tracking
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-/workspace}"
CVC5_DIR="${WORKSPACE}/cvc5"
BUILD_DIR="${CVC5_DIR}/build"
BINARY="${BUILD_DIR}/bin/cvc5"

log() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
ok() { echo -e "\033[0;32m[OK]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
err() { echo -e "\033[0;31m[ERROR]\033[0m $1"; }

# Parse args
SKIP_BUILD=false
for arg in "$@"; do
    case $arg in
        --skip-build) SKIP_BUILD=true ;;
    esac
done

echo "=== SANCOV + PGO INSTRUMENTATION TEST ==="

# Phase 1: Build (or skip if cached)
if [ "$SKIP_BUILD" = true ] && [ -f "$BINARY" ]; then
    log "Phase 1: Skipping build (using cached binary)"
else
    log "Phase 1: Building instrumented CVC5 (with allowlists)"
    # Pass allowlists for selective instrumentation
    SANCOV_ALLOWLIST="/scripts/sancov_allowlist.txt"
    PGO_ALLOWLIST="/scripts/pgo_allowlist.txt"
    /scripts/build_cvc5_sancov.sh "" "$SANCOV_ALLOWLIST" "$PGO_ALLOWLIST"
fi

# Verify binary exists
if [ ! -f "$BINARY" ]; then
    err "Binary not found: $BINARY"
    exit 1
fi

# Phase 2: Verify instrumentation
log "Phase 2: Verifying instrumentation"
SANCOV_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__sanitizer_cov" || echo "0")
PGO_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__llvm_profile" || echo "0")
echo "  Sancov symbols: $SANCOV_SYM"
echo "  PGO symbols: $PGO_SYM"

if [ "$SANCOV_SYM" -eq 0 ]; then
    err "No sancov symbols found!"
    exit 1
fi
if [ "$PGO_SYM" -eq 0 ]; then
    warn "No PGO symbols found (may need compiler-rt)"
fi

# Phase 3: Create test files
log "Phase 3: Creating test files"
TEST_DIR="${BUILD_DIR}/test"
PROFILE_DIR="${TEST_DIR}/profiles"
mkdir -p "$PROFILE_DIR"

# Test 1: Linear Integer Arithmetic
cat > "${TEST_DIR}/test1.smt2" << 'EOF'
(set-logic QF_LIA)
(declare-fun x () Int)
(declare-fun y () Int)
(assert (> x 0))
(assert (< y 100))
(assert (= (+ x y) 50))
(check-sat)
EOF

# Test 2: Bitvectors
cat > "${TEST_DIR}/test2.smt2" << 'EOF'
(set-logic QF_BV)
(declare-fun a () (_ BitVec 32))
(declare-fun b () (_ BitVec 32))
(assert (= (bvadd a b) #x00000042))
(assert (bvugt a #x00000010))
(check-sat)
EOF

# Test 3: Strings
cat > "${TEST_DIR}/test3.smt2" << 'EOF'
(set-logic QF_SLIA)
(declare-fun s () String)
(assert (= (str.len s) 5))
(assert (str.contains s "abc"))
(check-sat)
EOF

# Phase 4: Run coverage tracking with Python script
log "Phase 4: Running coverage tracker (Python)"

# Setup SHM ID for coverage agent
export __AFL_SHM_ID="0x12345678"

# Setup PGO profile output
export LLVM_PROFILE_FILE="${PROFILE_DIR}/test-%p.profraw"

# Run coverage tracker - it handles SHM and incremental tracking properly
python3 /scripts/coverage_tracker.py "$BINARY" \
    "${TEST_DIR}/test1.smt2" \
    "${TEST_DIR}/test2.smt2" \
    "${TEST_DIR}/test3.smt2" \
    --output "${TEST_DIR}/coverage_report.json"

TRACKER_EXIT=$?

# Phase 5: Extract function counts with Python script
log "Phase 5: Extracting function counts (Python)"

PROFRAW_COUNT=$(find "$PROFILE_DIR" -name "*.profraw" -size +0 2>/dev/null | wc -l | xargs)
echo "  Profraw files: $PROFRAW_COUNT"

if [ "$PROFRAW_COUNT" -gt 0 ]; then
    python3 /scripts/extract_function_counts.py "$BINARY" \
        --profile-dir "$PROFILE_DIR" \
        --output "${TEST_DIR}/function_counts.json" \
        --top 20
    EXTRACTOR_EXIT=$?
else
    warn "No profraw files generated - PGO not working"
    EXTRACTOR_EXIT=1
fi

# Phase 6: Summary
log "Phase 6: Summary"
echo ""
echo "=== RESULTS ==="
echo "Sancov symbols: $SANCOV_SYM"
echo "PGO symbols:    $PGO_SYM"
echo "Profraw files:  $PROFRAW_COUNT"

if [ -f "${TEST_DIR}/coverage_report.json" ]; then
    echo ""
    echo "Edge coverage report: ${TEST_DIR}/coverage_report.json"
    python3 -c "import json; d=json.load(open('${TEST_DIR}/coverage_report.json')); s=d['summary']; print(f\"  Total edges: {s['total_edges']:,}\"); print(f\"  Tests with new edges: {s['tests_with_new_edges']}/{s['total_tests']}\")"
fi

if [ -f "${TEST_DIR}/function_counts.json" ]; then
    echo ""
    echo "Function counts report: ${TEST_DIR}/function_counts.json"
    python3 -c "import json; d=json.load(open('${TEST_DIR}/function_counts.json')); s=d['summary']; print(f\"  CVC5 functions called: {s['total_cvc5_functions']:,}\"); print(f\"  Total CVC5 calls: {s['total_cvc5_calls']:,}\")"
fi

echo ""

# Determine pass/fail
if [ "$SANCOV_SYM" -eq 0 ]; then
    err "FAILED: No sancov instrumentation"
    exit 1
fi

if [ "$TRACKER_EXIT" -ne 0 ]; then
    err "FAILED: Coverage tracker failed"
    exit 1
fi

ok "TEST PASSED"
echo ""
echo "Re-run faster: $0 --skip-build"
