#!/bin/bash
# Test incremental instrumentation using compile_commands.json + coverage_agent
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-/workspace}"
CVC5_DIR="${WORKSPACE}/cvc5"
BUILD_DIR="${CVC5_DIR}/build"

log() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
ok() { echo -e "\033[0;32m[OK]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
err() { echo -e "\033[0;31m[ERROR]\033[0m $1"; }

SKIP_PRODUCTION_BUILD=false
for arg in "$@"; do
    case $arg in
        --skip-production-build) SKIP_PRODUCTION_BUILD=true ;;
        --commit=*) COMMIT_HASH="${arg#*=}" ;;
    esac
done

echo "=== INCREMENTAL INSTRUMENTATION TEST ==="

# Phase 1: Clone CVC5
log "Phase 1: Preparing CVC5"
[ ! -d "$CVC5_DIR" ] && git clone --depth 100 https://github.com/cvc5/cvc5.git "$CVC5_DIR"
cd "$CVC5_DIR"
[ -n "$COMMIT_HASH" ] && git fetch --depth 100 origin && git checkout "$COMMIT_HASH"
echo "Commit: $(git rev-parse --short HEAD)"

# Phase 2: Build production binary (non-instrumented)
log "Phase 2: Building production binary"
if [ "$SKIP_PRODUCTION_BUILD" = true ] && [ -f "${BUILD_DIR}/bin/cvc5" ]; then
    log "Skipping production build (using cached)"
else
    export CC=clang
    export CXX=clang++
    
    # Configure for production (static, optimized)
    ./configure.sh production --static --auto-download --name="$BUILD_DIR" || {
        err "Configure failed"
        exit 1
    }
    
    cd "$BUILD_DIR"
    make -j$(nproc) || { err "Build failed"; exit 1; }
    
    ok "Production binary built: ${BUILD_DIR}/bin/cvc5"
fi

# Verify compile_commands.json exists
if [ ! -f "${BUILD_DIR}/compile_commands.json" ]; then
    err "compile_commands.json not found"
    exit 1
fi

# Phase 3: Select functions to instrument
log "Phase 3: Selecting functions to instrument"

# Example functions from different CVC5 modules
FUNCTIONS_TO_INSTRUMENT=(
    "cvc5::internal::Node::printAst"
    "cvc5::internal::NodeValue::inc"
    "cvc5::internal::NodeValue::dec"
    "cvc5::internal::expr::NodeValue::isConst"
    "cvc5::internal::theory::arith::linear::ArithCongruenceManager::explain"
    "cvc5::internal::theory::strings::StringsRewriter::rewriteConcat"
    "cvc5::internal::prop::CnfStream::convertAndAssert"
    "cvc5::internal::DecisionEngine::getNext"
)

# Create allowlist
ALLOWLIST="${BUILD_DIR}/incremental_allowlist.txt"
echo "# Incremental instrumentation allowlist" > "$ALLOWLIST"
echo "src:*" >> "$ALLOWLIST"
echo "" >> "$ALLOWLIST"
for func in "${FUNCTIONS_TO_INSTRUMENT[@]}"; do
    echo "fun:*${func}*" >> "$ALLOWLIST"
done

echo "Allowlist:"
cat "$ALLOWLIST"
echo ""

# Phase 4: Find source files containing target functions
log "Phase 4: Finding source files"

# Map functions to source files
declare -A FUNC_TO_FILE
FUNC_TO_FILE["cvc5::internal::Node::printAst"]="src/expr/node.cpp"
FUNC_TO_FILE["cvc5::internal::NodeValue::inc"]="src/expr/node_value.cpp"
FUNC_TO_FILE["cvc5::internal::NodeValue::dec"]="src/expr/node_value.cpp"
FUNC_TO_FILE["cvc5::internal::expr::NodeValue::isConst"]="src/expr/node_value.cpp"
FUNC_TO_FILE["cvc5::internal::theory::arith::linear::ArithCongruenceManager::explain"]="src/theory/arith/linear/arith_congruence_manager.cpp"
FUNC_TO_FILE["cvc5::internal::theory::strings::StringsRewriter::rewriteConcat"]="src/theory/strings/strings_rewriter.cpp"
FUNC_TO_FILE["cvc5::internal::prop::CnfStream::convertAndAssert"]="src/prop/cnf_stream.cpp"
FUNC_TO_FILE["cvc5::internal::DecisionEngine::getNext"]="src/decision/decision_engine.cpp"

# Get unique source files
declare -A SOURCE_FILES
for func in "${FUNCTIONS_TO_INSTRUMENT[@]}"; do
    file="${FUNC_TO_FILE[$func]}"
    if [ -n "$file" ] && [ -f "${CVC5_DIR}/${file}" ]; then
        SOURCE_FILES["$file"]=1
    fi
done

echo "Source files to recompile:"
for file in "${!SOURCE_FILES[@]}"; do
    echo "  $file"
done
echo ""

# Phase 5: Build coverage agent
log "Phase 5: Building coverage agent"

AGENT_SRC="/scripts/coverage_agent.cpp"
AGENT_OBJ="${BUILD_DIR}/coverage_agent.o"

if [ ! -f "$AGENT_SRC" ]; then
    err "Coverage agent source not found: $AGENT_SRC"
    exit 1
fi

clang++ -c -o "$AGENT_OBJ" "$AGENT_SRC" \
    -O2 -g -std=c++17 -Wall -Wextra \
    -fno-sanitize-coverage=trace-pc-guard || {
    err "Failed to compile coverage agent"
    exit 1
}

ok "Coverage agent built: $AGENT_OBJ"

# Phase 6: Extract compile commands and recompile with instrumentation
log "Phase 6: Recompiling selected files with instrumentation"

cd "$BUILD_DIR"

# Instrumentation flags
SANCOV_FLAGS="-fsanitize-coverage=trace-pc-guard -fsanitize-coverage-allowlist=${ALLOWLIST}"
PGO_FLAGS="-fprofile-instr-generate -fcoverage-mapping -fprofile-list=${ALLOWLIST}"
INST_FLAGS="$SANCOV_FLAGS $PGO_FLAGS"

RECOMPILED=0
FAILED=0

for src_file in "${!SOURCE_FILES[@]}"; do
    full_path="${CVC5_DIR}/${src_file}"
    
    # Extract compile command from compile_commands.json
    COMPILE_CMD=$(python3 -c "
import json
import sys

with open('compile_commands.json') as f:
    commands = json.load(f)

target = '$src_file'
for cmd in commands:
    if cmd.get('file', '').endswith(target) or target in cmd.get('file', ''):
        # Get the command and directory
        command = cmd.get('command', '')
        directory = cmd.get('directory', '.')
        print(f'{directory}|||{command}')
        break
" 2>/dev/null)
    
    if [ -z "$COMPILE_CMD" ]; then
        warn "No compile command found for $src_file"
        continue
    fi
    
    # Parse directory and command
    COMPILE_DIR=$(echo "$COMPILE_CMD" | cut -d'|||' -f1)
    ORIG_CMD=$(echo "$COMPILE_CMD" | cut -d'|||' -f2-)
    
    # Add instrumentation flags to the command
    # Insert flags after the compiler (clang++ or clang)
    INST_CMD=$(echo "$ORIG_CMD" | sed "s/clang++/clang++ $INST_FLAGS/; s/clang /clang $INST_FLAGS /")
    
    echo "Recompiling: $src_file"
    echo "  Dir: $COMPILE_DIR"
    echo "  Cmd: ${INST_CMD:0:100}..."
    
    # Execute the instrumented compile
    cd "$COMPILE_DIR"
    if eval "$INST_CMD" 2>&1; then
        ok "  Recompiled: $src_file"
        ((RECOMPILED++))
    else
        err "  Failed: $src_file"
        ((FAILED++))
    fi
done

echo ""
echo "Recompilation summary: $RECOMPILED succeeded, $FAILED failed"

# Phase 7: Relink the binary
log "Phase 7: Relinking binary with coverage agent"

cd "$BUILD_DIR"

# Find the original link command
LINK_DIR="${BUILD_DIR}/src/main"
LINK_CMD_FILE="${LINK_DIR}/link.txt"

if [ ! -f "$LINK_CMD_FILE" ]; then
    # Try to find it in CMakeFiles
    LINK_CMD_FILE=$(find "$BUILD_DIR" -name "link.txt" -path "*/cvc5-bin.dir/*" 2>/dev/null | head -1)
fi

if [ -f "$LINK_CMD_FILE" ]; then
    ORIG_LINK=$(cat "$LINK_CMD_FILE")
    
    # Add coverage agent and profile runtime to link command
    INST_LINK="$ORIG_LINK $AGENT_OBJ -fprofile-instr-generate"
    
    echo "Relinking with coverage agent..."
    cd "$LINK_DIR"
    if eval "$INST_LINK" 2>&1; then
        ok "Relinked successfully"
    else
        err "Relink failed"
        exit 1
    fi
else
    warn "link.txt not found, trying make"
    
    # Force relink by touching the main.cpp
    touch "${CVC5_DIR}/src/main/main.cpp" 2>/dev/null || true
    
    cd "$BUILD_DIR"
    CMAKE_EXE_LINKER_FLAGS="$AGENT_OBJ -fprofile-instr-generate" make -j$(nproc) cvc5-bin || {
        err "Relink via make failed"
        exit 1
    }
fi

# Phase 8: Verify instrumentation
log "Phase 8: Verifying instrumentation"

BINARY="${BUILD_DIR}/bin/cvc5"

if [ ! -f "$BINARY" ]; then
    err "Binary not found: $BINARY"
    exit 1
fi

SANCOV_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__sanitizer_cov" || echo "0")
PGO_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__llvm_profile" || echo "0")

echo "Instrumentation symbols:"
echo "  Sancov: $SANCOV_SYM"
echo "  PGO: $PGO_SYM"

if [ "$SANCOV_SYM" -eq 0 ]; then
    err "No sancov symbols found!"
    exit 1
fi

# Quick functionality test
"$BINARY" --version || { err "Binary doesn't run"; exit 1; }

# Phase 9: Run tests and collect coverage
log "Phase 9: Running coverage tests"

TEST_DIR="${BUILD_DIR}/test_incremental"
PROFILE_DIR="${TEST_DIR}/profiles"
mkdir -p "$PROFILE_DIR"

# Create test files
cat > "${TEST_DIR}/test1.smt2" << 'EOF'
(set-logic QF_LIA)
(declare-fun x () Int)
(assert (> x 0))
(check-sat)
EOF

cat > "${TEST_DIR}/test2.smt2" << 'EOF'
(set-logic QF_BV)
(declare-fun a () (_ BitVec 32))
(assert (= (bvadd a a) #x00000042))
(check-sat)
EOF

cat > "${TEST_DIR}/test3.smt2" << 'EOF'
(set-logic QF_SLIA)
(declare-fun s () String)
(assert (str.contains s "abc"))
(check-sat)
EOF

# Setup coverage environment
export __AFL_SHM_ID="0x12345678"
export LLVM_PROFILE_FILE="${PROFILE_DIR}/test-%p.profraw"

# Create shared memory for edge coverage
SHM_PATH="/dev/shm/afl_shm_${__AFL_SHM_ID}"
dd if=/dev/zero of="$SHM_PATH" bs=65536 count=1 2>/dev/null

echo ""
echo "Running tests..."
for test in "${TEST_DIR}"/*.smt2; do
    echo "  Running: $(basename $test)"
    timeout 30s "$BINARY" --check-models "$test" 2>&1 || true
done

# Phase 10: Analyze results
log "Phase 10: Analyzing results"

# Check edge coverage
if [ -f "$SHM_PATH" ]; then
    EDGES=$(python3 -c "
import mmap
with open('$SHM_PATH', 'rb') as f:
    data = f.read(65536)
    edges = sum(1 for i in range(65536) for b in range(8) if data[i] & (1 << b))
    print(edges)
")
    echo "Edges covered: $EDGES"
fi

# Check PGO profiles
PROFRAW_COUNT=$(find "$PROFILE_DIR" -name "*.profraw" -size +0 2>/dev/null | wc -l)
echo "Profraw files: $PROFRAW_COUNT"

if [ "$PROFRAW_COUNT" -gt 0 ]; then
    # Merge profiles
    llvm-profdata merge -sparse -o "${PROFILE_DIR}/merged.profdata" "${PROFILE_DIR}"/*.profraw 2>/dev/null || true
    
    if [ -f "${PROFILE_DIR}/merged.profdata" ]; then
        echo ""
        echo "Function counts (top 10):"
        llvm-cov export "$BINARY" -instr-profile="${PROFILE_DIR}/merged.profdata" \
            -format=text 2>/dev/null | \
            python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    funcs = []
    for f in data.get('data', [{}])[0].get('functions', []):
        name = f.get('name', '')
        count = sum(r.get('count', 0) for r in f.get('regions', []))
        if count > 0 and 'cvc5' in name:
            funcs.append((name, count))
    for name, count in sorted(funcs, key=lambda x: -x[1])[:10]:
        print(f'  {count:8d} {name[:60]}')
except Exception as e:
    print(f'Error: {e}')
"
    fi
fi

# Summary
echo ""
echo "=== SUMMARY ==="
echo "Functions targeted: ${#FUNCTIONS_TO_INSTRUMENT[@]}"
echo "Files recompiled: $RECOMPILED"
echo "Sancov symbols: $SANCOV_SYM"
echo "PGO symbols: $PGO_SYM"
echo "Edges covered: ${EDGES:-0}"
echo "Profraw files: $PROFRAW_COUNT"

if [ "$SANCOV_SYM" -gt 0 ] && [ "$RECOMPILED" -gt 0 ]; then
    ok "INCREMENTAL INSTRUMENTATION TEST PASSED"
    echo ""
    echo "Re-run faster: $0 --skip-production-build"
else
    err "TEST FAILED"
    exit 1
fi
