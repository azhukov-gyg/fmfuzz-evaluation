#!/bin/bash
# Build CVC5 with full sancov + PGO instrumentation from scratch
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-/workspace}"
CVC5_DIR="${WORKSPACE}/cvc5"
BUILD_DIR="${CVC5_DIR}/build"

# Options
COMMIT_HASH="${1:-}"
SANCOV_ALLOWLIST="${2:-}"
PGO_ALLOWLIST="${3:-}"

log() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
ok() { echo -e "\033[0;32m[OK]\033[0m $1"; }
err() { echo -e "\033[0;31m[ERROR]\033[0m $1"; exit 1; }

echo "=== Building CVC5 with Sancov + PGO Instrumentation ==="

# Phase 1: Clone CVC5
log "Phase 1: Cloning CVC5"
if [ ! -d "$CVC5_DIR" ]; then
    git clone --depth 100 https://github.com/cvc5/cvc5.git "$CVC5_DIR"
fi
cd "$CVC5_DIR"

if [ -n "$COMMIT_HASH" ]; then
    git fetch --depth 100 origin "$COMMIT_HASH"
    git checkout "$COMMIT_HASH"
fi
echo "Commit: $(git rev-parse --short HEAD)"

# Phase 2: Setup Python venv
log "Phase 2: Setting up Python environment"
if [ ! -d ~/.venv ]; then
    python3 -m venv ~/.venv
fi
source ~/.venv/bin/activate
pip install --quiet --upgrade pip

# Phase 3: Build coverage agent (provides __sanitizer_cov_trace_pc_guard callbacks)
log "Phase 3: Building coverage agent"
mkdir -p "$BUILD_DIR"

# Find coverage agent source
AGENT_SRC=""
for path in "/coverage_agent.cpp" "/scripts/../coverage_agent.cpp" "${SCRIPT_DIR}/../coverage_agent.cpp"; do
    if [ -f "$path" ]; then
        AGENT_SRC="$path"
        break
    fi
done

if [ -z "$AGENT_SRC" ]; then
    err "Coverage agent source not found!"
fi

AGENT_OBJ="${BUILD_DIR}/coverage_agent.o"
echo "  Source: $AGENT_SRC"

if clang++ -c -o "$AGENT_OBJ" "$AGENT_SRC" \
    -O2 -g -std=c++17 -fPIC -fno-sanitize-coverage=trace-pc-guard; then
    ok "Coverage agent built: $AGENT_OBJ"
else
    err "Failed to build coverage agent"
fi

# Phase 4: Configure build flags
log "Phase 4: Configuring instrumentation flags"
export CC=clang
export CXX=clang++

SANCOV_FLAGS="-fsanitize-coverage=trace-pc-guard"
PGO_FLAGS="-fprofile-instr-generate -fcoverage-mapping"

# Add allowlists if provided
if [ -n "$SANCOV_ALLOWLIST" ] && [ -f "$SANCOV_ALLOWLIST" ]; then
    SANCOV_FLAGS="$SANCOV_FLAGS -fsanitize-coverage-allowlist=$SANCOV_ALLOWLIST"
    echo "  Using sancov allowlist: $SANCOV_ALLOWLIST"
fi

if [ -n "$PGO_ALLOWLIST" ] && [ -f "$PGO_ALLOWLIST" ]; then
    PGO_FLAGS="$PGO_FLAGS -fprofile-list=$PGO_ALLOWLIST"
    echo "  Using PGO allowlist: $PGO_ALLOWLIST"
fi

export CFLAGS="$SANCOV_FLAGS $PGO_FLAGS -O1 -g -fno-omit-frame-pointer"
export CXXFLAGS="$SANCOV_FLAGS $PGO_FLAGS -O1 -g -fno-omit-frame-pointer"
# Link flags include coverage agent and PGO
export LDFLAGS="-fprofile-instr-generate"

echo "  CFLAGS: $CFLAGS"
echo "  CXXFLAGS: $CXXFLAGS"

# Phase 5: Configure CVC5
log "Phase 5: Configuring CVC5"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
# Rebuild coverage agent after rm
clang++ -c -o "$AGENT_OBJ" "$AGENT_SRC" -O2 -g -std=c++17 -fPIC -fno-sanitize-coverage=trace-pc-guard

./configure.sh debug --static --auto-download --name="$BUILD_DIR"
cd "$BUILD_DIR"

# Inject coverage agent into linker flags via CMake
log "Phase 5b: Injecting coverage agent into build"
cmake \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS} ${AGENT_OBJ}" \
    -DSTATIC_BINARY=OFF \
    . || err "CMake configuration failed"

log "Phase 6: Building CVC5"
BUILD_START=$(date +%s)
make -j$(nproc)
BUILD_TIME=$(($(date +%s) - BUILD_START))
ok "Build completed in ${BUILD_TIME}s"

# Phase 7: Verify instrumentation
log "Phase 7: Verifying instrumentation"
BINARY="${BUILD_DIR}/bin/cvc5"

SANCOV_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__sanitizer_cov" || echo "0")
PGO_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__llvm_profile" || echo "0")
echo "  Sancov symbols: $SANCOV_SYM"
echo "  PGO symbols: $PGO_SYM"

# Test binary works
if "$BINARY" --version > /dev/null 2>&1; then
    ok "Binary works"
else
    err "Binary crashed!"
fi

echo ""
echo "=== Build Summary ==="
echo "Binary: $BINARY"
echo "Build time: ${BUILD_TIME}s"
echo "Sancov symbols: $SANCOV_SYM"
echo "PGO symbols: $PGO_SYM"

if [ "$SANCOV_SYM" -gt 0 ] && [ "$PGO_SYM" -gt 0 ]; then
    ok "BUILD SUCCESSFUL - Instrumentation verified"
else
    err "BUILD FAILED - Missing instrumentation"
fi
