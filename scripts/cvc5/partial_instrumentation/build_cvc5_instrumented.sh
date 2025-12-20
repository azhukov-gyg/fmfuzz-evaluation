#!/bin/bash
# Build CVC5 with sancov + PGO instrumentation for production fuzzing
# 
# Usage:
#   ./build_cvc5_instrumented.sh [commit_hash] [sancov_allowlist] [pgo_allowlist]
#
# Environment variables:
#   WORKSPACE - workspace directory (default: /workspace)
#   COVERAGE_AGENT - path to coverage_agent.cpp (auto-detected if not set)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-/workspace}"
CVC5_DIR="${WORKSPACE}/cvc5"
BUILD_DIR="${CVC5_DIR}/build"

# Arguments
COMMIT_HASH="${1:-}"
SANCOV_ALLOWLIST="${2:-}"
PGO_ALLOWLIST="${3:-}"

log() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
ok() { echo -e "\033[0;32m[OK]\033[0m $1"; }
err() { echo -e "\033[0;31m[ERROR]\033[0m $1"; exit 1; }

echo "=============================================="
echo "Building CVC5 with Sancov + PGO Instrumentation"
echo "=============================================="

# Phase 1: Clone/checkout CVC5
log "Phase 1: Setting up CVC5 source"
if [ ! -d "$CVC5_DIR" ]; then
    git clone https://github.com/cvc5/cvc5.git "$CVC5_DIR"
fi
cd "$CVC5_DIR"

# Only do git operations if .git exists (workflow may have already checked out and removed .git)
if [ -d ".git" ]; then
    if [ -n "$COMMIT_HASH" ]; then
        git fetch origin
        git checkout "$COMMIT_HASH"
    fi
    echo "  Commit: $(git rev-parse --short HEAD)"
else
    echo "  Source already prepared (no .git directory)"
    if [ -n "$COMMIT_HASH" ]; then
        echo "  Expected commit: $COMMIT_HASH"
    fi
fi

# Phase 2: Setup Python venv (needed for CVC5 build)
log "Phase 2: Setting up Python environment"
if [ ! -d ~/.venv ]; then
    python3 -m venv ~/.venv
fi
source ~/.venv/bin/activate
pip install --quiet --upgrade pip

# Phase 3: Build coverage agent
log "Phase 3: Building coverage agent"
mkdir -p "$BUILD_DIR"

# Find coverage agent source
AGENT_SRC="${COVERAGE_AGENT:-}"
if [ -z "$AGENT_SRC" ] || [ ! -f "$AGENT_SRC" ]; then
    for path in "${SCRIPT_DIR}/coverage_agent.cpp" "/coverage_agent.cpp"; do
        if [ -f "$path" ]; then
            AGENT_SRC="$path"
            break
        fi
    done
fi

if [ -z "$AGENT_SRC" ] || [ ! -f "$AGENT_SRC" ]; then
    err "Coverage agent source not found! Set COVERAGE_AGENT env var."
fi

AGENT_OBJ="${BUILD_DIR}/coverage_agent.o"
echo "  Source: $AGENT_SRC"

# Compile agent WITHOUT sanitizer coverage (to avoid instrumenting the agent itself)
if clang++ -c -o "$AGENT_OBJ" "$AGENT_SRC" \
    -O2 -g -std=c++17 -fPIC -fno-sanitize-coverage=trace-pc-guard; then
    ok "Coverage agent built: $AGENT_OBJ"
else
    err "Failed to build coverage agent"
fi

# Phase 4: Configure instrumentation flags
log "Phase 4: Configuring instrumentation flags"
export CC=clang
export CXX=clang++

SANCOV_FLAGS="-fsanitize-coverage=trace-pc-guard"
PGO_FLAGS="-fprofile-instr-generate -fcoverage-mapping"

# Add allowlists if provided
if [ -n "$SANCOV_ALLOWLIST" ] && [ -f "$SANCOV_ALLOWLIST" ]; then
    SANCOV_FLAGS="$SANCOV_FLAGS -fsanitize-coverage-allowlist=$SANCOV_ALLOWLIST"
    SANCOV_COUNT=$(grep -c '^fun:' "$SANCOV_ALLOWLIST" 2>/dev/null || echo 0)
    echo "  Sancov allowlist: $SANCOV_ALLOWLIST ($SANCOV_COUNT functions)"
    echo "  --- Sancov allowlist contents ---"
    cat "$SANCOV_ALLOWLIST"
    echo "  ---------------------------------"
fi

if [ -n "$PGO_ALLOWLIST" ] && [ -f "$PGO_ALLOWLIST" ]; then
    PGO_FLAGS="$PGO_FLAGS -fprofile-list=$PGO_ALLOWLIST"
    PGO_COUNT=$(grep -c '^fun:' "$PGO_ALLOWLIST" 2>/dev/null || echo 0)
    echo "  PGO allowlist: $PGO_ALLOWLIST ($PGO_COUNT functions)"
    echo "  --- PGO allowlist contents ---"
    cat "$PGO_ALLOWLIST"
    echo "  ------------------------------"
fi

# Let CVC5's production profile handle optimization flags
# We only add our instrumentation flags
export CFLAGS="$SANCOV_FLAGS $PGO_FLAGS"
export CXXFLAGS="$SANCOV_FLAGS $PGO_FLAGS"
export LDFLAGS="-fprofile-instr-generate"

echo "  CFLAGS: $CFLAGS"
echo "  CXXFLAGS: $CXXFLAGS"
echo "  LDFLAGS: $LDFLAGS"

# Phase 5: Configure CVC5
log "Phase 5: Configuring CVC5 (production mode, static library)"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Rebuild coverage agent after rm
clang++ -c -o "$AGENT_OBJ" "$AGENT_SRC" -O2 -g -std=c++17 -fPIC -fno-sanitize-coverage=trace-pc-guard

# Configure with production profile and static library
# --static builds CVC5 as static library (BUILD_SHARED_LIBS=OFF)
./configure.sh production --static --auto-download --name="$BUILD_DIR"
cd "$BUILD_DIR"

# Phase 5b: Inject coverage agent via CMake
# STATIC_BINARY=OFF avoids -static linker flag which breaks PGO runtime linking
log "Phase 5b: Injecting coverage agent"
cmake \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS} ${AGENT_OBJ}" \
    -DSTATIC_BINARY=OFF \
    . || err "CMake configuration failed"

# Phase 6: Build
log "Phase 6: Building CVC5"
BUILD_START=$(date +%s)
make -j$(nproc)
BUILD_TIME=$(($(date +%s) - BUILD_START))
ok "Build completed in ${BUILD_TIME}s"

# Phase 7: Verify instrumentation
log "Phase 7: Verifying instrumentation"
BINARY="${BUILD_DIR}/bin/cvc5"

if [ ! -f "$BINARY" ]; then
    err "Binary not found: $BINARY"
fi

SANCOV_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__sanitizer_cov" || echo "0")
PGO_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__llvm_profile" || echo "0")
echo "  Sancov symbols: $SANCOV_SYM"
echo "  PGO symbols: $PGO_SYM"

# Test binary
if "$BINARY" --version > /dev/null 2>&1; then
    ok "Binary works"
else
    err "Binary crashed on --version!"
fi

# Summary
echo ""
echo "=============================================="
echo "BUILD SUMMARY"
echo "=============================================="
echo "Binary: $BINARY"
echo "Build time: ${BUILD_TIME}s"
echo "Sancov symbols: $SANCOV_SYM"
echo "PGO symbols: $PGO_SYM"
echo "File size: $(du -h "$BINARY" | cut -f1)"

if [ "$SANCOV_SYM" -gt 0 ] && [ "$PGO_SYM" -gt 0 ]; then
    ok "BUILD SUCCESSFUL - Instrumentation verified"
    exit 0
else
    err "BUILD FAILED - Missing instrumentation symbols"
fi
