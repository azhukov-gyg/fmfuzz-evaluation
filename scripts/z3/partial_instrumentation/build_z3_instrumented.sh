#!/bin/bash
# Build Z3 with sancov instrumentation for coverage-guided fuzzing
# 
# Usage:
#   ./build_z3_instrumented.sh [commit_hash] [sancov_allowlist]
#
# Environment variables:
#   WORKSPACE - workspace directory (default: /workspace)
#   COVERAGE_AGENT - path to coverage_agent.cpp (auto-detected if not set)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-/workspace}"
Z3_DIR="${WORKSPACE}/z3"
BUILD_DIR="${Z3_DIR}/build"

# Arguments
COMMIT_HASH="${1:-}"
SANCOV_ALLOWLIST="${2:-}"

log() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
ok() { echo -e "\033[0;32m[OK]\033[0m $1"; }
err() { echo -e "\033[0;31m[ERROR]\033[0m $1"; exit 1; }

echo "=============================================="
echo "Building Z3 with Sancov Instrumentation"
echo "=============================================="

# Phase 1: Clone/checkout Z3
log "Phase 1: Setting up Z3 source"
if [ ! -d "$Z3_DIR" ]; then
    git clone https://github.com/Z3Prover/z3.git "$Z3_DIR"
fi
cd "$Z3_DIR"

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

# Phase 2: Setup Python venv (needed for Z3 build)
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

# Add sancov allowlist if provided
if [ -n "$SANCOV_ALLOWLIST" ] && [ -f "$SANCOV_ALLOWLIST" ]; then
    SANCOV_FLAGS="$SANCOV_FLAGS -fsanitize-coverage-allowlist=$SANCOV_ALLOWLIST"
    SANCOV_COUNT=$(grep -c '^fun:' "$SANCOV_ALLOWLIST" 2>/dev/null || echo 0)
    echo "  Sancov allowlist: $SANCOV_ALLOWLIST ($SANCOV_COUNT functions)"
    echo "  --- Sancov allowlist contents ---"
    cat "$SANCOV_ALLOWLIST"
    echo "  ---------------------------------"
fi

# Let Z3's production profile handle optimization flags
# We only add our instrumentation flags + -fno-inline to prevent inlining
# (inlined functions bypass coverage guards, causing 0 edges hit)
export CFLAGS="$SANCOV_FLAGS -fno-inline"
export CXXFLAGS="$SANCOV_FLAGS -fno-inline"
export LDFLAGS=""

echo "  CFLAGS: $CFLAGS"
echo "  CXXFLAGS: $CXXFLAGS"
echo "  LDFLAGS: $LDFLAGS"

# Phase 5: Configure Z3
log "Phase 5: Configuring Z3 (debug mode with assertions, static library)"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Rebuild coverage agent after rm
clang++ -c -o "$AGENT_OBJ" "$AGENT_SRC" -O2 -g -std=c++17 -fPIC -fno-sanitize-coverage=trace-pc-guard

cd "$BUILD_DIR"

# Phase 5b: Configure Z3 with CMake
# Z3 uses CMake directly (no configure.sh like CVC5)
# Build in Debug mode with assertions to match simple fuzzer build
# This ensures we're comparing apples to apples:
# - Simple fuzzer uses: Debug build with assertions
# - Coverage-guided now uses: Debug build with assertions (+ sancov)
log "Phase 5b: Configuring Z3 with CMake"
cmake \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS} ${AGENT_OBJ}" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DZ3_BUILD_LIBZ3_SHARED=OFF \
    -DZ3_BUILD_EXECUTABLE=ON \
    -DZ3_BUILD_TEST_EXECUTABLES=OFF \
    -G "Unix Makefiles" \
    .. || err "CMake configuration failed"

# Phase 6: Build
log "Phase 6: Building Z3"
BUILD_START=$(date +%s)
make -j$(nproc)
BUILD_TIME=$(($(date +%s) - BUILD_START))
ok "Build completed in ${BUILD_TIME}s"

# Phase 7: Verify instrumentation
log "Phase 7: Verifying instrumentation"
BINARY="${BUILD_DIR}/z3"

if [ ! -f "$BINARY" ]; then
    err "Binary not found: $BINARY"
fi

SANCOV_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__sanitizer_cov" || echo "0")
echo "  Sancov symbols: $SANCOV_SYM"

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
echo "File size: $(du -h "$BINARY" | cut -f1)"

# Verify instrumentation
if [ "$SANCOV_SYM" -gt 0 ]; then
    ok "BUILD SUCCESSFUL - Instrumentation verified"
    exit 0
else
    err "BUILD FAILED - No sancov symbols found"
fi
