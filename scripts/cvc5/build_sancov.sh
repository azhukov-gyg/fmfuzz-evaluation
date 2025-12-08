#!/bin/bash
# Build CVC5 with sancov coverage instrumentation and allowlist
# Usage: ./build_sancov.sh [--allowlist=coverage_allowlist.txt] [--jobs=N]

set -e  # Exit on any error

# Default values
ALLOWLIST_FILE="coverage_allowlist.txt"
JOBS=$(nproc)
CVC5_DIR="cvc5"
BUILD_DIR="build"

# Parse arguments
for arg in "$@"; do
    case $arg in
        --allowlist=*)
            ALLOWLIST_FILE="${arg#*=}"
            shift
            ;;
        --jobs=*)
            JOBS="${arg#*=}"
            shift
            ;;
        --cvc5-dir=*)
            CVC5_DIR="${arg#*=}"
            shift
            ;;
        --build-dir=*)
            BUILD_DIR="${arg#*=}"
            shift
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--allowlist=FILE] [--jobs=N] [--cvc5-dir=DIR] [--build-dir=DIR]"
            exit 1
            ;;
    esac
done

echo "🔧 Building CVC5 with sancov coverage instrumentation"
echo "  Allowlist: $ALLOWLIST_FILE"
echo "  Jobs: $JOBS"
echo "  CVC5 dir: $CVC5_DIR"
echo "  Build dir: $BUILD_DIR"

# Convert allowlist path to absolute path (required for CMake compiler tests)
if [ ! -f "$ALLOWLIST_FILE" ]; then
    echo "⚠️  Warning: Allowlist file not found: $ALLOWLIST_FILE"
    echo "   Building without allowlist (all functions will be instrumented)"
    ALLOWLIST_FLAG=""
else
    # Convert to absolute path
    ALLOWLIST_ABS=$(cd "$(dirname "$ALLOWLIST_FILE")" && pwd)/$(basename "$ALLOWLIST_FILE")
    echo "✅ Using allowlist: $ALLOWLIST_FILE (absolute: $ALLOWLIST_ABS)"
    ALLOWLIST_FLAG="-fsanitize-coverage-allowlist=$ALLOWLIST_ABS"
fi

# Check if CVC5 directory exists
if [ ! -d "$CVC5_DIR" ]; then
    echo "❌ Error: CVC5 directory not found: $CVC5_DIR"
    exit 1
fi

cd "$CVC5_DIR"

# Check if Clang is available (required for sancov)
if ! command -v clang++ &> /dev/null; then
    echo "❌ Error: clang++ not found. Sancov requires Clang compiler."
    echo "   Please install Clang (e.g., sudo apt-get install clang)"
    exit 1
fi

echo "✅ Using Clang: $(clang++ --version | head -1)"

# Set up environment variables for sancov (Clang-specific)
# 
# Using inline-8bit-counters,pc-table with our custom coverage agent.
# This writes coverage to shared memory which the Python fuzzer reads.
# NO reliance on ASAN_OPTIONS=coverage=1 (which doesn't work reliably).
#
# The allowlist restricts instrumentation to specific functions.
export CC=clang
export CXX=clang++
export CXXFLAGS="${CXXFLAGS} -fsanitize-coverage=inline-8bit-counters,pc-table -fsanitize=address -O1 -g -fno-omit-frame-pointer ${ALLOWLIST_FLAG}"
export CFLAGS="${CFLAGS} -fsanitize-coverage=inline-8bit-counters,pc-table -fsanitize=address -O1 -g -fno-omit-frame-pointer ${ALLOWLIST_FLAG}"
export LDFLAGS="${LDFLAGS} -fsanitize-coverage=inline-8bit-counters,pc-table -fsanitize=address"

# Configure CVC5 with debug build (required for coverage)
echo "🔨 Configuring CVC5..."
./configure.sh debug --assertions --auto-download

# Build
echo "🔨 Building CVC5..."
cd "$BUILD_DIR"
make -j"$JOBS"

# Build coverage agent shared library
echo "🔨 Building coverage agent..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SRC="${SCRIPT_DIR}/coverage_agent.cpp"

if [ -f "$AGENT_SRC" ]; then
    clang++ -shared -fPIC -o libcov_agent.so "$AGENT_SRC" \
        -O2 -g -std=c++17 -Wall -Wextra \
        -fsanitize-coverage=inline-8bit-counters,pc-table \
        -lrt
    echo "✅ Coverage agent built: $(pwd)/libcov_agent.so"
else
    echo "⚠️  Coverage agent source not found: $AGENT_SRC"
    echo "   Coverage tracking may not work without the agent!"
fi

echo ""
echo "✅ Build complete!"
echo ""
echo "To run with sancov coverage using shared memory:"
echo "  LD_PRELOAD=./libcov_agent.so COVERAGE_SHM_NAME=cvc5_cov ./bin/cvc5 input.smt2"
echo ""
echo "The Python fuzzer will read coverage from shared memory."

