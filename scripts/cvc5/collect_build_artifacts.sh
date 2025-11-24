#!/bin/bash
# Collect CVC5 build artifacts preserving build directory structure
# This script collects everything needed for coverage analysis:
# - Headers, source .cpp files, binary, CMake files, .gcno files
# - All files preserve their relative paths from build/
# Source .cpp files are collected to src/... so fastcov can find them at build/src/...
#
# Usage: ./collect_build_artifacts.sh <build_dir> <output_dir>
# Example: ./collect_build_artifacts.sh cvc5/build artifacts

set -e

BUILD_DIR="${1:-cvc5/build}"
OUTPUT_DIR="${2:-artifacts}"

if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: Build directory not found: $BUILD_DIR"
    exit 1
fi

echo "📦 Collecting build artifacts from $BUILD_DIR"
echo "   Output directory: $OUTPUT_DIR"
echo "   Preserving build directory structure..."

mkdir -p "$OUTPUT_DIR"

# Collect binary
if [ -f "$BUILD_DIR/bin/cvc5" ]; then
    mkdir -p "$OUTPUT_DIR/bin"
    cp "$BUILD_DIR/bin/cvc5" "$OUTPUT_DIR/bin/cvc5"
    chmod +x "$OUTPUT_DIR/bin/cvc5"
    BINARY_SIZE=$(du -h "$OUTPUT_DIR/bin/cvc5" | cut -f1)
    echo "   ✓ Binary copied ($BINARY_SIZE)"
else
    echo "   ⚠ Warning: Binary not found at $BUILD_DIR/bin/cvc5"
fi

# Collect compile_commands.json
if [ -f "$BUILD_DIR/compile_commands.json" ]; then
    cp "$BUILD_DIR/compile_commands.json" "$OUTPUT_DIR/compile_commands.json"
    echo "   ✓ compile_commands.json copied"
fi

# Collect CMakeCache.txt
if [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
    cp "$BUILD_DIR/CMakeCache.txt" "$OUTPUT_DIR/CMakeCache.txt"
    echo "   ✓ CMakeCache.txt copied"
fi

# Collect all CTestTestfile.cmake files (preserving structure)
CTEST_COUNT=0
find "$BUILD_DIR" -name "CTestTestfile.cmake" -type f 2>/dev/null | while read -r ctest_file; do
    rel_path="${ctest_file#$BUILD_DIR/}"
    target_path="$OUTPUT_DIR/$rel_path"
    mkdir -p "$(dirname "$target_path")"
    cp "$ctest_file" "$target_path"
    CTEST_COUNT=$((CTEST_COUNT + 1))
done 2>/dev/null || true

CTEST_COUNT=$(find "$OUTPUT_DIR" -name "CTestTestfile.cmake" -type f 2>/dev/null | wc -l || echo "0")
if [ "$CTEST_COUNT" -gt 0 ]; then
    echo "   ✓ Collected $CTEST_COUNT CTestTestfile.cmake files"
fi

# Collect all headers (.h, .hpp, .hxx) preserving structure
HEADER_COUNT=0
find "$BUILD_DIR" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) 2>/dev/null | while read -r header; do
    rel_path="${header#$BUILD_DIR/}"
    target_path="$OUTPUT_DIR/$rel_path"
    mkdir -p "$(dirname "$target_path")"
    cp "$header" "$target_path"
done 2>/dev/null || true

HEADER_COUNT=$(find "$OUTPUT_DIR" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) 2>/dev/null | wc -l || echo "0")
if [ "$HEADER_COUNT" -gt 0 ]; then
    echo "   ✓ Collected $HEADER_COUNT header files"
fi

# Collect all .gcno files (coverage notes) preserving structure
GCNO_COUNT=0
find "$BUILD_DIR" -name "*.gcno" -type f 2>/dev/null | while read -r gcno_file; do
    rel_path="${gcno_file#$BUILD_DIR/}"
    target_path="$OUTPUT_DIR/$rel_path"
    mkdir -p "$(dirname "$target_path")"
    cp "$gcno_file" "$target_path"
done 2>/dev/null || true

GCNO_COUNT=$(find "$OUTPUT_DIR" -name "*.gcno" -type f 2>/dev/null | wc -l || echo "0")
if [ "$GCNO_COUNT" -gt 0 ]; then
    echo "   ✓ Collected $GCNO_COUNT .gcno files"
fi

# Collect source .cpp files from source directory (../src relative to build)
# fastcov rewrites paths from .gcno files relative to --search-directory (build/)
# So it looks for source files at build/src/... even though .gcno contains cvc5/src/...
# We need to place source files at src/... in artifacts so they extract to build/src/...
echo "🔍 Collecting source .cpp files..."
CPP_COUNT=0
SRC_DIR="$BUILD_DIR/../src"
echo "   Source directory: $SRC_DIR"
echo "   Build directory: $BUILD_DIR"
echo "   Output directory: $OUTPUT_DIR"

if [ -d "$SRC_DIR" ]; then
    echo "   ✓ Source directory exists"
    TOTAL_SRC_FILES=$(find "$SRC_DIR" -type f -name "*.cpp" 2>/dev/null | wc -l || echo "0")
    echo "   Found $TOTAL_SRC_FILES .cpp files in source directory"
    
    if [ "$TOTAL_SRC_FILES" -gt 0 ]; then
        echo "   Copying source files to $OUTPUT_DIR/src/..."
        COPIED=0
        find "$SRC_DIR" -type f -name "*.cpp" 2>/dev/null | while read -r cpp_file; do
            # Get relative path from src/ directory
            rel_path="${cpp_file#$SRC_DIR/}"
            # Place in output as src/... (matching build structure for fastcov)
            target_path="$OUTPUT_DIR/src/$rel_path"
            mkdir -p "$(dirname "$target_path")"
            cp "$cpp_file" "$target_path"
            COPIED=$((COPIED + 1))
            if [ $((COPIED % 100)) -eq 0 ]; then
                echo "   ... copied $COPIED files"
            fi
        done 2>/dev/null || true
        
        CPP_COUNT=$(find "$OUTPUT_DIR/src" -name "*.cpp" -type f 2>/dev/null | wc -l || echo "0")
        if [ "$CPP_COUNT" -gt 0 ]; then
            echo "   ✓ Collected $CPP_COUNT .cpp source files"
            echo "   Sample files collected:"
            find "$OUTPUT_DIR/src" -name "*.cpp" -type f 2>/dev/null | head -5 | sed 's/^/      /'
        else
            echo "   ✗ ERROR: No .cpp files found in output directory after copying"
            echo "   Checking output directory structure:"
            ls -la "$OUTPUT_DIR/src" 2>/dev/null | head -10 || echo "      Output src/ directory does not exist"
        fi
    else
        echo "   ⚠ Warning: No .cpp files found in source directory"
    fi
else
    echo "   ✗ ERROR: Source directory not found at $SRC_DIR"
    echo "   Build directory contents:"
    ls -la "$BUILD_DIR/.." 2>/dev/null | head -10 || echo "      Cannot list parent directory"
fi

# Summary
echo ""
echo "✅ Artifact collection complete!"
echo "   All files preserve build directory structure"
echo ""
echo "📊 Summary:"
echo "   Headers: $HEADER_COUNT"
echo "   Source files (.cpp): $CPP_COUNT"
echo "   .gcno files: $GCNO_COUNT"
echo "   CTestTestfile.cmake: $CTEST_COUNT"
if [ -f "$OUTPUT_DIR/bin/cvc5" ]; then
    echo "   Binary: ✓"
else
    echo "   Binary: ✗"
fi
if [ -f "$OUTPUT_DIR/compile_commands.json" ]; then
    echo "   compile_commands.json: ✓"
fi
if [ -f "$OUTPUT_DIR/CMakeCache.txt" ]; then
    echo "   CMakeCache.txt: ✓"
fi
