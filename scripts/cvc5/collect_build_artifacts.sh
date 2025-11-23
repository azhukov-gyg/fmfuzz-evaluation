#!/bin/bash
# Collect CVC5 build artifacts for libclang parsing and coverage analysis
# This script collects:
# - All header files (.h, .hpp, .hxx) from build directory with preserved paths
# - The CVC5 binary
# - compile_commands.json
# - .gcno files (coverage notes needed for fastcov)
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

# Create output directory structure
mkdir -p "$OUTPUT_DIR/headers"
mkdir -p "$OUTPUT_DIR/bin"

# Collect all header files with preserved directory structure
echo "🔍 Collecting header files..."

# Collect headers from include/
if [ -d "$BUILD_DIR/include" ]; then
    find "$BUILD_DIR/include" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) | while read -r header; do
        rel_path="${header#$BUILD_DIR/}"
        target_path="$OUTPUT_DIR/headers/$rel_path"
        mkdir -p "$(dirname "$target_path")"
        cp "$header" "$target_path"
    done
    INCLUDE_COUNT=$(find "$BUILD_DIR/include" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) 2>/dev/null | wc -l)
    echo "   ✓ Collected $INCLUDE_COUNT headers from include/"
fi

# Collect headers from src/
if [ -d "$BUILD_DIR/src" ]; then
    find "$BUILD_DIR/src" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) | while read -r header; do
        rel_path="${header#$BUILD_DIR/}"
        target_path="$OUTPUT_DIR/headers/$rel_path"
        mkdir -p "$(dirname "$target_path")"
        cp "$header" "$target_path"
    done
    SRC_COUNT=$(find "$BUILD_DIR/src" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) 2>/dev/null | wc -l)
    echo "   ✓ Collected $SRC_COUNT headers from src/"
fi

# Collect headers from deps/include/
if [ -d "$BUILD_DIR/deps/include" ]; then
    find "$BUILD_DIR/deps/include" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) | while read -r header; do
        rel_path="${header#$BUILD_DIR/}"
        target_path="$OUTPUT_DIR/headers/$rel_path"
        mkdir -p "$(dirname "$target_path")"
        cp "$header" "$target_path"
    done
    DEPS_INCLUDE_COUNT=$(find "$BUILD_DIR/deps/include" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) 2>/dev/null | wc -l)
    echo "   ✓ Collected $DEPS_INCLUDE_COUNT headers from deps/include/"
fi

# Collect headers from deps/src/
if [ -d "$BUILD_DIR/deps/src" ]; then
    find "$BUILD_DIR/deps/src" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) | while read -r header; do
        rel_path="${header#$BUILD_DIR/}"
        target_path="$OUTPUT_DIR/headers/$rel_path"
        mkdir -p "$(dirname "$target_path")"
        cp "$header" "$target_path"
    done
    DEPS_SRC_COUNT=$(find "$BUILD_DIR/deps/src" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) 2>/dev/null | wc -l)
    echo "   ✓ Collected $DEPS_SRC_COUNT headers from deps/src/"
fi

# Count total headers
TOTAL_HEADERS=$(find "$OUTPUT_DIR/headers" -type f 2>/dev/null | wc -l || echo "0")
echo "   Total headers collected: $TOTAL_HEADERS"

# Copy binary
if [ -f "$BUILD_DIR/bin/cvc5" ]; then
    cp "$BUILD_DIR/bin/cvc5" "$OUTPUT_DIR/bin/cvc5"
    chmod +x "$OUTPUT_DIR/bin/cvc5"
    BINARY_SIZE=$(du -h "$OUTPUT_DIR/bin/cvc5" | cut -f1)
    echo "   ✓ Binary copied ($BINARY_SIZE)"
else
    echo "   ⚠ Warning: Binary not found at $BUILD_DIR/bin/cvc5"
fi

# Copy compile_commands.json
if [ -f "$BUILD_DIR/compile_commands.json" ]; then
    cp "$BUILD_DIR/compile_commands.json" "$OUTPUT_DIR/compile_commands.json"
    echo "   ✓ compile_commands.json copied"
else
    echo "   ⚠ Warning: compile_commands.json not found at $BUILD_DIR/compile_commands.json"
fi

# Collect .gcno files (coverage notes needed for fastcov)
echo "🔍 Collecting .gcno files (coverage notes)..."
GCNO_COUNT=0
if find "$BUILD_DIR" -name "*.gcno" -type f 2>/dev/null | head -1 | grep -q .; then
    # Copy all .gcno files preserving directory structure
    find "$BUILD_DIR" -name "*.gcno" -type f | while read -r gcno_file; do
        rel_path="${gcno_file#$BUILD_DIR/}"
        target_path="$OUTPUT_DIR/$rel_path"
        mkdir -p "$(dirname "$target_path")"
        cp "$gcno_file" "$target_path"
    done
    GCNO_COUNT=$(find "$OUTPUT_DIR" -name "*.gcno" -type f 2>/dev/null | wc -l || echo "0")
    echo "   ✓ Collected $GCNO_COUNT .gcno files"
else
    echo "   ⚠ Warning: No .gcno files found (coverage build may not have .gcno files)"
fi

# Create summary
echo ""
echo "✅ Artifact collection complete!"
echo "   Headers: $OUTPUT_DIR/headers/"
echo "   Binary: $OUTPUT_DIR/bin/cvc5"
echo "   Compile commands: $OUTPUT_DIR/compile_commands.json"
if [ "$GCNO_COUNT" -gt 0 ]; then
    echo "   Coverage notes (.gcno): $GCNO_COUNT files"
fi
echo ""
echo "📊 Summary:"
echo "   Total header files: $TOTAL_HEADERS"
if [ -f "$OUTPUT_DIR/bin/cvc5" ]; then
    echo "   Binary: ✓"
else
    echo "   Binary: ✗"
fi
if [ -f "$OUTPUT_DIR/compile_commands.json" ]; then
    echo "   compile_commands.json: ✓"
else
    echo "   compile_commands.json: ✗"
fi
if [ "$GCNO_COUNT" -gt 0 ]; then
    echo "   .gcno files: ✓ ($GCNO_COUNT files)"
else
    echo "   .gcno files: ✗"
fi

