#!/bin/bash
# Extract CVC5 build artifacts from artifacts.tar.gz
# This script extracts:
# - All header files to build/ with preserved paths
# - The CVC5 binary to build/bin/cvc5
# - compile_commands.json to build/
# - .gcno files (coverage notes needed for fastcov)
#
# Usage: ./extract_build_artifacts.sh <artifact_file> <build_dir> [extract_headers]
# Example: ./extract_build_artifacts.sh artifacts/artifacts.tar.gz cvc5/build true
#
# If extract_headers is "true" (default), extracts headers. If "false", only extracts binary.

set -e

ARTIFACT_FILE="${1}"
BUILD_DIR="${2:-cvc5/build}"
EXTRACT_HEADERS="${3:-true}"

if [ -z "$ARTIFACT_FILE" ]; then
    echo "Error: Artifact file not specified"
    exit 1
fi

if [ ! -f "$ARTIFACT_FILE" ]; then
    echo "Error: Artifact file not found: $ARTIFACT_FILE"
    exit 1
fi

echo "📦 Extracting build artifacts from $ARTIFACT_FILE"
echo "   Build directory: $BUILD_DIR"
echo "   Extract headers: $EXTRACT_HEADERS"

mkdir -p "$BUILD_DIR"

# Extract to temp location
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

echo "Extracting archive..."
tar -xzf "$ARTIFACT_FILE" -C "$TMP_DIR"

# Extract binary
if [ -f "$TMP_DIR/bin/cvc5" ]; then
    mkdir -p "$BUILD_DIR/bin"
    cp "$TMP_DIR/bin/cvc5" "$BUILD_DIR/bin/cvc5"
    chmod +x "$BUILD_DIR/bin/cvc5"
    echo "✓ Binary extracted to $BUILD_DIR/bin/cvc5"
else
    echo "⚠ Warning: Binary not found in artifacts"
fi

# Extract compile_commands.json
if [ -f "$TMP_DIR/compile_commands.json" ]; then
    cp "$TMP_DIR/compile_commands.json" "$BUILD_DIR/compile_commands.json"
    echo "✓ compile_commands.json extracted"
else
    echo "⚠ Warning: compile_commands.json not found in artifacts"
fi

# Extract headers if requested
if [ "$EXTRACT_HEADERS" = "true" ]; then
    if [ -d "$TMP_DIR/headers" ]; then
        # Move all header directories to build root (preserve structure)
        if [ -d "$TMP_DIR/headers/include" ]; then
            mv "$TMP_DIR/headers/include" "$BUILD_DIR/include"
            echo "✓ Headers extracted: include/"
        fi
        if [ -d "$TMP_DIR/headers/src" ]; then
            mv "$TMP_DIR/headers/src" "$BUILD_DIR/src"
            echo "✓ Headers extracted: src/"
        fi
        if [ -d "$TMP_DIR/headers/deps" ]; then
            mv "$TMP_DIR/headers/deps" "$BUILD_DIR/deps"
            echo "✓ Headers extracted: deps/"
        fi
        
        # Count headers
        HEADER_COUNT=$(find "$BUILD_DIR" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) 2>/dev/null | wc -l || echo "0")
        echo "  Total headers: $HEADER_COUNT"
    else
        echo "⚠ Warning: headers/ directory not found in artifacts"
    fi
fi

# Extract .gcno files (coverage notes needed for fastcov)
echo "🔍 Extracting .gcno files (coverage notes)..."
GCNO_COUNT=0
find "$TMP_DIR" -name "*.gcno" -type f 2>/dev/null | while read -r gcno_file; do
    rel_path="${gcno_file#$TMP_DIR/}"
    target_path="$BUILD_DIR/$rel_path"
    mkdir -p "$(dirname "$target_path")"
    cp "$gcno_file" "$target_path"
done 2>/dev/null || true

GCNO_COUNT=$(find "$BUILD_DIR" -name "*.gcno" -type f 2>/dev/null | wc -l || echo "0")
if [ "$GCNO_COUNT" -gt 0 ]; then
    echo "✓ Extracted $GCNO_COUNT .gcno files"
else
    echo "⚠ Warning: No .gcno files found in artifacts"
fi

# Verify binary
if [ -f "$BUILD_DIR/bin/cvc5" ]; then
    "$BUILD_DIR/bin/cvc5" --version > /dev/null 2>&1 && echo "✓ Binary verified" || echo "⚠ Binary verification failed"
fi

echo "✅ Extraction complete!"

