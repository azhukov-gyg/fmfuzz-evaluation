#!/bin/bash
# Extract Z3 build artifacts preserving build directory structure
# This script extracts everything directly to build/ preserving paths
# Source .cpp files are extracted to build/src/... for fastcov path resolution
#
# Usage: ./extract_build_artifacts.sh <artifact_file> <build_dir> [extract_headers]
# Example: ./extract_build_artifacts.sh artifacts/artifacts.tar.gz z3/build true
#
# If extract_headers is "true" (default), extracts headers. If "false", only extracts binary.

set -e

ARTIFACT_FILE="${1}"
BUILD_DIR="${2:-z3/build}"
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

mkdir -p "$BUILD_DIR"

# Extract to temp location first
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

echo "Extracting archive..."
tar -xzf "$ARTIFACT_FILE" -C "$TMP_DIR"

# Extract everything preserving structure
# All files in the archive are already in the correct relative paths
# We just copy them to BUILD_DIR preserving those paths

# Extract binary (Z3 binary is in bin/ in artifacts, but goes to build root)
if [ -f "$TMP_DIR/bin/z3" ]; then
    cp "$TMP_DIR/bin/z3" "$BUILD_DIR/z3"
    chmod +x "$BUILD_DIR/z3"
    echo "✓ Binary extracted to $BUILD_DIR/z3"
fi

# Extract compile_commands.json
if [ -f "$TMP_DIR/compile_commands.json" ]; then
    cp "$TMP_DIR/compile_commands.json" "$BUILD_DIR/compile_commands.json"
    echo "✓ compile_commands.json extracted"
fi

# Extract CMakeCache.txt
if [ -f "$TMP_DIR/CMakeCache.txt" ]; then
    cp "$TMP_DIR/CMakeCache.txt" "$BUILD_DIR/CMakeCache.txt"
    echo "✓ CMakeCache.txt extracted"
fi

# Extract .gcno files (preserving structure)
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
fi

# Extract source .cpp files (preserving structure)
# fastcov rewrites paths relative to --search-directory, so it looks for build/src/...
CPP_COUNT=0
if [ -d "$TMP_DIR/src" ]; then
    echo "   Extracting .cpp files from archive..."
    find "$TMP_DIR/src" -type f -name "*.cpp" 2>/dev/null | while read -r cpp_file; do
        rel_path="${cpp_file#$TMP_DIR/}"
        target_path="$BUILD_DIR/$rel_path"
        mkdir -p "$(dirname "$target_path")"
        cp "$cpp_file" "$target_path"
        echo "   [ARCHIVE] ${rel_path#src/}"
    done 2>/dev/null || true
    
    CPP_COUNT=$(find "$BUILD_DIR/src" -name "*.cpp" -type f 2>/dev/null | wc -l || echo "0")
    if [ "$CPP_COUNT" -gt 0 ]; then
        echo "✓ Extracted $CPP_COUNT .cpp source files from archive"
    fi
fi

# Extract headers if requested
if [ "$EXTRACT_HEADERS" = "true" ]; then
    HEADER_COUNT=0
    find "$TMP_DIR" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) 2>/dev/null | while read -r header; do
        rel_path="${header#$TMP_DIR/}"
        target_path="$BUILD_DIR/$rel_path"
        mkdir -p "$(dirname "$target_path")"
        cp "$header" "$target_path"
    done 2>/dev/null || true
    
    HEADER_COUNT=$(find "$BUILD_DIR" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) 2>/dev/null | wc -l || echo "0")
    if [ "$HEADER_COUNT" -gt 0 ]; then
        echo "✓ Extracted $HEADER_COUNT header files"
    fi
fi

# Copy source files from checked-out z3 to build/src/ ONLY if they don't exist from archive
# The archive source files match the binary and .gcno files, so they should be preserved
# Only copy missing files from checkout (for generated files that might not be in archive)
SRC_BASE="$BUILD_DIR/../src"
if [ -d "$SRC_BASE" ]; then
    echo "   Copying missing .cpp files from checked-out source (preserving archive files)..."
    MISSING_COUNT=0
    if command -v rsync >/dev/null 2>&1; then
        # Use rsync with --ignore-existing to only copy files that don't exist
        rsync -a --include='*/' --include='*.cpp' --exclude='*' --ignore-existing "$SRC_BASE/" "$BUILD_DIR/src/" 2>/dev/null || true
        # Count missing files (files that would be copied)
        # Use Python to clean and validate the count (handles newlines/whitespace robustly)
        MISSING_COUNT=$(rsync -a --include='*/' --include='*.cpp' --exclude='*' --ignore-existing --dry-run "$SRC_BASE/" "$BUILD_DIR/src/" 2>/dev/null | grep -c "\.cpp$" 2>/dev/null || echo "0")
        MISSING_COUNT=$(echo "$MISSING_COUNT" | python3 -c "import sys; s = sys.stdin.read().strip(); print(int(s) if s.isdigit() else 0)")
    else
        find "$SRC_BASE" -type f -name "*.cpp" 2>/dev/null | while read -r cpp_file; do
            [ -z "$cpp_file" ] && continue
            rel_path="${cpp_file#$SRC_BASE/}"
            build_target="$BUILD_DIR/src/$rel_path"
            # Only copy if file doesn't exist (preserve archive files)
            if [ ! -f "$build_target" ]; then
                mkdir -p "$(dirname "$build_target")"
                cp "$cpp_file" "$build_target"
                echo "   [CHECKOUT] $rel_path (missing from archive)"
                MISSING_COUNT=$((MISSING_COUNT + 1))
            fi
        done 2>/dev/null || true
    fi
    if [ "$MISSING_COUNT" -gt 0 ]; then
        echo "   ✓ Copied $MISSING_COUNT missing .cpp files from checkout"
    else
        echo "   ✓ All .cpp files already present from archive (preserved)"
    fi
    # Update count after copying from checkout
    CPP_COUNT=$(find "$BUILD_DIR/src" -name "*.cpp" -type f 2>/dev/null | wc -l || echo "0")
    echo ""
    echo "📋 Full list of .cpp files in build/src/:"
    find "$BUILD_DIR/src" -name "*.cpp" -type f 2>/dev/null | sort | sed 's|^'"$BUILD_DIR/src/"'||' | sed 's/^/      /'
fi

# Verify binary
if [ -f "$BUILD_DIR/z3" ]; then
    "$BUILD_DIR/z3" --version > /dev/null 2>&1 && echo "✓ Binary verified" || echo "⚠ Binary verification failed"
fi

echo ""
echo "✅ Extraction complete!"
echo ""
echo "📊 Extraction summary:"
echo "   Binary: $([ -f "$BUILD_DIR/z3" ] && echo "✓" || echo "✗")"
echo "   Headers: $HEADER_COUNT"
echo "   Source files (.cpp): $CPP_COUNT"
echo "   .gcno files: $GCNO_COUNT"
echo "   compile_commands.json: $([ -f "$BUILD_DIR/compile_commands.json" ] && echo "✓" || echo "✗")"
echo "   CMakeCache.txt: $([ -f "$BUILD_DIR/CMakeCache.txt" ] && echo "✓" || echo "✗")"

