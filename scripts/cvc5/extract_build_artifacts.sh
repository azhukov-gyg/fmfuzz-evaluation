#!/bin/bash
# Extract CVC5 build artifacts preserving build directory structure
# This script extracts everything directly to build/ preserving paths
# Source .cpp files are extracted to build/src/... for fastcov path resolution
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
echo "   Preserving build directory structure..."

mkdir -p "$BUILD_DIR"

# Extract to temp location first
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

echo "Extracting archive..."
tar -xzf "$ARTIFACT_FILE" -C "$TMP_DIR"

# Extract everything preserving structure
# All files in the archive are already in the correct relative paths
# We just copy them to BUILD_DIR preserving those paths

# Extract binary
if [ -f "$TMP_DIR/bin/cvc5" ]; then
    mkdir -p "$BUILD_DIR/bin"
    cp "$TMP_DIR/bin/cvc5" "$BUILD_DIR/bin/cvc5"
    chmod +x "$BUILD_DIR/bin/cvc5"
    echo "✓ Binary extracted to $BUILD_DIR/bin/cvc5"
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

# Extract CTestTestfile.cmake files (preserving structure)
CTEST_COUNT=0
find "$TMP_DIR" -name "CTestTestfile.cmake" -type f 2>/dev/null | while read -r ctest_file; do
    rel_path="${ctest_file#$TMP_DIR/}"
    target_path="$BUILD_DIR/$rel_path"
    mkdir -p "$(dirname "$target_path")"
    cp "$ctest_file" "$target_path"
done 2>/dev/null || true

CTEST_COUNT=$(find "$BUILD_DIR" -name "CTestTestfile.cmake" -type f 2>/dev/null | wc -l || echo "0")
if [ "$CTEST_COUNT" -gt 0 ]; then
    echo "✓ Extracted $CTEST_COUNT CTestTestfile.cmake files"
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
echo "🔍 Extracting source .cpp files..."
CPP_COUNT=0
if [ -d "$TMP_DIR/src" ]; then
    echo "   Found src/ directory in artifacts"
    TOTAL_IN_ARCHIVE=$(find "$TMP_DIR/src" -type f -name "*.cpp" 2>/dev/null | wc -l || echo "0")
    echo "   Found $TOTAL_IN_ARCHIVE .cpp files in archive"
    
    if [ "$TOTAL_IN_ARCHIVE" -gt 0 ]; then
        echo "   Extracting to $BUILD_DIR/src/..."
        EXTRACTED=0
        find "$TMP_DIR/src" -type f -name "*.cpp" 2>/dev/null | while read -r cpp_file; do
            rel_path="${cpp_file#$TMP_DIR/}"
            target_path="$BUILD_DIR/$rel_path"
            mkdir -p "$(dirname "$target_path")"
            cp "$cpp_file" "$target_path"
            EXTRACTED=$((EXTRACTED + 1))
            if [ $((EXTRACTED % 100)) -eq 0 ]; then
                echo "   ... extracted $EXTRACTED files"
            fi
        done 2>/dev/null || true
        
        CPP_COUNT=$(find "$BUILD_DIR/src" -name "*.cpp" -type f 2>/dev/null | wc -l || echo "0")
        if [ "$CPP_COUNT" -gt 0 ]; then
            echo "✓ Extracted $CPP_COUNT .cpp source files"
            echo "   Sample extracted files:"
            find "$BUILD_DIR/src" -name "*.cpp" -type f 2>/dev/null | head -5 | sed 's/^/      /'
            
            # Verify a specific file that fastcov will look for
            SAMPLE_GCNO=$(find "$BUILD_DIR" -name "*.gcno" -type f | head -1)
            if [ -n "$SAMPLE_GCNO" ]; then
                ABSOLUTE_PATH=$(strings "$SAMPLE_GCNO" | grep -E "^/.*\.cpp$" | head -1)
                if [[ "$ABSOLUTE_PATH" == *"/cvc5/"* ]]; then
                    REL_PATH="${ABSOLUTE_PATH#*cvc5/}"
                    EXPECTED_PATH="$BUILD_DIR/$REL_PATH"
                    echo "   Verifying fastcov path resolution:"
                    echo "     .gcno contains: $ABSOLUTE_PATH"
                    echo "     fastcov will look for: $EXPECTED_PATH"
                    if [ -f "$EXPECTED_PATH" ]; then
                        echo "     ✓ File exists at expected path"
                    else
                        echo "     ✗ ERROR: File does NOT exist at expected path"
                        echo "     Checking if parent directory exists:"
                        ls -la "$(dirname "$EXPECTED_PATH")" 2>/dev/null | head -5 || echo "       Parent directory does not exist"
                    fi
                fi
            fi
        else
            echo "✗ ERROR: No .cpp files found in build directory after extraction"
            echo "   Checking build directory structure:"
            ls -la "$BUILD_DIR/src" 2>/dev/null | head -10 || echo "      Build src/ directory does not exist"
        fi
    else
        echo "   ⚠ Warning: No .cpp files found in archive src/ directory"
        echo "   Archive src/ directory contents:"
        ls -la "$TMP_DIR/src" 2>/dev/null | head -10 || echo "      Archive src/ directory does not exist"
    fi
else
    echo "⚠ Warning: src/ directory not found in artifacts"
    echo "   Archive contents:"
    ls -la "$TMP_DIR" 2>/dev/null | head -20 || echo "      Cannot list archive contents"
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

# Copy source files from checked-out cvc5 to build/src/ for fastcov path resolution
# This ensures files exist at both original paths (cvc5/src/...) and rewritten paths (cvc5/build/src/...)
# .gcno files contain absolute paths like /path/to/cvc5/src/... but fastcov looks for build/src/...
SRC_BASE="$BUILD_DIR/../src"
if [ -d "$SRC_BASE" ]; then
    echo "🔍 Copying source files from checked-out cvc5 to build directory..."
    
    # Count files before copying
    CHECKOUT_COUNT=$(find "$SRC_BASE" -name "*.cpp" -type f 2>/dev/null | wc -l || echo "0")
    BUILD_COUNT_BEFORE=$(find "$BUILD_DIR/src" -name "*.cpp" -type f 2>/dev/null | wc -l || echo "0")
    
    if [ "$CHECKOUT_COUNT" -gt 0 ]; then
        # Create temp file list to avoid subshell issues
        TEMP_FILE_LIST=$(mktemp)
        find "$SRC_BASE" -type f -name "*.cpp" 2>/dev/null > "$TEMP_FILE_LIST" || true
        
        COPIED=0
        while IFS= read -r cpp_file; do
            [ -z "$cpp_file" ] && continue
            rel_path="${cpp_file#$SRC_BASE/}"
            build_target="$BUILD_DIR/src/$rel_path"
            
            # Only copy if file doesn't already exist in build (from artifacts)
            if [ ! -f "$build_target" ]; then
                mkdir -p "$(dirname "$build_target")"
                cp "$cpp_file" "$build_target"
                COPIED=$((COPIED + 1))
                if [ $((COPIED % 100)) -eq 0 ]; then
                    echo "   ... copied $COPIED files from checkout"
                fi
            fi
        done < "$TEMP_FILE_LIST"
        rm -f "$TEMP_FILE_LIST"
        
        BUILD_COUNT_AFTER=$(find "$BUILD_DIR/src" -name "*.cpp" -type f 2>/dev/null | wc -l || echo "0")
        
        if [ "$COPIED" -gt 0 ]; then
            echo "✓ Copied $COPIED .cpp files from checkout to build/src/"
        fi
        echo "   Total .cpp files in build/src/: $BUILD_COUNT_AFTER (was $BUILD_COUNT_BEFORE, checkout has $CHECKOUT_COUNT)"
    else
        echo "⚠ Warning: No .cpp files found in checked-out source at $SRC_BASE"
    fi
else
    echo "⚠ Warning: Checked-out source directory not found at $SRC_BASE"
    echo "   Source files may not be available at original paths for fastcov"
fi

# Verify binary
if [ -f "$BUILD_DIR/bin/cvc5" ]; then
    "$BUILD_DIR/bin/cvc5" --version > /dev/null 2>&1 && echo "✓ Binary verified" || echo "⚠ Binary verification failed"
fi

echo "✅ Extraction complete!"
