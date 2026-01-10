#!/bin/bash
# Incremental build: add sancov instrumentation to pre-built CVC5
#
# Usage:
#   ./build_cvc5_sancov_incremental.sh <changed_functions_json> <sancov_allowlist>
#
# Prerequisites:
#   - CVC5 already built (debug + assertions)
#   - compile_commands.json exists in build directory
#   - changed_functions.json with function_info_map
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVC5_DIR="${CVC5_DIR:-$(pwd)/cvc5}"
BUILD_DIR="${BUILD_DIR:-${CVC5_DIR}/build}"

# Arguments
CHANGED_FUNCTIONS_JSON="${1:-}"
SANCOV_ALLOWLIST="${2:-}"

log() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
ok() { echo -e "\033[0;32m[OK]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
err() { echo -e "\033[0;31m[ERROR]\033[0m $1"; exit 1; }

echo "=============================================="
echo "Incremental Sancov Build"
echo "=============================================="
echo "CVC5_DIR: $CVC5_DIR"
echo "BUILD_DIR: $BUILD_DIR"

# Validate inputs
if [ ! -f "$CHANGED_FUNCTIONS_JSON" ]; then
    err "Changed functions JSON not found: $CHANGED_FUNCTIONS_JSON"
fi

if [ ! -f "$SANCOV_ALLOWLIST" ]; then
    err "Sancov allowlist not found: $SANCOV_ALLOWLIST"
fi

if [ ! -d "$BUILD_DIR" ]; then
    err "Build directory not found: $BUILD_DIR"
fi

if [ ! -f "${BUILD_DIR}/compile_commands.json" ]; then
    err "compile_commands.json not found in build directory"
fi

if [ ! -f "${BUILD_DIR}/bin/cvc5" ]; then
    err "Pre-built cvc5 binary not found"
fi

# Phase 1: Build coverage agent
log "Phase 1: Building coverage agent"

AGENT_SRC="${COVERAGE_AGENT:-${SCRIPT_DIR}/coverage_agent.cpp}"
AGENT_OBJ="${BUILD_DIR}/coverage_agent.o"

if [ ! -f "$AGENT_SRC" ]; then
    err "Coverage agent source not found: $AGENT_SRC"
fi

clang++ -c -o "$AGENT_OBJ" "$AGENT_SRC" \
    -O2 -g -std=c++17 -fPIC -fno-sanitize-coverage=trace-pc-guard || {
    err "Failed to build coverage agent"
}
ok "Coverage agent built: $AGENT_OBJ"

# Phase 2: Extract source files to recompile
log "Phase 2: Extracting source files from changed_functions.json"

# Use Python to do all the recompilation work (avoids subshell issues)
RECOMPILE_RESULT=$(python3 << PYTHON_EOF
import json
import subprocess
import os
import sys

changed_functions_json = "$CHANGED_FUNCTIONS_JSON"
compile_commands_path = "$BUILD_DIR/compile_commands.json"
sancov_allowlist = "$SANCOV_ALLOWLIST"
cvc5_dir = "$CVC5_DIR"
build_dir = "$BUILD_DIR"

# Instrumentation flags
sancov_flags = f"-fsanitize-coverage=trace-pc-guard -fsanitize-coverage-allowlist={sancov_allowlist}"
pgo_flags = "-fprofile-instr-generate -fcoverage-mapping"
inst_flags = f"{sancov_flags} {pgo_flags} -fno-inline"

# Load changed functions
with open(changed_functions_json) as f:
    data = json.load(f)

# Get unique source files
files = set()
for func_key, info in data.get('function_info_map', {}).items():
    file_path = info.get('file', '')
    if file_path and file_path.endswith(('.cpp', '.cc', '.c')):
        # Normalize to relative path under src/
        if '/src/' in file_path:
            file_path = 'src/' + file_path.split('/src/', 1)[1]
        files.add(file_path)

# Also check changed_functions list
for func in data.get('changed_functions', []):
    if ':' in func:
        file_path = func.split(':')[0]
        if file_path.endswith(('.cpp', '.cc', '.c')):
            files.add(file_path)

if not files:
    print("NO_FILES")
    sys.exit(0)

print(f"Source files to recompile: {len(files)}")
for f in sorted(files):
    print(f"  {f}")

# Load compile_commands.json
with open(compile_commands_path) as f:
    compile_commands = json.load(f)

# Build index by file suffix
cmd_index = {}
for cmd in compile_commands:
    file_path = cmd.get('file', '')
    cmd_index[file_path] = cmd
    # Also index by basename for flexibility
    basename = os.path.basename(file_path)
    if basename not in cmd_index:
        cmd_index[basename] = cmd

recompiled = 0
failed = 0

for src_file in sorted(files):
    # Find matching compile command
    matching_cmd = None
    for file_path, cmd in cmd_index.items():
        if file_path.endswith(src_file) or src_file in file_path:
            matching_cmd = cmd
            break
    
    if not matching_cmd:
        print(f"  ⚠️ No compile command for {src_file}")
        continue
    
    directory = matching_cmd.get('directory', '.')
    command = matching_cmd.get('command', '')
    
    if not command:
        print(f"  ⚠️ Empty command for {src_file}")
        continue
    
    # Add instrumentation flags after the compiler
    if 'clang++' in command:
        inst_cmd = command.replace('clang++', f'clang++ {inst_flags}', 1)
    elif 'clang ' in command:
        inst_cmd = command.replace('clang ', f'clang {inst_flags} ', 1)
    else:
        # Try adding flags after the first word (compiler)
        parts = command.split(' ', 1)
        if len(parts) == 2:
            inst_cmd = f"{parts[0]} {inst_flags} {parts[1]}"
        else:
            print(f"  ⚠️ Can't instrument {src_file}")
            continue
    
    print(f"  Recompiling: {src_file}")
    
    try:
        result = subprocess.run(
            inst_cmd,
            shell=True,
            cwd=directory,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"    ✓ Success")
            recompiled += 1
        else:
            print(f"    ✗ Failed: {result.stderr[:200]}")
            failed += 1
    except Exception as e:
        print(f"    ✗ Error: {e}")
        failed += 1

print(f"RESULT:{recompiled}:{failed}")
PYTHON_EOF
)

echo "$RECOMPILE_RESULT"

# Check if no files found
if echo "$RECOMPILE_RESULT" | grep -q "^NO_FILES$"; then
    warn "No source files found in changed_functions.json"
    warn "Attempting full rebuild with sancov flags..."
    exec "${SCRIPT_DIR}/build_cvc5_instrumented.sh" "" "$SANCOV_ALLOWLIST" ""
fi

# Extract results
RECOMPILED=$(echo "$RECOMPILE_RESULT" | grep "^RESULT:" | cut -d: -f2)
FAILED=$(echo "$RECOMPILE_RESULT" | grep "^RESULT:" | cut -d: -f3)
FILE_COUNT=$((RECOMPILED + FAILED))

echo ""
echo "Recompilation: $RECOMPILED succeeded, $FAILED failed"

# Phase 4: Relink binary with coverage agent
log "Phase 4: Relinking binary"

cd "$BUILD_DIR"

# Find link command
LINK_CMD_FILE=$(find "$BUILD_DIR" -name "link.txt" -path "*/cvc5-bin.dir/*" 2>/dev/null | head -1)

if [ -f "$LINK_CMD_FILE" ]; then
    ORIG_LINK=$(cat "$LINK_CMD_FILE")
    LINK_DIR=$(dirname "$LINK_CMD_FILE")
    
    # Add coverage agent and profile runtime
    INST_LINK="$ORIG_LINK $AGENT_OBJ -fprofile-instr-generate"
    
    cd "$LINK_DIR"
    if eval "$INST_LINK" 2>&1; then
        ok "Relinked via link.txt"
    else
        err "Relink failed"
    fi
else
    warn "link.txt not found, using make"
    
    # Force relink by touching main.cpp
    touch "${CVC5_DIR}/src/main/main.cpp" 2>/dev/null || true
    
    cd "$BUILD_DIR"
    CMAKE_EXE_LINKER_FLAGS="$AGENT_OBJ -fprofile-instr-generate" make -j$(nproc) cvc5-bin || {
        err "Relink via make failed"
    }
fi

# Phase 5: Verify instrumentation
log "Phase 5: Verifying instrumentation"

BINARY="${BUILD_DIR}/bin/cvc5"

SANCOV_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__sanitizer_cov" || echo "0")
PGO_SYM=$(nm "$BINARY" 2>/dev/null | grep -c "__llvm_profile" || echo "0")

echo "Instrumentation symbols:"
echo "  Sancov: $SANCOV_SYM"
echo "  PGO: $PGO_SYM"

# Test binary
if "$BINARY" --version > /dev/null 2>&1; then
    ok "Binary works"
else
    err "Binary crashed on --version!"
fi

# Summary
echo ""
echo "=============================================="
echo "INCREMENTAL BUILD SUMMARY"
echo "=============================================="
echo "Files recompiled: $FILE_COUNT"
echo "Sancov symbols: $SANCOV_SYM"
echo "PGO symbols: $PGO_SYM"
echo "Binary: $BINARY"
echo "Size: $(du -h "$BINARY" | cut -f1)"

if [ "$SANCOV_SYM" -gt 0 ]; then
    ok "INCREMENTAL BUILD SUCCESSFUL"
    exit 0
else
    err "BUILD FAILED - No sancov symbols found"
fi
