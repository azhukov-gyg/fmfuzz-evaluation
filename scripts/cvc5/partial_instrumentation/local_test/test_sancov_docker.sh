#!/bin/bash
# Run sancov + PGO build test in Docker
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="cvc5-sancov-test"
VOLUME_NAME="cvc5-sancov-cache"

echo "=== Sancov + PGO Build Test (Docker) ==="

# Build Docker image
echo "Building Docker image..."
docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile.test-sancov" "$SCRIPT_DIR"

# Create volume for build cache
docker volume create "$VOLUME_NAME" 2>/dev/null || true

# Run test
# Mount local_test/ as /scripts for local test scripts
# Mount parent's Python scripts for reuse
echo "Running build test..."
docker run --rm \
    -v "$VOLUME_NAME:/workspace" \
    -v "$SCRIPT_DIR:/scripts:ro" \
    -v "$PARENT_DIR/coverage_agent.cpp:/coverage_agent.cpp:ro" \
    -v "$PARENT_DIR/extract_function_counts.py:/scripts/extract_function_counts.py:ro" \
    --tmpfs /dev/shm:rw,size=2g \
    "$IMAGE_NAME" \
    /bin/bash /scripts/test_sancov_local.sh "$@"

echo ""
echo "Re-run: $0"
echo "Clean cache: docker volume rm $VOLUME_NAME"
