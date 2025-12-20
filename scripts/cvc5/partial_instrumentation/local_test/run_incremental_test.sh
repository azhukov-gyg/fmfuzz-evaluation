#!/bin/bash
# Run incremental instrumentation test in Docker
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="cvc5-incremental-test"
VOLUME_NAME="cvc5-build-cache"

REBUILD_IMAGE=false
EXTRA_ARGS=""
for arg in "$@"; do
    case $arg in
        --rebuild-image) REBUILD_IMAGE=true ;;
        *) EXTRA_ARGS="$EXTRA_ARGS $arg" ;;
    esac
done

echo "=== Incremental Instrumentation Test ==="

# Build image if needed
if [ "$REBUILD_IMAGE" = true ] || ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "Building Docker image..."
    docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile.incremental-test" "$SCRIPT_DIR"
fi

# Create volume for caching
docker volume inspect "$VOLUME_NAME" &>/dev/null || docker volume create "$VOLUME_NAME"

# Run test (mount both local_test and parent for coverage_agent.cpp)
PARENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

docker run --rm -it \
    -v "$VOLUME_NAME:/workspace" \
    -v "$SCRIPT_DIR:/scripts:ro" \
    -v "$PARENT_DIR/coverage_agent.cpp:/scripts/coverage_agent.cpp:ro" \
    "$IMAGE_NAME" \
    bash -c "bash /scripts/test_incremental_instrumentation.sh $EXTRA_ARGS"
