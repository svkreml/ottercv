#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="ottercv-appimage-builder"
CONTAINER_NAME="ottercv-appimage-build-$$"

echo "Building Docker image..."
docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile.appimage" "$SCRIPT_DIR"

echo "Running build in container..."
docker run --rm --name "$CONTAINER_NAME" \
    -v "$SCRIPT_DIR:/build" \
    -e "AI_TEST=${AI_TEST:-false}" \
    -e "HOME=/build" \
    --user "$(id -u):$(id -g)" \
    "$IMAGE_NAME" \
    bash -c "cd /build && mvn clean package -P linux-appimage -q"

echo ""
echo "AppImage built successfully:"
ls -lh "$SCRIPT_DIR"/target/*.AppImage 2>/dev/null || true
