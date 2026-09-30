#!/usr/bin/env bash
set -euo pipefail

# Spectra Release Script
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 1.0.0

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.0.0"
    exit 1
fi

echo "=== Spectra Release v${VERSION} ==="
echo ""

# 1. Pre-flight checks
echo "1. Running pre-flight checks..."
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
echo "   ✓ All checks passed"
echo ""

# 2. Update version numbers
echo "2. Updating version numbers..."
# Update Cargo.toml workspace version
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml
# Update package.json
if [ -f "npm/package.json" ]; then
    sed -i "s/\"version\": \".*\"/\"version\": \"${VERSION}\"/" npm/package.json
fi
echo "   ✓ Version updated to ${VERSION}"
echo ""

# 3. Build release
echo "3. Building release binaries..."
cargo build --release --workspace
echo "   ✓ Release build complete"
echo ""

# 4. Create git tag
echo "4. Creating git tag..."
git add -A
git commit -m "Release v${VERSION}"
git tag -a "v${VERSION}" -m "Release v${VERSION}"
echo "   ✓ Tagged v${VERSION}"
echo ""

# 5. Build Docker images
echo "5. Building Docker images..."
if command -v docker &> /dev/null; then
    docker build -t "spectra-api:${VERSION}" .
    docker build -t "spectra-worker:${VERSION}" .
    echo "   ✓ Docker images built"
else
    echo "   ⚠ Docker not found, skipping"
fi
echo ""

# 6. Summary
echo "=== Release Summary ==="
echo "Version: ${VERSION}"
echo "Tag: v${VERSION}"
echo ""
echo "Next steps:"
echo "  git push origin main --tags"
echo "  docker push spectra-api:${VERSION}"
echo "  docker push spectra-worker:${VERSION}"
echo "  npm publish --access public"
echo ""
echo "Release complete!"
