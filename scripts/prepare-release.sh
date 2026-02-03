#!/usr/bin/env bash
# Helper script to prepare a release
# Usage: ./scripts/prepare-release.sh

set -euo pipefail

# Check if git-cliff is installed
if ! command -v git-cliff &> /dev/null; then
    echo "Error: git-cliff is not installed"
    echo "Install with: brew install git-cliff"
    exit 1
fi

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2)
echo "Current version: ${CURRENT_VERSION}"

# Calculate next version based on commits (returns with 'v' prefix like 'v0.2.2')
NEXT_VERSION_WITH_V=$(git cliff --bumped-version)
# Strip the 'v' prefix for Cargo.toml
NEXT_VERSION=${NEXT_VERSION_WITH_V#v}
echo "Next version: ${NEXT_VERSION}"

# Ask for confirmation
read -p "Bump version to ${NEXT_VERSION}? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted"
    exit 1
fi

# Update Cargo.toml
echo "Updating Cargo.toml..."
sed -i.bak "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEXT_VERSION}\"/" Cargo.toml
rm Cargo.toml.bak

# Update Cargo.lock to reflect the new version
echo "Updating Cargo.lock..."
cargo check --quiet

# Generate changelog (git cliff expects the tag WITH 'v' prefix)
echo "Generating CHANGELOG.md..."
git cliff --unreleased --tag "${NEXT_VERSION_WITH_V}" --prepend CHANGELOG.md

echo ""
echo "✅ Release prepared!"
echo ""
echo "Next steps:"
echo "1. Review the changes in CHANGELOG.md"
echo "2. Sign security lists (if changed): minisign -Sm data/security-lists.toml -s /path/to/release-key.key"
echo "3. Commit: git add Cargo.toml Cargo.lock CHANGELOG.md && git commit -m 'Release v${NEXT_VERSION}'"
echo "4. Tag: git tag v${NEXT_VERSION}"
echo "5. Push: git push -u origin main && git push origin v${NEXT_VERSION}"
