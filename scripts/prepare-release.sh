#!/usr/bin/env bash
# Helper script to prepare a release for nono workspace
# Usage: ./scripts/prepare-release.sh

set -euo pipefail

# Check if git-cliff is installed
if ! command -v git-cliff &> /dev/null; then
    echo "Error: git-cliff is not installed"
    echo "Install with: brew install git-cliff"
    exit 1
fi

# Get current version from workspace root Cargo.toml (nono crate)
CURRENT_VERSION=$(grep '^version = ' crates/nono/Cargo.toml | head -1 | cut -d'"' -f2)
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

# Update all crate versions
echo "Updating crate versions..."

# Update nono (core library)
sed -i.bak "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEXT_VERSION}\"/" crates/nono/Cargo.toml
rm crates/nono/Cargo.toml.bak

# Update nono-proxy (version + nono dependency)
sed -i.bak -e "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEXT_VERSION}\"/" \
    -e "s/nono = { version = \"[^\"]*\"/nono = { version = \"${NEXT_VERSION}\"/" \
    crates/nono-proxy/Cargo.toml
rm crates/nono-proxy/Cargo.toml.bak

# Update nono-cli (version + nono and nono-proxy dependencies)
sed -i.bak -e "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEXT_VERSION}\"/" \
    -e "s/nono = { version = \"[^\"]*\"/nono = { version = \"${NEXT_VERSION}\"/" \
    -e "s/nono-proxy = { version = \"[^\"]*\"/nono-proxy = { version = \"${NEXT_VERSION}\"/" \
    crates/nono-cli/Cargo.toml
rm crates/nono-cli/Cargo.toml.bak

# Update nono-ffi (version + nono dependency)
sed -i.bak -e "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEXT_VERSION}\"/" \
    -e "s/nono = { version = \"[^\"]*\"/nono = { version = \"${NEXT_VERSION}\"/" \
    bindings/c/Cargo.toml
rm bindings/c/Cargo.toml.bak

# Update Cargo.lock to reflect the new versions
echo "Updating Cargo.lock..."
cargo check --quiet

# Generate changelog (git cliff expects the tag WITH 'v' prefix)
echo "Generating CHANGELOG.md..."
git cliff --unreleased --tag "${NEXT_VERSION_WITH_V}" --prepend CHANGELOG.md

echo ""
echo "Release prepared!"
echo ""
echo "Next steps:"
echo "1. Review the changes in CHANGELOG.md"
echo "2. Commit: git add crates/*/Cargo.toml bindings/c/Cargo.toml Cargo.lock CHANGELOG.md && git commit -m 'Release v${NEXT_VERSION}'"
echo "3. Tag: git tag v${NEXT_VERSION}"
echo "4. Push: git push origin main && git push origin v${NEXT_VERSION}"
