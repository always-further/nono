#!/usr/bin/env bash
# Helper script to prepare a release for nono workspace
# Usage: ./scripts/prepare-release.sh [VERSION]
# If VERSION is provided (e.g., 0.6.0), it overrides the auto-detected version.

set -euo pipefail

latest_tag() {
    git describe --tags --abbrev=0 2>/dev/null || true
}

show_bump_rationale() {
    local previous_tag="$1"
    local range=""

    if [[ -n "${previous_tag}" ]]; then
        range="${previous_tag}..HEAD"
        echo "Commits since ${previous_tag}:"
    else
        range="HEAD"
        echo "Commits considered for initial release:"
    fi

    local conventional_commits
    conventional_commits=$(git log --format='%s' "${range}" | grep -E '^[[:alpha:]]+(\([^)]*\))?!?: ' || true)

    if [[ -z "${conventional_commits}" ]]; then
        echo "  No conventional commits found in range; git-cliff selected the bump."
        return
    fi

    printf '%s\n' "${conventional_commits}" | sed 's/^/  - /'

    if printf '%s\n' "${conventional_commits}" | grep -Eq '^[[:alpha:]]+(\([^)]*\))?!: |BREAKING CHANGE'; then
        echo "Bump rationale: breaking change detected, so bumping major."
    elif printf '%s\n' "${conventional_commits}" | grep -Eq '^feat(\([^)]*\))?: '; then
        echo "Bump rationale: at least one feat commit detected, so bumping minor."
    elif printf '%s\n' "${conventional_commits}" | grep -Eq '^fix(\([^)]*\))?: '; then
        echo "Bump rationale: only fix-level changes detected, so bumping patch."
    else
        echo "Bump rationale: no feat or breaking commits detected; git-cliff selected the bump."
    fi
}

# Check if git-cliff is installed
if ! command -v git-cliff &> /dev/null; then
    echo "Error: git-cliff is not installed"
    echo "Install with: brew install git-cliff"
    exit 1
fi

# Get current version from workspace root Cargo.toml (nono crate)
CURRENT_VERSION=$(grep '^version = ' crates/nono/Cargo.toml | head -1 | cut -d'"' -f2)
PREVIOUS_TAG=$(latest_tag)
echo "Current version: ${CURRENT_VERSION}"

# Determine next version: use argument if provided, otherwise auto-detect
if [[ -n "${1:-}" ]]; then
    NEXT_VERSION="${1#v}"
    NEXT_VERSION_WITH_V="v${NEXT_VERSION}"
else
    NEXT_VERSION_WITH_V=$(git cliff --bumped-version)
    NEXT_VERSION=${NEXT_VERSION_WITH_V#v}
fi
echo "Next version: ${NEXT_VERSION}"

if [[ -z "${1:-}" ]]; then
    show_bump_rationale "${PREVIOUS_TAG}"
fi

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
touch CHANGELOG.md
git cliff --unreleased --tag "${NEXT_VERSION_WITH_V}" --prepend CHANGELOG.md

echo ""
echo "Release prepared!"
echo ""
echo "Next steps:"
echo "1. Review the changes in CHANGELOG.md"
echo "2. Commit: git add crates/*/Cargo.toml bindings/c/Cargo.toml Cargo.lock CHANGELOG.md && git commit -m 'chore: release v${NEXT_VERSION}'"
echo "3. Tag: git tag v${NEXT_VERSION}"
echo "4. Push: git push origin main && git push origin v${NEXT_VERSION}"
