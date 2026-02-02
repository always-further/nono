# Release Engineering

This document describes the release process for nono, including signing procedures and checklist.

## Prerequisites

### Required Tools

```bash
# Install minisign for signing
brew install minisign  # macOS
# or: cargo install minisign

# Install GitHub CLI for releases
brew install gh
```

### Signing Key Setup

The release signing key should be stored securely (ideally in an HSM or secure enclave). For development/testing, you can generate a key locally.

#### Generate Release Signing Key (One-time Setup)

```bash
# Generate the author keypair
# Store the secret key securely - this is the root of trust!
minisign -G -p release-key.pub -s release-key.key

# The public key will look like:
# RWTk1xXqcTODeYttYMCqEwcLg+KiX+Vpu1v6iV3D0sGabcdef12345678

# Add the public key to src/config/embedded.rs as AUTHOR_PUBLIC_KEY
```

#### Store the Secret Key

The secret key (`release-key.key`) must be:
- Stored in a secure location (not in the repository!)
- Password-protected (minisign prompts for this during generation)
- Backed up securely
- Access-controlled to release managers only

Recommended storage:
- Hardware security module (HSM/YubiKey)
- macOS Keychain (encrypted)
- 1Password / other password manager
- Encrypted USB drive in secure storage

## Signing Security Lists

Before each release, sign the security lists:

```bash
# Navigate to project root
cd /path/to/nono

# Sign the security lists
minisign -Sm data/security-lists.toml -s /path/to/release-key.key \
  -t "version:$(grep '^version = ' data/security-lists.toml | cut -d'"' -f2) file:security-lists.toml"

# This creates data/security-lists.toml.minisig
# The signature file should be committed to the repository
```

### Trusted Comment Format

The trusted comment should include:
- `version:N` - The monotonic version number from the TOML
- `file:security-lists.toml` - The original filename
- `timestamp:UNIX_TIMESTAMP` (optional, minisign adds this)

Example:
```
trusted comment: version:5 file:security-lists.toml timestamp:1705312200
```

## Release Checklist

### Before Release

- [ ] All tests pass: `cargo test`
- [ ] Clippy clean: `cargo clippy -- -D warnings -D clippy::unwrap_used`
- [ ] Formatting clean: `cargo fmt --check`
- [ ] Version bumped in `Cargo.toml`
- [ ] Version bumped in `data/security-lists.toml` (if security lists changed)
- [ ] CHANGELOG.md updated
- [ ] Security lists signed (if changed)

### Signing Process

```bash
# 1. Ensure security lists are signed (if they changed)
minisign -Sm data/security-lists.toml -s /secure/path/release-key.key

# 2. Verify the signature
minisign -Vm data/security-lists.toml -p release-key.pub

# 3. Commit the signature file
git add data/security-lists.toml.minisig
git commit -m "Sign security lists for release vX.Y.Z"
```

### Build Release

```bash
# Build release binary
cargo build --release

# The binary includes:
# - Embedded security-lists.toml
# - Embedded signature (if present)
# - SECURITY_LISTS_SIGNED=1 env var (if signature present)
```

### Create Release

```bash
# Tag the release
git tag -s v0.X.Y -m "Release v0.X.Y"
git push origin v0.X.Y

# Create GitHub release with binaries
# (Usually handled by CI/CD)
```

### Post-Release

- [ ] Verify release artifacts on GitHub
- [ ] Update Homebrew formula (if applicable)
- [ ] Announce release (Discord, etc.)

## Version Numbering

### Semantic Versioning

nono follows semantic versioning:
- MAJOR: Breaking changes to CLI or security model
- MINOR: New features, backwards compatible
- PATCH: Bug fixes, security patches

### Security Lists Version

The `version` field in `data/security-lists.toml` is a monotonic counter used for downgrade protection:

```toml
[meta]
version = 5  # Must always increase, never decrease
```

**Important**: This version number must NEVER decrease. Each release with security list changes must increment this number.

## CI/CD Integration

### GitHub Actions Workflow

The release workflow should:

1. Run tests and linting
2. Build release binaries for all platforms
3. Sign binaries with release key
4. Create GitHub release with artifacts
5. Update Homebrew tap

### Secrets Required

Configure these secrets in GitHub Actions:

| Secret | Description |
|--------|-------------|
| `MINISIGN_SECRET_KEY` | Base64-encoded secret key |
| `MINISIGN_PASSWORD` | Password for the secret key |
| `HOMEBREW_TAP_TOKEN` | Token for updating Homebrew formula |

### Example Signing Step (GitHub Actions)

```yaml
- name: Sign Release Binaries
  env:
    MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
    MINISIGN_PASSWORD: ${{ secrets.MINISIGN_PASSWORD }}
  run: |
    # Decode and write secret key
    echo "$MINISIGN_SECRET_KEY" | base64 -d > /tmp/release.key

    # Sign each binary
    for binary in target/release/nono-*; do
      echo "$MINISIGN_PASSWORD" | minisign -Sm "$binary" -s /tmp/release.key -t "file:$(basename $binary)"
    done

    # Clean up
    rm /tmp/release.key
```

## Key Rotation

If the signing key needs to be rotated (compromise, expiration, etc.):

### Planned Rotation

1. Generate new keypair
2. Update `AUTHOR_PUBLIC_KEY` in `src/config/embedded.rs`
3. Sign security lists with new key
4. Release new version
5. Securely destroy old secret key

### Emergency Rotation (Key Compromise)

1. Immediately generate new keypair
2. Increment security lists version significantly (e.g., +1000)
3. Update `AUTHOR_PUBLIC_KEY` in source
4. Sign with new key and release immediately
5. Communicate compromise to users
6. Securely destroy compromised key

## Troubleshooting

### "Signature verification failed"

Check that:
- The `.minisig` file is in the correct location (`data/security-lists.toml.minisig`)
- The public key in `src/config/embedded.rs` matches the signing key
- The file hasn't been modified after signing

### "Version downgrade detected"

This error means someone is trying to use an older version of the security lists. The version number in `data/security-lists.toml` must always increase.

### Build Without Signatures (Development)

For development builds without signatures:

```bash
# Remove the signature file (if present)
rm -f data/security-lists.toml.minisig

# Build - will set SECURITY_LISTS_SIGNED=0
cargo build

# Debug output will show "Running with unsigned security lists (development mode)"
```

## Security Considerations

### Key Security

- The release signing key is the root of trust for nono security
- Compromise of this key allows arbitrary modification of security lists
- Protect it accordingly (HSM, secure storage, limited access)

### Supply Chain

- All dependencies are audited with `cargo-audit`
- `cargo-deny` checks for known vulnerabilities
- Consider reproducible builds for maximum verification

### Transparency

- All signing operations should be logged
- Release commits should be signed with GPG
- Consider Sigstore/Rekor for public transparency log
