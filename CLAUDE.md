# nono - Development Guide

## Project Overview

nono is a capability-based shell for running untrusted AI agents with OS-enforced isolation. It uses Landlock (Linux) and Seatbelt (macOS) to create sandboxes where unauthorized operations are structurally impossible.

## Architecture

```
src/
├── main.rs           # Entry point, CLI handling, command execution
├── cli.rs            # Clap argument definitions
├── error.rs          # Error types (NonoError)
├── capability.rs     # Capability model (FsCapability, CapabilitySet)
└── sandbox/
    ├── mod.rs        # Platform dispatch (apply, is_supported)
    ├── linux.rs      # Landlock implementation
    └── macos.rs      # Seatbelt implementation
```

## Build & Test

After evevry session at the end of completing a task, run the following commands to ensure correctness:

```bash
# Build
cargo build

# Run tests
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run -- --allow . -- echo "test"

# Dry run (show capabilities without applying sandbox)
cargo run -- --allow . --dry-run -- command
```

## Lint and Format

After evevry session at the end of completing a task, run the following commands to ensure correctness:

```bash
# Lint code
cargo clippy -- -D warnings -D clippy::unwrap_used

# Format code
cargo fmt -- --check
```

## Key Design Decisions

1. **No escape hatch**: Once sandbox is applied via `restrict_self()` (Landlock) or `sandbox_init()` (Seatbelt), there is no API to expand permissions.

2. **exec() model**: After applying the sandbox, nono uses `exec()` to replace itself with the target command. This means the command inherits all restrictions.

4. **Capability resolution**: All paths are canonicalized at grant time to prevent symlink escapes.

## Platform-Specific Notes

### macOS (Seatbelt)
- Uses `sandbox_init()` FFI with raw profile strings
- Profile is Scheme-like DSL: `(allow file-read* (subpath "/path"))`
- Network denied by default with `(deny network*)`
- System paths (/usr, /bin, /System, etc.) allowed for executables

### Linux (Landlock)
- Uses landlock crate for safe Rust bindings
- Detects highest available ABI (v1-v5)
- ABI v4+ includes TCP network filtering
- Older kernels need seccomp fallback for network

## Adding New Capabilities

To add a new capability type:

1. Add variant to `Capability` enum in `capability.rs`
2. Update `CapabilitySet::from_args()` to parse from CLI
3. Update `sandbox/linux.rs` to apply via Landlock
4. Update `sandbox/macos.rs` to generate Seatbelt profile rules

## Testing Sandbox Enforcement

```bash
# Should succeed (write to allowed path)
nono --allow . -- sh -c "echo test > ./allowed.txt"

# Should fail (write to disallowed path)
nono --allow . -- sh -c "echo test > /tmp/outside.txt"

# Should fail (network blocked)
nono --allow . -- curl https://example.com
```

## Coding Standards
- Error Handling: Use NonoError for all errors; propagation via ? only.
- Unwrap Policy: Strictly forbid .unwrap() and .expect(); use clippy::unwrap_used to enforce.
- Use proper error propagation and handling with Result<T, E> and Option<T> for expected and recoverable errors
- Unsafe Code: Restrict unsafe to FFI; must be wrapped in safe APIs with // SAFETY: docs.
- Path Security: Validate and canonicalize all paths before applying capabilities.
- Arithmetic: Use checked_, saturating_, or overflowing_ methods for security-critical math.
- Memory: Use the zeroize crate for sensitive data (keys/passwords) in memory.
- Dependencies: Mandatory cargo-audit and cargo-deny checks in CI.
- Testing: Write unit tests for all new capability types and sandbox logic.
- Attributes: Apply #[must_use] to all functions returning critical Results.
- Avoid blanket permissions on entire directories; be specific about which paths are allowed and which operations (read/write) are permitted.

## Security Considerations

**SECURITY IS NON-NEGOTIABLE.** This is a security-critical codebase. Every change must be evaluated through a security lens first. When in doubt, choose the more restrictive option.

### Core Principles
- **Principle of Least Privilege**: Only grant the minimum necessary capabilities. Never add broad permissions for convenience.
- **Defense in Depth**: Combine OS-level sandboxing with application-level checks. Never rely on a single layer.
- **Fail Secure**: On any error, deny access. Never silently degrade to a less secure state.
- **Explicit Over Implicit**: Security-relevant behavior must be explicit and auditable.

### Sandbox-Specific Security Requirements

#### Path Handling (CRITICAL)
- **Always use path component comparison, not string operations.** String `starts_with()` on paths is a vulnerability. Use `std::path::Path::starts_with()` which compares path components.
- **Canonicalize paths at the enforcement boundary**, not just at input. Be aware of TOCTOU (time-of-check-time-of-use) race conditions with symlinks.
- **Validate environment variables before use.** Never assume `HOME`, `TMPDIR`, or other env vars are set or trustworthy. Handle missing/malicious values explicitly.
- **Escape and validate all data used in profile generation.** When building Seatbelt profiles or similar DSLs, treat all external input as potentially malicious. Validate for injection characters (newlines, parentheses, quotes).

#### Permission Scope (CRITICAL)
- **Never grant access to entire directories when specific paths suffice.** Granting `/etc` when you need `/etc/resolv.conf` is a vulnerability.
- **Audit every path added to allow lists.** Consider what else lives in that directory. System directories often contain sensitive files alongside needed ones.
- **Separate read and write permissions.** Read access to `/dev` is very different from write access. Be explicit about which operations are allowed.
- **Sensitive path lists must be comprehensive.** When adding credential storage locations, research all common tools and their config paths. Missing entries are vulnerabilities.

#### Error Handling (CRITICAL)
- **Configuration load failures must be fatal.** If security lists fail to load, the program must abort, not continue with empty/default permissions.
- **Log security-relevant failures.** Silent failures hide attacks. All permission denials should be auditable.
- **Never catch and ignore errors in security paths.** Every `Result` in sandbox code must be explicitly handled.

#### Environment and Input Validation
- **Treat all environment variables as attacker-controlled.** An attacker running `HOME=/tmp/evil nono ...` should not bypass protections.
- **Validate that required security preconditions are met before proceeding.** Check that critical env vars exist, paths resolve correctly, and the system supports required features.

### Common Footguns to Avoid

1. **String comparison for paths**: `path.starts_with("/home")` matches `/homeevil`. Use `Path::starts_with()`.
2. **Silent fallbacks**: `unwrap_or_default()` on security config returns empty permissions = no protection.
3. **Overly broad wildcards**: `/dev/*` includes `/dev/sda`. Enumerate specific safe entries instead.
4. **Trusting resolved paths**: Symlinks can change between resolution and use. Minimize the window.
5. **Forgetting platform differences**: macOS `/etc` is a symlink to `/private/etc`. Both must be considered.
6. **Metadata leaks**: Even denying file content, allowing metadata reveals file existence, size, and timestamps.
7. **Write access to unexpected locations**: `/tmp` and `/dev` write access enables symlink attacks and IPC escapes.

### Security Review Checklist

Before any PR that touches sandbox code:
- [ ] Are all paths compared using path-aware methods, not strings?
- [ ] Do all config/list load failures result in program abort?
- [ ] Are new allow-list entries minimal and justified?
- [ ] Have you checked what else exists in any directories being granted?
- [ ] Are environment variables validated before use?
- [ ] Is external input escaped before use in profile generation?
- [ ] Are there any new silent fallbacks that could degrade security?
- [ ] Have you tested with malicious/missing environment variables?

## References

- [SPEC.md](./SPEC.md) - Full specification and threat model
- [IMPLEMENTATION.md](./IMPLEMENTATION.md) - Detailed implementation plan
- [Landlock docs](https://landlock.io/)
- [macOS Sandbox Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/)
