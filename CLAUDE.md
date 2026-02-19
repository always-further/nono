# nono - Development Guide

## Project Overview

nono is a capability-based sandboxing system for running untrusted AI agents with OS-enforced isolation. It uses Landlock (Linux) and Seatbelt (macOS) to create sandboxes where unauthorized operations are structurally impossible.

The project is a Cargo workspace with three members:
- **nono** (`crates/nono/`) - Core library. Pure sandbox primitive with no built-in security policy.
- **nono-cli** (`crates/nono-cli/`) - CLI binary. Owns all security policy, profiles, hooks, and UX.
- **nono-ffi** (`bindings/c/`) - C FFI bindings. Exposes the library via `extern "C"` functions and auto-generated `nono.h` header.

Language bindings live in separate repositories:
- **nono-py** (`../nono-py/`) - Python bindings via PyO3. Published to PyPI.
- **nono-ts** (`../nono-ts/`) - TypeScript/Node bindings via napi-rs. Published to npm.

## Architecture

```
crates/nono/src/                    # Library - pure sandbox primitive
├── lib.rs                          # Public API re-exports
├── capability.rs                   # CapabilitySet, FsCapability, AccessMode (builder pattern)
├── error.rs                        # NonoError enum
├── state.rs                        # SandboxState serialization
├── diagnostic.rs                   # DiagnosticFormatter
├── query.rs                        # QueryContext for permission checking
├── keystore.rs                     # Secure credential loading from system keystore
├── undo/
│   ├── mod.rs                      # Module root, re-exports public API
│   ├── types.rs                    # ContentHash, FileState, Change, SnapshotManifest, SessionMetadata
│   ├── object_store.rs             # Content-addressable file storage (SHA-256, dedup, clone_or_copy)
│   ├── merkle.rs                   # MerkleTree (cryptographic state commitment)
│   ├── snapshot.rs                 # SnapshotManager (baseline, incremental, restore)
│   └── exclusion.rs                # ExclusionFilter (gitignore, patterns, globs)
└── sandbox/
    ├── mod.rs                      # Sandbox facade: apply(), is_supported(), support_info()
    ├── linux.rs                    # Landlock implementation
    └── macos.rs                    # Seatbelt implementation

crates/nono-cli/src/                # CLI - security policy and UX
├── main.rs                         # Entry point, command routing
├── cli.rs                          # Clap argument definitions
├── capability_ext.rs               # CapabilitySetExt trait (CLI-specific construction)
├── policy.rs                       # Group resolver: parse policy.json, filter, expand, resolve
├── query_ext.rs                    # CLI-specific query functions
├── sandbox_state.rs                # CLI-specific state handling
├── exec_strategy.rs                # Fork+exec with signal forwarding (Direct/Monitor/Supervised)
├── hooks.rs                        # Claude Code hook installation
├── setup.rs                        # System setup and verification
├── output.rs                       # Banner, dry-run output, prompts
├── rollback_ui.rs                  # Interactive rollback review and restore prompts
├── learn.rs                        # strace-based path discovery (Linux only)
├── config/
│   ├── mod.rs                      # Config module root
│   ├── embedded.rs                 # Embedded data (build.rs artifacts)
│   ├── user.rs                     # User configuration
│   └── version.rs                  # Version tracking
└── profile/
    ├── mod.rs                      # Profile loading
    └── builtin.rs                  # Built-in profiles (delegates to policy resolver)

crates/nono-cli/data/               # Embedded at build time via build.rs
├── policy.json                     # Groups, deny rules, built-in profiles (single source of truth)
└── hooks/
    └── nono-hook.sh                # Hook script for Claude Code

bindings/c/src/                     # C FFI - extern "C" wrappers over core library
├── lib.rs                          # Thread-local error store, string helpers, version
├── types.rs                        # #[repr(C)] enums and structs
├── capability_set.rs               # NonoCapabilitySet opaque pointer API
├── fs_capability.rs                # Index-based FsCapability accessors
├── sandbox.rs                      # Sandbox apply/support functions
├── query.rs                        # NonoQueryContext opaque pointer API
└── state.rs                        # NonoSandboxState opaque pointer API
```

### Library vs CLI Boundary

The library is a **pure sandbox primitive**. It applies ONLY what clients explicitly add to `CapabilitySet`:

| In Library | In CLI |
|------------|--------|
| `CapabilitySet` builder | Policy groups (deny rules, dangerous commands, system paths) |
| `Sandbox::apply()` | Group resolver (`policy.rs`) and platform-aware deny handling |
| `SandboxState` | `ExecStrategy` (Direct/Monitor/Supervised) |
| `DiagnosticFormatter` | Profile loading and hooks |
| `QueryContext` | All output and UX |
| `keystore` | `learn` mode |
| `undo` module (ObjectStore, SnapshotManager, MerkleTree, ExclusionFilter) | Rollback lifecycle, exclusion policy, rollback UI |

## Build & Test

After every session, run these commands to verify correctness:

```bash
# Build everything
make build

# Run all tests
make test

# Full CI check (clippy + fmt + tests)
make ci
```

Individual targets:
```bash
make build-lib       # Library only
make build-cli       # CLI only
make test-lib        # Library tests only
make test-cli        # CLI tests only
make test-doc        # Doc tests only
make clippy          # Lint (strict: -D warnings -D clippy::unwrap_used)
make fmt-check       # Format check
make fmt             # Auto-format
```

## Coding Standards

- **Error Handling**: Use `NonoError` for all errors; propagation via `?` only.
- **Unwrap Policy**: Strictly forbid `.unwrap()` and `.expect()`; enforced by `clippy::unwrap_used`.
- **Libraries should almost never panic**: Panics are for unrecoverable bugs, not expected error conditions. Use `Result` instead.
- **Unsafe Code**: Restrict to FFI; must be wrapped in safe APIs with `// SAFETY:` docs.
- **Path Security**: Validate and canonicalize all paths before applying capabilities.
- **Arithmetic**: Use `checked_`, `saturating_`, or `overflowing_` methods for security-critical math.
- **Memory**: Use the `zeroize` crate for sensitive data (keys/passwords) in memory.
- **Testing**: Write unit tests for all new capability types and sandbox logic.
- **Attributes**: Apply `#[must_use]` to functions returning critical Results.
- **Lazy use of dead code**: Avoid `#[allow(dead_code)]`. If code is unused, either remove it or write tests that use it.

## Key Design Decisions

1. **No escape hatch**: Once sandbox is applied via `restrict_self()` (Landlock) or `sandbox_init()` (Seatbelt), there is no API to expand permissions.

2. **Fork+wait process model**: nono stays alive as a parent process. On child failure, prints a diagnostic footer to stderr. Three execution strategies: `Direct` (exec, backward compat), `Monitor` (sandbox-then-fork, default), `Supervised` (fork-then-sandbox, for rollbacks/expansion).

3. **Capability resolution**: All paths are canonicalized at grant time to prevent symlink escapes.

4. **Library is policy-free**: The library applies ONLY what's in `CapabilitySet`. No built-in sensitive paths, dangerous commands, or system paths. Clients define all policy.

## Platform-Specific Notes

### macOS (Seatbelt)
- Uses `sandbox_init()` FFI with raw profile strings
- Profile is Scheme-like DSL: `(allow file-read* (subpath "/path"))`
- Network denied by default with `(deny network*)`

### Linux (Landlock)
- Uses landlock crate for safe Rust bindings
- Detects highest available ABI (v1-v5)
- ABI v4+ includes TCP network filtering
- Strictly allow-list: cannot express deny-within-allow. `deny.access`, `deny.unlink`, and `symlink_pairs` are macOS-only. Avoid broad allow groups that cover deny paths.

## Security Considerations

**SECURITY IS NON-NEGOTIABLE.** This is a security-critical codebase. Every change must be evaluated through a security lens first. When in doubt, choose the more restrictive option.

### Core Principles
- **Principle of Least Privilege**: Only grant the minimum necessary capabilities.
- **Defense in Depth**: Combine OS-level sandboxing with application-level checks.
- **Fail Secure**: On any error, deny access. Never silently degrade to a less secure state.
- **Explicit Over Implicit**: Security-relevant behavior must be explicit and auditable.

### Path Handling (CRITICAL)
- Always use path component comparison, not string operations. String `starts_with()` on paths is a vulnerability.
- Canonicalize paths at the enforcement boundary. Be aware of TOCTOU race conditions with symlinks.
- Validate environment variables before use. Never assume `HOME`, `TMPDIR`, etc. are trustworthy.
- Escape and validate all data used in Seatbelt profile generation.

### Permission Scope (CRITICAL)
- Never grant access to entire directories when specific paths suffice.
- Separate read and write permissions explicitly.
- Configuration load failures must be fatal. If security lists fail to load, abort.

### Common Footguns
1. **String comparison for paths**: `path.starts_with("/home")` matches `/homeevil`. Use `Path::starts_with()`.
2. **Silent fallbacks**: `unwrap_or_default()` on security config returns empty permissions = no protection.
3. **Trusting resolved paths**: Symlinks can change between resolution and use.
4. **Platform differences**: macOS `/etc` is a symlink to `/private/etc`. Both must be considered.
5. **Overly broad permissions**: Granting `/tmp` read/write when only `/tmp/specific-file` is needed.
6. **Solving for one architecture**: Linux and macOS have different capabilities and threat models. Design must account for both. Develop abstractions that can be implemented securely on both platforms. Test on both platforms regularly to catch divergences.

## References

- [DESIGN-library.md](proj/DESIGN-library.md) - Library architecture, workspace layout, bindings
- [DESIGN-group-policy.md](proj/DESIGN-group-policy.md) - Group-based security policy, `never_grant`
- [DESIGN-supervisor.md](proj/DESIGN-supervisor.md) - Process model, execution strategies, supervisor IPC
- [DESIGN-undo-system.md](proj/DESIGN-undo-system.md) - Content-addressable snapshot system
- [Landlock docs](https://landlock.io/)
- [macOS Sandbox Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/)
