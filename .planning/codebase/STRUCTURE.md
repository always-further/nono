# Codebase Structure

**Analysis Date:** 2024-04-04

## Directory Layout

```
[project-root]/
├── .github/            # GitHub Actions CI/CD workflows
├── assets/             # Logos and static assets
├── bindings/           # Language bindings (C/C++)
├── build_notes/        # Documentation and scratchpad
├── crates/             # Main source code (Rust workspace)
│   ├── nono/           # Core sandboxing library
│   ├── nono-cli/       # CLI tool and supervisor
│   └── nono-proxy/     # Network filtering proxy
├── docs/               # User and internal documentation
├── profiles/           # Sample profiling data/traces
├── scripts/            # Platform-specific utilities and tests
├── tests/              # Integration test suites
└── tools/              # Helper tools (Docker, etc.)
```

## Directory Purposes

**crates/nono:**
- Purpose: The core library providing platform-specific sandbox primitives.
- Contains: `src/sandbox/`, `src/supervisor/`, `src/undo/`.
- Key files: `src/lib.rs`, `src/capability.rs`, `src/manifest.rs`.

**crates/nono-cli:**
- Purpose: Orchestrates the sandbox lifecycle and provides a user CLI.
- Contains: Command runtimes (`..._runtime.rs`), execution strategies (`src/exec_strategy/`).
- Key files: `src/main.rs`, `src/cli.rs`, `src/sandbox_prepare.rs`.

**crates/nono-proxy:**
- Purpose: A standalone proxy for network domain filtering and credential injection.
- Contains: Proxy servers (`src/server.rs`), credential handling (`src/credential.rs`).
- Key files: `src/lib.rs`, `src/filter.rs`.

**bindings/c:**
- Purpose: C API for the `nono` library.
- Contains: Rust bridge code and generated headers.
- Key files: `src/lib.rs`, `include/nono.h`.

**tests/integration:**
- Purpose: End-to-end shell-based tests for CLI commands.
- Contains: Shell scripts testing various sandbox scenarios (e.g., `test_fs_access.sh`).

## Key File Locations

**Entry Points:**
- `crates/nono-cli/src/main.rs`: Primary CLI entry point.
- `crates/nono/src/lib.rs`: Library API entry point.

**Configuration:**
- `crates/nono-cli/src/config/`: Default policies and profile loading logic.
- `Cargo.toml`: Workspace configuration and dependency management.

**Core Logic:**
- `crates/nono/src/sandbox/`: OS-specific drivers (Linux/macOS/Windows).
- `crates/nono/src/capability.rs`: The core capability model used by all crates.
- `crates/nono/src/undo/`: Snapshot and rollback implementation.

**Testing:**
- `tests/integration/`: High-level behavior tests.
- `crates/nono/tests/`: Library unit tests.
- `crates/nono-cli/tests/`: CLI integration tests.

## Naming Conventions

**Files:**
- Rust modules: `snake_case.rs`
- Platform-specific: `*_windows.rs`, `*_linux.rs`
- Command runtimes: `*_runtime.rs`

**Directories:**
- Crate names: `nono-*`
- Module groups: `snake_case`

## Where to Add New Code

**New Sandboxing Primitive:**
- Primary code: `crates/nono/src/sandbox/` (or a new module in `crates/nono/src/`)
- Tests: `crates/nono/tests/`

**New CLI Command:**
- Runtime logic: `crates/nono-cli/src/[name]_runtime.rs`
- CLI definition: `crates/nono-cli/src/cli.rs`
- Orchestration: `crates/nono-cli/src/app_runtime.rs`

**New Proxy Feature:**
- Logic: `crates/nono-proxy/src/`

**Utilities:**
- Shared library helpers: `crates/nono/src/`
- Shared CLI helpers: `crates/nono-cli/src/`

## Special Directories

**target/:**
- Purpose: Build artifacts.
- Generated: Yes
- Committed: No

**.planning/:**
- Purpose: Architectural documentation and project management state.
- Generated: No
- Committed: Yes

---

*Structure analysis: 2024-04-04*
