# Codebase Concerns

**Analysis Date:** 2025-05-15

## Tech Debt

**Monolithic CLI Modules:**
- Issue: `profile/mod.rs` and `exec_strategy.rs` have grown to several thousand lines, combining configuration, validation, process management, and terminal handling.
- Files: `crates/nono-cli/src/profile/mod.rs`, `crates/nono-cli/src/exec_strategy.rs`
- Impact: Increased cognitive load for maintainers, high risk of side effects when modifying logic, and difficult unit testing.
- Fix approach: Refactor `profile/mod.rs` into a submodule structure (e.g., `profile/config.rs`, `profile/validation.rs`, `profile/loader.rs`). Split `exec_strategy.rs` into process management, signal handling, and terminal interaction components.

**Manual Fork/Exec Complexity:**
- Issue: The `Supervised` strategy uses manual `fork()` and requires strict adherence to async-signal-safety between `fork()` and `exec()`.
- Files: `crates/nono-cli/src/exec_strategy.rs`, `crates/nono/src/sandbox/linux.rs`
- Impact: Subtle bugs can lead to deadlocks (e.g., if a lock is held by another thread during fork) or memory corruption in the child.
- Fix approach: Move more preparation logic to the parent before fork. Use a dedicated `pre_exec` helper that is rigorously audited for signal safety.

**Platform-Specific Implementation Divergence:**
- Issue: Significant logic differences exist between Linux (Landlock), macOS (Sandbox.kext), and Windows (AppContainer/Job Objects).
- Files: `crates/nono/src/sandbox/`
- Impact: Features available on one platform may be missing or behave differently on others, leading to a fragmented user experience and complex documentation.
- Fix approach: Standardize the `Sandbox` trait and ensure capability mapping is as consistent as possible across platforms.

## Security Considerations

**Heavy Use of Unsafe Rust:**
- Risk: Memory safety vulnerabilities in the core security enforcement logic.
- Files: `crates/nono/src/sandbox/*.rs`, `crates/nono/src/supervisor/socket.rs`, `crates/nono/src/undo/object_store.rs`
- Current mitigation: Code reviews and localized `unsafe` blocks.
- Recommendations: Implement automated fuzzing for platform-specific sandbox entry points. Use higher-level wrappers where possible (e.g., `nix` crate more extensively).

**Supervisor IPC Surface:**
- Risk: Malicious or compromised child processes could attempt to escape the sandbox by exploiting the IPC channel used for FD passing or policy queries.
- Files: `crates/nono/src/supervisor/socket.rs`, `crates/nono-cli/src/exec_strategy.rs`
- Current mitigation: Use of Unix domain sockets and structured `SupervisorMessage` types.
- Recommendations: Implement strict protocol validation and consider using a formal schema for IPC messages. Ensure the supervisor runs with the minimum necessary privileges.

**Credential Proxying Risks:**
- Risk: Phantom tokens or real credentials could be leaked if the proxy is bypassed or if logging/debugging incorrectly captures sensitive headers.
- Files: `crates/nono-cli/src/profile/mod.rs`, `crates/nono-proxy/src/`
- Current mitigation: Proxy only injects credentials into specified headers/paths; `InjectMode` restricts where data goes.
- Recommendations: Add explicit "redaction" logic to all logging in the proxy. Ensure that the proxy process itself is heavily sandboxed.

## Performance Bottlenecks

**Syscall Interception Latency:**
- Problem: Using Landlock or Seccomp with supervisor interception adds a context switch and IPC round-trip for every restricted operation.
- Files: `crates/nono/src/sandbox/linux.rs`, `crates/nono-cli/src/exec_strategy.rs`
- Cause: Kernel-to-user-space transitions for policy decisions.
- Improvement path: Optimize the supervisor's event loop. Use Landlock's native enforcement for as much as possible to avoid user-space interception.

**Fixed-Size Tracking Buffers:**
- Problem: `MAX_DENIAL_RECORDS` (1000) and `MAX_TRACKED_REQUEST_IDS` (4096) are hard-capped.
- Files: `crates/nono-cli/src/exec_strategy.rs`
- Cause: Memory exhaustion prevention.
- Improvement path: Implement a circular buffer or LRU cache for these records, and make the limits configurable for high-throughput environments.

## Fragile Areas

**Thread Safety During Fork:**
- Files: `crates/nono-cli/src/exec_strategy.rs`
- Why fragile: The `ThreadingContext` check (e.g., `MAX_KEYRING_THREADS`) makes assumptions about background threads spawned by dependencies like `keyring` or `aws-lc-rs`.
- Safe modification: Changes to dependencies that spawn more threads could cause `nono` to refuse to run.
- Test coverage: Gaps in testing with various background thread configurations.

**Landlock/tmpfs Interaction (EBADFD):**
- Files: `tests/integration/test_system_paths.sh`, `crates/nono/src/sandbox/linux.rs`
- Why fragile: Landlock sometimes returns `EBADFD` when adding rules for `tmpfs` or in certain containerized environments (e.g., GitHub Actions).
- Safe modification: Be cautious when modifying path normalization logic for `/tmp`.
- Test coverage: Tests for `/tmp` are currently skipped on Linux in CI due to this issue.

## Known Limitations

**Windows Feature Parity:**
- Problem: `nono shell` and `nono wrap` are unavailable on Windows. Filesystem enforcement is less granular than Linux/macOS.
- Blocks: Users on Windows cannot get a persistent sandboxed shell or use the same wrapping patterns as Linux/macOS users.

**Landlock ABI Dependency:**
- Problem: Many security features (e.g., network filtering, signal scoping) require recent Landlock ABI versions (V4+ or V6+).
- Blocks: Users on older Linux kernels (e.g., LTS kernels before 6.x) will have significantly reduced security enforcement.

## Test Coverage Gaps

**Integration with Complex SDKs:**
- What's not tested: How the sandbox and proxy behave with complex, multi-threaded SDKs (e.g., AWS SDK, GCP SDK) that might have unusual network or thread patterns.
- Files: `crates/nono-proxy/src/`
- Risk: These SDKs might fail in unexpected ways within the sandbox.
- Priority: Medium

**Edge Case Filesystems:**
- What's not tested: Behavior on NFS, FUSE, or encrypted filesystems where Landlock or Sandbox.kext may have limited visibility or compatibility issues.
- Files: `crates/nono/src/sandbox/`
- Risk: Security bypasses or application crashes on non-standard filesystems.
- Priority: Medium

---

*Concerns audit: 2025-05-15*
