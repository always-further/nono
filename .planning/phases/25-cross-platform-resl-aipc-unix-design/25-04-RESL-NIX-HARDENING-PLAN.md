---
phase: 25-cross-platform-resl-aipc-unix-design
plan: 04
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/exec_strategy/supervisor_macos.rs
autonomous: true
gap_closure: true
addresses: [WR-03, WR-05]
requirements: [REQ-RESL-NIX-01, REQ-RESL-NIX-03]

must_haves:
  truths:
    - "CgroupSession::detect_from_str rejects cgroup-relative paths containing .. components with NonoError::UnsupportedPlatform"
    - "nix::errno::Errno-to-io::Error conversion in supervisor_macos.rs uses std::io::Error::from(e) not e as i32"
  artifacts:
    - path: "crates/nono-cli/src/exec_strategy/supervisor_linux.rs"
      provides: "Path traversal guard in detect_from_str; regression tests for .. injection"
      contains: "starts_with(\"/sys/fs/cgroup\")"
    - path: "crates/nono-cli/src/exec_strategy/supervisor_macos.rs"
      provides: "Idiomatic errno conversion in install_pre_exec; updated SAFETY doc comment"
      contains: "std::io::Error::from"
  key_links:
    - from: "CgroupSession::detect_from_str"
      to: "NonoError::UnsupportedPlatform"
      via: "abs_path.starts_with(\"/sys/fs/cgroup\") guard after PathBuf::join"
      pattern: "starts_with.*sys/fs/cgroup"
    - from: "MacosResourceLimits::install_pre_exec setrlimit calls"
      to: "std::io::Error"
      via: "map_err(std::io::Error::from) using nix's public From<Errno> impl"
      pattern: "map_err\\(std::io::Error::from\\)"
---

<objective>
Fix two code-review warnings, each in a separate platform supervisor module:

- **WR-03** (`supervisor_linux.rs`): `CgroupSession::detect_from_str` constructs the cgroup path from `/proc/self/cgroup` content without verifying the result stays under `/sys/fs/cgroup`. An attacker-controlled cgroup entry with `..` components could redirect path construction. Add `Path::starts_with("/sys/fs/cgroup")` validation after the join, and add unit regression tests.

- **WR-05** (`supervisor_macos.rs`): `map_err(|e| std::io::Error::from_raw_os_error(e as i32))` in `MacosResourceLimits::install_pre_exec` relies on `nix::errno::Errno` being `#[repr(i32)]`. Use the public `From<Errno> for std::io::Error` impl instead: `map_err(std::io::Error::from)`. Also update the SAFETY doc comment above `install_pre_exec` to reference the correct conversion.

Note: WR-02 (setrlimit fail-closed) and WR-04 (getpgid watchdog match) are handled in Plan 25-03 Task 3 and Task 4, which own all `exec_strategy.rs` edits. This plan touches only `supervisor_linux.rs` and `supervisor_macos.rs`.

Purpose: Harden the Linux cgroup path construction against traversal injection; use the stable, public nix errno conversion API in the macOS supervisor.

Output: Modified `supervisor_linux.rs` (traversal guard + regression tests) and `supervisor_macos.rs` (idiomatic errno conversion + updated doc comment).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/25-cross-platform-resl-aipc-unix-design/25-01-RESL-NIX-SUMMARY.md

<interfaces>
<!-- From supervisor_linux.rs: detect_from_str (lines 880–908) -->
```rust
pub(crate) fn detect_from_str(contents: &str) -> Result<PathBuf> {
    // ... validates 0:: prefix ...
    let abs_path = PathBuf::from("/sys/fs/cgroup")
        .join(cgroup_rel.trim_start_matches('/').trim_end_matches('/'));
    Ok(abs_path)   // <-- WR-03: no Path::starts_with check here
}
```

<!-- From supervisor_macos.rs: install_pre_exec (lines 97–129) -->
```rust
pub(crate) fn install_pre_exec(&self, cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    let memory_bytes = self.memory_bytes;
    let max_processes = self.max_processes;

    // SAFETY: pre_exec runs in the forked child, post-fork pre-exec.
    // setrlimit is async-signal-safe (POSIX). No heap allocation or locks
    // are taken inside the closure. All captured values are Copy.
    unsafe {
        cmd.pre_exec(move || -> std::io::Result<()> {
            #[cfg(target_os = "macos")]
            {
                use nix::sys::resource::{setrlimit, Resource};
                if let Some(bytes) = memory_bytes {
                    let limit = bytes.try_into().unwrap_or(nix::libc::rlim_t::MAX);
                    setrlimit(Resource::RLIMIT_AS, limit, limit)
                        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;  // WR-05
                }
                if let Some(n) = max_processes {
                    let limit = u64::from(n);
                    setrlimit(Resource::RLIMIT_NPROC, limit, limit)
                        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;  // WR-05
                }
            }
            Ok(())
        });
    }
}
```

<!-- SAFETY doc comment that also needs updating (line ~89–90 of supervisor_macos.rs): -->
```
/// The `nix::errno::Errno` → `std::io::Error` conversion uses
/// `std::io::Error::from_raw_os_error` which is also safe in `pre_exec`.
```
<!-- Replace with: -->
```
/// The `nix::errno::Errno` → `std::io::Error` conversion uses
/// `std::io::Error::from` (nix's public `From<Errno>` impl) which is
/// also safe in `pre_exec`.
```

<!-- NonoError variants available for use: -->
```rust
// From crates/nono/src/error.rs:
NotSupportedOnPlatform { feature: String },
UnsupportedPlatform(String),
SandboxInit(String),
```
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Add Path::starts_with guard in detect_from_str + regression tests (WR-03)</name>
  <files>crates/nono-cli/src/exec_strategy/supervisor_linux.rs</files>
  <read_first>
    - crates/nono-cli/src/exec_strategy/supervisor_linux.rs (lines 875–945: detect_from_str and detect, plus existing test module at line 638)
    - 25-REVIEW.md WR-03 section for the exact fix pattern required
    - CLAUDE.md §Path Handling for the mandate: "Always use path component comparison, not string operations. String starts_with() on paths is a vulnerability."
  </read_first>
  <behavior>
    - After fix: `detect_from_str("0::/../../etc")` returns `Err(NonoError::UnsupportedPlatform(...))` with message containing "path traversal"
    - After fix: `detect_from_str("0::/user.slice/session-1.scope")` still returns `Ok(PathBuf)` with path `/sys/fs/cgroup/user.slice/session-1.scope` (normal case unaffected)
    - After fix: a unit test `cgroup_path_rejects_parent_dir_traversal` exists in the `#[cfg(test)] mod tests` block and calls `CgroupSession::detect_from_str` with a malicious input
    - After fix: a unit test `cgroup_path_accepts_normal_path` exists to confirm normal operation
  </behavior>
  <action>
    **Step 1 — Add the guard in detect_from_str:**

    After the `let abs_path = PathBuf::from("/sys/fs/cgroup").join(...)` line (currently the last line before `Ok(abs_path)`), add:

    ```rust
    // WR-03: Validate the constructed path stays within /sys/fs/cgroup.
    // Path::starts_with performs component-level comparison, so
    // "/sys/fs/cgroupevil" does NOT match — only proper children do.
    // A malicious /proc/self/cgroup entry with ".." components (e.g.,
    // "0::/../../etc") would produce an abs_path that escapes the cgroup root.
    if !abs_path.starts_with("/sys/fs/cgroup") {
        return Err(NonoError::UnsupportedPlatform(format!(
            "cgroup_v2: constructed cgroup path {abs_path:?} escapes /sys/fs/cgroup \
             (path traversal detected in /proc/self/cgroup content)"
        )));
    }
    ```

    The final `detect_from_str` body (after the fix) should end with:
    ```rust
    if !abs_path.starts_with("/sys/fs/cgroup") {
        return Err(NonoError::UnsupportedPlatform(format!(
            "cgroup_v2: constructed cgroup path {abs_path:?} escapes /sys/fs/cgroup \
             (path traversal detected in /proc/self/cgroup content)"
        )));
    }
    Ok(abs_path)
    ```

    **Step 2 — Add regression tests in the existing #[cfg(test)] mod tests block:**

    Append to the existing `tests` module at the bottom of the file:

    ```rust
    #[test]
    fn cgroup_path_rejects_parent_dir_traversal() {
        // Attacker-controlled /proc/self/cgroup with .. to escape /sys/fs/cgroup
        let err = CgroupSession::detect_from_str("0::/../../etc")
            .expect_err("must reject path traversal");
        match err {
            NonoError::UnsupportedPlatform(msg) => {
                assert!(
                    msg.contains("path traversal") || msg.contains("escapes"),
                    "error message must mention traversal, got: {msg}"
                );
            }
            other => panic!("expected UnsupportedPlatform, got: {other:?}"),
        }
    }

    #[test]
    fn cgroup_path_rejects_encoded_traversal() {
        // Variant: leading .. after trim_start_matches strips the slash
        let err = CgroupSession::detect_from_str("0::/../../../proc/self")
            .expect_err("must reject path traversal with leading slash");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
    }

    #[test]
    fn cgroup_path_accepts_normal_path() {
        // Normal systemd-delegated cgroup path must still work
        let result = CgroupSession::detect_from_str("0::/user.slice/user-1000.slice/session-1.scope");
        // We cannot verify the path exists on this host, but construction must succeed
        // (detect_from_str does NOT check fs existence — that is detect()'s job).
        // Confirm the returned path starts with /sys/fs/cgroup.
        let path = result.expect("normal cgroup path must be accepted");
        assert!(
            path.starts_with("/sys/fs/cgroup"),
            "path must be under /sys/fs/cgroup, got: {path:?}"
        );
    }
    ```

    Note: the test module already has `#[allow(clippy::unwrap_used)]` per the existing tests pattern — do NOT add `#[allow(dead_code)]`. The tests use `expect_err` / `expect` which are allowed in tests (CLAUDE.md: "permitted in test modules").

    The `CgroupSession::detect_from_str` function is `pub(crate)`, so the in-module `use super::*` in the test module already brings it into scope.
  </action>
  <verify>
    <automated>
      grep -n "starts_with.*sys/fs/cgroup" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
      grep -n "cgroup_path_rejects_parent_dir_traversal\|cgroup_path_accepts_normal_path\|cgroup_path_rejects_encoded" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
      cargo test --package nono-cli cgroup_path_rejects_parent_dir_traversal 2>&1 | tail -10
      cargo test --package nono-cli cgroup_path_accepts_normal_path 2>&1 | tail -10
      cargo test --package nono-cli cgroup_path_rejects_encoded_traversal 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "starts_with.*sys/fs/cgroup" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns at least 1 (the new guard in detect_from_str) — note: this uses Path::starts_with called on a PathBuf, so the literal in source is `.starts_with("/sys/fs/cgroup")`.
    2. `grep -c "cgroup_path_rejects_parent_dir_traversal" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 1.
    3. `grep -c "cgroup_path_accepts_normal_path" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 1.
    4. `cargo test --package nono-cli cgroup_path_rejects_parent_dir_traversal` exits 0 (test passes).
    5. `cargo test --package nono-cli cgroup_path_accepts_normal_path` exits 0 (test passes).
    6. `cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used` exits 0.
  </acceptance_criteria>
  <done>detect_from_str rejects paths with .. traversal via Path::starts_with guard. Three regression tests pass. Clippy clean.</done>
</task>

<task type="auto">
  <name>Task 2: Use idiomatic From&lt;Errno&gt; conversion in install_pre_exec + update SAFETY doc (WR-05)</name>
  <files>crates/nono-cli/src/exec_strategy/supervisor_macos.rs</files>
  <read_first>
    - crates/nono-cli/src/exec_strategy/supervisor_macos.rs (lines 85–129: SAFETY doc comment and install_pre_exec body)
    - 25-REVIEW.md WR-05 section for the exact fix pattern required
  </read_first>
  <action>
    Apply two targeted changes to `supervisor_macos.rs` only. Do NOT touch `exec_strategy.rs` — WR-02 and WR-04 edits to that file are owned by Plan 25-03.

    ---

    **Fix 1 — Update SAFETY doc comment (line ~89–90):**

    Change the sentence:
    ```
    /// The `nix::errno::Errno` → `std::io::Error` conversion uses
    /// `std::io::Error::from_raw_os_error` which is also safe in `pre_exec`.
    ```
    to:
    ```
    /// The `nix::errno::Errno` → `std::io::Error` conversion uses
    /// `std::io::Error::from` (nix's public `From<Errno>` impl) which is
    /// also safe in `pre_exec`.
    ```

    ---

    **Fix 2 — Replace both map_err calls in install_pre_exec:**

    In `MacosResourceLimits::install_pre_exec`, replace BOTH occurrences of:
    ```rust
    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    ```
    with:
    ```rust
    .map_err(std::io::Error::from)?;
    ```

    Apply to BOTH the `RLIMIT_AS` call (line ~114) and the `RLIMIT_NPROC` call (line ~119).

    This uses `nix`'s public `From<Errno> for std::io::Error` impl instead of casting the internal `#[repr(i32)]` representation. If nix ever changes the repr or the cast semantics, the public API remains stable.

    No other changes to this file.
  </action>
  <verify>
    <automated>
      grep -n "from_raw_os_error" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
      grep -n "map_err(std::io::Error::from)" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
      grep -n "From<Errno>" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
      cargo build --package nono-cli 2>&1 | tail -10
      cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used 2>&1 | tail -10
      cargo fmt --check --all 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "from_raw_os_error" crates/nono-cli/src/exec_strategy/supervisor_macos.rs` returns 0 (both occurrences removed).
    2. `grep -c "map_err(std::io::Error::from)" crates/nono-cli/src/exec_strategy/supervisor_macos.rs` returns 2 (one per setrlimit call in install_pre_exec).
    3. `grep -c 'From<Errno> for std::io::Error' crates/nono-cli/src/exec_strategy/supervisor_macos.rs` returns >= 1 (the updated SAFETY doc comment mentions this conversion).
    4. `cargo build --package nono-cli` exits 0.
    5. `cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used` exits 0.
    6. `cargo fmt --check --all` exits 0.
  </acceptance_criteria>
  <done>Both from_raw_os_error casts replaced with idiomatic map_err(std::io::Error::from). SAFETY doc comment updated to reference From<Errno>. Build, clippy, fmt pass.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| /proc/self/cgroup content → PathBuf construction | Kernel-provided but potentially attacker-influenced in container escape scenarios |
| nix Errno internal repr → io::Error | Casting internal repr risks silent breakage on nix ABI changes |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-25-04-01 | Elevation of Privilege | CgroupSession::detect_from_str path construction | mitigate | WR-03: Add `abs_path.starts_with("/sys/fs/cgroup")` using Path component comparison (not string starts_with), return Err on mismatch |
| T-25-04-02 | Tampering | nix Errno internal repr change | mitigate | WR-05: Use public From<Errno> for io::Error impl instead of `e as i32` cast; eliminates silent breakage if nix changes repr |
</threat_model>

<verification>
After both tasks:

```bash
# WR-03: traversal guard present
grep -n "starts_with.*sys/fs/cgroup" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: at least 1 line in detect_from_str

# WR-03: regression tests present
grep -n "cgroup_path_rejects_parent_dir_traversal\|cgroup_path_accepts_normal_path\|cgroup_path_rejects_encoded" \
  crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: 3 lines (one per test function name)

# WR-05: idiomatic errno conversion
grep -c "from_raw_os_error" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
# Expected: 0

# WR-05: replacement present
grep -c "map_err(std::io::Error::from)" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
# Expected: 2

# WR-05: SAFETY doc comment updated
grep -c 'From<Errno> for std::io::Error' crates/nono-cli/src/exec_strategy/supervisor_macos.rs
# Expected: >= 1

# Full build + lint + tests
cargo test --package nono-cli cgroup_path_rejects_parent_dir_traversal
cargo test --package nono-cli cgroup_path_accepts_normal_path
cargo test --package nono-cli cgroup_path_rejects_encoded_traversal
cargo build --workspace
cargo clippy --workspace -- -D warnings -D clippy::unwrap_used
cargo fmt --check --all
```
</verification>

<success_criteria>
- `grep -c "starts_with.*sys/fs/cgroup" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` >= 1
- `grep -c "from_raw_os_error" crates/nono-cli/src/exec_strategy/supervisor_macos.rs` == 0
- `grep -c "map_err(std::io::Error::from)" crates/nono-cli/src/exec_strategy/supervisor_macos.rs` == 2
- `grep -c 'From<Errno> for std::io::Error' crates/nono-cli/src/exec_strategy/supervisor_macos.rs` >= 1
- Three new cgroup_path_* unit tests pass under `cargo test --package nono-cli`
- `cargo build --workspace` exits 0
- `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0
- `cargo fmt --check --all` exits 0
</success_criteria>

<output>
After completion, create `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-04-RESL-NIX-HARDENING-SUMMARY.md`
</output>
