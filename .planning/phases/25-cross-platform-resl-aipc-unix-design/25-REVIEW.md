---
phase: 25-cross-platform-resl-aipc-unix-design
reviewed: 2026-05-10T00:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/exec_strategy/supervisor_macos.rs
  - crates/nono-cli/tests/resl_nix_async_signal_safety.rs
findings:
  critical: 0
  warning: 1
  info: 3
  total: 4
  resolved:
    - id: CR-A
      resolved_in: ebbd6257
      summary: "Removed orphan `use std::sync::{atomic::AtomicBool, Arc};` at exec_strategy.rs:801 left behind by WR-C cleanup. Linux CI now passes -D warnings."
status: issues_found
---

# Phase 25 Re-Review After Gap-Closure (Plans 25-05 + 25-06)

**Reviewed:** 2026-05-10
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found
**Diff base:** `ef405bd6`

## Summary

This re-review covers the gap-closure cycle from plans 25-05 (CR-01-RESIDUAL)
and 25-06 (WR-A through WR-D) against the prior gap-closure REVIEW
(`25-REVIEW-GAPS.md`). All five prior findings have been technically addressed
at the called-out sites:

| Prior        | Site                                                  | Closure verified |
|--------------|-------------------------------------------------------|------------------|
| CR-01-RESIDUAL | `clear_close_on_exec` errors via `format!()`        | Replaced with `std::io::Error::last_os_error()`; signature now `std::io::Result<()>` (exec_strategy.rs:2767-2785). Per-helper static-analysis assertion added (resl_nix_async_signal_safety.rs:188-222). |
| WR-A         | First-match scoping of child arm in test              | Replaced with sentinel-based search (`CR-01-CHILD-ARM-START` / `END` at exec_strategy.rs:842, 1201; test scoping at resl_nix_async_signal_safety.rs:56-87). |
| WR-B         | Brace-counting ignored string literals/block comments | Sentinel slicing replaces brace counting in the broad child-arm scan; brace counting is retained only inside `slice_function_body` for a small named helper (rationale documented in tests/resl_nix_async_signal_safety.rs:112-116). |
| WR-C         | `timeout_fired: AtomicBool` dead atomic               | All references removed from supervisor_macos.rs; the misleading "Sets timeout_fired to true" doc comments are replaced with accurate "Sends SIGKILL to the entire process group" wording (supervisor_macos.rs:140-181, exec_strategy.rs:105-113). |
| WR-D         | `CgroupSession::disarm()` + `armed` field dead code   | Both removed; `Drop` now unconditionally cleans up (supervisor_linux.rs:1240-1264). |

**However, the WR-C cleanup left a CI-blocking dead `use` statement.**

The dead-imports `use std::sync::{atomic::AtomicBool, Arc};` was originally
introduced inside the Linux-only block at `exec_strategy.rs:800` to support
the `Arc<AtomicBool>` watchdog flag. After WR-C removed all references to
`AtomicBool` and `Arc` in this scope, the `use` statement was not removed.
Under the project's `cargo clippy -D warnings` policy (CLAUDE.md § Coding
Standards), this triggers `unused_imports` and FAILS the Linux CI build. The
defect is invisible on Windows (the `#[cfg(target_os = "linux")]` gate
suppresses compilation), so a Windows-only `cargo check` does not surface it.

One additional minor issue: the strengthened CR-01-RESIDUAL test references
"line 950 call site" in its panic message (resl_nix_async_signal_safety.rs:211)
but the actual call site is at exec_strategy.rs:955. Documentation drift only.

The WR-A / WR-B sentinel approach is a good improvement and correctly closes
the test-fragility concern. The CR-01-RESIDUAL fix is correct: `Error::last_os_error()`
captures errno into a stack-resident `io::Error::Repr::OsError(i32)` without
allocating, satisfying the async-signal-safety requirement on the post-fork
child error path.

---

## Critical Issues

### CR-A: Unused `use std::sync::{atomic::AtomicBool, Arc};` in Linux-gated block fails CI under `-D warnings`

**File:** `crates/nono-cli/src/exec_strategy.rs:801`

**Issue:** The block at lines 799-811 imports `AtomicBool` and `Arc` from
`std::sync` but never uses either. After WR-C removed `timeout_fired: Arc<AtomicBool>`
from this location, the `use` statement was orphaned:

```rust
#[cfg(target_os = "linux")]
let (unix_resource_guard, linux_cgroup_procs_path_nul) = {
    use std::sync::{atomic::AtomicBool, Arc};   // <-- nothing in this block uses AtomicBool or Arc
    if resource_limits.is_empty() {
        (None::<supervisor_linux::cgroup::CgroupSession>, Vec::new())
    } else {
        let session =
            supervisor_linux::cgroup::CgroupSession::new(resource_session_id, resource_limits)?;
        session.apply_limits()?;
        let procs_nul = session.procs_path_nul();
        (Some(session), procs_nul)
    }
};
```

A grep confirms `Arc` and `AtomicBool` appear nowhere inside the block body
(the only `Arc` reference in this function is the fully-qualified
`std::sync::Arc<std::sync::Mutex<...>>` in the function signature at line 547,
which does not depend on this import). Under `-D warnings` (CLAUDE.md §
Coding Standards: `clippy: -D warnings -D clippy::unwrap_used`), the Rust
compiler emits `warning: unused imports: AtomicBool, Arc` and the build
fails on Linux targets.

This is invisible to Windows-only `cargo check` because the entire block is
behind `#[cfg(target_os = "linux")]` — exactly the surface the WR-C cleanup
modified. The defect is the cleanup's own residue.

**Fix:** Remove the orphaned `use` statement entirely:

```rust
#[cfg(target_os = "linux")]
let (unix_resource_guard, linux_cgroup_procs_path_nul) = {
    if resource_limits.is_empty() {
        (None::<supervisor_linux::cgroup::CgroupSession>, Vec::new())
    } else {
        let session =
            supervisor_linux::cgroup::CgroupSession::new(resource_session_id, resource_limits)?;
        session.apply_limits()?;
        let procs_nul = session.procs_path_nul();
        (Some(session), procs_nul)
    }
};
```

Add a Linux build to the gap-closure CI matrix (or run `cargo clippy --target
x86_64-unknown-linux-gnu -p nono-cli --all-targets -- -D warnings` locally)
before declaring 25-06 verified. If a Linux runner is unavailable, at minimum
run `cargo clippy --target x86_64-unknown-linux-gnu -p nono-cli` against a
hosted Linux toolchain via CI before merging.

---

## Warnings

### WR-A-RESIDUAL: Comment drift in CR-01-RESIDUAL helper assertion (line-number stale)

**File:** `crates/nono-cli/tests/resl_nix_async_signal_safety.rs:211`

**Issue:** The strengthened CR-01-RESIDUAL test panic message reads:

```rust
"... This helper is called \
 from the post-fork child arm of execute_supervised (line 950 call site), \
 so any heap allocation here re-opens the allocator-mutex-deadlock \
 primitive that CR-01 was supposed to eliminate.\n\
```

The actual call site to `clear_close_on_exec(fd)` in
`crates/nono-cli/src/exec_strategy.rs` is at line 955 (the `if let Err(_e) =
clear_close_on_exec(fd) {` arm). Line 950 is now a comment line. Similar
drift exists in a code comment at lines 188-191 of the test file.

This is documentation only — the test correctness is unaffected because the
search anchors on the function signature string, not the line number. But
the message will mislead future maintainers debugging a regression to the
wrong line. It also reflects a broader risk: hard-coded line numbers in
panic messages and code comments tend to drift silently every time the
production file changes.

**Fix:** Either drop the line number entirely from the panic message ("This
helper is called from the post-fork child arm of execute_supervised, so
any heap allocation here ...") or compute it dynamically by searching for
the `clear_close_on_exec(` call site in `src` and reporting the matching
line. Repeat for the line-comment at test line 189-191.

---

## Info

### IN-A: `place_self_in_cgroup_raw` reads errno after `close()` may have clobbered it (re-flagged)

**File:** `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:1194-1202`

**Issue:** This was IN-A in the prior gap-closure REVIEW and remains
unaddressed. The pattern:

```rust
let written = libc::write(fd, ...);
libc::close(fd);          // <-- POSIX permits close() to set errno
if written < 0 {
    return Err(std::io::Error::last_os_error());  // <-- reads errno AFTER close
}
```

If `write()` returns -1 setting errno to (say) `EPERM`, and the subsequent
`close()` modifies errno (e.g. sets `EBADF` on a redundant close), then
`last_os_error()` reports the close errno. The actual write failure is lost.

In the production child caller (exec_strategy.rs:881-898) the diagnostic is
discarded anyway (only the static `MSG_CGROUP` byte string is written to
stderr), so the user-visible impact is nil. But the io::Error returned to a
hypothetical non-child caller would be wrong.

The gap-closure plans 25-05 and 25-06 do not mention this finding — it
was intentionally deferred. Re-flagging here for tracking.

**Fix:** Capture errno before `close()`:

```rust
let written = libc::write(fd, ...);
let write_err = if written < 0 { Some(std::io::Error::last_os_error()) } else { None };
libc::close(fd);
if let Some(e) = write_err {
    return Err(e);
}
```

---

### IN-B: `cr_01_and_wr_02_const_msg_byte_strings_present` lower-bound is loose (re-flagged)

**File:** `crates/nono-cli/tests/resl_nix_async_signal_safety.rs:230-255`

**Issue:** Same as IN-B in the prior gap-closure REVIEW: the test asserts
`count >= 11`, so a future commit can remove one specific named const (e.g.
`MSG_CGROUP`) and the assertion still passes if the total count stays at
or above 11. The plan summary lists 11 named constants explicitly, so
per-name presence checks would be tighter.

Not addressed by 25-05 or 25-06. Re-flagging for tracking.

**Fix:** Either tighten the test to enforce per-name presence (loop over
the list of 11 names asserting each appears) or accept the loose count and
add an inline comment documenting the tradeoff.

---

### IN-C: `MacosResourceLimits::install_pre_exec` non-macOS branch is dead-compiled

**File:** `crates/nono-cli/src/exec_strategy/supervisor_macos.rs:130-133`

**Issue:** The closure inside `install_pre_exec` contains:

```rust
#[cfg(target_os = "macos")]
{
    use nix::sys::resource::{setrlimit, Resource};
    if let Some(bytes) = memory_bytes { ... }
    if let Some(n) = max_processes { ... }
}
#[cfg(not(target_os = "macos"))]
{
    let _ = (memory_bytes, max_processes);
}
```

But the entire `supervisor_macos` module is gated `#[cfg(target_os = "macos")]
mod supervisor_macos;` at exec_strategy.rs:16-17. The `#[cfg(not(target_os =
"macos"))]` arm is therefore unreachable at compile time. It is harmless
(the branch is silently dropped during macros expansion) but indicates
copy-pasted scaffolding that has no purpose.

This is purely a code-cleanliness item; no functional defect. Not introduced
by the gap closure.

**Fix:** Remove the `#[cfg(not(target_os = "macos"))]` arm entirely. The
outer module gate already guarantees we are on macOS.

---

_Reviewed: 2026-05-10_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Diff base: `ef405bd6`_
