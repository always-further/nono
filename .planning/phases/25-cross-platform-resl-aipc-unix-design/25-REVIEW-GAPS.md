---
phase: 25-cross-platform-resl-aipc-unix-design
review_type: gap-closure
reviewed: 2026-05-10T00:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/exec_strategy/supervisor_macos.rs
  - crates/nono-cli/tests/resl_nix_async_signal_safety.rs
findings:
  critical: 1
  warning: 4
  info: 3
  total: 8
status: issues_found
---

# Phase 25 Gap-Closure Code Review

**Reviewed:** 2026-05-10
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found
**Diff base:** `9b780c1191df6bc358e9a6fc24630afa86f1c6ac`

## Summary

This review covers the gap-closure work in Plans 25-03 and 25-04 that addressed
six findings from the original 25-REVIEW (CR-01, CR-02, WR-02, WR-03, WR-04,
WR-05). All six original findings have technically been fixed at the sites
called out in the original review:

| Original | Site                                | Fix verified |
|----------|-------------------------------------|--------------|
| CR-01    | 9 `format!()` calls in child branch | Replaced with `const MSG_*: &[u8]` (lines 882-1147) |
| CR-02    | `--timeout` ignored in Direct mode  | `warn!()` + `eprintln!()` at lines 462-470 |
| WR-02    | macOS `let _ = setrlimit(...)`      | Fail-closed `_exit(126)` at lines 910, 929 |
| WR-03    | cgroup path traversal               | `Path::starts_with` + `Component::ParentDir` scan at lines 928-937 |
| WR-04    | `getpgid().unwrap_or(child)`        | Safe `match` at lines 1353-1369 |
| WR-05    | `Errno as i32` cast                 | `std::io::Error::from` at lines 122, 127 |

**However, the CR-01 fix is incomplete.** A function called from inside the
post-fork child branch (`clear_close_on_exec`) still uses `format!()` on its
error path. The static-analysis test (`cr_01_no_format_macro_in_post_fork_child_branch`)
only inspects the lexical region of the `Ok(ForkResult::Child) => {` arm and
does not recursively scan called functions, so the test reports green while the
underlying defect remains exploitable. This re-opens the original CR-01
allocator-deadlock risk along the fcntl-failure code path.

Three warnings about pattern consistency, test scoping, and an `#[allow(dead_code)]`
that violates CLAUDE.md project rules. Three info items on minor code-quality
and documentation issues.

The WR-03 traversal-guard is a notable strengthening over the plan's literal
text — combining `Path::starts_with` with `Component::ParentDir` correctly
defeats `0::/../../etc` payloads that bare `Path::starts_with` would let
through. This is documented inline and in 25-04-SUMMARY § "Auto-fixed Issues".

---

## Critical Issues

### CR-01-RESIDUAL: `clear_close_on_exec()` still calls `format!()` from the post-fork child branch

**File:** `crates/nono-cli/src/exec_strategy.rs:949-964` (call site) and
`crates/nono-cli/src/exec_strategy.rs:2759-2773` (callee)

**Issue:** The CR-01 fix replaced `format!()` calls *that appear textually
inside the lexical child branch* with `const MSG_*: &[u8]` static byte strings.
However, the child branch at line 949 calls `clear_close_on_exec(fd)`, and the
implementation of `clear_close_on_exec` (line 2759) builds its error variant
via `format!()`:

```rust
fn clear_close_on_exec(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(NonoError::SandboxInit(format!(
            "fcntl(F_GETFD) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    ...
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) };
    if result < 0 {
        return Err(NonoError::SandboxInit(format!(
            "fcntl(F_SETFD) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    ...
}
```

When `fcntl(F_GETFD)` or `fcntl(F_SETFD)` returns `< 0` in the post-fork child,
the `Err` branch builds a `String` via `format!()` *before* the child's calling
code reaches the static `MSG_SOCK` write at line 952. This is exactly the
allocator-mutex-deadlock primitive that CR-01 was supposed to remove from the
child branch.

The static-analysis test
`cr_01_no_format_macro_in_post_fork_child_branch` only scans the *lexical*
region of `Ok(ForkResult::Child) => {` — it does not analyze called functions.
The test reports GREEN while the defect is reachable. From a security-review
perspective this is worse than the original CR-01: it now passes a regression
test without fixing the underlying issue.

The same architectural concern applies to other functions called from the
child branch (`Sandbox::apply()`, `nono::sandbox::install_seccomp_notify()`,
`nono::supervisor::socket::send_fd_via_socket()`, `nono::sandbox::install_seccomp_proxy_filter()`,
`nix::sys::prctl::set_dumpable()`). The summary doc (25-03) explicitly accepts
`Sandbox::apply()` allocations on the basis of pre-fork threading-context
validation, but if that argument is sound then CR-01 itself wasn't a blocker
at all — and the `format!()` calls inside `clear_close_on_exec` are equally
defensible. The current state is **internally inconsistent**: the team accepted
the allocator-safe-by-threading-validation argument for `Sandbox::apply()` but
rejected it for the original 9 `format!()` sites. Either the threading argument
holds (and the original CR-01 was over-stated) or it does not (and many more
sites need fixing). Pick one.

**Fix:** Either:

(a) **Audit + harden every function called from the child branch** to ensure no
heap allocation on any path. Replace the `format!()` calls in `clear_close_on_exec`
with a `Result<()>` carrying a non-allocating error variant (e.g.
`std::io::Error::from_raw_os_error(errno)` which stores the errno inline). Apply
the same audit to `Sandbox::apply` and the seccomp helpers. This is the
strict reading of CR-01.

(b) **Document the formal threading-context contract** as the security
boundary, retract CR-01's "zero allocation" goal, and note that the static
`MSG_*` byte strings exist only to avoid losing diagnostic visibility under a
hypothetical allocator-deadlock case. Update 25-03-SUMMARY accordingly. This
is the pragmatic reading.

The bare minimum to close this finding without choosing (a) or (b): convert
`clear_close_on_exec` to return a non-allocating error type (e.g. raw
`io::Error::from_raw_os_error(libc::__errno_location())`), since this is the
one function that is reachable from the child error path *outside* the
documented "Sandbox::apply allocates by design" exception.

```rust
// Non-allocating variant suitable for post-fork child use:
fn clear_close_on_exec(fd: i32) -> std::io::Result<()> {
    // SAFETY: fcntl is async-signal-safe.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let new_flags = flags & !libc::FD_CLOEXEC;
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
```

`std::io::Error::last_os_error()` does not allocate (it captures the errno
into a stack-resident `io::Error` whose `Repr` for raw OS errors is inline).

Strengthen the regression test to also reject `format!(` and any heap-allocating
construct in the call graph reachable from the child arm — or at minimum, in
the body of `clear_close_on_exec`.

---

## Warnings

### WR-A: Static-analysis test does not cover the test-helper child branches in the same file

**File:** `crates/nono-cli/tests/resl_nix_async_signal_safety.rs:47-79`

**Issue:** The helper `find_child_branch_lines` uses `src.find(marker)` which
returns the **first** occurrence of `Ok(ForkResult::Child) => {`. The
production child branch is at line 844 (the first match), so the test
correctly inspects the right region. However, `exec_strategy.rs` contains
**three** `Ok(ForkResult::Child) => {` arms — the production one at 844 and
two test-helper forks at 3551 and 3647. If a future refactor reorders these,
or if a new child branch is added before line 844, the static-analysis tests
silently start checking the wrong code.

This is a fragile assumption. The two test-helper child branches at
`exec_strategy.rs:3551` and `:3647` happen to only call `drop()` and `_exit()`
today, but no automated check enforces that.

**Fix:** Either (a) anchor the marker search on a more specific lexical
context — e.g. require the marker to be inside `pub fn execute_supervised`, or
(b) iterate over all matches and assert the property for each. Option (b) is
preferable because it catches new child branches automatically:

```rust
// Find ALL Ok(ForkResult::Child) => { arms and check each.
let mut start = 0;
while let Some(pos) = src[start..].find("Ok(ForkResult::Child) => {") {
    let abs_pos = start + pos;
    let (s, e) = find_child_branch_from(&src, abs_pos);
    let region = slice_lines(&src, s, e);
    // Check region contains zero format!(...) and at least N const MSG_* declarations.
    ...
    start = e;
}
```

---

### WR-B: Brace-counting in `find_child_branch_lines` ignores string literals, char literals, and block comments

**File:** `crates/nono-cli/tests/resl_nix_async_signal_safety.rs:55-70`

**Issue:** The brace counter at lines 55-70 walks the source byte-by-byte
counting `{` and `}` without tracking lexical context (string literals, char
literals, raw-string literals like `r#"..."#`, `b"..."`, `/* ... */` block
comments). If any future code in the child branch contains a `{` or `}`
inside a string or block comment, the counter terminates early or late,
returning the wrong end-line. The body of `cr_01_no_format_macro_...` then
scans the wrong region.

This is hypothetical today — I verified that lines 844-1196 contain no
braces inside string literals or block comments — but the test is one
careless string-literal addition away from silently checking nothing or the
wrong thing.

**Fix:** Either:
- Use a structural Rust source parser (e.g. `syn`) to scope by `match` arm
  rather than by raw brace counting. This is heavier but correct.
- Or annotate the production child arm with a sentinel comment
  (`// CR-01-CHILD-ARM-START` / `// CR-01-CHILD-ARM-END`) and have the test
  scope by string search for those sentinels. Cheap, robust, and the sentinel
  comment doubles as documentation for future maintainers.

---

### WR-C: `timeout_fired` AtomicBool is set by the watchdog but never read

**File:** `crates/nono-cli/src/exec_strategy.rs:833, 1336, 1355` and
`crates/nono-cli/src/exec_strategy/supervisor_macos.rs:179`

**Issue:** Both watchdogs (`spawn_linux_timeout_watchdog` at line 124 and
`spawn_macos_timeout_watchdog` at line 179) store `true` to the `timeout_fired`
flag immediately before delivering the kill. The doc comments at lines 108-109
and supervisor_macos.rs:152-153 claim the parent's wait loop reads this to
populate `timeout_kill: true` in inspect data:

> "Sets timeout_fired to true before writing so the parent's wait loop can
> record timeout_kill: true in inspect data."

However, a project-wide grep for `timeout_fired` and `timeout_kill` shows the
flag is never `.load()`'d anywhere. The "inspect data" plumbing is missing,
and the user has no way to distinguish "child exited normally just before the
deadline" from "watchdog SIGKILL'd the child". This degrades the user-visible
diagnostic for the WR-04 scenario where `getpgid` failure causes the watchdog
to be silently skipped — the user is told nothing because `timeout_fired`
stays `false`.

This is not introduced by the gap closure (it predates 25-03 and 25-04) but
the WR-04 fix relies on the watchdog signaling timeout via a side channel
that does not exist.

**Fix:** Either (a) wire `timeout_fired.load()` into the post-wait reporting
path and surface "timeout enforcement fired" in the supervisor footer, or
(b) remove the misleading doc comments and the `AtomicBool` if no consumer
plans to be added soon. Option (a) closes a UX hole around WR-04.

---

### WR-D: `#[allow(dead_code)]` on `CgroupSession::disarm` violates CLAUDE.md "no dead code"

**File:** `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:1049-1052`

**Issue:**
```rust
/// Disarm the drop cleanup. After calling this, `Drop` will NOT remove the
/// cgroup directory. Use only when cleanup responsibility has been transferred.
#[allow(dead_code)]
pub(crate) fn disarm(&mut self) {
    self.armed = false;
}
```

CLAUDE.md § "Lazy use of dead code" explicitly forbids `#[allow(dead_code)]`:
> "Avoid `#[allow(dead_code)]`. If code is unused, either remove it or write
> tests that use it."

`disarm()` is unreferenced anywhere in the workspace. It either needs (a) a
caller that uses it, (b) a unit test that exercises it, or (c) deletion.

This is a project-rule violation, not introduced by the gap closure (`disarm`
predates Plan 25-03), but the gap-closure work modified this same file and
is the natural opportunity to address it.

**Fix:** Delete the `disarm` method (and the `armed` field if `armed` is only
ever set to `true` at construction). If the method is intended for a future
cleanup-transfer pattern, write a test that exercises the
"armed=false → Drop is no-op" branch.

---

## Info

### IN-A: `place_self_in_cgroup_raw` reads errno after `close()` may have clobbered it

**File:** `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:1204-1212`

**Issue:**
```rust
let written = libc::write(fd, ...);
libc::close(fd);
if written < 0 {
    return Err(std::io::Error::last_os_error());
}
```

If `write()` returns `-1` and sets errno, but the subsequent `close()`
modifies errno (POSIX permits this), then `last_os_error()` reports the close
errno, not the write errno. This is a minor diagnostic bug — the resulting
`io::Error` may report `EBADF` (from a redundant close) instead of the real
write failure (e.g. `EPERM`, `EBUSY`).

The caller in the post-fork child only checks `is_err()` and writes the
static `MSG_CGROUP` byte string anyway, so the diagnostic is dropped. But if
the function gains a non-child caller in the future, the wrong errno is
reported.

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

### IN-B: `cr_01_and_wr_02_const_msg_byte_strings_present` lower-bound is loose

**File:** `crates/nono-cli/tests/resl_nix_async_signal_safety.rs:147`

**Issue:** The test asserts `count >= 11`. If a future commit removes one of
the `const MSG_*` declarations (e.g. by collapsing two error sites that
share a now-identical message), the test still passes as long as 11 remain
elsewhere in the file. The test does not enforce that *each named const* in
the failure-message list still exists.

The plan summary's table at 25-03-SUMMARY lines 130-138 lists the 9 + 2 = 11
specific names: `MSG_CGROUP`, `MSG_SOCK`, `MSG_SANDBOX_LINUX`,
`MSG_SANDBOX_OTHER`, `MSG_SECCOMP_SEND`, `MSG_SECCOMP_FAIL`, `MSG_PROXY_SEND`,
`MSG_PROXY_FAIL`, `MSG_DUMPABLE`, `MSG_RLIMIT_AS_FAIL`, `MSG_RLIMIT_NPROC_FAIL`.

**Fix:** Either tighten the test to enforce per-name presence:

```rust
for name in [
    "MSG_CGROUP", "MSG_SOCK", "MSG_SANDBOX_LINUX", "MSG_SANDBOX_OTHER",
    "MSG_SECCOMP_SEND", "MSG_SECCOMP_FAIL", "MSG_PROXY_SEND", "MSG_PROXY_FAIL",
    "MSG_DUMPABLE", "MSG_RLIMIT_AS_FAIL", "MSG_RLIMIT_NPROC_FAIL",
] {
    assert!(src.contains(&format!("const {name}: &[u8]")), "missing {name}");
}
```

Or accept that the loose count is sufficient and document the tradeoff
(a single removal won't be detected; a wholesale removal will).

---

### IN-C: WR-03 fix message says "path traversal detected in /proc/self/cgroup content" without surfacing the suspect substring

**File:** `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:933-936`

**Issue:** The error path includes the full constructed `abs_path` via
`{abs_path:?}`:

```rust
return Err(NonoError::UnsupportedPlatform(format!(
    "cgroup_v2: constructed cgroup path {abs_path:?} escapes /sys/fs/cgroup \
     (path traversal detected in /proc/self/cgroup content)"
)));
```

This is good for debugging benign issues but in an attack scenario the
"path traversal detected" message ends up in logs along with the
attacker-influenced path content. Standard advice for security errors is to
log the suspect input verbatim only at debug level and surface a generic
`UnsupportedPlatform("cgroup_v2: traversal detected")` to the parent
supervisor. Today the entire path appears in the public error variant.

This is purely a diagnostic-cleanliness concern; the attacker cannot
exfiltrate anything new (they wrote `/proc/self/cgroup` themselves, by
hypothesis), and the message is emitted only on the fail-fast path before
any child is spawned.

**Fix:** Optional — log the full `abs_path` via `tracing::debug!` and surface
a generic message in the `NonoError`. Or accept the current shape; this is
nuanced and reasonable people disagree.

---

_Reviewed: 2026-05-10_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Diff base: `9b780c1191df6bc358e9a6fc24630afa86f1c6ac`_
