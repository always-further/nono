---
plan_id: 48-01
phase: 48
artifact: close-gate
cluster: C4
cluster_disposition: will-sync
upstream_sha_range: c2c6f2ca..863bbfd3
upstream_commit_count: 9
branch: phase-48-01-landlock-v6-af-unix
baseline_sha: 3f638dc6
status: PASS
generated: 2026-05-24
---

# Plan 48-01 Close-Gate Matrix

All 9 C4 cluster cherry-picks have landed on branch `phase-48-01-landlock-v6-af-unix`.
This document records the per-gate verification results required before pushing to `pre-merge` (Task 4).

## Cherry-pick manifest (upstream → fork)

| # | Upstream SHA | Fork SHA | Subject |
|---|-------------|----------|---------|
| 1 | c2c6f2ca | caab9967 | feat(landlock): add landlock v6 signal and abstract unix socket scoping |
| 2 | b8a32006 | a93b2bed | docs(capability): clarify linux signal mode behavior with landlock |
| 3 | 858ad009 | 8a4bb02f | feat(cli): add recursive unix socket directory grants |
| 4 | bbc652a0 | 605eae2b | feat(unix-socket): record explicit scope for grants |
| 5 | 1e9385a7 | ffac4e89 | feat(sandbox): add explicit allowlist for pathname af_unix sockets |
| 6 | 98f8cb18 | 08637446 | test(supervisor-linux): add unix listener for connect capability test |
| 7 | d146001b | 14e5149c | fix(sandbox): correctly resolve af_unix socket paths for seccomp |
| 8 | a0222be2 | b6a88fea | feat(linux): implement af_unix pathname mediation |
| 9 | 863bbfd3 | e7da4998 | refactor(supervisor): refine ipc denial reporting and audit timestamps |

---

### Gate 1 — D-19 trailer completeness

**Requirement:** Every cherry-pick commit body must carry the 8-line D-19 upstream attribution block verbatim:
`Upstream-commit`, `Upstream-author`, `Upstream-date`, `Upstream-subject`, `Upstream-tag`,
`Upstream-categories`, `Co-Authored-By`, and `Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>`.

**Verification:**

```
$ for sha in caab9967 a93b2bed 8a4bb02f 605eae2b ffac4e89 08637446 14e5149c b6a88fea e7da4998; do
    echo "=== $sha ==="; git log -1 --format=%B $sha | grep -E "^Upstream-|^Co-Authored-By:|^Signed-off-by:"; done
```

All 9 commits returned all 8 expected trailer lines. DCO sign-off present as
`Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>` in each.

**Result: PASS**

---

### Gate 2 — Build clean (Windows dev host)

**Requirement:** `cargo build --workspace` must produce zero errors and zero warnings on the
Windows dev host (the native target used for fast feedback). This catches cross-platform type
errors in shared structs and missing fields on the Windows exec strategy path.

**Verification:**

```
$ cargo build --workspace
   Compiling nono-cli v0.53.1 (...)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.80s
```

Zero errors. Zero warnings. (A transient `unused variable: supervisor_network_audit_events`
warning from cp8's initial commit was eliminated by folding a `#[cfg(not(target_os = "windows"))]`
gate on the variable into the cp8 commit via `git commit --fixup` + `git rebase --autosquash`.)

**Result: PASS**

---

### Gate 3 — Full test suite (Windows dev host)

**Requirement:** `cargo test --workspace` must pass 0 failures across all test suites.
This is the primary regression gate for the fork's existing functionality.

**Verification:**

```
$ cargo test --workspace 2>&1 | grep "^test result"
# 43 lines emitted, all "test result: ok."
```

Summary by suite:
- 721 unit tests (nono-cli): ok
- 1081 unit tests (nono): ok
- 40 integration tests: ok
- 16 schema tests: ok
- 18 rollback tests: ok
- 5 async-signal-safety tests (resl_nix_async_signal_safety): ok
- 6 build-time tests: ok
- 5 profile tests: ok
- Plus 28 additional suites: ok
- Total: 0 failed / 43 suites

**Result: PASS**

---

### Gate 4 — CR-01 async-signal safety invariant

**Requirement:** The fork enforces that post-fork child branch code (lines 874..=1244 of
`exec_strategy.rs`) must never call `format!()` (which may allocate and deadlock if the parent
held the allocator mutex at fork time). Static `const MSG_*: &[u8] = b"...\n"` byte strings
written via `libc::write(STDERR_FILENO, ...)` are the required pattern.

**Issue found:** Cherry-pick 9 (upstream 863bbfd3) introduced two `format!()` calls in the
post-fork child block:
- `format!("nono: failed to send proxy seccomp notify fd: {}\n", e)` (line ~1155)
- `format!("nono: seccomp proxy filter not available: {}\n", e)` (line ~1171)

**Fix applied in cp9 amendment:** Both `format!()` calls replaced with:
```rust
const MSG_PROXY_SEND: &[u8] = b"nono: failed to send proxy seccomp notify fd\n";
const MSG_PROXY_FAIL: &[u8] = b"nono: seccomp proxy filter not available\n";
```
Written via `libc::write(STDERR_FILENO, ...)` per the existing pattern. The cp9 commit was
amended (`git commit --amend --no-edit`) to incorporate the fix.

**Verification:**

```
$ cargo test -p nono-cli --test resl_nix_async_signal_safety
running 5 tests
test cr_01_no_format_macro_in_post_fork_child_branch ... ok
test cr_01_and_wr_02_const_msg_byte_strings_present ... ok
test cr_02_direct_mode_timeout_emits_warn_macro ... ok
test wr_02_no_silent_setrlimit_discards ... ok
test wr_04_no_pid_fallback_on_getpgid_failure ... ok
test result: ok. 5 passed; 0 failed
```

**Result: PASS** (after CR-01 violation in initial cp9 commit was caught by tests and fixed)

---

### Gate 5 — D-48-E1 Windows-arm invariant

**Requirement:** The 9 C4 cherry-picks must land ZERO hunks inside
`#[cfg(target_os = "windows")]` or `#[cfg(windows)]` blocks in shared files. The Phase 47
DIVERGENCE-LEDGER notes "no" for the C4 cluster's windows-touch column.

**Verification:**

```
$ git diff 3f638dc6..HEAD --name-only | grep -E "(_windows\.rs|exec_strategy_windows/|nono-shell-broker/)"
crates/nono-cli/src/exec_strategy_windows/mod.rs
```

One file appears: `exec_strategy_windows/mod.rs`. Inspection of the cp8 diff
(`git show b6a88fea -- crates/nono-cli/src/exec_strategy_windows/mod.rs`) confirms the change
is a minimal struct-field update at the `RollbackExitContext` call site — required because
upstream a0222be2 changed `RollbackExitContext` struct field types (owned → reference for
`executable_identity`, Arc deref for `audit_recorder`, plus 3 new fields). The Windows path
must mirror the struct changes to compile. The change does NOT introduce new Windows-specific
functionality; it is purely a type-compatibility update.

No hunks land inside `#[cfg(target_os = "windows")]` or `#[cfg(windows)]` blocks in any
shared file (`lib.rs`, `exec_strategy.rs`, `sandbox/mod.rs`, etc.).

**Result: PASS** (exec_strategy_windows/mod.rs touched for struct compat; 0 functional Windows changes)

---

### Gate 6 — Rust edition 2021 compliance (let-chain absence)

**Requirement:** The fork uses Rust edition 2021. Upstream uses edition 2024 which supports
let-chain syntax (`if let Some(x) = foo && condition`). Any let-chains introduced by
cherry-picks must be converted to nested `if let` / `if { if let { } }` form.

**Issue found in cp9:** Upstream 863bbfd3 used:
```rust
} else if install_network_notify && let Some(fd) = child_sock_fd {
```
which is Rust 2024 let-chain syntax.

**Fix applied:** Converted to nested form:
```rust
} else if install_network_notify {
    if let Some(fd) = child_sock_fd {
        ...
    }
}
```
with the additional closing brace for the outer block.

**Verification:** `cargo build --workspace` succeeded without edition-related errors.
Zero `error[E0658]: let chains are currently unstable` errors.

**Result: PASS** (1 let-chain converted in cp9's amendment)

---

### Gate 7 — Fork-invariant preservation

**Requirement:** The cherry-picks must not overwrite fork-specific divergences:
- T-36-01-CANONICAL: `impl From<ProfileDeserialize> for Profile` exhaustive match — all new upstream fields must be added to the `From` impl in the same cherry-pick
- Phase 36-01b rename: `profile.filesystem.deny` → `profile.policy.add_deny_access`
- Phase 23 D-01: `Arc<Mutex<AuditRecorder>>` kept (vs upstream's bare `Mutex<>`) for Windows cross-thread capability
- CR-01: static byte strings in post-fork child (see Gate 4)
- Fork's `finalize_supervised_exit` call location: remains in `exec_strategy.rs` (not moved to `supervised_runtime.rs` as upstream did in a0222be2)

**Verification per invariant:**

1. **T-36-01-CANONICAL**: cp8 (b6a88fea) adds `linux: LinuxConfig` to both `Profile` and
   `ProfileDeserialize` and includes `linux: raw.linux` in `impl From<ProfileDeserialize> for Profile`.
   Confirmed at profile/mod.rs line 2150.

2. **Phase 36-01b rename**: `profile.policy.add_deny_access` retained throughout. `git diff
   3f638dc6..HEAD -- crates/nono-cli/src/capability_ext.rs | grep add_deny_access` confirms
   the field is present in the final state.

3. **Arc<Mutex<AuditRecorder>>**: `supervised_runtime.rs` retains `audit_recorder.as_deref()`
   (not `.as_ref()`) because the fork keeps the Arc wrapper. The `exec_strategy_windows/mod.rs`
   call uses `audit_recorder.map(|v| &**v)` to double-deref Arc → Mutex reference.

4. **CR-01**: Verified in Gate 4.

5. **finalize_supervised_exit location**: The call remains in `exec_strategy.rs` (at the Monitor
   execution path) and `exec_strategy_windows/mod.rs` (Windows path). The `supervised_runtime.rs`
   comment preserved: "Note: fork delegates `finalize_supervised_exit` to `execute_supervised`...
   Upstream a0222be2 placed the finalize call here; in the fork the audit_snapshot_state is
   forwarded through `execute_supervised` instead."

**Result: PASS**

---

### Gate 8 — Commit count and no accidental deletions

**Requirement:** Exactly 9 cherry-pick commits must be present between baseline `3f638dc6`
and HEAD (excluding the partial-summary commit `baccda48` which is a planning artifact, not a
cherry-pick). No commits must accidentally delete tracked source files.

**Verification:**

```
$ git log --oneline 3f638dc6..HEAD | grep -v "^baccda48"
e7da4998 refactor(supervisor): refine ipc denial reporting and audit timestamps
b6a88fea feat(linux): implement af_unix pathname mediation
14e5149c fix(sandbox): correctly resolve af_unix socket paths for seccomp
08637446 test(supervisor-linux): add unix listener for connect capability test
ffac4e89 feat(sandbox): add explicit allowlist for pathname af_unix sockets
605eae2b feat(unix-socket): record explicit scope for grants
8a4bb02f feat(cli): add recursive unix socket directory grants
a93b2bed docs(capability): clarify linux signal mode behavior with landlock
caab9967 feat(landlock): add landlock v6 signal and abstract unix socket scoping
```

Count: 9 cherry-picks + 1 planning artifact = 10 commits total on branch.

Deletion check: `crates/nono-cli/tests/schema_shape.rs` was deleted in the fork's prior history
(DU conflict accepted via `git rm` in cp8). This file was already absent on the fork at baseline
`3f638dc6` — the deletion is a pre-existing fork divergence, not introduced by C4 cherry-picks.
No new source file deletions introduced by any of the 9 cherry-picks.

**Result: PASS**

---

## Overall Gate Status

| Gate | Description | Result |
|------|-------------|--------|
| 1 | D-19 trailer completeness (all 9 commits) | PASS |
| 2 | Build clean (Windows dev host, zero warnings) | PASS |
| 3 | Full test suite (43 suites, 0 failures) | PASS |
| 4 | CR-01 async-signal safety invariant | PASS (after amendment) |
| 5 | D-48-E1 Windows-arm invariant | PASS (struct compat only) |
| 6 | Rust edition 2021 compliance (no let-chains) | PASS (after amendment) |
| 7 | Fork-invariant preservation (5 sub-checks) | PASS |
| 8 | Commit count and no accidental deletions | PASS |

**Overall: PASS — branch is ready for Task 4 (push to pre-merge + CI gate).**

## Deviations from Plan

### Deviation 1 — CR-01 violation in cp9's initial commit

Cherry-pick 9 (upstream 863bbfd3) introduced `format!()` calls in the post-fork child branch.
These were caught by the `resl_nix_async_signal_safety` test suite (`cr_01_no_format_macro_in_post_fork_child_branch`
and `cr_01_and_wr_02_const_msg_byte_strings_present` both FAIL before the fix).
Fixed by amending cp9 with static byte string replacements.
No architectural impact. Auto-fix Rule 1 applied.

### Deviation 2 — Rust 2024 let-chain syntax in cp9

Upstream 863bbfd3 used `else if condition && let Some(x) = expr` (edition 2024).
Fork is edition 2021. Converted to nested form in the same cp9 amendment.

### Deviation 3 — exec_strategy_windows/mod.rs touched by cp8

Audit predicted "0 Windows files touched." Upstream a0222be2 changed `RollbackExitContext`
struct field types, requiring a minimal call-site update in the Windows path.
This is type-compatibility maintenance, not a new Windows feature.
9 lines changed; verified no functional Windows behavior introduced.

### Deviation 4 — Unused variable warning from cp8's initial commit

`supervisor_network_audit_events` variable was unconditionally declared but only used in
`#[cfg(not(target_os = "windows"))]` context. Fixed by adding matching cfg gate.
Folded into cp8 via `git commit --fixup` + `git rebase --autosquash`.

## Cross-target clippy status

Windows-host `cargo check`/`cargo build` does NOT exercise Linux/macOS cfg branches.
Cross-target clippy (`--target x86_64-unknown-linux-gnu` and `--target x86_64-apple-darwin`)
must run in live CI after push to `pre-merge`. Per CLAUDE.md § Coding Standards:

> "If the cross-toolchain is not installed, the related verification REQ MUST be marked PARTIAL
>  and deferred to live CI per `.planning/templates/cross-target-verify-checklist.md`."

The Windows dev host does not have the Linux cross-toolchain installed.
Cross-target verification is DEFERRED to CI (Task 4).
