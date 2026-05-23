---
phase: 45-source-migration-aipc-g-04-resl-native-re-validation
reviewed: 2026-05-23T00:00:00Z
depth: standard
files_reviewed: 18
files_reviewed_list:
  - bindings/c/src/capability_set.rs
  - bindings/c/src/lib.rs
  - bindings/c/src/fs_capability.rs
  - bindings/c/src/sandbox.rs
  - bindings/c/src/state.rs
  - bindings/c/src/query.rs
  - crates/nono/src/supervisor/types.rs
  - crates/nono/src/supervisor/aipc_sdk.rs
  - crates/nono/src/supervisor/mod.rs
  - crates/nono/src/supervisor/socket.rs
  - crates/nono/src/supervisor/socket_windows.rs
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/exec_strategy_windows/supervisor.rs
  - crates/nono-cli/src/terminal_approval.rs
  - CHANGELOG.md
  - docs/architecture/audit-bundle-target.md
  - .github/workflows/phase-45-resl-native-host.yml
findings:
  critical: 0
  warning: 5
  info: 5
  total: 10
status: issues_found
---

# Phase 45: Code Review Report

**Reviewed:** 2026-05-23
**Depth:** standard
**Files Reviewed:** 18
**Status:** issues_found

## Summary

Phase 45 is a focused three-plan delivery:

- **Plan 45-01 (mechanical `#[unsafe(no_mangle)]` sweep):** 39 sites across 6 FFI files in `bindings/c/src/`. Read end-to-end. The conversions are uniform, the `# Safety` doc-comments accurately describe the contracts, and the pattern matches Edition 2024 requirements. No defects found in the sweep itself.
- **Plan 45-02 (BREAKING wire-format change `Granted` → `Approved(ResourceGrant)`):** The structural elimination of `(Approved, grant=None)` is sound — the `decision: ApprovalDecision` variant now carries the grant inline and the `grant: Option<ResourceGrant>` field is removed from `SupervisorResponse::Decision`. The child-side SDK demultiplexer (`aipc_sdk.rs::send_capability_request`) correctly drops the former `ok_or_else` defense-in-depth branch; the Windows dispatcher (`exec_strategy_windows/supervisor.rs`) keeps a `(decision, _grant)` tuple as documented defense-in-depth. The G-04 broker-failure flip is preserved. The Phase 18.1-02 invariant is now type-level.
- **Plan 45-03 (workflow + protocol doc):** workflow_dispatch-only CI workflow with SHA-pinned actions. No source-tree edits.

The findings below are largely robustness / clarity concerns surfaced by the wide review surface. None are blockers for the phase's stated goals; several are pre-existing issues exposed by reading the touched files at depth.

## Warnings

### WR-01: Unix supervisor silently overwrites backend-selected `ResourceGrant` with a `File`-shaped placeholder, breaking non-File AIPC paths on Linux/macOS

**File:** `crates/nono-cli/src/exec_strategy.rs:2867-2873`
**Issue:** After receiving an `Approved(grant)` from the approval backend, the Unix supervisor unconditionally replaces the inline grant with `ResourceGrant::sideband_file_descriptor(request.access)` before sending it back to the child:

```rust
let decision = if decision.is_approved() {
    ApprovalDecision::Approved(nono::ResourceGrant::sideband_file_descriptor(
        request.access,
    ))
} else {
    decision
};
```

`sideband_file_descriptor` sets `resource_kind = GrantedResourceKind::File` and `transfer = SidebandFileDescriptor`. If a non-File AIPC request (Event / Mutex / Pipe / Socket / JobObject) ever reaches this dispatcher on Unix — including the `unsupported_platform_message()` early-out being bypassed in a future cross-platform expansion — the child SDK's `extract_duplicated_handle` and `reconstruct_socket_from_blob` validators will reject the response because the `transfer` field does not match (the child expects `DuplicatedWindowsHandle` or `SocketProtocolInfoBlob`, gets `SidebandFileDescriptor`). The aipc_sdk module already returns `UnsupportedPlatform` on non-Windows for the 5 AIPC kinds, so today this is latent — but the rewrite is silent (no `debug_assert!` that `request.kind == HandleKind::File`) and there is no guard in `exec_strategy.rs` that this code path only executes for File-kind requests. Phase 45-02's stated goal is type-level enforcement of the wire invariant; this site happily lets a backend's `Event`/`Mutex`/`Pipe` grant be discarded without any compile-time or runtime signal.

**Fix:** Either (a) assert / guard `request.kind == HandleKind::File` before the unconditional overwrite, or (b) preserve the backend-selected grant for non-File kinds and only override for File. Recommended:

```rust
let decision = if decision.is_approved() {
    // Unix supervisor only transports File handles via SCM_RIGHTS today.
    // Non-File kinds return UnsupportedPlatform from the SDK before
    // reaching this dispatcher; assert that invariant rather than
    // silently overwriting a non-File grant with a File placeholder.
    debug_assert_eq!(
        request.kind,
        nono::supervisor::HandleKind::File,
        "Unix supervisor overwrite assumes File-kind requests only"
    );
    ApprovalDecision::Approved(nono::ResourceGrant::sideband_file_descriptor(
        request.access,
    ))
} else {
    decision
};
```

### WR-02: `read_pipe_rendezvous` accepts the published pipe name verbatim with no anti-traversal / character-class validation

**File:** `crates/nono/src/supervisor/socket_windows.rs:932-968`
**Issue:** `read_pipe_rendezvous` reads the published rendezvous file and trusts the first line as the pipe name with only a `\\.\pipe\` prefix check (line 942). Any string that begins with `\\.\pipe\` is accepted as `pipe_name` and passed to `CreateFileW` in `connect_named_pipe`. The rendezvous file is created by the supervisor with `create_new(true)` and parent-only permissions on Linux — on Windows there is no equivalent ACL applied to the rendezvous file at creation time (`write_pipe_rendezvous` calls `OpenOptions::new().write(true).create_new(true).open(path)` with no explicit security descriptor at line 906-915). If an attacker can race the `create_new` (TOCTOU window) or otherwise plant a rendezvous file under the expected path, they can redirect the child's `CreateFileW` to an attacker-controlled named pipe, bypassing the per-session token check.

Defense-in-depth comparison: `validate_session_sid_for_sddl` (line 1002) and `current_logon_sid` (line 1054) enforce strict character-class allow-lists on SID strings before embedding in SDDL. The pipe name read from the rendezvous file gets no comparable validation.

**Fix:** Validate the read pipe name against a strict character-class allow-list mirroring `pipe_name_from_rendezvous_path`'s output shape (`\\.\pipe\nono-<safe_leaf>-<8-hex>-<32-hex>`). Reject anything containing path-traversal sequences, NUL bytes, or characters outside `[a-zA-Z0-9-_\\.]`. At minimum:

```rust
fn validate_rendezvous_pipe_name(name: &str) -> Result<()> {
    if !name.starts_with(r"\\.\pipe\nono-") {
        return Err(NonoError::SandboxInit(format!(
            "Rendezvous pipe name does not match nono-* prefix: {name:?}"
        )));
    }
    for b in name.bytes() {
        if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'\\') {
            return Err(NonoError::SandboxInit(format!(
                "Rendezvous pipe name contains disallowed byte: {name:?}"
            )));
        }
    }
    Ok(())
}
```

### WR-03: `recv_fd_via_socket` leaks every FD beyond the first in any multi-FD SCM_RIGHTS message

**File:** `crates/nono/src/supervisor/socket.rs:340-377`
**Issue:** The receive loop walks the cmsg list and returns `OwnedFd::from_raw_fd(fd)` on the FIRST `SCM_RIGHTS` cmsg, regardless of how many file descriptors the cmsg carries. Per the SCM_RIGHTS contract, a single cmsg can carry an array of FDs — `header.cmsg_len` minus `CMSG_LEN(0)` divided by `sizeof(int)` is the count. The current implementation:

1. Computes `expected_cmsg_len` for exactly one FD and rejects only undersized payloads (the `< expected_cmsg_len` check at line 346).
2. Reads only the first FD via `copy_nonoverlapping` of `sizeof(RawFd)` bytes.
3. Returns immediately, dropping the cmsg list walk.

If the peer sends two or more FDs in one message (legitimately or maliciously), all FDs beyond the first are leaked into the receiver's FD table with no owner — the kernel allocates them at message-receive time, regardless of how many the user-space reader extracts. The leaked FDs remain open until process exit.

In a sandboxed agent context this is also a privilege-escalation surface: a compromised peer can stuff a multi-FD message and the leaked FDs reach the child with kernel rights the child was never granted.

`SCM_RIGHTS_BUFFER_CAPACITY` (64 bytes — line 24) holds at most ~12 FDs (`CMSG_SPACE(sizeof(int)*12)` is 64ish on 64-bit Linux), so the attack surface is bounded but real.

**Fix:** After computing `fd_count` from `header.cmsg_len`, either (a) reject any cmsg with `fd_count != 1` (close the array and return an error), or (b) close all extra FDs before returning the first. The fail-secure option is to close all and error out:

```rust
let payload_len = (header.cmsg_len as usize)
    .saturating_sub(unsafe { libc::CMSG_LEN(0) } as usize);
let fd_count = payload_len / std::mem::size_of::<RawFd>();
if fd_count != 1 {
    // Close any extra fds in the array to prevent leak.
    let data_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const RawFd;
    for i in 0..fd_count {
        let extra_fd = unsafe { std::ptr::read_unaligned(data_ptr.add(i)) };
        if extra_fd >= 0 {
            unsafe { libc::close(extra_fd) };
        }
    }
    return Err(NonoError::SandboxInit(format!(
        "SCM_RIGHTS message carried {fd_count} fds; expected exactly 1"
    )));
}
```

### WR-04: `bind_aipc_pipe` rejects `INVALID_HANDLE_VALUE` only via `==` and `.is_null()` — does not handle the `ERROR_PIPE_BUSY` race / re-entrant call

**File:** `crates/nono/src/supervisor/socket_windows.rs:763-781`
**Issue:** `bind_aipc_pipe` calls `CreateNamedPipeW(..., PIPE_UNLIMITED_INSTANCES, ...)` and checks for `INVALID_HANDLE_VALUE` / null. With `PIPE_UNLIMITED_INSTANCES` the call should not fail with `ERROR_PIPE_BUSY` under normal load, but the function offers no retry / disambiguation for the case where it does return `INVALID_HANDLE_VALUE` with `GetLastError() == ERROR_ACCESS_DENIED` — which can happen when the caller passes a name that another process already created with stricter SDDL. The error message embeds the canonical name but only the last OS error code is reported; a contributor reading this in audit context cannot distinguish "name collision" from "SDDL rejection" from "out of resources".

The bigger issue: the function comment (lines 743-747) claims `canonical_name` MUST be the server-canonicalized `\\.\pipe\nono-aipc-<user_session_id>-<sanitized_name>` shape and that the caller is responsible for canonicalization. There is no runtime check enforcing that contract; passing a non-canonical name (e.g. `\\.\pipe\arbitrary`) succeeds and creates a non-AIPC-namespaced pipe. The contract is asserted in the doc-comment but unenforced in code — easy to break in a future refactor.

**Fix:** Add a runtime check for the AIPC prefix, fail-closed if violated:

```rust
const AIPC_PREFIX: &str = r"\\.\pipe\nono-aipc-";
if !canonical_name.starts_with(AIPC_PREFIX) {
    return Err(NonoError::SandboxInit(format!(
        "bind_aipc_pipe requires canonicalized prefix {AIPC_PREFIX:?}; got {canonical_name:?}"
    )));
}
```

### WR-05: `prepare_bind_pipe_name` accepts any `\\.\pipe\…` path via the `explicit_pipe_name` shortcut — bypasses the SHA-256-of-rendezvous-path naming scheme and disables the rendezvous publication

**File:** `crates/nono/src/supervisor/socket_windows.rs:865-875` (and `explicit_pipe_name` at 817-824)
**Issue:** Any `Path` whose `to_string_lossy()` starts with `\\.\pipe\` is accepted verbatim as the pipe name and returns `(pipe_name, None)` — the `None` skips rendezvous publication entirely. This means a caller who supplies an attacker-influenced path that happens to start with `\\.\pipe\` can choose the exact pipe name without going through the SHA-256 + nonce derivation, and no rendezvous file gets cleaned up on drop (`cleanup_rendezvous_path` is `None`).

The `bind()` callers in this codebase always supply rendezvous file paths under nono-owned directories, so this is currently latent. But the explicit-name shortcut is wired into `prepare_bind_pipe_name`, `resolve_connect_pipe_name`, and `write_pipe_rendezvous` simultaneously and no test asserts that a path beginning with `\\.\pipe\` is REJECTED for the supervisor-control transport. A future caller (test helper, embedding API) could accidentally hand a user-controllable `Path` to `bind()` and get explicit-name semantics without warning. Compare with the strict `validate_session_sid_for_sddl` (line 1002): every other security-sensitive string input on this surface gets a fail-closed character-class validator; pipe names from `Path` arguments do not.

**Fix:** Either (a) gate the explicit-name path behind a separate constructor (`bind_explicit_name`) so the regular `bind()` always derives nonce-backed names, or (b) keep the shortcut but require the path to also live under a known nono-owned directory before honoring the explicit-name shape.

## Info

### IN-01: `current_logon_sid` skips the `entry.Sid.is_null()` check before passing to `ConvertSidToStringSidW`

**File:** `crates/nono/src/supervisor/socket_windows.rs:1114-1126`
**Issue:** The TOKEN_GROUPS walk dereferences `entry.Sid` via `ConvertSidToStringSidW` without first checking that `entry.Sid` is non-null. Windows `TokenGroups` queries should never return null `Sid` for an enabled group with `SE_GROUP_LOGON_ID`, but defense-in-depth would add a `if entry.Sid.is_null() { continue; }` guard before the FFI call. As-is, a corrupted token buffer would cause `ConvertSidToStringSidW` to fail (the function does its own null check), so the failure mode is graceful — but a one-line guard makes the precondition explicit.
**Fix:** Add `if entry.Sid.is_null() { continue; }` before `ConvertSidToStringSidW`.

### IN-02: `audit-bundle-target.md` Amendment 45-A states `is_granted()` was "renamed" but CHANGELOG.md (line 30) says "removed" — pick one phrasing

**File:** `docs/architecture/audit-bundle-target.md:108`, `CHANGELOG.md:30`
**Issue:** The ADR says: `The 'is_granted()' method is renamed 'is_approved()'.` The CHANGELOG says: `**Renamed API:** ApprovalDecision::is_granted() renamed to ApprovalDecision::is_approved(). The old name is removed`. These are consistent but the ADR omits the "old name is removed" half. For external consumers grepping the ADR for migration impact, the omission could lead them to expect a deprecation period that does not exist. Align the ADR phrasing with the CHANGELOG.
**Fix:** Append to the ADR line: `The old name is removed; downstream ApprovalBackend implementations must update at the binary-pin boundary (no deprecation period).`

### IN-03: `unsupported_platform_message` is locked verbatim by two assertion tests but no constant denotes the literal — tests reference the function output directly

**File:** `crates/nono/src/supervisor/aipc_sdk.rs:69-74`, tests at lines 648-679
**Issue:** The two snapshot tests (`unsupported_platform_message_is_d09_locked_string`, `unsupported_platform_message_starts_with_aipc_brokering`) lock specific substrings ("AIPC handle brokering is Windows-only on v2.1", "SCM_RIGHTS", "Events, mutexes, and Job Objects", start prefix, end suffix). The substrings live as string literals inside the test bodies; the live message lives as a string literal inside the function body. If a contributor updates the function but forgets to update the tests (or vice versa) the relationship is invisible at the call site. Defensible as-is (the tests document intent), but a `pub const MSG: &str = "…"; pub fn unsupported_platform_message() -> &'static str { MSG }` shape would let the tests assert against `MSG.contains(...)` and the production code reference the same `MSG`.
**Fix:** Optional refactor — extract a private `const UNSUPPORTED_MSG: &str = "…";` and have the function return it; have the tests reference `super::UNSUPPORTED_MSG` directly. Low priority — current shape is correct.

### IN-04: `disconnect_on_drop` flag fires unconditionally when set but the writer may already be closed

**File:** `crates/nono/src/supervisor/socket_windows.rs:786-795`
**Issue:** `SupervisorSocket::drop` checks `disconnect_on_drop` and unconditionally calls `DisconnectNamedPipe(raw as HANDLE)` if `self.writer.as_raw_handle()` is non-null. If the writer was closed by an explicit `Drop` of the inner `File` earlier (e.g. via `std::mem::replace`), the `as_raw_handle()` call would return a stale handle and `DisconnectNamedPipe` would either no-op or — on handle reuse — disconnect an unrelated pipe instance. As-is the code path is unreachable through the public API (no field-level mutation), but the latent risk would surface if a future refactor adds early-close semantics for the writer end.
**Fix:** Use a sentinel (e.g. wrap `disconnect_on_drop` together with the handle in a dedicated `Option<OwnedHandle>` that `drop` takes via `Option::take()`) instead of two coupled fields.

### IN-05: `phase-45-resl-native-host.yml` uses `RUSTFLAGS: -Dwarnings` globally but does not pass `-D clippy::unwrap_used`

**File:** `.github/workflows/phase-45-resl-native-host.yml:35`
**Issue:** Workflow sets `RUSTFLAGS: -Dwarnings` for the build, but the project's CLAUDE.md mandates `-D warnings -D clippy::unwrap_used` for cross-target clippy. This workflow only runs `cargo build` and `cargo test`, not `cargo clippy`, so the `-D clippy::unwrap_used` enforcement does not apply here — but the workflow is named "RESL native re-validation" and could mislead a reader into thinking it covers the cross-target clippy bar. Add a `# Note:` comment that this workflow intentionally skips clippy (the cross-target clippy bar is enforced by the existing local `cross` + Docker pipeline per CLAUDE.md).
**Fix:** Append a brief comment block above `env:`:

```yaml
# Note: this workflow runs build + test only. Cross-target clippy
# (`-D warnings -D clippy::unwrap_used`) is enforced separately via the
# local `cross` + Docker pipeline per CLAUDE.md § Coding Standards.
```

---

_Reviewed: 2026-05-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
