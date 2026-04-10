# Phase 1: PR-A Library Contract - Research

**Researched:** 2026-04-03
**Domain:** Rust OS sandboxing library — Windows `Sandbox::apply()` contract promotion
**Confidence:** HIGH

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| LIBCON-01 | `Sandbox::apply()` validates capability set against the supported Windows subset and returns `Ok(())` for accepted shapes (directory read, directory read-write, empty fs; AllowAll/Blocked/ProxyOnly network; default signal/process/ipc modes) | `apply()` must call `compile_filesystem_policy` + `compile_network_policy` and check each field against defaults; `Ok(())` return path is the validate-and-signal success path |
| LIBCON-02 | `Sandbox::apply()` returns explicit `NonoError::UnsupportedPlatform` with a named message for every rejected capability shape | The `WindowsUnsupportedIssueKind` and `WindowsUnsupportedNetworkIssueKind` enums and their `description()` methods already provide the vocabulary; `apply()` must surface them via `UnsupportedPlatform` |
| LIBCON-03 | `support_info()` reports `SupportStatus::Supported` / `is_supported: true`; `WINDOWS_PREVIEW_SUPPORTED` constant promoted in the same commit as `apply()` | `WINDOWS_PREVIEW_SUPPORTED` must be flipped to `true`; `support_info()` must return `SupportStatus::Supported`; all three functions must be consistent |
| LIBCON-04 | 9 required unit tests encode the promoted contract (listed by name in requirements) | All 9 tests must live in `crates/nono/src/sandbox/windows.rs` under `#[cfg(test)]`; the existing test `support_info_reports_consistent_partial_status` must be replaced |
| LIBCON-05 | The `setup.rs` line stating "library contract remains partial on Windows" removed or rewritten (minimal touch) | Line 756 of `crates/nono-cli/src/setup.rs` is the only permitted change outside `crates/nono/` |
</phase_requirements>

---

## Summary

Phase 1 promotes the Windows `Sandbox::apply()` from an unconditional stub that discards `caps` and returns `UnsupportedPlatform` to a real validate-and-signal function that accepts the enforceable subset and fails closed on everything else. The core insight from SUMMARY.md is that "validate-and-signal, not enforce-in-process" is the correct architecture: on Linux and macOS `apply()` restricts the calling process directly, but on Windows the calling process is the nono-cli supervisor and restricting it is wrong. Windows enforcement happens at child-process-creation time via `CreateProcessAsUserW` with a low-integrity token and WFP filters — both CLI-owned and already implemented. `apply()` validates that the capability set is within the enforceable subset and returns `Ok(())` to signal that enforcement can proceed.

The implementation path is fully specified by existing code: `compile_filesystem_policy()` and `compile_network_policy()` already exist in `windows.rs`, the unsupported-shape enums already define the vocabulary for rejection messages, and the `Sandbox::apply()` dispatch in `mod.rs` already routes to `windows::apply(caps)`. No new crates or structural changes are needed. The only behavioral changes are: (1) replacing the `let _ = caps; Err(...)` stub with the validate-and-signal body, (2) activating the `WindowsUnsupportedIssueKind` classifications in `compile_filesystem_policy` for single-file and write-only shapes, (3) flipping `WINDOWS_PREVIEW_SUPPORTED` to `true` and updating `support_info()` to return `SupportStatus::Supported`, and (4) writing the 9 required contract tests.

One critical gap must be addressed in this phase: `compile_filesystem_policy` currently does not populate its `unsupported` vec — it pushes all capabilities into `rules` unconditionally regardless of shape. PR-A must activate the single-file and write-only rejection logic inside `compile_filesystem_policy` (or directly inside `apply()`) so that the tests for `apply_rejects_unsupported_single_file_grant` and `apply_rejects_unsupported_write_only_directory_grant` can pass.

**Primary recommendation:** Replace the `apply()` stub with a validate-and-signal body that calls `compile_filesystem_policy` / `compile_network_policy`, inspects their `unsupported` vecs, then checks the remaining `CapabilitySet` fields against their defaults — all in a single function body in `crates/nono/src/sandbox/windows.rs`. Flip `WINDOWS_PREVIEW_SUPPORTED` to `true` in the same commit. Write the 9 tests. Remove line 756 from `setup.rs`. Nothing else.

---

## Project Constraints (from CLAUDE.md)

- **No `.unwrap()` or `.expect()`** — enforced by `clippy::unwrap_used`. All paths through `apply()` must use `?` or explicit `match`.
- **Fail secure** — canonicalization failure in `apply()` must return an error, never silently accept an un-canonicalized path.
- **Path security** — never use string `.starts_with()` on paths; always use `windows_paths_start_with_case_insensitive()` (already exists in `windows.rs`).
- **No `#[allow(dead_code)]`** — if `WindowsUnsupportedIssueKind` variants are used by new logic, the old test `compile_filesystem_policy_keeps_single_file_rules` (which asserts `is_fully_supported: true` for a single-file cap) must be updated to assert `is_fully_supported: false` once the classification is activated.
- **Error propagation via `?` only** — no manual `unwrap`/`panic` paths.
- **Commits require DCO sign-off** — `Signed-off-by: Name <email>` in every commit message.
- **`#[must_use]`** — the `apply()` function already has `#[must_use]`, keep it.
- **Tests for all new logic** — the 9 required tests cover this; each classification branch must have test coverage.
- **Env vars save/restore in tests** — any test that sets `LOCALAPPDATA` or `USERPROFILE` must save/restore before/after.

---

## Standard Stack

### Core (no changes required)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows-sys` | 0.59 | Win32 FFI for SACL queries, path operations | Already in `crates/nono/Cargo.toml`; provides the Win32 types used by existing `windows.rs` code |
| `thiserror` | 2 | `NonoError::UnsupportedPlatform` error variant | Already the project error model; no alternative |

### No New Dependencies

Zero crates need to be added. Confirmed by reading `crates/nono/Cargo.toml` and the existing imports in `windows.rs`. The `windows-sys` features already declared cover everything needed for the validate-and-signal path.

**Installation:** None required.

---

## Architecture Patterns

### The Validate-and-Signal Pattern

`apply()` on Windows must not restrict the calling process. It must validate and signal. The correct body:

```rust
// Source: derived from existing compile_filesystem_policy / compile_network_policy
// in crates/nono/src/sandbox/windows.rs
pub fn apply(caps: &CapabilitySet) -> Result<()> {
    // 1. Filesystem shape validation
    let fs_policy = compile_filesystem_policy(caps);
    if !fs_policy.unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows sandbox does not support: {}",
            fs_policy.unsupported_messages().join(", ")
        )));
    }

    // 2. Network shape validation
    let net_policy = compile_network_policy(caps);
    if !net_policy.unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows sandbox does not support: {}",
            net_policy.unsupported_messages().join(", ")
        )));
    }

    // 3. Remaining field validation against defaults
    if caps.signal_mode() != crate::SignalMode::Isolated {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support non-default signal mode".to_string(),
        ));
    }
    if caps.process_info_mode() != crate::ProcessInfoMode::Isolated {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support non-default process info mode".to_string(),
        ));
    }
    if caps.ipc_mode() != crate::IpcMode::SharedMemoryOnly {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support non-default IPC mode".to_string(),
        ));
    }
    if caps.extensions_enabled() {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support runtime capability expansion".to_string(),
        ));
    }
    if !caps.platform_rules().is_empty() {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support platform-specific rules (Seatbelt-only feature)"
                .to_string(),
        ));
    }

    // 4. Validated — CLI layer can proceed with enforcement
    Ok(())
}
```

### The `compile_filesystem_policy` Gap That Must Be Fixed

Currently `compile_filesystem_policy` pushes every capability into `rules` with no rejection logic:

```rust
// Current (broken for PR-A purposes): all caps go into rules, unsupported stays empty
for cap in caps.fs_capabilities() {
    rules.push(WindowsFilesystemRule { ... });
}
```

PR-A must activate the rejection classification. The `WindowsUnsupportedIssueKind` enum already has `SingleFileGrant` and `WriteOnlyDirectoryGrant` variants. The fix is to branch on `cap.is_file` and `cap.access` inside the loop:

```rust
// Pattern to activate inside compile_filesystem_policy:
for cap in caps.fs_capabilities() {
    if cap.is_file {
        unsupported.push(WindowsUnsupportedIssue {
            kind: WindowsUnsupportedIssueKind::SingleFileGrant,
            path: normalize_windows_path(&cap.resolved),
        });
    } else if cap.access == crate::AccessMode::Write {
        unsupported.push(WindowsUnsupportedIssue {
            kind: WindowsUnsupportedIssueKind::WriteOnlyDirectoryGrant,
            path: normalize_windows_path(&cap.resolved),
        });
    } else {
        rules.push(WindowsFilesystemRule { ... });
    }
}
```

**Critical:** Activating this logic will break the existing tests `compile_filesystem_policy_keeps_single_file_rules` and `compile_filesystem_policy_keeps_write_only_directory_rules`. Both tests currently assert `is_fully_supported: true` for shapes that are now rejected. Those tests must be updated to assert `is_fully_supported: false` and verify the `unsupported` vec content.

### Constants and `support_info()` Promotion

```rust
// Change these together in one commit (LIBCON-03):
const WINDOWS_PREVIEW_SUPPORTED: bool = true;  // was false
const WINDOWS_SUPPORTED_DETAILS: &str =
    "Windows sandbox enforcement supports directory read and directory read-write grants, \
     blocked network mode, and default signal/process/ipc modes. Single-file grants, \
     write-only directory grants, port-level network filtering, runtime capability \
     expansion, and platform-specific rules are not in the supported subset. \
     `nono shell` and `nono wrap` remain intentionally unavailable on Windows.";

pub fn support_info() -> SupportInfo {
    SupportInfo {
        is_supported: WINDOWS_PREVIEW_SUPPORTED,  // now true
        status: SupportStatus::Supported,          // was Partial
        platform: "windows",
        details: WINDOWS_SUPPORTED_DETAILS.to_string(),
    }
}
```

### Recommended Project Structure (no change)

The file layout does not change. All work stays in:

```
crates/nono/src/sandbox/windows.rs   # All changes: apply(), compile_filesystem_policy(), constants, tests
crates/nono-cli/src/setup.rs         # One line removal only (line 756)
```

### Anti-Patterns to Avoid

- **Copying the `let _ = caps;` pattern** from the stub into any branch. Every code path must inspect `caps`.
- **String-based path comparison** — use `windows_paths_start_with_case_insensitive()` and `windows_paths_equal_case_insensitive()`, which already exist.
- **Silent fallback on canonicalization error** — `compile_filesystem_policy` already uses `normalize_windows_path` which does not canonicalize; if any new path validation in `apply()` calls `canonicalize()`, failure must be an error, not an `unwrap_or_else`.
- **Promoting `is_supported()` before `apply()` is real** — `WINDOWS_PREVIEW_SUPPORTED` must be flipped in the same commit that makes `apply()` real, not before.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Capability shape classification | Custom shape-detection logic | `compile_filesystem_policy()` + `compile_network_policy()` already in `windows.rs` | They already produce `unsupported` vecs with the right enums |
| Path prefix matching | String `.starts_with()` | `windows_paths_start_with_case_insensitive()` in `windows.rs` | Case-insensitive Windows path semantics; string `starts_with` is a security vulnerability |
| Error message vocabulary | New error strings | `WindowsUnsupportedIssueKind::description()` and `WindowsUnsupportedNetworkIssueKind::description()` | Consistent messages; tests can assert specific substrings |
| Unsupported-shape detection | New field-inspection logic | The existing enum variants (`SingleFileGrant`, `WriteOnlyDirectoryGrant`, `PortConnectAllowlist`, etc.) | They already name all the shapes in the rejected contract |

**Key insight:** The entire rejected-shape vocabulary was built in the preview work and already exists. PR-A wires it into `apply()` return values; it does not invent new vocabulary.

---

## Common Pitfalls

### Pitfall 1: Flipping the Constant Before the Logic Is Real (S1)

**What goes wrong:** `WINDOWS_PREVIEW_SUPPORTED` is flipped to `true` in one commit, but `apply()` still contains the stub `let _ = caps; Err(...)`. Now `is_supported()` returns `true` but `apply()` always fails. Tests that call only `is_supported()` pass; any test that calls `apply()` with a supported shape fails.

**Why it happens:** The constant is a single easy edit; the `apply()` body takes more work.

**How to avoid:** The three functions (`apply()`, `is_supported()`, `support_info()`) must be promoted in a single commit. The test `support_info_reports_supported_status_for_promoted_subset_contract` calls all three with the same capability set and asserts consistency — this test must pass in the same commit.

**Warning signs:** Any test that passes `is_supported()` but fails on `apply()` with a supported capability set.

---

### Pitfall 2: Silent Fallback for Unrecognized Capability Shapes (S2)

**What goes wrong:** A capability field added after PR-A (e.g., a future `dns_mode`) is silently accepted by `apply()` because the field check was not added to the validation body. The capability set looks supported but enforcement is actually absent.

**Why it happens:** The `apply()` body only checks known fields at write time. Future fields default to some value that is never validated.

**How to avoid:** All non-default non-supported values must produce an explicit `UnsupportedPlatform`. The validation body must be exhaustive over all current `CapabilitySet` fields that have Windows enforcement implications. Review the full `CapabilitySet` struct field list before writing the body.

**Warning signs:** A capability set with a non-default value for any field not listed in the accepted table returns `Ok(())`.

---

### Pitfall 3: Breaking Existing Tests Without Updating Them (B1)

**What goes wrong:** Activating the `SingleFileGrant` and `WriteOnlyDirectoryGrant` classification in `compile_filesystem_policy` breaks two existing tests that assert `is_fully_supported: true` for those shapes.

**Why it happens:** The existing tests (`compile_filesystem_policy_keeps_single_file_rules`, `compile_filesystem_policy_keeps_write_only_directory_rules`) were written when the preview did not classify those shapes as unsupported.

**How to avoid:** Update those tests in the same commit that activates the classification. The old tests assert `policy.is_fully_supported()` = `true`; the updated tests must assert `policy.is_fully_supported()` = `false` and inspect `policy.unsupported`.

**Warning signs:** `cargo test -p nono windows:: --lib` fails on existing tests rather than the 9 new ones.

---

### Pitfall 4: Scope Creep into PR-B Files (SC3)

**What goes wrong:** Once `apply()` is real and `is_supported()` returns `true`, the CLI's `test_windows_support()` output (which still says "Library support status: partial") looks wrong. The developer edits `setup.rs` beyond the single permitted line, or edits `env_vars.rs` to update test assertions, or touches `output.rs`.

**Why it happens:** The inconsistency is visually jarring once the library is promoted.

**How to avoid:** PR-A has a hard non-changes list: only `crates/nono/src/sandbox/windows.rs` and the one `setup.rs` line are permitted. Any edit to `output.rs`, `env_vars.rs`, `ci.yml`, `README.md`, or any other CLI messaging file requires a written scope-justification and belongs in PR-B.

**Warning signs:** `git diff --name-only` shows files outside `crates/nono/` other than the single `setup.rs` line.

---

### Pitfall 5: `compile_filesystem_policy` Tests Assert Wrong Direction (B3)

**What goes wrong:** After activating single-file rejection in `compile_filesystem_policy`, the existing test `compile_filesystem_policy_keeps_single_file_rules` (line ~1454) still asserts `policy.is_fully_supported()` is `true`. The test name says "keeps" but the correct behavior is "rejects."

**Why it happens:** Test names reflect the pre-promotion intent.

**How to avoid:** Rename the tests to reflect the new contract: `compile_filesystem_policy_classifies_single_file_as_unsupported`, `compile_filesystem_policy_classifies_write_only_directory_as_unsupported`. Assert `!policy.is_fully_supported()` and assert `policy.unsupported.len() == 1` and check the kind.

**Warning signs:** A passing test with a name that says "keeps" for a shape that should be rejected.

---

## Code Examples

### The 9 Required Contract Tests (skeletons)

```rust
// Source: REQUIREMENTS.md LIBCON-04 + ROADMAP.md success criteria
// All tests go inside the existing #[cfg(test)] mod tests block in windows.rs

#[test]
fn support_info_reports_supported_status_for_promoted_subset_contract() {
    let info = support_info();
    assert!(is_supported());
    assert!(info.is_supported);
    assert_eq!(info.status, SupportStatus::Supported);
    assert_eq!(info.platform, "windows");
    // details string must be non-empty and not mention "partial"
    assert!(!info.details.is_empty());
    assert!(!info.details.to_ascii_lowercase().contains("partial"));
}

#[test]
fn apply_accepts_minimal_supported_windows_subset() {
    let dir = tempdir().expect("tempdir");
    let caps = CapabilitySet::new()
        .allow_path(dir.path(), AccessMode::Read)
        .expect("allow path");
    assert!(apply(&caps).is_ok());
}

#[test]
fn apply_accepts_network_blocked_capability_set() {
    let caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
    assert!(apply(&caps).is_ok());
}

#[test]
fn apply_rejects_unsupported_single_file_grant() {
    let dir = tempdir().expect("tempdir");
    let file = dir.path().join("note.txt");
    std::fs::write(&file, "x").expect("write");
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
    let err = apply(&caps).expect_err("single-file grant must be rejected");
    assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
    // message must be explicit, not generic
    let msg = err.to_string();
    assert!(msg.contains("single-file") || msg.contains("SingleFile"),
        "expected named error message, got: {msg}");
}

#[test]
fn apply_rejects_unsupported_write_only_directory_grant() {
    let dir = tempdir().expect("tempdir");
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Write).expect("dir cap"));
    let err = apply(&caps).expect_err("write-only directory grant must be rejected");
    assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
}

#[test]
fn apply_rejects_unsupported_proxy_with_ports() {
    let mut caps = CapabilitySet::new();
    caps.add_tcp_bind_port(8080);
    let err = apply(&caps).expect_err("port bind allowlist must be rejected");
    assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
}

#[test]
fn apply_rejects_capability_expansion_shape() {
    let caps = CapabilitySet::new().enable_extensions();
    let err = apply(&caps).expect_err("extensions_enabled must be rejected");
    assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
}

#[test]
fn apply_rejects_non_default_ipc_mode() {
    let caps = CapabilitySet::new().set_ipc_mode(IpcMode::Full);
    let err = apply(&caps).expect_err("non-default IPC mode must be rejected");
    assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
}

#[test]
fn apply_error_message_remains_explicit_for_unsupported_subset() {
    // The error must name the specific unsupported feature, not emit a generic string
    let dir = tempdir().expect("tempdir");
    let file = dir.path().join("note.txt");
    std::fs::write(&file, "x").expect("write");
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
    let err = apply(&caps).expect_err("must reject");
    let msg = err.to_string();
    // Must not be the old generic stub message
    assert!(!msg.contains("library-wide `Sandbox::apply()` contract remains partial"),
        "error is still the old stub: {msg}");
    // Must contain a recognizable feature name
    assert!(msg.contains("single-file") || msg.contains("not support"),
        "expected named feature in error, got: {msg}");
}
```

### The `setup.rs` Line Change (LIBCON-05)

Line 756 of `crates/nono-cli/src/setup.rs`:

```rust
// Remove this line:
println!("Windows CLI/release support is defined by that supported command surface; the embedded library `Sandbox::apply()` contract remains partial on Windows.");

// Replace with (or simply remove — full messaging is deferred to PR-B):
// [line deleted]
```

This is the only permitted change outside `crates/nono/`. No other lines in `setup.rs` change in PR-A.

---

## Runtime State Inventory

Step 2.5: SKIPPED — this is not a rename/refactor/migration phase. No stored data, live service config, OS-registered state, secrets, or build artifacts carry the string being changed. The change is code behavior, not a naming convention.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust / Cargo | Build and test | Yes | Active toolchain on Windows | None required |
| Windows target (`x86_64-pc-windows-msvc`) | `#[cfg(target_os = "windows")]` | Yes — this is a Windows machine | Current OS: Windows 11 | None required |
| `tempfile` crate | Test helper (`tempdir()`) | Yes — already in `[dev-dependencies]` | Existing | None |
| `icacls.exe` | Some existing tests for low-integrity labels | Yes (standard Windows) | System | Tests skip gracefully on failure |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** None.

All required tooling is already present. The entire phase is `crates/nono/`-only code changes plus one line in `crates/nono-cli/src/setup.rs`.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness (no external framework) |
| Config file | `Makefile` targets: `make test-lib`, `make test-cli` |
| Quick run command | `cargo test -p nono windows:: --lib` |
| Full suite command | `make test` (runs `cargo test` for all workspace members) |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| LIBCON-01 | `apply()` returns `Ok(())` for directory-read + network-blocked | unit | `cargo test -p nono windows::tests::apply_accepts_minimal_supported_windows_subset --lib` | No — Wave 0 |
| LIBCON-01 | `apply()` returns `Ok(())` for network-blocked only | unit | `cargo test -p nono windows::tests::apply_accepts_network_blocked_capability_set --lib` | No — Wave 0 |
| LIBCON-02 | `apply()` rejects single-file grant with named error | unit | `cargo test -p nono windows::tests::apply_rejects_unsupported_single_file_grant --lib` | No — Wave 0 |
| LIBCON-02 | `apply()` rejects write-only directory grant | unit | `cargo test -p nono windows::tests::apply_rejects_unsupported_write_only_directory_grant --lib` | No — Wave 0 |
| LIBCON-02 | `apply()` rejects proxy-with-ports | unit | `cargo test -p nono windows::tests::apply_rejects_unsupported_proxy_with_ports --lib` | No — Wave 0 |
| LIBCON-02 | `apply()` rejects extensions_enabled | unit | `cargo test -p nono windows::tests::apply_rejects_capability_expansion_shape --lib` | No — Wave 0 |
| LIBCON-02 | `apply()` rejects non-default IPC mode | unit | `cargo test -p nono windows::tests::apply_rejects_non_default_ipc_mode --lib` | No — Wave 0 |
| LIBCON-02 | Error message is explicit, not generic stub | unit | `cargo test -p nono windows::tests::apply_error_message_remains_explicit_for_unsupported_subset --lib` | No — Wave 0 |
| LIBCON-03 | `is_supported()` / `support_info()` / `apply()` all describe same contract | unit | `cargo test -p nono windows::tests::support_info_reports_supported_status_for_promoted_subset_contract --lib` | No — Wave 0 (replaces old `support_info_reports_consistent_partial_status`) |
| LIBCON-04 | All 9 named tests pass | unit | `cargo test -p nono windows:: --lib` | No — all Wave 0 |
| LIBCON-05 | `setup.rs` no longer contains the "partial" claim line | build/manual | `grep "contract remains partial" crates/nono-cli/src/setup.rs` (expect no match) | Existing file, one line deleted |

### Sampling Rate

- **Per task commit:** `cargo test -p nono windows:: --lib`
- **Per wave merge:** `make test`
- **Phase gate:** Full `make ci` (clippy + fmt + all tests) green before PR-A is submitted

### Wave 0 Gaps

All 9 required tests are new — they do not exist yet. They will be written in the implementation wave.

- [ ] `support_info_reports_supported_status_for_promoted_subset_contract` — replaces `support_info_reports_consistent_partial_status`
- [ ] `apply_accepts_minimal_supported_windows_subset` — new
- [ ] `apply_accepts_network_blocked_capability_set` — new
- [ ] `apply_rejects_unsupported_single_file_grant` — new
- [ ] `apply_rejects_unsupported_write_only_directory_grant` — new
- [ ] `apply_rejects_unsupported_proxy_with_ports` — new
- [ ] `apply_rejects_capability_expansion_shape` — new
- [ ] `apply_rejects_non_default_ipc_mode` — new
- [ ] `apply_error_message_remains_explicit_for_unsupported_subset` — new

Existing tests that must be updated (not new, not deleted):

- [ ] `compile_filesystem_policy_keeps_single_file_rules` — must assert `is_fully_supported: false` after classification is activated
- [ ] `compile_filesystem_policy_keeps_write_only_directory_rules` — same update required

No new test infrastructure, fixtures, or frameworks are needed.

---

## Open Questions

1. **`NetworkMode::ProxyOnly` with empty `bind_ports` — accept or reject?**
   - What we know: `preview_runtime_status` classifies `ProxyOnly` as `RequiresEnforcement`. The CLI WFP layer can enforce loopback-permit + block for `ProxyOnly { port, bind_ports: [] }`. `bind_ports` non-empty is already covered by `PortBindAllowlist` rejection.
   - What's unclear: Should `apply()` accept `ProxyOnly { port, bind_ports: [] }` (trusting the CLI WFP layer) or reject it (conservative)?
   - Recommendation: Accept `ProxyOnly { port, bind_ports: [] }` as the WFP enforcement is implemented. Reject `bind_ports` non-empty via `PortBindAllowlist`. This matches the accepted-shapes table in SUMMARY.md. Make the decision explicit in the PR description.

2. **Error message for `apply()` when multiple shapes are rejected simultaneously**
   - What we know: `unsupported_messages()` returns a `Vec<String>`. The error must be explicit.
   - What's unclear: Join all messages into one `UnsupportedPlatform` string, or return the first failure only?
   - Recommendation: Return all messages joined (consistent with how `validate_launch_paths` works). The test `apply_error_message_remains_explicit_for_unsupported_subset` only needs to verify the message is non-generic; joining multiple messages still satisfies that.

3. **Whether `seatbelt_debug_deny` needs explicit handling in `apply()`**
   - What we know: The field exists in `CapabilitySet` but is macOS-only. On Windows it has no effect.
   - What's unclear: Does `apply()` need to explicitly check and accept it, or is "not checking it" equivalent to accepting it?
   - Recommendation: Do not check `seatbelt_debug_deny` in `apply()`. It is macOS-only and silently ignoring it on Windows is the correct behavior (it produces no enforcement claim either way). Document this in the function body comment.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `apply()` on Windows: `let _ = caps; Err(UnsupportedPlatform(...))` | Validate-and-signal: inspect each capability dimension, return `Ok(())` or named error | PR-A | `is_supported()` can honestly return `true` |
| `WINDOWS_PREVIEW_SUPPORTED: bool = false` | `WINDOWS_PREVIEW_SUPPORTED: bool = true` | PR-A (same commit) | `support_info()` returns `SupportStatus::Supported` |
| `compile_filesystem_policy` puts all caps into `rules` | Branch on `is_file` and `Write`-only, push unsupported shapes to `unsupported` vec | PR-A | Single-file and write-only grants produce named errors |

---

## Sources

### Primary (HIGH confidence)

- `crates/nono/src/sandbox/windows.rs` — full content read; stub implementation, existing functions, test block
- `crates/nono/src/sandbox/mod.rs` — full content read; dispatch facade, `SupportStatus`, `WindowsUnsupportedIssueKind`, `WindowsUnsupportedNetworkIssueKind` definitions
- `crates/nono/src/capability.rs` — read; `CapabilitySet` fields, `IpcMode`/`SignalMode`/`ProcessInfoMode` defaults
- `crates/nono/src/error.rs` — full content read; `NonoError::UnsupportedPlatform` variant
- `crates/nono-cli/src/setup.rs` — read; confirmed line 756 is the target LIBCON-05 change
- `.planning/research/SUMMARY.md` — full content read; project-level research synthesized before this phase
- `.planning/REQUIREMENTS.md` — full content read; LIBCON-01 through LIBCON-05 requirements
- `.planning/ROADMAP.md` — full content read; phase success criteria
- `CLAUDE.md` — full content read; coding standards and security constraints

### Secondary (MEDIUM confidence)

None — all findings are from direct code reading.

### Tertiary (LOW confidence)

None.

---

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — confirmed by reading `Cargo.toml`; zero new dependencies
- Architecture: HIGH — validate-and-signal pattern is the only correct approach given the Windows process model; confirmed by reading CLI enforcement code and the existing `apply()` dispatch
- Pitfalls: HIGH — all pitfalls are grounded in specific line numbers and test names in the live codebase; no speculative pitfalls

**Research date:** 2026-04-03
**Valid until:** 2026-05-03 (stable Rust codebase; no fast-moving external dependencies)
