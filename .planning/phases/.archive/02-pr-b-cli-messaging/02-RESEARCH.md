# Phase 2: PR-B CLI Messaging - Research

**Researched:** 2026-04-03
**Domain:** Rust CLI messaging, dead code removal, integration test assertion updates
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

#### Unified status line (CLIMSG-01)
- **D-01:** Drop `windows_cli_support_status_label()` entirely — function is removed.
- **D-02:** In `setup.rs:test_windows_support()`, replace the two-line `"CLI support status"` / `"Library support status"` pattern with a single line: `"  * Support status: {info.status_label()}"`.
- **D-03:** Same collapse in `setup.rs:print_check_only_summary()` — one `"Support status: {info.status_label()}"` line, `info.details` printed separately as before.
- **D-04:** `info.status_label()` is the single source of truth for Windows support status in all setup output.

#### Runtime banner after promotion (CLIMSG-02 / CLIMSG-04)
- **D-05:** Remove the Windows-specific `!support.is_supported` branch in `apply_pre_fork_sandbox()` in `execution_runtime.rs`. This branch is dead code after PR-A and was the source of "Windows restricted execution covers the current supported command surface".
- **D-06:** After removing the dead branch, Windows live-run follows the same path as Linux/macOS: `output::print_applying_sandbox(silent)` and `output::print_sandbox_active(silent)` are called — no Windows-specific banner text.
- **D-07:** In `env_vars.rs`, the assertion `text.contains("Windows restricted execution covers the current supported command surface")` is **removed**. The assertion `!text.contains("first-class supported")` is **removed**. New assertion added: `text.contains("Sandbox active")` (or the exact string `print_sandbox_active` produces). Each assertion is updated surgically — none deleted wholesale.
- **D-08:** The dry-run assertion `text.contains("current Windows command surface without claiming full parity")` also needs surgical update — it comes from `output::print_dry_run` Windows path, which should be checked and aligned.

#### Shell/Wrap unconditional rejection (CLIMSG-03)
- **D-09:** Remove the `if !Sandbox::support_info().is_supported {` guard in `command_runtime.rs:run_shell()` (line ~78). The `#[cfg(target_os = "windows")]` block calling `validate_windows_preview_entry_point(Shell, ...)` fires unconditionally.
- **D-10:** Same for `command_runtime.rs:run_wrap()` (line ~149): remove `if !Sandbox::support_info().is_supported {` guard. Rejection is unconditional.
- **D-11:** The library's rejection messages for Shell and Wrap already say "intentionally unavailable on Windows" — these messages are NOT changed in PR-B (they're library-owned and already correct post-PR-A).

#### Dead code removal (scope: PR-B)
- **D-12:** Remove `validate_windows_preview_direct_execution()` function from `execution_runtime.rs` entirely (it always returned `Ok(())` after PR-A — `is_supported` is now `true`, so the `validate_windows_preview_entry_point(RunDirect, ...)` call inside it never fired).
- **D-13:** Remove the call site of `validate_windows_preview_direct_execution` at line ~226 in `execution_runtime.rs`.
- **D-14:** The `apply_pre_fork_sandbox()` function's Windows-specific `!support.is_supported` branch (lines ~22-43) is removed as part of D-05 — this is the same cleanup.

#### Test assertion strategy (CLIMSG-04)
- **D-15:** Every `env_vars.rs` assertion updated **individually** — no assertion block deleted wholesale. Old string → new string, or old negative guard → affirmative (or removed if no longer meaningful).
- **D-16:** After cleanup, no `env_vars.rs` test asserts "preview" language, "restricted command surface", "CLI support status", "Library support status", or explicitly checks that "first-class supported" is absent.

### Claude's Discretion
- Exact string `print_sandbox_active` produces (already defined in `output.rs` — use whatever it currently says)
- Whether to add a Windows-specific note to the dry-run output summary or just use the cross-platform path
- Order of assertions in updated test functions (preserve logical grouping)

### Deferred Ideas (OUT OF SCOPE)
- Renaming `WindowsPreviewEntryPoint`, `WindowsPreviewContext`, `validate_preview_entry_point` in the library to remove "preview" from names — these are library API changes and belong after all four PRs are merged, not in PR-B.
- Updating the dry-run "without claiming full parity" message in `output::print_dry_run` to promoted language — if this string comes from library-controlled output, that's library scope; if CLI-controlled, it's in scope for CLIMSG-04 but should be confirmed before touching.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CLIMSG-01 | `setup --check-only` emits one unified Windows support status line (no separate CLI/library split labels) | Two touch points found: `test_windows_support()` and `print_check_only_summary()` in `setup.rs`; `windows_cli_support_status_label()` function to delete; two env_vars.rs tests assert old split labels and must be updated. |
| CLIMSG-02 | CLI runtime validation routes through the library's now-authoritative `support_info()` rather than a standalone Windows preview gate | Dead `!support.is_supported` branch in `apply_pre_fork_sandbox()` verified in `execution_runtime.rs` lines 22-43; after removal Windows follows the Linux/macOS code path. |
| CLIMSG-03 | `nono shell` and `nono wrap` remain hard-rejected on Windows via `validate_preview_entry_point` with explicit messaging | Confirmed: `command_runtime.rs` `run_shell()` line ~78 and `run_wrap()` line ~149 both guard the rejection with `if !Sandbox::support_info().is_supported {` — guard must be removed so rejection fires unconditionally. |
| CLIMSG-04 | `env_vars.rs` test assertions updated per-assertion to match first-class supported wording (surgical updates, not wholesale deletion) | Exact assertions identified: `windows_run_executes_basic_command` (lines 492-498), `windows_run_allows_supported_directory_allowlist_in_preview_live_run` (lines 568-575), `windows_dry_run_reports_preview_validation_without_enforcement_claims` (lines 464-471), `windows_setup_check_only_reports_live_profile_subset` (lines 2518-2525, 2571-2586), `windows_setup_check_only_reports_partial_support_without_first_class_claim` (lines 2571-2586). |
</phase_requirements>

## Summary

Phase 2 (PR-B) is a focused dead code removal and messaging cleanup phase within `crates/nono-cli/` only. The library API (`crates/nono/`) is read-only. PR-A established that `Sandbox::is_supported()` returns `true` and `support_info().status` is `SupportStatus::Supported` on Windows. Several CLI code paths that forked on `!support.is_supported` are now dead branches that must be removed, and the two-line CLI/library support status split in setup output must collapse into a single unified line.

The three categories of change are: (1) setup messaging — delete `windows_cli_support_status_label()`, collapse two status lines into one; (2) execution runtime — remove the dead `!is_supported` branch in `apply_pre_fork_sandbox()` and the now-dead `validate_windows_preview_direct_execution()` function; (3) shell/wrap gate — remove the `if !is_supported` guard so rejection fires unconditionally on Windows. Integration tests in `env_vars.rs` must be updated assertion-by-assertion to match the new behavior.

There are additional dead `!support.is_supported` branches in `output.rs` (`print_banner` lines 49-63, `print_supervised_info` lines 317-338) that the CONTEXT.md decisions do not explicitly name but that become unreachable dead code under the same PR-A change. These should be resolved to keep the codebase clean per CLAUDE.md's "no `#[allow(dead_code)]`" policy.

**Primary recommendation:** Execute in three atomic steps — (1) delete the function and collapse setup output, (2) remove execution_runtime.rs dead branches, (3) remove shell/wrap guards — then update all env_vars.rs assertions in one pass before the test run.

## Standard Stack

Phase 2 is internal refactoring — no new dependencies. The existing stack is all that is needed.

### Core (read-only reference)
| Library | Version | Purpose | Role in Phase |
|---------|---------|---------|---------------|
| `nono` (library crate) | workspace | Sandbox API, `support_info()`, `validate_preview_entry_point()` | Source of truth — not modified |
| `nono-cli` (binary crate) | workspace | CLI, messaging, output, setup, command routing | All changes are here |

### No new dependencies

**Build verification:**
```bash
cargo build -p nono-cli
cargo clippy -p nono-cli -- -D warnings -D clippy::unwrap_used
cargo test -p nono-cli
```

## Architecture Patterns

### Established Cross-Platform Execution Path

Linux/macOS and (after PR-B) Windows all follow the same sequence in `apply_pre_fork_sandbox()`:

```
output::print_applying_sandbox(silent)
  → Sandbox::apply(caps)?          // platform-specific, returns Ok(()) on Windows
  → output::print_sandbox_active(silent)
```

The Windows-specific dead branch that short-circuited this before PR-B is removed. No new abstraction is needed — Windows joins the existing cross-platform path.

### `#[cfg(target_os = "windows")]` Guard Pattern

Shell/Wrap rejection uses an outer `#[cfg(target_os = "windows")]` block that wraps the call to `validate_windows_preview_entry_point`. The inner `if !Sandbox::support_info().is_supported {` guard is the only change — the `#[cfg]` wrapper stays.

**Before PR-B:**
```rust
#[cfg(target_os = "windows")]
if !Sandbox::support_info().is_supported {
    Sandbox::validate_windows_preview_entry_point(
        nono::WindowsPreviewEntryPoint::Shell,
        ...
    )?;
}
```

**After PR-B:**
```rust
#[cfg(target_os = "windows")]
Sandbox::validate_windows_preview_entry_point(
    nono::WindowsPreviewEntryPoint::Shell,
    ...
)?;
```

The same pattern applies to `run_wrap()`.

### Setup Output Collapse Pattern

**Before PR-B (two lines in both `test_windows_support()` and `print_check_only_summary()`):**
```rust
// test_windows_support()
println!("  * CLI support status: {}", windows_cli_support_status_label());
println!("  * Library support status: {}", info.status_label());

// print_check_only_summary()
println!("CLI support status: {}", windows_cli_support_status_label());
println!("Library support status: {}", info.status_label());
```

**After PR-B (one line each):**
```rust
// test_windows_support()
println!("  * Support status: {}", info.status_label());

// print_check_only_summary()
println!("Support status: {}", info.status_label());
```

`windows_cli_support_status_label()` is deleted entirely (it has no remaining callers).

### Anti-Patterns to Avoid

- **Wholesale assertion block deletion:** Do not delete entire `assert!()` blocks from `env_vars.rs`. Update each assertion individually to reflect the new behavior.
- **Dead `#[allow(dead_code)]` insertion:** Per CLAUDE.md, if a function becomes unused, remove it — don't suppress the warning.
- **Scope creep into library:** `crates/nono/` files are read-only for PR-B. Renaming `WindowsPreviewEntryPoint` etc. is deferred.
- **Removing test functions entirely:** Integration tests whose names reference "preview" are updated in-place (body updated, name may be updated to reflect new behavior) — not deleted.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Checking Windows support status | Custom bool flags or env vars | `Sandbox::support_info().is_supported` | Library owns this — already called throughout CLI |
| Unified support string | New formatting function | `info.status_label()` returns `"supported"` — use directly | Single source of truth per D-04 |
| Shell/Wrap rejection message | Custom error string | `validate_preview_entry_point()` already returns the correct `NonoError::UnsupportedPlatform` | Library owns the message; CLI just propagates `?` |

## Common Pitfalls

### Pitfall 1: Missing Dead Branch in `output.rs`
**What goes wrong:** `print_banner()` (lines 49-63) and `print_supervised_info()` (lines 317-338) in `output.rs` also have `if !support.is_supported {` branches that are now dead. The CONTEXT.md decisions name `execution_runtime.rs` explicitly but do not list `output.rs`. Leaving these in place means dead code persists under the broad `#[cfg_attr(target_os = "windows", allow(dead_code))]` suppressor at line 1 of `output.rs`.
**Why it happens:** The CONTEXT.md `specifics` section focuses on the most impactful touch points. `output.rs` dead branches are suppressed by the file-level attribute and won't cause build errors, but they violate CLAUDE.md's "no `#[allow(dead_code)]`" policy spirit.
**How to avoid:** Include `output.rs` cleanup in the PR-B scope: remove the `!support.is_supported` branch from `print_banner()` and `print_supervised_info()`. After removal, check whether the `#[cfg_attr(target_os = "windows", allow(dead_code))]` file attribute is still needed for genuinely Linux/macOS-only functions.
**Warning signs:** clippy passing cleanly on Linux/macOS but the dead branches remaining on Windows.

### Pitfall 2: Wrong `print_sandbox_active` Assert String
**What goes wrong:** D-07 says new assertion should be `text.contains("Sandbox active")` but `output.rs` `print_sandbox_active()` actually prints the word `"active"` (lowercase, green bold) — it does NOT print `"Sandbox active"` as a phrase.
**Why it happens:** The decision text used a descriptive name, not the literal string.
**How to avoid:** Read `output.rs:print_sandbox_active()` before writing the assertion. The function prints `" active"` (after clearing a pending status line started by `print_applying_sandbox` which prints `"Applying sandbox..."`). A composite run therefore produces `"Applying sandbox... active"` on stderr. Assert `text.contains("active")` — or the full composite if stderr is captured together.
**Warning signs:** Assertion added for `"Sandbox active"` fails on a real Windows run despite the sandbox path being taken.

### Pitfall 3: Dry-Run Assertion is Deferred, Not Deleted
**What goes wrong:** D-08 marks the dry-run assertion update as needing investigation (`if CLI-controlled, it's in scope`). The `dry_run_summary()` function in `output.rs` (line 564) has a Windows-specific branch: `if !_support.is_supported { return "dry-run validates the current Windows command surface without claiming full parity"; }`. Since `is_supported` is now `true`, this branch is dead — `dry_run_summary()` always returns `"sandbox would be applied with above capabilities"` on Windows.
**Why it happens:** The deferred note in CONTEXT.md might be interpreted as "do not touch" but the function is CLI-owned dead code.
**How to avoid:** Remove the dead `if !_support.is_supported` branch from `dry_run_summary()`. Update the `windows_dry_run_reports_preview_validation_without_enforcement_claims` test: replace the `text.contains("current Windows command surface without claiming full parity")` assertion with `text.contains("sandbox would be applied with above capabilities")` and update the `!text.contains("sandbox would be applied")` negative assertion (which becomes a false negative after the change). The test name should also be updated to reflect that dry-run now applies the same path as Linux/macOS.
**Warning signs:** Test passes because the dead branch still runs (impossible since `is_supported=true`) — actually the test will FAIL if not updated, because `dry_run_summary()` no longer returns the old string.

### Pitfall 4: `validate_windows_preview_direct_execution` Removal Breaks the `#[cfg]` Call Site
**What goes wrong:** The call site at `execution_runtime.rs` line ~226 is:
```rust
#[cfg(target_os = "windows")]
if matches!(strategy, exec_strategy::ExecStrategy::Direct) {
    validate_windows_preview_direct_execution(&flags, &caps)?;
}
```
Removing the function without removing this call site causes a compile error.
**How to avoid:** Remove both the function definition (D-12) and the call site block (D-13) in the same edit.

### Pitfall 5: `apply_pre_fork_sandbox` Signature Change
**What goes wrong:** `apply_pre_fork_sandbox()` takes `#[cfg(target_os = "windows")] current_dir: &Path` as a parameter — this parameter exists only because the dead Windows branch uses it to call `Sandbox::preview_runtime_status(caps, current_dir, ...)`. After removing the dead branch, `current_dir` becomes unused on Windows, causing a compiler warning or unused-variable error.
**How to avoid:** After removing the dead branch, also remove the `current_dir` parameter from the function signature and all call sites (the call in `execute_sandboxed()` passes `&current_dir` under `#[cfg(target_os = "windows")]`).

## Code Examples

### Exact Strings Produced by Output Functions

From `output.rs` (source of truth for assertion strings):

```rust
// print_applying_sandbox prints to stderr (no newline):
eprint!("  {}", fg("Applying sandbox...", t.subtext));

// print_sandbox_active prints after the pending line:
// If pending status line exists: " active\n\n"
// If not:                        "  active\n\n"
// The word is "active" (lowercase, green bold)
```

For integration test assertions targeting the active-sandbox path, use:
```rust
assert!(text.contains("active"), "expected sandbox-active indicator, got:\n{text}");
// or more precisely:
assert!(text.contains("Applying sandbox"), "expected sandbox-applying indicator, got:\n{text}");
```

### Dry-Run String After Dead Branch Removal

After removing the `!is_supported` branch from `dry_run_summary()`:
```rust
// Windows dry-run will produce:
"dry-run sandbox would be applied with above capabilities"
// (same as Linux/macOS)
```

Integration test `windows_dry_run_reports_preview_validation_without_enforcement_claims` should assert:
```rust
assert!(
    text.contains("sandbox would be applied with above capabilities"),
    "expected cross-platform dry-run wording, got:\n{text}"
);
assert!(
    !text.contains("without claiming full parity"),
    "dry-run must not use old preview wording, got:\n{text}"
);
```

### Shell/Wrap Rejection Messages (library-owned, unchanged)

From `crates/nono/src/sandbox/windows.rs`:
```
Shell: "Live `nono shell` is intentionally unavailable on Windows. ..."
Wrap:  "Live `nono wrap` is intentionally unavailable on Windows. ..."
```

Both messages contain `"intentionally unavailable on Windows"`. Integration tests asserting shell/wrap rejection should key off this phrase (it is already present in the library strings).

### `setup --check-only` Output After PR-B

`print_check_only_summary()` after D-03:
```
Support status: supported
<details line from info.details>
User config root: ...
...
```

`test_windows_support()` after D-02:
```
  * Platform: windows
  * Support status: supported
  * <details>
  ...
```

`env_vars.rs` assertion updates for `windows_setup_check_only_reports_live_profile_subset`:
```rust
// Remove:
assert!(text.contains("CLI support status: supported restricted command surface"), ...);
assert!(text.contains("Library support status: supported"), ...);
// Add:
assert!(text.contains("Support status: supported"), ...);
```

## State of the Art

| Old Pattern | New Pattern | Changed | Impact |
|-------------|-------------|---------|--------|
| Two-line CLI/library status split in setup output | Single `Support status: {info.status_label()}` line | PR-B | Setup output no longer misleads users that CLI and library have different support states |
| `!is_supported` gate on shell/wrap rejection | Unconditional rejection on Windows | PR-B | Security fix: shell/wrap cannot execute on Windows regardless of `is_supported` value |
| Windows-specific "restricted execution" banner on live run | Cross-platform `print_applying_sandbox` + `print_sandbox_active` | PR-B | Windows live-run output is consistent with Linux/macOS |
| `validate_windows_preview_direct_execution()` | Deleted (always returned `Ok(())` after PR-A) | PR-B | Dead code removal |

**Dead code in scope for PR-B:**
- `windows_cli_support_status_label()` in `setup.rs` — delete
- `validate_windows_preview_direct_execution()` in `execution_runtime.rs` — delete
- `!support.is_supported` branch in `apply_pre_fork_sandbox()` in `execution_runtime.rs` — delete
- `!support.is_supported` guard in `run_shell()` in `command_runtime.rs` — delete
- `!support.is_supported` guard in `run_wrap()` in `command_runtime.rs` — delete
- `!_support.is_supported` branch in `dry_run_summary()` in `output.rs` — delete
- `!support.is_supported` branch in `print_banner()` in `output.rs` — delete
- `!support.is_supported` branch in `print_supervised_info()` in `output.rs` — delete

## Open Questions

1. **`apply_pre_fork_sandbox` parameter cleanup**
   - What we know: The `current_dir: &Path` parameter is gated `#[cfg(target_os = "windows")]` and is only used in the dead branch being removed.
   - What's unclear: Whether removing the parameter would require updating the call site signature in `execute_sandboxed()` — which also passes `&current_dir` under `#[cfg(target_os = "windows")]`.
   - Recommendation: Remove the parameter and update the call site. Leaving an unused `#[cfg(target_os = "windows")]` parameter would be dead code.

2. **`output.rs` file-level `allow(dead_code)` attribute**
   - What we know: `#[cfg_attr(target_os = "windows", allow(dead_code))]` at line 1 suppresses warnings for functions only reachable on non-Windows platforms. After removing the `!is_supported` branches, some of those functions may now be reachable on Windows (e.g., `print_supervised_info` still has a live path even after removing the dead branch).
   - What's unclear: Whether all functions under this attribute have genuinely Windows-unreachable code paths that require the suppressor, or whether the suppressor should be narrowed/removed.
   - Recommendation: Leave the file-level attribute in place for now — it covers Linux/macOS-only functions (like `print_abi_info`). The key action is removing the dead *bodies* of branches, not the file-level attribute.

3. **`windows_setup_check_only_reports_partial_support_without_first_class_claim` test**
   - What we know: This test (lines 2560-2587) asserts both the old split labels AND `!text.contains("first-class supported")`. After PR-B: the split-label assertions become false (output changes), and the `!first-class` negative guard becomes meaningless (output no longer contains that phrase anyway).
   - What's unclear: Should the test be renamed to reflect its new purpose (now it verifies unified status) or kept with the old name?
   - Recommendation: Update assertions (remove old asserts, add `"Support status: supported"` assert), optionally rename the function to `windows_setup_check_only_reports_unified_support_status` to reflect its new meaning.

## Environment Availability

Step 2.6: SKIPPED — Phase 2 is purely code and test changes within `crates/nono-cli/`. No external tools, services, or runtimes are introduced. Build and test use the existing Cargo workspace.

## Validation Architecture

`workflow.nyquist_validation` is absent from `.planning/config.json` — treated as enabled.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Cargo test (built-in Rust test runner) |
| Config file | `Cargo.toml` (workspace root), test file `crates/nono-cli/tests/env_vars.rs` |
| Quick run command | `cargo test -p nono-cli --lib` |
| Full suite command | `cargo test -p nono-cli` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CLIMSG-01 | `setup --check-only` emits one unified status line, no CLI/library split | integration | `cargo test -p nono-cli windows_setup_check_only` | ✅ (env_vars.rs — assertions need updating) |
| CLIMSG-02 | Live run banner routes through `print_sandbox_active` not Windows-specific dead branch | integration | `cargo test -p nono-cli windows_run_executes_basic_command` | ✅ (env_vars.rs — assertions need updating) |
| CLIMSG-03 | Shell/Wrap rejected unconditionally on Windows (not guarded by `is_supported`) | integration | `cargo test -p nono-cli windows_shell` or similar | ✅ (env_vars.rs) |
| CLIMSG-04 | All env_vars.rs Windows assertions use promoted wording | integration | `cargo test -p nono-cli` (full suite) | ✅ (env_vars.rs — surgical updates required) |

### Sampling Rate
- **Per task commit:** `cargo clippy -p nono-cli -- -D warnings`
- **Per wave merge:** `cargo test -p nono-cli`
- **Phase gate:** `cargo build -p nono-cli && cargo clippy -p nono-cli -- -D warnings && cargo test -p nono-cli`

### Wave 0 Gaps
None — existing test infrastructure covers all phase requirements. No new test files need to be created. The work is updating existing assertions in `env_vars.rs`.

## Project Constraints (from CLAUDE.md)

All of the following apply to PR-B changes:

- **No `.unwrap()` or `.expect()`:** Propagate errors via `?`. No new unwraps may be introduced.
- **No `#[allow(dead_code)]`:** Remove dead code — do not suppress warnings.
- **DCO sign-off on all commits:** Every commit must have `Signed-off-by: Name <email>`.
- **Path handling:** Use `Path::starts_with()` for path comparison — not string `starts_with()`. (Not directly relevant to PR-B changes, but applies to any incidental path code.)
- **No new panics in library code:** PR-B is CLI-only so this is less relevant, but the principle extends to CLI code.
- **Env var save/restore in tests:** Any test modifying `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, etc. must save and restore. (Not expected to be needed in PR-B test updates, but flag if a new test is written.)
- **Scope discipline:** `crates/nono/` is read-only for PR-B. Any temptation to rename `WindowsPreviewEntryPoint` etc. is deferred.

## Sources

### Primary (HIGH confidence)
- Direct code read: `crates/nono-cli/src/setup.rs` — `test_windows_support()` (line 184), `print_check_only_summary()` (line 741), `windows_cli_support_status_label()` (line 762)
- Direct code read: `crates/nono-cli/src/execution_runtime.rs` — `apply_pre_fork_sandbox()` (lines 16-62), `validate_windows_preview_direct_execution()` (lines 64-82), call site (lines 224-228)
- Direct code read: `crates/nono-cli/src/command_runtime.rs` — `run_shell()` (lines 47-119), `run_wrap()` (lines 121-190)
- Direct code read: `crates/nono-cli/src/output.rs` — `print_banner()`, `print_sandbox_active()`, `print_applying_sandbox()`, `print_supervised_info()`, `dry_run_summary()`
- Direct code read: `crates/nono-cli/tests/env_vars.rs` — specific assertion lines identified: 464-471, 492-498, 568-575, 2518-2525, 2571-2586
- Direct code read: `crates/nono/src/sandbox/mod.rs` — `SupportInfo::status_label()` returns `self.status.as_str()` = `"supported"` when `SupportStatus::Supported`
- Direct code read: `crates/nono/src/sandbox/windows.rs` — `WINDOWS_PREVIEW_SUPPORTED = true`, `support_info()` returns `SupportStatus::Supported`, `validate_preview_entry_point()` Shell/Wrap messages
- `.planning/phases/01-pr-a-library-contract/01-VERIFICATION.md` — confirmed PR-A complete: `is_supported=true`, `status_label()="supported"`, working tree clean

### Secondary (MEDIUM confidence)
- None needed — all claims verified from source code directly.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies; existing Cargo workspace
- Architecture: HIGH — all touch points verified by direct code read
- Pitfalls: HIGH — each pitfall derives from an observed code fact (dead branches seen in source, parameter scope confirmed in signature)

**Research date:** 2026-04-03
**Valid until:** 2026-05-03 (stable Rust codebase; validity is until next major refactor)
