# Phase 2: PR-B CLI Messaging - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Remove the CLI/library support split from all runtime output; `setup --check-only` emits one unified Windows support line; CLI runtime validation routes through the library's now-authoritative `support_info()`; `nono shell` and `nono wrap` remain hard-rejected on Windows. Scope is `crates/nono-cli/` only (library API unchanged). CI lane updates and docs flip belong to PR-C and PR-D respectively.

</domain>

<decisions>
## Implementation Decisions

### Unified status line (CLIMSG-01)
- **D-01:** Drop `windows_cli_support_status_label()` entirely — function is removed.
- **D-02:** In `setup.rs:test_windows_support()`, replace the two-line `"CLI support status"` / `"Library support status"` pattern with a single line: `"  * Support status: {info.status_label()}"`.
- **D-03:** Same collapse in `setup.rs:print_check_only_summary()` — one `"Support status: {info.status_label()}"` line, `info.details` printed separately as before.
- **D-04:** `info.status_label()` is the single source of truth for Windows support status in all setup output.

### Runtime banner after promotion (CLIMSG-02 / CLIMSG-04)
- **D-05:** Remove the Windows-specific `!support.is_supported` branch in `apply_pre_fork_sandbox()` in `execution_runtime.rs`. This branch is dead code after PR-A and was the source of "Windows restricted execution covers the current supported command surface".
- **D-06:** After removing the dead branch, Windows live-run follows the same path as Linux/macOS: `output::print_applying_sandbox(silent)` and `output::print_sandbox_active(silent)` are called — no Windows-specific banner text.
- **D-07:** In `env_vars.rs`, the assertion `text.contains("Windows restricted execution covers the current supported command surface")` is **removed**. The assertion `!text.contains("first-class supported")` is **removed**. New assertion added: `text.contains("Sandbox active")` (or the exact string `print_sandbox_active` produces). Each assertion is updated surgically — none deleted wholesale.
- **D-08:** The dry-run assertion `text.contains("current Windows command surface without claiming full parity")` also needs surgical update — it comes from `output::print_dry_run` Windows path, which should be checked and aligned.

### Shell/Wrap unconditional rejection (CLIMSG-03)
- **D-09:** Remove the `if !Sandbox::support_info().is_supported {` guard in `command_runtime.rs:run_shell()` (line ~78). The `#[cfg(target_os = "windows")]` block calling `validate_windows_preview_entry_point(Shell, ...)` fires unconditionally.
- **D-10:** Same for `command_runtime.rs:run_wrap()` (line ~149): remove `if !Sandbox::support_info().is_supported {` guard. Rejection is unconditional.
- **D-11:** The library's rejection messages for Shell and Wrap already say "intentionally unavailable on Windows" — these messages are NOT changed in PR-B (they're library-owned and already correct post-PR-A).

### Dead code removal (scope: PR-B)
- **D-12:** Remove `validate_windows_preview_direct_execution()` function from `execution_runtime.rs` entirely (it always returned `Ok(())` after PR-A — `is_supported` is now `true`, so the `validate_windows_preview_entry_point(RunDirect, ...)` call inside it never fired).
- **D-13:** Remove the call site of `validate_windows_preview_direct_execution` at line ~226 in `execution_runtime.rs`.
- **D-14:** The `apply_pre_fork_sandbox()` function's Windows-specific `!support.is_supported` branch (lines ~22-43) is removed as part of D-05 — this is the same cleanup.

### Test assertion strategy (CLIMSG-04)
- **D-15:** Every `env_vars.rs` assertion updated **individually** — no assertion block deleted wholesale. Old string → new string, or old negative guard → affirmative (or removed if no longer meaningful).
- **D-16:** After cleanup, no `env_vars.rs` test asserts "preview" language, "restricted command surface", "CLI support status", "Library support status", or explicitly checks that "first-class supported" is absent.

### Claude's Discretion
- Exact string `print_sandbox_active` produces (already defined in `output.rs` — use whatever it currently says)
- Whether to add a Windows-specific note to the dry-run output summary or just use the cross-platform path
- Order of assertions in updated test functions (preserve logical grouping)

</decisions>

<specifics>
## Specific Ideas

- The `windows_cli_support_status_label()` function in `setup.rs` (line ~762) is the only remaining standalone Windows-CLI-specific support label — its removal is the primary CLIMSG-01 fix.
- The `apply_pre_fork_sandbox` dead branch was the origin of the "Windows restricted execution" string in integration test assertions — removing the branch automatically eliminates the string source.
- Shell/Wrap rejection is a **security correctness fix** (not just messaging): the bypass via `!is_supported` gate meant `nono shell` could execute on promoted Windows without enforcement — CLIMSG-03 closes this.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirements
- `.planning/REQUIREMENTS.md` — CLIMSG-01 through CLIMSG-04 (what each requirement demands)
- `.planning/ROADMAP.md` §Phase 2 — Success criteria (4 criteria, each independently verifiable)

### CLI messaging code
- `crates/nono-cli/src/setup.rs` — `test_windows_support()`, `print_check_only_summary()`, `windows_cli_support_status_label()` (primary CLIMSG-01 touch points)
- `crates/nono-cli/src/execution_runtime.rs` — `apply_pre_fork_sandbox()`, `validate_windows_preview_direct_execution()` (dead code removal)
- `crates/nono-cli/src/command_runtime.rs` — `run_shell()`, `run_wrap()` (CLIMSG-03 gate fix, lines ~77-87 and ~148-158)
- `crates/nono-cli/src/output.rs` — `print_sandbox_active()`, `print_applying_sandbox()`, `print_dry_run()` (what strings the planner needs to assert)

### Test contract
- `crates/nono-cli/tests/env_vars.rs` — All Windows integration tests with assertions to update (CLIMSG-04)

### Library API (read-only — do not modify)
- `crates/nono/src/sandbox/windows.rs` — `validate_preview_entry_point()` rejection messages for Shell/Wrap (these stay as-is), `validate_preview_entry_point(RunDirect, ...)` path
- `crates/nono/src/sandbox/mod.rs` — `support_info()`, `SupportInfo::status_label()` return values (what the unified status line will display)

### Prior phase context
- `.planning/phases/01-pr-a-library-contract/01-02-PLAN.md` — What PR-A changed in `sandbox/mod.rs` and `sandbox/windows.rs` (apply(), is_supported(), support_info())
- `.planning/phases/01-pr-a-library-contract/01-VERIFICATION.md` — Verified contract: what `support_info().status_label()` returns and what `is_supported()` returns on Windows post-PR-A

### Project guidelines
- `CLAUDE.md` — Coding standards: no #[allow(dead_code)], no .unwrap(), env var save/restore in tests, DCO sign-off on commits
- `proj/DESIGN-library.md` — Library/CLI boundary: library is policy-free, CLI owns all messaging and policy

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `output::print_sandbox_active(silent)` — Already exists, already called on Linux/macOS after sandbox applied. Windows will call this same function after the dead branch is removed.
- `nono::Sandbox::support_info()` — Already imported and used throughout CLI. `info.status_label()` is the string the unified status line needs.

### Established Patterns
- All other CLI platforms (Linux, macOS) call `print_applying_sandbox` → `Sandbox::apply(caps)?` → `print_sandbox_active` in sequence. Windows will follow this same pattern after dead code removal.
- `#[cfg(target_os = "windows")]` blocks: the pattern for Windows-only code. Shell/Wrap rejections use this — removing the `if !is_supported` guard keeps the `#[cfg]` wrapper.

### Integration Points
- `execution_runtime.rs:apply_pre_fork_sandbox()` — the fork in the road between Windows dead-branch and cross-platform sandbox path. Removing the dead branch merges Windows into the cross-platform flow.
- `command_runtime.rs` shell/wrap functions — The rejection must fire **before** `execute_sandboxed()` is called. Current position (after `prepare_sandbox`) is correct — the guard removal preserves this.

</code_context>

<deferred>
## Deferred Ideas

- Renaming `WindowsPreviewEntryPoint`, `WindowsPreviewContext`, `validate_preview_entry_point` in the library to remove "preview" from names — these are library API changes and belong after all four PRs are merged, not in PR-B.
- Updating the dry-run "without claiming full parity" message in `output::print_dry_run` to promoted language — if this string comes from library-controlled output, that's library scope; if CLI-controlled, it's in scope for CLIMSG-04 but should be confirmed before touching.

</deferred>

---

*Phase: 02-pr-b-cli-messaging*
*Context gathered: 2026-04-03*
