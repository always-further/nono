# Phase 3: PR-C CI Verification - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Align `scripts/windows-test-harness.ps1`, `.github/workflows/ci.yml`, and `crates/nono-cli/src/cli.rs` to the promoted Windows support contract from PR-A/B. Scope is CI harness + CLI help strings only. `crates/nono/` is read-only. `crates/nono-cli/tests/env_vars.rs` assertions were updated in Phase 2 — this phase covers only the harness script, the CI YAML, and the `cli.rs` help strings and their tests. README and .mdx docs belong to PR-D.

</domain>

<decisions>
## Implementation Decisions

### cli.rs CLI_ABOUT wording (CIVER-01)
- **D-01:** Drop the Windows qualifier from `CLI_ABOUT` entirely. Replace:
  `"A capability-based shell for running untrusted AI agents and processes\nwith Windows restricted execution plus explicit command-surface limitations.\nUnsupported Windows flows fail closed instead of implying full sandbox parity."`
  with:
  `"A capability-based shell for running untrusted AI agents and processes with OS-enforced isolation.\nUnsupported flows fail closed instead of implying full sandbox parity."`
- **D-02:** `test_root_help_mentions_windows_restricted_execution_surface` assertion strings updated to match the new `CLI_ABOUT` text — the assertion that checked for `"Windows restricted execution plus explicit command-surface limitations"` is replaced with a check for `"OS-enforced isolation"` (or whatever the new about string contains). The test may optionally be renamed to reflect its new purpose.

### cli.rs "preview surface" command docs (CIVER-01)
- **D-03:** All 7 command help strings (lines 127, 149, 167, 191, 215, 259, 300 as of Phase 2 state) that say `"not implemented for the current Windows preview surface"` are replaced with `"not available on Windows"`. Each is a minimal surgical replacement — surrounding text unchanged.

### WFP privilege gate in harness + CI (CIVER-02)
- **D-04:** `ci.yml` sets env var `NONO_CI_HAS_WFP: true` in the `windows-security` job when running on a privileged runner (or via an expression that evaluates runner capability). On unprivileged runners or in PR builds where WFP access is not guaranteed, the var is absent or `false`.
- **D-05:** `windows-test-harness.ps1` security suite checks `$env:NONO_CI_HAS_WFP` before running the WFP tests (`windows_run_block_net_blocks_probe_connection` and `windows_run_block_net_cleans_up_promoted_wfp_filters_after_exit`). If the var is not `'true'`, the harness prints `"SKIPPED: WFP tests require elevated runner (NONO_CI_HAS_WFP not set)"` and exits 0 for that test group. No hard failure on unprivileged runners.

### Dead harness entry removal (CIVER-01)
- **D-06:** Remove `test_validate_windows_preview_direct_execution_allows_override_deny_when_policy_is_supported` from `$regressionTests` in `windows-test-harness.ps1`. This function was deleted in Phase 2 (Plan 01, Task 2). The harness entry is a dead reference that would fail the regression lane on any run.

### Claude's Discretion
- Whether to add `windows_setup_check_only_reports_unified_support_status` (added in Phase 2) to the `$smokeTests` array in the harness, and whether to also remove/keep `windows_setup_check_only_reports_live_profile_subset` (which still exists)
- Whether the `test_root_help_mentions_windows_restricted_execution_surface` test is renamed or only its assertion body is updated
- Exact `ci.yml` expression for `NONO_CI_HAS_WFP` (e.g., hardcoded `true` in the job env if the runner is always admin, or a secret/label-based expression)

</decisions>

<specifics>
## Specific Ideas

- The WFP gate pattern mirrors how other CI systems distinguish "elevated" from "standard" runners — an env var is the idiomatic approach because it keeps the harness testable locally (just set the var to skip WFP) and keeps the CI YAML as the single source of runner capability truth.
- `CLI_ABOUT` losing its Windows-specific sentence is intentional — after promotion, nono's root description should not call out Windows as a special case. The Windows-specific limitations (shell, wrap, ps, etc.) are still documented in subcommand help strings.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirements
- `.planning/REQUIREMENTS.md` — CIVER-01 and CIVER-02 (what each requirement demands)
- `.planning/ROADMAP.md` §Phase 3 — Success criteria (3 criteria, each independently verifiable)

### CI harness and YAML
- `scripts/windows-test-harness.ps1` — Full harness: all 5 suites (build/smoke/integration/security/regression), exact test filter strings, PowerShell structure
- `.github/workflows/ci.yml` — All Windows CI lane job definitions (windows-build, windows-smoke, windows-integration, windows-security, windows-regression, windows-packaging); how env vars are passed to harness steps

### CLI help strings and tests
- `crates/nono-cli/src/cli.rs` — `CLI_ABOUT` (line 13), 7 "preview surface" command doc strings (lines ~127, 149, 167, 191, 215, 259, 300), `test_root_help_mentions_windows_restricted_execution_surface` test (~line 2203)

### Prior phase context
- `.planning/phases/02-pr-b-cli-messaging/02-01-SUMMARY.md` — What Phase 2 Plan 01 deleted: `validate_windows_preview_direct_execution` function removed from `execution_runtime.rs`; this is why the regression harness entry is now dead
- `.planning/phases/02-pr-b-cli-messaging/02-02-SUMMARY.md` — What test functions were renamed in Phase 2 (env_vars.rs)
- `.planning/phases/02-pr-b-cli-messaging/02-VERIFICATION.md` — Pre-existing `query_ext` unit test failure documented; unrelated to Phase 3 scope

### Project guidelines
- `CLAUDE.md` — Coding standards: no `#[allow(dead_code)]`, no `.unwrap()`, env var save/restore in tests, DCO sign-off on commits
- `proj/DESIGN-library.md` — Library/CLI boundary: `crates/nono/` is read-only for this phase

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `Invoke-TestList` function in harness — existing pattern for conditionally running test batches; WFP gate wraps this call, not the function itself
- `Invoke-LoggedCommand` — existing pattern for non-cargo commands; if the privilege check uses a scriptblock, same pattern applies

### Established Patterns
- All 5 harness suites follow the same `Invoke-TestList` / `Invoke-LoggedCargo` pattern — privilege check is a guard block before the `Invoke-TestList` call for WFP-specific tests
- `ci.yml` uses `env:` blocks per-job for test configuration — `NONO_CI_HAS_WFP` follows the same pattern as `CARGO_TERM_COLOR` and `RUSTFLAGS` in the existing jobs

### Integration Points
- `windows-security` job in `ci.yml` → `windows-test-harness.ps1 -Suite security` → `$securityTests` array → WFP test entries
- `cli.rs:CLI_ABOUT` const → `Cli::command()` → help output text → `test_root_help_mentions_windows_restricted_execution_surface` assertion

</code_context>

<deferred>
## Deferred Ideas

- Renaming `WindowsPreviewEntryPoint`, `WindowsPreviewContext`, `validate_preview_entry_point` in `crates/nono/` — library API renaming post all four PRs merged; explicitly deferred per Phase 2 CONTEXT.md
- Updating "Windows preview" in test function names in `env_vars.rs` beyond what was renamed in Phase 2 — these are error message strings, not CI assertion strings; cosmetic and deferred
- README and .mdx docs language flip — belongs to PR-D (Phase 4)

</deferred>

---

*Phase: 03-pr-c-ci-verification*
*Context gathered: 2026-04-03*
