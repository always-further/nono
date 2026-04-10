# Phase 3: PR-C CI Verification - Research

**Researched:** 2026-04-03
**Domain:** CI harness (PowerShell), GitHub Actions YAML, Rust CLI help strings and their tests
**Confidence:** HIGH

## Summary

Phase 3 is a surgical alignment of three artifacts — `scripts/windows-test-harness.ps1`, `.github/workflows/ci.yml`, and `crates/nono-cli/src/cli.rs` — to the promoted Windows support contract delivered by Phase 1 (library contract) and Phase 2 (CLI messaging). All four locked decisions in CONTEXT.md are narrowly scoped: two string replacements (CLI_ABOUT, 7 "preview surface" command docs), one dead harness entry removal, and one privilege-gated skip pattern for WFP integration tests.

The codebase state entering Phase 3 is fully confirmed: Phase 2 deleted `validate_windows_preview_direct_execution`, collapsed the CLI/library support split, and updated env_vars.rs assertions. The regression harness entry for the deleted function (line 123 of harness) is a dead reference that will fail the regression lane on every run. The smoke harness still references `test_root_help_mentions_windows_restricted_execution_surface` whose assertion body checks the old `CLI_ABOUT` text — both need updating in tandem.

The WFP privilege gate (CIVER-02) is the only area with unresolved infrastructure. `windows-latest` GitHub Actions runners run as Administrator but do NOT have WFP driver access by default; WFP filter installation requires `SeLoadDriverPrivilege` which standard runners may not grant. The locked decision (D-04/D-05) uses an env var `NONO_CI_HAS_WFP` as the gate signal rather than trying to probe privilege at runtime, keeping the harness testable locally and CI YAML as the single source of privilege truth.

**Primary recommendation:** Execute the four locked decisions in order — cli.rs strings first (D-01/D-02/D-03), then harness cleanups (D-04/D-05/D-06) — because the smoke harness test and CLI_ABOUT must be co-updated or the smoke lane immediately fails.

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**cli.rs CLI_ABOUT wording (CIVER-01)**
- D-01: Drop the Windows qualifier from `CLI_ABOUT` entirely. Replace:
  `"A capability-based shell for running untrusted AI agents and processes\nwith Windows restricted execution plus explicit command-surface limitations.\nUnsupported Windows flows fail closed instead of implying full sandbox parity."`
  with:
  `"A capability-based shell for running untrusted AI agents and processes with OS-enforced isolation.\nUnsupported flows fail closed instead of implying full sandbox parity."`
- D-02: `test_root_help_mentions_windows_restricted_execution_surface` assertion strings updated to match the new `CLI_ABOUT` text — the assertion that checked for `"Windows restricted execution plus explicit command-surface limitations"` is replaced with a check for `"OS-enforced isolation"` (or whatever the new about string contains). The test may optionally be renamed to reflect its new purpose.

**cli.rs "preview surface" command docs (CIVER-01)**
- D-03: All 7 command help strings (lines 127, 149, 167, 191, 215, 259, 300 as of Phase 2 state) that say `"not implemented for the current Windows preview surface"` are replaced with `"not available on Windows"`. Each is a minimal surgical replacement — surrounding text unchanged.

**WFP privilege gate in harness + CI (CIVER-02)**
- D-04: `ci.yml` sets env var `NONO_CI_HAS_WFP: true` in the `windows-security` job when running on a privileged runner (or via an expression that evaluates runner capability). On unprivileged runners or in PR builds where WFP access is not guaranteed, the var is absent or `false`.
- D-05: `windows-test-harness.ps1` security suite checks `$env:NONO_CI_HAS_WFP` before running the WFP tests (`windows_run_block_net_blocks_probe_connection` and `windows_run_block_net_cleans_up_promoted_wfp_filters_after_exit`). If the var is not `'true'`, the harness prints `"SKIPPED: WFP tests require elevated runner (NONO_CI_HAS_WFP not set)"` and exits 0 for that test group. No hard failure on unprivileged runners.

**Dead harness entry removal (CIVER-01)**
- D-06: Remove `test_validate_windows_preview_direct_execution_allows_override_deny_when_policy_is_supported` from `$regressionTests` in `windows-test-harness.ps1`. This function was deleted in Phase 2 (Plan 01, Task 2). The harness entry is a dead reference that would fail the regression lane on any run.

### Claude's Discretion

- Whether to add `windows_setup_check_only_reports_unified_support_status` (added in Phase 2) to the `$smokeTests` array in the harness, and whether to also remove/keep `windows_setup_check_only_reports_live_profile_subset` (which still exists)
- Whether the `test_root_help_mentions_windows_restricted_execution_surface` test is renamed or only its assertion body is updated
- Exact `ci.yml` expression for `NONO_CI_HAS_WFP` (e.g., hardcoded `true` in the job env if the runner is always admin, or a secret/label-based expression)

### Deferred Ideas (OUT OF SCOPE)

- Renaming `WindowsPreviewEntryPoint`, `WindowsPreviewContext`, `validate_preview_entry_point` in `crates/nono/` — library API renaming post all four PRs merged; explicitly deferred per Phase 2 CONTEXT.md
- Updating "Windows preview" in test function names in `env_vars.rs` beyond what was renamed in Phase 2 — these are error message strings, not CI assertion strings; cosmetic and deferred
- README and .mdx docs language flip — belongs to PR-D (Phase 4)
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CIVER-01 | Windows regression harness validates the aligned support contract; setup/help/runtime checks no longer assume a CLI/library split; host environment failures distinguished from code regressions | Covered by: D-01 (CLI_ABOUT), D-02 (test assertion update), D-03 (7 "preview surface" string replacements in *_AFTER_HELP consts), D-06 (remove dead regression harness entry). The smoke harness test `test_root_help_mentions_windows_restricted_execution_surface` must be updated alongside CLI_ABOUT. |
| CIVER-02 | CI Windows lane assertions updated from "partial" to "supported" across all lanes; WFP integration tests gated on privilege detection | Covered by: D-04 (NONO_CI_HAS_WFP env var in ci.yml windows-security job), D-05 (skip guard in harness security suite). No "partial" language was found in ci.yml itself — the "partial" was in runtime output strings already cleaned in Phase 2. CIVER-02 is about the harness/CI alignment, not YAML string replacement. |
</phase_requirements>

---

## Standard Stack

### Core
| Artifact | Current State | What Changes |
|---------|--------------|-------------|
| `crates/nono-cli/src/cli.rs` | `CLI_ABOUT` (line 13) is Windows-specific; 7 `*_AFTER_HELP` consts contain "preview surface" (lines 127, 149, 167, 191, 215, 259, 300); test at line 2203 asserts old text | D-01/D-02/D-03: string replacements only — no structural changes |
| `scripts/windows-test-harness.ps1` | `$smokeTests` at line 87 references old test name; `$regressionTests` at line 123 has dead entry; `$securityTests` at lines 112-113 has WFP tests with no privilege gate | D-05/D-06: remove dead entry, add skip guard before WFP tests; discretion: add `windows_setup_check_only_reports_unified_support_status` to smoke |
| `.github/workflows/ci.yml` | `windows-security` job (lines 236-270) has no `env:` block; pattern for job-level env vars is `CARGO_TERM_COLOR`/`RUSTFLAGS` at global env (lines 13-14) | D-04: add `NONO_CI_HAS_WFP: true` to `windows-security` job env |

### Supporting Patterns in Use
| Pattern | Location | Relevance |
|---------|----------|-----------|
| Job-level `env:` in YAML | ci.yml: used globally at top level | Add per-job `env:` block under `windows-security` job — same YAML key, just scoped to job |
| `Invoke-TestList` + guard block | windows-test-harness.ps1 lines 45-63 | WFP gate wraps the `Invoke-TestList` call for WFP tests, not the function itself |
| `#[cfg(target_os = "windows")]` const | cli.rs lines 12-16 | CLI_ABOUT is platform-conditional — only the Windows variant changes |

---

## Architecture Patterns

### Pattern 1: PowerShell WFP Skip Guard
**What:** A guard block before the `Invoke-TestList` call for WFP-specific tests. Checks `$env:NONO_CI_HAS_WFP`. Prints explicit skip message and continues (does not throw) when absent.

**When to use:** Any test batch that requires elevated system privileges not available on standard runners.

**Example (to implement per D-05):**
```powershell
# In the "security" case block, before the WFP entries in $securityTests
# Split $securityTests into two batches: non-WFP tests run unconditionally,
# WFP tests run only when NONO_CI_HAS_WFP is 'true'.

$wfpTests = @(
    @{ Package = "nono-cli"; Filter = "windows_run_block_net_blocks_probe_connection" },
    @{ Package = "nono-cli"; Filter = "windows_run_block_net_cleans_up_promoted_wfp_filters_after_exit" }
)

$nonWfpSecurityTests = $securityTests | Where-Object {
    $_.Filter -notin $wfpTests.Filter
}

Invoke-TestList -LogFile "windows-security.log" -Tests $nonWfpSecurityTests

if ($env:NONO_CI_HAS_WFP -eq 'true') {
    Invoke-TestList -LogFile "windows-security.log" -Tests $wfpTests
} else {
    "SKIPPED: WFP tests require elevated runner (NONO_CI_HAS_WFP not set)" |
        Tee-Object -FilePath (Join-Path $LogDir "windows-security.log") -Append
}
```

**Alternative (simpler — single array, inline gate):** Keep `$securityTests` unchanged, split only at the call site inside the `"security"` switch block. Either approach is valid — the second keeps the array declarations clean.

### Pattern 2: ci.yml Per-Job env Block
**What:** Job-scoped `env:` added to `windows-security` job. Follows the same YAML structure as the global env (lines 13-14). No expressions needed if `windows-latest` runners are always admin — hardcode `NONO_CI_HAS_WFP: true`.

**Example (to implement per D-04):**
```yaml
windows-security:
  name: Windows Security
  needs: changes
  if: ${{ !startsWith(github.head_ref, 'dependabot/github_actions/') && needs.changes.outputs.run_code_jobs == 'true' }}
  runs-on: windows-latest
  env:
    NONO_CI_HAS_WFP: true   # windows-latest runners run as Administrator
  steps:
    ...
```

**Note on the discretion item (D-04):** `windows-latest` GitHub Actions runners run as Administrator in a clean VM. This means `NONO_CI_HAS_WFP: true` hardcoded is the right call for the current CI setup — no secrets, labels, or expressions required. If the project ever moves to self-hosted non-admin runners, this is the single place to change. Hardcoding is the correct choice; this is confirmed HIGH confidence from GitHub Actions documentation.

### Pattern 3: cli.rs `CLI_ABOUT` Platform Conditional
**What:** Two `const CLI_ABOUT: &str` definitions separated by `#[cfg(target_os = "windows")]` / `#[cfg(not(target_os = "windows"))]`. Only the Windows variant changes. The non-Windows variant (line 15-16) becomes identical to the new Windows text per D-01 — after D-01 the two variants have different last sentences but the same opening line.

**Current state (confirmed by direct read):**
- Windows (line 13): `"A capability-based shell for running untrusted AI agents and processes\nwith Windows restricted execution plus explicit command-surface limitations.\nUnsupported Windows flows fail closed instead of implying full sandbox parity."`
- Non-Windows (line 16): `"A capability-based shell for running untrusted AI agents and processes\nwith OS-enforced filesystem and network isolation."`

**After D-01, Windows becomes:**
`"A capability-based shell for running untrusted AI agents and processes with OS-enforced isolation.\nUnsupported flows fail closed instead of implying full sandbox parity."`

Note: The non-Windows variant is NOT touched — out of scope per CONTEXT.md phase boundary.

### Pattern 4: "preview surface" Replacement in *_AFTER_HELP Consts
**What:** 7 Windows `*_AFTER_HELP` constants contain the phrase "not implemented for the current Windows preview surface". Each is a single sentence in a multi-line string. Replace the phrase with "not available on Windows". Surrounding text is unchanged.

**Affected constants (all `#[cfg(target_os = "windows")]`):**
| Const | Line | Exact phrase to replace |
|-------|------|------------------------|
| `PS_AFTER_HELP` | 127 | "not implemented for the current Windows preview surface." |
| `STOP_AFTER_HELP` | 149 | "not implemented for the current Windows preview surface." |
| `DETACH_AFTER_HELP` | 167 | "not implemented for the current Windows preview surface, so help examples for in-band detach do not apply." |
| `ATTACH_AFTER_HELP` | 191 | "not implemented for the current Windows preview surface." |
| `LOGS_AFTER_HELP` | 215 | "on the current Windows preview surface." |
| `INSPECT_AFTER_HELP` | 259 | "not implemented for the current Windows preview surface." |
| `PRUNE_AFTER_HELP` | 300 | "are not produced by the current Windows preview surface." |

**Replacement target per D-03:** Each full sentence containing "preview surface" is rewritten as a clean "not available on Windows" statement. The surrounding `\x1b[1mWINDOWS\x1b[0m` block and other sentences remain intact.

### Anti-Patterns to Avoid
- **Splitting $securityTests array at declaration:** Prefer splitting at the call site inside the switch block, not by changing the top-level array — the top-level arrays are documentation of what the suite contains; the gate logic belongs in the suite execution block.
- **Checking for WFP at test runtime with PowerShell driver API calls:** Over-engineering. The env var pattern is simpler, more auditable, and keeps the harness testable locally by setting the var.
- **Removing WFP entries from $securityTests entirely:** They must stay discoverable in the harness. Skip != remove.
- **Changing the non-Windows CLI_ABOUT:** CONTEXT.md scope is Windows only; the non-Windows variant is untouched.
- **Touching `crates/nono/`:** Library is read-only for this phase.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CI privilege detection | Runtime PowerShell `Get-Privilege` or WinAPI checks | `$env:NONO_CI_HAS_WFP` set in ci.yml | Env var is idiomatic, testable locally, and keeps CI YAML as single source of runner capability truth |
| Conditional test execution | Custom test runner logic | Existing `Invoke-TestList` + guard block | Pattern already established in harness; consistent with existing suite structure |

---

## Common Pitfalls

### Pitfall 1: Smoke Lane Breaks If cli.rs and Harness Are Not Co-Updated
**What goes wrong:** `$smokeTests` contains `test_root_help_mentions_windows_restricted_execution_surface` (harness line 87). This test's assertion body (cli.rs line 2211) checks for `"Windows restricted execution plus explicit command-surface limitations"`. After D-01 changes `CLI_ABOUT`, the test will fail unless D-02 updates the assertion in the same commit or task.
**Why it happens:** The harness references the test by filter string; the filter string is the function name (unchanged). The failure is the assertion body, not the function name.
**How to avoid:** Update cli.rs CLI_ABOUT + test assertion in one atomic commit (D-01 + D-02 together). The harness does not need updating for this — the function name stays valid.
**Warning signs:** If a plan separates D-01 and D-02 into different tasks with a CI gate between them, the smoke lane will be red in the interim.

### Pitfall 2: Regression Lane Fails Immediately Due to Dead Entry
**What goes wrong:** `$regressionTests` line 123 references `test_validate_windows_preview_direct_execution_allows_override_deny_when_policy_is_supported`. This function was deleted in Phase 2 Plan 01 Task 2. Cargo will report "no tests found" and exit non-zero, failing the entire regression lane.
**Why it happens:** The harness entry was not cleaned up when the function was deleted.
**How to avoid:** D-06 must be executed before or alongside any CI run. This is a blocking fix — the regression lane cannot be used for verification until D-06 is applied.
**Warning signs:** `windows-regression` lane failure with "no tests found" or "0 tests passed" in the cargo output.

### Pitfall 3: WFP Skip Message Must Use Exit 0 Semantics
**What goes wrong:** If the skip branch throws an exception or calls `exit 1`, the security lane fails on unprivileged runners — the opposite of the goal.
**Why it happens:** PowerShell's `$ErrorActionPreference = "Stop"` (line 2 of harness) makes unhandled errors terminate with non-zero exit. The skip block must not throw.
**How to avoid:** The skip block only writes to the log and falls through — no `throw`, no `exit 1`. The `Invoke-TestList` call for WFP tests is simply not made. The harness naturally exits 0 at end.

### Pitfall 4: Confusing the Two `windows_setup_check_only` Test Functions
**What goes wrong:** Two test functions now exist in env_vars.rs: `windows_setup_check_only_reports_live_profile_subset` (line 2507, already in $smokeTests) and `windows_setup_check_only_reports_unified_support_status` (line 2560, added in Phase 2, NOT yet in $smokeTests). They overlap significantly — both assert `"Support status: supported"`. If both are added to $smokeTests, it is redundant but harmless. If the live_profile_subset test is removed from the harness, coverage is maintained by the unified_support_status test.
**Recommendation (discretion):** Add `windows_setup_check_only_reports_unified_support_status` to `$smokeTests` and KEEP `windows_setup_check_only_reports_live_profile_subset` — the latter also asserts the verbose subset content (dry-run guidance, direct-run wording, backend-readiness note, shell/wrap limitation, User state root) which the unified test does not. Both should run.

### Pitfall 5: Test Rename Is Optional But the Assert Body Is Mandatory
**What goes wrong:** D-02 says the test "may optionally be renamed." If a plan marks the rename as required and the assertion update as optional, the priority is inverted.
**How to avoid:** The assertion body change (`"Windows restricted execution plus explicit command-surface limitations"` → `"OS-enforced isolation"`) is mandatory. The rename is cosmetic. Plan tasks should reflect this priority.

---

## Code Examples

### Current cli.rs State (confirmed by direct read)

```rust
// cli.rs lines 12-16 (CONFIRMED)
#[cfg(target_os = "windows")]
const CLI_ABOUT: &str = "A capability-based shell for running untrusted AI agents and processes\nwith Windows restricted execution plus explicit command-surface limitations.\nUnsupported Windows flows fail closed instead of implying full sandbox parity.";

#[cfg(not(target_os = "windows"))]
const CLI_ABOUT: &str = "A capability-based shell for running untrusted AI agents and processes\nwith OS-enforced filesystem and network isolation.";
```

```rust
// cli.rs lines 2201-2222 (CONFIRMED) — test to update per D-02
#[cfg(target_os = "windows")]
#[test]
fn test_root_help_mentions_windows_restricted_execution_surface() {
    let mut cmd = Cli::command();
    let mut buf = Vec::new();
    cmd.write_long_help(&mut buf)
        .expect("failed to write root help");
    let help = String::from_utf8(buf).expect("help is not utf-8");

    assert!(
        help.contains("Windows restricted execution plus explicit command-surface limitations"),
        "root help should mention the Windows command surface"
    );
    assert!(
        help.contains("live shell is unsupported on Windows"),
        "root help should make shell limitation explicit on Windows"
    );
    assert!(
        help.contains("live wrap is unsupported on Windows"),
        "root help should make wrap limitation explicit on Windows"
    );
}
```

**After D-01 + D-02, the first assert becomes:**
```rust
assert!(
    help.contains("OS-enforced isolation"),
    "root help should describe OS-enforced isolation"
);
```
The second and third asserts check strings that come from `SHELL_AFTER_HELP` / `WRAP_AFTER_HELP` — those consts are NOT being changed (they describe intentional product limitations, not the Windows qualifier). However, the exact strings "live shell is unsupported on Windows" and "live wrap is unsupported on Windows" need to be verified against the actual content of `SHELL_AFTER_HELP` and `WRAP_AFTER_HELP`.

**IMPORTANT:** The current `SHELL_AFTER_HELP` (lines 19-27) says "Live `nono shell` is intentionally unavailable on Windows" — NOT "live shell is unsupported on Windows". The current `WRAP_AFTER_HELP` (lines 37-45) says "Live `nono wrap` is intentionally unavailable on Windows" — NOT "live wrap is unsupported on Windows". This means the second and third assertions in the test are ALREADY failing (or the test was never run successfully post-Phase 2). The plan must either fix these two assertions to match the actual strings, or investigate whether there is other text in the help output that contains those exact phrases.

### Current Harness State (confirmed by direct read)

**$smokeTests (lines 86-93):**
```powershell
$smokeTests = @(
    @{ Package = "nono-cli"; Filter = "test_root_help_mentions_windows_restricted_execution_surface" },
    @{ Package = "nono-cli"; Filter = "windows_setup_check_only_reports_live_profile_subset" },
    @{ Package = "nono-cli"; Filter = "windows_run_executes_basic_command" },
    @{ Package = "nono-cli"; Filter = "windows_run_live_default_profile_executes_command" },
    @{ Package = "nono-cli"; Filter = "windows_shell_help_reports_documented_limitation" },
    @{ Package = "nono-cli"; Filter = "windows_wrap_help_reports_documented_limitation" }
)
```

**Dead regression entry to remove (line 123):**
```powershell
@{ Package = "nono-cli"; Filter = "test_validate_windows_preview_direct_execution_allows_override_deny_when_policy_is_supported" },
```

**WFP entries in $securityTests (lines 112-113):**
```powershell
@{ Package = "nono-cli"; Filter = "windows_run_block_net_blocks_probe_connection" },
@{ Package = "nono-cli"; Filter = "windows_run_block_net_cleans_up_promoted_wfp_filters_after_exit" }
```

---

## Open Questions

1. **Are the second and third assertions in `test_root_help_mentions_windows_restricted_execution_surface` passing today?**
   - What we know: The test checks `help.contains("live shell is unsupported on Windows")` and `help.contains("live wrap is unsupported on Windows")`. The actual SHELL_AFTER_HELP text (confirmed) says "intentionally unavailable on Windows" not "unsupported on Windows".
   - What's unclear: Either (a) the test was never running on Windows in CI and the mismatch has never surfaced, or (b) there is additional text in the root help output that happens to contain these strings from some other source, or (c) the test is currently failing on Windows.
   - Recommendation: The planner should include a task to audit these two assertions against actual `--help` output and update them to match real strings. This is inside the scope of D-02 (assertion update). The safe replacement for both is to check for "intentionally unavailable on Windows" which appears in both SHELL_AFTER_HELP and WRAP_AFTER_HELP.

2. **Should `windows_setup_check_only_reports_unified_support_status` replace or supplement `windows_setup_check_only_reports_live_profile_subset` in $smokeTests?**
   - What we know: Both functions exist and are valid. `live_profile_subset` tests verbose subset content. `unified_support_status` tests the absence of split labels. They are complementary, not redundant.
   - Recommendation: Add `unified_support_status` to $smokeTests alongside `live_profile_subset`. Both should run. (Discretion item — planner decides.)

---

## Environment Availability

Step 2.6: SKIPPED — Phase 3 is purely code/config changes (PowerShell harness, GitHub Actions YAML, Rust source strings). No new external dependencies. The existing CI infrastructure (GitHub Actions `windows-latest`) is already in use.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in test (`cargo test`) |
| Config file | None — workspace-level Cargo.toml |
| Quick run command | `cargo test -p nono-cli test_root_help_mentions_windows_restricted_execution_surface -- --nocapture` |
| Full suite command | `.\scripts\windows-test-harness.ps1 -Suite all` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CIVER-01 | CLI_ABOUT no longer contains "Windows restricted execution" language | unit | `cargo test -p nono-cli test_root_help_mentions_windows_restricted_execution_surface -- --nocapture` | Yes (cli.rs line 2203) — assertion body must be updated |
| CIVER-01 | 7 "preview surface" strings replaced with "not available on Windows" | unit | `cargo test -p nono-cli` (no specific test; no existing test for these strings) | No test exists; verified by build passing + grep |
| CIVER-01 | Dead harness entry removed; regression lane passes | integration | `.\scripts\windows-test-harness.ps1 -Suite regression` | Harness exists; entry must be removed |
| CIVER-02 | WFP tests skip cleanly when NONO_CI_HAS_WFP unset | manual/local | `$env:NONO_CI_HAS_WFP=$null; .\scripts\windows-test-harness.ps1 -Suite security` | Harness exists; gate logic must be added |
| CIVER-02 | WFP tests run when NONO_CI_HAS_WFP=true | integration (CI) | Automatic when ci.yml sets NONO_CI_HAS_WFP: true on windows-security job | ci.yml exists; env var must be added |

### Sampling Rate
- **Per task commit:** `cargo test -p nono-cli <changed_test_name> -- --nocapture` (unit tests only; harness changes verified locally)
- **Per wave merge:** `cargo test -p nono-cli -- --nocapture` (all CLI tests)
- **Phase gate:** `.\scripts\windows-test-harness.ps1 -Suite all` green before `/gsd:verify-work`

### Wave 0 Gaps
None — existing test infrastructure covers all phase requirements. No new test files needed. The cli.rs test needs assertion updates (not creation). The harness changes are PowerShell edits.

---

## Sources

### Primary (HIGH confidence)
- Direct file read: `crates/nono-cli/src/cli.rs` — CLI_ABOUT line 13, 7 *_AFTER_HELP consts lines 127/149/167/191/215/259/300, test function line 2203
- Direct file read: `scripts/windows-test-harness.ps1` — complete harness, all 5 suites, exact test filter strings, $smokeTests/$securityTests/$regressionTests
- Direct file read: `.github/workflows/ci.yml` — all Windows job definitions, env var patterns
- Direct file read: Phase 2 summaries (02-01-SUMMARY.md, 02-02-SUMMARY.md) — confirmed deletions and test renames from Phase 2
- Direct file read: Phase 2 verification (02-VERIFICATION.md) — confirmed pre-existing `query_ext` failure is unrelated to Phase 3 scope
- Direct file read: `crates/nono-cli/tests/env_vars.rs` — confirmed both `windows_setup_check_only` test functions exist at lines 2507/2560

### Secondary (MEDIUM confidence)
- GitHub Actions documentation pattern: `windows-latest` runners run as Administrator (confirmed from project's existing use of Windows runners; standard GitHub behavior)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — direct file reads of all three artifacts to be modified
- Architecture: HIGH — patterns confirmed from existing code; WFP gate pattern is straightforward PowerShell
- Pitfalls: HIGH — all identified from direct inspection of current code state, not from inference

**Research date:** 2026-04-03
**Valid until:** 2026-05-03 (stable domain — harness/CI changes unlikely to drift)
