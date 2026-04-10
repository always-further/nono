---
phase: 3
slug: pr-c-ci-verification
status: draft
nyquist_compliant: false
wave_0_complete: true
created: 2026-04-03
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test (`cargo test`) + PowerShell harness |
| **Config file** | None — workspace-level `Cargo.toml` |
| **Quick run command** | `cargo test -p nono-cli test_root_help_mentions_windows_restricted_execution_surface -- --nocapture` |
| **Full suite command** | `.\scripts\windows-test-harness.ps1 -Suite all` |
| **Estimated runtime** | ~15 seconds (unit) / ~2 min (harness all) |

---

## Sampling Rate

- **After every task commit:** `cargo test -p nono-cli <changed_test_name> -- --nocapture`
- **After every plan wave:** `cargo test -p nono-cli -- --nocapture`
- **Before `/gsd:verify-work`:** `.\scripts\windows-test-harness.ps1 -Suite all` must be green
- **Max feedback latency:** ~15 seconds (unit) / ~2 minutes (harness)

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 1 | CIVER-01 | unit | `cargo test -p nono-cli test_root_help_mentions_windows_restricted_execution_surface -- --nocapture` | ✅ cli.rs:2203 | ⬜ pending |
| 03-01-02 | 01 | 1 | CIVER-01 | build+grep | `cargo build -p nono-cli && grep -c "preview surface" crates/nono-cli/src/cli.rs` (should be 0) | ✅ cli.rs | ⬜ pending |
| 03-02-01 | 02 | 2 | CIVER-01 | harness | `.\scripts\windows-test-harness.ps1 -Suite regression` | ✅ harness | ⬜ pending |
| 03-02-02 | 02 | 2 | CIVER-02 | harness+local | `$env:NONO_CI_HAS_WFP=$null; .\scripts\windows-test-harness.ps1 -Suite security` exits 0 | ✅ harness | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test files needed. The `cli.rs` test needs assertion body updates (not creation). Harness changes are PowerShell edits.

*Wave 0 complete: no new test stubs required.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| WFP tests skip cleanly on unprivileged runner | CIVER-02 | Requires simulating missing WFP access locally | Run `$env:NONO_CI_HAS_WFP=$null; .\scripts\windows-test-harness.ps1 -Suite security` — verify "SKIPPED:" message and exit 0 |
| WFP tests execute on privileged runner | CIVER-02 | Requires actual admin elevation + WFP driver | Set `$env:NONO_CI_HAS_WFP="true"` and run security suite — verify WFP test filters execute |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s (unit) / < 2 min (harness)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
