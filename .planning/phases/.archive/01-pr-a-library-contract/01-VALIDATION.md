---
phase: 1
slug: pr-a-library-contract
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-03
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness (`#[cfg(test)]`) |
| **Config file** | `Makefile` targets (`make test-lib`, `make ci`) |
| **Quick run command** | `cargo test -p nono windows:: --lib` |
| **Full suite command** | `make test` |
| **Estimated runtime** | ~10 seconds (quick), ~60 seconds (full) |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p nono windows:: --lib`
- **After every plan wave:** Run `make test`
- **Before `/gsd:verify-work`:** Full `make ci` must be green
- **Max feedback latency:** ~10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 1-01-01 | 01 | 0 | LIBCON-01,02,03,04 | unit | `cargo test -p nono windows:: --lib` | ❌ W0 | ⬜ pending |
| 1-01-02 | 01 | 1 | LIBCON-01 | unit | `cargo test -p nono windows::tests::apply_accepts_minimal_supported_windows_subset --lib` | ❌ W0 | ⬜ pending |
| 1-01-03 | 01 | 1 | LIBCON-01 | unit | `cargo test -p nono windows::tests::apply_accepts_network_blocked_capability_set --lib` | ❌ W0 | ⬜ pending |
| 1-01-04 | 01 | 1 | LIBCON-02 | unit | `cargo test -p nono windows::tests::apply_rejects_unsupported_single_file_grant --lib` | ❌ W0 | ⬜ pending |
| 1-01-05 | 01 | 1 | LIBCON-02 | unit | `cargo test -p nono windows::tests::apply_rejects_unsupported_write_only_directory_grant --lib` | ❌ W0 | ⬜ pending |
| 1-01-06 | 01 | 1 | LIBCON-02 | unit | `cargo test -p nono windows::tests::apply_rejects_unsupported_proxy_with_ports --lib` | ❌ W0 | ⬜ pending |
| 1-01-07 | 01 | 1 | LIBCON-02 | unit | `cargo test -p nono windows::tests::apply_rejects_capability_expansion_shape --lib` | ❌ W0 | ⬜ pending |
| 1-01-08 | 01 | 1 | LIBCON-02 | unit | `cargo test -p nono windows::tests::apply_rejects_non_default_ipc_mode --lib` | ❌ W0 | ⬜ pending |
| 1-01-09 | 01 | 1 | LIBCON-02 | unit | `cargo test -p nono windows::tests::apply_error_message_remains_explicit_for_unsupported_subset --lib` | ❌ W0 | ⬜ pending |
| 1-01-10 | 01 | 1 | LIBCON-03 | unit | `cargo test -p nono windows::tests::support_info_reports_supported_status_for_promoted_subset_contract --lib` | ❌ W0 | ⬜ pending |
| 1-01-11 | 01 | 1 | LIBCON-05 | build/grep | `grep "contract remains partial" crates/nono-cli/src/setup.rs` (expect no match) | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

All 9 required contract tests are new — none exist yet. Wave 0 writes the test stubs:

- [ ] `support_info_reports_supported_status_for_promoted_subset_contract` — replaces old `support_info_reports_consistent_partial_status`
- [ ] `apply_accepts_minimal_supported_windows_subset` — new
- [ ] `apply_accepts_network_blocked_capability_set` — new
- [ ] `apply_rejects_unsupported_single_file_grant` — new
- [ ] `apply_rejects_unsupported_write_only_directory_grant` — new
- [ ] `apply_rejects_unsupported_proxy_with_ports` — new
- [ ] `apply_rejects_capability_expansion_shape` — new
- [ ] `apply_rejects_non_default_ipc_mode` — new
- [ ] `apply_error_message_remains_explicit_for_unsupported_subset` — new

Existing tests that must be updated (not new, not deleted):

- [ ] `compile_filesystem_policy_keeps_single_file_rules` — assert `is_fully_supported: false` after classification is activated
- [ ] `compile_filesystem_policy_keeps_write_only_directory_rules` — same update required

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `setup.rs` "partial" claim removed | LIBCON-05 | grep-verifiable | `grep "contract remains partial" crates/nono-cli/src/setup.rs` — must return no match |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
