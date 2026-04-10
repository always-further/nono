---
phase: 2
slug: pr-b-cli-messaging
status: draft
nyquist_compliant: false
wave_0_complete: true
created: 2026-04-03
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Cargo test (built-in Rust test runner) |
| **Config file** | `Cargo.toml` (workspace root), `crates/nono-cli/tests/env_vars.rs` |
| **Quick run command** | `cargo clippy -p nono-cli -- -D warnings` |
| **Full suite command** | `cargo test -p nono-cli` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo clippy -p nono-cli -- -D warnings`
- **After every plan wave:** Run `cargo test -p nono-cli`
- **Before `/gsd:verify-work`:** `cargo build -p nono-cli && cargo clippy -p nono-cli -- -D warnings && cargo test -p nono-cli`
- **Max feedback latency:** ~30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | CLIMSG-01 | integration | `cargo test -p nono-cli windows_setup_check_only` | ✅ env_vars.rs | ⬜ pending |
| 02-01-02 | 01 | 1 | CLIMSG-02 | integration | `cargo test -p nono-cli windows_run` | ✅ env_vars.rs | ⬜ pending |
| 02-01-03 | 01 | 1 | CLIMSG-03 | integration | `cargo test -p nono-cli windows_shell` | ✅ env_vars.rs | ⬜ pending |
| 02-01-04 | 01 | 2 | CLIMSG-04 | integration | `cargo test -p nono-cli` | ✅ env_vars.rs | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test files need to be created. The work is updating existing assertions in `crates/nono-cli/tests/env_vars.rs`.

*Wave 0 complete: no new test stubs required.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `nono setup --check-only` output on Windows shows single status line | CLIMSG-01 | Requires live Windows runtime | Run `nono setup --check-only` on Windows; verify single `Support status: supported` line, no CLI/library split |
| `nono shell` and `nono wrap` hard-rejected on Windows | CLIMSG-03 | Requires live Windows runtime | Run `nono shell` and `nono wrap` on Windows; verify explicit rejection message |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
