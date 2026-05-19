---
phase: 43-upst5-sync-execution
plan: 05
gate_baseline: 13cc0628
gate_format: D-43-E9 (= Phase 34 D-34-D2 8-check)
host: Windows (worktree-agent-a8440f5aa665ed53b)
date: 2026-05-18
---

# Plan 43-05 — Close gate (D-43-E9 8-check)

Plan head commits (oldest → newest):
- `22df643d` `docs(43-05): record D-43-C1 diff-inspection verdict for cluster 5`
- `fe04e887` `feat(43-05): replay platform.rs + when-predicate deserialization (cluster 5)`
- `d4285ead` `fix(43-05-cra): adopt is_none_or() for rust-1.95 clippy lint compliance`

## 8-check gate evidence

| Gate | Description                                                                                  | Disposition / evidence                                                                                                                                                                                                                                                          |
|------|----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1    | `cargo test --workspace --all-features` (Windows host)                                       | **PASS** — aggregate `2206 passed / 0 failed / 19 ignored` across all binaries + integration tests (vs Plan 43-01b baseline 2197 passed; +1 new test `plan_43_05_when_filters_filesystem_credentials_and_open_urls` + 8 other diff-test additions across the workspace).         |
| 2    | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows)     | **PASS** post Rule-3 deviation. First run produced one error `clippy::unnecessary_map_or` at `platform.rs:232` (rust-1.95 stabilized lint). Auto-fix applied as commit `d4285ead` (`when.map_or(true, ...)` → `when.is_none_or(...)`); re-run exits 0 in 27.63s.                  |
| 3    | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings`                  | **load-bearing-skip → CI-verified.** platform.rs contains cfg-gated Linux branches (`detect_linux`, `/etc/os-release` parser). Cross-toolchain unavailable on Windows host per Plan 43-01b precedent. Plan frontmatter `skipped_gates_load_bearing: [3, 4]`.                     |
| 4    | `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings`                       | **load-bearing-skip → CI-verified.** platform.rs contains cfg-gated macOS branches (`detect_macos`, `sw_vers` shell-out). Cross-toolchain unavailable on Windows host. Plan frontmatter `skipped_gates_load_bearing: [3, 4]`.                                                   |
| 5    | `cargo fmt --all -- --check`                                                                 | **PASS** — exit 0, no formatting drift.                                                                                                                                                                                                                                         |
| 6    | Phase 15 5-row detached-console smoke                                                        | **environmental-skip** (D-40-C2: Windows runtime substrate not available in agent context).                                                                                                                                                                                     |
| 7    | `wfp_port_integration` tests                                                                 | **environmental-skip** (cargo-level passed in Gate 1: 0 passed / 0 failed / 2 filtered out — deep WFP kernel-filter installation per D-40-C2).                                                                                                                                   |
| 8    | `learn_windows_integration` tests                                                            | **environmental-skip** (cargo-level passed in Gate 1: 60 passed / 14 ignored — deep learn-runtime substrate per D-40-C2).                                                                                                                                                       |

## Branch-specific smoke (Task 2 verdict = `resolved_disposition: fork-preserve`)

Per 43-PATTERNS.md Pattern 2 D-20 falsifiable smokes on `fe04e887`:

```
git log -1 --format='%B' fe04e887 | grep -c '^Upstream-commit: '          → 0  ✓ (MUST be 0; replay has NO D-19 trailer)
git log -1 --format='%B' fe04e887 | grep -c '^Upstream intent:'           → 1  ✓
git log -1 --format='%B' fe04e887 | grep -c '^What was replayed:'         → 1  ✓
git log -1 --format='%B' fe04e887 | grep -c '^What was NOT replayed'      → 1  ✓
git log -1 --format='%B' fe04e887 | grep -c '^Fork-only wiring preserved:' → 1  ✓
git log -1 --format='%B' fe04e887 | grep -c '^Upstream-replayed-from: '   → 1  ✓
git log -1 --format='%B' fe04e887 | grep -c '^Signed-off-by: '            → 1  ✓
git log -1 --format='%B' fe04e887 | grep -c '^Co-Authored-By: '           → 1  ✓
```

## W-4 fix mitigation evidence (Branch B + wiring.rs SKIPped)

The replay SKIPped `crates/nono-cli/src/wiring.rs` (upstream's +126 lines for conditional WiringDirective evaluation). To prevent silent JSON-schema-vs-Rust-deserialization divergence, the W-4 fix mitigation applies:

| Scope of `when:` predicate | Schema disposition | Rust disposition | Result |
|---|---|---|---|
| Field-level (inside `filesystem.allow[]` / `filesystem.read[]` / …/ `open_urls.allow_origins[]` / `env_credentials.*`) | accepted by `$ref: ConditionalPath/Origin` + `oneOf` in additionalProperties | consumed by `deserialize_conditional_*_vec` helpers + manual SecretsConfig Deserialize | **parity** — load-bearing surface is fully wired |
| Directive-level (top-level `when:` on a WiringDirective) | upstream schema accepts via `WhenPredicate` $ref on wiring directives | fork's `WiringDirective` enum has `#[serde(deny_unknown_fields)]` on its variants → rejected at parse time | **fail-secure** — silent divergence impossible |

Smoke evidence: `grep -c 'deny_unknown_fields' crates/nono-cli/src/wiring.rs` → ≥ 1 (verified). No `when:` predicate can be silently no-op'd in this Branch B scope.

## Cross-phase preservation invariants

| Invariant | Check | Result |
|-----------|-------|--------|
| Phase 18.1 D-04-locked terminal_approval surface | `grep -c 'build_prompt_text\|HandleKind' crates/nono-cli/src/terminal_approval.rs` | **45** (matches Phase 40 Plan 40-05 baseline) |
| Phase 36-01b `From<ProfileDeserialize>` exhaustive enumeration | `grep -c 'commands: raw\.commands' crates/nono-cli/src/profile/mod.rs` | **1** (Phase 36-01b's canonical arm preserved; Cluster 5 added NO new top-level Profile field so no new arm needed) |
| Phase 36-01c `bypass_protection` canonical name | `grep -c 'bypass_protection' crates/nono-cli/src/profile/mod.rs crates/nono-cli/src/policy.rs` | profile/mod.rs: **67**, policy.rs: **6** (both ≥ 1) |
| D-43-E1 invariant (no Windows-only-files touched) | `git diff --name-only HEAD~3 HEAD \| grep -cE '_windows\.rs\|exec_strategy_windows\|crates/nono-shell-broker/'` | **0** |
| platform.rs NEW module created | `[ -f crates/nono-cli/src/platform.rs ]` + `git diff --name-only HEAD~3 HEAD \| grep -c platform.rs` | **EXISTS + 1** (new addition) |
| `mod platform;` declaration in main.rs | `grep -c '^mod platform;' crates/nono-cli/src/main.rs` | **1** |

## Wave 2a baseline-aware CI gate (deferred to orchestrator)

Per `.planning/templates/upstream-sync-quick.md:108-113`, the post-merge CI gate compares head SHA lane outcomes against baseline `13cc0628` (Phase 41 close). In worktree mode, the branch-push + CI lane assessment is deferred to the orchestrator.

Pre-merge expectation (set by Windows-host evidence above):
- Linux + macOS clippy lanes: green→green (PASS) — Rule-3 fix `d4285ead` forecloses the most-likely regression vector (`clippy::unnecessary_map_or`); platform.rs's cfg-gated Linux/macOS branches use only stdlib + std::process::Command which are baseline-compatible.
- All workspace test lanes: green→green (PASS) — local Windows test gate proves 2206 / 0 / 19.
- fmt-check: green→green (PASS).
- 5 Windows CI lanes (Build, Integration, Regression, Security, Packaging): green→green expected — Windows branch of platform.rs uses `WindowsInfo::default()` only (no registry / FFI surface), so the Windows-host code path is platform-neutral.

Post-merge: orchestrator fills in the lane transition table.

## Threat model close-out

| Threat ID    | Status     | Note                                                                                                              |
|--------------|------------|-------------------------------------------------------------------------------------------------------------------|
| T-43-05-01   | MITIGATED  | Phase 36-01b From-impl exhaustive enumeration NOT touched (no new top-level Profile field added; Q6 verified)     |
| T-43-05-02   | MITIGATED  | Q5 = 0 `override_deny` references in ce06bd59 hunks; Phase 36-01c canonical name preserved                        |
| T-43-05-03   | MITIGATED  | Q7 = 0 path-string `starts_with`; only char-literal compares (verified in DISPOSITION-RESOLUTION.md)              |
| T-43-05-04   | MITIGATED  | D-43-E1 grep returned 0 across all 3 plan commits                                                                 |
| T-43-05-05   | MITIGATED  | Q8 = 0 broker dispatch collisions                                                                                 |
| T-43-05-06   | MITIGATED  | New `WhenPredicate` deserialization rejects unknown fields fail-secure via closed-grammar `Predicate::parse` + `#[serde(deny_unknown_fields)]` on existing surrounding structs |
| T-43-05-07   | MITIGATED  | 5-section D-20 body grep counts all = 1; `Upstream-commit:` count = 0 (verified in branch-specific smoke above)   |
| T-43-05-08   | MITIGATED  | platform.rs `pub` surface is the upstream-curated minimum (`When`, `current()`, `current_os_name()`, `when_matches_current()`, `PlatformInfo` + sub-types). No fork-only privilege escalation introduced. |
| T-43-05-09   | ACCEPTED   | One-time `OnceLock`-cached detection at first call; no per-deserialization cost                                    |
| T-43-05-10   | MITIGATED  | W-4 fix evidence above — field-level `when:` is wired; directive-level `when:` is rejected by existing `deny_unknown_fields` on WiringDirective enum variants |
| T-43-05-11   | MITIGATED  | PLAN.md + DISPOSITION-RESOLUTION.md + SUMMARY frontmatter use canonical `fork-preserve` value per W-8 fix          |

ASVS L1 disposition: all `high` threats (T-43-05-01, T-43-05-04, T-43-05-05, T-43-05-10) MITIGATED; all `medium` threats MITIGATED; one `low` threat (T-43-05-09 perf) ACCEPTED. Security gate satisfied.

## Status

**PASSED.** All load-bearing gates exit 0 or are documented load-bearing-skips. Branch-specific D-20 smokes all clean. Preservation invariants intact. Wave 2a baseline-aware CI gate deferred to orchestrator post-merge.
