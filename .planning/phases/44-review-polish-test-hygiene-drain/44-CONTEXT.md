---
phase: 44
phase_name: review-polish-test-hygiene-drain
gathered: 2026-05-20
status: Ready for planning
requirements_locked_via: REQUIREMENTS.md § REQ-REVIEW-FU-01 + REQ-TEST-HYG-01..04 (no SPEC.md — drain phase with explicit success criteria in ROADMAP.md)
---

# Phase 44: REVIEW polish + test hygiene drain - Context

**Gathered:** 2026-05-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 44 is a single-purpose **drain phase** clearing two backlogs accumulated through v2.5 close so the rest of v2.6 inherits a quiet baseline:

1. **REVIEW.md polish (REQ-REVIEW-FU-01)** — Resolve all 16 WARNING findings from Phase 37 (10 warnings) + Phase 43 (6 warnings) via a single `chore(v2.6-followup):` plan. Roadmap SC#1 forbids silent ignore: every WR gets an explicit disposition (fix / explicit-defer-with-rationale / suppress-with-comment).
2. **Test hygiene drain (REQ-TEST-HYG-01..04)** — Close the 4 test-hygiene follow-up todos accumulated at Plan 41-10 close:
   - REQ-TEST-HYG-01: Class D Linux deny-overlap regression test (`run_allow_cwd_with_profile_deny_under_workdir_fails_closed`) un-`#[ignore]`'d.
   - REQ-TEST-HYG-02: Class E Windows `env_vars` parallel test flakes (2 — `windows_run_redirects_profile_state_vars_into_writable_allowlist` + `windows_run_redirects_temp_vars_into_writable_allowlist`) eliminated via cargo-nextest subprocess-per-test isolation.
   - REQ-TEST-HYG-03: v24 broker CR-01 (`BrokerNotFound` FFI remap to `ErrSandboxInit`) cross-binding lockstep landed in `../nono-py/` + `../nono-ts/`.
   - REQ-TEST-HYG-04: v24 broker CR-02 (broker-side FFI handle null/INVALID validation) cross-binding lockstep landed in `../nono-py/` + `../nono-ts/`.

**Phase close SHA becomes the v2.6 quiet-baseline anchor** for Phase 46's post-merge CI lane diff (REQ-CI-FU-03 references this baseline). STATE.md `## Deferred Items` is cleared of the 5 motivating todos at phase close.

Two plans run in parallel (surface-disjoint):
- **Plan 44-01** — `chore(v2.6-followup): REVIEW.md polish` — touches `crates/nono-cli/src/` (platform.rs, pack_update_hint.rs, exec_strategy/supervisor_linux.rs, session_commands{,_windows}.rs, cli.rs, sandbox_prepare.rs, diagnostic_formatter.rs), `crates/nono/{src/trust/signing.rs, src/undo/snapshot.rs, Cargo.toml}`, `crates/nono-cli/tests/{auto_pull_e2e_linux.rs, resl_nix_linux.rs}`, `.github/{workflows/phase-37-linux-resl.yml, scripts/check-cli-doc-flags.sh}`.
- **Plan 44-02** — `chore(44): test hygiene drain` — touches `crates/nono-cli/tests/deny_overlap_run.rs`, `crates/nono-cli/tests/env_vars.rs`, `.config/nextest.toml` (NEW), `bindings/c/src/lib.rs` (verification only; tests live in siblings), `../nono-py/` (clone-or-fetch + new test), `../nono-ts/` (clone-or-fetch + new test).

**In scope:**
- All 16 WARNING dispositions in PLAN.md task table (canonical source) with row-per-warning: WR-id, file:line, disposition (fix / defer-with-rationale / suppress-with-comment), commit ref.
- All 12 INFO findings (7 Phase 37 + 5 Phase 43) follow the same default-fix policy unless cost-prohibitive (planner discretion).
- 5 motivating todos closed; new follow-up todos filed for residual issues surfaced by Phase 44 work (WR-01 fd-relative hardening, validate_deny_overlaps pre-flight investigation).
- v24 CR-03 + CR-04 todo archive — bookkeeping commit moving `v24-cr-03-*` and `v24-cr-04-*` from `.planning/todos/pending/` to `.planning/todos/done/` with Phase 41 close SHA as resolution ref (per v2.4 milestone audit acknowledgment 2026-05-16).
- Cross-binding lockstep work in `../nono-py/` + `../nono-ts/`: clone if absent (URL derived from this repo's `git remote -v` upstream), add FFI remap regression test mirroring `bindings/c/src/lib.rs:285-291`, add CR-02 null-handle reject test mirroring `crates/nono-shell-broker/src/main.rs:535,562`. Commits land in sibling repos (separate PRs if upstream-targeted).

**Out of scope (route elsewhere or explicitly defer):**
- **Phase 45 surfaces** — Edition 2024 `#[unsafe(no_mangle)]` rewrites, AIPC G-04 wire-protocol tightening, Phase 38 RESL native re-validation. Phase 44 and Phase 45 run in parallel per ROADMAP Sequencing Rationale; surfaces disjoint.
- **Phase 46 surfaces** — windows-squash merge, post-merge CI verifications, UAT backlog. Sequential after 44 + 45.
- **fd-relative TOCTOU hardening of `validate_restore_target`** (Phase 43 WR-01) — substantial refactor (O_NOFOLLOW / openat / fd-relative ops on Linux + macOS + Windows). Doc-only fix in this phase; follow-up todo files dedicated security-scoped phase.
- **`validate_deny_overlaps` pre-flight root-cause fix** (the underlying validator bug surfaced by Class D CI failure) — requires Linux dev host access to instrument `policy.rs:1032-1088`. Phase 44 closes the test via runtime-Landlock-equivalence assertion update; follow-up todo files the validator-correctness investigation.
- **Project-wide cargo-nextest adoption** — Phase 44 scopes nextest config to the 2 affected env_vars tests via `.config/nextest.toml`. Replacing `cargo test` everywhere is a larger structural change deferred to a dedicated phase if/when needed.
- **Major REVIEW finding refactors** that exceed the "default-fix where cheap" line — caught by planner discretion + this CONTEXT.md's disposition policy. New todos filed instead.

</domain>

<decisions>
## Implementation Decisions

### Plan slicing (Area A — discussed)

- **D-44-A1: Two plans, parallel execution.** Plan 44-01 = `chore(v2.6-followup): REVIEW.md polish` (REQ-REVIEW-FU-01). Plan 44-02 = `chore(44): test hygiene drain` (REQ-TEST-HYG-01..04). Surfaces are disjoint (44-01 = REVIEW.md fix sites in `crates/nono-cli/src/` + `crates/nono/src/` + `.github/`; 44-02 = test files + `.config/nextest.toml` NEW + sibling repo work). Two-plan shape honors Roadmap SC#1's "single `chore(v2.6-followup):` plan" wording for the REVIEW work specifically while letting test-hygiene work run in parallel. **User explicitly chose** option (a) over (b) "single bundled plan" and (c) "four plans per concern".

- **D-44-A2: Plans run in parallel (Phase 43 D-43-A2 pattern).** Mirrors Phase 43's parallel-wave shape — disjoint surfaces, halved wall-clock time. Per Roadmap "phases 44+45 parallel-safe" framing, this phase also runs parallel internally. **User explicitly chose** option (a) over (b) "sequential REVIEW → test-hygiene" and (c) "sequential test-hygiene → REVIEW".

- **D-44-A3: PLAN.md task list is the canonical REVIEW disposition source.** Plan 44-01 PLAN.md carries a table with one row per finding (16 WARNING + 12 INFO = 28 rows total), columns = [WR-id / IN-id, file:line, category, disposition (fix / defer / suppress), commit ref to be filled in post-execute]. SUMMARY.md echoes the table at close. Mirrors Phase 41 D-07 "table-in-body" pattern. **User explicitly chose** option (a) over (b) "SUMMARY-only" and (c) "inline commit messages".

- **D-44-A4: Plan 44-01 commits = one per warning class (~5-7 commits).** Group findings by category for review-friendly diff scope:
  - `chore(44-01): test thread-safety` — WR-03 + WR-04 (Phase 37) + IN-01 (Phase 37).
  - `chore(44-01): CI hygiene` — WR-01 + WR-08 + WR-10 (Phase 37).
  - `chore(44-01): platform.rs correctness` — WR-02 + WR-04 + WR-06 (Phase 43) + IN-05 (Phase 43).
  - `chore(44-01): pack_update_hint UX` — WR-03 + WR-05 (Phase 43) + IN-01 + IN-02 (Phase 43).
  - `feat(44-01): wire NONO_TRUST_OIDC_ISSUER in trust/signing.rs` — WR-09 (Phase 37). NOT a `chore:` — real production code.
  - `docs(44-01): document validate_restore_target TOCTOU residual race` — WR-01 (Phase 43). NOT a `chore:` — doc + follow-up todo.
  - `chore(44-01): misc INFO drain` — IN-02..IN-07 (Phase 37) + IN-03, IN-04 (Phase 43).
  - Planner refines exact grouping; reviewer can mentally classify per class. Mirrors Phase 41 D-07. **User explicitly chose** option (a) over (b) "per-finding" and (c) "single mega-commit".

### REVIEW disposition policy (Area B — discussed)

- **D-44-B1: Default-fix; explicit defer only on cost.** Each WARNING gets a code fix UNLESS the cost is clearly disproportionate (see D-44-B3 + D-44-B4 + D-44-B5 for the explicit-defer exceptions). All 12 INFO findings follow the same default-fix policy unless the planner identifies a cost-prohibitive case. Roadmap SC#1 forbids "silent ignore" — every WR gets an explicit PLAN.md disposition row. **User explicitly chose** option (a) over (b) "default-fix; no exceptions" and (c) "prefer suppress/defer over fix".

- **D-44-B2: Phase 43 WR-05 pack-update synchronous startup-latency → drop synchronous entirely (option (b)).** Replace `refresh_synchronous` callsite with always-background refresh in `pack_update_hint::show_pack_update_hints`. First-run users see the hint on second `nono run` instead of first; matches the "background refresh" pattern used elsewhere in the file; aligns with CLAUDE.md "Zero startup latency" constraint. Simpler code than option (a) bounded timeout — delete the synchronous path rather than parameterize a timeout. **User explicitly chose** option (b) over (a) "bounded 2s timeout" and (c) "defer to follow-up".

- **D-44-B3: Phase 37 WR-09 NONO_TRUST_OIDC_ISSUER → wire production-side this phase.** Implement the reader in `crates/nono/src/trust/signing.rs` so the CI workflow's env var actually enforces REQ-PKGS-04 acceptance #4. Real production decision but small surface; closes the misleading-CI gap definitively. Lands as a `feat(44-01):` commit, not `chore:` — codified scope expansion beyond pure drain. **User explicitly chose** option (a) "implement reader" over (b) "TODO marker only" and (c) "defer with todo".

- **D-44-B4: Phase 43 WR-01 `validate_restore_target` TOCTOU → doc-only + follow-up todo.** Update the `validate_restore_target` doc comment to explicitly document the residual race window (per the reviewer's exact suggested wording at 43-REVIEW.md:99-109). File new follow-up todo for the fd-relative O_NOFOLLOW / openat hardening (substantial cross-platform refactor: Linux + macOS + Windows have different fd-relative semantics). Doc-only fix preserves the security message ("this is best-effort against TOCTOU; full closure requires a refactor") and creates the breadcrumb. **User explicitly chose** option (a) over (b) "refactor to fd-relative now" and (c) "suppress with `#[allow]`".

- **D-44-B5: INFO finding default-fix unless cost-prohibitive (planner discretion).** Phase 37 IN-03 cross-platform `format_bytes_short` dedup is a small refactor (move to a shared module under `crates/nono-cli/src/`); planner decides whether to fold into D-44-A4 commits or defer. Phase 43 IN-01 (non-atomic state-file writes in `pack_update_hint::save_state`) is a low-cost change (mirror `package::write_lockfile`'s tmp+rename pattern) — fix. Phase 43 IN-02 (refresh_in_background detached JoinHandle) — accept as documented (no shutdown signal path exists); add a comment per Plan 44-01 task list. Phase 43 IN-05 (`parse_windows_registry_value` multi-space collapse) — accept as documented (no security impact, unlikely real-world fixture).

### Class D Linux deny-overlap strategy (Area C — discussed)

- **D-44-C1: Update assertion to accept runtime Landlock denial as equivalent.** `crates/nono-cli/tests/deny_overlap_run.rs:111` assertion #2 changes from `stderr.contains("Landlock deny-overlap")` to **either** `stderr.contains("Landlock deny-overlap")` (validator pre-flight) **OR** `stderr.contains("Permission denied") && stderr.contains("No path denials were observed")` (runtime Landlock filesystem denial). Inline comment explains the security equivalence: both deny the read, neither leaks the secret (assertion #1 + #3 hold either way). Most permissive — passes whether validator pre-flight fires or doesn't; future validator fix doesn't break the test. Drops `#[ignore]` attribute. Closes REQ-TEST-HYG-01 via source change only — **no Linux dev host access required**. **User explicitly chose** option (a) over (b) "reproduce + root-cause fix" and (c) "defer to host-required phase".

- **D-44-C2: Either-or assertion shape (not strict-runtime-only, not split-tests).** D-44-C1's "validator OR runtime denial" assertion is the chosen shape. Strict-runtime-only would force a deliberate re-update if the validator ever pre-flights correctly on CI; split-tests would double maintenance overhead. Either-or is the most-permissive shape that still proves the security guarantee. **User explicitly chose** option (a) over (b) "strict runtime-only" and (c) "split into two tests".

- **D-44-C3: File follow-up todo for `validate_deny_overlaps` pre-flight investigation.** The runtime-denial equivalence closes the test, but the underlying validator pre-flight not firing on CI IS a real bug (validator-path correctness in `crates/nono-cli/src/policy.rs::validate_deny_overlaps` per the original todo's 5-hypothesis branches at lines 41-46). New todo file `.planning/todos/pending/44-class-d-validator-preflight-investigation.md` captures the hypothesis branches + Linux-host instrumentation steps. Tagged for a future Linux-host phase (Phase 46 or beyond). Phase 44 closes REQ-TEST-HYG-01; the latent validator bug stays tracked. **User explicitly chose** option (a) over (b) "skip — runtime equivalent" and (c) "inline code comment only".

### Cross-binding lockstep + Class E flake (Area D — discussed)

- **D-44-D1: Clone sibling repos this phase; land commits in both.** Plan 44-02 task #1 = `git remote -v` in this repo → derive the upstream org → check `<org>/nono-py` + `<org>/nono-ts` exist → `git clone` to `../nono-py/` + `../nono-ts/` if absent. If the sibling repos don't exist at that org, surface as a deviation and ask the user before continuing. Land regression tests as separate commits in each sibling repo:
  - **nono-py:** new test file (PyO3-style — see sibling's existing test patterns) asserting `BrokerNotFound` Python exception maps to `SandboxInitError` (not `FileNotFoundError`); new test asserting `--inherit-handle 0x0` raises structured error.
  - **nono-ts:** new test file (napi-rs / vitest style — see sibling's existing patterns) asserting equivalent behavior.
  Phase 44 close gates on both sibling commits SHAs being recorded in `44-02-SUMMARY.md`; PR coordination to sibling upstreams is plan-discretion (push branch + open PR OR squash-merge to local main, depending on sibling repo conventions discovered at clone-time). Honors SC#4 "land" wording. **User explicitly chose** option (a) over (b) "open coordinated PRs only" and (c) "file follow-up todos only".

- **D-44-D2: Sibling repo URLs derived from this repo's `git remote -v` at plan-open.** Plan 44-02 task #1 reads `git remote -v` for the fork upstream URL (e.g., `<org>/nono.git`), then derives `<org>/nono-py.git` + `<org>/nono-ts.git`. If the orgs differ or repos don't exist there, surface as a deviation and ask the user during plan-open. Doesn't hardcode URLs in PLAN.md (avoids stale-URL rot). **User explicitly chose** option (a) over (b) "hardcode `always-further/nono-py` + `nono-ts`" and (c) "ask user during plan-open".

- **D-44-D3: cargo-nextest scoped to affected tests via `.config/nextest.toml` (smallest blast radius).** Plan 44-02 adds `.config/nextest.toml` (NEW file at repo root) with per-test override running `windows_run_redirects_profile_state_vars_*` + `windows_run_redirects_temp_vars_*` in subprocess-per-test isolation (NEXTEST_TEST_THREADS=1 for those test groups, or equivalent `[[profile.default.overrides]]` block). Other tests stay parallel under regular `cargo test`. CI workflows opt-in via `cargo nextest run --config-file .config/nextest.toml` for the env_vars-affected suite; broader workflows continue to use `cargo test`. SC#3 validation: 50 consecutive runs of the 2 affected tests pass deterministically on a Windows host (or CI lane equivalent). **User explicitly chose** option (a) over (b) "crate-wide subprocess-per-test" and (c) "project-wide nextest adoption".

- **D-44-D4: CR-03 + CR-04 todos archived as a bookkeeping commit.** Phase 41 D-12 (CR-03 = reject empty `--inherit-handle` list) and D-13 (CR-04 = panic-on-missing-broker test) already shipped at Phase 41 close. v2.4 milestone audit acknowledged "v24 CR-A class (4 todos) resolved by Phase 41; cleared 2026-05-16" but the actual `.planning/todos/pending/v24-cr-03-*.md` + `v24-cr-04-*.md` files were never moved to `.planning/todos/done/`. Plan 44-02 includes a single bookkeeping commit `chore(44-02): archive v24 CR-03 + CR-04 todos resolved by Phase 41` moving both files to `.planning/todos/done/` with Phase 41 close SHA as resolution ref in the commit body. **User explicitly chose** option (a) over (b) "leave pending; clean at milestone close" and (c) "re-verify before archiving".

### Folded Todos

All 5 motivating todos listed in Roadmap SC#5 are folded into Phase 44 scope:

- **41-10-linux-deny-overlap-regression.md** → Plan 44-02 task list; D-44-C1 + D-44-C2 + D-44-C3. Closed by assertion update; follow-up todo filed for validator pre-flight investigation.
- **41-10-windows-integration-env-vars-flake.md** → Plan 44-02 task list; D-44-D3. Closed by cargo-nextest subprocess-per-test isolation for the affected test.
- **41-10-windows-regression-temp-vars-flake.md** → Plan 44-02 task list; D-44-D3. Closed alongside the env_vars-flake sibling via the same nextest config.
- **v24-cr-01-broker-not-found-ffi-mapping.md** → Plan 44-02 task list; D-44-D1 + D-44-D2. Closed by sibling-repo regression tests in nono-py + nono-ts confirming the `ErrSandboxInit` mapping holds across bindings.
- **v24-cr-02-broker-null-handle-validation.md** → Plan 44-02 task list; D-44-D1. Closed by sibling-repo regression tests in nono-py + nono-ts asserting `--inherit-handle 0x0` rejection.

Plus 2 todos folded as bookkeeping (not work):

- **v24-cr-03-broker-empty-handle-list-path.md** → Plan 44-02 D-44-D4. Already resolved by Phase 41 D-12; this phase archives it.
- **v24-cr-04-job-object-test-skip-policy.md** → Plan 44-02 D-44-D4. Already resolved by Phase 41 D-13; this phase archives it.

### Carry-forward from Phase 41 / 43 (binding — locked, not for re-discussion)

- **D-44-E1 (= Phase 41 D-15 / Phase 43 D-43-E3): Baseline-aware CI gate.** Phase 44 plans gate vs the Phase 41 close SHA `13cc0628` per `.planning/templates/upstream-sync-quick.md:102` until Phase 46 post-merge moves the baseline. Zero `success → failure` transitions on Phase 44 head commits. Lane transitions categorized per Phase 40 anti-pattern #3 (`skipped_gates_load_bearing` vs `_environmental`).
- **D-44-E2 (= Phase 41 D-06 / memory `feedback_clippy_cross_target`): Cross-target clippy required for cfg-gated Unix code.** Plan 44-01's REVIEW polish touches several `#[cfg(target_os = "linux")]` files (`exec_strategy/supervisor_linux.rs` WR-02 site, `tests/auto_pull_e2e_linux.rs` WR-03/04 sites, `tests/resl_nix_linux.rs` WR-06/07 sites). MUST run `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` AND `--target x86_64-apple-darwin` per `.planning/templates/cross-target-verify-checklist.md`. Windows-host workspace clippy alone is insufficient. If cross-toolchain unavailable, mark related verification REQ as PARTIAL per the checklist.
- **D-44-E3 (= Phase 41 D-10 / Phase 44 SC#4): Sibling repo lockstep mandatory.** Phase 41 explicitly deferred this with a "file follow-up todo if downstream IS affected" disposition. Phase 44 SC#4 inverts that disposition: cross-binding lockstep is REQUIRED to land this phase, not deferred. D-44-D1 + D-44-D2 implement the lockstep.
- **D-44-E4 (= memory `project_workspace_crates`): nono workspace has 5 crates, not 3.** Phase 44 Plan 44-01 touches `Cargo.toml` only if a REVIEW finding requires it (e.g., WR-05 sigstore-verify 0.7.0 verify_sct default — D-44-B-implicit: the test-pinning fix touches a test file, not Cargo.toml). If any workspace `Cargo.toml` edit is required, all 5 are checked for consistency.
- **D-44-E5 (= CLAUDE.md § "Lazy use of dead code"): No `#[allow(dead_code)]` added without justification.** Applies to any dead-code orphans surfaced by Phase 44's WR-09 production wiring or D-44-B5 INFO refactors.
- **D-44-E6 (= CLAUDE.md § "Environment variables in tests"): env-var save/restore pattern.** Plan 44-01's WR-03 / WR-04 / IN-01 fixes (test thread-safety in `auto_pull_e2e_linux.rs`) MUST use the canonical `crate::common::test_env::lock_env()` pattern + EnvVarGuard, removing the file-local `EnvGuard` per the reviewer's exact suggested fix at 37-REVIEW.md:55-57.
- **D-44-E7: PR strategy is local-merge to main + push (no upstream PR umbrella).** Phase 44 is fork-internal cleanup (NOT an upstream-sync phase like 43/48). No D-19 trailer block. No upstream PR umbrella. Plan 44-01 + 44-02 land as direct commits on a Phase 44 feature branch → merge to main per the team's existing pattern. Sibling-repo work in nono-py + nono-ts follows the conventions of those repos (may or may not involve upstream PRs depending on D-44-D1's plan-open discovery).

### Claude's Discretion

- **Exact disposition wording for INFO findings.** D-44-B5 specifies default-fix unless cost-prohibitive; planner picks the exact disposition per finding. Specifically: Phase 37 IN-03 `format_bytes_short` shared-module dedup, Phase 43 IN-01 atomic-write retrofit, Phase 43 IN-02 detached-JoinHandle accept-as-documented.
- **Test-thread-safety fix mechanics.** D-44-E6 mandates `lock_env()` + EnvVarGuard pattern; planner picks whether to delete the file-local `EnvGuard` struct or keep it as a thin wrapper around the canonical primitive.
- **`feat(44-01)` commit body for WR-09.** Planner specifies the exact production-code structure for `crates/nono/src/trust/signing.rs` reader (env-var fallback shape, error class, test coverage). The fork-side acceptance gate is "the env var is read; if set, asserts as the trusted OIDC issuer at signature verification time; if unset, falls back to current behavior".
- **`.config/nextest.toml` schema specifics.** D-44-D3 specifies per-test override; planner picks `[[profile.default.overrides]]` block shape vs `[test-groups]` declaration + `[[profile.default.overrides]] filter = ...` redirection. Either is acceptable; pick whichever the nextest docs current at plan-open recommend.
- **Sibling-repo test idiom.** D-44-D1 specifies regression tests in nono-py + nono-ts but leaves the test-idiom to the planner — match the sibling repo's existing test style (pytest fixtures vs unittest; vitest vs jest vs napi-rs internal-test). Planner reads sibling repo at clone-time to discover the convention.
- **Plan numbering.** Plans 44-01 + 44-02 follow the `{padded_phase}-{NN}-{theme}` convention. Suggested names captured above (44-01-REVIEW-POLISH, 44-02-TEST-HYGIENE-DRAIN). Planner may refine.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 44 scope sources
- `.planning/REQUIREMENTS.md` § REQ-REVIEW-FU-01 + REQ-TEST-HYG-01..04 — Acceptance criteria for the 5 in-phase requirements.
- `.planning/ROADMAP.md` § Phase 44 — Goal + dependencies + 5 success criteria + reference list.
- `.planning/PROJECT.md` § v2.6 UPST6 + v2.5 Drain — milestone context, key decisions, deferred items.

### REVIEW.md inputs (BINDING — every WR + IN is a disposition row)
- `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-REVIEW.md` — Phase 37 code review: 10 WARNING + 7 INFO findings. Specific high-leverage fixes called out at lines 142-145: WR-01 multi-line `#[arg(...)]` parser bug (high-coverage win), WR-05 sigstore SCT default pin-test, WR-03 test thread-safety.
- `.planning/phases/43-upst5-sync-execution/43-REVIEW.md` — Phase 43 code review: 6 WARNING + 5 INFO findings. WR-01 `validate_restore_target` TOCTOU (doc-only per D-44-B4); WR-02 REG_DWORD fallback; WR-03 pre-release semver false update; WR-04 `compare_versions` Ord antisymmetry; WR-05 pack-update sync startup-latency (D-44-B2: drop-sync); WR-06 case-sensitive registry name match.

### Test-hygiene todo inputs (BINDING — each is a folded scope item)
- `.planning/todos/pending/41-10-linux-deny-overlap-regression.md` — Class D source; 5-hypothesis branch list at lines 41-46 (root cause TBD); acceptance gate at lines 57-61 allows runtime-equivalence assertion update.
- `.planning/todos/pending/41-10-windows-integration-env-vars-flake.md` — Class E.1 source; cargo-nextest recommendation at lines 27-33.
- `.planning/todos/pending/41-10-windows-regression-temp-vars-flake.md` — Class E.2 source; sibling flake to Class E.1.
- `.planning/todos/pending/v24-cr-01-broker-not-found-ffi-mapping.md` — CR-01 source; suggested fix lines 12-15.
- `.planning/todos/pending/v24-cr-02-broker-null-handle-validation.md` — CR-02 source; acceptance gate line 18.
- `.planning/todos/pending/v24-cr-03-broker-empty-handle-list-path.md` — CR-03 archive target; already resolved by Phase 41 D-12 (see `.planning/phases/41-*/41-CONTEXT.md`).
- `.planning/todos/pending/v24-cr-04-job-object-test-skip-policy.md` — CR-04 archive target; already resolved by Phase 41 D-13 (see `.planning/phases/41-*/41-CONTEXT.md`).

### Phase 41 precedent context (binding — Phase 41 deferred the cross-binding lockstep that Phase 44 lands)
- `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-CONTEXT.md` § Implementation Decisions D-09 (`BrokerNotFound` → `ErrSandboxInit` remap site at `bindings/c/src/lib.rs:138`), D-10 (cross-binding deferred to follow-up), D-11 (3 new tests + manual verification check), D-12 (CR-03 reject-empty-list), D-13 (CR-04 panic-on-missing-broker).
- `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-SUMMARY.md` — Phase 41 close-gate semantics; baseline reset to `13cc0628` (Phase 44 inherits).
- `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-VERIFICATION.md` — Phase 41 verifier confirming close-gate semantics.

### Code surfaces touched by this phase

**Plan 44-01 (REVIEW polish):**
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:891,901,910,981,993,997` — Phase 37 WR-02 LOCKED cgroup-v2 hint dedup site (centralize as `const CGROUP_V2_HINT`).
- `crates/nono/src/error.rs:421` — Phase 37 WR-02 sibling hint string site.
- `crates/nono-cli/src/cli.rs:1484-1496` — Phase 37 IN-04 `--no-auto-pull` env-var hint site.
- `crates/nono-cli/src/cli.rs:1773` — Phase 37 WR-10 `hide = true` doc-check blind spot site.
- `crates/nono-cli/src/diagnostic_formatter.rs:25-41` — Phase 37 IN-07 `format_error_footer` "set" grep-contract context.
- `crates/nono-cli/src/pack_update_hint.rs:84-99,183-218,263-274,290-304` — Phase 43 WR-03 + WR-05 + IN-01 + IN-02 fix sites.
- `crates/nono-cli/src/platform.rs:146-169,583-597` — Phase 43 WR-02 + WR-04 + WR-06 fix sites.
- `crates/nono-cli/src/sandbox_prepare.rs:108-112` — Phase 43 WR-05 callsite for sync→background swap.
- `crates/nono-cli/src/package_cmd.rs:341-346,580-585,629-633` — Phase 43 IN-03 + IN-04 fix sites.
- `crates/nono-cli/src/session_commands.rs:691-714` + `session_commands_windows.rs:610-628` — Phase 37 IN-03 cross-platform `format_bytes_short` dedup target.
- `crates/nono/src/trust/signing.rs` — Phase 37 WR-09 NEW production reader for `NONO_TRUST_OIDC_ISSUER` per D-44-B3.
- `crates/nono/src/undo/snapshot.rs:595-687` — Phase 43 WR-01 doc-only update per D-44-B4.
- `crates/nono/Cargo.toml:48` — Phase 37 WR-05 sigstore-verify pin-test target (the test sites at `VerificationPolicy::default()` callsites are the actual fix locations).
- `crates/nono-cli/tests/auto_pull_e2e_linux.rs:29-61,44-51,218,280,329,334-372,391-465,492` — Phase 37 WR-03 + WR-04 + IN-01 + IN-02 + IN-05 fix sites.
- `crates/nono-cli/tests/resl_nix_linux.rs:37-39,212-253` — Phase 37 WR-06 + WR-07 fix sites.
- `.github/workflows/phase-37-linux-resl.yml:135,294` — Phase 37 WR-08 + WR-09 (workflow side).
- `.github/scripts/check-cli-doc-flags.sh:24,64-67` — Phase 37 WR-01 + WR-10 awk-parser fix sites.

**Plan 44-02 (test hygiene drain):**
- `crates/nono-cli/tests/deny_overlap_run.rs:111` — Class D assertion update site per D-44-C1.
- `crates/nono-cli/tests/env_vars.rs` — Class E test sites (lines `windows_run_redirects_profile_state_vars_*` + `windows_run_redirects_temp_vars_*`; planner greps for exact line numbers at plan-open).
- `.config/nextest.toml` — NEW per D-44-D3.
- `bindings/c/src/lib.rs:285-291` — Phase 41 D-09 FFI mapping site (CR-01 lockstep verification context; sibling tests mirror this).
- `crates/nono-shell-broker/src/main.rs:535,562` — Phase 41 D-12 + D-13 broker argv parser site (CR-02 lockstep verification context; sibling tests mirror this).
- `../nono-py/` — sibling repo clone target per D-44-D1.
- `../nono-ts/` — sibling repo clone target per D-44-D1.

### Cross-phase invariants (inherited from ROADMAP § Cross-Phase Invariants)
- `.planning/ROADMAP.md` § Cross-Phase Invariants — D-19 trailer (NOT applicable to Phase 44; fork-internal), D-34-E1 / D-40-E1 / D-43-E1 Windows-only-files invariant (Phase 44 touches `crates/nono-cli/tests/env_vars.rs` which is cross-platform via cfg-gating; planner verifies no `*_windows.rs` violation), CLAUDE.md "lazy use of dead code", cross-target clippy for cfg-gated Unix code, DIVERGENCE-LEDGER cluster isolation (NOT applicable here).
- `.planning/templates/upstream-sync-quick.md` — Baseline SHA `13cc0628` per Phase 41 close (line 102); Phase 44 gates against this until Phase 46 post-merge moves it.
- `.planning/templates/cross-target-verify-checklist.md` — MANDATORY for every Plan 44-01 commit touching cfg-gated Unix code per D-44-E2.

### Coding & security standards (CLAUDE.md)
- `CLAUDE.md` § Coding Standards — no `.unwrap()`, env-var save/restore in tests, `#[must_use]` on critical Results, DCO sign-off (`Signed-off-by:` lines on every commit).
- `CLAUDE.md` § Security Considerations — path component comparison (relevant to WR-01 + WR-06 fixes), fail-secure on any unsupported shape.
- `CLAUDE.md` § Cross-target clippy verification — Phase 41 close-gate codifies; Phase 44 D-44-E2 inherits.
- `CLAUDE.md` § "Lazy use of dead code" — Phase 44 D-44-E5 inherits.

### Memory anchors
- Memory `feedback_clippy_cross_target` — Cross-target Linux + macOS clippy from Windows host (Plan 44-01 enforces per D-44-E2).
- Memory `project_workspace_crates` — Workspace has 5 crates; planner verifies any `Cargo.toml` edit cascades correctly (likely no edit needed in Phase 44).
- Memory `gh_available` — `gh` command usable for sibling-repo PR coordination if Plan 44-02 elects upstream PRs.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`crate::common::test_env::lock_env()` + `EnvVarGuard`** (`crates/nono-cli/src/test_env.rs`) — canonical env-var test-isolation primitive per CLAUDE.md and Phase 41 D-08. Plan 44-01 WR-03 / WR-04 / IN-01 fixes use this instead of the file-local `EnvGuard` in `auto_pull_e2e_linux.rs`.
- **`crates/nono/src/undo/snapshot.rs::validate_restore_target` (lines 595-687)** — already implemented in Phase 43; Phase 44 WR-01 fix is a doc-comment retrofit at the same site.
- **Phase 41 commit `13cc0628`** — clean baseline SHA in `.planning/templates/upstream-sync-quick.md:102`. Phase 44's baseline-aware CI gate inherits.
- **`crate::package::write_lockfile`** (`crates/nono-cli/src/package.rs:373-377`) — canonical atomic-write tmp+rename pattern. Phase 43 IN-01 (D-44-B5) reuses this for `pack_update_hint::save_state`.
- **`bindings/c/src/lib.rs:285-291` + `crates/nono-shell-broker/src/main.rs:535,562`** — Phase 41 D-09 + D-12 + D-13 reference implementations for the sibling-repo regression tests per D-44-D1.
- **`NonoErrorCode::ErrSandboxInit`** (`bindings/c/src/types.rs`) — existing FFI variant Phase 41 chose for the `BrokerNotFound` remap. Sibling repos must mirror this mapping (integer code -6 if they map by value).

### Established Patterns
- **One commit per warning class (Phase 41 D-07 + D-44-A4).** Plan 44-01 commit boundaries follow this pattern: test thread-safety / CI hygiene / platform.rs correctness / pack_update_hint UX / WR-09 feat / WR-01 doc / misc INFO drain.
- **PLAN.md table-in-body as canonical disposition source (Phase 41 D-07 + D-44-A3).** Reviewer can mentally classify per-row without git-archaeology.
- **Baseline-aware CI gate (Phase 40 anti-pattern #3 / Phase 41 close).** Categorize transitions: green→green PASS, green→red FAIL, red→red PASS (carry-forward), red→green PASS+IMPROVEMENT. `skipped_gates_load_bearing` vs `_environmental` documented in plan SUMMARY frontmatter.
- **Cross-target clippy from Windows host (Phase 41 D-06 / `feedback_clippy_cross_target` memory).** Phase 44 Plan 44-01 enforces per D-44-E2.
- **env-var save/restore in tests (CLAUDE.md / Phase 41 D-08).** Phase 44 Plan 44-01 WR-03/WR-04/IN-01 enforces via `lock_env()` + `EnvVarGuard`.
- **Phase-internal feature branch + merge-to-main (NOT upstream-sync PR umbrella).** Phase 44 is fork-internal cleanup; no D-19 trailers, no upstream PR umbrella per D-44-E7.

### Integration Points
- **Phase 44 → Phase 46:** Phase 44 close SHA becomes the v2.6 quiet-baseline anchor referenced by REQ-CI-FU-03 (Phase 46 baseline-aware CI lane diff vs Phase 41 close SHA `13cc0628`; Phase 44 must not introduce new red lanes).
- **Phase 44 ⇄ Phase 45:** Parallel-safe per ROADMAP Sequencing Rationale; surfaces disjoint (Plan 44-01 touches `crates/nono-cli/src/` + `crates/nono/src/` + `.github/`; Phase 45 touches `bindings/c/src/` Edition 2024 + `aipc_sdk.rs` + Linux/macOS host).
- **sibling repo lockstep (Phase 44 → nono-py + nono-ts):** Plan 44-02 D-44-D1 lands regression tests in both sibling repos. PR coordination to sibling upstreams is plan-discretion based on conventions discovered at clone-time.
- **STATE.md `## Deferred Items` cleanup (Phase 44 SC#5):** Phase 44 close clears the 5 motivating todos from STATE.md's tracking. The 2 archived CR-03/CR-04 todos move out of `.planning/todos/pending/` to `.planning/todos/done/` via D-44-D4.

### Phase 44 plan + commit map (final)

```
Plan 44-01 (REVIEW polish — chore(v2.6-followup))      Plan 44-02 (test hygiene drain — chore(44))
   │  ~5-7 commits, one per warning class                  │  ~3-4 commits + 2 sibling-repo commits
   │                                                       │
   ├─ chore(44-01): test thread-safety                     ├─ test(44-02): Class D either-or assertion + drop #[ignore]
   │     (WR-03 + WR-04 + IN-01 Phase 37)                  │     (deny_overlap_run.rs:111)
   ├─ chore(44-01): CI hygiene                             ├─ test(44-02): Class E nextest config + opt-in
   │     (WR-01 + WR-08 + WR-10 Phase 37)                  │     (.config/nextest.toml NEW + env_vars.rs notes)
   ├─ chore(44-01): platform.rs correctness                ├─ chore(44-02): archive v24 CR-03 + CR-04
   │     (WR-02 + WR-04 + WR-06 Phase 43 + IN-05 P43)      │     (todos/pending → todos/done)
   ├─ chore(44-01): pack_update_hint UX                    ├─ test(44-02): nono-py CR-01 + CR-02 regression
   │     (WR-03 + WR-05 Phase 43 + IN-01 + IN-02)          │     (sibling repo commit; in ../nono-py/)
   ├─ feat(44-01): wire NONO_TRUST_OIDC_ISSUER             └─ test(44-02): nono-ts CR-01 + CR-02 regression
   │     (WR-09 Phase 37 — real production code)                 (sibling repo commit; in ../nono-ts/)
   ├─ docs(44-01): validate_restore_target TOCTOU doc
   │     (WR-01 Phase 43 — doc-only + follow-up todo)
   └─ chore(44-01): misc INFO drain
         (IN-02..IN-07 Phase 37 + IN-03..IN-04 Phase 43)

Both plans land on a Phase 44 feature branch → merge to main per
the team's existing pattern (no upstream PR umbrella per D-44-E7).
```

</code_context>

<specifics>
## Specific Ideas

- **D-44-B2 chose option (b) "drop synchronous entirely" for WR-05** — user explicitly chose over option (a) "bounded 2s timeout" or option (c) "defer". Rationale: simpler code (delete the path) + aligns with CLAUDE.md "Zero startup latency" + matches background-refresh pattern used elsewhere in the file.
- **D-44-B3 upgraded WR-09 to in-scope production wiring** — user explicitly chose option (a) "implement reader in trust/signing.rs" over (b) "TODO marker only" and (c) "defer with todo". Phase 44 absorbs the production decision rather than punting it. Commits as `feat(44-01):`, not `chore:`.
- **D-44-C1 chose runtime-Landlock-equivalence assertion over Linux-host repro** — user explicitly chose option (a) over (b) "reproduce + root-cause fix" and (c) "defer to host-required phase". Closes REQ-TEST-HYG-01 without host-blocking the phase; validator pre-flight bug stays tracked via D-44-C3 follow-up todo.
- **D-44-D1 clones siblings + lands commits in this phase** — user explicitly chose option (a) over (b) "open coordinated PRs only" and (c) "file follow-up todos only". Honors SC#4 "land" wording; produces real sibling-repo commits during Phase 44 execution.
- **D-44-D3 scoped nextest config to affected tests only** — user explicitly chose option (a) `.config/nextest.toml` per-test override over (b) "crate-wide subprocess-per-test" and (c) "project-wide nextest adoption". Smallest blast radius; preserves `cargo test` for the bulk of the suite.

</specifics>

<deferred>
## Deferred Ideas

- **`validate_restore_target` fd-relative TOCTOU hardening (WR-01 follow-up).** O_NOFOLLOW + openat + fd-relative ops across Linux + macOS + Windows; substantial cross-platform refactor. Phase 44 ships doc-only fix per D-44-B4; new todo `.planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md` to be filed by planner at Plan 44-01 open.
- **`validate_deny_overlaps` pre-flight investigation (Class D follow-up).** The runtime-Landlock-equivalence assertion closes REQ-TEST-HYG-01, but the underlying validator bug (`validate_deny_overlaps` not firing on CI Linux) is a real latent issue. Phase 44 D-44-C3 files new todo `.planning/todos/pending/44-class-d-validator-preflight-investigation.md` with 5-hypothesis branches preserved from the original Plan 41-10 todo. Tagged for a future Linux-host phase (Phase 46 or beyond).
- **Project-wide cargo-nextest adoption.** D-44-D3 scoped to affected tests only. If broader flake patterns emerge in v2.6+, a dedicated phase replaces `cargo test` with `cargo nextest run` across Makefile + CI workflows + scripts.
- **Sibling repo upstream PR coordination** (if D-44-D1 plan-open discovery surfaces a non-trivial PR cadence for nono-py / nono-ts). Plan 44-02 lands commits in sibling repos; if upstream PR merge gates the close, planner may file a sibling-repo coordination follow-up rather than blocking Phase 44 close indefinitely.
- **Sigstore-verify 0.6.5 → 0.6.6 stretch upgrade (P32-DEFER-005, REQUIREMENTS.md v2 deferred).** If Phase 44 has space after the core drain, could land in 44-01. Default: stays in v2 deferred bucket per REQUIREMENTS.md § v2 Requirements.

### Reviewed Todos (not folded)

None — all 7 matching todos surfaced by `todo.match-phase 44` were either folded (5 motivating + 2 archive-bookkeeping) or are tracked above as follow-up new-todos. The CR-03 + CR-04 todos are folded as bookkeeping per D-44-D4 (archive, not work); they're functionally "reviewed and resolved by Phase 41" but Phase 44 owns the file move.

</deferred>

---

*Phase: 44-review-polish-test-hygiene-drain*
*Context gathered: 2026-05-20*
