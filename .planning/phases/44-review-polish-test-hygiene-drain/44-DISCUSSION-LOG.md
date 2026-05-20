# Phase 44: REVIEW polish + test hygiene drain - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-20
**Phase:** 44-review-polish-test-hygiene-drain
**Areas discussed:** Plan slicing, REVIEW disposition policy, Class D Linux deny-overlap strategy, Cross-binding lockstep + Class E flake

---

## Plan slicing

### Q1: How should Phase 44 be sliced into plans?

| Option | Description | Selected |
|--------|-------------|----------|
| Two plans: REVIEW + test-hygiene | Plan 44-01 covers all 16 REVIEW warnings (matches roadmap SC#1 verbatim); Plan 44-02 covers all 4 test-hygiene todos + CR-03/04 archive. Two-plan shape with parallel execution. | ✓ |
| Single bundled plan | All 16 warnings + 4 test-hygiene todos in one chore plan. Tightest blast-radius bound but mixes pure file edits with host-dependent test work. | |
| Four plans (one per concern) | 44-01 REVIEW polish, 44-02 deny-overlap, 44-03 env_vars flakes, 44-04 cross-binding lockstep. Maximum traceability but heavyweight for a single drain phase. | |

**User's choice:** Two plans: REVIEW + test-hygiene
**Notes:** Tracks the roadmap SC#1 "single chore(v2.6-followup) plan" wording for REVIEW polish specifically, while letting test-hygiene work proceed in parallel inside the same phase.

### Q2: Should the two plans run sequentially or in parallel?

| Option | Description | Selected |
|--------|-------------|----------|
| Parallel | Surfaces disjoint: 44-01 touches `crates/nono-cli/src/` + `.github/` + `Cargo.toml`; 44-02 touches test files + bindings/c + sibling repos. Mirrors Phase 43 D-43-A2 parallel pattern. | ✓ |
| Sequential: REVIEW → test-hygiene | REVIEW polish lands first; test-hygiene picks up the clean baseline. Easier rollback. | |
| Sequential: test-hygiene → REVIEW | Test hygiene first so REVIEW polish runs against a quieter test suite. | |

**User's choice:** Parallel
**Notes:** Halves wall-clock time; per ROADMAP "phases 44+45 parallel-safe" framing, this phase also runs parallel internally.

### Q3: Where do the REVIEW.md disposition tables live?

| Option | Description | Selected |
|--------|-------------|----------|
| In 44-01-PLAN.md task list | Canonical disposition source; SUMMARY.md echoes post-execute. Mirrors Phase 41 D-07 "table-in-body" pattern. | ✓ |
| In 44-01-SUMMARY.md only | PLAN.md stays minimal; dispositions recorded at close. Less ceremony but plan-phase reviewers can't verify upfront. | |
| Inline in commit messages | Each fix commit body carries its own WR-N disposition rationale. Cleanest git-log but no single-pane view. | |

**User's choice:** In 44-01-PLAN.md task list
**Notes:** Reviewer can verify the full 16-WR disposition list before any execution begins.

### Q4: What commit granularity inside Plan 44-01 (REVIEW polish)?

| Option | Description | Selected |
|--------|-------------|----------|
| One commit per warning class | Group by category: thread-safety / CI hygiene / platform.rs correctness / pack_update_hint UX / WR-09 feat / WR-01 doc / misc INFO. ~5-7 commits. Phase 41 D-07 pattern. | ✓ |
| One commit per WR/IN finding | 16+ commits. Maximum git-log granularity but heavy ceremony for one-line fixes. | |
| Single mega-commit | All 16 warnings in one commit. Tightest atomic boundary, biggest diff to review. | |

**User's choice:** One commit per warning class

---

## REVIEW disposition policy

### Q1: Default disposition for the 16 REVIEW warnings?

| Option | Description | Selected |
|--------|-------------|----------|
| Default-fix; explicit defer only on cost | Each WR gets a code fix UNLESS cost is clearly disproportionate. Roadmap SC#1 forbids silent ignore — explicit PLAN.md row for every WR. | ✓ |
| Default-fix; no exceptions | Every warning fixed in-phase. Forces WR-09 + WR-05 decisions now. | |
| Suppress/defer-preferred | Optimize for tight mechanical drain: fix only cheap warnings; defer production decisions. | |

**User's choice:** Default-fix; explicit defer only on cost

### Q2: WR-05 pack-update synchronous startup-latency — which fix shape?

| Option | Description | Selected |
|--------|-------------|----------|
| (b) Drop synchronous entirely | Always refresh in background; first-run users see hint on 2nd run. Aligns with CLAUDE.md "Zero startup latency". | ✓ |
| (a) Bounded per-request timeout (2s) | Keep synchronous-first-run but cap to 2s/pack. Preserves first-run UX. | |
| Defer | File follow-up todo. Doesn't close WR-05 this phase. | |

**User's choice:** (b) Drop synchronous entirely

### Q3: WR-09 OIDC issuer-pin — wire production-side or defer?

| Option | Description | Selected |
|--------|-------------|----------|
| Implement reader in `crates/nono/src/trust/signing.rs` | Wire `NONO_TRUST_OIDC_ISSUER` into trust-signing path. Real production decision but small surface; closes the misleading-CI gap. | ✓ |
| Add TODO(D-15-clause-2) marker on workflow line | Reviewer's lighter suggestion; production wiring lands in a dedicated phase. | |
| Defer with no marker; file standalone todo only | Treat WR-09 as structural defer. | |

**User's choice:** Implement reader in `crates/nono/src/trust/signing.rs`
**Notes:** Scope expansion beyond pure drain — Phase 44 absorbs the production decision. Commits as `feat(44-01):`, not `chore:`.

### Q4: Phase 43 WR-01 `validate_restore_target` TOCTOU — doc-only or refactor?

| Option | Description | Selected |
|--------|-------------|----------|
| Doc-only — update doc comment + file follow-up | Reviewer's explicit suggestion. Residual race inherent to non-fd-based ops; full closure requires substantial refactor. | ✓ |
| Refactor to fd-relative ops now | Close TOCTOU via O_NOFOLLOW / openat. Cross-platform refactor; out-of-character for drain phase. | |
| Suppress with `#[allow]` and SUMMARY rationale | No code change, no follow-up. Loses the breadcrumb for future hardening. | |

**User's choice:** Doc-only — update doc comment + file follow-up

---

## Class D Linux deny-overlap strategy

### Q1: Reproduction strategy?

| Option | Description | Selected |
|--------|-------------|----------|
| Update assertion to accept runtime Landlock denial as equivalent | Todo's acceptance gate allows this. Security posture INTACT either way. Pure source change — no Linux host needed. | ✓ |
| Reproduce on Linux dev host, instrument, fix root cause | Per todo's "Suggested fix". Preferred root-cause but host-blocking. | |
| Defer to a Linux-host-required follow-up phase | Leave test #[ignore]'d; file new todo with Phase 46 host-dependency tag. Breaks SC#2 "un-ignored" promise. | |

**User's choice:** Update assertion to accept runtime Landlock denial as equivalent

### Q2: Assertion strictness?

| Option | Description | Selected |
|--------|-------------|----------|
| Either-or: accept validator OR runtime denial | stderr matches validator pre-flight string OR runtime Landlock denial string. Inline comment explains security equivalence. Most permissive. | ✓ |
| Strict runtime-only assertion | Replace assertion entirely with runtime-denial match. If validator pre-flight ever fires, test fails — forces deliberate re-update. | |
| Split into two tests — one per path | test_a asserts validator pre-flight; test_b asserts runtime denial. Highest maintenance overhead. | |

**User's choice:** Either-or: accept validator OR runtime denial

### Q3: Validator pre-flight investigation follow-up?

| Option | Description | Selected |
|--------|-------------|----------|
| File follow-up todo with runtime-equivalent doc | New todo captures 5-hypothesis branches from original; tagged for Linux-host follow-up phase. | ✓ |
| Skip — runtime denial is structurally equivalent | Don't track latent bug separately. | |
| Inline as a code comment in policy.rs only | Add TODO comment near `validate_deny_overlaps`. No separate todo file. | |

**User's choice:** File follow-up todo with runtime-equivalent doc

---

## Cross-binding lockstep + Class E flake

### Q1: Cross-binding lockstep mechanism (sibling repos NOT cloned locally)?

| Option | Description | Selected |
|--------|-------------|----------|
| Clone siblings to ../nono-py/ + ../nono-ts/ this phase; land commits in both | Plan 44-02 includes clone-or-verify task; lands FFI remap + CR-02 null-handle tests in both siblings as separate commits. Honors SC#4 "land" wording. | ✓ |
| Open coordinated PRs upstream; close phase on merge | Same code work but skip local clone — fork via `gh repo fork`. May host-block on maintainer response. | |
| File authoritative follow-up todos in both sibling repos | Phase 44 produces instruction packets only. Punts the actual lockstep — violates SC#4 "land". | |

**User's choice:** Clone siblings to ../nono-py/ + ../nono-ts/ this phase; land commits in both

### Q2: Sibling repo URLs — where do we clone from?

| Option | Description | Selected |
|--------|-------------|----------|
| Use whatever `git remote` reports in this repo | Plan 44-02 task #1 reads `git remote -v`; derives sibling URLs from same org. Surface deviation if differ. Doesn't hardcode URLs. | ✓ |
| Hardcode `https://github.com/always-further/nono-py` + `nono-ts` in PLAN.md | Phase 43 references that upstream; default same org. | |
| Ask the user during plan-open | Defer URL question to planner agent. | |

**User's choice:** Use whatever `git remote` reports in this repo

### Q3: Class E env_vars flake fix — cargo-nextest scope?

| Option | Description | Selected |
|--------|-------------|----------|
| Affected tests only via .config/nextest.toml | Per-test override (NEXTEST_TEST_THREADS=1 for 2 affected tests). Other tests stay parallel. Smallest blast radius. | ✓ |
| Crate-wide nextest with subprocess-per-test | All env-mutating tests move to subprocess-per-test. Larger CI workflow rewrite. | |
| Project-wide nextest adoption | Replace `cargo test` everywhere. Far larger scope; deferred. | |

**User's choice:** Affected tests only via .config/nextest.toml

### Q4: CR-03 + CR-04 carry-forward todos — status?

| Option | Description | Selected |
|--------|-------------|----------|
| Archive both — already resolved by Phase 41 | Plan 44-02 includes single bookkeeping commit moving v24-cr-03 + v24-cr-04 to `.planning/todos/done/` with Phase 41 close SHA as resolution ref. | ✓ |
| Leave pending; clean at milestone close | Don't touch. | |
| Re-verify before archiving | Grep-confirm fixes still present, then archive. Belt-and-suspenders. | |

**User's choice:** Archive both — already resolved by Phase 41

---

## Claude's Discretion

- Exact disposition wording for INFO findings — planner decides per finding using D-44-B5's "default-fix unless cost-prohibitive" rubric. Specific cases: Phase 37 IN-03 `format_bytes_short` shared-module dedup (small refactor; fold into D-44-A4 commits or defer), Phase 43 IN-01 atomic-write retrofit (low-cost; fix), Phase 43 IN-02 detached-JoinHandle (accept-as-documented).
- Test-thread-safety fix mechanics — D-44-E6 mandates `lock_env()` + `EnvVarGuard`; planner decides whether to delete file-local `EnvGuard` struct or keep as thin wrapper.
- `feat(44-01)` commit body for WR-09 — planner specifies env-var fallback shape + error class + test coverage for the new `crates/nono/src/trust/signing.rs` reader.
- `.config/nextest.toml` schema specifics — planner picks `[[profile.default.overrides]]` block shape vs `[test-groups]` declaration based on current nextest docs at plan-open.
- Sibling-repo test idiom — planner reads sibling repo conventions at clone-time (PyO3-style pytest vs unittest; napi-rs/vitest/jest).
- Plan numbering — `44-01-REVIEW-POLISH`, `44-02-TEST-HYGIENE-DRAIN`; planner may refine.

## Deferred Ideas

- `validate_restore_target` fd-relative TOCTOU hardening — substantial cross-platform refactor; new follow-up todo filed by planner at Plan 44-01 open.
- `validate_deny_overlaps` pre-flight investigation — Linux-host required; new follow-up todo per D-44-C3.
- Project-wide cargo-nextest adoption — dedicated phase if broader flake patterns emerge.
- Sibling-repo upstream PR coordination — plan-discretion based on clone-time discovery; may file sibling-repo coordination follow-up rather than block Phase 44 close indefinitely.
- Sigstore-verify 0.6.5 → 0.6.6 stretch upgrade (P32-DEFER-005) — stays in v2 deferred bucket per REQUIREMENTS.md.
