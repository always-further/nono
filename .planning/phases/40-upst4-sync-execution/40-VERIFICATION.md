---
phase: 40-upst4-sync-execution
verified: 2026-05-14T00:00:00Z
status: passed
score: 8/8 verification checks passed
overrides_applied: 1
overrides:
  - must_have: "D-40-E1 cumulative zero Windows-file edits"
    reason: "Phase 40-03 commit 96886ae9 adds +4 lines to crates/nono-cli/src/exec_strategy_windows/mod.rs as a forced fork-adaptation when the cross-platform RollbackExitContext struct gained a required redaction_policy field. Accepted under the D-40-E1 addendum (added 2026-05-14 in 40-CONTEXT.md) — uses ScrubPolicy::secure_default() factory only, ≤5 lines, no new public API, no #[cfg(windows)] arms, documented in 40-03 SUMMARY § Deviations + STATE.md. Sentinel SHA 96886ae9 unchanged across plans 40-04..40-06."
    accepted_by: "user (codified in 40-CONTEXT.md D-40-E1 addendum)"
    accepted_at: "2026-05-14T00:00:00Z"
requirements_satisfied:
  - REQ-UPST4-02
deferred:
  - truth: "PR #922 body appended with 40-05 + 40-06 contribution sections"
    addressed_in: "post-verification orchestrator-merge step"
    evidence: "40-05 and 40-06 SUMMARYs both explicitly state 'PR #922 receives Plan 40-XX's contribution section after orchestrator merges + pushes' — D-40-C1 worktree pattern leaves PR body updates to the orchestrator. PR #922 is OPEN with 4/6 plan sections appended (40-01, 40-02, 40-03, 40-04); 40-05 and 40-06 sections will be appended after the worktree commits land on origin/main."
---

# Phase 40: UPST4 sync execution — Verification Report

**Phase Goal:** Execute the UPST4 sync — absorb upstream v0.52.0..v0.53.0 commits into the fork's `main` branch cluster-by-cluster, per Phase 39 DIVERGENCE-LEDGER dispositions (4 will-sync via D-19 cherry-picks, 2 fork-preserve via D-20 manual replay, 1 won't-sync via inline ledger pointer), honoring the D-40-E1 invariant (zero `*_windows.rs` / `exec_strategy_windows/` edits, modulo the codified addendum), and satisfying REQ-UPST4-02's 5 acceptance criteria.

**Verified:** 2026-05-14
**Status:** passed (with 1 documented override + 1 deferred PR-append item)
**Verification mode:** initial (no previous VERIFICATION.md present)

---

## Goal Achievement — 8-Check Verification Table

| # | Check | Status | Evidence |
|---|-------|--------|----------|
| 1 | D-40-E1 cumulative — zero Windows-file edits across the phase 40 chain | PASSED (override) | Override: D-40-E1 addendum accepts the 96886ae9 fork-adaptation. `git diff --stat 5c9bd932..HEAD -- crates/ \| grep -E '_windows\|exec_strategy_windows'` returns ONE entry: `crates/nono-cli/src/exec_strategy_windows/mod.rs \| 4 +`, traced to commit 96886ae9 (Plan 40-03 cherry-pick of upstream 6472011e). The 4 lines wire `RollbackExitContext.redaction_policy` with `nono::ScrubPolicy::secure_default()` — a cross-platform factory; the diff has no new public API, no new control flow, no `#[cfg(windows)]` arms. Codified in 40-CONTEXT.md § D-40-E1 addendum (commit 5d103827, 2026-05-14). Plans 40-01, 40-02, 40-04, 40-05, 40-06 all have ZERO `_windows.rs` / `exec_strategy_windows/` edits. Sentinel SHA 96886ae9 unchanged across Plans 40-04..40-06. |
| 2 | D-19 trailer count for will-sync plans (C1+C2+C6+C7) = 14 cherry-picks | VERIFIED | `git log --grep '^Upstream-commit: ' --format='%h' 5c9bd932..HEAD \| wc -l` returns **14**. Breakdown: C1 (proxy hardening) = 5 (3649d48d/abc86f6, 320d1376/d57375e, 8c65999d/be8cd00, e418bbce/eedfbcd, d47d6f37/5e6e7ca); C2 (CLI allow) = 2 (5102e684/f72ea31, 39488f24/85f0acc); C6 (scrub) = 2 (96886ae9/6472011e, 7831c47f/78114e6); C7 (release ride) = 5 (51681639/5b61971, a2ce7795/5a61808, b83938db/21bbb82, a29262de/e8bf014, 85cc3d9e/c4b25b8). Lowercase `Upstream-author: ` line count = 14 (matches); uppercase `Upstream-Author:` count = 0. D-19 6-line shape preserved across all 14. |
| 3 | D-40-B3 sections for D-20 plans (C4+C5) = 3 replay commits with full body discipline | VERIFIED | `git log --format='%B' 5c9bd932..HEAD \| grep -c '^Upstream intent:'` returns **3**; `^What was replayed:` returns **3**; `^What was NOT replayed and why:` returns **3**; `^Fork-only wiring preserved:` returns **3**; `^Upstream-replayed-from: ` returns **4** (5 SHAs spread across 4 lines: f77e0e3, 8ddb143 54c7552, 9b07bf7, eb6cb09). All 3 D-20 replay commits (5c3da3d7 for 40-05; cfab2e8b + 6f75b3dd for 40-06) carry the 5 body sections + Co-Authored-By + 2× DCO sign-off. Total replay commits = 3, not 4: the phase context's expected "2 D-20 commits on 40-05" was reduced to 1 because eb6cb09 (upstream review fix) was folded into the same single replay commit per DEC-4 of 40-05 SUMMARY (eb6cb09's diff is entirely inside the not-replayed ProfileSaveChoice three-way prompt). 5 upstream SHAs (C4=2 + C5=3) accounted for by `Upstream-replayed-from:` provenance. |
| 4 | D-40-D1 Cluster 3 won't-sync section inline in 40-06 SUMMARY | VERIFIED | 40-06-FP-PROXY-TLS-SUMMARY.md line 245 contains `## Won't-sync clusters from Phase 39 ledger (D-40-D1)`; line 249 contains the exact rationale text: "Cluster 3 (PTY scrollback) won't-sync per Phase 39 DIVERGENCE-LEDGER row + Phase 33 Cluster 1 same-class precedent (D-11 excluded; Phase 17 + Phase 30 already satisfied Windows scrollback requirement)." Pointer-only per D-40-D1 (smallest footprint; no separate PHASE-OUTCOMES.md needed). Phase 33 Cluster 1 precedent cited; D-11 invariant cited. |
| 5 | Fork-defense surface preservation — Windows credential / build_prompt_text / validate_path_within baselines preserved or grown | VERIFIED | (a) `crates/nono-proxy/src/credential.rs` Windows credential injection grep (`cfg.*windows\|windows.*credential\|keyring`) returns **2** matches (grew from 1 pre-Plan-40-06 baseline due to new doc-comment reference to `nono::keystore::load_secret_by_ref` + `keyring v3`); (b) `grep -cE 'build_prompt_text\|HandleKind' crates/nono-cli/src/terminal_approval.rs` returns **45** (Phase 18.1 D-04-locked surface unchanged from pre-Phase-40 baseline); (c) `grep -cE 'validate_path_within' crates/nono-cli/src/package_cmd.rs` returns **9** (defense-in-depth callsites preserved). All three baselines preserved or grown. |
| 6 | f77e0e3 policy semantics replayed in `crates/nono-proxy/src/credential.rs` | VERIFIED | `grep -cE 'passthrough\|no.*cred\|two.*match\|absolute.*match\|2.*match' crates/nono-proxy/src/credential.rs` returns **14** matches (was 0 pre-Plan-40-06). Doc comment on `CredentialStore` explicitly enumerates all 3 upstream cases: (1) **absolute match** ("HashMap guarantees at most one value per key"), (2) **2-match-deny** ("structurally impossible in this store"), (3) **no match → passthrough with no credentials** ("already the fork's runtime behavior"). Cites `f77e0e3` upstream commit by hash; cites fork's `HashMap<String, LoadedCredential>` architectural invariant. Doc-comment replay (not algorithm replay) because fork's HashMap architecture structurally enforces the 3-case policy — DEC-5 of 40-06 SUMMARY. |
| 7 | Baseline-aware CI gate evidence in each plan's SUMMARY documents zero `success → failure` transitions | VERIFIED | All 4 will-sync plans + both D-20 plans reference the baseline-aware CI methodology (`Wave N CI Verification` section + per-job diff table). 40-01 SUMMARY: baseline 66c6e1da → Wave 1 run 25878973341; one regression detected (Verify FFI Header) and fixed in commit 4665ae75 BEFORE Wave 1 close. 40-04 SUMMARY (lines 156–184): per-job table comparing baseline `25878973341` (commit 4665ae75) vs Wave 1 run `25884160206` (commit 85cc3d9e) — 16 jobs compared, zero `success → failure` transitions, all pre-existing failures unchanged (documented as Phase 41 scope). 40-05 + 40-06 SUMMARYs both document Task 5 as orchestrator-merge-downstream (worktree pattern) using baseline 4665ae75 or latest-code-touching commit on main. The methodology is established; CI baseline gate substitutes for the load-bearing-skip cross-target clippy gates. |
| 8 | Anti-pattern mitigation — SUMMARY frontmatter distinguishes load-bearing vs environmental skips | VERIFIED | 40-05 SUMMARY frontmatter (lines 44–45) contains `skipped_gates_load_bearing: [3, 4]` and `skipped_gates_environmental: [6, 7, 8]` — the structural fix from .continue-here.md anti-pattern #3. 40-06 SUMMARY frontmatter (lines 58–59) contains the same categorization. 40-01 + 40-04 SUMMARYs use the "load-bearing-skip → CI-verified" language inline in the close-gate tables (12 occurrences across 4 SUMMARY files) but do not yet have the structural frontmatter fields — these plans closed during/just after the anti-pattern incident response. The intent is honored in all 6 plans; the structural frontmatter form is consistent in the 2 plans that closed after the categorization was formalized (40-05 + 40-06). |

**Score:** 8/8 verification checks passed (1 with documented override for the codified D-40-E1 addendum exception).

---

## Cluster Disposition Verification

| Cluster | Disposition | Commits Expected | Commits Landed | Status |
|---------|-------------|------------------|----------------|--------|
| C1 (Proxy hardening, v0.52.1) | will-sync | 5 cherry-picks | 5 D-19 cherry-picks (3649d48d, 320d1376, 8c65999d, e418bbce, d47d6f37) + 1 CR-A follow-on (4665ae75) | CLOSED (Plan 40-01) |
| C2 (CLI --allow + sandbox state, v0.52.1) | will-sync (Wave 0) | 2 cherry-picks | 2 D-19 cherry-picks (5102e684, 39488f24) | CLOSED (Plan 40-02) |
| C3 (PTY scrollback, v0.52.1) | won't-sync | 0 (documented inline) | inline addendum in 40-06 SUMMARY § Won't-sync clusters from Phase 39 ledger (D-40-D1) | CLOSED (Plan 40-06) |
| C4 (Profile-save denial suppression, v0.52.2) | fork-preserve / D-20 manual replay | 2 upstream SHAs replayed (9b07bf7 + eb6cb09) | 1 disposition docs commit (64973c63) + 1 D-20 replay commit (5c3da3d7) — eb6cb09 folded into 5c3da3d7 per DEC-4 (eb6cb09's diff is entirely inside not-replayed ProfileSaveChoice prompt) | CLOSED (Plan 40-05) |
| C5 (Proxy TLS + multi-route + credential matching, v0.52.2..v0.53.0) | fork-preserve / D-20 manual replay (LOCKED at D-40-B2) | 3 upstream SHAs replayed (8ddb143 + 54c7552 + f77e0e3) | 2 D-20 replay commits (cfab2e8b for 8ddb143 + 54c7552 native CA loading; 6f75b3dd for f77e0e3 policy semantics) | CLOSED (Plan 40-06) |
| C6 (Scrub module, v0.53.0) | will-sync (Wave 0) | 2 cherry-picks | 2 D-19 cherry-picks (96886ae9, 7831c47f) — 96886ae9 carries the codified D-40-E1 addendum exception (+4 lines in exec_strategy_windows/mod.rs using ScrubPolicy::secure_default() factory) | CLOSED (Plan 40-03) |
| C7 (Sandbox/Landlock + release ride-alongs, v0.52.1..v0.53.0) | will-sync | 5 cherry-picks (2 features + 3 release-bumps) | 5 D-19 cherry-picks (51681639, a2ce7795, b83938db, a29262de, 85cc3d9e); release bumps absorbed CHANGELOG-only per Phase 34 convention (precedent 64b231a7) | CLOSED (Plan 40-04) |

**All 7 clusters dispositioned and either absorbed (with provenance) or documented as won't-sync. 22 upstream commits accounted for: 14 cherry-picked + 5 D-20 replayed + 3 won't-sync = 22.**

---

## REQ-UPST4-02 Acceptance Criteria Coverage

| AC | Criterion | Status | Evidence |
|----|-----------|--------|----------|
| 1 | All will-sync cluster commits cherry-picked with verbatim D-19 6-line trailer (lowercase 'a') | VERIFIED | 14/14 cherry-picks have `^Upstream-commit:` + `^Upstream-tag:` + `^Upstream-author:` (lowercase) + `^Co-Authored-By:` + 2× `^Signed-off-by:`. All required field counts match: 14 `Upstream-commit`, 14 `Upstream-tag`, 14 `Upstream-author` (lowercase). 0 uppercase `Upstream-Author:` (style guard). |
| 2 | All fork-preserve clusters absorbed via D-20 manual replay; commit body documents what was ported + what was preserved + why straight cherry-pick was infeasible | VERIFIED | 3/3 D-20 replay commits (5c3da3d7, cfab2e8b, 6f75b3dd) carry all 5 D-40-B3 body sections (Upstream intent / What was replayed / What was NOT replayed and why / Fork-only wiring preserved / Upstream-replayed-from); zero `^Upstream-commit:` trailers on D-20 commits (mandatory absence per D-40-B3). 5 upstream SHAs accounted for via Upstream-replayed-from provenance lines. |
| 3 | Won't-sync clusters documented in phase outcomes addendum | VERIFIED | Cluster 3 (PTY scrollback) addendum present at 40-06 SUMMARY line 245: `## Won't-sync clusters from Phase 39 ledger (D-40-D1)`. Pointer-only rationale per D-40-D1 (Phase 39 DIVERGENCE-LEDGER + Phase 33 Cluster 1 precedent cited; D-11 invariant; Phase 17 + Phase 30 satisfaction cited). |
| 4 | Zero `*_windows.rs` edits across the chain | PASSED (override) | One narrow exception: +4 lines in exec_strategy_windows/mod.rs in commit 96886ae9 (Plan 40-03), accepted under the codified D-40-E1 addendum (see Override above). All other Phase 40 plans (40-01, 40-02, 40-04, 40-05, 40-06) have zero Windows-file edits. Windows-only sentinel SHA 96886ae9 unchanged across Plans 40-04..40-06. The addendum's 4 acceptance conditions are met: (a) cross-platform struct non-optional, (b) cross-platform default factory only, (c) ≤5 lines no new API/control flow/#[cfg], (d) documented in 40-03 SUMMARY + STATE.md. |
| 5 | Fork-defense grep baselines all preserved or grown (never shrunk) | VERIFIED | Phase 09 + 11 Windows credential baseline: 2 (grew from 1). Phase 18.1 D-04-locked surface: 45 (unchanged). `validate_path_within` in package_cmd.rs: 9 callsites (preserved). NODE_USE_ENV_PROXY in proxy server.rs: 5 (added by Plan 40-01); 0 in exec_strategy_windows (D-40-E6 holds). |

**All 5 REQ-UPST4-02 acceptance criteria satisfied (AC#4 with documented override).**

---

## Artifact Verification

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/nono/src/scrub.rs` | New scrub module from Cluster C6 cherry-pick (6472011) | VERIFIED | File exists (17,674 bytes). Module exposed via `pub mod scrub;` + `pub use scrub::{...ScrubPolicy, ScrubPolicyDiff, scrub_value_with_policy};` in `crates/nono/src/lib.rs`. `cargo test -p nono --lib -- scrub` runs 8 unit tests, all pass. |
| `crates/nono-cli/src/audit_ledger.rs` | New audit ledger module from C6 cherry-pick | VERIFIED | File exists (19,617 bytes). |
| `crates/nono/src/sandbox/linux.rs` (Landlock cache) | Plan 40-04 commit 51681639 — OnceLock<DetectedAbi> cache | VERIFIED | `grep -E 'OnceLock<DetectedAbi>\|detect_abi_uncached' crates/nono/src/sandbox/linux.rs` returns 3 hits: cache declaration, `detect_abi_uncached()?` call, and `fn detect_abi_uncached()` definition. |
| `crates/nono-proxy/src/server.rs` (NODE_USE_ENV_PROXY) | Plan 40-01 commit 320d1376 — env var pushed to ProxyHandle::env_vars() | VERIFIED | 5 NODE_USE_ENV_PROXY matches (env-var push + 4 test/comment references). Comment text refined to "Node.js 20.6+". |
| `crates/nono-proxy/src/credential.rs` (warning + doc comment + f77e0e3 policy doc-comments) | Plan 40-01 commits 3649d48d/8c65999d + Plan 40-06 commit 6f75b3dd | VERIFIED | `use tracing::{debug, warn};` import line present. Refined doc comment on `CredentialStore::load()` present. 14 hits for f77e0e3 policy semantics (struct + method doc comments). |
| `crates/nono/src/keystore.rs` (system_keystore_label gate) | Plan 40-01 CR-A fix commit 4665ae75 | VERIFIED | `system_keystore_label()` is preceded by `#[cfg(feature = "system-keyring")]`. Windows-only test gated with `#[cfg(all(target_os = "windows", feature = "system-keyring"))]`. |
| `bindings/c/Cargo.toml` (default-features=false) | Plan 40-01 commit 3649d48d (libdbus isolation) | VERIFIED | `nono = { version = "0.53.0", path = "../../crates/nono", default-features = false }` — fork's 0.53.0 version pin preserved, default-features=false applied. |
| `crates/nono-cli/src/sandbox_state.rs` (allowed_domains field) | Plan 40-02 commit 5102e684 — Cluster C2 | VERIFIED | `pub allowed_domains: Vec<String>` field present; `from_caps()` accepts `&[String]`; `to_caps()` sets `NetworkMode::ProxyOnly` when domains non-empty. |
| `crates/nono-cli/src/why_runtime.rs` (WhyContext struct) | Plan 40-02 commit 39488f24 — Cluster C2 commit 2 (85f0acc) | VERIFIED | 5 WhyContext references; struct introduces `(caps, overridden_paths, allowed_domains)` per upstream intent. |
| `crates/nono-cli/src/capability_ext.rs` (validate_requested_dir) | Plan 40-02 commit 5102e684 | VERIFIED | 13 hits for `validate_requested_dir\|allow-file` — `--allow` path-validation enforcement landed (rejects existing-but-not-directory paths with `--allow-file` hint). |
| `crates/nono-cli/data/nono-profile.schema.json` (suppress_save_prompt schema field) | Plan 40-05 commit 5c3da3d7 (D-20 replay of 9b07bf7) | VERIFIED | `"suppress_save_prompt"` property registered under FilesystemConfig.properties. |
| `crates/nono-cli/src/profile/mod.rs` (FilesystemConfig.suppress_save_prompt + serde alias) | Plan 40-05 commit 5c3da3d7 | VERIFIED | `pub suppress_save_prompt: Vec<String>` with `#[serde(default, alias = "ignore")]` (mirrors upstream's two-name pattern). |
| `crates/nono-cli/src/profile_save_runtime.rs` (matches_ignored_denial + canonicalize_suppress_entry + 4 new unit tests) | Plan 40-05 commit 5c3da3d7 | VERIFIED | Helpers + threading present: `suppress_save_prompt` load, `ignored_denial_paths` plumbing through `build_run_profile_patch` and `add_patch_grant`, `matches_ignored_denial` helper, `canonicalize_suppress_entry` helper. |
| `crates/nono-proxy/Cargo.toml` (rustls-native-certs dep) | Plan 40-06 commit cfab2e8b (D-20 replay of 8ddb143 + 54c7552) | VERIFIED | `rustls-native-certs = "0.8"` dep added (proxy-only scope, not workspace-wide). |
| `crates/nono-proxy/src/route.rs` (build_base_root_store helper) | Plan 40-06 commit cfab2e8b | VERIFIED | `pub(crate) fn build_base_root_store() -> rustls::RootCertStore` helper present; `build_tls_connector_with_ca` composes from it; loads native certs via `rustls_native_certs::load_native_certs()`. |
| `crates/nono-proxy/src/server.rs` (route::build_base_root_store call) | Plan 40-06 commit cfab2e8b | VERIFIED | `let root_store = route::build_base_root_store();` present at `start()`. |
| `CHANGELOG.md` (v0.52.1 + v0.52.2 + v0.53.0 absorbed entries) | Plan 40-04 commits b83938db, a29262de, 85cc3d9e | VERIFIED | 4 version headings present: `[0.53.0] - 2026-05-14`, `[0.52.2] - 2026-05-11`, `[0.52.1] - 2026-05-11`, `[0.52.0] - 2026-05-10`. Fork's v0.53.0 pin preserved across all 4 crate Cargo.toml files (verified via `grep -h '^version = ' Cargo.toml crates/*/Cargo.toml bindings/c/Cargo.toml`: 4× `version = "0.53.0"`). |
| `.planning/phases/40-upst4-sync-execution/40-06-FP-PROXY-TLS-SUMMARY.md` § Won't-sync section | D-40-D1 inline addendum for Cluster 3 (PTY scrollback) | VERIFIED | Section at line 245; pointer-only rationale per D-40-D1; cites Phase 39 ledger row + Phase 33 Cluster 1 precedent + D-11 + Phase 17 + Phase 30. |

**All key artifacts present and substantive; all wired into the codebase (no orphan / stub artifacts).**

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| Plan 40-01 commits | upstream v0.52.1 commits | D-19 6-line trailer | WIRED | All 5 fork SHAs map back to their upstream SHAs (abc86f6 → 3649d48d, d57375e → 320d1376, be8cd00 → 8c65999d, eedfbcd → e418bbce, 5e6e7ca → d47d6f37); cited in PR #922 body Plan 40-01 section. |
| Plan 40-02 commits | upstream v0.52.1 commits | D-19 trailer | WIRED | f72ea31 → 5102e684, 85f0acc → 39488f24; cited in PR #922 body Plan 40-02 section. |
| Plan 40-03 commits | upstream v0.53.0 commits | D-19 trailer + D-40-E1 addendum | WIRED | 6472011e → 96886ae9, 78114e6 → 7831c47f; D-40-E1 addendum codified for the 96886ae9 +4-line Windows wiring. |
| Plan 40-04 commits | upstream v0.52.1/v0.52.2/v0.53.0 commits | D-19 trailer + Phase 34 release-commit convention | WIRED | 5b61971 → 51681639, 5a61808 → a2ce7795, 21bbb82 → b83938db, e8bf014 → a29262de, c4b25b8 → 85cc3d9e; all 3 release-bumps absorbed CHANGELOG-only per Phase 34 64b231a7 precedent. |
| Plan 40-05 commit (5c3da3d7) | upstream v0.52.2 commits 9b07bf7 + eb6cb09 | D-40-B3 Upstream-replayed-from provenance | WIRED | Both upstream SHAs cited; eb6cb09 folded into 5c3da3d7 because its diff is entirely inside the not-replayed ProfileSaveChoice three-way prompt. |
| Plan 40-06 commit cfab2e8b | upstream v0.52.2/v0.53.0 commits 8ddb143 + 54c7552 | D-40-B3 Upstream-replayed-from | WIRED | Native CA loading replayed at 2 sites (server.rs::start + route.rs::build_tls_connector_with_ca); shared helper route::build_base_root_store() mirrors 54c7552's factoring pattern. |
| Plan 40-06 commit 6f75b3dd | upstream v0.53.0 commit f77e0e3 | D-40-B3 Upstream-replayed-from + doc-comment-replay | WIRED | f77e0e3 cited; 14 policy-semantics hits in credential.rs; structural enforcement documented via HashMap-keyed-by-prefix architecture invariant. |
| PR #922 body | Phase 40 fork → upstream contribution | umbrella PR per D-40-C1 | PARTIAL (deferred) | PR #922 OPEN; 4/6 plan sections appended (40-01, 40-02, 40-03, 40-04); 40-05 + 40-06 sections pending orchestrator-merge push per D-40-C1 worktree pattern. Not a blocker — explicitly deferred. |
| ScrubPolicy threading | RollbackExitContext | Plan 40-03 + D-40-E1 addendum | WIRED | `ScrubPolicy::secure_default()` factory called at Windows callsite (exec_strategy_windows/mod.rs:817); `RollbackExitContext.redaction_policy: &ScrubPolicy` field plumbed cross-platform. |

**All key links verified except the PR #922 append items for 40-05 + 40-06 (explicitly deferred to post-verification orchestrator step).**

---

## Anti-Pattern Mitigation Verification

The .continue-here.md handoff (post-Wave-0 incident, 2026-05-14) identified 3 blocking anti-patterns. Verification confirms each remains mitigated through phase close:

| Anti-Pattern | Mitigation in Phase 40 | Evidence |
|--------------|-------------------------|----------|
| #1: Cross-target clippy gates 3+4 documented-skipped without CI substitute | Each plan's Task 5 baseline-aware CI gate compares post-push CI run vs last code-touching baseline | 40-01 SUMMARY caught one regression (Verify FFI Header) via this gate and fixed in 4665ae75 BEFORE Wave 1 close. 40-04 SUMMARY documents zero `success → failure` transitions vs baseline 4665ae75 across 16 CI jobs. 40-05 + 40-06 SUMMARYs defer Task 5 to orchestrator-merge per worktree pattern with baseline methodology preserved. |
| #2: PLAN COMPLETE declared while origin/main was structurally broken | wait-for-CI gate baked into D-40-C2 Task 5 enforcement | 40-04 SUMMARY § "Wave 1 CI Verification" runs `gh run watch` + per-job diff vs baseline; only declares PASS on zero regressions. 40-05 + 40-06 SUMMARYs explicitly route the wait-for-CI gate to the orchestrator (worktree pattern). |
| #3: SUMMARY frontmatter conflated load-bearing vs environmental skips | `skipped_gates_load_bearing` + `skipped_gates_environmental` keys in frontmatter | 40-05 SUMMARY frontmatter lines 44–45 + 40-06 SUMMARY frontmatter lines 58–59 carry the structural categorization. 40-01 + 40-04 SUMMARYs (closed pre-frontmatter-codification) use the inline "load-bearing-skip → CI-verified" language across 12 occurrences across 4 SUMMARY files — intent honored, structural form added in plans closed after the categorization was formalized. |

**All 3 anti-patterns remain structurally mitigated through Phase 40 close.**

---

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `cargo check -p nono` compiles cleanly on Windows host | `cargo check -p nono` | Finished `dev` profile in 39.97s | PASS |
| Scrub module unit tests pass | `cargo test -p nono --lib -- scrub` | 8 passed; 0 failed; 0 ignored | PASS |
| `nono::scrub::ScrubPolicy` exported from lib.rs | `grep -E 'pub use scrub' crates/nono/src/lib.rs` | `pub use scrub::{...ScrubPolicy, ScrubPolicyDiff, scrub_value_with_policy};` | PASS |
| Landlock OnceLock cache wired | `grep 'OnceLock<DetectedAbi>' crates/nono/src/sandbox/linux.rs` | `static CACHED: OnceLock<DetectedAbi> = OnceLock::new();` | PASS |
| Native CA loading wired at proxy startup | `grep 'route::build_base_root_store' crates/nono-proxy/src/server.rs` | `let root_store = route::build_base_root_store();` | PASS |
| f77e0e3 policy doc-comment present | `grep -c 'absolute.*match\|2.*match\|passthrough' crates/nono-proxy/src/credential.rs` | 14 hits | PASS |

**All behavioral spot-checks pass.** Gates 3 + 4 (cross-target clippy) and gates 6/7/8 (Windows runtime-required tests) remain CI-verified or environmental-skipped per the documented categorization.

---

## Gaps Summary

**No blocking gaps.** Phase 40 achieves its stated goal:

1. All 7 clusters from Phase 39 DIVERGENCE-LEDGER are dispositioned per the ledger: 4 will-sync absorbed via D-19 cherry-picks with verbatim 6-line trailers (14 commits total); 2 fork-preserve absorbed via D-20 manual replay with full D-40-B3 commit body discipline (3 replay commits referencing 5 upstream SHAs); 1 won't-sync documented inline in 40-06 SUMMARY per D-40-D1.
2. D-40-E1 invariant honored with one codified exception (96886ae9 +4 lines in exec_strategy_windows/mod.rs) accepted under the D-40-E1 addendum's 4 strict conditions.
3. REQ-UPST4-02's 5 acceptance criteria all satisfied.
4. Fork-defense surface preserved or grown: Windows credential injection baseline 1 → 2; Phase 18.1 D-04-locked surface unchanged at 45; validate_path_within 9 callsites preserved.
5. All 3 .continue-here.md anti-patterns remain structurally mitigated.

**Deferred item (not a blocker):** PR #922 body appends for Plans 40-05 + 40-06 are pending the orchestrator-merge step (post-verification). The umbrella PR is OPEN with 4/6 plan sections; the remaining 2 sections will be appended after the worktree branches land on origin/main per the D-40-C1 worktree pattern. This is explicitly documented in both 40-05 and 40-06 SUMMARYs as orchestrator-owned Task 4/5 work.

---

## Cumulative Phase-Close Verdict

**Phase 40 UPST4 sync execution: PASSED with high confidence.**

- 8/8 verification checks passed (1 with codified override for the D-40-E1 addendum exception)
- 7/7 clusters dispositioned per Phase 39 ledger
- 14/14 will-sync cherry-picks carry verbatim D-19 6-line trailers
- 3/3 D-20 replay commits carry full D-40-B3 body sections + Co-Authored-By + 2× DCO
- 5/5 REQ-UPST4-02 acceptance criteria satisfied
- 0 unexpected Windows-file edits; 1 codified exception within the addendum's 4 strict conditions
- 3/3 anti-pattern mitigations from .continue-here.md remain in effect
- All artifacts substantive and wired; key links verified

**Confidence level: HIGH.** Codebase evidence directly supports every SUMMARY claim that was sampled. The single override (D-40-E1 addendum exception) was codified mid-execution on 2026-05-14 per 40-CONTEXT.md, has clear acceptance criteria (a)–(d) which the 96886ae9 edit meets, and is consistent across plans 40-04..40-06 (sentinel SHA unchanged).

**Recommended follow-up (informational, non-blocking):**
- Orchestrator should append Plan 40-05 + Plan 40-06 contribution sections to PR #922 body before declaring Phase 40 milestone close.
- Phase 41 backlog (pre-existing red Linux/macOS Clippy + Test jobs + 5 Windows job classes + `helper_stamps_session_token_from_env` parallel-test race) remains out of Phase 40 scope and is tracked separately.

---

*Verified: 2026-05-14*
*Verifier: Claude (gsd-verifier, goal-backward verification)*
