---
phase: 43-upst5-sync-execution
plan: 05
cluster_id: 5
subsystem: profile-deserialization + platform-detection
tags: [upstream-sync, fork-preserve, D-20-manual-replay, when-predicate, platform-detection, foundation, Wave-2a]
status: COMPLETE
disposition: fork-preserve
resolved_disposition: fork-preserve
disposition_resolution_evidence: .planning/phases/43-upst5-sync-execution/43-05-DISPOSITION-RESOLUTION.md
upstream_range: v0.53.0..v0.54.0
upstream_shas: [ce06bd59]
upstream_tag: v0.54.0
baseline_sha: 13cc0628
dependency_graph:
  requires:
    - "Plan 43-04 RELEASE-RIDE close (Wave 1 sequential predecessor; commit 6b00932f release-ride landed at HEAD~10)"
    - "Plan 43-01b workspace MSRV 1.95 baseline + lints workspace inheritance"
    - "Phase 42 DIVERGENCE-LEDGER Cluster 5 fork-preserve default per D-42-C3"
    - "Phase 36-01b From<ProfileDeserialize> for Profile exhaustive enumeration discipline"
    - "Phase 36-01c bypass_protection canonical-name rename"
  provides:
    - "crates/nono-cli/src/platform.rs (NEW module — host detection + When-predicate evaluation; 659 lines replayed verbatim)"
    - "Field-level platform-conditional deserialization for filesystem paths, env_credentials, open_urls.allow_origins"
    - "WhenPredicate / ConditionalPath / ConditionalName / ConditionalOrigin schema $defs (parity surface for future fork evolution)"
    - "W-4 fix mitigation precedent for D-20 replays that SKIP wiring.rs"
  affects:
    - "Plan 43-06 PLATFORM-DETECTION-WINDOWS (Wave 2b sequential) — builds on platform.rs as Windows-registry-parsing foundation; UNBLOCKED"
    - "Phase 43 close: § Wave 2a integrated into 43-SUMMARY.md"
    - "Future fork evolution toward a pub struct GroupsConfig — deserialize_conditional_name_vec helper pre-staged for wiring"
tech_stack:
  added:
    - "crate::platform module: PlatformInfo / Os / LinuxInfo / MacosInfo / WindowsInfo data types"
    - "When predicate grammar (closed; security-relevant fail-secure parse-error-on-unknown-syntax)"
    - "OnceLock-cached host detection (zero per-deserialization perf cost)"
  patterns:
    - "D-20 manual replay 5-section commit body (Phase 40 Plan 40-05 precedent)"
    - "Disposition resolution committed as separate docs-only commit BEFORE any code change (Phase 40 Plan 40-05 pattern; W-8 fix canonical disposition values)"
    - "MSRV-bump-surfaced lint Rule-3 deviation: clippy::unnecessary_map_or → is_none_or auto-fix as separate fix(43-05-cra): commit (mirrors Plan 43-01b clippy::manual_is_multiple_of precedent)"
    - "Field-level platform-conditional list deserialization via deserialize_with helper functions consuming { path/name/origin, when } object forms"
key_files_created:
  - crates/nono-cli/src/platform.rs
  - .planning/phases/43-upst5-sync-execution/43-05-DISPOSITION-RESOLUTION.md
  - .planning/phases/43-upst5-sync-execution/43-05-CLOSE-GATE.md
  - .planning/phases/43-upst5-sync-execution/43-05-PR-SECTION.md
  - .planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md
key_files_modified:
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/data/nono-profile.schema.json
  - .planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-PLAN.md
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; platform.rs contains cfg-gated Linux branches (detect_linux, /etc/os-release parser) — load-bearing per cross-target-verify-checklist § PARTIAL Disposition"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; platform.rs contains cfg-gated macOS branches (detect_macos, sw_vers shell-out) — load-bearing per cross-target-verify-checklist § PARTIAL Disposition"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_7_wfp_port_integration: "cargo-level passed in Gate 1; deep WFP kernel-filter installation environmental-skip per D-40-C2"
  gate_8_learn_windows_integration: "cargo-level passed in Gate 1; deep learn-runtime substrate environmental-skip per D-40-C2"
key_decisions:
  - "DEC-1 (Task 1 verdict per D-43-C1): resolved_disposition = fork-preserve. Trial cherry-pick produced 7 conflicts (6 content + 1 modify/delete in docs/cli/features/package-publishing.mdx which fork deleted entirely). Clause (a) FAIL. Surface-semantics divergence: fork has no `pub struct GroupsConfig` — upstream Profile.groups: GroupsConfig vs fork flat `groups: Vec<String>`. Clause (b) FAIL. Verdict committed as docs-only `22df643d` BEFORE any code change (Phase 40 Plan 40-05 pattern). W-8 fix: canonical `fork-preserve` value written into PLAN.md frontmatter `resolved_disposition:` field; `disposition:` stays at conservative default."
  - "DEC-2 (Minimal replay scope per Phase 40 Plan 40-05 DEC-2 + Cluster 5 specifics): Replayed (a) platform.rs verbatim 659 lines (security-relevant closed grammar; no fork-only collision points), (b) 4 helper deserialize functions in profile/mod.rs, (c) 9 FilesystemConfig fields + OpenUrlConfig::allow_origins wired with deserialize_with, (d) SecretsConfig derive→manual Deserialize swap accepting conditional object form, (e) schema WhenPredicate/ConditionalPath/ConditionalName/ConditionalOrigin definitions + reference updates, (f) one integration test, (g) `mod platform;` declaration. SKIPped wiring.rs (no callers; would be dead code), policy.rs (fork's Group::platform already provides the concept), package_cmd.rs (Cluster 1 surface; not load-bearing), MDX docs (fork's docs/ subtree deleted). GroupsConfig replay deferred to a future fork-side refactor toward a pub struct GroupsConfig."
  - "DEC-3 (W-4 fix mitigation): wiring.rs SKIPped per DEC-2; W-4 fix requires that JSON schema's `when:` predicate not silently no-op. Field-level `when:` (the load-bearing surface) is fully consumed by the replayed deserialize_conditional_*_vec helpers + manual SecretsConfig Deserialize. Directive-level `when:` (the SKIPped surface) is rejected fail-secure by fork's existing `#[serde(deny_unknown_fields)]` on WiringDirective enum variants — no silent divergence path. Mitigation evidence recorded in CLOSE-GATE.md § W-4 fix mitigation evidence."
  - "DEC-4 (Rust 1.95 lint Rule-3 deviation): Gate 2 (Windows clippy) surfaced one new `clippy::unnecessary_map_or` error at platform.rs:232 — upstream's `when.map_or(true, |p| p.matches(current()))` form. Auto-fix `when.is_none_or(|p| p.matches(current()))` applied as separate commit d4285ead with subject prefix `fix(43-05-cra):` mirroring Plan 43-01b DEC-4 / commit 2603c7a6 precedent for `clippy::manual_is_multiple_of`. Mechanical rewrite; equivalent semantics; preserves zero green→red CI lane transition guarantee."
  - "DEC-5 (W-8 fix compliance): canonical disposition values used throughout. PLAN.md frontmatter `disposition: fork-preserve` (conservative default per D-42-C3, unchanged). PLAN.md frontmatter `resolved_disposition: fork-preserve` (Task 1 verdict, written via `Edit` tool from initial `null` value). SUMMARY frontmatter mirrors. No non-canonical strings like `TBD-at-plan-open` or `will-sync-via-diff-inspection-upgrade` appear anywhere."
  - "DEC-6 (Phase 36-01b discipline preserved automatically): Cluster 5 adds NO new top-level Profile field. Conditional logic is wired INSIDE FilesystemConfig / OpenUrlConfig field-level deserializers + the new manual SecretsConfig Deserialize impl. The `From<ProfileDeserialize> for Profile` exhaustive enumeration at profile/mod.rs:1893+ is UNTOUCHED. Rustc's struct-literal completeness check remains the structural guard against any future regression (if a future plan adds a new top-level field without updating the impl, rustc will reject)."
patterns_established:
  - "D-20 manual replay with verbatim NEW-file content: when the upstream NEW file (here platform.rs) has no fork-only collision points AND is security-relevant (closed grammar, fail-secure parse errors), the full file content is replayed verbatim — not artificially crippled to a minimal subset. The minimal-replay-scope discipline applies to MODIFIED files where collision-avoidance is the constraint."
  - "Field-level conditional deserialization without top-level Profile field changes: extending Profile evaluation behavior (filtering list entries based on host platform) is layered into field-level `deserialize_with` helpers + a manual Deserialize impl on one nested struct. Phase 36-01b's `From<ProfileDeserialize> for Profile` exhaustive enumeration is preserved automatically by this approach. Future plans extending similar conditional behavior should follow the same pattern (avoid adding a new top-level Profile field if the semantic can be expressed via field-level deserializer)."
  - "W-4 fix decision tree (Branch B + wiring.rs SKIPped): (1) Identify whether the SKIPped surface is reachable from JSON schema; (2) If reachable: enforce fail-secure rejection at deserialization via existing `deny_unknown_fields` OR new explicit error. Field-level vs directive-level scopes have different mitigation paths — field-level (consumed) needs the helpers wired; directive-level (rejected) needs the deny_unknown_fields invariant verified."
requirements_completed:
  - "REQ-UPST5-02 (partial — Cluster 5 fork-preserve disposition portion). Acceptance criteria #2 (every fork-preserve cluster has a documented rationale) and #3 (windows-touch:yes cluster handled per audit disposition with explicit Phase 43 plan-phase verdict) both advanced."
duration_minutes: 404
completed: "2026-05-18"
---

# Phase 43 Plan 05: Platform-Detection-Foundation — Cluster 5 D-20 manual replay

## Outcome

**One-liner:** Fork-preserve D-20 manual replay of upstream `ce06bd59 feat(profile): add platform-conditional profile fields` (v0.54.0). Lands as 3 atomic commits: (1) `docs(43-05):` disposition resolution per Phase 40 Plan 40-05 pattern; (2) `feat(43-05):` replay with verbatim 659-line `platform.rs` + field-level conditional deserializers + schema updates + integration test; (3) `fix(43-05-cra):` rust-1.95 `clippy::unnecessary_map_or` auto-fix. Phase 36-01b `From<ProfileDeserialize>` exhaustive enumeration discipline preserved automatically. W-4 fix mitigation satisfied (wiring.rs SKIPped; directive-level `when:` rejected fail-secure). W-8 fix canonical disposition values throughout.

## Performance

- 3 atomic commits + 4 planning artifacts (DISPOSITION-RESOLUTION, CLOSE-GATE, PR-SECTION, SUMMARY)
- `cargo test --workspace --all-features` final: **2206 passed / 0 failed / 19 ignored** (+1 new plan-43-05 conditional test vs Plan 43-01b baseline 2197)
- `cargo clippy --workspace --all-targets`: clean post-Rule-3-deviation (27.63s)
- `cargo fmt --all -- --check`: clean
- Total plan duration ≈ 404 minutes (Task 1 diff-inspection + Task 2 replay + cargo test cycles + lint fix + close-gate + SUMMARY)

## Accomplishments

1. **D-43-C1 verdict task executed cleanly** — Q1-Q8 surface-overlap analysis answered; trial cherry-pick produced 7 conflicts (clause a FAIL) and surfaced a real schema-shape divergence (fork has no `pub struct GroupsConfig`; clause b FAIL). Verdict `resolved_disposition: fork-preserve` recorded in `43-05-DISPOSITION-RESOLUTION.md` + PLAN.md frontmatter; disposition resolution committed as docs-only `22df643d` BEFORE any code change.

2. **platform.rs replayed verbatim (659 lines)** — full upstream module (`PlatformInfo` / `Os` / `LinuxInfo` / `MacosInfo` / `WindowsInfo` data types, `When` predicate type + Deserialize impl, `Predicate` + `VersionConstraint` parsers, `current()` cached-on-OnceLock host detection, `when_matches_current()` evaluation entry point). Security-relevant closed predicate grammar preserved exactly. Zero fork-only Windows-file touches.

3. **Field-level conditional deserialization wired into fork** — 4 helper deserialize functions in `profile/mod.rs`; `deserialize_with = "deserialize_conditional_path_vec"` attribute added to all 9 `FilesystemConfig` path fields; `deserialize_conditional_origin_vec` added to `OpenUrlConfig::allow_origins`; `SecretsConfig` derive-Deserialize replaced with manual impl accepting bare-string OR conditional object form. New integration test `plan_43_05_when_filters_filesystem_credentials_and_open_urls` covers the full conditional surface.

4. **JSON schema parity for the WhenPredicate surface** — `WhenPredicate` / `ConditionalPath` / `ConditionalName` / `ConditionalOrigin` `$defs` added (matching upstream structure verbatim); `FilesystemConfig` field array items + `SecretsConfig` `additionalProperties` + `OpenUrlConfig.allow_origins` array items updated to reference the new `$defs`.

5. **W-4 fix mitigation satisfied** — `wiring.rs` SKIPped per minimal-replay-scope discipline (no callers in fork; replay would be dead code). Field-level `when:` (the load-bearing surface) IS consumed by the replayed helpers; directive-level `when:` (the SKIPped surface) is rejected fail-secure by fork's existing `#[serde(deny_unknown_fields)]` on `WiringDirective` enum variants. No silent JSON-schema-vs-Rust-deserialization divergence.

6. **Phase 36-01b/c invariants preserved** — `From<ProfileDeserialize> for Profile` exhaustive enumeration at lines 1893+ is UNTOUCHED (no new top-level Profile field needed); `bypass_protection` canonical name (Phase 36-01c) preserved by merging the new `deserialize_with` attribute into the same serde block as the existing `alias = "override_deny"`.

7. **Rust 1.95 lint Rule-3 deviation handled atomically** — `clippy::unnecessary_map_or` surfaced at `platform.rs:232`; mechanical `when.map_or(true, ...)` → `when.is_none_or(...)` rewrite landed as separate `fix(43-05-cra):` commit `d4285ead` (mirrors Plan 43-01b DEC-4 commit `2603c7a6` precedent for `clippy::manual_is_multiple_of`).

8. **D-43-E1 invariant satisfied** — `git diff --name-only HEAD~3 HEAD | grep -cE '_windows\.rs|exec_strategy_windows|crates/nono-shell-broker/'` → 0 across all 3 plan commits.

9. **W-8 fix canonical disposition values applied** — PLAN.md frontmatter `disposition: fork-preserve` (conservative default unchanged); PLAN.md + DISPOSITION-RESOLUTION + SUMMARY frontmatter `resolved_disposition: fork-preserve` (verdict); no non-canonical strings anywhere.

## Task Commits

| Task | Commit     | Subject                                                                                | Files                                                                                                                                                                                                       |
|------|------------|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1    | `22df643d` | docs(43-05): record D-43-C1 diff-inspection verdict for cluster 5                       | 43-05-DISPOSITION-RESOLUTION.md (new) + 43-05-PLATFORM-DETECTION-FOUNDATION-PLAN.md (resolved_disposition: null → fork-preserve)                                                                            |
| 2    | `fe04e887` | feat(43-05): replay platform.rs + when-predicate deserialization (cluster 5)            | crates/nono-cli/src/platform.rs (new, 659 lines) + crates/nono-cli/src/profile/mod.rs (+217 lines) + crates/nono-cli/src/main.rs (`mod platform;`) + crates/nono-cli/data/nono-profile.schema.json (+99 lines) |
| 2.cra| `d4285ead` | fix(43-05-cra): adopt is_none_or() for rust-1.95 clippy lint compliance                 | crates/nono-cli/src/platform.rs (1 line — `when.map_or(true, ...)` → `when.is_none_or(...)`) — Rule-3 deviation surfaced in Gate 2                                                                          |
| 3    | (no commit — produces text artifact 43-05-CLOSE-GATE.md only)                          | n/a — close gate is text artifact (PR open deferred to orchestrator per worktree mode)                                                                                                                      | (artifact written; SUMMARY commit picks it up)                                                                                                                                                              |
| 4    | (this commit — `docs(43-05): summarize ...`)                                            | SUMMARY.md + CLOSE-GATE.md + PR-SECTION.md                                                                                                                                                                  | 3 planning artifacts                                                                                                                                                                                        |

## Files Created/Modified

**Created (code):**
- `crates/nono-cli/src/platform.rs` — 659 lines, NEW. Verbatim from upstream `ce06bd59` with one Rule-3 lint fix at line 232 (`when.is_none_or` instead of `when.map_or(true, ...)`).

**Modified (code):**
- `crates/nono-cli/src/profile/mod.rs` — +217 lines (4 helper deserialize fns + 9 FilesystemConfig field attributes + manual SecretsConfig Deserialize impl + OpenUrlConfig allow_origins attribute + 1 integration test)
- `crates/nono-cli/src/main.rs` — 1 line addition (`mod platform;` between `package_status` and `policy`)
- `crates/nono-cli/data/nono-profile.schema.json` — +99 lines (4 `$defs` additions + reference updates across FilesystemConfig / SecretsConfig / OpenUrlConfig)

**Created (planning):**
- `.planning/phases/43-upst5-sync-execution/43-05-DISPOSITION-RESOLUTION.md` — Task 1 D-43-C1 verdict evidence
- `.planning/phases/43-upst5-sync-execution/43-05-CLOSE-GATE.md` — 8-check gate evidence + branch-specific D-20 smokes + W-4 mitigation + preservation invariants
- `.planning/phases/43-upst5-sync-execution/43-05-PR-SECTION.md` — Phase 43 umbrella PR contribution section
- `.planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md` — this SUMMARY

**Modified (planning):**
- `.planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-PLAN.md` — frontmatter `resolved_disposition: null` → `fork-preserve` (W-8 canonical value)

## Decisions Made

### DEC-1: D-43-C1 diff-inspection verdict = `resolved_disposition: fork-preserve`

Trial cherry-pick on a scratch branch (`43-05-trial-cherry-pick`) produced **7 conflicts** (6 content + 1 modify/delete): `nono-profile.schema.json`, `profile-authoring-guide.md`, `package_cmd.rs`, `policy.rs`, `profile/mod.rs`, `wiring.rs` (content), plus `docs/cli/features/package-publishing.mdx` (modify/delete because fork deleted the entire `docs/cli/` MDX subtree).

Surface-semantics divergence (clause b): upstream has `pub struct GroupsConfig { include, exclude }` at the Profile level referenced from `Profile.groups: GroupsConfig`. Fork has NO `GroupsConfig` struct — fork uses flat `groups: Vec<String>` + `exclude_groups: Vec<String>` directly inside policy/security configs. This is a real schema-shape divergence: upstream's `GroupsConfig::include/exclude` hunks have no target struct in fork.

Both D-40-B1 clauses (a) zero conflicts AND (b) identical surface semantics FAILED. `resolved_disposition` stays at the conservative `fork-preserve` default per D-42-C3. Phase 40 D-40-B1 upgrade authority not exercised.

Verdict committed as a docs-only commit `22df643d` BEFORE any code change (Phase 40 Plan 40-05 pattern). The 43-05-DISPOSITION-RESOLUTION.md artifact records Q1-Q8 numeric evidence + trial cherry-pick output + cleanup audit trail.

### DEC-2: Minimal replay scope (Cluster 5 specifics)

Per Phase 40 Plan 40-05 DEC-2 ("Minimal replay scope") — adapted to Cluster 5:

**Replayed:**
- `platform.rs` (NEW, 659 lines verbatim — security-relevant closed grammar; no fork-only collision points; the full file is the natural replay unit)
- 4 helper deserialize functions in `profile/mod.rs` (closed grammar consumers + the bridge to `crate::platform::When`)
- `deserialize_with` attribute on all 9 `FilesystemConfig` path fields + `OpenUrlConfig::allow_origins`
- Manual `SecretsConfig` Deserialize impl accepting bare-string OR conditional object form
- JSON schema `WhenPredicate` / `ConditionalPath` / `ConditionalName` / `ConditionalOrigin` `$defs` + reference updates
- One integration test `plan_43_05_when_filters_filesystem_credentials_and_open_urls`
- `mod platform;` declaration in `main.rs`

**NOT replayed:**
- `crates/nono-cli/src/wiring.rs` (+126 lines): no callers in fork — would be dead code. W-4 fix mitigation: directive-level `when:` rejected fail-secure by existing `deny_unknown_fields` on WiringDirective variants.
- `crates/nono-cli/src/policy.rs` (+28 lines): fork's `Group::platform: Option<String>` (policy.rs:43-46) already provides the group-level platform-conditional concept; upstream's hunks would conflict or duplicate.
- `crates/nono-cli/src/package_cmd.rs`: downstream of Cluster 1 surface (already absorbed in Plan 43-03); not load-bearing for `when:` evaluation.
- `crates/nono-cli/data/profile-authoring-guide.md` + `docs/cli/features/package-publishing.mdx`: fork's `docs/cli/` MDX subtree deleted; not tracked.
- `GroupsConfig::include/exclude` deserializer wiring at the struct level: fork has no `pub struct GroupsConfig`. The `deserialize_conditional_name_vec` helper is included in the replay for API parity (currently `#[allow(dead_code)]`) so a future fork evolution toward a GroupsConfig struct can wire it in without re-replaying.

Rationale documented in commit `fe04e887` body's `What was NOT replayed and why:` section.

### DEC-3: W-4 fix mitigation strategy (wiring.rs SKIPped)

The W-4 fix from the PLAN.md threat model T-43-05-10 mandates: if Branch B (manual replay) is chosen AND wiring.rs is SKIPped, JSON schema's `when:` predicate must not be silently no-op'd at evaluation — fail-secure rejection required.

Two scopes of `when:` exist in the JSON schema:
1. **Field-level** (inside `filesystem.allow[]` / `filesystem.read[]` / …/ `open_urls.allow_origins[]` / `env_credentials.*`): the load-bearing surface for the upstream feat-intent. Consumed by the replayed `deserialize_conditional_*_vec` helpers + manual SecretsConfig Deserialize. **Parity** between schema and Rust.
2. **Directive-level** (top-level `when:` on a WiringDirective): the SKIPped surface. Fork's `WiringDirective` enum has `#[serde(deny_unknown_fields)]` on its variants → unknown `when:` key rejected at parse time. **Fail-secure** — silent divergence impossible.

Mitigation evidence captured in `43-05-CLOSE-GATE.md` § W-4 fix mitigation evidence with grep proofs.

### DEC-4: Rust 1.95 lint Rule-3 deviation as separate fix(43-05-cra) commit

Per phase_context (and Plan 43-01b DEC-4 precedent for `clippy::manual_is_multiple_of`): when a verbatim upstream replay surfaces a new clippy lint introduced by the workspace MSRV (1.95), the auto-fix lands as a separate `fix(<plan>-cra):` commit, not folded into the replay commit and not silenced with `#[allow]`.

In this plan, Gate 2 (Windows clippy with `-D warnings -D clippy::unwrap_used`) surfaced one error: `clippy::unnecessary_map_or` at `platform.rs:232` on the form `when.map_or(true, |p| p.matches(current()))`. The auto-suggested replacement `when.is_none_or(|p| p.matches(current()))` has equivalent semantics — both return true when `when` is `None` and call the closure otherwise.

The fix landed as commit `d4285ead` with subject `fix(43-05-cra): adopt is_none_or() for rust-1.95 clippy lint compliance`. The body explicitly references Plan 43-01b's precedent commit `2603c7a6` for traceability.

Considered alternatives rejected:
- `#[allow(clippy::unnecessary_map_or)]` — violates cross-target-verify-checklist § Anti-pattern 2 ("Adding `#[allow(...)]` to silence cross-target lints").
- Squash into commit `fe04e887` — would obscure the upstream-replay-vs-MSRV-lint-fix boundary in `git log`.

### DEC-5: W-8 fix canonical disposition values used throughout

Per W-8 fix in PLAN.md (`disposition_resolution_at_plan_open: true`, `final_disposition_field_name: resolved_disposition`):
- PLAN.md frontmatter `disposition: fork-preserve` is the conservative default per D-42-C3 — unchanged throughout.
- PLAN.md frontmatter `resolved_disposition:` is the Task 1 verdict field — written from initial `null` to `fork-preserve` via `Edit` tool during Task 1.
- DISPOSITION-RESOLUTION.md frontmatter `resolved_disposition: fork-preserve` matches.
- This SUMMARY frontmatter `disposition: fork-preserve` + `resolved_disposition: fork-preserve` matches.
- CLOSE-GATE.md text references the canonical value.
- PR-SECTION.md disposition line uses the canonical value.

No non-canonical strings (`TBD-at-plan-open`, `will-sync-via-diff-inspection-upgrade`) appear in any frontmatter or artifact. Downstream tooling can read `resolved_disposition` for the live verdict.

### DEC-6: Phase 36-01b discipline preserved automatically

A key observation from the Q2 / Q6 portion of Task 1's diff-inspection: upstream `ce06bd59` does NOT touch fork's `From<ProfileDeserialize> for Profile` exhaustive enumeration at `profile/mod.rs:1893-1921`. Cluster 5 adds NO new top-level Profile field — conditional logic is wired INSIDE field-level deserializers (`deserialize_conditional_path_vec` family) + a new manual `SecretsConfig` Deserialize impl that lives one level down (on the `env_credentials: SecretsConfig` field's deserializer, not on the Profile struct itself).

This means Phase 36-01b's structural rustc-completeness-check guard is preserved by construction. No new arm is added to the From-impl; no risk of silent field-drop regression.

Verification: `grep -c 'commands: raw\.commands' crates/nono-cli/src/profile/mod.rs` → 1 (Phase 36-01b canonical arm intact). The discipline is captured as a pattern in `patterns_established` for future Cluster 5-shaped plans.

## Deviations from Plan

### Rule 3 — Auto-fix blocking issue (MSRV-bump-surfaced lint)

**Found during:** Task 3 Gate 2 (Windows clippy run).
**Issue:** rust 1.95 stabilized `clippy::unnecessary_map_or`. Verbatim cherry-pick of upstream `platform.rs` carried a `when.map_or(true, |p| p.matches(current()))` form at line 232 that the new lint rejects under `-D warnings`.
**Fix:** mechanical `when.map_or(true, ...)` → `when.is_none_or(...)` rewrite in commit `d4285ead`. Equivalent semantics; no behavior change.
**Files modified:** `crates/nono-cli/src/platform.rs` (1 line).
**Commit:** `d4285ead`.
**Justification:** mirrors Plan 43-01b DEC-4 / commit `2603c7a6` precedent for the same MSRV-bump-surfaced-lint class. Preserves "zero green→red CI lane transitions vs baseline `13cc0628`" (D-43-E3).

### No other deviations

Tasks 1, 2, 3, 4 ran as planned. Branch B (D-20 manual replay) was correctly selected by Task 1's D-43-C1 verdict (D-40-B1 upgrade authority not exercised). Minimal replay scope per DEC-2 selected SKIP for `wiring.rs` / `policy.rs` / `package_cmd.rs` / MDX docs per the rationale in commit `fe04e887` body.

## Issues Encountered

### Issue 1 — Trial cherry-pick `--abort` cleanup quirk

After the trial cherry-pick on scratch branch `43-05-trial-cherry-pick` produced 7 conflicts (the expected D-40-B1 clause-a-fail signal), `git cherry-pick --abort` returned `error: no cherry-pick or revert in progress` even though `git status` showed unmerged paths.

This is the expected behavior on Windows git when `cherry-pick --no-commit` fails *before* it can stage the merge state: there is no `.git/CHERRY_PICK_HEAD` for `--abort` to clean up, but the index is still in an unmerged state. The recovery path was:
1. `git reset --hard HEAD` (resets index + working tree to the scratch branch HEAD = `6354167a`).
2. `git switch worktree-agent-a8440f5aa665ed53b`.
3. `git branch -D 43-05-trial-cherry-pick`.

Final `[ ! -f .git/CHERRY_PICK_HEAD ]` confirmed state sealed; final `git status --short` empty. No cherry-pick-state leak. Documented for future Branch-A-but-not-quite plans.

### Issue 2 — Phase 41 D-14 / CR-04 broker-binary precondition (recurrence)

Cargo test infrastructure (specifically `broker_launch_assigns_child_to_job_object`) expects `target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe` to exist before test launch. First `cargo build -p nono-shell-broker --release` produced the binary at `target/release/nono-shell-broker.exe` only; the target-triple-suffixed path was absent.

Resolution: copied the binary to the expected target-triple path:
```
mkdir -p target/x86_64-pc-windows-msvc/release
cp target/release/nono-shell-broker.exe target/x86_64-pc-windows-msvc/release/
```

This is the same recurrence as Plan 43-01b Issue 1. Recommendation for future Phase 43 worktree-agent runs: orchestrator should ensure `cargo build -p nono-shell-broker --target x86_64-pc-windows-msvc --release` (with explicit target triple) is part of the pre-test environment setup.

## D-43-E9 8-check close gate

See `.planning/phases/43-upst5-sync-execution/43-05-CLOSE-GATE.md` for full evidence. Summary:

| Gate | Description                                           | Disposition                                                    |
|------|-------------------------------------------------------|----------------------------------------------------------------|
| 1    | `cargo test --workspace --all-features` (Windows)     | PASS (2206 passed, 0 failed, 19 ignored)                       |
| 2    | `cargo clippy --workspace --all-targets` (Windows)    | PASS post Rule-3 deviation commit `d4285ead`                   |
| 3    | `cargo clippy --target x86_64-unknown-linux-gnu`      | load-bearing-skip → CI-verified (cross-toolchain absent)       |
| 4    | `cargo clippy --target x86_64-apple-darwin`           | load-bearing-skip → CI-verified (cross-toolchain absent)       |
| 5    | `cargo fmt --all -- --check`                          | PASS                                                           |
| 6    | Phase 15 5-row detached-console smoke                 | environmental-skip (D-40-C2)                                   |
| 7    | `wfp_port_integration` tests                          | environmental-skip (cargo-level 0/0/2 in Gate 1)               |
| 8    | `learn_windows_integration` tests                     | environmental-skip (cargo-level 60/14 in Gate 1)               |

## Wave 2a CI Verification

Per `.planning/templates/upstream-sync-quick.md:108-113`, the baseline-aware CI gate compares post-merge CI lanes on the head SHA against baseline `13cc0628` (Phase 41 close). In worktree mode, the actual branch-push + CI lane assessment is deferred to the orchestrator.

Pre-merge expectation (set by Windows-host evidence):
- Linux + macOS clippy lanes: green→green (PASS) — Rule-3 fix `d4285ead` forecloses the rust-1.95 lint regression vector; platform.rs's cfg-gated Linux + macOS branches use only stdlib types + `std::process::Command::new("sw_vers")` which are baseline-compatible.
- All workspace test lanes: green→green (PASS) — local Windows test gate proves 2206 / 0 / 19.
- fmt-check: green→green (PASS).
- 5 Windows CI lanes (Build, Integration, Regression, Security, Packaging): green→green expected — Windows branch of `platform.rs` uses `WindowsInfo::default()` only (no registry / FFI surface; that's deferred to Plan 43-06 / Cluster 4).

Post-merge: orchestrator fills in the lane transition table in `43-05-CLOSE-GATE.md` § "Wave 2a baseline-aware CI gate".

## Threat-model close-out

| Threat ID    | Status     | Note                                                                                                              |
|--------------|------------|-------------------------------------------------------------------------------------------------------------------|
| T-43-05-01   | MITIGATED  | Phase 36-01b From-impl untouched (no new top-level Profile field); rustc structural guard remains the safety net  |
| T-43-05-02   | MITIGATED  | Q5 = 0 `override_deny` references in upstream hunks; Phase 36-01c canonical name preserved                         |
| T-43-05-03   | MITIGATED  | Q7 = 0 path-string `starts_with`; only char-literal compares in platform.rs (verified in DISPOSITION-RESOLUTION.md)|
| T-43-05-04   | MITIGATED  | D-43-E1 grep returned 0 across all 3 plan commits (commits 22df643d + fe04e887 + d4285ead)                         |
| T-43-05-05   | MITIGATED  | Q8 = 0 broker dispatch collisions in upstream hunks                                                                |
| T-43-05-06   | MITIGATED  | Closed-grammar `Predicate::parse` rejects unknown syntax; existing `#[serde(deny_unknown_fields)]` on FilesystemConfig / OpenUrlConfig / WiringDirective intact |
| T-43-05-07   | MITIGATED  | 5-section D-20 body grep counts all = 1; `Upstream-commit:` count = 0; `Upstream-replayed-from: ce06bd59` present  |
| T-43-05-08   | MITIGATED  | platform.rs `pub` surface is the upstream-curated minimum; no fork-only privilege escalation introduced            |
| T-43-05-09   | ACCEPTED   | One-time OnceLock-cached detection; no per-deserialization cost                                                    |
| T-43-05-10   | MITIGATED  | W-4 fix evidence in CLOSE-GATE.md — field-level `when:` wired; directive-level rejected by deny_unknown_fields     |
| T-43-05-11   | MITIGATED  | W-8 fix canonical `fork-preserve` value used everywhere; no non-canonical strings                                  |

ASVS L1 disposition: all `high` threats MITIGATED; all `medium` threats MITIGATED; one `low` threat (T-43-05-09 perf) ACCEPTED. Security gate satisfied.

## Self-Check

| Check                                                                                                                              | Result |
|------------------------------------------------------------------------------------------------------------------------------------|--------|
| `[ -f .planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md ]`                                   | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-05-DISPOSITION-RESOLUTION.md ]`                                                  | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-05-CLOSE-GATE.md ]`                                                              | FOUND  |
| `[ -f .planning/phases/43-upst5-sync-execution/43-05-PR-SECTION.md ]`                                                              | FOUND  |
| `[ -f crates/nono-cli/src/platform.rs ]`                                                                                           | FOUND  |
| `git log --oneline -1 22df643d` matches `docs(43-05): record D-43-C1 ...`                                                          | FOUND  |
| `git log --oneline -1 fe04e887` matches `feat(43-05): replay platform.rs ...`                                                      | FOUND  |
| `git log --oneline -1 d4285ead` matches `fix(43-05-cra): adopt is_none_or() ...`                                                   | FOUND  |
| `grep -c '^mod platform;' crates/nono-cli/src/main.rs` → 1                                                                         | PASS   |
| `wc -l crates/nono-cli/src/platform.rs` → 659                                                                                      | PASS   |
| `git log -1 --format='%B' fe04e887 \| grep -c '^Upstream-commit: '` → 0                                                            | PASS   |
| `git log -1 --format='%B' fe04e887 \| grep -c '^Upstream intent:'` → 1                                                             | PASS   |
| `git log -1 --format='%B' fe04e887 \| grep -c '^What was replayed:'` → 1                                                           | PASS   |
| `git log -1 --format='%B' fe04e887 \| grep -c '^What was NOT replayed'` → 1                                                        | PASS   |
| `git log -1 --format='%B' fe04e887 \| grep -c '^Fork-only wiring preserved:'` → 1                                                  | PASS   |
| `git log -1 --format='%B' fe04e887 \| grep -c '^Upstream-replayed-from: '` → 1                                                     | PASS   |
| `git diff --name-only HEAD~3 HEAD \| grep -cE '_windows\.rs\|exec_strategy_windows\|crates/nono-shell-broker/'` → 0                | PASS   |
| `grep -c 'commands: raw\.commands' crates/nono-cli/src/profile/mod.rs` → 1 (Phase 36-01b preserved)                                | PASS   |
| `cargo check --workspace` (post-final commit) exits 0                                                                              | PASS   |
| `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) exits 0                              | PASS   |
| `cargo fmt --all -- --check` exits 0                                                                                               | PASS   |
| `cargo test --workspace --all-features`: 2206 passed / 0 failed                                                                    | PASS   |
| `[ ! -f .git/CHERRY_PICK_HEAD ]`                                                                                                   | PASS   |
| PLAN.md frontmatter `resolved_disposition: fork-preserve` (canonical value per W-8 fix)                                            | PASS   |

Status: **PASSED.**

## User Setup Required

None for this plan. Orchestrator (post-merge) responsibilities:
1. Push the worktree branch to remote.
2. Append `43-05-PR-SECTION.md` content to the Phase 43 umbrella PR body.
3. After CI completes on the head SHA, fill in the CI lane transition table in `43-05-CLOSE-GATE.md` § "Wave 2a baseline-aware CI gate".

## Next Phase Readiness

Plan 43-06 (PLATFORM-DETECTION-WINDOWS, Wave 2b sequential) is now **UNBLOCKED**. Plan 43-06 inherits:
- `crates/nono-cli/src/platform.rs` module as the host-detection + Windows-registry-parsing foundation (Cluster 4's 2 upstream commits `0748cced` Windows registry queries + `5d821c12` REG_DWORD parse fix build on `WindowsInfo` and `detect_windows` skeleton replayed here)
- Phase 36-01b/c invariants preserved (no exhaustive-match churn)
- W-4 fix mitigation pattern documented in `patterns_established`
- Rust 1.95 clippy lint Rule-3 deviation precedent for `clippy::unnecessary_map_or` available if Plan 43-06's cherry-pick hits the same lint

Plan 43-06 sequences after Plan 43-05 close per D-43-A3.

The Phase 43 umbrella PR is NOT yet opened (worktree mode); orchestrator will assemble + open it post-merge per the umbrella-section append protocol.
