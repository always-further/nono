# Phase 48: UPST6 sync execution - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-24
**Phase:** 48-upst6-sync-execution
**Areas discussed:** Wave structure & plan slicing, Cluster C4 internal sequencing, Cluster C9 fork-preserve disposition pathway, Release-ride + schema-test specifics

---

## Cross-reference Todos (pre-discussion gate)

| Option | Description | Selected |
|--------|-------------|----------|
| Neither — review only | Both todos are explicitly out-of-scope: 44-class-d is a Phase 44 follow-up tagged for Phase 46+47 batch (already past); 44-validate-restore-target is post-v2.6 substantial work. Records both as reviewed-but-not-folded in deferred ideas. | ✓ |
| Fold 44-class-d-validator | Linux Landlock policy.rs investigation. Tangentially related to Cluster C5 (Linux Landlock deny-overlap quieting) but Phase 48 is cherry-pick discipline, not new investigation work. | |
| Fold 44-validate-restore-target | 2-3 week cross-platform fd-relative TOCTOU refactor. Not a cherry-pick — would derail Phase 48 scope. Already targeted post-v2.6. | |

**User's choice:** Neither — review only.
**Notes:** Both todos preserved in `<deferred>` § Reviewed Todos (not folded).

---

## Wave structure & plan slicing

### Q1: Plan granularity

| Option | Description | Selected |
|--------|-------------|----------|
| One plan per cluster (9 plans) | Mirrors Phase 40 D-40-A1 + Phase 43 D-43-A2 'one plan per cluster' precedent. Max per-cluster traceability; rollback granularity = one cluster. | ✓ |
| Consolidate small polish clusters (6 plans) | Merge C5+C6+C7 into one POLISH plan since each is small and surface-disjoint within itself. | |
| Aggressive consolidation (4-5 plans by wave) | One plan per WAVE not per cluster. Fewest atomic units; mixes multiple cluster dispositions per plan. | |

**User's choice:** One plan per cluster (9 plans). Captured as D-48-A1.

### Q2: Wave structure

| Option | Description | Selected |
|--------|-------------|----------|
| 4 waves: foundation → sequenced → parallel polish → release | Wave 0: C4 solo. Wave 1: C1 → C2 (sequenced after C4). Wave 2 parallel: C5 || C6 || C7 || C8 || C9. Wave 3: C3 release-ride solo. Mirrors Phase 43 D-43-A1/A2/A3/A4. | ✓ |
| 5 waves with sub-divided polish wave | Wave 2 splits into Wave 2a (Linux/macOS Unix-side polish) then Wave 2b (cross-platform proxy + fork-preserve). | |
| 3 waves: foundation + parallel-all-non-conflicting + release | Wave 0: C4 solo. Wave 1: C1 → C2 sequential AND C5+C6+C7+C8+C9 all parallel. Wave 2: C3 release. | |

**User's choice:** 4 waves: foundation → sequenced → parallel polish → release. Captured as D-48-A2.

### Q3: Wave 1 internal ordering

| Option | Description | Selected |
|--------|-------------|----------|
| Parallel (C1 || C2 after C4 closes) | C1 + C2 are surface-disjoint from each other (C1 = profile/*, C2 = cli.rs + runtime/strategy files). Both wait for C4 plan close. Halves Wave 1 elapsed time. | ✓ |
| Sequential (C1 then C2) | More conservative — reduces concurrent CI lane activity. Slower wall-clock; cleaner per-plan rollback chain. | |
| Sequential (C2 then C1) | C2 dead-infra removal might surface cleanup work that affects how C1's profile shadowing should land. | |

**User's choice:** Parallel (C1 || C2 after C4 closes). Captured as D-48-A3.

### Q4: PR umbrella opening cadence

| Option | Description | Selected |
|--------|-------------|----------|
| After Wave 0 (C4) close | Substantive content from day one; per-plan sections from Waves 1–3 append. Mirrors Phase 43 cadence. | ✓ |
| At Phase 48 open | Earliest possible upstream signaling. PR opens as draft with placeholder body. | |
| At Phase 48 close | Single ship-event. Matches Phase 40 PR #922 pattern. | |

**User's choice:** After Wave 0 (C4) close. Captured as D-48-A4.

---

## Cluster C4 internal sequencing

### Q1: C4 plan structure

| Option | Description | Selected |
|--------|-------------|----------|
| Single plan, all 9 sequential cherry-picks | One Plan 48-01 with 9 commits cherry-picked in upstream-chronological order. Preserves cluster atomicity; close-gate runs once. Mirrors Phase 43 Plan 43-01 single-plan-86-files pattern. | ✓ |
| Split into 2 plans by feature (Landlock-v6-scoping vs af-unix-mediation) | Plan 48-01a Landlock work + Plan 48-01b af_unix mediation. Two close-gates; breaks Phase 47 cluster atomicity. | |
| Split a0222be2 to its own plan (size-based) | Plan 48-01a (8 commits) + Plan 48-01b (a0222be2 solo). Size-based split heuristic. | |

**User's choice:** Single plan, all 9 sequential cherry-picks. Captured as D-48-B1.

### Q2: Conflict resolution stance

| Option | Description | Selected |
|--------|-------------|----------|
| Pre-flight diff-inspection task at Plan 48-01 open | Plan opens with structured 'compare upstream c2c6f2ca + a0222be2 + 863bbfd3 against fork-side supervisor.rs / lib.rs / sandbox/linux.rs surfaces' task BEFORE first cherry-pick. Extends Phase 43 D-43-C1 to will-sync-with-high-conflict-potential. | ✓ |
| Straight per-commit cherry-pick with hand-resolution as conflicts surface | Mirror Phase 43 Plan 43-01 86-file Cluster 2 approach. Risk = mid-cherry-pick abort if conflict scope is larger than expected. | |
| Accept upstream verbatim + re-add fork-side hunks in a separate commit | Cleaner audit trail; breaks 'one cherry-pick = one commit' atomicity. | |

**User's choice:** Pre-flight diff-inspection task at Plan 48-01 open. Captured as D-48-B2.

### Q3: Pre-flight artifact format

| Option | Description | Selected |
|--------|-------------|----------|
| Separate artifact `48-01-PRE-CHERRY-PICK-AUDIT.md` | Mirrors Phase 43 Plan 43-02/43-03 precedent. Captures per-commit conflict-prediction table + per-file diff inspection + chosen resolution strategy per commit. | ✓ |
| Inline in `48-01-PLAN.md` as Pre-flight section | Single file; reduces artifact count. Less navigable for 9-commit / 29-file scope. | |
| First commit on the branch (`docs(48-01): pre-flight diff-inspection results`) | Git-native audit trail; forces commit amendments if inspection iterates. | |

**User's choice:** Separate artifact `48-01-PRE-CHERRY-PICK-AUDIT.md`. Captured as D-48-B2.

### Q4: Escalation if irreconcilable conflict

| Option | Description | Selected |
|--------|-------------|----------|
| Split Plan 48-01 into 48-01a + 48-01b | Mirrors Phase 43 Plan 43-01 → 43-01b precedent. 48-01a lands cleanly-resolvable; 48-01b takes deferred with D-20 manual-replay. Preserves cluster atomicity at cluster level. | ✓ |
| Hand-fix on the cherry-pick branch + continue | Single plan; risk = D-19 trailer fidelity weakens (fork-side hunks ride inside upstream cherry-pick commit). | |
| D-20 manual-replay the problematic commit | Manually replay the equivalent fork-side change. Carries `Upstream-replayed-from:` trailer per Phase 43 convention. | |

**User's choice:** Split Plan 48-01 into 48-01a + 48-01b. Captured as D-48-B3.

---

## Cluster C9 fork-preserve disposition pathway

### Q1: Disposition pathway choice

| Option | Description | Selected |
|--------|-------------|----------|
| Diff-inspection-first with upgrade authority | Mirror Phase 43 D-43-C1 pattern. Plan 48-08 opens with structured diff-inspection task against fork's Phase 35/45 trust-bundle work. If no D-32-15 collision → UPGRADE to will-sync; else stay D-20 manual-replay. | ✓ |
| Commit upfront to D-20 manual-replay | Accept Phase 47's conservative default verbatim. Carries `Upstream-replayed-from:` trailers. | |
| Commit upfront to will-sync (skip conservative default) | Treat Phase 47's fork-preserve as overly cautious. Violates Phase 47 ledger rationale. | |

**User's choice:** Diff-inspection-first with upgrade authority. Captured as D-48-C1.

### Q2: Disposition resolution artifact

| Option | Description | Selected |
|--------|-------------|----------|
| `48-08-DISPOSITION-RESOLUTION.md` separate artifact | Mirrors Phase 43 D-43-C1 artifact convention (`43-05-DISPOSITION-RESOLUTION.md` + `43-06-DISPOSITION-RESOLUTION.md`). Captures diff-inspection methodology + per-file findings + D-32-15 check + upgrade-or-not decision. | ✓ |
| Inline in `48-08-PLAN.md` Decision section | Single file; reduces artifact count. Cleaner for small (2 commit) scope. | |
| Fold into shared `48-FORK-PRESERVE-RESOLUTION.md` | Single doc for all fork-preserve plans. Over-engineered for 1-cluster-this-cycle reality. | |

**User's choice:** `48-08-DISPOSITION-RESOLUTION.md` separate artifact. Captured as D-48-C2.

### Q3: D-32-15 offline-verify regression test

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, mandatory regression test | Plan 48-08 close-gate adds fork-side integration test (`tests/integration/offline_verify_extended_trust_bundle.rs` or similar) proving D-32-15 offline-verify holds with new `installed_path` + `sha256_digest` fields. Belt-and-suspenders for security-critical surface. | ✓ |
| Only if diff-inspection surfaces concrete risk | Adaptive; risk = subtle invariant break could slip past existing tests if they don't exercise new schema fields. | |
| No, standard close-gate is sufficient | Trust existing offline-verify + sigstore-verify tests cover the surface. Risk = D-32-15 invariant has no direct schema-extension regression test. | |

**User's choice:** Yes, mandatory regression test. Captured as D-48-C3.

### Q4: C9 resolution recording

| Option | Description | Selected |
|--------|-------------|----------|
| `48-08-DISPOSITION-RESOLUTION.md` + 48-SUMMARY.md hand-off | Resolution lives in Plan 48-08 artifacts. 48-SUMMARY.md `## Hand-off to UPST7` states C9 final disposition + rationale. Phase 47 ledger stays as-shipped. Matches Phase 47's own pattern (Cluster 2 follow-on annotation in Phase 47, not retroactive Phase 42 amendment). | ✓ |
| Amend Phase 47 DIVERGENCE-LEDGER.md C9 row in-place | One-line annotation on Phase 47 ledger's C9 row. Breaks `audit-shipped` immutability convention. | |
| Both — plan artifacts + ledger annotation | Belt-and-suspenders. Redundant. | |

**User's choice:** `48-08-DISPOSITION-RESOLUTION.md` + 48-SUMMARY.md hand-off. Captured as D-48-C4.

---

## Release-ride + schema-test specifics

### Q1: C3 release-ride structure

| Option | Description | Selected |
|--------|-------------|----------|
| Single consolidated CHANGELOG commit with 3 stacked D-19 trailers | One commit `chore(48-09): absorb upstream v0.55.0..v0.57.0 CHANGELOG entries`; commit body carries 3 stacked `Upstream-commit:` trailers (one per release). Matches Phase 47 ledger consolidation invitation. | ✓ |
| Three separate release-ride commits (one per upstream release) | Cleaner per-release rollback; matches Phase 40 + 43 single-release-per-commit pattern. | |
| Single consolidated commit with 1 aggregate trailer | Breaks D-19 trailer convention. Not recommended without explicit ADR amendment. | |

**User's choice:** Single consolidated CHANGELOG commit with 3 stacked D-19 trailers. Captured as D-48-D1.

### Q2: C8 schema regression test

| Option | Description | Selected |
|--------|-------------|----------|
| Verify existing schema-validator coverage first; add test only if gap | Plan 48-07 grep fork-side tests for jsonschema validation against `nono-profile.schema.json`. If coverage exercises new `credential_format` shape → no new test; else add focused test. Adaptive. | ✓ |
| Yes, mandatory regression test | Unconditionally add fork-side schema regression test across all 3 shapes. Belt-and-suspenders. | |
| No, rely on standard close-gate | Existing cargo test --workspace + proxy integration tests catch wire-protocol regressions. | |

**User's choice:** Verify existing schema-validator coverage first; add test only if gap. Captured as D-48-D2.

### Q3: C2 dead-infra removal handling

| Option | Description | Selected |
|--------|-------------|----------|
| Pre-flight grep + cleanup task before cherry-pick | Plan 48-03 grep for `startup_prompt` across fork tree. If references found → fork-side cleanup commit BEFORE cherry-picking 4e0e127a. Safe path; preserves cherry-pick atomicity. | ✓ |
| Cherry-pick 4e0e127a; let cargo build fail; hand-fix in-place | Single commit on branch; risk = D-19 trailer fidelity weakens. | |
| Split 4e0e127a: D-20 manual-replay just SIGKILL change | Preserve fork's startup_prompt.rs structure. Risk = fork diverges from upstream cleanup. | |

**User's choice:** Pre-flight grep + cleanup task before cherry-pick. Captured as D-48-D3.

### Q4: C7 musl-target verification

| Option | Description | Selected |
|--------|-------------|----------|
| `cargo check --target x86_64-unknown-linux-musl` if cross-toolchain available; PARTIAL if not | Mirrors cross-target-verify-checklist pattern: try the verification, mark PARTIAL with `_environmental` skipped-gate categorization if musl-cross unavailable, defer to live CI. | ✓ |
| Add musl-target CI lane explicitly | Codifies the gate permanently. Substantial CI setup work. | |
| No musl verification — standard close-gate sufficient | Smallest scope; accepts that musl regressions surface only via user reports. | |

**User's choice:** `cargo check --target x86_64-unknown-linux-musl` if cross-toolchain available; PARTIAL if not. Captured as D-48-D4.

---

## Claude's Discretion

- **Plan numbering finalization** — planner may refine `48-NN-{CLUSTER-THEME}` naming for clarity.
- **Per-plan close-gate composition** — planner may add/skip 8-check format gates per plan with explicit `skipped_gates_load_bearing` / `_environmental` categorization (Phase 40 anti-pattern #3).
- **PR umbrella body assembly** — planner specifies per-plan contribution section template.
- **C4 cherry-pick chronological order verification** — planner verifies at Plan 48-01 open against `git log v0.54.0..v0.57.0 -- ...` ordering.
- **C4 commit b8a32006 (docs-only) sequencing** — per upstream chronology; no special handling.
- **Plan 48-08 upgrade decision artifact suffix** — planner may add `-UPGRADED` / `-DEFERRED` to filename at plan close, or leave bare.
- **48-SUMMARY.md hand-off section structure** — planner decides whether to include additional sections beyond `## Hand-off to UPST7`.
- **Cluster C5 / C6 / C7 close-gate adjustments** — planner may streamline small-cluster polish plans.
- **Plan 48-08 re-export scan execution** — only if upgrade-to-will-sync; scan output in `48-08-DISPOSITION-RESOLUTION.md` § Re-export check subsection.
- **PR umbrella title + body initial state** — planner decides at Wave 0 close.

## Deferred Ideas

- Post-v0.57.0 commit absorption (UPST7).
- Follow-on ADR amendment if Plan 48-01 pre-flight surfaces structural pattern.
- C9 partial absorption (per-commit disposition if 5f1c9c73 + 8d774753 have different feasibility).
- Defense-in-depth wiring of newly-absorbed cross-platform features into fork-only Windows surface.
- Cross-binding lockstep updates for nono-py / nono-ts (only if C9 upgrade introduces new public Rust API).
- Reviewed-but-not-folded todos: `44-class-d-validator-preflight-investigation` + `44-validate-restore-target-fd-relative-hardening`.
