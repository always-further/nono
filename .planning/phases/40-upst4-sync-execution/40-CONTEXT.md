# Phase 40: UPST4 sync execution - Context

**Gathered:** 2026-05-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Execute the 7-cluster disposition-complete inventory from Phase 39's `DIVERGENCE-LEDGER.md` (4 will-sync + 2 fork-preserve + 1 won't-sync) against the 22 cross-platform commits in upstream `v0.52.0..v0.53.0`. Mirror Phase 34 shape: per-commit cherry-pick of will-sync clusters with verbatim D-19 trailer; D-20 manual replay for fork-preserve clusters (with diff-inspection upgrade authority for Cluster 4 only); inline 40-SUMMARY section for the single won't-sync cluster.

**In scope:**
- Per-commit cherry-pick of 4 `will-sync` clusters with `Upstream-commit:` D-19 trailer block on every fork commit (Cluster 1 proxy server hardening 5 commits; Cluster 2 CLI --allow + sandbox state 2 commits; Cluster 6 nono::scrub module 2 commits; Cluster 7 Sandbox/Landlock + release ride-alongs 5 commits).
- Manual replay of 2 `fork-preserve` clusters per D-20 (Cluster 4 profile-save denial suppression 2 commits; Cluster 5 proxy TLS trust + multi-route + credential matching 3 commits) — replay the *intent* without deleting fork-only Windows wiring.
- Cluster 4 diff-inspection authority (D-40-B1): Plan 40-05 begins with an upstream-vs-fork diff inspection step. If zero fork-only-line conflicts AND identical surface semantics → upgrade disposition to `will-sync` (D-19 trailer cherry-pick). Otherwise stay D-20 manual replay. Decision documented in PLAN.md.
- Inline `## Won't-sync clusters from Phase 39 ledger` section in 40-SUMMARY.md documenting Cluster 3 (PTY scrollback) won't-sync disposition with pointer-only rationale (cite Phase 39 ledger row + Phase 33 Cluster 1 same-class precedent).
- D-19 cherry-pick trailer block on every cherry-picked commit (verbatim 6-line shape from `.planning/templates/upstream-sync-quick.md`).
- D-34-D2 per-plan close gate verbatim (8 checks: cargo test + 4-platform clippy + fmt + Phase 15 smoke + wfp_port_integration + learn_windows_integration).

**Out of scope (route elsewhere or explicitly defer):**
- Defense-in-depth wiring of newly-absorbed cross-platform features into fork-only Windows surface — D-34-B2 surgical-retrofit posture inherits unchanged; no opportunistic Windows composition during cherry-pick.
- Closure or replay of fork-only Windows seams (`crates/nono-shell-broker/`, `WindowsTokenArm::BrokerLaunch`, Phase 28 chain-walker, Phase 32 TUF cached-root + broker self-trust-anchor, NONO_TEST_HOME seam) — these stay byte-identical (D-17 from Phase 22; cross-phase invariant).
- Upstream v0.54.0+ ingestion — Phase 39 audit caps at v0.53.0; UPST5 stub in ROADMAP § v2.5 backlog absorbs v0.54.0 (including the 2 windows-touch commits `5d821c12` + `0748cced` discovered at audit time).
- G-25-DRIFT-01 closure (already done in Phase 34 Plan 34-00) — no Phase 40 prep plan analog needed.
- Re-litigation of Phase 39 dispositions (D-39-B3 invariant: dispositions locked at audit-close).
- Phase 25 RESL-NIX backend execution and Phase 26 PKG streaming follow-up (queued for Linux/macOS host; not Phase 40 scope).

</domain>

<decisions>
## Implementation Decisions

### Plan slicing & wave shape (Area A)

- **D-40-A1: One plan per cluster (6 plans total).** Six plans: 4 will-sync (one per cluster — Clusters 1, 2, 6, 7) + 2 fork-preserve manual-replay plans (Clusters 4, 5). Cluster 3 won't-sync gets no plan per D-40-D1 (inline SUMMARY section). Cluster-theme names matching Phase 34 D-34-A1 convention: e.g., `40-01-PROXY-HARDENING` (Cluster 1), `40-02-CLI-ALLOW-VALIDATE` (Cluster 2), `40-03-SCRUB-MODULE` (Cluster 6), `40-04-RELEASE-RIDE` (Cluster 7), `40-05-FP-PROFILE-SAVE` (Cluster 4), `40-06-FP-PROXY-TLS` (Cluster 5). Maximum per-cluster traceability; reviewer attention concentrates per cluster.

- **D-40-A2: Wave 0 = Cluster 2 + Cluster 6 in PARALLEL (single foundation wave).** Both clusters carry `wave-hint: foundation` from Phase 39 ledger D-39-B3. They are surface-disjoint:
  - Cluster 2 surface: `crates/nono-cli/src/cli.rs` + `sandbox_state.rs` + `why_runtime.rs` + `profile/mod.rs` + `query_ext.rs`
  - Cluster 6 surface: NEW `crates/nono/src/scrub.rs` module + `lib.rs` re-export + integration into `audit_integrity.rs`/`audit_ledger.rs`/`command_runtime.rs`
  Run both in parallel as Wave 0; downstream Wave 1 plans rebase on top. Faster than the Phase 34 D-34-A2 single-cluster sequential gate (justified because Phase 34's C7 was 23 commits touching the canonical JSON schema — Phase 40's foundation clusters are 2 commits each on disjoint surfaces).

- **Wave structure (planner refines):**
  ```
  Wave 0 (parallel): 40-02-CLI-ALLOW-VALIDATE (Cluster 2), 40-03-SCRUB-MODULE (Cluster 6) — surface-disjoint foundations
              │
              ↓ (Wave 0 closes)
  Wave 1 (parallel): 40-01-PROXY-HARDENING (Cluster 1), 40-04-RELEASE-RIDE (Cluster 7) — disjoint surfaces; release ride-alongs sequence chronologically by upstream tag
              │
              ↓ (Wave 1 closes)
  Wave 2 (sequential): 40-05-FP-PROFILE-SAVE (Cluster 4), then 40-06-FP-PROXY-TLS (Cluster 5) — fork-preserve manual replays; Cluster 5 reads post-Cluster-4 state of cross-cutting profile/proxy interactions
  ```
  Planner has discretion to refine wave membership based on actual surface conflicts encountered. Plan numbering follows wave order (40-02/40-03 = Wave 0, 40-01/40-04 = Wave 1, 40-05/40-06 = Wave 2) — diverges from upstream-tag chronology to keep PLAN.md execution order readable.

- **D-40-A3: No phase-prep plan (no 40-00 analog).** Phase 34 Plan 34-00 landed the G-25-DRIFT-01 closure; Phase 40 has no analogous open-gap to close. UPST5 absorption already queued (D-39-D2 in ROADMAP § v2.5 backlog); no contradicting ADR finding; no PROJECT.md Key Decisions row to update. Plan 40-02 (Cluster 2) is the first plan to land.

### fork-preserve cluster handling (Area B)

- **D-40-B1: Cluster 4 (profile-save denial suppression) — diff-inspection upgrade authority granted.** Plan 40-05-FP-PROFILE-SAVE begins with an upstream-vs-fork diff inspection step:
  1. Read upstream `9b07bf7` (11 files) + `eb6cb09` (1 file) diff against fork HEAD.
  2. Surface-overlap check: does the diff touch any `#[cfg(target_os = "windows")]` arms in `terminal_approval.rs`, `profile_save_runtime.rs`, `policy.rs`, or `profile/mod.rs`? Does it intersect Phase 18.1 Plan 18.1-01 build_prompt_text per-HandleKind template surface (D-04-locked)? Does it intersect Phase 36/36.5 profile-drafts surface (REQ-PORT-CLOSURE-02 + REQ-PORT-CLOSURE-03)?
  3. **Upgrade rule (strict):** if (a) cherry-pick applies with zero fork-only-line conflicts AND (b) upstream feature semantics match what the fork already enforces (no behavioral surprise) → upgrade to will-sync with D-19 trailer cherry-pick. If either fails → stay D-20 manual replay.
  4. Decision documented in PLAN.md `## Disposition resolution` section with diff-evidence citations.

- **D-40-B2: Cluster 5 (proxy TLS trust + multi-route + credential matching) — keep conservative D-20 manual replay; no upgrade attempt.** Cluster 5 is explicitly the Phase 33 Cluster 11 follow-on per Phase 39 ledger rationale. Fork's `crates/nono-proxy/src/credential.rs` was rewritten on `windows-squash` for Windows credential injection (Phase 09 + Phase 11). Cherry-pick of `8ddb143 feat: fix upstream TLS trust, intercept auth, and multi-route dispatch` would merge directly into that rewritten path. Phase 34 D-34-B1 chose manual-replay for the analogous Phase 33 Cluster 11; same justification applies here. Plan 40-06-FP-PROXY-TLS reads upstream's structure and replays credential-match policy semantics (`f77e0e3 fix: absolute match / 2 matches = deny / no match = passthrough w no creds`) — these policy semantics MUST be replayed because they intersect the Windows credential-store fallback behavior — while preserving fork-only TLS interception wiring.

- **D-40-B3: Manual-replay commit-body discipline (commit-per-semantic-change, no D-19 trailer).** Each manual-replay commit (Plan 40-05 if disposition stays D-20; Plan 40-06 always) is structured as:
  - One commit per replayed semantic change (no squash; supports bisect).
  - Commit body sections (NO `Upstream-commit:` D-19 trailer because it's NOT a cherry-pick):
    - `Upstream intent:` what the upstream commit was trying to do.
    - `What was replayed:` the specific behavior carried into the fork.
    - `What was NOT replayed and why:` the upstream code/wiring that would have collided with fork-only surface.
    - `Fork-only wiring preserved:` explicit list of file paths/symbols/cfg-arms that the cherry-pick would have overwritten.
    - `Upstream-replayed-from:` optional trailer field citing the upstream sha for provenance (does NOT match the D-19 grep `^Upstream-commit: ` so it doesn't pollute the cherry-pick smoke check).
    - Two `Signed-off-by:` lines + `Co-Authored-By: Claude` (mirrors D-19 author/sign-off discipline without the cherry-pick-specific fields).
  Precedent: Phase 26 Plan 26-01 PKGS-02 + Phase 34 Plan 34-10 commit-body shape.

### PR / branch / close-gate (Area C)

- **D-40-C1: One PR per plan, direct-on-main (6 PRs).** Mirror Phase 34 D-34-D1 verbatim. PR ordering follows the D-40-A2 wave structure (Wave 0 PRs first — 40-02 + 40-03 in parallel; then Wave 1 — 40-01 + 40-04 in parallel; then Wave 2 sequential — 40-05 then 40-06). Push to `origin/main` occurs at each plan-close boundary. Reviewer attention concentrates per cluster; easier to spot a botched cherry-pick than against a bundled PR. Direct-on-main is consistent with v2.2 fast-forward at commit `1ef30c63` making `main` the integration branch.

- **D-40-C2: Per-plan close gate = D-34-D2 verbatim (8 checks).** Before each plan can close, the following must pass on the dev host (Windows):
  1. `cargo test --workspace --all-features` (Windows).
  2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host).
  3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` — Phase 25 CR-A cross-target lesson (memory entry `feedback_clippy_cross_target`); Windows-host clippy cannot catch unused-import drift inside `#[cfg(target_os = "linux"|"macos")]` blocks.
  4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` — symmetric coverage for macOS-gated code.
  5. `cargo fmt --all -- --check`.
  6. Phase 15 5-row detached-console smoke gate (`nono run --detached` → `nono ps` → `nono attach` → detach → `nono stop`).
  7. `wfp_port_integration` test suite passes (or documented-skipped with admin/service-not-available reason).
  8. `learn_windows_integration` test suite passes (or documented-skipped).

  **STOP triggers (mid-plan):** any gate (1)–(8) fails → plan freezes; investigate; either split the plan (Phase 22-05a/22-05b precedent — D-40-C3 below) or roll back the cherry-pick chain to the last clean state. No silent landing.

- **D-40-C3: Per-cluster split allowed if fork-divergence exceeds estimate.** If a will-sync cluster's cherry-pick chain hits more fork-divergence conflicts than the Phase 39 audit anticipated, plan can split into `40-NN-a` (clean cherry-picks) + `40-NN-b` (manual ports for divergent files). Phase 22-05a/05b precedent inherited verbatim. Mid-plan split decision documented in the original PLAN.md as a STOP-trigger event with link to the spawn-off plan files.

- **D-40-C4: D-19 trailer convention = Phase 22 D-19 verbatim (6-line shape).** Every cherry-pick commit ends with:
  ```
  Upstream-commit: <full-sha>
  Upstream-tag: <vX.Y.Z>
  Upstream-author: <Name <email>>     # lowercase 'a'
  Co-Authored-By: Claude <noreply@anthropic.com>
  Signed-off-by: Full Name <full-name@email>
  Signed-off-by: github-handle <github-handle@users.noreply.github.com>
  ```
  Smoke check at plan close: `git log --format='%B' main~N..main | grep -c '^Upstream-commit: '` equals the will-sync commit count for the cluster.

### Won't-sync documentation shape for Cluster 3 (Area D)

- **D-40-D1: Cluster 3 (PTY scrollback) documented inline in 40-SUMMARY.md.** Phase 40 close-out SUMMARY gets a `## Won't-sync clusters from Phase 39 ledger` section with one-line pointer-only rationale: "Cluster 3 (PTY scrollback) won't-sync per Phase 39 DIVERGENCE-LEDGER row + Phase 33 Cluster 1 same-class precedent (D-11 excluded; Phase 17 + Phase 30 already satisfied Windows scrollback requirement)." Smallest footprint; Phase 39 ledger has the full rationale and is the single source of truth for the v0.52.0..v0.53.0 audit range.

- **D-40-D2: No re-confirmation of Phase 39 § Fork-only surface area at Phase 40 close.** Phase 39 audit-walked Phase 33's enumeration against Phase 35/36/36.5 SUMMARYs at audit time. Phase 40 only touches cross-platform files (D-11 invariant enforced via D-40-E1 below) so fork-only surface is structurally untouched by Phase 40 work. No re-confirmation grep required.

- **D-40-D3: No ADR closure note at Phase 40 close.** Phase 39 § ADR review point (d) already documented "Phase 33 ADR remains Accepted — no superseding ADR needed yet." Phase 40 is execution-only; doesn't update the ADR; doesn't re-litigate the audit conclusion. ADR closure is structurally complete.

### Carry-Forward From Phase 22 / 24 / 34 (still binding — locked, not for re-discussion)

- **D-40-E1 (= Phase 22 D-17 / Phase 34 D-34-E1): Windows-only files structurally invariant.** Any cherry-pick or manual port that touches `*_windows.rs` files or `crates/nono-cli/src/exec_strategy_windows/` subtree is by definition a cherry-pick bug — abort, investigate, revert the Windows hunk. The Phase 24 D-11 drift-tool filter ensures these never appear in upstream commits we cherry-pick. Manual ports must explicitly diff-check `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows'` and confirm zero hits.

- **D-40-E2 (= Phase 22 D-19 / Phase 34 D-34-E2): Atomic commit-per-semantic-change with D-19 trailer block.** Verbatim 6-line shape from D-40-C4 above. Trailer is MANDATORY on every cherry-picked commit; smoke check `git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream-commit: '` must equal cluster commit count at plan close.

- **D-40-E3 (= Phase 22 D-20 / Phase 34 D-34-E3): Manual port for heavily-diverged files.** Per Phase 22 D-02 fallback rule + the fork-divergence catalog in `.planning/templates/upstream-sync-quick.md`. Manual-port commit body documents what was ported and why straight cherry-pick was infeasible (see D-40-B3 for the per-section structure).

- **D-40-E4 (= Phase 22 D-13/D-14 / Phase 34 D-34-E4): Port upstream test fixtures alongside production code.** If an absorbed feature ships with upstream test infrastructure (e.g., Cluster 6 scrub module unit tests in `crates/nono/src/scrub.rs`), port the fixture as part of the same cherry-pick chain. No fork-local mocks where upstream provides coverage. Windows-specific extension tests atop ported fixtures land behind `#[cfg(target_os = "windows")]`.

- **D-40-E5 (= Phase 34 D-34-E5): Use `.planning/templates/upstream-sync-quick.md` as the per-plan PLAN.md scaffold.** Each plan copies the template, fills `{placeholder}` markers for its cluster range, and the smoke check `grep -oE '\{[a-z_]+\}' PLAN.md` returns zero before plan starts. Template's Conflict-file inventory + Windows-specific retrofit checklist + Fork-divergence catalog are required reading per plan.

- **D-40-E6 (= D-34-B2): Surgical retrofit posture — inherit upstream as-is for cross-platform features that touch fork-only surface.** No opportunistic Windows composition during Phase 40 cherry-picks. Every "while we're here, let's also wire it up on Windows" retrofit becomes load-bearing surface the fork owns forever. Specific watch items for Phase 40 clusters:
  - Cluster 2 `nono why --host` proxy-domain awareness (`85f0acc`): flows through `nono-cli/src/why_runtime.rs` only. NO fork-side wiring to make `nono why` Windows-specific code aware. If a future Windows-hardening phase wants composition with Phase 09 WFP filter state in the `nono why` output, that's a new phase.
  - Cluster 6 `nono::scrub` module (`6472011`): ships cross-platform unchanged. NO Windows-specific scrub rules (e.g., Windows credential paths, registry-store URI patterns) — if those need scrubbing, that's a separate scope.

### Claude's Discretion

- **Exact wave membership beyond D-40-A2.** Planner refines Wave 1 grouping based on actual surface conflict probing (e.g., whether Cluster 1's `nono-proxy/src/server.rs` edits intersect Cluster 4's `policy.rs` post-Wave-0-rebase state).
- **Plan 40-04-RELEASE-RIDE handling of the 3 release commits.** `21bbb82` (release v0.52.1), `e8bf014` (release v0.52.2), `c4b25b8` (release v0.53.0) — Cargo.toml version bumps. Planner decides whether they ride along with each cluster's chain in upstream-chronological order, or get bundled into Plan 40-04 as a release-bumps-only plan that cherry-picks them in sequence at Wave 1. Either acceptable; Phase 34 / Phase 33 precedent inherited.
- **Whether Plan 40-05-FP-PROFILE-SAVE PLAN.md is written assuming the diff-inspection upgrade WILL fire or WON'T fire.** D-40-B1 leaves the upgrade decision to plan-phase. Planner can either: (a) write PLAN.md as a D-20 manual replay with a "may upgrade to D-19 cherry-pick if diff-inspection clears" branch documented in the disposition resolution section, or (b) write PLAN.md as a D-19 cherry-pick with a "may downgrade to D-20 if diff-inspection fails" branch. Either shape is acceptable as long as the diff-inspection step is the first task in PLAN.md and the disposition resolution decision is documented before any cherry-pick/replay commit lands.
- **Whether to push to `origin/main` after each plan close, or batch pushes per wave.** D-40-C1 says push at each plan-close boundary; planner may batch within a wave (e.g., push 40-02 + 40-03 together when both close) if it simplifies CI runs. Direct-on-main is the non-negotiable; push frequency within that is discretion.

### Folded Todos

None — the `gsd-sdk query todo.match-phase 40` matches (`v24-cr-01-broker-not-found-ffi-mapping.md`, `v24-cr-02-broker-null-handle-validation.md`, `v24-cr-03-broker-empty-handle-list-path.md`, `v24-cr-04-job-object-test-skip-policy.md`) are Phase 31 broker FFI / handle validation items with no UPST4 sync relationship. Score 0.6 was a false-positive on the `phase / planning / phases` keywords; surface is the FFI broker-launch path, not upstream-sync. Reviewed and not folded.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 40 scope sources (binding inputs)
- `.planning/ROADMAP.md` § Phase 40 — locked title `UPST4 sync execution`; depends-on Phase 39; Requirements: REQ-UPST4-02; "mirror Phase 34 shape" directive.
- `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` — **authoritative inventory of all 7 clusters / 22 commits**; per-cluster disposition (4 will-sync + 2 fork-preserve + 1 won't-sync); commit-row tables with sha/subject/upstream-tag/categories/files-changed/windows-touch; wave-hints (Cluster 2 foundation, Cluster 6 foundation); ADR review section confirming Phase 33 ADR Option A `continue` remains Accepted. Plan slicing aligns to cluster numbering in this artifact.
- `.planning/phases/39-upst4-audit/39-01-SUMMARY.md` — Phase 39 hand-off section explicitly addressed to Phase 40 (immutable input + plan-slicing input + wave-hints advisory + manual-replay cluster citations).
- `.planning/REQUIREMENTS.md` § REQ-UPST4-02 — phase acceptance contract (5 acceptance bullets: all will-sync cherry-picked with D-19 trailer; fork-preserve via D-20 manual replay with documented preservation; won't-sync documented in phase outcomes addendum; zero `*_windows.rs` edits; fork-defense grep baselines preserved or grown).

### Sync execution mechanics (mandatory template)
- `.planning/templates/upstream-sync-quick.md` — **MANDATORY scaffold for every Phase 40 plan** per D-40-E5. D-19 cherry-pick trailer block (verbatim 6-line shape with lowercase 'a' in `Upstream-author:`); Conflict-file inventory table (`profile/mod.rs`, `exec_strategy.rs`, `supervised_runtime.rs`, `rollback_runtime.rs`, `package_cmd.rs`, `nono-proxy/oauth2.rs`); Windows-specific retrofit checklist; Fork-divergence catalog (`validate_path_within` retention, deferred enum variants, async-runtime wrapping, hooks subsystem ownership, D-21 Windows-only file globs).
- `docs/cli/development/upstream-drift.mdx` — long-form runbook (output formats, categorization rules, fixture regeneration procedure, fork-divergence catalog rationale).
- `.planning/PROJECT.md` § Upstream Parity Process — 4-step process (inventory drift → scaffold the sync → cherry-pick per commit with D-19 trailer → verify Windows retrofit).

### Precedent CONTEXTs Phase 40 inherits structurally (D-40-A1..E6 lineage)
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md` — **nearest analog** (Phase 34 UPST3 v0.41–v0.52 sync). D-34-A1 one-plan-per-cluster shape, D-34-B1 fork-preserve plan-shape, D-34-B2 surgical-retrofit posture, D-34-D1 one-PR-per-plan direct-on-main, D-34-D2 8-check close gate, D-34-E1..E5 invariants. **D-40-A1..E6 inherit verbatim or near-verbatim from D-34-A1..E5.**
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/33-CONTEXT.md` — D-33 audit invocation pattern, ledger schema, ADR convention; informs how Phase 40 reads Phase 39 ledger (which inherited from D-33).
- `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-CONTEXT.md` — D-09/D-10/D-12 wave-parallel sequencing; D-17 Windows-only files invariant; D-19 atomic commit-per-semantic-change; D-20 manual port for heavily-diverged files. **Direct ancestor of Phase 40 D-19/D-20/D-40-E1.**
- `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05a-AUD-CORE-SUMMARY.md` + `22-05b-AUD-RENAME-SUMMARY.md` — Phase 22-05 mid-plan split precedent informs D-40-C3 STOP-trigger split-allowed behavior.
- `.planning/phases/26-pkg-streaming-followup/` Plan 26-01 — most recent D-20 manual-replay precedent (PKGS-02); informs D-40-B3 manual-replay commit-body discipline.
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-10-FP-PROXY-TLS-SUMMARY.md` — direct precedent for Plan 40-06 (Cluster 5 is the Phase 33 Cluster 11 follow-on, which Phase 34 Plan 34-10 replayed).
- `.planning/phases/24-parity-drift-prevention/24-CONTEXT.md` — D-08 drift-tool auto-detect range logic; D-11 path filter on `*_windows.rs` + `exec_strategy_windows/`; informs D-40-E1 Windows-only file invariant.

### Project-level context
- `.planning/PROJECT.md` § Current Milestone + Constraints + Key Decisions — Core Value ("Every nono command that works on Linux/macOS should work on Windows with equivalent security guarantees"); zero-startup-latency Windows constraint.
- `.planning/STATE.md` — current milestone v2.4 ("Complete the Partial Ports + UPST4"); v2.4 status; Phase 39 audit complete 2026-05-13; Phase 40 is the execution sibling.

### Coding & security standards (apply to every Phase 40 plan)
- `CLAUDE.md` § Coding Standards — no `.unwrap()`, DCO sign-off (`Signed-off-by:` lines in D-19 trailer; two lines per D-40-C4 convention), `#[must_use]` on critical Results, env-var save/restore in tests.
- `CLAUDE.md` § Security Considerations — path component comparison (not string ops); relevant for Cluster 2 `--allow` path validation (`f72ea31`) where upstream's pattern must compose with fork's `validate_path_within` defense-in-depth retention.
- `CLAUDE.md` § Platform-Specific Notes — Linux Landlock allow-list constraint; macOS Seatbelt DSL escaping. Relevant: Cluster 7 Landlock ABI cache optimization (`5b61971`); cross-platform diagnostic preservation (`5a61808`).
- Memory entry `feedback_clippy_cross_target` — Cross-target clippy required for cfg-gated Unix code; locks D-40-C2 close-gate steps 3 + 4.

### Phase 39 audit invariants (inherited as binding)
- D-39-B3 — dispositions locked at audit close; Phase 40 does NOT re-litigate the 4/2/1 split.
- D-39-C1 — windows-touch column structural carrier (Phase 40 doesn't need to re-validate; row values are `no` for all 22 commits in scope).
- D-39-D2 — v0.54.0+ absorbs into UPST5 (the 2 windows-touch candidates `5d821c12` + `0748cced` are NOT Phase 40 scope).

### Upstream source (git-resolvable from `upstream` remote at `https://github.com/always-further/nono.git`)
- Tag `v0.52.0` (`5d15b50`) — Phase 34 UPST3 sync point; Phase 40 baseline.
- Tag `v0.52.1` (`21bbb82`) — release commit; cluster boundary for 11 commits.
- Tag `v0.52.2` (`e8bf014`) — release commit; cluster boundary for 6 commits.
- Tag `v0.53.0` (`c4b25b8`) — release commit; cluster boundary for 5 commits.
- Upstream HEAD at Phase 39 audit time: `fc5c9553` (2026-05-13). Phase 40 plans cite v0.53.0 as the upper bound; commits after `c4b25b8` (the v0.53.0 release commit) are NOT in Phase 40 scope (UPST5 absorbs).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`make check-upstream-drift` tooling (Phase 24, sha `0834aa66`)** — `scripts/check-upstream-drift.{sh,ps1}`; Makefile target dispatches per-platform. Phase 40 plans can re-invoke at any time to confirm cluster boundaries hold against the live upstream HEAD. On Windows hosts where `make` is not on PATH, dispatch via `bash scripts/check-upstream-drift.sh` directly (Phase 39 39-01-SUMMARY § Deviations precedent inherited).
- **`.planning/templates/upstream-sync-quick.md`** — full PLAN.md scaffold (D-19 trailer block, conflict-file inventory, Windows retrofit checklist, fork-divergence catalog). Each Phase 40 plan copies this verbatim and fills `{placeholder}` markers per D-40-E5.
- **Phase 34 cherry-pick chain on `main`** — 10-plan reference for cluster-theme plan-naming + per-PR cadence + D-19 trailer shape; `git log --grep='^Upstream-commit:' --format='%H %s' main | head -30` lists in-repo precedents.
- **Phase 26 Plan 26-01 PKGS-02 + Phase 34 Plan 34-10 manual-replay precedents** — D-20 fork-preserve replay shape; informs Plan 40-05 (Cluster 4 if downgraded) and Plan 40-06 (Cluster 5) commit-body discipline per D-40-B3.

### Established Patterns
- **D-19 trailer block (verbatim 6-line shape)** — every cherry-pick commit ends with `Upstream-commit:` + `Upstream-tag:` + `Upstream-author:` (lowercase 'a') + `Co-Authored-By:` + 2× `Signed-off-by:`. Smoke check at plan-close: `git log --format='%B' main~N..main | grep -c '^Upstream-commit: '` equals N.
- **D-11 Windows-only file invariant** — drift tool's `*_windows.rs` + `exec_strategy_windows/` filter ensures upstream commits never touch these; cherry-picks that accidentally edit a Windows file must revert the Windows hunk. Verification: `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows'` returns zero hits per commit.
- **Wave-parallel by disjoint surface (Phase 22 D-09/D-10/D-12 / Phase 34 D-34-A2)** — plans wave-parallelize iff their working surfaces don't overlap. Cluster 2 (CLI/sandbox_state) + Cluster 6 (new crates/nono/src/scrub.rs) are surface-disjoint → Wave 0 parallel per D-40-A2.
- **D-20 manual-replay shape** — read upstream's commit + the fork-only wiring it would overwrite; replay the *intent* without the *form*; commit body documents what was ported and why straight cherry-pick was infeasible.
- **Cross-target clippy gate (Phase 25 CR-A lesson, memory `feedback_clippy_cross_target`)** — `cargo clippy --workspace --target x86_64-unknown-linux-gnu` catches `#[cfg(target_os = "linux")]` drift that Windows-host clippy silently misses. `--target x86_64-apple-darwin` for symmetric macOS coverage. Non-negotiable per D-40-C2 steps 3 + 4.

### Integration Points
- **Cherry-pick → fork-divergence catalog cross-check.** Every Plan 40 cherry-pick that touches a file in `.planning/templates/upstream-sync-quick.md` § Fork-divergence catalog must read the relevant catalog entry before resolving conflicts. Silent acceptance of upstream's removal of `validate_path_within` calls is the most common upstream-sync regression class.
- **Wave 0 (Cluster 2 + 6) closes before Wave 1.** Plans 40-01 (Cluster 1 proxy) + 40-04 (Cluster 7 sandbox + release ride-alongs) rebase on top of Wave 0's post-Cluster-2 `SandboxState` shape + post-Cluster-6 `nono::scrub` re-export. Cluster 1's `nono-proxy/src/server.rs` edits are independent of the scrub module; Cluster 7's release commits + Landlock ABI cache are independent of Cluster 2's CLI changes.
- **Wave 2 sequential: 40-05 (Cluster 4) → 40-06 (Cluster 5).** Cluster 5 proxy TLS manual replay reads post-Wave-1 proxy state; Cluster 4 profile-save diff inspection happens first because if it upgrades to will-sync, the resulting cherry-picks land before Cluster 5's manual replay (which may interact with policy.rs / profile.rs changes from Cluster 4).
- **D-40-C3 STOP-trigger plan split** → if mid-plan fork-divergence exceeds estimate, plan splits into `40-NN-a` / `40-NN-b`. Phase 22-05a/05b precedent inherited.
- **`.planning/STATE.md` "Last activity" log** → each plan-close appends a row recording cluster + commit chain. Phase 40 milestone closes when all 6 plan rows land (or fewer if mid-plan splits create 40-NN-a/b shape).

</code_context>

<specifics>
## Specific Ideas

- **One plan per cluster, cluster-theme names matching Phase 34** (D-40-A1) — user explicitly chose this over bundling small clusters or a mega-plan. Per-cluster traceability is the deciding factor; loss of reviewer focus is the trade-off rejected.
- **Wave 0 parallel for Cluster 2 + Cluster 6** (D-40-A2) — user explicitly chose parallel over Phase 34's sequential single-cluster gate. Justified because Phase 40's foundation clusters are 2 commits each on disjoint surfaces (vs Phase 34's 23-commit C7 schema gate).
- **No 40-00 prep plan** (D-40-A3) — user explicitly chose to skip phase-prep. No G-25-DRIFT-01 analog; UPST5 already queued; nothing to close at phase start.
- **Cluster 4 diff-inspection upgrade authority granted** (D-40-B1) — user chose to let Plan 40-05 read the upstream diff and upgrade to will-sync IF strict criteria pass (zero fork-only-line conflicts AND identical surface semantics). Upgrade is conditional, not automatic.
- **Cluster 5 stays conservative D-20 manual replay** (D-40-B2) — user explicitly rejected diff-inspection upgrade for Cluster 5 because it's the Phase 33 Cluster 11 follow-on and the fork's credential-injection rewrite makes collision likely.
- **Commit-per-semantic-change for manual replays, no D-19 trailer, optional `Upstream-replayed-from:` provenance** (D-40-B3) — user chose granular commits over squash for bisect support.
- **One PR per plan, direct-on-main (6 PRs)** (D-40-C1) — user explicitly chose Phase 34 D-34-D1 verbatim over bundling or single-PR shapes.
- **D-34-D2 8-check close gate verbatim** (D-40-C2) — user explicitly rejected dropping wfp_port_integration / learn_windows_integration or deferring cross-target clippy to PR gate. Phase 25 CR-A lesson is the framing.
- **STOP-trigger freeze on any gate failure, with per-cluster split allowed** (D-40-C3) — user chose strict freeze + Phase 22-05a/05b precedent for split rather than soft user-prompted recovery.
- **D-19 trailer convention verbatim from Phase 22 / Phase 34** (D-40-C4) — user explicitly rejected stripping Co-Authored-By or using single Signed-off-by.
- **Cluster 3 won't-sync inline in 40-SUMMARY, pointer-only rationale** (D-40-D1) — user chose smallest footprint over PHASE-OUTCOMES.md file or duplicated ledger rationale.
- **No re-confirmation of fork-only surface or ADR closure note at Phase 40 close** (D-40-D2, D-40-D3) — user explicitly chose trust-the-audit-invariants over defensive re-validation.

</specifics>

<deferred>
## Deferred Ideas

- **`nono why --host` Windows-side composition with Phase 09 WFP state** (D-40-E6 watch item from Cluster 2) — if a future Windows-hardening phase wants `nono why --host` aware of WFP filter state in addition to proxy domain filtering, that's a new phase with its own design. Phase 40 ships Cluster 2's `nono why` proxy-domain awareness as-is per surgical retrofit posture.
- **Windows-specific scrub rules in `nono::scrub` module** (D-40-E6 watch item from Cluster 6) — if Windows credential paths, registry-store URI patterns, or other Windows-only secret patterns need scrubbing in audit events, that's a separate scope. Phase 40 ships Cluster 6's scrub module cross-platform unchanged.
- **UPST5 audit phase (v0.54.0+)** — already queued in ROADMAP § v2.5 backlog with explicit citation of the 2 windows-touch candidates (`5d821c12` + `0748cced`). Phase 40 does not absorb v0.54.0 commits; UPST5 will be the first audit where windows-touch:yes fires.
- **Plan 40-06 partial-replay scope** — D-40-B2 allows Cluster 5 manual replay to selectively replay only the audit/policy semantics that strengthen the fork. Exact "what's defense-in-depth-useful vs skip" boundary is planner discretion; deferred to Plan 40-06 PLAN.md.
- **Push-to-origin batching within a wave** — D-40-C1 says push at each plan-close; planner may batch within a wave if CI simplifies. Specific batching policy is discretion.

### Reviewed Todos (not folded)

- `v24-cr-01-broker-not-found-ffi-mapping.md` — Phase 31 broker FFI error mapping (CR-01 from Phase 31 review). NOT in Phase 40 scope; surface is `bindings/c/` FFI mapping for broker errors, not upstream-sync. Belongs in a Phase 31 follow-up or Phase 31.x revision plan.
- `v24-cr-02-broker-null-handle-validation.md` — Phase 31 broker argv parser (CR-02 from Phase 31 review). NOT in Phase 40 scope; surface is `crates/nono-shell-broker/` argv handling.
- `v24-cr-03-broker-empty-handle-list-path.md` — Phase 31 broker empty-handle-list path (CR-03 from Phase 31 review). NOT in Phase 40 scope; surface is `crates/nono-shell-broker/`.
- `v24-cr-04-job-object-test-skip-policy.md` — Phase 31 broker Job Object test skip policy (CR-04 from Phase 31 review). NOT in Phase 40 scope; surface is broker integration test policy.

False-positive matches on `phase / planning / phases` keywords (score 0.6); none have any UPST4 sync relationship.

</deferred>

---

*Phase: 40-UPST4 sync execution*
*Context gathered: 2026-05-13*
