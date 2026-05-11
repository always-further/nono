# Phase 34: UPST3 — Upstream v0.41–v0.52 Sync Execution - Context

**Gathered:** 2026-05-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Execute the disposition-complete inventory in Phase 33's `DIVERGENCE-LEDGER.md` per the Wave 2 strategic ADR (`docs/architecture/upstream-parity-strategy.md`, Option A — continue bidirectional parity, Accepted 2026-05-11). Eight `will-sync` clusters get per-commit cherry-picks; two `fork-preserve` clusters get D-20 manual replays; two `won't-sync` clusters get explicit non-port documentation. G-25-DRIFT-01 closes as `no-divergence` against the Phase 33 audit-walk finding (zero RESL-rename commits in v0.40.1..v0.52.0).

**In scope:**
- Per-commit cherry-pick of all 8 `will-sync` clusters (C2 CLI consolidation, C4 proxy/network hardening, C5 keyring + display, C7 path canon + JSON schema restructure, C8 shell completion + truncation, C9 trust scan + YAML merge, C10 ps + env:// + ioctl, C12 env deny_vars + learn deprecation) with `Upstream-commit:` D-19 trailer block on every fork commit.
- Manual replay of 2 `fork-preserve` clusters (C6 v0.44 pack migration; C11 v0.51 proxy TLS interception + audit context) — replay the *intent* without deleting fork-only Windows wiring (Phase 18.1-03 widening for C6; Windows credential-injection rewrite for C11).
- Closure of G-25-DRIFT-01 at phase-start as `no-divergence` (audit citation; PROJECT.md Key Decisions row update; 25-HUMAN-UAT.md status flip).
- Documentation of the 2 `won't-sync` clusters (C1 PTY attach/detach polish — fork's ConPTY structurally different per D-11; C3 Unix-socket capability — Unix-only by construction, would violate D-19 if added to `crates/nono/`) as explicit non-ports in the phase ledger.

**Out of scope (route elsewhere or explicitly defer):**
- Defense-in-depth wiring of newly-absorbed cross-platform features into fork-only Windows surface (e.g., `--allow-connect-port` routing through Phase 09 WFP filter, `nono completion` MSI installer integration, `nono learn` deprecation flowing into D-11-excluded `learn_windows.rs`) — D-34-B2 locks the surgical-only retrofit posture.
- Closure or replay of fork-only Windows seams (`crates/nono-shell-broker/`, `WindowsTokenArm::BrokerLaunch`, Phase 28 chain-walker, Phase 32 TUF cached-root + broker self-trust-anchor, NONO_TEST_HOME seam) — these stay byte-identical (D-17 from Phase 22; cross-phase invariant).
- Phase 25 RESL-NIX backend execution (Linux/macOS host work; remains queued at Plan 25-01).
- Phase 26 PKG streaming follow-up (Plan 26-02 queued for Linux/macOS host).
- Upstream v0.53.0+ ingestion — Phase 34 caps at v0.52.0; next UPST4 phase fires per the Phase 33 ADR's "per upstream release, lazily-evaluated" cadence rule when a new minor release lands.

</domain>

<decisions>
## Implementation Decisions

### Plan slicing & wave shape (Area A)

- **D-34-A1: One plan per cluster (10 plans total).** Eight will-sync plans (one per cluster: C2, C4, C5, C7, C8, C9, C10, C12) plus two fork-preserve plans (C6 packs, C11 proxy TLS). Plus a phase-prep plan (34-00) for the G-25-DRIFT-01 no-divergence closure. Total ≈ 11 plans. Naming follows cluster theme + plan number, e.g., `34-01-CLI-CONSOLIDATION` (C2), `34-04-PATH-CANON-SCHEMA` (C7), `34-09-FP-PACKS` (C6 manual replay), `34-10-FP-PROXY-TLS` (C11 manual replay). Maximum per-cluster traceability; reviewer attention concentrates per cluster.

- **D-34-A2: C7 lands first as Wave 0 foundation (sequential gate).** Cluster 7 (v0.46–v0.47.1 path canonicalization + canonical JSON schema restructure; 23 commits — the largest cluster) lands alone before any other will-sync plan starts. Other clusters' profile-touching changes (C2 `nono policy` → `nono profile` rename, C6 pack migration) then rebase on top of the post-C7 canonical JSON schema state. Matches the Phase 22 D-09 pattern (PROF gate before PKG + OAUTH wave). Higher upfront risk but de-risks every downstream plan because they all fork off the post-schema state.

- **Wave structure (planner refines):**
  ```
  Wave −1: 34-00 G-25-DRIFT-01 no-divergence closure (D-34-C1)
  Wave  0: 34-04-PATH-CANON-SCHEMA (C7 alone — gate)
              │
              ↓ (C7 closes)
  Wave  1: 34-01 (C2 CLI consolidation), 34-06 (C9 trust scan), 34-03 (C5 keyring) — wave-parallel, disjoint surfaces
              │
              ↓ (Wave 1 closes)
  Wave  2: 34-02 (C4 proxy net), 34-05 (C8 completion), 34-07 (C10 ps/env://), 34-08 (C12 env deny_vars) — wave-parallel where surface-disjoint; serialize cli.rs touches by upstream chronological order
              │
              ↓ (Wave 2 closes)
  Wave  3: 34-09 (C6 pack migration manual replay), 34-10 (C11 proxy TLS manual replay) — sequential within wave (proxy TLS replay reads C4 final state)
  ```
  Planner has discretion to refine wave membership based on actual surface conflicts encountered.

- **D-34-A3: Won't-sync clusters documented as one inline ledger update (no dedicated plan).** Clusters C1 (PTY attach/detach) and C3 (Unix-socket capability) get explicit `won't-sync` rows in Phase 34's plan-close ledger update (a small addendum to the Phase 33 DIVERGENCE-LEDGER.md or a Phase 34 PHASE-OUTCOMES.md) so future audits can see they were considered and rejected with rationale. No code change, no separate plan.

### fork-preserve cluster handling (Area B)

- **D-34-B1: Both C6 (pack migration) and C11 (proxy TLS interception) in scope for Phase 34 as dedicated manual-replay plans.** C6 (34-09): read upstream `24d8b92` + harden-install commits + replay the *intent* (registry-pack format awareness, install/uninstall hardening) while preserving v2.1 Phase 18.1-03 widening wiring on Windows. C11 (34-10): replay structured audit context (`9300de9`) since Phase 23 REQ-AUD-05 composes cleanly with the upstream pattern; for the TLS-interception commits (`149abde`, `879562c`, `8db8919`, `dcf2d29`) — read upstream's structure, document the delta as fork-preserve (Windows credential-injection rewrite would be deleted by cherry-pick), and replay only the audit-context shape. The ledger row for cluster 11 ships with a "Phase 34 manual-replay summary" sub-section documenting exactly what was and was not replayed.

### Windows-specific retrofit depth (Area B continued)

- **D-34-B2: Surgical retrofit posture — inherit upstream as-is for cross-platform features that touch fork-only surface.** Three specific touchpoints:
  - **C4 `--allow-connect-port`** — port allowlist flag flows through `nono-proxy` only (upstream's path). NO fork-side wiring to Phase 09 WFP port-level filter. Phase 09 WFP allowlist remains a separate, parallel enforcement layer; users wanting kernel-level port enforcement still use Phase 09's `--allow-port` (Windows-only). This avoids a load-bearing composition that we'd own forever; `--allow-connect-port` is a CLI-surface parity item, not a defense-in-depth item.
  - **C8 `nono completion <shell>`** — ship the subcommand verbatim from upstream (`03546d6`). NO MSI installer integration; NO PowerShell `$PROFILE.d/` shim. Users on Windows run `nono completion powershell > $PROFILE.d/nono.ps1` manually (one-line cookbook entry sufficient). MSI integration deferred to a separate phase if user demand materializes.
  - **C12 `nono learn` deprecation** — cross-platform deprecation message in `cli.rs` flows through unchanged from upstream `b34c2af`. `learn_windows.rs` (D-11 excluded; ETW path) stays byte-identical. No Windows-specific deprecation docstring addition; the user-visible stderr message is sufficient.

  Rationale: every "while we're here, let's also wire it up on Windows" retrofit becomes load-bearing surface the fork owns forever. Phase 34's job is to absorb upstream, not to grow Windows-specific composition.

### G-25-DRIFT-01 closure (Area C)

- **D-34-C1: Close G-25-DRIFT-01 as `no-divergence` at phase-start (Plan 34-00, before any sync work).** Phase 33 audit empirically disproved the original RESL-rename hypothesis (zero commits matching `--memory` / `--cpu-percent` / `--max-processes` / `--timeout` rename keywords in v0.40.1..v0.52.0; upstream at v0.52.0 HEAD `54f7c32a` still ships the 4 flags under their original Phase 25 names). Plan 34-00 commits three small edits in one wave:
  1. Flip `25-HUMAN-UAT.md` G-25-DRIFT-01 entry: `status: open` → `status: closed: no-divergence`. Cite Phase 33 DIVERGENCE-LEDGER.md Headline finding + upstream HEAD sha.
  2. Update `PROJECT.md` § Key Decisions row added at Phase 33 to note "G-25-DRIFT-01 closed Phase 34 — empirical no-divergence finding".
  3. (Optional, planner discretion) Add a one-line note to `.planning/STATE.md` "Last activity" log.
  This removes a stale open-gap entry before the rest of Phase 34 piles new state on top.

### PR / branch / close-gate (Area D)

- **D-34-D1: Direct-on-main commits; one PR per plan (10–11 PRs).** Commits land directly on `main` per the Phase 22 D-05 pattern (main is the integration branch since the v2.2 fast-forward at commit `1ef30c63`). Each plan opens its own PR at plan-close for review on that cluster's 5–25 cherry-picks. Reviewer attention concentrates per cluster — easier to spot a botched cherry-pick than against a single 97-commit PR. Per-plan PR ordering follows the D-34-A2 wave structure (PR for 34-00 first, then 34-04 alone, then Wave 1 PRs in parallel, etc.). Push to origin/main occurs at each plan-close boundary.

- **D-34-D2: Per-plan close gate = Phase 22 D-18 baseline + cross-target clippy (Linux + macOS).** Before each plan can close, the following must pass on the dev host (Windows):
  1. `cargo test --workspace --all-features` (Windows).
  2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host).
  3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` — Phase 25 CR-A lesson: Windows-host clippy cannot catch unused-import drift inside `#[cfg(target_os = "linux"|"macos")]` blocks.
  4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` — symmetric coverage for macOS-gated code.
  5. `cargo fmt --all -- --check`.
  6. Phase 15 5-row detached-console smoke gate (`nono run --detached` → `nono ps` → `nono attach` → detach → `nono stop`).
  7. `wfp_port_integration` test suite passes (or documented-skipped with admin/service-not-available reason).
  8. `learn_windows_integration` test suite passes (or documented-skipped).

  **STOP triggers (mid-plan):** any gate (1)–(8) fails. Plan freezes; investigate; either split the plan (Phase 22-05a/22-05b precedent) or roll back the cherry-pick chain to the last clean state. No silent landing.

### Carry-Forward From Phase 22 / 24 (still binding)

- **D-34-E1 (= Phase 22 D-17): Windows-only files structurally invariant.** Any cherry-pick or manual port that touches `*_windows.rs` files or `crates/nono-cli/src/exec_strategy_windows/` subtree is by definition a cherry-pick bug — abort, investigate, revert the Windows hunk. The drift tool's D-11 filter (Phase 24 D-08) ensures these never appear in upstream commits we cherry-pick. Manual ports must explicitly diff-check `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows'` and confirm zero hits.

- **D-34-E2 (= Phase 22 D-19): Atomic commit-per-semantic-change with `Upstream-commit:` D-19 trailer block.** Verbatim 6-line shape from `.planning/templates/upstream-sync-quick.md` § D-19 cherry-pick trailer block: `Upstream-commit:` → `Upstream-tag:` → `Upstream-author:` (lowercase 'a') → `Co-Authored-By:` → `Signed-off-by:` (full name) → `Signed-off-by:` (github handle). Smoke check at plan close: `git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream-commit: '` must equal cluster commit count.

- **D-34-E3 (= Phase 22 D-20): Manual port for heavily-diverged files.** Files in scope where fork drift is high (`keystore.rs`, `sandbox_prepare.rs`, `rollback_runtime.rs`, `supervised_runtime.rs`, `exec_strategy.rs`, `policy.rs`, `network_policy.rs`, `package_cmd.rs`, `nono-proxy/oauth2.rs`) are read-upstream-and-replay candidates per Phase 22 D-02 fallback rule. Manual-port commit body documents what was ported and why straight cherry-pick was infeasible.

- **D-34-E4 (= Phase 22 D-13/D-14): Port upstream test fixtures alongside production code.** If an absorbed feature ships with upstream test infrastructure (e.g., C7 path-canonicalization regression tests, C9 trust-scan symlink-escape tests, C12 env deny_vars unit tests), port the fixture as part of the same cherry-pick chain. No fork-local mocks where upstream provides coverage. D-34-E4 inherits Phase 22 D-15 — Windows-specific extension tests atop ported fixtures land behind `#[cfg(target_os = "windows")]`.

- **D-34-E5: Use `.planning/templates/upstream-sync-quick.md` as the per-plan PLAN.md scaffold.** Each plan copies the template, fills `{placeholder}` markers for its cluster range, and the smoke check `grep -oE '\{[a-z_]+\}' PLAN.md` returns zero before plan starts. Template's Conflict-file inventory + Windows-specific retrofit checklist + Fork-divergence catalog are required reading per plan.

### Claude's Discretion

- **Exact wave membership beyond D-34-A2.** Planner refines Wave 1 / Wave 2 / Wave 3 cluster groupings based on actual surface conflict probing (e.g., whether C5 keyring's `Cargo.toml` feature-flag changes collide with C7's `Cargo.toml` `jsonschema` bump — Phase 33 ledger row v0.47.1 `7329ef7`).
- **Plan numbering scheme.** D-34-A1 names plans by cluster theme; planner decides whether plan numbers (`34-01`, `34-02`, …) follow upstream-tag chronology (C2 v0.41 → C12 v0.52) or wave order (C7 first as 34-01 even though its upstream tags are mid-range). Either is acceptable as long as the PLAN.md frontmatter records both the plan-number and the cluster ID.
- **Whether C12's `nono learn` deprecation needs a deprecation-window release boundary.** Upstream `b34c2af` adds the deprecation message; whether fork emits the same message starting at v2.4 or waits one milestone is a v2.4-milestone scoping decision, not a Phase 34 decision. Default: emit the message immediately on Phase 34 close (no extra release delay).
- **Whether to commit Plan 34-00's G-25-DRIFT-01 closure on a separate branch from the rest of Phase 34.** D-34-D1 says direct-on-main; Plan 34-00 is the simplest place to land — three small edits, no cherry-pick chain. Planner can choose to bundle 34-00 into the same PR as 34-04 (the Wave 0 plan) or open a tiny dedicated PR; both are acceptable.
- **PHASE-OUTCOMES.md vs DIVERGENCE-LEDGER.md amendment** for D-34-A3 won't-sync documentation. Planner picks whichever shape composes better with the existing Phase 33 ledger artifact.

### Folded Todos

None — no pending todos matched Phase 34 scope (validated via `gsd-sdk query todo.match-phase 34`).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 34 scope sources
- `.planning/ROADMAP.md` § Phase 34 — phase goal placeholder (Wave 3 / Plan 33-03 wrote the stub); locked title `UPST3 — Upstream v0.41–v0.52 Sync Execution`; depends-on Phase 33.
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md` — **authoritative inventory of all 12 clusters / 97 commits**; per-cluster disposition (8 will-sync + 2 fork-preserve + 2 won't-sync); commit-row tables with sha/subject/upstream-tag/categories/files-changed; Fork-only surface area enumeration. Plan numbering aligns to cluster numbering in this artifact.
- `docs/architecture/upstream-parity-strategy.md` — Phase 33 strategic ADR (Status: Accepted; Option A `continue` chosen); 5-criterion L/M/H decision table; D-33-C3 tiebreaker convention; "Future audit cadence" consequence clause (Phase 34 sets the cadence for UPST4+).
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/33-CONTEXT.md` — D-33-A1..D-33-D2 decision IDs; audit invocation pattern (D-33-A1); ledger schema (D-33-B1/B2/B3); ADR convention (D-33-C4); G-25-DRIFT-01 update shape (D-33-D2 informs D-34-C1).
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/33-SPEC.md` — REQ-1..5 acceptance contract for Phase 33 (Phase 34 inherits the audit/ADR as immutable inputs).

### Sync execution mechanics (mandatory template)
- `.planning/templates/upstream-sync-quick.md` — **MANDATORY scaffold for every Phase 34 plan**. D-19 cherry-pick trailer block (verbatim 6-line shape with lowercase 'a' in `Upstream-author:`); Conflict-file inventory table (`profile/mod.rs`, `exec_strategy.rs`, `supervised_runtime.rs`, `rollback_runtime.rs`, `package_cmd.rs`, `nono-proxy/oauth2.rs`); Windows-specific retrofit checklist (per-feature questions); Fork-divergence catalog (`validate_path_within` retention, deferred enum variants, async-runtime wrapping, hooks subsystem ownership, D-21 Windows-only file globs).
- `docs/cli/development/upstream-drift.mdx` — long-form runbook (output formats, categorization rules, fixture regeneration procedure, fork-divergence catalog rationale).
- `.planning/PROJECT.md` § Upstream Parity Process — 4-step process (inventory drift → scaffold the sync → cherry-pick per commit with D-19 trailer → verify Windows retrofit).

### Pattern reference (prior phases Phase 34 inherits)
- `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-CONTEXT.md` — **nearest analog** (Phase 22 UPST2 v0.38–v0.40 sync). D-09 / D-10 / D-12 wave-parallel sequencing; D-13..D-16 test fixture port discipline; D-17 Windows-only files invariant; D-18 Windows-regression safety net per plan; D-19 atomic commit-per-semantic-change; D-20 manual port for heavily-diverged files. **D-34-E1..E5 inherit verbatim or near-verbatim from Phase 22 D-17/D-19/D-20/D-13/D-14.**
- `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05a-AUD-CORE-SUMMARY.md` + `22-05b-AUD-RENAME-SUMMARY.md` — Phase 22-05 mid-plan split precedent (CONTEXT STOP trigger when fork-divergence exceeded estimates); informs D-34-D2 STOP-trigger behavior.
- `.planning/phases/24-parity-drift-prevention/24-CONTEXT.md` — drift-tool tooling decisions (D-08 auto-detect range logic; D-11 path filter on `*_windows.rs` + `exec_strategy_windows/`); informs Phase 34 audit re-validation (if needed) and the Windows-only file invariant.
- `.planning/phases/20-upstream-parity-sync/20-CONTEXT.md` — Phase 20 UPST-01 pattern (4-plan upstream-parity phase); D-15 / D-17 / D-18 / D-20 / D-21 precedents Phase 22 D-01..D-21 inherited.
- `.planning/phases/26-pkg-streaming-followup/` Plan 26-01 — most recent D-20 manual-replay precedent (PKGS-02 chose fork-preserve disposition for package-manager surface to protect Windows hook installer wiring); informs D-34-B1 manual-replay shape for C6 packs.

### Project-level context
- `.planning/PROJECT.md` § Current Milestone + Constraints + Key Decisions — Core Value ("Every nono command that works on Linux/macOS should work on Windows with equivalent security guarantees"); zero-startup-latency Windows constraint; D-33 row (Phase 33 strategy decision) immediately precedes D-34.
- `.planning/STATE.md` — current milestone v2.3 status; v2.3 closes via Phases 25-01 / 26-02 on Linux/macOS host; Phase 34 is post-v2.3 sync execution (the planner-of-record decides v2.4 milestone routing).
- `.planning/REQUIREMENTS.md` — overall requirements registry (Phase 34 has no formal REQ-IDs per ROADMAP `Requirements: TBD`; CONTEXT.md is the binding contract).

### Phase 25 G-25-DRIFT-01 closure inputs
- `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-HUMAN-UAT.md` § G-25-DRIFT-01 — the gap entry Plan 34-00 flips to `closed: no-divergence`. Phase 33 Plan 33-03 already appended an `Update (Phase 33, 2026-05-11)` section; Phase 34 Plan 34-00 appends a `Closure (Phase 34, 2026-MM-DD)` section.
- `.planning/PROJECT.md` § Key Decisions table — row added by Phase 33 Wave 3; Plan 34-00 updates the row to "G-25-DRIFT-01 closed Phase 34 — empirical no-divergence finding".

### Coding & security standards (apply to every Phase 34 plan)
- `CLAUDE.md` § Coding Standards — no `.unwrap()`, DCO sign-off (`Signed-off-by:` lines in D-19 trailer; two lines per Phase 22 D-19 convention), `#[must_use]` on critical Results, env-var save/restore in tests.
- `CLAUDE.md` § Security Considerations — path component comparison (not string ops); critical for cherry-picking C7 (path canon) and C9 (trust scan path-traversal) where upstream's pattern must compose with fork's `validate_path_within` defense-in-depth retention.
- `CLAUDE.md` § Platform-Specific Notes — Linux Landlock allow-list constraint; macOS Seatbelt DSL escaping. Relevant: C7 deny-overlap re-validation, C9 trust-scan empty-parent handling (Windows path semantics differ from POSIX), C12 env deny_vars cross-platform parser.

### Upstream source (git-resolvable from `upstream` remote at `https://github.com/always-further/nono.git`)
- Tag `v0.40.1` (`79154fe0`) — Phase 22 UPST2 sync point; Phase 34 baseline.
- Tags `v0.41.0` (`073620e`), `v0.42.0` (`a87c6ae`), `v0.43.0` (`30c0f76`), `v0.43.1` (`f405067`), `v0.44.0` (release commit), `v0.45.0` (`d38fe64`), `v0.46.0` (`d49585b`), `v0.47.0` (`7a01e32`), `v0.47.1` (`0cba04a`), `v0.48.0` (`e15b9c4`), `v0.49.0` (`587d98d`), `v0.50.0` (`cd74c4c`), `v0.50.1` (`2d183e8`), `v0.51.0` (`da60dae`), `v0.52.0` (`5d15b50`) — Phase 34 covers every commit in v0.41..v0.52 that the Phase 33 audit flagged as `will-sync` or `fork-preserve`.
- Upstream HEAD at audit time: `54f7c32a` (2026-05-11). Phase 34 plans cite v0.52.0 as the upper bound; commits after `54f7c32a` are NOT in Phase 34 scope.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`make check-upstream-drift` tooling (Phase 24)** — `scripts/check-upstream-drift.{sh,ps1}` (sha `0834aa66`); Makefile target dispatches per-platform. Phase 34 plans can re-invoke at any time to confirm cluster boundaries hold against the live upstream HEAD.
- **`.planning/templates/upstream-sync-quick.md`** — full PLAN.md scaffold (D-19 trailer block, conflict-file inventory, Windows retrofit checklist, fork-divergence catalog). Each Phase 34 plan copies this verbatim and fills `{placeholder}` markers.
- **Phase 22 cherry-pick chain on `windows-squash` (now merged to `main` at commit `1ef30c63`)** — 78-commit reference for the D-19 trailer shape; `git log --grep='^Upstream-commit:' --format='%H %s' main | head` lists in-repo precedents.
- **Phase 26 Plan 26-01 PKGS-02 manual-replay precedent** — most recent D-20 fork-preserve replay shape; informs Plan 34-09 (C6 packs) and Plan 34-10 (C11 proxy TLS) commit-body discipline.

### Established Patterns
- **D-19 trailer block (verbatim 6-line shape)** — every cherry-pick commit ends with `Upstream-commit:` + `Upstream-tag:` + `Upstream-author:` (lowercase 'a') + `Co-Authored-By:` + 2× `Signed-off-by:`. Smoke check at plan-close: `git log --format='%B' main~N..main | grep -c '^Upstream-commit: '` equals N.
- **D-11 Windows-only file invariant** — drift tool's `*_windows.rs` + `exec_strategy_windows/` filter ensures upstream commits never touch these; cherry-picks that accidentally edit a Windows file must revert the Windows hunk. Verification: `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows'` returns zero hits per commit.
- **Wave-parallel by disjoint surface (Phase 22 D-09/D-10/D-12)** — plans wave-parallelize iff their working surfaces don't overlap. Same-file edits serialize by upstream chronological order within a wave.
- **D-20 manual-replay shape** — read upstream's commit + the fork-only wiring it would overwrite; replay the *intent* without the *form*; commit body documents what was ported and why straight cherry-pick was infeasible.
- **Cross-target clippy gate (Phase 25 CR-A lesson, in feedback memory)** — `cargo clippy --workspace --target x86_64-unknown-linux-gnu` catches `#[cfg(target_os = "linux")]` drift that Windows-host clippy silently misses. Add `--target x86_64-apple-darwin` for symmetric macOS coverage.

### Integration Points
- **Cherry-pick → fork-divergence catalog cross-check.** Every Plan 34 cherry-pick that touches a file in the catalog (`validate_path_within` retention, deferred enum variants, async-runtime wrapping, hooks subsystem ownership, D-21 Windows-only file globs) must read the relevant catalog entry before resolving conflicts. Silent acceptance of upstream's removal of `validate_path_within` calls is the most common upstream-sync regression class.
- **C7 path-canon foundation** → all subsequent profile-touching plans (C2 rename, C6 pack migration) fork off the post-C7 canonical schema state. Wave gate (D-34-A2) is non-negotiable.
- **C11 proxy TLS manual replay** → reads C4 final proxy-state. C4 (proxy net hardening) closes before C11 (proxy TLS interception) starts.
- **Plan 34-00 G-25-DRIFT-01 closure** → flips `25-HUMAN-UAT.md` status field and updates `PROJECT.md` Key Decisions row. No code change; landed before any cherry-pick chain begins.
- **`.planning/STATE.md` "Last activity" log** → each plan-close appends a row recording cluster + commit chain. Phase 34 milestone closes when all 10–11 plan rows land.

</code_context>

<specifics>
## Specific Ideas

- **One PR per plan, direct-on-main** (D-34-D1) — user specifically rejected the single-Phase-34-PR shape from Phase 22 and the integration-branch shape. Reviewer attention per cluster is the deciding factor.
- **Surgical Windows retrofit posture** (D-34-B2) — user explicitly rejected defense-in-depth for `--allow-connect-port`/WFP composition and MSI integration for `nono completion`. "Every retrofit becomes load-bearing surface the fork owns forever" is the framing.
- **C7 first as Wave 0 foundation** (D-34-A2) — user explicitly rejected landing C7 last or middle. "Foundation wave" framing locks the canonical JSON schema state before any other profile-touching plan starts.
- **Both fork-preserve clusters in Phase 34** (D-34-B1) — user rejected carving cluster 11 (proxy TLS) into a separate phase. Phase 34 closes the full disposition-complete ledger from Phase 33; no carry-over.
- **G-25-DRIFT-01 closes at phase-start, not phase-end** (D-34-C1) — user explicitly chose front-loading. Removes stale open-gap before piling new state on top.

</specifics>

<deferred>
## Deferred Ideas

- **`nono completion` MSI installer integration** — D-34-B2 ships the subcommand as-is; MSI integration deferred to a separate phase if user demand materializes. Cookbook entry will read `nono completion powershell > $PROFILE.d/nono.ps1`.
- **`--allow-connect-port` ↔ Phase 09 WFP defense-in-depth composition** — D-34-B2 keeps `--allow-connect-port` proxy-only; if a future Windows hardening phase wants kernel-enforced port allowlisting alongside the proxy layer, that's a new phase with its own design.
- **`nono learn` Windows ETW deprecation routing** — D-34-B2 keeps `learn_windows.rs` byte-identical; if a future phase wants to actively gate or replace the ETW path on Windows, that's a separate scope.
- **UPST4 (v0.53+) ingestion** — Phase 33 ADR's "per upstream release, lazily-evaluated" cadence rule fires when v0.53.0 ships. No work owed until then.
- **PHASE-OUTCOMES.md vs DIVERGENCE-LEDGER.md amendment for won't-sync documentation** (D-34-A3) — planner's call; both shapes acceptable.

### Reviewed Todos (not folded)

None — no pending todos surfaced for Phase 34 scope.

</deferred>

---

*Phase: 34-UPST3 — Upstream v0.41–v0.52 Sync Execution*
*Context gathered: 2026-05-11*
