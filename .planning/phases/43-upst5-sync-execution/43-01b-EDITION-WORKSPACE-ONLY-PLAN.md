---
plan_id: 43-01b-EDITION-WORKSPACE-ONLY
phase: 43-upst5-sync-execution
plan: 01b
wave: "0a"
type: execute
cluster_id: 2
disposition: split-from-43-01
upstream_range: v0.53.0..v0.54.0
upstream_shas: []
upstream_tag: v0.54.0
baseline_sha: 13cc0628
supersedes: 43-01-EDITION-2024-FOUNDATION
supersedes_reason: "Plan 43-01 hit a Rule 4 architectural blocker (commit 4afbaa67 / SUMMARY status: BLOCKED). Upstream 8b888a1c re-exports public_key_id_hex + sign_statement_bundle that fork's signing.rs does not define and the commit itself does not add — proving the cherry-pick has implicit cross-cluster dependencies on commits not yet absorbed. 43-01b drops the cherry-pick path and instead applies the mechanically-resolvable workspace Cargo.toml edits as a fork-authored commit, deferring the source-file edition-2024 migration (and the symbol-introducing trust/signing commits) to v2.6 / UPST6."
umbrella_pr_section: "Plan 43-01b — Cluster 2 (split) workspace edits + MSRV bump (fork-authored)"
opens_umbrella_pr: true
requirements: [REQ-UPST5-02]
depends_on: []
autonomous: true
files_modified:
  - Cargo.toml
  - Cargo.lock
  - bindings/c/Cargo.toml
  - crates/nono/Cargo.toml
  - crates/nono-cli/Cargo.toml
  - crates/nono-proxy/Cargo.toml
  - crates/nono-shell-broker/Cargo.toml
skipped_gates_load_bearing: [3, 4]
skipped_gates_environmental: [6, 7, 8]
skipped_gates_rationale:
  gate_3_cross_target_linux_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (workspace edits affect every cfg-gated build, so load-bearing)"
  gate_4_cross_target_macos_clippy: "cross-toolchain unavailable on Windows host; CI lane substitute per cross-target-verify-checklist.md § PARTIAL Disposition (load-bearing)"
  gate_6_phase15_smoke: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_7_wfp_port_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
  gate_8_learn_windows_integration: "Windows runtime substrate not available in agent context per Phase 40 D-40-C2 precedent"
must_haves:
  truths:
    - "Workspace MSRV advanced from rust-version = \"1.77\" to rust-version = \"1.95\" atomically with the workspace-deps centralization commit"
    - "Workspace edition behavior: see Task 3 — attempt edition = \"2024\" first; if `cargo check --workspace` fails on edition-2024 lints/errors, revert to edition = \"2021\" and explicitly document the source-migration deferral to v2.6/UPST6 in SUMMARY DEC-3"
    - "`[workspace.dependencies]` gains nix (0.31.3), landlock (0.4), getrandom (0.4) as centralized deps; fork's url = \"2.5\" pin preserved (NOT downgraded to upstream's url = \"2\")"
    - "`[workspace.lints.clippy] unwrap_used = \"deny\"` declared formally in root Cargo.toml (already enforced via CLI args + CLAUDE.md — this formalizes it in the manifest)"
    - "Per-crate Cargo.toml files switch their nix / landlock / getrandom dep entries to `.workspace = true` references (where each crate currently uses those deps; do NOT add fresh deps the crate does not use)"
    - "Fork's workspace version pin (currently 0.53.0) NOT bumped — Cluster 2 was a feature commit upstream; the Phase 40 release-ride convention applies only to Cluster 3 (Plan 43-04). Dual-shape preservation accepted (literal `version = \"0.53.0\"` per crate OR `version.workspace = true` if Task 2 chooses to centralize)"
    - "Cargo.lock regenerated post-edit as a SEPARATE chore commit (NOT --amend) per CLAUDE.md commit policy"
    - "Zero green→red lane transitions vs baseline SHA 13cc0628 (D-43-E3)"
    - "All cross-target clippy lanes (Windows host + Linux + macOS) exit 0 — or marked load-bearing-skip → CI-verified per .planning/templates/cross-target-verify-checklist.md (D-43-E4)"
    - "Zero touches to fork-only Windows files (`*_windows.rs`, `exec_strategy_windows/`, `crates/nono-shell-broker/src/*.rs`) — D-43-E1 invariant trivially honored (this plan ONLY edits workspace + per-crate Cargo.toml files, never source files)"
    - "Phase 43 umbrella PR opened with Plan 43-01b contribution section (D-43-E6 / memory `project_cross_fork_pr_pattern`)"
    - "REQ-UPST5-02 acceptance criterion #1 advanced for Cluster 2 (split disposition recorded in DIVERGENCE-LEDGER; workspace edits land in 43-01b; source-migration deferred to v2.6/UPST6 with explicit DIVERGENCE-LEDGER follow-on entry)"
    - "Plan 43-01's BLOCKED SUMMARY + MSRV-VERIFICATION.txt + original PLAN.md preserved on main as historical record — see commits fa0b826c, 4afbaa67, e4a6bed7 — referenced by 43-01b SUMMARY and DIVERGENCE-LEDGER split-disposition entry"
  artifacts:
    - path: Cargo.toml
      provides: "MSRV bump + [workspace.dependencies] centralization + [workspace.lints.clippy] formalization"
      contains: "rust-version = \"1.95\""
    - path: .planning/phases/43-upst5-sync-execution/43-01b-EDITION-WORKSPACE-ONLY-SUMMARY.md
      provides: "Per-Phase-34-D-34-D2 8-check close gate evidence + per-plan PR umbrella contribution section text + reference back to 43-01 BLOCKED SUMMARY for historical lineage"
  key_links:
    - from: workspace root Cargo.toml
      to: crates/{nono,nono-cli,nono-proxy,nono-shell-broker}/Cargo.toml + bindings/c/Cargo.toml
      via: "rust-version.workspace = true inheritance + [workspace.dependencies].nix/landlock/getrandom usage via `.workspace = true`"
      pattern: "rust-version\\.workspace = true"
---

<objective>
Apply the mechanically-resolvable workspace `Cargo.toml` edits from upstream Cluster 2 (commit `8b888a1c`) as a **fork-authored** commit — NOT as a cherry-pick. Specifically: MSRV bump (`1.77` → `1.95`), `[workspace.dependencies]` centralization for `nix` / `landlock` / `getrandom`, `[workspace.lints.clippy] unwrap_used = "deny"` formalization, per-crate switch of those three deps to `.workspace = true` references, and a conditional edition bump (`2021` → `2024` if `cargo check` passes; otherwise stay on 2021 and defer source migration).

This plan supersedes Plan 43-01 after its Rule 4 architectural blocker (commit `fa0b826c` / `4afbaa67`). 43-01's PLAN.md + BLOCKED SUMMARY + MSRV-VERIFICATION.txt are preserved as historical record per user direction. 43-01b is the new Wave 0a foundation gate; it inherits `opens_umbrella_pr: true` from 43-01.

Purpose: unblock Wave 0b (Plan 43-02) and Wave 1 (Plans 43-03, 43-04) and Wave 2 (Plans 43-05, 43-06) by providing a buildable post-edit workspace baseline. Source-file edition-2024 migration is deferred to v2.6 / UPST6 because it requires absorbing the trust/signing symbols upstream `8b888a1c` re-exports but does not define (see memory `feedback-cluster-isolation-invalid`).

Output: 1 workspace-edits commit (fork-authored, NO D-19 trailer because this is NOT a cherry-pick) + 1 follow-on `chore(43-01b): regenerate Cargo.lock` commit (separate, NOT --amend) + 1 umbrella PR opened with Plan 43-01b contribution section + 1 SUMMARY.md.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/43-upst5-sync-execution/43-CONTEXT.md
@.planning/phases/43-upst5-sync-execution/43-PATTERNS.md
@.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-PLAN.md
@.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md
@.planning/phases/43-upst5-sync-execution/43-01-MSRV-VERIFICATION.txt
@.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md
@.planning/templates/upstream-sync-quick.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md
@Cargo.toml
@crates/nono/Cargo.toml
@crates/nono-cli/Cargo.toml
@crates/nono-proxy/Cargo.toml
@crates/nono-shell-broker/Cargo.toml
@bindings/c/Cargo.toml

<historical_lineage>
- **Predecessor:** Plan 43-01 (BLOCKED) — see `.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md` (status: `BLOCKED — Rule 4 architectural checkpoint`).
- **Predecessor commits:** `fa0b826c` (BLOCKED SUMMARY on worktree branch) + `4afbaa67` (merge to main) + `e4a6bed7` (STATE.md blocker record).
- **Predecessor PLAN.md retained:** `.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-PLAN.md` is preserved unchanged as evidence of what was attempted.
- **Predecessor evidence:** `.planning/phases/43-upst5-sync-execution/43-01-MSRV-VERIFICATION.txt` captured upstream's edition/MSRV values from `v0.54.0` Cargo.toml — reused by Task 1 below instead of re-running the verification.
- **Memory entry:** `feedback-cluster-isolation-invalid` captures the cross-cluster re-export dep lesson.
</historical_lineage>

<scope_boundary>
**IN-SCOPE for 43-01b** (mechanically-resolvable, no source-file changes):
- Root `Cargo.toml` `[workspace.package]`: `rust-version` 1.77 → 1.95
- Root `Cargo.toml` `[workspace.package]`: `edition` 2021 → 2024 **conditional** (Task 3 attempts; falls back to 2021 if `cargo check` fails)
- Root `Cargo.toml` `[workspace.dependencies]` additions: `nix = "0.31.3"`, `landlock = "0.4"`, `getrandom = "0.4"`
- Root `Cargo.toml` `[workspace.lints.clippy]` formalization: `unwrap_used = "deny"`
- Per-crate `Cargo.toml` (5 crates): switch existing `nix` / `landlock` / `getrandom` direct deps to `.workspace = true` (only where the crate currently uses each dep; do NOT add fresh deps)
- `Cargo.lock` regeneration (separate `chore(43-01b)` commit)

**OUT-OF-SCOPE for 43-01b** (deferred to v2.6 / UPST6):
- Source-file edition-2024 migrations (`dyn` keyword additions, parens around `+` trait bounds, closure-capture semantic shifts)
- Cherry-picking upstream `8b888a1c` (depends on unabsorbed trust/signing commits — see Predecessor SUMMARY DEC-1)
- Absorbing the `public_key_id_hex` and `sign_statement_bundle` symbols (those live in upstream commits not yet identified — Phase 42 follow-on audit needed)
- Upstream `serde_json` change from `"1.0.149"` to `"1"` — leave fork's pin alone for this plan
- Upstream `url` change from `"2.5"` to `"2"` — fork prefers tighter pin per Predecessor SUMMARY § "Cargo.toml work that IS mechanically resolvable"

**OUT-OF-SCOPE check at acceptance:** Task 2 acceptance must include `git diff --stat` showing ONLY Cargo.toml / Cargo.lock changes (no `.rs` files). If any `.rs` file is staged, STOP.
</scope_boundary>
</context>

<tasks>

<task id="1" type="execute" autonomous="true">
  <name>Task 1: Reconfirm upstream MSRV + edition values from Predecessor evidence</name>
  <read_first>
    - .planning/phases/43-upst5-sync-execution/43-01-MSRV-VERIFICATION.txt (Predecessor Task 1 output — already on main per commit 4afbaa67)
    - .planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md (Predecessor SUMMARY — confirms upstream edition="2024", rust-version="1.95")
  </read_first>
  <action>
    1. Read the Predecessor MSRV verification file. Confirm the captured values:
       - Upstream `edition` at `v0.54.0` = "2024"
       - Upstream `rust-version` at `v0.54.0` = "1.95"
       - Local `rustc --version` ≥ 1.95 (Predecessor SUMMARY confirmed 1.95.0 was available)
       If the Predecessor file is missing or any value is absent, re-run the verification per Plan 43-01 Task 1 steps 1-5 and write fresh evidence to `.planning/phases/43-upst5-sync-execution/43-01b-MSRV-VERIFICATION-REFRESH.txt`.
    2. Re-verify local rustc still satisfies the MSRV at execution time (toolchain may have changed since the Predecessor ran):
       `rustc --version` and compare against "1.95".
    3. NO git commit yet — Task 1 produces or reuses text-only evidence.
  </action>
  <acceptance_criteria>
    - Either: `.planning/phases/43-upst5-sync-execution/43-01-MSRV-VERIFICATION.txt` exists (Predecessor output) AND its captured values are referenced in this plan's SUMMARY
    - Or: a refreshed `.planning/phases/43-upst5-sync-execution/43-01b-MSRV-VERIFICATION-REFRESH.txt` is written and committed alongside Task 2 with the same fields
    - Local `rustc --version` major.minor ≥ 1.95 (semver compare)
  </acceptance_criteria>
  <done>Upstream MSRV + edition values reconfirmed from Predecessor evidence (or refreshed); local rustc verified ≥ MSRV.</done>
</task>

<task id="2" type="execute" autonomous="true">
  <name>Task 2: Apply workspace deps centralization + MSRV bump + clippy-lints formalization (fork-authored commit)</name>
  <read_first>
    - Current `Cargo.toml` (root) — capture `[workspace.package]`, `[workspace.dependencies]` (if it exists), and `[workspace.lints.*]` (if any) before editing
    - Each per-crate `Cargo.toml` to check which crates currently use `nix`, `landlock`, `getrandom` directly
    - CLAUDE.md § Commits (DCO sign-off required; prefer new commits over --amend)
    - `.planning/templates/upstream-sync-quick.md` § "Fork-authored (non-cherry-pick) commit shape" if such a section exists; otherwise follow the standard `chore(43-01b):` commit-message convention
  </read_first>
  <action>
    1. Confirm working tree clean: `git status --porcelain` returns empty.
    2. **Edit root `Cargo.toml`:**
       - In `[workspace.package]`: change `rust-version = "1.77"` to `rust-version = "1.95"`. LEAVE `edition = "2021"` for now (Task 3 attempts the bump).
       - Add or extend `[workspace.dependencies]`:
         ```toml
         [workspace.dependencies]
         # existing entries preserved verbatim (do NOT downgrade fork's url = "2.5")
         nix = "0.31.3"
         landlock = "0.4"
         getrandom = "0.4"
         ```
         If `[workspace.dependencies]` already exists, append the three new lines AFTER existing entries — do not reorder. If `url = "2.5"` is already centralized in fork's workspace, leave it; if it's currently per-crate, leave it per-crate for this plan (the dual-shape acceptance handles it).
       - Add `[workspace.lints.clippy]` section if absent:
         ```toml
         [workspace.lints.clippy]
         unwrap_used = "deny"
         ```
         If the section already exists with other entries, append `unwrap_used = "deny"` (no replace).
    3. **Edit per-crate `Cargo.toml` files** for each of `crates/nono`, `crates/nono-cli`, `crates/nono-proxy`, `crates/nono-shell-broker`, `bindings/c`:
       - For each direct dep entry matching `nix`, `landlock`, or `getrandom` with a literal version, replace with `.workspace = true`:
         ```toml
         # BEFORE
         nix = "0.31.2"
         # AFTER
         nix = { workspace = true }
         ```
         Use the table form `{ workspace = true }` if the original entry had additional fields (features, default-features); preserve those fields:
         ```toml
         # BEFORE
         nix = { version = "0.31.2", features = ["fs"], default-features = false }
         # AFTER
         nix = { workspace = true, features = ["fs"], default-features = false }
         ```
       - If a crate does NOT currently use one of these deps, leave it alone — do NOT add a fresh `.workspace = true` reference.
       - Add `[lints] workspace = true` to each crate's `Cargo.toml` if not already present (so the workspace clippy-lints inheritance kicks in).
    4. **Verify scope:** After all edits, `git status --porcelain` should show ONLY Cargo.toml files (no `.rs` files). Run:
       ```bash
       git diff --name-only | grep -vE '(^|/)Cargo\.toml$|^Cargo\.lock$' | head -1
       ```
       Must return empty. If any non-Cargo.toml file appears, STOP and surface the unexpected change.
    5. **Build sanity check:** `cargo check --workspace` must exit 0. This confirms the workspace-deps centralization + MSRV bump compiles cleanly under the CURRENT edition (2021). If it fails, diagnose: usually a version-mismatch between the workspace centralization and a per-crate dep that wasn't switched to `.workspace = true`. Fix and re-check.
    6. **Commit (fork-authored, no D-19 trailer):**
       Write commit message to `/tmp/43-01b-workspace-msg.txt`:
       ```
       chore(43-01b): centralize nix/landlock/getrandom deps + bump MSRV to 1.95

       Fork-authored split-out of upstream Cluster 2 (commit 8b888a1c) workspace
       Cargo.toml edits. Source-file edition-2024 migration deferred to v2.6 /
       UPST6 — see .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md § Cluster:
       Rust edition 2024 (split disposition).

       Predecessor: Plan 43-01 BLOCKED at Rule 4 architectural checkpoint per
       commits fa0b826c / 4afbaa67; this plan delivers the mechanically-resolvable
       portion only. See 43-01-EDITION-2024-FOUNDATION-SUMMARY.md for full
       discovery and 43-01b-EDITION-WORKSPACE-ONLY-PLAN.md for re-scoped task list.

       Changes:
       - rust-version: 1.77 → 1.95 ([workspace.package])
       - [workspace.dependencies]: + nix = "0.31.3", landlock = "0.4", getrandom = "0.4"
       - [workspace.lints.clippy]: + unwrap_used = "deny" (formalize existing CLAUDE.md guidance)
       - per-crate Cargo.toml: switch nix/landlock/getrandom direct deps to .workspace = true
       - per-crate Cargo.toml: add [lints] workspace = true inheritance

       Not changed (deferred):
       - edition = "2021" (kept — Task 3 may bump to 2024 conditionally)
       - source-file edition-2024 migrations (deferred — see DIVERGENCE-LEDGER split entry)
       - upstream serde_json "1.0.149" → "1" change (fork keeps current pin)
       - upstream url "2.5" → "2" change (fork keeps tighter pin)

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       ```
       Stage and commit:
       ```bash
       git add Cargo.toml bindings/c/Cargo.toml crates/nono/Cargo.toml crates/nono-cli/Cargo.toml crates/nono-proxy/Cargo.toml crates/nono-shell-broker/Cargo.toml
       git commit -F /tmp/43-01b-workspace-msg.txt
       ```
    7. **Regenerate Cargo.lock as a SEPARATE chore commit:**
       ```bash
       cargo update --workspace
       ```
       If Cargo.lock changes, stage and commit as a NEW commit (NOT --amend):
       ```bash
       git add Cargo.lock
       ```
       Commit message at `/tmp/43-01b-lockfile-msg.txt`:
       ```
       chore(43-01b): regenerate Cargo.lock post-workspace-deps centralization

       Mechanical regeneration follow-up to the 43-01b workspace edits commit.
       No D-19 trailer block — this is a fork-side mechanical commit, not an
       upstream-traced commit.

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       ```
       Then: `git commit -F /tmp/43-01b-lockfile-msg.txt`
       If `cargo update --workspace` does NOT change Cargo.lock (no transitive changes), skip the chore commit and document the no-op in the SUMMARY.
  </action>
  <acceptance_criteria>
    - `git diff --name-only HEAD~2 HEAD | grep -vE '(^|/)Cargo\.toml$|^Cargo\.lock$' | wc -l` → 0 (only Cargo.toml/Cargo.lock files touched across the workspace commit + optional Cargo.lock commit)
    - `grep -E '^rust-version = "1\.95"' Cargo.toml | wc -l` → 1
    - `grep -E '^edition = "2021"' Cargo.toml | wc -l` → 1 (Task 3 may change this later in the wave)
    - `grep -E '^nix = "0\.31\.3"|^nix \. workspace = true' Cargo.toml | wc -l` → ≥ 1 (workspace-level entry exists)
    - `grep -cE 'nix = \{ workspace = true' crates/*/Cargo.toml bindings/c/Cargo.toml` → ≥ 1 (at least one per-crate switched to workspace ref)
    - `cargo check --workspace` exits 0
    - `[[ ! -f .git/CHERRY_PICK_HEAD ]]` (this plan never invokes cherry-pick — fork-authored only)
    - **D-43-E1 invariant trivially honored:** `git show HEAD~1 --name-only | grep -cE '_windows\.rs|exec_strategy_windows|crates/nono-shell-broker/src/'` → 0 (Cargo.toml-only commits)
    - Commit subject matches: `git log -1 --format='%s' HEAD~1 | grep -cE '^chore\(43-01b\): centralize'` → 1 (workspace commit at HEAD~1 if Cargo.lock chore landed, else HEAD)
    - Commit body contains NO `Upstream-commit:` line: `git log -1 --format='%B' HEAD~1 | grep -c '^Upstream-commit:'` → 0
    - Commit body contains DCO sign-off: `git log -1 --format='%B' HEAD~1 | grep -cE '^Signed-off-by: '` → ≥ 1
  </acceptance_criteria>
  <done>Workspace deps centralized; MSRV bumped to 1.95; clippy-lints formalized; per-crate Cargo.toml switched to workspace refs; cargo check clean; commit landed without D-19 trailer (fork-authored, not cherry-pick); Cargo.lock regen committed separately if needed.</done>
</task>

<task id="3" type="execute" autonomous="true">
  <name>Task 3: Conditional edition bump (2021 → 2024) with automatic fallback</name>
  <read_first>
    - Output of Task 2 (workspace edits already landed; `cargo check` was clean under edition 2021)
    - Rust edition 2024 migration guide: https://doc.rust-lang.org/edition-guide/rust-2024/
    - `.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md` § DEC-1 (the cross-cluster re-export blocker that prevents the upstream source migration — but does NOT prevent attempting just the edition flag flip)
  </read_first>
  <action>
    1. Bump edition: edit root `Cargo.toml` `[workspace.package]` → `edition = "2024"`.
    2. **Attempt automatic source migration (cargo fix --edition):**
       ```bash
       cargo fix --edition --workspace --allow-dirty --allow-staged
       ```
       This applies trivial automatic source-level fixes (adding `dyn` keyword, parens around bare trait bounds). It does NOT touch closure-capture semantics or the trust/signing re-exports the Predecessor blocker identified — those are runtime / semantic concerns.
    3. **Verify build:**
       ```bash
       cargo check --workspace 2>&1 | tee /tmp/43-01b-edition-check.log
       ```
       Capture exit code. If exit 0, proceed to step 5.
    4. **On `cargo check` failure: revert and document deferral.**
       ```bash
       git checkout -- Cargo.toml  # revert edition bump
       git checkout -- '*.rs' '**/*.rs' 2>/dev/null || true  # revert any cargo-fix source edits
       # Confirm rollback: edition should be back to "2021"
       grep -E '^edition = "2021"' Cargo.toml || { echo "FAIL: edition not reverted"; exit 1; }
       cargo check --workspace || { echo "FAIL: revert state does not build — investigate"; exit 1; }
       ```
       Record the failure log content into the SUMMARY's "Decisions Made" section as DEC-3 (edition bump attempted, fell back to 2021, source migration deferred to v2.6/UPST6). NO commit on the failure path — the working tree returns to the post-Task-2 state.
       Then: STOP this Task — proceed directly to Task 4. The DIVERGENCE-LEDGER update will explicitly record the source-migration deferral, so this failure path is the EXPECTED outcome if the Predecessor's analysis was correct (upstream's edition-2024 source migrations depend on commits the fork has not absorbed).
    5. **On `cargo check` success: commit edition bump.**
       If step 3 exited 0, the workspace builds clean under edition 2024 with whatever automatic fixes `cargo fix --edition` applied. Stage everything that changed:
       ```bash
       git add -A
       git diff --staged --stat | head -10
       ```
       Verify scope: changes should be limited to root `Cargo.toml` + possibly a small set of `.rs` files that `cargo fix --edition` auto-migrated. If the source-file change-count is large (>20 files), STOP and surface — this likely means `cargo fix` started applying semantic changes the Predecessor warned about.
       Commit:
       ```
       chore(43-01b): bump workspace edition 2021 → 2024 (automatic source fixes only)

       Edition flag flip plus the minimal source migrations applied automatically
       by `cargo fix --edition --workspace --allow-dirty`. Manual source migrations
       (closure-capture semantic shifts, semantic let-else / let-chain refactors)
       remain deferred to v2.6 / UPST6 per the DIVERGENCE-LEDGER Cluster 2 split.

       `cargo check --workspace` exits 0 post-edit.

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       ```
    6. **Regenerate Cargo.lock if needed** (per Task 2 step 7 pattern — separate `chore(43-01b):` commit, not --amend).
  </action>
  <acceptance_criteria>
    - **Either** (success path): `grep -E '^edition = "2024"' Cargo.toml | wc -l` → 1 AND `cargo check --workspace` exits 0 AND commit landed with subject `chore(43-01b): bump workspace edition 2021 → 2024`
    - **Or** (fallback path): `grep -E '^edition = "2021"' Cargo.toml | wc -l` → 1 AND working tree clean AND no edition-bump commit landed AND SUMMARY DEC-3 documents the deferral with `cargo check` failure log excerpt
    - Either way: `cargo check --workspace` exits 0 at end of Task 3
    - Either way: `git status --porcelain` empty
  </acceptance_criteria>
  <done>Edition bump either landed atomically (with automatic source fixes) or was reverted cleanly with deferral documented; workspace builds in either case.</done>
</task>

<task id="4" type="execute" autonomous="true">
  <name>Task 4: Per-plan 8-check close gate (D-43-E9) + Wave 0a baseline-aware CI gate</name>
  <read_first>
    - .planning/templates/cross-target-verify-checklist.md (full file)
    - .planning/templates/upstream-sync-quick.md (§ "Baseline-aware CI gate" lines 96-113)
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (lines 148-184 — Wave-1 CI Verification per-job table format)
    - .planning/phases/43-upst5-sync-execution/43-PATTERNS.md § "Pattern 3: Per-Plan 8-Check Close Gate"
  </read_first>
  <action>
    Run the 8-check close gate per D-43-E9 (= Phase 34 D-34-D2 verbatim). For each gate, record output (or skip rationale) into `/tmp/43-01b-close-gate.log`:
    1. Gate 1: `cargo test --workspace --all-features` (Windows host).
    2. Gate 2: `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host).
    3. Gate 3: `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`. If cross-toolchain absent, mark `load-bearing-skip → CI-verified` per cross-target-verify-checklist.md § PARTIAL Disposition.
    4. Gate 4: `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`. Same handling as Gate 3.
    5. Gate 5: `cargo fmt --all -- --check`.
    6. Gate 6 (Phase 15 5-row detached-console smoke): environmental-skip per Phase 40 D-40-C2.
    7. Gate 7 (`wfp_port_integration`): environmental-skip if Windows runtime absent.
    8. Gate 8 (`learn_windows_integration`): environmental-skip if Windows runtime absent.
    9. Baseline-aware CI gate (Wave 0a): push branch + diff vs `13cc0628` per `.planning/templates/upstream-sync-quick.md:108-113`. Critical: this is the post-Phase-41 clean baseline — any red lane is a real regression.
    10. Record evidence into `.planning/phases/43-upst5-sync-execution/43-01b-CLOSE-GATE.md`.
  </action>
  <acceptance_criteria>
    - Gates 1, 2, 5 exit 0 on Windows host
    - Gates 3, 4 either exit 0 OR marked `skipped_gates_load_bearing: [3, 4]` with checklist PARTIAL prose
    - Gates 6, 7, 8 either pass OR marked `skipped_gates_environmental: [6, 7, 8]` per D-40-C2
    - Baseline CI diff: zero green→red lane transitions vs `13cc0628`
    - `.planning/phases/43-upst5-sync-execution/43-01b-CLOSE-GATE.md` exists with per-gate sections + per-job CI table
  </acceptance_criteria>
  <done>8-check close gate executed with skips properly categorized; baseline CI diff captured; zero new regressions vs `13cc0628`.</done>
</task>

<task id="5" type="execute" autonomous="true">
  <name>Task 5: Open Phase 43 umbrella PR + append Plan 43-01b contribution section (D-43-E6)</name>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md § PR body update pattern
    - .planning/phases/43-upst5-sync-execution/43-PATTERNS.md § "Pattern 6: Umbrella PR Body Assembly"
    - memory: project_cross_fork_pr_pattern
  </read_first>
  <action>
    1. Verify Phase 40's PR #922 is closed (per CONTEXT.md it was closed at v2.4 ship). If still open, surface to user.
    2. Open new umbrella PR against `upstream/main` (or agreed-upon Phase 43 base branch — confirm with user if ambiguous):
       - Title: `Phase 43 — UPST5 sync execution (v0.53.0..v0.54.0)`
       - Body: open with milestone summary (Phase 43, REQ-UPST5-02, baseline `13cc0628`), then the first contribution section for Plan 43-01b. Plans 43-02..43-06 append their sections later.
       - `gh pr create --base main --head <branch> --title "Phase 43 — UPST5 sync execution (v0.53.0..v0.54.0)" --body-file /tmp/43-umbrella-pr-body.md`
       - Record PR URL in `.planning/phases/43-upst5-sync-execution/43-UMBRELLA-PR.txt`.
    3. Contribution section template:
       ```markdown
       ## Plan 43-01b — Cluster 2 (split) workspace edits + MSRV bump (fork-authored)

       **Cluster:** 2 (Rust edition 2024 + workspace deps centralization — split disposition per DIVERGENCE-LEDGER)
       **Disposition:** split: workspace edits in 43-01b, source migration deferred to v2.6 / UPST6
       **Upstream commits:** none cherry-picked in 43-01b (fork-authored). Predecessor Plan 43-01 attempted cherry-pick of 8b888a1c — see 43-01-SUMMARY for BLOCKED disposition.
       **Files touched:** Cargo.toml + 5 crate-level Cargo.toml + Cargo.lock (no source files)
       **Key decision:** Atomic fork-authored split of Cluster 2; workspace deps centralization + MSRV bump 1.77 → 1.95 + clippy-lints formalization. Edition bump (2021 → 2024) {applied | deferred per Task 3 fallback}.
       **CI baseline diff:** zero success → failure transitions vs baseline `13cc0628`
       ```
    4. (Worktree mode) If running in a worktree, defer PR open + push to orchestrator. Task 5 produces the contribution-section text in `.planning/phases/43-upst5-sync-execution/43-01b-PR-SECTION.md` and documents the deferral.
  </action>
  <acceptance_criteria>
    - `.planning/phases/43-upst5-sync-execution/43-01b-PR-SECTION.md` exists with Plan 43-01b contribution section
    - Either: `.planning/phases/43-upst5-sync-execution/43-UMBRELLA-PR.txt` exists with the URL (executor-mode); OR SUMMARY documents PR open is deferred to orchestrator (worktree-mode)
    - `grep -c '^## Plan 43-01b — ' .planning/phases/43-upst5-sync-execution/43-01b-PR-SECTION.md` → 1
  </acceptance_criteria>
  <done>Plan 43-01b contribution section captured; umbrella PR opened (or deferred).</done>
</task>

<task id="6" type="execute" autonomous="true">
  <name>Task 6: Write Plan 43-01b SUMMARY.md</name>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (skeleton template)
    - .planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md (Predecessor — reference for historical lineage section)
    - All artifacts produced by Tasks 1-5
  </read_first>
  <action>
    Write `.planning/phases/43-upst5-sync-execution/43-01b-EDITION-WORKSPACE-ONLY-SUMMARY.md` mirroring the 40-01 skeleton structure with these specific sections:
    - Frontmatter: phase, plan, cluster_id (=2, same as Predecessor), subsystem (="workspace-config + msrv-bump"), tags (include "split-disposition", "deferred-source-migration"), dependency_graph (requires=[Plan 43-01 BLOCKED disposition recorded], provides=[edition + MSRV baseline for Wave 0b/1/2]), skipped_gates_*, key_decisions (include DEC-1 superseding rationale, DEC-2 fork-authored vs cherry-pick choice, DEC-3 edition bump outcome per Task 3), patterns_established (include "Cluster-split disposition: workspace edits land fork-authored when cherry-pick is blocked"), requirements_completed: [REQ-UPST5-02 partial — Cluster 2 split workspace-edits portion]
    - Sections: Performance / Accomplishments / Historical Lineage (link to 43-01 SUMMARY + commit SHAs fa0b826c, 4afbaa67, e4a6bed7) / Task Commits / Files Created/Modified / Decisions Made (DEC-1..N) / Deviations from Plan / Issues Encountered / D-43-E9 8-check close gate (mirror 40-01 table) / Wave 0a CI Verification (per-job table) / Threat-model close-out / Self-Check / User Setup Required / Next Phase Readiness (Plan 43-02 SNAPSHOT-SYMLINK-FIX unblocked)
    Commit:
    `git commit -F /tmp/43-01b-summary-msg.txt` with message:
    ```
    docs(43-01b): summarize cluster 2 split workspace edits

    Closes the 43-01b fork-authored portion of Cluster 2. Source-file edition-2024
    migration remains deferred to v2.6 / UPST6.

    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    ```
  </action>
  <acceptance_criteria>
    - File exists: `.planning/phases/43-upst5-sync-execution/43-01b-EDITION-WORKSPACE-ONLY-SUMMARY.md`
    - Frontmatter contains: phase, plan, cluster_id, supersedes, requirements_completed
    - `grep -c '^## ' SUMMARY.md` → ≥ 10
    - `git log -1 --format='%s' HEAD | grep -cE '^docs\(43-01b\):'` → 1
    - `git log -1 --format='%B' HEAD | grep -cE '^Signed-off-by: '` → ≥ 1
  </acceptance_criteria>
  <done>SUMMARY.md written; committed separately; Plan 43-01b closes Wave 0a; downstream plans unblocked.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| fork main → fork main (fork-authored commit) | Lower-trust boundary than cherry-pick: no upstream commit ID to trace; rely on fork's review process + CI gates + the Predecessor SUMMARY's analysis to validate the edits are correct |
| MSRV 1.77 → 1.95 transition | Any fork-only code path that relied on 1.77-only behavior would surface at `cargo check`; CI's Linux + macOS clippy lanes are the structural detector |
| edition 2021 → 2024 transition (conditional) | Task 3 attempts; falls back cleanly on `cargo check` failure |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation |
|-----------|----------|-----------|-------------|-----------|
| T-43-01b-01 | Tampering | `Cargo.toml` `[workspace.package]` | mitigate | Task 2 acceptance verifies fork's version pin preserved across all 5 per-crate files (dual-shape acceptance) |
| T-43-01b-02 | Tampering | fork-only Windows files | mitigate | D-43-E1 trivially honored: Task 2 acceptance requires Cargo.toml-only diff (no `.rs` files staged) |
| T-43-01b-03 | Elevation | MSRV bump exposes a fork-only code path that relied on older rustc | mitigate | Task 4 Gates 1+2 (Windows host) + Gates 3+4 (cross-target Linux/macOS) detect; Phase 40 CR-A class fix-on-main pattern applies if a regression surfaces |
| T-43-01b-04 | Elevation | edition 2024 binding-scope shifts (`if_let_rescope`) | mitigate | Task 3 fallback: revert edition to 2021 if `cargo check` fails; explicit deferral entry in DIVERGENCE-LEDGER documents the unresolved source-migration scope |
| T-43-01b-05 | DoS | `cargo update --workspace` regenerates Cargo.lock with a problematic transitive bump | accept | Task 2 step 7 lands as separate chore commit; any bad transitive surfaces in Task 4 Gate 1; baseline `13cc0628` is the regression detector |
| T-43-01b-06 | Information Disclosure | a workspace-dep centralization accidentally changes a per-crate feature flag | mitigate | Task 2 step 3 preserves features + default-features fields verbatim when switching to `.workspace = true` table form |
| T-43-01b-07 | Repudiation | fork-authored commit lacks upstream traceability | accept | This is by design — 43-01b is explicitly fork-authored. The commit body references the Predecessor (43-01 SUMMARY + commit SHAs) + the DIVERGENCE-LEDGER split entry. No D-19 trailer expected |

**ASVS L1 disposition:** All `high` threats (T-43-01b-01, T-43-01b-02) mitigated. `medium` threats mitigated. `low` threats accepted with CI as detector. Security gate satisfied.
</threat_model>

<verification>
Per-plan close gate (D-43-E9 = 8-check format per Plan 43-01 / Plan 43-02 pattern):

| Gate | Description | Required | Disposition |
|------|-------------|----------|-------------|
| 1 | `cargo test --workspace --all-features` (Windows host) | required | execute |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | required | execute |
| 3 | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | load-bearing | execute or skipped → CI |
| 4 | `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` | load-bearing | execute or skipped → CI |
| 5 | `cargo fmt --all -- --check` | required | execute |
| 6 | Phase 15 5-row detached-console smoke | environmental | execute or skipped |
| 7 | `wfp_port_integration` tests | environmental | execute (Windows host) or skipped |
| 8 | `learn_windows_integration` tests | environmental | execute (Windows host) or skipped |

Wave 0a baseline-aware CI gate: zero `success → failure` lane transitions vs baseline SHA `13cc0628` per D-43-E3.
</verification>

<success_criteria>
- Workspace `[workspace.dependencies]` gains centralized nix / landlock / getrandom entries; fork's url = "2.5" preserved
- Workspace MSRV bumped 1.77 → 1.95
- `[workspace.lints.clippy] unwrap_used = "deny"` formalized
- Per-crate Cargo.toml files switch direct nix/landlock/getrandom deps to `.workspace = true` references (where each crate uses each dep)
- Edition either bumped to 2024 (with automatic source fixes) OR remains at 2021 with deferral documented
- Cargo.lock regen landed as separate `chore(43-01b):` commit if any transitive changed
- Zero touches to source files (`.rs`) in the workspace commit — D-43-E1 trivially honored
- D-43-E9 8-check close gate executed with all skips properly categorized
- Wave 0a baseline-aware CI gate: zero `success → failure` transitions vs `13cc0628`
- Phase 43 umbrella PR opened with Plan 43-01b contribution section
- SUMMARY.md committed referencing Predecessor 43-01 BLOCKED SUMMARY + DIVERGENCE-LEDGER split entry
- REQ-UPST5-02 acceptance criterion #1 advanced for Cluster 2 (split workspace-edits portion); source-migration portion explicitly tracked as v2.6/UPST6 follow-on in DIVERGENCE-LEDGER
</success_criteria>

<output>
After completion, create `.planning/phases/43-upst5-sync-execution/43-01b-EDITION-WORKSPACE-ONLY-SUMMARY.md` per Task 6 specification.
</output>
