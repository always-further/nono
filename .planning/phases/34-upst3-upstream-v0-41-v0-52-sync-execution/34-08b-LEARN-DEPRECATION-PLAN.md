---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-08b
plan: 08b
slug: learn-deprecation
cluster_id: C12-non-env
type: execute
wave: 2
depends_on: ["34-04", "34-04b", "34-01", "34-02", "34-05", "34-07", "34-08a"]
blocks: []
files_modified:
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/learn.rs
  - crates/nono-cli/src/diagnostic.rs
  - crates/nono-cli/src/profile/mod.rs
  - Cargo.toml
  - CHANGELOG.md
upstream_tag_range: v0.52.0
upstream_commit_count: 5
disposition: cherry-pick-clean
parent_plan: 34-08 (archived) — split sibling of 34-08a
autonomous: true
requirements: [C12-non-env]
tags: [upst3, c12-non-env, learn-deprecation, macos-learn, interactive, wave-2, split-from-34-08]

must_haves:
  truths:
    - "All 5 non-env-touching C12 commits cherry-picked onto `main` in upstream chronological order (1d491b4d, b5f0a3ab, b34c2af6, bbdf7b85, 5d15b50e)"
    - "Every Plan 34-08b commit body carries the verbatim D-19 6-line trailer block (lowercase 'a' in `Upstream-author:`)"
    - "D-34-B2 surgical posture: `learn_windows.rs` last-touched SHA UNCHANGED post-plan (anchor SHA captured pre-plan)"
    - "D-34-B2 surgical posture: `b34c2af6` deprecation message flows through `cli.rs` verbatim; NO Windows-specific deprecation docstring; NO `#[cfg(target_os = \"windows\")]` arm added for the deprecation surface"
    - "macOS learn diagnostics enhanced (`1d491b4d`) — macOS-cfg-gated paths only; Windows diagnostic surface untouched"
    - "Interactive prompt improvement (`b5f0a3ab`) — cross-platform UI fix; no Windows-only retrofit"
    - "Escaped-quotes profile JSON output fix (`bbdf7b85`) — cross-platform serde rendering"
    - "v0.52.0 release commit (`5d15b50e`) cherry-picked as CHANGELOG-only; fork drops upstream version bumps in Cargo.toml + Cargo.lock per 34-04b/34-06 precedent"
    - "D-34-E1 invariant: zero edits to `*_windows.rs` / `exec_strategy_windows/` for every commit AND at plan close"
    - "Fork-defense grep baselines preserved: `never_grant|apply_deny_overrides` ≥21; `validate_path_within` ≥9; `capabilities.aipc|loaded_profile` ≥17; `find_denied_user_grants` ≥1; `bypass_protection` ≥1"
    - "Plan-close smoke: `git log --format='%B' main~5..main | grep -c '^Upstream-commit: '` equals 5"
    - "D-34-D2 close-gates 1, 2, 5 PASS on dev host (carry-forward P34-DEFER-01-1 + AIPC-SDK env-leak flake acceptable); 3, 4 deferred-to-CI per user-accepted posture; 6, 7, 8 admin-skipped"
    - "G-25-DRIFT-01 closure invariant preserved: NO RESL flag rename commits introduced (re-grep returns 0)"
  artifacts:
    - path: "crates/nono-cli/src/cli.rs"
      provides: "`nono learn` deprecation message (`b34c2af6`); escaped-quotes profile JSON output fix touch (`bbdf7b85` if applicable)"
      grep_pattern: "deprecat.*learn|learn.*deprecat"
    - path: "crates/nono-cli/src/learn.rs"
      provides: "Cross-platform `nono learn` deprecation surface (`b34c2af6`) — NOT `learn_windows.rs`"
      grep_pattern: "deprecat"
    - path: "crates/nono-cli/src/diagnostic.rs"
      provides: "macOS learn diagnostics improvement (`1d491b4d`); macOS-cfg-gated; escaped-quote parser fix (`bbdf7b85` if applicable)"
      grep_pattern: "cfg.*target_os.*macos"
    - path: "CHANGELOG.md"
      provides: "v0.52.0 upstream release-notes line (`5d15b50e`) — fork tracks own version separately"
      grep_pattern: "v0.52|0.52.0"
  key_links:
    - from: "User running `nono learn` (cross-platform, including Windows)"
      to: "Deprecation message printed to stderr"
      via: "Cross-platform `cli.rs` surface; `learn_windows.rs` (D-11 excluded ETW path) stays byte-identical per D-34-B2"
      pattern: "learn.*deprecated|nono learn.*replaced"
    - from: "Upstream commit `5d15b50e` v0.52.0 release bump"
      to: "Fork CHANGELOG.md note (no Cargo.toml/Cargo.lock version change)"
      via: "Cherry-pick + amend reverting version bump hunks (mirror 34-04b/34-06 release-commit handling)"
      pattern: "0.52|v0.52"
---

<objective>
Cluster C12-non-env (upstream v0.52.0, 5 commits): the non-env-touching subset of the original archived Plan 34-08 (C12). Splits from sibling Plan 34-08a (env_sanitization surface port + 4 env-touching v0.52 commits, manual-replay shape). This plan executes 5 clean cherry-picks:

1. `1d491b4d` — macOS learn diagnostics improvement (macOS-cfg-gated)
2. `b5f0a3ab` — interactive prompt improvements (cross-platform UI fix)
3. `b34c2af6` — **D-34-B2 surgical-posture commit**: deprecate `nono learn` subcommand; cross-platform deprecation message in `cli.rs`; `learn_windows.rs` byte-identical
4. `bbdf7b85` — escaped quotes in profile JSON output (cross-platform serde fix)
5. `5d15b50e` — chore: release v0.52.0 (CHANGELOG only; drop upstream Cargo.toml + Cargo.lock version bumps per fork-tracks-own-version convention 34-04b/34-06)

The 5 commits do NOT touch `env_sanitization.rs` (that surface ships in sibling 34-08a). All 5 are clean cherry-picks (no manual replay needed); plan is `autonomous: true`.

**Critical D-34-B2 posture for `b34c2af6`:** Deprecation message flows through `cli.rs` and `learn.rs` (cross-platform path) unchanged from upstream. `learn_windows.rs` (D-11-excluded fork-only ETW path; Phase 11 wiring) stays BYTE-IDENTICAL. NO Windows-specific deprecation docstring addition. NO new `#[cfg(target_os = "windows")]` arm for the deprecation surface. User-visible stderr message is sufficient cross-platform — Windows users see the same deprecation banner as Linux/macOS users.

**Critical D-34-E1 invariant:** Every commit's diff stat against `*_windows.rs` / `exec_strategy_windows/` must equal 0. Per-commit AND plan-close verification.

**Critical 34-04b/34-06 precedent for `5d15b50e`:** Fork tracks its own version (currently v2.3-track / Cargo.toml v0.37.x). Upstream's `5d15b50e` bumps `Cargo.toml` to 0.52.0 + regenerates `Cargo.lock`. After cherry-pick, revert the version-bump hunks (Cargo.toml + Cargo.lock); keep only the CHANGELOG.md entry. This matches Plan 34-04b (`d38fe644`) and Plan 34-06 release-commit handling.

Output: 5 atomic commits on `main` with D-19 trailers; D-34-B2 surgical posture verified; fork-version invariant preserved; Wave 2 complete (jointly with 34-08a).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md
@.planning/templates/upstream-sync-quick.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08-ENV-DENY-PLAN.archive.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-03-KEYRING-PLAN.md
@crates/nono-cli/src/cli.rs
@crates/nono-cli/src/learn.rs
@crates/nono-cli/src/learn_windows.rs

<interfaces>
**Cluster C12-non-env cherry-pick chain (5 commits, chronological per upstream topology):**

| Order | SHA | Tag | Subject | Upstream Author | Surface |
|-------|-----|-----|---------|-----------------|---------|
| 1 | `1d491b4d` | v0.52.0 | feat(diagnostic): macOS learn diagnostics improvement | (read via `git show`) | `diagnostic.rs` macOS-cfg arms |
| 2 | `b5f0a3ab` | v0.52.0 | fix(cli): interactive prompt improvements | (read via `git show`) | `cli.rs` cross-platform UI |
| 3 | `b34c2af6` | v0.52.0 | feat(cli): deprecate `nono learn` subcommand | Luke Hinds <lukehinds@gmail.com> | **D-34-B2 surgical**: `cli.rs` + `learn.rs` cross-platform; `learn_windows.rs` byte-identical |
| 4 | `bbdf7b85` | v0.52.0 | fix: escaped quotes in profile JSON output | (read via `git show`) | `profile/mod.rs` and/or `diagnostic.rs` serde rendering |
| 5 | `5d15b50e` | v0.52.0 | chore: release v0.52.0 | Luke Hinds <lukehinds@gmail.com> | CHANGELOG only (revert Cargo.toml + Cargo.lock version bumps) |

**Note on chronological ordering:** The exact within-v0.52.0 chronology must be verified pre-cherry-pick via `git log --topo-order --reverse upstream/v0.51.0..upstream/v0.52.0 -- <files>` filtered to non-env-sanitization surfaces. The 5 SHAs above are listed in the order they should land relative to each other; the archived 34-08 plan listed them as commits 1, 6, 5, 7, 10 in its 10-commit chain. After sibling 34-08a lands its 4 env-touching commits (3657c935, 780965d7, a022e5c7, 31f2fc27), these 5 commits cherry-pick onto the resulting state.

**Cherry-pick ordering vs sibling 34-08a:** Plan 34-08b depends on 34-08a closing first (Wave 2 sequential). The 9 commits of the original 34-08 chain (C12) split as 4 env-touching → 34-08a + 5 non-env → 34-08b. Order within 34-08b is upstream chronological among the 5 non-env commits; their absolute position in the v0.52.0 timeline is interleaved with 34-08a's commits, but since 34-08a closes first, 34-08b cherry-picks land cleanly on a state that already contains 34-08a's env_sanitization work.

**D-19 trailer block (verbatim, paste per commit, LOWERCASE 'a' in `Upstream-author:`):**

```
Upstream-commit: {sha_8char}
Upstream-tag: v0.52.0
Upstream-author: {name} <{email}>
Co-Authored-By: {name} <{email}>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

**D-34-B2 commit-body specifics for `b34c2af6` (paste verbatim as commit body):**

```
feat(cli): deprecate 'nono learn' subcommand

Per Phase 34 D-34-B2 surgical retrofit posture: deprecation message flows
through the cross-platform cli.rs / learn.rs surface unchanged from upstream.
learn_windows.rs (D-11 excluded; Phase 11 fork-only ETW path) stays
BYTE-IDENTICAL. No Windows-specific deprecation docstring addition. No new
#[cfg(target_os = "windows")] arm for the deprecation surface. User-visible
stderr message is sufficient cross-platform.

Upstream-commit: b34c2af6
Upstream-tag: v0.52.0
Upstream-author: Luke Hinds <lukehinds@gmail.com>
Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

**D-34 release-commit handling for `5d15b50e` (mirror 34-04b / 34-06 precedent):**

After `git cherry-pick 5d15b50e`, immediately revert the upstream version-bump hunks (fork tracks own version):

```bash
# Step 1: cherry-pick (will bring CHANGELOG + Cargo.toml + Cargo.lock changes)
git cherry-pick 5d15b50e

# Step 2: revert version-bump hunks (preserve fork's Cargo.toml + Cargo.lock state)
git checkout HEAD~1 -- Cargo.toml Cargo.lock
git add Cargo.toml Cargo.lock

# Step 3: verify only CHANGELOG.md remains staged from upstream
git diff --cached --stat
# Expected: only CHANGELOG.md (or equivalent release-notes file) in the diff

# Step 4: commit body documents the version-bump revert (mirror 34-04b shape)
git commit --amend
```

Commit body for `5d15b50e` (paste verbatim):

```
chore: release v0.52.0 (CHANGELOG-only; fork tracks own version)

Per Phase 34 release-commit handling convention (34-04b, 34-06 precedent):
fork drops upstream Cargo.toml + Cargo.lock version bumps. Fork tracks its
own version separately (currently v2.3-track). Only the CHANGELOG.md entry
is absorbed from upstream's v0.52.0 release commit.

Upstream-commit: 5d15b50e
Upstream-tag: v0.52.0
Upstream-author: Luke Hinds <lukehinds@gmail.com>
Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

**Fork-divergence catalog cross-checks:**

- **`learn_windows.rs` byte-identical preservation** (D-11 + D-34-B2): per-commit AND plan-close.
  ```bash
  # Per-commit (must equal 0 lines):
  git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/learn_windows.rs | wc -l

  # Plan-close anchor SHA verification:
  git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs
  # MUST equal the pre-Plan-34-08b SHA captured in Task 1.
  # Reference baseline from archived Plan 34-08 pre-flight (if recorded in sibling 34-08a SUMMARY,
  # use that; otherwise capture fresh in this plan's Task 1).
  ```

- **No new `#[cfg(target_os = "windows")]` arms for `b34c2af6` deprecation surface.** D-34-B2 forbids Windows-specific deprecation docstring. Verify:
  ```bash
  # Count of Windows-cfg arms in learn.rs and cli.rs BEFORE cherry-pick (capture in Task 1):
  git show HEAD:crates/nono-cli/src/learn.rs | grep -c '#\[cfg(target_os = "windows")\]'
  git show HEAD:crates/nono-cli/src/cli.rs | grep -c '#\[cfg(target_os = "windows")\]'

  # AFTER cherry-pick of b34c2af6, count must equal pre-cherry-pick baseline:
  grep -c '#\[cfg(target_os = "windows")\]' crates/nono-cli/src/learn.rs
  grep -c '#\[cfg(target_os = "windows")\]' crates/nono-cli/src/cli.rs
  ```

- **Fork tracks own version invariant** (5d15b50e handling): post-cherry-pick + revert, fork's Cargo.toml version field must be unchanged from pre-plan state. Verify:
  ```bash
  # Pre-plan (Task 1) capture:
  grep -E '^version = ' Cargo.toml | head -1
  # Post-5d15b50e (Task 2):
  grep -E '^version = ' Cargo.toml | head -1
  # MUST match pre-plan value.
  ```

- **Fork-defense grep baselines (Task 1 capture, plan-close verify):**
  ```bash
  # Capture pre-plan baselines:
  grep -rE 'never_grant|apply_deny_overrides' crates/ | wc -l   # Expected baseline ≥21
  grep -rE 'validate_path_within' crates/ | wc -l               # Expected baseline ≥9
  grep -rE 'capabilities\.aipc|loaded_profile' crates/ | wc -l  # Expected baseline ≥17
  grep -rE 'find_denied_user_grants' crates/ | wc -l            # Expected baseline ≥1
  grep -rE 'bypass_protection' crates/ | wc -l                  # Expected baseline ≥1
  # Plan-close: each count must be ≥ pre-plan baseline.
  ```

- **G-25-DRIFT-01 closure invariant**: NO RESL flag rename surface introduced. Verify post-Task 2:
  ```bash
  grep -rE 'memory.*deprecat|cpu-percent.*deprecat|max-processes.*deprecat|timeout.*deprecat' crates/   # Expected: 0
  ```
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — verify sibling 34-08a closed; capture all baselines (learn_windows.rs SHA, Cargo.toml version, Windows-cfg counts, fork-defense greps)</name>
  <files>(git operations + grep captures only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A2 + D-34-B2 + D-34-E1 + D-34-D2
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-ENV-SURFACE-PORT-SUMMARY.md (post-close; record its closing HEAD)
    - crates/nono-cli/src/learn_windows.rs (read first 20 lines to confirm fork-only Phase 11 ETW path; this file must stay byte-identical through the plan)
    - crates/nono-cli/src/cli.rs § `Commands::Learn` (the deprecation message lands here on `b34c2af6`)
  </read_first>
  <action>
    1. Verify sibling 34-08a closed. SUMMARY exists; main HEAD advanced past 34-08a's final commit:
       ```bash
       ls .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-*-SUMMARY.md
       git log --oneline --format='%H %s' | head -20
       # Expect to see 4 commits from 34-08a (env_sanitization surface port + 4 v0.52 env-touching cherry-picks) at the top.
       ```
       If 34-08a not closed, ABORT this plan; do not proceed.

    2. Verify all dependent plans (34-04, 34-04b, 34-01, 34-02, 34-05, 34-07) closed:
       ```bash
       for plan in 34-04 34-04b 34-01 34-02 34-05 34-07; do
         ls .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/${plan}-*-SUMMARY.md
       done
       ```

    3. `git fetch upstream --tags` and verify all 5 C12-non-env SHAs reachable:
       ```bash
       git fetch upstream --tags
       for sha in 1d491b4d b5f0a3ab b34c2af6 bbdf7b85 5d15b50e; do
         git rev-parse --verify "$sha" || echo "MISSING: $sha"
       done
       ```

    4. **CRITICAL** Capture pre-Plan-34-08b `learn_windows.rs` last-touched SHA (D-34-B2 anchor):
       ```bash
       git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs
       # Record verbatim in SUMMARY § "Pre-state: learn_windows.rs SHA"
       # This SHA MUST be unchanged at plan close.
       ```
       Cross-reference: if sibling 34-08a's SUMMARY recorded this SHA pre-its-plan, the value should still match (34-08a did not touch learn_windows.rs either; the SHA pre-34-08a equals the SHA pre-34-08b).

    5. Capture pre-Plan-34-08b HEAD SHA and Cargo.toml version field (fork-version invariant anchor for `5d15b50e`):
       ```bash
       git rev-parse HEAD
       grep -E '^version = ' Cargo.toml | head -1
       # Record both in SUMMARY § "Pre-state: HEAD + Cargo.toml version".
       ```

    6. Capture pre-Plan-34-08b Windows-cfg arm counts (D-34-B2 invariant for `b34c2af6`):
       ```bash
       grep -c '#\[cfg(target_os = "windows")\]' crates/nono-cli/src/learn.rs   # Record as baseline_learn_winarms
       grep -c '#\[cfg(target_os = "windows")\]' crates/nono-cli/src/cli.rs     # Record as baseline_cli_winarms
       ```
       Record both counts in SUMMARY. Post-cherry-pick of `b34c2af6` (Task 2 commit 3), these counts MUST equal the baseline (no new Windows arms added for the deprecation surface).

    7. Capture pre-Plan-34-08b fork-defense grep baselines:
       ```bash
       grep -rE 'never_grant|apply_deny_overrides' crates/ | wc -l
       grep -rE 'validate_path_within' crates/ | wc -l
       grep -rE 'capabilities\.aipc|loaded_profile' crates/ | wc -l
       grep -rE 'find_denied_user_grants' crates/ | wc -l
       grep -rE 'bypass_protection' crates/ | wc -l
       ```
       Record all 5 counts. Plan-close each must be ≥ baseline.

    8. Capture G-25-DRIFT-01 closure invariant baseline (must be 0; must STAY 0):
       ```bash
       grep -rE 'memory.*deprecat|cpu-percent.*deprecat|max-processes.*deprecat|timeout.*deprecat' crates/ | wc -l
       # Expected: 0 (pre-plan). Must remain 0 post-plan.
       ```

    9. `cargo build --workspace` baseline green.

    10. Inspect upstream commit shapes pre-cherry-pick:
       ```bash
       git show 1d491b4d --stat
       git show b5f0a3ab --stat
       git show b34c2af6 --stat
       git show bbdf7b85 --stat
       git show 5d15b50e --stat
       ```
       Record file lists in SUMMARY § "Pre-state: upstream commit shapes" so Task 2 cherry-pick conflicts (if any) can be diagnosed quickly.
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; git rev-parse --verify 1d491b4d &amp;&amp; git rev-parse --verify b5f0a3ab &amp;&amp; git rev-parse --verify b34c2af6 &amp;&amp; git rev-parse --verify bbdf7b85 &amp;&amp; git rev-parse --verify 5d15b50e &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - Sibling 34-08a SUMMARY present; 34-04, 34-04b, 34-01, 34-02, 34-05, 34-07 SUMMARYs all present.
    - All 5 C12-non-env SHAs reachable via `upstream` remote.
    - `learn_windows.rs` last-touched SHA captured verbatim in SUMMARY (D-34-B2 anchor).
    - Pre-plan HEAD SHA + Cargo.toml version field captured.
    - Pre-plan Windows-cfg arm counts captured for `learn.rs` and `cli.rs`.
    - Pre-plan fork-defense grep counts captured (5 numbers).
    - Pre-plan G-25-DRIFT-01 invariant grep returns 0.
    - `cargo build --workspace` exits 0.
    - 5 upstream commit shapes (`git show --stat`) recorded in SUMMARY.
  </acceptance_criteria>
  <done>
    All baselines captured. Ready for C12-non-env cherry-pick chain. STOP if 34-08a is not closed.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 5 C12-non-env commits with D-19 trailers; D-34-B2 surgical posture for b34c2af6; release-commit handling for 5d15b50e</name>
  <files>
    crates/nono-cli/src/cli.rs
    crates/nono-cli/src/learn.rs
    crates/nono-cli/src/diagnostic.rs
    crates/nono-cli/src/profile/mod.rs
    Cargo.toml
    Cargo.lock
    CHANGELOG.md
  </files>
  <read_first>
    - crates/nono-cli/src/cli.rs § `Commands::Learn` (where `b34c2af6` deprecation message lands)
    - crates/nono-cli/src/learn.rs § cross-platform learn surface (where `b34c2af6` may also touch)
    - crates/nono-cli/src/learn_windows.rs (read first 20 lines — fork-only Phase 11 ETW path; MUST stay byte-identical through all 5 commits)
    - crates/nono-cli/src/diagnostic.rs § macOS-cfg-gated paths (`1d491b4d` target)
    - crates/nono-cli/src/profile/mod.rs § serde rendering paths (`bbdf7b85` target)
    - CHANGELOG.md (if present) — current v0.37.x-track entries; `5d15b50e` adds v0.52.0 entry
    - Cargo.toml § fork-version field (pre-plan baseline from Task 1; must stay unchanged through `5d15b50e`)
    - `git show 1d491b4d b5f0a3ab b34c2af6 bbdf7b85 5d15b50e --stat` (already run in Task 1)
  </read_first>
  <action>
    Cherry-pick all 5 commits in upstream chronological order. Per-commit template + per-commit D-34-E1 invariant + per-commit `learn_windows.rs` byte-identity check + special handling for commits 3 (b34c2af6, D-34-B2) and 5 (5d15b50e, release-commit).

    **Per-commit template (commits 1, 2, 4 — straightforward cherry-picks):**

    ```bash
    git cherry-pick <sha>
    # Resolve any conflicts (expected: minimal; these are cross-platform files with no fork-divergence catalog entries except diagnostic.rs/cli.rs which are well-known shared surfaces).
    cargo build --workspace
    # Amend with D-19 trailer:
    git commit --amend -m "$(cat <<'EOF'
    <upstream subject verbatim>

    Upstream-commit: <8-char sha>
    Upstream-tag: v0.52.0
    Upstream-author: <name> <<email>>
    Co-Authored-By: <name> <<email>>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    # Per-commit D-34-E1 invariant (must equal 0):
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l
    # Per-commit learn_windows.rs byte-identity (must equal 0):
    git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/learn_windows.rs | wc -l
    ```

    ---

    **Commit 1/5: `1d491b4d` — feat(diagnostic): macOS learn diagnostics improvement**

    After cherry-pick, verify macOS-cfg gate is intact (fork's Windows diagnostic path must NOT be affected):
    ```bash
    grep -c '#\[cfg(target_os = "macos")\]' crates/nono-cli/src/diagnostic.rs
    # Expected: ≥ baseline (macOS arms preserved; new macOS arm may be added)
    git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/diagnostic.rs
    # Expected: changes confined to macOS-cfg arms or cross-platform helpers that don't conflict with Windows surface
    ```
    Use standard per-commit template above. D-19 author/email read via `git show 1d491b4d --format='%an <%ae>'`.

    ---

    **Commit 2/5: `b5f0a3ab` — fix(cli): interactive prompt improvements**

    Cross-platform UI fix. After cherry-pick, verify no Windows-surface leak:
    ```bash
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    cargo build --workspace
    ```
    If feasible (interactive testing not strictly required), note prompt-behavior change in SUMMARY for manual smoke. Otherwise defer to manual testing post-plan.

    Use standard per-commit template. D-19 author/email read via `git show b5f0a3ab --format='%an <%ae>'`.

    ---

    **Commit 3/5: `b34c2af6` — feat(cli): deprecate `nono learn` subcommand — D-34-B2 SURGICAL POSTURE COMMIT (CRITICAL)**

    ```bash
    git cherry-pick b34c2af6
    cargo build --workspace
    ```

    **D-34-B2 verification BEFORE amending the commit:**
    ```bash
    # learn_windows.rs MUST be byte-identical (no diff hunks):
    git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/learn_windows.rs | wc -l   # Expected: 0
    git diff HEAD~1 HEAD -- crates/nono-cli/src/learn_windows.rs                  # Expected: empty
    ```

    **D-34-B2 verification on Windows-cfg arm counts (must equal Task 1 baselines):**
    ```bash
    grep -c '#\[cfg(target_os = "windows")\]' crates/nono-cli/src/learn.rs
    # Expected: equals Task 1 baseline_learn_winarms (no new Windows arm added)
    grep -c '#\[cfg(target_os = "windows")\]' crates/nono-cli/src/cli.rs
    # Expected: equals Task 1 baseline_cli_winarms (no new Windows arm added)
    ```

    If either count exceeds the baseline → ABORT, investigate, manually revert the Windows-arm hunk, re-amend the commit, re-verify.

    **Verify deprecation message landed on cross-platform surface:**
    ```bash
    grep -cE 'deprecat' crates/nono-cli/src/cli.rs crates/nono-cli/src/learn.rs
    # Expected: ≥ 1 (new deprecation message text appears on at least one of these cross-platform files)
    grep -cE 'deprecat' crates/nono-cli/src/learn_windows.rs
    # Expected: equals Task 1 baseline (likely 0; no deprecation docstring added to ETW path)
    ```

    **Amend commit body using the verbatim D-34-B2 template** (see `<interfaces>` section above for the exact text). The body includes the D-34-B2 rationale paragraph + D-19 trailer block.

    After amending:
    ```bash
    git log -1 --format='%B' | grep -c 'D-34-B2'      # Expected: ≥ 1 (rationale paragraph present)
    git log -1 --format='%B' | grep -c '^Upstream-commit: '   # Expected: 1
    ```

    ---

    **Commit 4/5: `bbdf7b85` — fix: escaped quotes in profile JSON output**

    Cross-platform serde rendering fix. After cherry-pick, verify:
    ```bash
    # Check which file(s) touched (likely profile/mod.rs or diagnostic.rs):
    git diff --stat HEAD~1 HEAD -- crates/
    # Expected: changes confined to cross-platform serde/JSON-rendering paths
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    cargo test -p nono-cli profile::tests::   # If tests touched the escape-quote handler, they should pass
    ```

    Use standard per-commit template. D-19 author/email read via `git show bbdf7b85 --format='%an <%ae>'`.

    ---

    **Commit 5/5: `5d15b50e` — chore: release v0.52.0 — FORK-VERSION-INVARIANT RELEASE-COMMIT HANDLING (CRITICAL, mirrors 34-04b/34-06)**

    ```bash
    git cherry-pick 5d15b50e
    # The cherry-pick will bring: CHANGELOG.md entry + Cargo.toml version bump + Cargo.lock regen.
    # The Cargo.toml + Cargo.lock changes MUST be reverted (fork tracks own version).

    # Revert version-bump hunks:
    git checkout HEAD~1 -- Cargo.toml Cargo.lock
    git add Cargo.toml Cargo.lock

    # Verify only CHANGELOG.md (or equivalent release-notes file) remains in the cherry-pick diff:
    git diff --cached --stat
    # Expected: only CHANGELOG.md (or .md release-notes file); NO Cargo.toml, NO Cargo.lock
    ```

    **Verify fork-version invariant:**
    ```bash
    grep -E '^version = ' Cargo.toml | head -1
    # Expected: equals Task 1 baseline (fork's pre-plan version, e.g., 0.37.x)
    ```

    If `Cargo.toml` version field shows 0.52.0 → revert FAILED; redo:
    ```bash
    # Re-revert:
    git checkout HEAD~1 -- Cargo.toml Cargo.lock
    git add Cargo.toml Cargo.lock
    grep -E '^version = ' Cargo.toml | head -1   # Re-verify
    ```

    **Amend commit body using the verbatim release-commit template** (see `<interfaces>` section above for the exact text). The body documents the version-bump revert rationale + D-19 trailer block.

    After amending:
    ```bash
    git log -1 --format='%B' | grep -c 'fork tracks own version'   # Expected: ≥ 1
    git log -1 --format='%B' | grep -c '^Upstream-commit: '         # Expected: 1
    git diff --stat HEAD~1 HEAD -- Cargo.toml Cargo.lock            # Expected: 0 lines (Cargo files unchanged)
    git diff --stat HEAD~1 HEAD -- CHANGELOG.md                     # Expected: ≥ 1 line (CHANGELOG entry added)
    ```

    ---

    **After all 5 commits, plan-close smoke verifications:**

    ```bash
    # 1. All 5 commits have D-19 trailers:
    git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: '   # Expected: 5

    # 2. Trailer field name lowercase 'a' (verbatim shape):
    git log --format='%B' HEAD~5..HEAD | grep -c 'Upstream-Author:'     # Expected: 0 (no uppercase A)
    git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-author: '   # Expected: 5

    # 3. Two Signed-off-by lines per commit (DCO + GitHub attribution):
    git log --format='%B' HEAD~5..HEAD | grep -c '^Signed-off-by: '     # Expected: 10

    # 4. learn_windows.rs anchor SHA UNCHANGED:
    git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs
    # MUST equal Task 1 baseline (D-34-B2 anchor)

    # 5. D-34-E1 invariant across the 5-commit chain:
    git diff --stat HEAD~5 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0

    # 6. Fork-version invariant:
    grep -E '^version = ' Cargo.toml | head -1   # Expected: equals Task 1 baseline

    # 7. Windows-cfg arm counts UNCHANGED on b34c2af6 surfaces:
    grep -c '#\[cfg(target_os = "windows")\]' crates/nono-cli/src/learn.rs   # Expected: equals Task 1 baseline_learn_winarms
    grep -c '#\[cfg(target_os = "windows")\]' crates/nono-cli/src/cli.rs     # Expected: equals Task 1 baseline_cli_winarms

    # 8. G-25-DRIFT-01 closure invariant preserved:
    grep -rE 'memory.*deprecat|cpu-percent.*deprecat|max-processes.*deprecat|timeout.*deprecat' crates/   # Expected: 0

    # 9. Fork-defense grep baselines preserved (each ≥ Task 1 baseline):
    grep -rE 'never_grant|apply_deny_overrides' crates/ | wc -l
    grep -rE 'validate_path_within' crates/ | wc -l
    grep -rE 'capabilities\.aipc|loaded_profile' crates/ | wc -l
    grep -rE 'find_denied_user_grants' crates/ | wc -l
    grep -rE 'bypass_protection' crates/ | wc -l

    # 10. Workspace builds clean:
    cargo build --workspace
    ```
  </action>
  <verify>
    <automated>test "$(git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: ')" = "5" &amp;&amp; test "$(git log --format='%B' HEAD~5..HEAD | grep -c '^Signed-off-by: ')" = "10" &amp;&amp; test "$(git diff --stat HEAD~5 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 5 commits on `main` with verbatim D-19 trailers (lowercase 'a' in `Upstream-author:`, 2× Signed-off-by per commit).
    - `git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: '` returns `5`.
    - Per-commit AND plan-close D-34-E1 invariant: 0 hits in `_windows` / `exec_strategy_windows` paths.
    - `learn_windows.rs` last-touched SHA EQUALS Task 1 baseline (D-34-B2 anchor preserved).
    - Per-commit `learn_windows.rs` diff returns 0 lines for every cherry-pick.
    - Windows-cfg arm counts in `learn.rs` and `cli.rs` EQUAL Task 1 baselines post-`b34c2af6` (no new Windows arms for deprecation surface).
    - `b34c2af6` commit body includes the verbatim D-34-B2 rationale paragraph (grep returns ≥1 hit for "D-34-B2").
    - Fork's `Cargo.toml` version field UNCHANGED post-`5d15b50e` (equals Task 1 baseline).
    - `5d15b50e` commit body includes the verbatim "fork tracks own version" rationale.
    - `5d15b50e` cherry-pick diff against `Cargo.toml` + `Cargo.lock` returns 0 lines (version bump reverted).
    - G-25-DRIFT-01 closure invariant grep returns 0 (no RESL flag rename surface introduced).
    - Fork-defense grep baselines preserved (5 counts each ≥ Task 1 baseline).
    - `cargo build --workspace` exits 0.
  </acceptance_criteria>
  <done>
    C12-non-env chain complete; D-34-B2 surgical posture verified; fork-version invariant preserved.
  </done>
</task>

<task type="auto">
  <name>Task 3: D-34-D2 close-gate + write SUMMARY</name>
  <files>
    .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-LEARN-DEPRECATION-SUMMARY.md
    .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md
  </files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D2 (8 close-gates)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-07-SUMMARY.md (or 34-03-SUMMARY.md) — analog SUMMARY shape
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md (if exists; P34-DEFER-* numbering scheme)
  </read_first>
  <action>
    Run all 8 D-34-D2 close-gates per user-accepted posture:

    **Gate 1: `cargo test --workspace --all-features` (Windows host)** — MUST PASS (carry-forward P34-DEFER-01-1 + AIPC-SDK env-leak flake acceptable).
    ```bash
    cargo test --workspace --all-features
    ```

    **Gate 2: `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host)** — MUST PASS.
    ```bash
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
    ```

    **Gate 3: Cross-target clippy Linux** — DEFERRED-TO-CI per user posture (record in SUMMARY).
    ```bash
    # Attempted on dev host; document any failures as deferred-to-CI:
    cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used 2>&1 | tail -20
    # If failures: record in SUMMARY § "Deferred-to-CI gates"; do NOT block plan close.
    ```

    **Gate 4: Cross-target clippy macOS** — DEFERRED-TO-CI per user posture (record in SUMMARY).
    ```bash
    cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used 2>&1 | tail -20
    # If failures: record in SUMMARY § "Deferred-to-CI gates"; do NOT block plan close.
    ```

    **Gate 5: `cargo fmt --all -- --check`** — MUST PASS.
    ```bash
    cargo fmt --all -- --check
    ```

    **Gate 6: Phase 15 5-row detached-console smoke** — ADMIN-SKIPPED on dev host; record skip rationale in SUMMARY.

    **Gate 7: `wfp_port_integration` test suite** — ADMIN-SKIPPED on dev host (requires admin/WFP service); record skip in SUMMARY.

    **Gate 8: `learn_windows_integration` test suite** — ADMIN-SKIPPED on dev host (requires Windows admin for ETW); record skip in SUMMARY. Special attention given D-34-B2 surgical posture: even though `learn_windows.rs` byte-identity is verified, the integration test gate is the ultimate sanity check that ETW path remained functional. Since admin-skipped, byte-identity assertion in Task 2 serves as the proxy guarantee.

    **Write SUMMARY.md** at `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-LEARN-DEPRECATION-SUMMARY.md` documenting:
    - Pre-state captures from Task 1 (learn_windows.rs SHA, Cargo.toml version, Windows-cfg counts, fork-defense baselines, G-25-DRIFT-01 invariant baseline).
    - Per-commit cherry-pick log (5 commits with their final SHAs on `main`, D-19 trailer presence, D-34-E1 invariant 0-hit confirmation, learn_windows.rs byte-identity 0-hit confirmation).
    - Special commit handling: `b34c2af6` D-34-B2 posture verification; `5d15b50e` fork-version-invariant release-commit handling.
    - Plan-close smoke results (10 verification items from Task 2 end).
    - D-34-D2 close-gate results (gates 1, 2, 5 PASS; gates 3, 4 deferred-to-CI; gates 6, 7, 8 admin-skipped — all with documented rationale).
    - Carry-forward flakes (P34-DEFER-01-1 + AIPC-SDK env-leak) acknowledged.
    - Any new deferred items recorded in `deferred-items.md` with P34-DEFER-08b-N numbering (e.g., P34-DEFER-08b-1 if interactive prompt smoke testing is deferred to manual).
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check &amp;&amp; test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-LEARN-DEPRECATION-SUMMARY.md</automated>
  </verify>
  <acceptance_criteria>
    - Gates 1, 2, 5 PASS (with P34-DEFER-01-1 + AIPC-SDK flake carry-forward documented).
    - Gates 3, 4 attempted; failures recorded as deferred-to-CI in SUMMARY (NOT blocking).
    - Gates 6, 7, 8 admin-skipped with rationale in SUMMARY.
    - SUMMARY.md exists at `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-LEARN-DEPRECATION-SUMMARY.md`.
    - All Task 1 baselines reproduced in SUMMARY (pre/post comparison table).
    - All Task 2 plan-close smoke results documented in SUMMARY.
    - Any new deferrals recorded in `deferred-items.md` with P34-DEFER-08b-N IDs.
  </acceptance_criteria>
  <done>
    Plan 34-08b close-gate cleared per D-34-D2 user-accepted posture. SUMMARY published.
  </done>
</task>

<task type="auto">
  <name>Task 4: Push to origin/main</name>
  <files>(git push only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D1 (direct-on-main; one PR per plan, but per archived 34-08 + sibling 34-08a coordination this plan pushes as part of the C12 cluster joint completion)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-LEARN-DEPRECATION-SUMMARY.md (just written)
  </read_first>
  <action>
    1. Verify local main is ahead of origin/main by exactly 5 commits (this plan's chain):
       ```bash
       git fetch origin
       git log origin/main..main --oneline | wc -l
       # Expected: 5 (the 5 cherry-picks from Task 2)
       # If sibling 34-08a closed earlier and already pushed, expect 5; if 34-08a NOT yet pushed, expect 5 + 34-08a's commits.
       ```

    2. Push:
       ```bash
       git push origin main
       ```

    3. (Optional, per D-34-D1) Open PR for this plan's 5 commits. Per archived 34-08 + 34-08a coordination, the planner may bundle this plan's PR with sibling 34-08a's PR into a single "Plan 34-08 (C12 split): env surface port + non-env cherry-picks" combined PR, OR open separate PRs. Default per D-34-D1 is one-PR-per-plan; bundling is acceptable if cluster traceability is preserved in the PR description.
       ```bash
       gh pr create --title "Plan 34-08b (C12-non-env): nono learn deprecation + macOS diagnostics + v0.52.0 release (5 commits)" --body "$(cat <<'EOF'
       ## Cluster C12-non-env (split from archived Plan 34-08)

       Sibling plan: 34-08a (env_sanitization surface port + 4 env-touching v0.52 commits).

       **Cherry-picks (5 commits, v0.52.0):**
       - 1d491b4d — feat(diagnostic): macOS learn diagnostics improvement
       - b5f0a3ab — fix(cli): interactive prompt improvements
       - b34c2af6 — feat(cli): deprecate nono learn subcommand (D-34-B2 surgical posture)
       - bbdf7b85 — fix: escaped quotes in profile JSON output
       - 5d15b50e — chore: release v0.52.0 (CHANGELOG only; fork tracks own version)

       **D-34-B2 invariant verified:** learn_windows.rs byte-identical pre/post plan.
       **D-34-E1 invariant verified:** 0 edits to *_windows.rs / exec_strategy_windows/.
       **Fork-version invariant verified:** Cargo.toml version unchanged through 5d15b50e.

       See SUMMARY: .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-LEARN-DEPRECATION-SUMMARY.md
       EOF
       )"
       ```
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - `git push origin main` exits 0.
    - `git log origin/main..main` returns empty (origin caught up).
    - (Optional) PR opened with cluster-traceable title and D-34-B2 / D-34-E1 / fork-version invariant attestations.
  </acceptance_criteria>
  <done>
    Plan 34-08b published. C12 cluster (jointly via 34-08a + 34-08b) closed. Wave 2 complete (jointly with parallel siblings).
  </done>
</task>

</tasks>

<non_goals>
**D-34-B2 surgical posture — `learn_windows.rs` byte-identical.** Per-commit diff against `learn_windows.rs` MUST be empty across all 5 commits. NO deprecation docstring addition to the fork-only ETW path. NO new `#[cfg(target_os = "windows")]` arms for the `b34c2af6` deprecation surface in `learn.rs` or `cli.rs`.

**No `env_sanitization.rs` touched.** All env-touching commits (`3657c935`, `780965d7`, `a022e5c7`, `31f2fc27`) belong to sibling Plan 34-08a. This plan's diff scope against `env_sanitization.rs` MUST be empty (or limited to incidental upstream-shape adjustments that don't change env_sanitization semantics — verify per-commit via `git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/exec_strategy/env_sanitization.rs`; expected ≈ 0 lines).

**No RESL flag rename.** G-25-DRIFT-01 was closed Plan 34-00 as no-divergence; Plan 34-08b must not introduce a rename. Plan-close grep returns 0.

**No `*_windows.rs` / `exec_strategy_windows/` touched.** D-34-E1 invariant — per-commit AND plan-close `git diff --stat` against these paths returns 0.

**No `learn` subcommand removal.** Deprecation message lands (`b34c2af6`); the subcommand still functions cross-platform. Removal is a future-phase decision.

**No upstream Cargo.toml / Cargo.lock version bump absorbed.** Fork tracks its own version (currently v2.3-track / v0.37.x). Release-commit `5d15b50e` lands CHANGELOG-only per 34-04b / 34-06 precedent.

**No interactive testing required.** `b5f0a3ab` prompt change relies on visual smoke; if not feasible on automated CI, deferred to manual testing post-plan (record as P34-DEFER-08b-N if needed).

**No PR-merge action by this plan.** This plan opens the PR (or bundles into a combined 34-08a + 34-08b PR); merging is per the phase's downstream PR-review workflow.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Cross-platform `cli.rs` / `learn.rs` deprecation surface ↔ fork-only `learn_windows.rs` ETW path | D-34-B2 invariant: ETW path is fork-only (Phase 11 wiring); upstream's deprecation message MUST flow only through the cross-platform surface. |
| Diagnostic structured-property parser (escaped quotes) → terminal output (`bbdf7b85`) | Untrusted profile JSON values pass through the serde renderer. |
| Fork Cargo.toml version field ↔ upstream `5d15b50e` release commit | Fork tracks its own version; absorbing upstream's 0.52.0 bump would conflate two version-tracking lineages. |
| macOS diagnostic-cfg arm (`1d491b4d`) ↔ fork's Windows diagnostic surface | macOS-cfg gate must remain intact; Windows diagnostic path must not inherit macOS-specific behavior accidentally. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-08b-01 | Tampering | D-34-B2 surgical-posture violation on `b34c2af6` — Windows-specific deprecation docstring added to `learn.rs` / `cli.rs`, OR `learn_windows.rs` edited by the cherry-pick | **high** | mitigate (BLOCKING) | Task 2 per-commit `learn_windows.rs` diff = 0 + per-commit Windows-cfg arm count equals Task 1 baseline (`baseline_learn_winarms`, `baseline_cli_winarms`). |
| T-34-08b-02 | Tampering | D-34-E1 Windows-only-files invariant violation — any of the 5 cherry-picks touches `*_windows.rs` or `exec_strategy_windows/` | **high** | mitigate (BLOCKING) | Per-commit `git diff --stat HEAD~1 HEAD -- crates/ \| grep -E '_windows\|exec_strategy_windows'` returns 0; plan-close 5-commit diff returns 0. |
| T-34-08b-03 | Repudiation | D-19 trailer-block missing or malformed (uppercase 'A' in `Upstream-Author:`, missing Co-Authored-By, missing 2nd Signed-off-by) | **high** | mitigate (BLOCKING) | Plan-close smokes: `grep -c '^Upstream-commit: ' = 5`; `grep -c '^Signed-off-by: ' = 10`; `grep -c 'Upstream-Author:' = 0` (uppercase forbidden). |
| T-34-08b-04 | Elevation of Privilege | Fork-version invariant violation on `5d15b50e` — `Cargo.toml` version field accidentally bumps to 0.52.0, conflating fork's version-tracking lineage with upstream's | **high** | mitigate (BLOCKING) | Task 2 commit 5 post-cherry-pick: explicit revert of Cargo.toml + Cargo.lock via `git checkout HEAD~1 -- Cargo.toml Cargo.lock`; post-verification `grep -E '^version = ' Cargo.toml` equals Task 1 baseline. |
| T-34-08b-05 | Tampering | macOS-cfg gate regression on `1d491b4d` — fork's Windows diagnostic path accidentally inherits macOS-only diagnostic behavior because cfg gate was widened during conflict resolution | medium | mitigate | Task 2 commit 1 post-cherry-pick: verify `#[cfg(target_os = "macos")]` count in `diagnostic.rs` ≥ pre-cherry-pick baseline AND verify `diagnostic.rs` diff is confined to macOS-cfg arms or cross-platform helpers. If gate widened, manually narrow back. |
| T-34-08b-06 | Information Disclosure | Escaped-quote parser regression on `bbdf7b85` — fix is incomplete or introduces a new escaping vector that allows profile JSON injection into structured terminal output | low | accept | Upstream's fix is reviewed-public; profile JSON path is operator-controlled (not adversary-supplied at runtime); standard nono CLI output redaction applies. Plan-close `cargo test -p nono-cli profile::tests::` serves as sentinel if profile-side escape tests exist. |
</threat_model>

<verification>
- All 5 commits cherry-picked in upstream chronological order with verbatim D-19 trailers (lowercase 'a' in `Upstream-author:`, 2× Signed-off-by).
- `git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: '` returns `5`.
- `git log --format='%B' HEAD~5..HEAD | grep -c '^Signed-off-by: '` returns `10`.
- `git log --format='%B' HEAD~5..HEAD | grep -c 'Upstream-Author:'` returns `0` (uppercase 'A' forbidden).
- Per-commit AND plan-close D-34-E1 invariant: 0 hits in `_windows` / `exec_strategy_windows` paths.
- Per-commit `learn_windows.rs` diff returns 0 lines for every cherry-pick.
- Plan-close `learn_windows.rs` last-touched SHA EQUALS Task 1 baseline (D-34-B2 anchor preserved).
- Windows-cfg arm counts in `learn.rs` and `cli.rs` EQUAL Task 1 baselines (no new Windows arms added for `b34c2af6` deprecation surface).
- `b34c2af6` commit body includes D-34-B2 rationale paragraph (grep returns ≥1 hit).
- Fork's `Cargo.toml` version field UNCHANGED post-`5d15b50e` (equals Task 1 baseline).
- `5d15b50e` commit body includes "fork tracks own version" rationale.
- `5d15b50e` diff against `Cargo.toml` + `Cargo.lock` returns 0 lines (version-bump reverted).
- G-25-DRIFT-01 closure invariant grep returns 0 (no RESL flag rename surface introduced).
- Fork-defense grep baselines preserved (5 counts each ≥ Task 1 baseline).
- D-34-D2 gates 1, 2, 5 PASS on dev host (with P34-DEFER-01-1 + AIPC-SDK flake carry-forward).
- D-34-D2 gates 3, 4 deferred-to-CI per user-accepted posture (recorded in SUMMARY).
- D-34-D2 gates 6, 7, 8 admin-skipped (recorded in SUMMARY).
- SUMMARY.md published at `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-LEARN-DEPRECATION-SUMMARY.md`.
- `origin/main` advanced; PR opened (or bundled with 34-08a per planner discretion).
</verification>

<success_criteria>
- 5 atomic commits on `main`, each with verbatim D-19 trailer block.
- macOS learn diagnostics enhanced (`1d491b4d`); interactive prompt improved (`b5f0a3ab`); `nono learn` deprecation message landed cross-platform (`b34c2af6`); escaped-quotes profile JSON fix landed (`bbdf7b85`); v0.52.0 CHANGELOG entry absorbed (`5d15b50e`).
- D-34-B2 surgical posture verified: `learn_windows.rs` byte-identical; no Windows-specific deprecation docstring; no new Windows-cfg arms for the deprecation surface.
- Fork-version invariant preserved: Cargo.toml version field unchanged through `5d15b50e`.
- D-34-E1 invariant: 0 edits to `*_windows.rs` / `exec_strategy_windows/` across all 5 commits.
- G-25-DRIFT-01 closure invariant preserved: 0 RESL flag rename surface.
- Fork-defense grep baselines preserved.
- D-34-D2 close-gates 1, 2, 5 PASS; 3, 4 deferred-to-CI; 6, 7, 8 admin-skipped — all documented.
- SUMMARY.md published.
- `origin/main` advanced; PR opened (or bundled with sibling 34-08a).
- C12 cluster (jointly via 34-08a + 34-08b) closed; Wave 2 complete (jointly with parallel siblings).
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-LEARN-DEPRECATION-SUMMARY.md`.
</output>
