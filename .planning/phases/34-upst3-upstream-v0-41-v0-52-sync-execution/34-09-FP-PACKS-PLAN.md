---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-09
plan: 09
slug: fp-packs
cluster_id: C6
type: execute
wave: 3
depends_on: ["34-04"]
blocks: ["34-10"]
files_modified:
  - crates/nono-cli/src/package_cmd.rs
  - crates/nono-cli/src/package.rs
  - crates/nono-cli/src/hooks.rs
  - crates/nono-cli/data/policy.json
upstream_tag_range: v0.44.0
upstream_commit_count: 6
disposition: fork-preserve-manual-replay
autonomous: false
requirements: [C6]
tags: [upst3, c6, packs, fork-preserve, manual-replay, d-20, wave-3]

must_haves:
  truths:
    - "All 6 cluster-C6 upstream commits (24d8b924, d05672d5, bdf183e9, a05fdc57, f1243c75, 5654b0f9) READ in full and EXPLICITLY dispositioned in Task 2: each gets either (A) straight cherry-pick (only if it touches zero fork-divergent surface), (B) manual replay with replay-intent commit body, or (C) skip with documented rationale. Verified by Task 2 producing a written disposition decision per SHA recorded in /tmp/c6-dispositions.txt."
    - "Phase 18.1-03 Windows widening wiring in `crates/nono-cli/src/package_cmd.rs` is BYTE-IDENTICAL on the Windows arms after plan close. Pre/post-plan diff against the `cfg(target_os = \"windows\")` arms (lines 1177, 1255, 1285 at plan start) shows ZERO deletions: `git diff <pre-plan-sha>..HEAD -- crates/nono-cli/src/package_cmd.rs | grep -E '^-' | grep -E 'cfg\\(windows\\)|cfg\\(target_os = .windows.\\)|_windows' | wc -l` returns 0."
    - "`validate_path_within` call site count in `crates/nono-cli/src/package_cmd.rs` is >= pre-plan baseline (9 callsites confirmed at plan start). Verified: `grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs` returns >= 9 at plan close. Phase 22-03 PKG-04 + Phase 26-01 PKGS-02 defense-in-depth retention preserved verbatim."
    - "`crates/nono-cli/src/hooks.rs` retained as the fork's centralized hook-installation surface. Upstream C6 commit `5654b0f9 feat(claude): prompt to remove old builtin hooks` may delete or restructure `hooks.rs` references; per upstream-sync-quick.md catalog 'Hooks subsystem ownership', the fork keeps `hooks.rs` as the sole hook-installation surface. Verified: `git diff <pre-plan-sha>..HEAD -- crates/nono-cli/src/hooks.rs | grep -c '^-fn '` returns 0 (no function-level deletions) AND `grep -c 'fn install\\|fn uninstall' crates/nono-cli/src/hooks.rs` returns the same value as pre-plan baseline."
    - "Every Plan 34-09 commit body carries EITHER (a) the verbatim D-19 6-line trailer block for cherry-picked commits, OR (b) a `Manual-replay: <upstream-sha>` body documenting what was replayed and why straight cherry-pick was infeasible (plus 2x `Signed-off-by:` DCO lines for replay-intent commits). Smoke check at plan close: `git log --format='%B' HEAD~N..HEAD | grep -cE '^Upstream-commit: |^Manual-replay: '` equals the plan's total commit count N minus 1 (the summary commit carries neither); `grep -c 'Upstream-Author:'` equals 0 (case-sensitivity invariant)."
    - "Plan 34-09's final commit (the summary commit) appends a `Manual-replay summary` section to the commit chain documenting exactly: (i) which upstream commits were replayed, (ii) which were straight-cherry-picked, (iii) which were skipped, and (iv) for each, what fork-only Windows wiring was preserved. Verified: `git log -1 --format='%B' HEAD | grep -c 'Manual-replay summary'` returns 1."
    - "D-34-E1 invariant per commit: `git diff --stat <prev>..<this> -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns 0 for EVERY commit in the Plan 34-09 chain. No edits to `*_windows.rs` files or the `exec_strategy_windows/` subtree."
    - "Registry-pack format awareness (intent of upstream `24d8b924`) replayed on the fork: `ArtifactType::Plugin` round-trips correctly after this plan (Phase 26 PKGS-02 preservation); pack manifest parsing accepts the upstream registry-pack shape WITHOUT deleting the fork's claude-code Phase 18.1-03 widening codepath. Verified: `cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips` exits 0."
    - "Install/uninstall hardening (intent of upstream `d05672d5` and `bdf183e9`) replayed where it composes with the fork's Windows install_dir + hooks.rs path; replay does NOT silently strip fork's `validate_path_within` defense-in-depth call sites."
    - "All 8 D-34-D2 close-gates pass on the Windows host (or are documented-skip with rationale for Gates 6-8)."
    - "Plan 34-09 commits pushed to origin/main at plan close; `git log origin/main..main --oneline | wc -l` returns 0."
  artifacts:
    - path: "crates/nono-cli/src/package_cmd.rs"
      provides: "Registry-pack format replay (intent of 24d8b924); install/uninstall hardening replay (intent of d05672d5 + bdf183e9); fork's Phase 18.1-03 Windows widening wiring + `validate_path_within` defense-in-depth + cfg(target_os = \"windows\") arms PRESERVED VERBATIM"
      grep_pattern: "validate_path_within|cfg\\(windows\\)|cfg\\(target_os = .windows.\\)"
      grep_negative: "// removed validate_path_within|// fork wiring removed"
      min_call_sites: 9
    - path: "crates/nono-cli/src/package.rs"
      provides: "ArtifactType enum + serde shape preserved; Phase 26 PKGS-02 `Plugin` variant + `#[serde(rename_all = \"snake_case\")]` round-trips against any new registry-pack format introduced by the replay"
      grep_pattern: "ArtifactType::Plugin|rename_all = .snake_case."
    - path: "crates/nono-cli/src/hooks.rs"
      provides: "Centralized hook installation surface retained (upstream-sync-quick.md catalog 'Hooks subsystem ownership'). The fork rejects upstream's `claude-code integration package` removal pattern; `hooks.rs` remains the sole hook-installation surface."
      grep_pattern: "fn install|fn uninstall|fn register"
      grep_negative: "// hooks moved to package manager|// see package_cmd::install_hooks"
    - path: "crates/nono-cli/data/policy.json"
      provides: "Builtin profile entries for claude-code / codex preserved on Windows (Phase 18.1-03 wiring depends on these existing in the embedded data); upstream `24d8b924` migrates them to registry-pack format - the replay decision documents whether the fork keeps both shapes (builtin + pack) or accepts the pack-only shape with a Windows-side compatibility shim."
      grep_pattern: "claude-code|codex"
  key_links:
    - from: "Cluster C6 disposition row in DIVERGENCE-LEDGER.md (Phase 33 ledger)"
      to: "Plan 34-09 commit chain (manual-replay shape per D-20)"
      via: "per-commit disposition pass + replay-intent execute pass + summary commit"
      pattern: "Upstream-commit: (24d8b924|d05672d5|bdf183e9|a05fdc57|f1243c75|5654b0f9)|Manual-replay: (24d8b924|d05672d5|bdf183e9|a05fdc57|f1243c75|5654b0f9)"
    - from: "Fork's Phase 18.1-03 Windows widening wiring (v2.1 G-06 profile widening end-to-end -> AipcResolvedAllowlist via Windows SupervisorConfig field)"
      to: "Upstream's v0.44.0 pack migration shape"
      via: "manual replay preserves fork wiring; pack-format awareness layered onto the existing fork code path"
      pattern: "cfg\\(target_os = .windows.\\)|cfg\\(windows\\)"
    - from: "Fork's `validate_path_within` defense-in-depth retention (Phase 22-03 PKG-04 + Phase 26-01 PKGS-02)"
      to: "Upstream C6 commits `d05672d5` + `bdf183e9` (install/uninstall hardening)"
      via: "compose as defense-in-depth; never remove fork's call sites; layer upstream's hardening BEFORE or AFTER fork's validation, not INSTEAD OF"
      pattern: "validate_path_within"
    - from: "Fork's `crates/nono-cli/src/hooks.rs` centralized hook-installation surface (Phase 22-03 PKG-03)"
      to: "Upstream `5654b0f9 feat(claude): prompt to remove old builtin hooks`"
      via: "replay the user-prompt behavior; preserve `hooks.rs` as the install entrypoint; do NOT accept upstream's deletion of fork-side hook wiring"
      pattern: "fn install|fn uninstall"
    - from: "Plan 34-04 close (Wave 0 gate - post-C7 canonical JSON schema state)"
      to: "Plan 34-09 (registry-pack format replay rebases on post-C7 schema)"
      via: "C7 establishes canonical JSON profile schema; C6 pack format builds on it"
      pattern: "depends_on.*34-04"
---

<objective>
Land cluster C6 (upstream v0.44.0, 6 commits) into the fork via **D-20 manual replay** - the fork-preserve disposition selected by Phase 33's DIVERGENCE-LEDGER.md row + D-34-B1. Straight `git cherry-pick` would delete the fork's Phase 18.1-03 Windows widening wiring in `crates/nono-cli/src/package_cmd.rs`, the fork's centralized `crates/nono-cli/src/hooks.rs` hook-installation surface, and the `validate_path_within` defense-in-depth call sites retained from Phase 22-03 PKG-04 + Phase 26-01 PKGS-02.

The 6 C6 commits (in upstream topological order per `git log --topo-order --reverse v0.43.1..v0.44.0`):

| Order | SHA | Tag | Subject | Files | Default disposition |
|-------|-----|-----|---------|-------|---------------------|
| 1 | `24d8b924` | v0.44.0 | feat(profile, migration): move codex, claude-code to registry pack | 17 | **manual replay** (replays registry-pack format awareness; preserves fork's builtin claude-code wiring on Windows) |
| 2 | `d05672d5` | v0.44.0 | fix(wiring): harden install and uninstall wiring | 4 | **manual replay** (replays hardening intent; preserves `hooks.rs` + `validate_path_within` callsites) |
| 3 | `bdf183e9` | v0.44.0 | fix(package): harden re-pulls against user edits | 4 | **manual replay** (replays re-pull-hardening intent against fork's package_cmd path) |
| 4 | `a05fdc57` | v0.44.0 | refactor(wiring): simplify string expansion | 1 | **straight cherry-pick** if non-divergent; **manual replay** if it touches fork-only surface - Task 2 decides per-commit |
| 5 | `f1243c75` | v0.44.0 | chore(ci): improve ci stability and profile test coverage | 3 | **straight cherry-pick** if CI-only; verify no fork CI divergence first |
| 6 | `5654b0f9` | v0.44.0 | feat(claude): prompt to remove old builtin hooks | 5 | **manual replay** (replay the user-prompt UX; explicitly preserve `hooks.rs` per upstream-sync-quick.md catalog 'Hooks subsystem ownership') |

All 6 commits were authored by Luke Hinds <lukehinds@gmail.com>.

**Manual-replay intent (D-34-B1 verbatim):** "Read upstream `24d8b92` + harden-install commits + replay the *intent* (registry-pack format awareness, install/uninstall hardening) while preserving v2.1 Phase 18.1-03 widening wiring on Windows."

**Why this plan is NOT autonomous:** D-20 manual replay requires per-commit human decision on what to port vs. preserve. Task 2 is an explicit `checkpoint:decision` gate where the user approves the per-commit disposition table before per-commit execute tasks begin. This is one of only two non-autonomous plans in Phase 34 (the other is 34-10 proxy-TLS).

Purpose: A Windows user who has `claude-code` profile installed via the v2.1 Phase 18.1-03 wiring continues to launch sandboxes after Plan 34-09 lands, with no regression in `%LOCALAPPDATA%\nono\packages` resolution, no removal of `validate_path_within` defense-in-depth, and no loss of `hooks.rs` as the centralized hook installer. The fork ALSO gains registry-pack format awareness (so a future Plan 34-10 + post-Phase-34 work that consumes upstream's pack format can rely on it being present) and the install/uninstall hardening intent (cross-platform re-pull resilience, idempotent uninstall).

Output: 6-7 commits on `main` (one per upstream C6 SHA dispositioned + one final `Manual-replay summary` commit), each carrying either D-19 trailer (cherry-picks) or `Manual-replay:` body (replay-intent commits). Files in `crates/nono-cli/src/{package_cmd.rs,package.rs,hooks.rs}` and `crates/nono-cli/data/policy.json` evolved to absorb C6 intent without deleting fork-only Windows wiring. Zero edits to `*_windows.rs` files (D-34-E1). All 8 D-34-D2 close-gates green.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-03-PKG-SUMMARY.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-PATTERNS.md
@.planning/phases/26-pkg-streaming-followup/26-01-SUMMARY.md
@.planning/templates/upstream-sync-quick.md
@crates/nono-cli/src/package_cmd.rs
@crates/nono-cli/src/package.rs
@crates/nono-cli/src/hooks.rs

<interfaces>
**Cluster C6 commit chain (6 commits, upstream topological order verified at plan-write time):**

| Order | SHA (8-char) | Subject (verbatim) | Author | Tag | Disposition |
|-------|--------------|---------------------|--------|-----|-------------|
| 1 | `24d8b924` | feat(profile, migration): move codex, claude-code to registry pack | Luke Hinds <lukehinds@gmail.com> | v0.44.0 | manual replay - touches Phase 18.1-03 Windows widening surface |
| 2 | `d05672d5` | fix(wiring): harden install and uninstall wiring | Luke Hinds <lukehinds@gmail.com> | v0.44.0 | manual replay - touches `hooks.rs` + `validate_path_within` callsite surface |
| 3 | `bdf183e9` | fix(package): harden re-pulls against user edits | Luke Hinds <lukehinds@gmail.com> | v0.44.0 | manual replay - touches `package_cmd.rs` install path |
| 4 | `a05fdc57` | refactor(wiring): simplify string expansion | Luke Hinds <lukehinds@gmail.com> | v0.44.0 | Task 2 decides - likely straight cherry-pick (1-file refactor; verify non-divergent) |
| 5 | `f1243c75` | chore(ci): improve ci stability and profile test coverage | Luke Hinds <lukehinds@gmail.com> | v0.44.0 | Task 2 decides - likely straight cherry-pick (CI/test-only) |
| 6 | `5654b0f9` | feat(claude): prompt to remove old builtin hooks | Luke Hinds <lukehinds@gmail.com> | v0.44.0 | manual replay - explicitly preserve `hooks.rs` ownership per upstream-sync-quick.md catalog |

**D-19 trailer block (verbatim, for the straight-cherry-pick subset of commits):**

```
Upstream-commit: {sha_abbrev_8char}
Upstream-tag: v0.44.0
Upstream-author: Luke Hinds <lukehinds@gmail.com>
Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

Field rules (per `.planning/templates/upstream-sync-quick.md` D-19 cherry-pick trailer block):
- Lowercase 'a' in `Upstream-author:` (NOT `Upstream-Author:`).
- 8-character SHA abbrev in `Upstream-commit:`.
- `Upstream-author:` and `Co-Authored-By:` carry the SAME `name <email>`.
- Two `Signed-off-by:` lines (DCO + GitHub attribution).
- Trailer block separated from body by EXACTLY ONE blank line.

**Manual-replay trailer block (for the replay-intent subset of commits):**

```
{free-form prose body documenting what was replayed and why straight cherry-pick was infeasible}

Manual-replay: {sha_abbrev_8char}
Upstream-tag: v0.44.0
Upstream-author: Luke Hinds <lukehinds@gmail.com>
Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

The `Manual-replay:` field substitutes for `Upstream-commit:` - semantic: "this commit replays the INTENT of upstream's commit but the form differs because of fork divergence." Same lowercase 'a' / two-DCO-lines convention. Mirror Phase 26-01 PKGS-02 commit-body style for the prose body.

**Fork-divergence surface that drives the fork-preserve disposition (read upstream-sync-quick.md Fork-divergence catalog before resolving any conflict):**

1. **Phase 18.1-03 Windows widening wiring in `crates/nono-cli/src/package_cmd.rs`** - G-06 profile widening end-to-end -> AipcResolvedAllowlist via Windows SupervisorConfig field. The fork's `cfg(target_os = "windows")` arms at lines ~1177, ~1255, ~1285 (verified at plan-write time) carry Windows-specific install_dir resolution + long-path handling. Upstream's `24d8b924` and `d05672d5` would rewrite the package wiring assuming this Windows code path does NOT exist (D-19 invariant - no library mutation by upstream).
2. **`validate_path_within` defense-in-depth at 9 callsites in `crates/nono-cli/src/package_cmd.rs`** - Phase 22-03 PKG-04 + Phase 26-01 PKGS-02 retention. Upstream's hardening commits (`d05672d5`, `bdf183e9`) may rewrite the install path; the fork's `validate_path_within` callsites MUST be preserved. Annotate each retained site: `// Defense-in-depth (fork divergence: see Phase 22-03 PKG-04 + Phase 26-01 PKGS-02). Do not remove without security review.`
3. **`crates/nono-cli/src/hooks.rs` centralized hook-installation surface** - Phase 22-03 PKG-03 wiring routes through it. Upstream `5654b0f9` adds a user prompt that ultimately wants hook bundles to live in package-manager territory; the fork keeps `hooks.rs` as the sole hook-installation surface. Action on replay: implement the user-prompt UX in the fork's existing `hooks.rs` install flow (do not silently accept removal).
4. **`crates/nono-cli/data/policy.json` builtin entries (claude-code, codex)** - fork's Phase 18.1-03 wiring depends on these being present in the embedded data. Upstream `24d8b924` migrates them to registry-pack format. Replay decision: keep the builtin entries on Windows (Phase 18.1-03 dependency) AND add pack-format awareness in `package.rs` so Plan 34-10+ work can consume packs cleanly. Document the dual-shape decision in the replay commit body.

**Phase 26-01 PKGS-02 precedent (most recent D-20 manual-replay in fork):**

Phase 26-01 PKGS-02 added `ArtifactType::Plugin` as the 7th `ArtifactType` enum variant (`crates/nono-cli/src/package.rs:87`) and ported upstream's `validate_relative_path` as input-string defense-in-depth alongside fork's existing `validate_path_within`. Plan 34-09 inherits both: any registry-pack format introduced by the manual replay must round-trip `ArtifactType::Plugin` (`#[serde(rename_all = "snake_case")]` -> `"plugin"`) and must NOT delete the `validate_relative_path` + `validate_path_within` dual-layer.

**Per-commit STRAIGHT-CHERRY-PICK template** (only for the subset of commits Task 2 dispositions as cherry-pick-safe):

```
git cherry-pick <sha>
# D-02 fallback gate: if conflicts > 50 lines OR > 2 files, abort -> D-20 manual replay
cargo build --workspace
git commit --amend -m "$(cat <<'EOF'
<original upstream subject - copy verbatim from git log -1 <sha> --format='%s'>

<original upstream body if present - copy verbatim from git log -1 <sha> --format='%b'>

Upstream-commit: <8-char sha>
Upstream-tag: v0.44.0
Upstream-author: Luke Hinds <lukehinds@gmail.com>
Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
EOF
)"
# D-34-E1 invariant verify:
git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
# Fork-divergence sentinel:
grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs   # Expected: >= 9 (baseline)
```

**Per-commit MANUAL-REPLAY template** (for the subset Task 2 dispositions as fork-preserve):

```
# Step 1: Read upstream's diff in full
git show <sha>
git show <sha> -- crates/nono-cli/src/   # production-code diff
# Step 2: Identify the INTENT (registry-pack awareness, hardening, user-prompt UX) vs. the FORM (specific file edits)
# Step 3: Apply the INTENT by hand against fork's current state - do NOT delete fork-only wiring
#         (Windows cfg arms, validate_path_within callsites, hooks.rs centralization, policy.json builtins)
# Step 4: Build + targeted test
cargo build --workspace
cargo test -p nono-cli package::tests::
# Step 5: Stage + commit with Manual-replay body
git add -A
git commit -m "$(cat <<'EOF'
<replay subject, e.g., "replay(C6): registry-pack format awareness from upstream 24d8b924">

<prose body documenting:
 (1) what the upstream commit did,
 (2) which fork-only surface a straight cherry-pick would have deleted,
 (3) what intent the fork now carries from the replay,
 (4) what was NOT replayed (and why)>

Manual-replay: <8-char upstream sha>
Upstream-tag: v0.44.0
Upstream-author: Luke Hinds <lukehinds@gmail.com>
Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
EOF
)"
# D-34-E1 invariant verify (mandatory after EVERY commit in the chain):
git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
# Fork-divergence sentinels (mandatory after EVERY commit):
grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs   # Expected: >= 9 (baseline)
grep -c 'fn install\|fn uninstall' crates/nono-cli/src/hooks.rs     # Expected: >= pre-plan baseline
```

NOTE on DCO sign-off: do NOT use `git commit -s` to add Signed-off-by - it produces only ONE line. Use the explicit HEREDOC body to write BOTH `Signed-off-by:` lines (DCO + GitHub attribution) as required by Phase 22 D-19.

**Pattern map analogs:**
- Pack format awareness without deleting builtin policy.json entries: fork's `nono-cli/data/policy.json` is embedded at build time via `build.rs`; the fork can carry BOTH builtin entries AND registry-pack awareness (the policy resolver in `crates/nono-cli/src/policy.rs` already handles "builtin" + "registry" lookup paths post-Phase 22-01 + Phase 26-01).
- Hook user-prompt UX without removing hooks.rs: fork's `hooks.rs` already exposes install/uninstall public API; the replay layers the user-prompt at the entry point (where the user invokes `nono package install claude-code`) without changing the underlying installer.
- Install/uninstall hardening without removing `validate_path_within`: upstream's hardening (`d05672d5`) tightens upstream's path validation, which is `Path::canonicalize + starts_with` (CLAUDE.md Common Footguns #1 - the well-known string-prefix-on-path footgun). Fork's `validate_path_within` is the CORRECT primitive on Windows (UNC, `\\?\`, drive-letter paths); the replay layers upstream's hardening BEFORE or AFTER the fork's call site, never INSTEAD OF.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Read source artifacts + capture pre-Plan-34-09 baseline</name>
  <files>(no files modified - read + measurement only)</files>
  <read_first>
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md cluster C6 row (the 6-commit table)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md D-34-B1 (manual-replay intent for C6) + D-34-D2 (8 close-gates) + D-34-E1..E5 (invariants)
    - .planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-03-PKG-SUMMARY.md (Phase 22-03 PKG-04 validate_path_within retention rationale + Windows %LOCALAPPDATA% wiring)
    - .planning/phases/26-pkg-streaming-followup/26-01-SUMMARY.md (most recent D-20 manual-replay precedent; commit-body style for replay-intent commits)
    - .planning/templates/upstream-sync-quick.md Fork-divergence catalog (the FULL catalog - every entry applies; validate_path_within and hooks.rs entries are load-bearing for C6) + D-19 cherry-pick trailer block (verbatim 6-line shape)
    - crates/nono-cli/src/package_cmd.rs (read at least the regions around lines 1177, 1255, 1285 - the cfg(windows) arms - and all 9 validate_path_within callsites)
    - crates/nono-cli/src/package.rs (read ArtifactType enum definition at ~line 87; verify the Phase 26 Plugin variant is present)
    - crates/nono-cli/src/hooks.rs (read full file - the centralized installer surface that upstream 5654b0f9 would restructure)
    - crates/nono-cli/data/policy.json claude-code + codex entries (the builtin entries upstream 24d8b924 migrates to packs)
  </read_first>
  <action>
    1. Fetch upstream + tags (idempotent):
       `git fetch upstream --tags`

    2. Confirm cluster C6 boundaries against the live upstream HEAD:
       ```
       git tag --list 'v0.44*'   # Expected: v0.44.0 (and possibly v0.44.1 if upstream advanced post-audit)
       for sha in 24d8b924 d05672d5 bdf183e9 a05fdc57 f1243c75 5654b0f9; do
         git cat-file -e ${sha}^{commit} && echo "OK: $sha" || echo "MISSING: $sha"
       done
       # Expected: 6 OK lines, 0 MISSING. If MISSING: STOP + return PLAN BLOCKED.
       ```

    3. Read each C6 commit's subject + author + body for the disposition pass (Task 2 will use these):
       ```
       for sha in 24d8b924 d05672d5 bdf183e9 a05fdc57 f1243c75 5654b0f9; do
         echo "==== $sha ===="
         git log -1 $sha --format='SHA: %H%nAUTHOR: %an <%ae>%nSUBJECT: %s%n%nBODY:%n%b'
         echo "---- stat ----"
         git show --stat $sha | head -50
       done > /tmp/c6-commit-bodies.txt
       wc -l /tmp/c6-commit-bodies.txt
       ```

    4. Capture pre-Plan-34-09 baseline (record ALL six numbers in SUMMARY under "Pre-Plan-34-09 baseline"):
       ```
       git log -1 --format='%H %s' main > /tmp/c6-baseline-head.txt
       cat /tmp/c6-baseline-head.txt

       grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs                                # expected baseline: 9
       grep -cE 'cfg\(windows\)|cfg\(target_os = .windows.\)' crates/nono-cli/src/package_cmd.rs      # expected baseline: >= 1
       grep -c '^pub fn \|^fn ' crates/nono-cli/src/hooks.rs                                          # fork-only hook installer fn count
       grep -c 'ArtifactType::Plugin\|    Plugin,' crates/nono-cli/src/package.rs                     # expected baseline: >= 1 (Phase 26 PKGS-02)
       grep -cE 'claude-code|codex' crates/nono-cli/data/policy.json                                  # expected baseline: >= 2 (Phase 18.1-03)

       git status --porcelain | wc -l   # Expected: 0
       ```

    5. Confirm baseline build is green BEFORE starting:
       `cargo build --workspace`
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; for sha in 24d8b924 d05672d5 bdf183e9 a05fdc57 f1243c75 5654b0f9; do git cat-file -e ${sha}^{commit} || exit 1; done &amp;&amp; test "$(grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs)" -ge 9 &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - All 6 C6 SHAs reachable on the upstream remote (`git cat-file -e ${sha}^{commit}` exits 0 for each).
    - /tmp/c6-commit-bodies.txt exists with non-zero line count.
    - `grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs` returns >= 9 (baseline).
    - `grep -cE 'cfg\(windows\)|cfg\(target_os = .windows.\)' crates/nono-cli/src/package_cmd.rs` returns >= 1 (Phase 18.1-03 Windows wiring present).
    - SUMMARY records the pre-Plan-34-09 HEAD SHA + the six baseline numbers above.
    - `git status` reports working tree clean.
    - `cargo build --workspace` exits 0 (baseline green).
  </acceptance_criteria>
  <done>
    Baseline captured; C6 cluster verified against upstream; disposition pass ready.
  </done>
</task>

<task type="checkpoint:decision" gate="blocking">
  <name>Task 2: Per-commit disposition pass - decide cherry-pick vs. manual replay vs. skip for each of the 6 C6 commits</name>
  <decision>For each of the 6 C6 commits, choose disposition: (A) straight cherry-pick, (B) manual replay (D-20), or (C) skip with rationale.</decision>
  <context>
    D-34-B1 locks the cluster-level disposition as `fork-preserve` (manual replay), but per-commit decisions still need explicit choice + rationale because not every commit in the cluster touches fork-divergent surface. Commits that touch ONLY upstream-side files (e.g., a CI-config tweak) MAY be cherry-pick-safe; commits that touch `package_cmd.rs`, `hooks.rs`, or `policy.json` MUST be manual-replayed.

    Read /tmp/c6-commit-bodies.txt (produced in Task 1) and `git show <sha> --stat` for each commit. Apply the disposition criteria:

    **Disposition criteria (apply in order):**
    1. Does the commit touch `crates/nono-cli/src/package_cmd.rs`, `crates/nono-cli/src/hooks.rs`, `crates/nono-cli/data/policy.json`, or any Phase 18.1-03 wiring file? -> **manual replay (B)**.
    2. Does the commit only touch upstream-side files with no fork analog (e.g., a CI config the fork doesn't run, a docs file the fork doesn't ship)? -> **skip with rationale (C)**.
    3. Does the commit touch files where fork has zero divergence (a clean refactor in a file the fork hasn't modified)? -> **straight cherry-pick (A)** - but ONLY if the cherry-pick is genuinely free of fork-divergent edits.
    4. Default (when ambiguous): **manual replay (B)** - safer to read the intent and re-apply than to risk silent deletion.
  </context>
  <options>
    <option id="default-dispositions">
      <name>Default per-commit dispositions (recommended starting point)</name>
      <table>
| # | SHA | Subject | Default disposition | Rationale |
|---|-----|---------|---------------------|-----------|
| 1 | `24d8b924` | feat(profile, migration): move codex, claude-code to registry pack | manual replay | 17-file diff touching data/policy.json builtins + package_cmd.rs install path; Phase 18.1-03 Windows wiring at risk |
| 2 | `d05672d5` | fix(wiring): harden install and uninstall wiring | manual replay | 4-file diff touching hooks.rs + package_cmd.rs; validate_path_within callsites at risk |
| 3 | `bdf183e9` | fix(package): harden re-pulls against user edits | manual replay | 4-file diff touching package_cmd.rs install path; re-pull hardening interacts with fork's Windows install_dir |
| 4 | `a05fdc57` | refactor(wiring): simplify string expansion | TBD - read diff first | 1-file refactor; cherry-pick-safe IF file untouched on fork side |
| 5 | `f1243c75` | chore(ci): improve ci stability and profile test coverage | TBD - read diff first | 3-file CI/test change; cherry-pick-safe IF fork's CI matches upstream's shape |
| 6 | `5654b0f9` | feat(claude): prompt to remove old builtin hooks | manual replay | 5-file diff structurally wants to delete hooks.rs; explicit catalog item |
      </table>
      <pros>Conservative; preserves fork-only Windows wiring by default; aligns with D-34-B1 cluster-level "fork-preserve" intent.</pros>
      <cons>More work than necessary if commits 4-5 turn out to be cherry-pick-safe.</cons>
    </option>
    <option id="aggressive-cherry-pick">
      <name>Aggressive cherry-pick (only commits 1 + 6 are manual-replay)</name>
      <table>Manual-replay: 24d8b924 (17-file migration), 5654b0f9 (prompt to remove hooks). Cherry-pick: d05672d5, bdf183e9, a05fdc57, f1243c75.</table>
      <pros>Less work; fewer manual-replay commit bodies to write.</pros>
      <cons>HIGH risk that d05672d5 (install/uninstall hardening) or bdf183e9 (re-pull hardening) will silently delete validate_path_within callsites; D-34-B1 spirit is "preserve fork-only wiring" - this option erodes the safety margin.</cons>
    </option>
    <option id="full-replay">
      <name>Full manual-replay (all 6 commits are replay-intent)</name>
      <pros>Maximum safety; every fork-divergence-catalog entry gets explicit human review before any code change.</pros>
      <cons>Most work; commits 4-5 may not need it.</cons>
    </option>
  </options>
  <action>
    For each of the 6 C6 commits, the executor:

    1. Reads `git show <sha> --stat` and `git show <sha> -- crates/ data/` (production + data diff).
    2. Cross-references with the disposition criteria above.
    3. Records the chosen disposition in /tmp/c6-dispositions.txt (one line per commit: `<sha> <disposition> <rationale-tag>`).
    4. For each commit dispositioned as cherry-pick: notes the expected D-19 trailer subject + author.
    5. For each commit dispositioned as manual-replay: notes the INTENT (what is being replayed) + the FORK-ONLY SURFACE that would be deleted by a straight cherry-pick.
    6. For each commit dispositioned as skip: notes the rationale + cites the upstream-sync-quick.md catalog entry justifying the skip.

    Pause for user review of the disposition table BEFORE proceeding to Tasks 3-7 (per-commit execute tasks).
  </action>
  <resume-signal>Type "approved: <disposition-id>" where disposition-id is `default-dispositions`, `aggressive-cherry-pick`, `full-replay`, or `custom: <inline table>`. Replay-intent commits proceed to the manual-replay execute path; cherry-pick commits proceed to the straight-cherry-pick path.</resume-signal>
  <acceptance_criteria>
    - Every one of the 6 C6 SHAs has a recorded disposition in /tmp/c6-dispositions.txt.
    - For each manual-replay commit: the file records (a) the upstream intent, (b) the fork-only surface that would be deleted by straight cherry-pick, (c) the planned replay shape.
    - For each cherry-pick commit: the file records (a) the upstream subject verbatim, (b) the upstream author + email, (c) the expected files-modified set.
    - For each skip: the file records the rationale + the catalog entry justifying the skip.
    - User has approved the disposition table.
  </acceptance_criteria>
  <done>
    Disposition pass complete; per-commit execute tasks (3-6) ready to run with explicit guidance per commit.
  </done>
</task>

<task type="auto">
  <name>Task 3: Replay commit 1/6 - `24d8b924` registry-pack format awareness (manual replay)</name>
  <files>
    crates/nono-cli/src/package.rs
    crates/nono-cli/src/package_cmd.rs
    crates/nono-cli/data/policy.json
  </files>
  <read_first>
    - `git show 24d8b924 --stat` (17-file diff; large surface)
    - `git show 24d8b924 -- crates/nono-cli/src/package.rs` (the registry-pack format additions to the type definitions)
    - `git show 24d8b924 -- crates/nono-cli/data/` (the builtin -> pack migration; what policy.json loses on upstream)
    - crates/nono-cli/src/package.rs (current ArtifactType enum + any pack-related types)
    - crates/nono-cli/data/policy.json claude-code + codex entries (the Phase 18.1-03 wiring dependency)
    - .planning/templates/upstream-sync-quick.md Fork-divergence catalog entries "Deferred enum variants" + "Hooks subsystem ownership"
  </read_first>
  <action>
    **Manual-replay intent (per D-34-B1):** Replay registry-pack format AWARENESS without deleting the fork's builtin claude-code/codex entries in policy.json (Phase 18.1-03 wiring depends on those being present in the embedded data).

    1. Read upstream's diff in full: `git show 24d8b924`.

    2. Identify the upstream additions that are pure type/format-shape work (no fork-side wiring deletion):
       - New `Pack` / `PackEntry` types (if upstream introduces them) - port to `crates/nono-cli/src/package.rs` as new types alongside fork's existing `ArtifactType` enum (preserve Phase 26 PKGS-02 `Plugin` variant).
       - New serde shape for pack manifests - port verbatim where it does not collide with fork's existing manifest types.

    3. Identify the upstream changes that would delete fork-only surface and DO NOT replay them:
       - Removal of `claude-code` / `codex` entries from `data/policy.json` - keep the builtin entries on Windows. Document this preservation in the replay commit body.
       - Removal of fork's Windows install_dir resolution (`%LOCALAPPDATA%\nono\packages` path) - Phase 22-03 PKG-02 wiring stays.
       - Removal of `validate_path_within` callsites in `package_cmd.rs` - Phase 22-03 PKG-04 retention.

    4. Apply the type/format awareness by hand: edit `crates/nono-cli/src/package.rs` to add pack-format types; edit `crates/nono-cli/src/package_cmd.rs` to teach the install path about packs (NEW code path; existing builtin path unchanged). Then `cargo build --workspace`.

    5. Run targeted tests:
       ```
       cargo test -p nono-cli package::tests::
       cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips   # Phase 26 PKGS-02 retention sentinel
       ```

    6. Stage + commit with the manual-replay body. Subject: `replay(C6): registry-pack format awareness from upstream 24d8b924`. Body documents (a) upstream intent, (b) fork-only surface preserved (claude-code/codex builtins in policy.json for Phase 18.1-03, `%LOCALAPPDATA%\nono\packages` Windows install_dir, `validate_path_within` callsites), (c) what was NOT replayed (deletion of builtins; hook bundling - deferred to Task 6 5654b0f9 replay). Trailer block:
       ```
       Manual-replay: 24d8b924
       Upstream-tag: v0.44.0
       Upstream-author: Luke Hinds <lukehinds@gmail.com>
       Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```

    7. **D-34-E1 per-commit invariant verification (BLOCKING):**
       ```
       git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
       ```

    8. **Fork-divergence sentinels (BLOCKING):**
       ```
       grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs                            # Expected: >= 9
       grep -cE 'cfg\(windows\)|cfg\(target_os = .windows.\)' crates/nono-cli/src/package_cmd.rs   # Expected: >= pre-plan baseline
       grep -cE 'claude-code|codex' crates/nono-cli/data/policy.json                                # Expected: >= pre-plan baseline
       grep -c 'ArtifactType::Plugin\|    Plugin,' crates/nono-cli/src/package.rs                   # Expected: >= 1
       ```
       If ANY sentinel regresses: STOP, `git reset --soft HEAD~1`, re-attempt the replay preserving the dropped surface.
  </action>
  <verify>
    <automated>git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l | grep -E '^0$' &amp;&amp; test "$(grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs)" -ge 9 &amp;&amp; git log -1 --format='%B' HEAD | grep -c '^Manual-replay: 24d8b924' | grep -E '^1$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 1 commit landed on `main` with `Manual-replay: 24d8b924` in body.
    - Commit body documents (a) upstream intent, (b) fork-only surface preserved, (c) what was NOT replayed and why.
    - `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returned `0`.
    - `grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs` returns >= 9 (baseline preserved).
    - `grep -cE 'cfg\(windows\)|cfg\(target_os = .windows.\)' crates/nono-cli/src/package_cmd.rs` returns >= pre-plan baseline.
    - `grep -cE 'claude-code|codex' crates/nono-cli/data/policy.json` returns >= pre-plan baseline (Phase 18.1-03 wiring preserved).
    - `cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips` exits 0 (Phase 26 PKGS-02 retention).
    - `cargo build --workspace` exits 0.
  </acceptance_criteria>
  <done>
    Registry-pack format awareness landed on the fork; Phase 18.1-03 + Phase 22-03 PKG-04 + Phase 26-01 PKGS-02 retention preserved.
  </done>
</task>

<task type="auto">
  <name>Task 4: Replay commits 2-3/6 - `d05672d5` install/uninstall hardening + `bdf183e9` re-pull hardening (manual replay)</name>
  <files>
    crates/nono-cli/src/package_cmd.rs
    crates/nono-cli/src/hooks.rs
  </files>
  <read_first>
    - `git show d05672d5 --stat` (4-file diff)
    - `git show d05672d5 -- crates/nono-cli/src/`
    - `git show bdf183e9 --stat` (4-file diff)
    - `git show bdf183e9 -- crates/nono-cli/src/`
    - crates/nono-cli/src/package_cmd.rs install + uninstall codepaths + all 9 validate_path_within callsites
    - crates/nono-cli/src/hooks.rs install + uninstall public API
    - .planning/templates/upstream-sync-quick.md Fork-divergence catalog entry "validate_path_within defense-in-depth retention" (LOAD-BEARING for these 2 commits)
  </read_first>
  <action>
    **Replay commit 2/6: `d05672d5 fix(wiring): harden install and uninstall wiring`**

    Upstream intent: tighten error handling and idempotency of install/uninstall wiring (the path that registers hooks + writes artifacts + records install state).

    Fork-only surface a straight cherry-pick would delete: `validate_path_within(staging_root, &store_path)?` callsites in package_cmd.rs; `crates/nono-cli/src/hooks.rs` install/uninstall API surface.

    1. Read upstream's diff: `git show d05672d5`.
    2. Identify the hardening INTENT (idempotent uninstall? better error messages? retry on transient failure?) and apply it BY HAND to the fork's install/uninstall path. Preserve every `validate_path_within` callsite verbatim. Preserve `hooks.rs` as the install entrypoint.
    3. Build + targeted test: `cargo build --workspace && cargo test -p nono-cli package::tests::`.
    4. Commit with body: `replay(C6): install/uninstall hardening from upstream d05672d5`. Body documents intent + preserved fork surface (validate_path_within callsites, hooks.rs centralization) + NOT-replayed items (any removal of validate_path_within calls; any movement of hook logic out of hooks.rs). Trailer:
       ```
       Manual-replay: d05672d5
       Upstream-tag: v0.44.0
       Upstream-author: Luke Hinds <lukehinds@gmail.com>
       Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
    5. **D-34-E1 + fork-divergence sentinels (BLOCKING):**
       ```
       git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
       grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs                            # Expected: >= 9
       grep -c '^pub fn \|^fn ' crates/nono-cli/src/hooks.rs                                        # Expected: >= pre-plan baseline
       ```

    **Replay commit 3/6: `bdf183e9 fix(package): harden re-pulls against user edits`**

    Upstream intent: when a user has manually edited files in a previously-installed package and then re-pulls, upstream's hardening prevents data loss / silent overwrite.

    Fork-only surface a straight cherry-pick would delete: same validate_path_within callsites; Phase 22-03 PKG-02 Windows install_dir resolution.

    1. Read upstream's diff: `git show bdf183e9`.
    2. Identify the re-pull-hardening INTENT (detect-and-abort? backup-then-overwrite? prompt-for-confirmation?) and apply it BY HAND to the fork's `nono package pull` re-pull path.
    3. Build + test: `cargo build --workspace && cargo test -p nono-cli package::tests::`.
    4. Commit with body: `replay(C6): re-pull hardening from upstream bdf183e9`. Body documents intent + preserved fork surface (`%LOCALAPPDATA%\nono\packages` install_dir + validate_path_within defense-in-depth). Trailer:
       ```
       Manual-replay: bdf183e9
       Upstream-tag: v0.44.0
       Upstream-author: Luke Hinds <lukehinds@gmail.com>
       Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
    5. **D-34-E1 + fork-divergence sentinels (BLOCKING):**
       ```
       git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
       grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs                            # Expected: >= 9
       ```

    Per-task post-check (after both replays):
    ```
    git log --format='%B' HEAD~2..HEAD | grep -cE '^Manual-replay: (d05672d5|bdf183e9)'   # Expected: 2
    git log --format='%B' HEAD~2..HEAD | grep -c '^Signed-off-by: '   # Expected: 4 (2 per commit)
    git log --format='%B' HEAD~2..HEAD | grep -c 'Upstream-Author:'   # Expected: 0
    cargo build --workspace
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~2..HEAD | grep -cE '^Manual-replay: (d05672d5|bdf183e9)' | grep -E '^2$' &amp;&amp; test "$(grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs)" -ge 9 &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 2 commits landed (one per replay) with `Manual-replay: d05672d5` and `Manual-replay: bdf183e9` bodies respectively.
    - Each commit body documents upstream intent + preserved fork surface + what was NOT replayed.
    - Per-commit `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returned `0`.
    - `grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs` returns >= 9 after BOTH commits (no callsite deletion).
    - `grep -c '^pub fn \|^fn ' crates/nono-cli/src/hooks.rs` returns >= pre-plan baseline (no function deletion).
    - `cargo build --workspace` exits 0 after each commit.
    - `cargo test -p nono-cli package::tests::` exits 0 after each commit.
  </acceptance_criteria>
  <done>
    Install/uninstall + re-pull hardening replayed; validate_path_within + hooks.rs retention preserved.
  </done>
</task>

<task type="auto">
  <name>Task 5: Disposition execute for commits 4-5/6 - `a05fdc57` string-expansion refactor + `f1243c75` CI/test hardening (per Task 2 decision)</name>
  <files>
    (depends on Task 2 disposition: if cherry-pick, files match upstream; if manual replay, files match fork's analogous surface)
  </files>
  <read_first>
    - Task 2's recorded disposition for `a05fdc57` and `f1243c75` (in /tmp/c6-dispositions.txt)
    - `git show a05fdc57` and `git show f1243c75` (full diffs)
    - If cherry-pick: the fork's current state of the files upstream touches (verify zero divergence)
  </read_first>
  <action>
    For each of `a05fdc57` and `f1243c75`, the executor follows the disposition recorded in Task 2:

    **If disposition is straight cherry-pick (A):** Follow the per-commit STRAIGHT-CHERRY-PICK template from `<interfaces>` above. Commit body uses `Upstream-commit: <sha>` field.

    **If disposition is manual replay (B):** Follow the per-commit MANUAL-REPLAY template from `<interfaces>` above. Commit body uses `Manual-replay: <sha>` field.

    **If disposition is skip (C):** Do NOT cherry-pick. Record the skip in SUMMARY with rationale.

    After both commits handled:
    ```
    git log --format='%B' HEAD~K..HEAD | grep -cE '^Upstream-commit: |^Manual-replay: '   # Expected: K (where K = 2 minus skipped)
    git log --format='%B' HEAD~K..HEAD | grep -c 'Upstream-Author:'                       # Expected: 0
    cargo build --workspace
    ```
  </action>
  <verify>
    <automated>cargo build --workspace &amp;&amp; test "$(grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs)" -ge 9 &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <acceptance_criteria>
    - Both commits `a05fdc57` and `f1243c75` have EITHER landed on `main` (with appropriate D-19 or Manual-replay trailer) OR been explicitly skipped with documented rationale in SUMMARY.
    - For each landed commit: `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returned `0`.
    - `grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs` returns >= 9.
    - `cargo build --workspace` exits 0.
    - `cargo fmt --all -- --check` exits 0 (especially after `a05fdc57` refactor or `f1243c75` test changes).
  </acceptance_criteria>
  <done>
    Disposition for commits 4-5 executed per Task 2 decision.
  </done>
</task>

<task type="auto">
  <name>Task 6: Replay commit 6/6 - `5654b0f9 feat(claude): prompt to remove old builtin hooks` (manual replay, hooks-ownership-sensitive)</name>
  <files>
    crates/nono-cli/src/hooks.rs
    crates/nono-cli/src/package_cmd.rs
    crates/nono-cli/data/policy.json
  </files>
  <read_first>
    - `git show 5654b0f9 --stat` (5-file diff)
    - `git show 5654b0f9 -- crates/nono-cli/src/`
    - crates/nono-cli/src/hooks.rs (full file - the surface the fork is preserving)
    - .planning/templates/upstream-sync-quick.md Fork-divergence catalog entry "Hooks subsystem ownership" (LOAD-BEARING for this commit - explicit "do NOT silently accept upstream's removal" instruction)
    - crates/nono-cli/data/policy.json claude-code entry (the builtin the prompt is asking the user to remove)
  </read_first>
  <action>
    **Manual-replay intent:** Add the user-prompt UX that warns a user with old builtin hooks installed that they should migrate. Implement the prompt in the fork's existing `hooks.rs` install flow. EXPLICITLY preserve `hooks.rs` as the sole hook-installation surface.

    Fork-only surface a straight cherry-pick would delete: `crates/nono-cli/src/hooks.rs` as the centralized installer (upstream's commit structurally moves hook bundling into the package manager); the `claude-code` builtin entry in `policy.json` (Phase 18.1-03 wiring dependency).

    1. Read upstream's diff: `git show 5654b0f9`.

    2. Identify the user-prompt INTENT (when does it fire? what does it say? what does the user choose between?) and the FORM (which file owns the prompt, how it's triggered).

    3. Apply the INTENT in the fork:
       - Implement the prompt as a NEW function in `hooks.rs` (or as a new method on the existing installer struct). Hook into the `nono package install claude-code` codepath (where the user invokes the action).
       - The prompt fires when the user installs claude-code AND old builtin hooks are detected (a `policy.json` builtin entry exists alongside a previously-installed pack).
       - The prompt offers the user a choice: keep both, remove builtin, or abort.
       - The fork's `hooks.rs` remains the only file that mutates the hook-installation state.

    4. Apply the prompt's call site in `package_cmd.rs` install path; preserve all `validate_path_within` callsites; preserve Windows install_dir resolution.

    5. Build + test: `cargo build --workspace && cargo test -p nono-cli package::tests::`.

    6. Commit. Subject: `replay(C6): prompt-to-remove-old-builtin-hooks UX from upstream 5654b0f9`. Body documents (a) upstream intent, (b) catalog-driven preservation of `hooks.rs` + `policy.json` claude-code builtin, (c) NOT-replayed items (migration of hook-bundling out of hooks.rs; removal of claude-code builtin from policy.json). Trailer:
       ```
       Manual-replay: 5654b0f9
       Upstream-tag: v0.44.0
       Upstream-author: Luke Hinds <lukehinds@gmail.com>
       Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```

    7. **D-34-E1 + fork-divergence sentinels (BLOCKING):**
       ```
       git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
       grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs                            # Expected: >= 9
       grep -c '^pub fn \|^fn ' crates/nono-cli/src/hooks.rs                                        # Expected: >= pre-plan baseline + 1 (one new prompt function added)
       grep -cE 'claude-code|codex' crates/nono-cli/data/policy.json                                # Expected: >= pre-plan baseline (builtin entries preserved)
       ```
  </action>
  <verify>
    <automated>git log -1 --format='%B' HEAD | grep -c '^Manual-replay: 5654b0f9' | grep -E '^1$' &amp;&amp; grep -cE 'claude-code|codex' crates/nono-cli/data/policy.json &amp;&amp; test "$(grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs)" -ge 9 &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 1 commit landed with `Manual-replay: 5654b0f9` body.
    - Commit body documents the catalog-driven preservation of hooks.rs + policy.json claude-code builtin.
    - `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returned `0`.
    - `grep -c '^pub fn \|^fn ' crates/nono-cli/src/hooks.rs` returns >= pre-plan baseline (NO function deletion; ONE function addition is acceptable).
    - `grep -cE 'claude-code|codex' crates/nono-cli/data/policy.json` returns >= pre-plan baseline.
    - `cargo build --workspace` exits 0; `cargo test -p nono-cli package::tests::` exits 0.
  </acceptance_criteria>
  <done>
    Prompt UX replayed; hooks.rs ownership preserved.
  </done>
</task>

<task type="auto">
  <name>Task 7: Manual-replay summary commit + chain-wide verification</name>
  <files>
    (no source files modified - commit body documents the chain)
  </files>
  <read_first>
    - /tmp/c6-dispositions.txt (Task 2 output - disposition per commit)
    - `git log --format='%H %s' HEAD~N..HEAD` where N is the total number of Plan 34-09 commits landed so far
    - Pre-Plan-34-09 baseline numbers from Task 1 SUMMARY entry
  </read_first>
  <action>
    Create a single empty commit (`git commit --allow-empty`) whose body is the "Manual-replay summary" - the canonical record of what Plan 34-09 did. Mirror Phase 26-01 PKGS-02's commit-body style.

    1. Calculate plan commit count:
       ```
       PRE_PLAN_SHA=$(cat /tmp/c6-baseline-head.txt | awk '{print $1}')
       PLAN_N=$(git log --format='%H' ${PRE_PLAN_SHA}..HEAD | wc -l)
       echo "Plan 34-09 has landed $PLAN_N commits so far"
       ```

    2. Verify chain-wide trailer presence:
       ```
       git log --format='%B' ${PRE_PLAN_SHA}..HEAD | grep -cE '^Upstream-commit: |^Manual-replay: '   # Expected: $PLAN_N (every commit so far carries one or the other)
       git log --format='%B' ${PRE_PLAN_SHA}..HEAD | grep -c 'Upstream-Author:'                       # Expected: 0 (case-sensitivity invariant)
       git log --format='%B' ${PRE_PLAN_SHA}..HEAD | grep -c '^Signed-off-by: '                       # Expected: $PLAN_N * 2 (two DCO lines per commit)
       ```

    3. Verify per-commit D-34-E1 invariant across the chain:
       ```
       git log --format='%H' ${PRE_PLAN_SHA}..HEAD | while read sha; do
         git diff --stat ${sha}^..${sha} -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l
       done | sort -u
       # Expected: only "0" appears
       ```

    4. Create the Manual-replay summary commit (`git commit --allow-empty -m "..."`). Body MUST contain:
       - Subject line: `chore(34-09): Manual-replay summary for cluster C6 (v0.44.0 pack migration)`
       - Section header line: `Manual-replay summary` (exact phrase - verified by grep gate).
       - Per-commit disposition (6 rows: SHA, subject, disposition, brief rationale).
       - Fork-only surface preserved across the chain (cfg(windows) arms, 9 validate_path_within callsites, hooks.rs ownership, claude-code/codex builtins, Phase 26 Plugin variant).
       - Invariant verifications run (D-34-E1, D-19/Manual-replay trailer, fork-divergence sentinels).
       - Pre/post HEAD SHAs + total commit count.
       - Trailer: two `Signed-off-by:` DCO lines (NO `Upstream-commit:` or `Manual-replay:` - this is a fork-only summary, not an upstream port).

    5. Verify the summary commit is well-formed:
       ```
       git log -1 --format='%B' HEAD | grep -c 'Manual-replay summary'   # Expected: 1
       git log -1 --format='%B' HEAD | grep -c '^Signed-off-by: '        # Expected: 2
       ```
  </action>
  <verify>
    <automated>git log -1 --format='%B' HEAD | grep -c 'Manual-replay summary' | grep -E '^1$' &amp;&amp; git log -1 --format='%B' HEAD | grep -c '^Signed-off-by: ' | grep -E '^2$'</automated>
  </verify>
  <acceptance_criteria>
    - The summary commit body contains the literal string "Manual-replay summary".
    - The summary records (a) per-commit disposition, (b) fork-only surface preserved, (c) invariant verifications run, (d) pre/post HEAD SHAs, (e) total commit count.
    - The summary commit carries two `Signed-off-by:` DCO lines.
    - Chain-wide trailer presence: `git log --format='%B' ${PRE_PLAN_SHA}..HEAD~1 | grep -cE '^Upstream-commit: |^Manual-replay: '` equals the count of non-summary commits in the plan.
    - Chain-wide `Upstream-Author:` (case-sensitive) returns 0.
    - Per-commit D-34-E1 invariant check returned 0 for every commit in the chain.
  </acceptance_criteria>
  <done>
    Plan 34-09 commit chain closed with explicit Manual-replay summary.
  </done>
</task>

<task type="auto">
  <name>Task 8: D-34-D2 close-gate (8 gates, all blocking) + Plan-34-09-specific verification</name>
  <files>(read-only verification)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md D-34-D2 (full close-gate text)
    - crates/nono-cli/tests/wfp_port_integration.rs
    - crates/nono-cli/tests/learn_windows_integration.rs
  </read_first>
  <action>
    Run all 8 gates from D-34-D2 in order. Any failure = STOP per D-34-D2 trigger.

    1. **Gate 1: Windows-host workspace test:**
       `cargo test --workspace --all-features`
       Expected: exit 0 within Phase 19 deferred-flake tolerance. NEW failures = STOP.

    2. **Gate 2: Windows-host clippy:**
       `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used`

    3. **Gate 3: Linux cross-target clippy (CR-A lesson):**
       `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`

    4. **Gate 4: macOS cross-target clippy:**
       `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`

    5. **Gate 5: cargo fmt:** `cargo fmt --all -- --check`

    6. **Gate 6: Phase 15 5-row detached-console smoke (Windows host):**
       ```
       nono run --detached --profile default -- powershell -Command "Write-Host 'row1'; Write-Host 'row2'; Write-Host 'row3'; Write-Host 'row4'; Write-Host 'row5'; Start-Sleep 30"
       nono ps
       nono attach <session-id>
       # Ctrl-Q to detach
       nono stop <session-id>
       ```
       Documented-skip if Windows host unavailable.

    7. **Gate 7: WFP port integration:** `cargo test -p nono-cli --test wfp_port_integration -- --ignored`. Documented-skip if admin/service unavailable.

    8. **Gate 8: ETW learn smoke:** `cargo test -p nono-cli --test learn_windows_integration`. Documented-skip if service unavailable.

    9. **Plan-34-09-specific verification (BLOCKING):**
       ```
       PRE_PLAN_SHA=$(cat /tmp/c6-baseline-head.txt | awk '{print $1}')

       # Chain-wide D-34-E1 invariant
       git log --format='%H' ${PRE_PLAN_SHA}..HEAD | while read sha; do
         git diff --stat ${sha}^..${sha} -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l
       done | sort -u
       # Expected: only "0" appears

       # Phase 18.1-03 Windows wiring preserved (no Windows-arm deletions across the chain)
       git diff ${PRE_PLAN_SHA}..HEAD -- crates/nono-cli/src/package_cmd.rs | \
         grep -E '^-' | grep -E 'cfg\(windows\)|cfg\(target_os = .windows.\)|_windows' | wc -l
       # Expected: 0

       # validate_path_within retention
       grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs
       # Expected: >= 9 (baseline)

       # hooks.rs ownership preserved
       grep -c '^pub fn \|^fn ' crates/nono-cli/src/hooks.rs
       # Expected: >= pre-plan baseline

       # policy.json builtin entries preserved
       grep -cE 'claude-code|codex' crates/nono-cli/data/policy.json
       # Expected: >= pre-plan baseline

       # Phase 26 PKGS-02 Plugin round-trip
       cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips
       # Expected: exit 0
       ```

    10. If ANY gate fails: STOP per D-34-D2 trigger. Investigate. Either split the plan (Phase 22-05a/22-05b precedent) or roll back to the pre-Plan-34-09 HEAD (`git reset --hard <pre-Plan-34-09-HEAD-SHA>` from Task 1 record) and re-scope.
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check &amp;&amp; test "$(grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs)" -ge 9 &amp;&amp; cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips</automated>
  </verify>
  <acceptance_criteria>
    - Gate 1: `cargo test --workspace --all-features` exits 0 within deferred-flake window.
    - Gate 2: Windows-host clippy exits 0.
    - Gate 3: Linux cross-target clippy exits 0.
    - Gate 4: macOS cross-target clippy exits 0.
    - Gate 5: `cargo fmt --all -- --check` exits 0.
    - Gate 6: Phase 15 5-row smoke passes OR documented-skip with rationale.
    - Gate 7: `wfp_port_integration --ignored` passes OR documented-skip.
    - Gate 8: `learn_windows_integration` exits 0 OR documented-skip.
    - Chain-wide D-34-E1 invariant: across all Plan 34-09 commits, the per-commit Windows-file-touched count is 0.
    - Phase 18.1-03 Windows wiring preserved: zero deletions of Windows arms in `package_cmd.rs`.
    - `grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs` returns >= 9.
    - `grep -c '^pub fn \|^fn ' crates/nono-cli/src/hooks.rs` returns >= pre-plan baseline.
    - `grep -cE 'claude-code|codex' crates/nono-cli/data/policy.json` returns >= pre-plan baseline.
    - `cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips` exits 0.
  </acceptance_criteria>
  <done>
    Plan 34-09 close-gate cleared. Wave 3 sibling Plan 34-10 cleared to start (D-34-A2 wave-3 says "sequential within wave - proxy TLS replay reads C4 final state"; 34-09 closes before 34-10 starts).
  </done>
</task>

<task type="auto">
  <name>Task 9: D-34-D1 plan-close push to origin + PR creation</name>
  <files>(git push + gh pr create only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md D-34-D1 (direct-on-main; one PR per plan)
  </read_first>
  <action>
    1. Verify origin not ahead of local:
       ```
       git fetch origin
       git log main..origin/main --oneline | wc -l   # Expected: 0 - if non-zero, STOP (remote raced)
       ```

    2. Push: `git push origin main`.

    3. Confirm origin caught up:
       ```
       git fetch origin
       git log origin/main..main --oneline | wc -l   # Expected: 0
       git log -1 origin/main --format='%H'          # Capture for SUMMARY
       ```

    4. Open PR via `gh pr create` titled `Plan 34-09 (C6): Pack migration manual replay (v0.44.0, 6 commits fork-preserve)`. Body documents:
       - Summary: 6 cluster-C6 commits absorbed under D-20 manual-replay disposition.
       - Per-commit disposition table (mirrors the summary commit body).
       - Fork-only surface preserved (Phase 18.1-03 wiring, validate_path_within, hooks.rs, policy.json builtins).
       - D-34-D2 close-gate checklist (all 8 gates with green/skip status).
       - D-34-E1 invariant confirmation: zero `*_windows.rs` edits across the chain.
       - Phase 26 PKGS-02 Plugin round-trip preservation confirmed.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - `git log origin/main..main --oneline | wc -l` returns `0` post-push.
    - PR URL recorded in SUMMARY.
    - SUMMARY records the post-push origin/main SHA (HEAD of Plan 34-09 chain) for traceability.
  </acceptance_criteria>
  <done>
    Plan 34-09 commits published to origin; PR opened.
  </done>
</task>

</tasks>

<non_goals>
**No Windows-only file touched (D-34-E1).** Any cherry-pick or manual-replay that surfaces a `*_windows.rs` edit is a BUG - abort per D-34-E1 invariant. Plan 34-09 has ZERO Windows file edits.

**No retrofit of upstream features into Windows surface (D-34-B2).** The pack-format awareness is absorbed AS-IS in cross-platform code; fork's `%LOCALAPPDATA%\nono\packages` Windows install_dir handling is a SEPARATE, parallel mechanism. No "while we're here" Windows wiring.

**No `validate_path_within` removal.** Fork retains this defense-in-depth call at every callsite (Phase 22-03 PKG-04 + Phase 26-01 PKGS-02 retention). Upstream's `d05672d5` + `bdf183e9` hardening composes AS additional defense-in-depth, not as a replacement.

**No `hooks.rs` removal.** Fork keeps `crates/nono-cli/src/hooks.rs` as the sole hook-installation surface per upstream-sync-quick.md Fork-divergence catalog. Upstream `5654b0f9`'s structural movement of hook bundling into the package manager is NOT replayed; only the user-prompt UX is.

**No `claude-code` / `codex` builtin removal from `data/policy.json`.** Phase 18.1-03 Windows wiring depends on these being present in the embedded data. Upstream `24d8b924`'s migration to pack-only shape is NOT replayed; fork carries BOTH shapes (builtin + pack) so both v2.1 Phase 18.1-03 consumers and future pack consumers work.

**No `ArtifactType::Plugin` deletion.** Phase 26-01 PKGS-02 added the variant; Plan 34-09 preserves it; any new pack-format types are layered alongside, not replacing the enum.

**No POLY-01-stricter regression.** Fork's POLY-01 posture (CONTRADICTION-A from Phase 22 PATTERNS) survives Plan 34-09 - none of the C6 commits touch policy.rs, but the chain-wide cargo test gate sentinels the invariant.

**No upstream version field sync.** Fork's Cargo.toml version stream is independent of upstream's release-bump commits. C6 doesn't include a release bump in scope (release commit `e9...` is excluded per Phase 33 audit; only the 6 feature/fix/refactor commits are in cluster C6), but if a Cargo.toml version conflict arises during replay, preserve fork's version.

**No pre-emptive 34-10 work.** Plan 34-10 (C11 proxy TLS manual replay) lives in the same Wave 3 but sequenced AFTER 34-09; 34-09 does NOT pre-emptively touch proxy / OAuth surface.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Upstream commit chain -> fork commit chain | Cherry-pick or manual-replay crosses an authorial trust boundary. Each upstream commit's intent must be inspected before it lands on the fork. |
| User-supplied pack manifest -> ArtifactType parser | Pack format awareness (replayed from upstream `24d8b924`) introduces a new JSON shape crossing into `serde_json::from_str` on the install path. |
| Package install path -> filesystem | Install/uninstall hardening (replayed from `d05672d5` + `bdf183e9`) operates at the filesystem boundary where path-traversal and TOCTOU footguns live; `validate_path_within` is the fork's enforcement primitive here. |
| User confirmation prompt -> hook installation state | The `5654b0f9` user-prompt UX gives the user the choice to delete state (old builtin hooks); the prompt itself is a trust boundary. |
| Embedded data/policy.json -> Phase 18.1-03 Windows wiring | The builtin claude-code/codex entries are a load-bearing input to the Windows widening codepath; deleting them silently is a downstream failure. |
| Fork's hooks.rs centralized surface -> package manager | Phase 22-03 PKG-03 routes hook installation through hooks.rs; upstream's restructuring attempts to move this boundary. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-09-01 | Tampering | Manual replay of `24d8b924` silently deletes claude-code/codex builtin entries from `data/policy.json` (Phase 18.1-03 Windows wiring breaks) | **high** | mitigate (BLOCKING) | Task 3 acceptance criterion: `grep -cE 'claude-code\|codex' crates/nono-cli/data/policy.json` returns >= pre-plan baseline. Task 8 plan-close re-verifies. The replay commit body explicitly documents the preservation decision. |
| T-34-09-02 | Tampering | Manual replay of `d05672d5` or `bdf183e9` silently deletes `validate_path_within` callsites (Phase 22-03 PKG-04 + Phase 26-01 PKGS-02 defense-in-depth lost) | **high** | mitigate (BLOCKING) | Tasks 3, 4, 6 per-commit sentinel: `grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs` returns >= 9 baseline after EVERY commit. Plan-close re-verifies. Each retained callsite annotated with the defense-in-depth comment per upstream-sync-quick.md catalog. |
| T-34-09-03 | Elevation of Privilege | D-34-E1 Windows-only files invariant violation (commit touches `*_windows.rs` outside intended scope - particularly `exec_identity_windows.rs` or `learn_windows.rs` which a careless package-manager refactor might inadvertently edit) | **high** | mitigate (BLOCKING) | Per-commit D-34-E1 invariant check (`git diff --stat HEAD~1 HEAD -- crates/ \| grep -E '_windows\|exec_strategy_windows' \| wc -l`) MUST return 0. Failure = abort, revert Windows hunk, re-attempt the replay. |
| T-34-09-04 | Repudiation | D-19 / Manual-replay trailer block tampered or missing (no `Upstream-commit:` / `Manual-replay:` field; no DCO sign-off; uppercase 'A' in `Upstream-Author:`) | **high** | mitigate (BLOCKING) | Per-task acceptance criteria + Task 7 chain-wide smoke check: `grep -cE '^Upstream-commit: \|^Manual-replay: '` equals total non-summary commit count; `grep -c 'Upstream-Author:'` (case-sensitive) returns 0; `grep -c '^Signed-off-by: '` returns 2 per non-summary commit. |
| T-34-09-05 | Information Disclosure | Phase 18.1-03 Windows widening codepath regression - replay of `24d8b924` deletes a `cfg(target_os = "windows")` arm in `package_cmd.rs`, weakening the G-06 widening on Windows | **high** | mitigate (BLOCKING) | Task 3 acceptance criterion + Task 8 close-gate: pre/post diff `git diff <pre-plan-sha>..HEAD -- crates/nono-cli/src/package_cmd.rs \| grep -E '^-' \| grep -E 'cfg\(windows\)\|cfg\(target_os = .windows.\)\|_windows' \| wc -l` returns 0. Zero Windows-arm deletions across the chain. |
| T-34-09-06 | Tampering | Hooks subsystem ownership regression - replay of `5654b0f9` moves hook-installation logic out of `hooks.rs` into the package manager, breaking Phase 22-03 PKG-03 centralized installer + upstream-sync-quick.md catalog invariant | medium | mitigate | Task 6 acceptance criterion: `grep -c '^pub fn \|^fn ' crates/nono-cli/src/hooks.rs` returns >= pre-plan baseline (no function deletion; ONE addition for the prompt is acceptable). Catalog entry "Hooks subsystem ownership" explicitly cited in the replay commit body. |

**BLOCKING threats:** T-34-09-01, T-34-09-02, T-34-09-03, T-34-09-04, T-34-09-05 - five of six threats block plan-close until mitigations are demonstrably present. T-34-09-06 is high-impact but second-order to the load-bearing path/policy.json invariants.
</threat_model>

<verification>
Per-plan close gate (D-34-D2):

- `cargo test --workspace --all-features` exits 0 within Phase 19 deferred-flake tolerance.
- `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) exits 0.
- `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` exits 0.
- `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` exits 0.
- `cargo fmt --all -- --check` exits 0.
- Phase 15 5-row detached-console smoke gate passes (or documented-skip).
- `cargo test -p nono-cli --test wfp_port_integration -- --ignored` passes (or documented-skip).
- `cargo test -p nono-cli --test learn_windows_integration` exits 0 (or documented-skip).

Chain-wide trailer checks (Task 7 + Task 8):
- `git log --format='%B' <pre-plan-sha>..HEAD~1 | grep -cE '^Upstream-commit: |^Manual-replay: '` equals the count of non-summary commits in the plan.
- `git log --format='%B' <pre-plan-sha>..HEAD | grep -c 'Upstream-Author:'` returns 0 (case-sensitivity invariant; lowercase 'a' only).
- `git log --format='%B' <pre-plan-sha>..HEAD~1 | grep -c '^Signed-off-by: '` returns 2 * (non-summary commit count); the summary commit adds 2 more (chain total = 2 * (PLAN_N)).
- `git log -1 --format='%B' HEAD | grep -c 'Manual-replay summary'` returns 1.

Per-commit D-34-E1 invariant: across every Plan 34-09 commit, `git diff --stat <prev>..<this> -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns `0`.

Plan-34-09-specific sentinels (Task 8):
- `grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs` returns >= 9 (pre-plan baseline preserved).
- `git diff <pre-plan-sha>..HEAD -- crates/nono-cli/src/package_cmd.rs | grep -E '^-' | grep -E 'cfg\(windows\)|cfg\(target_os = .windows.\)|_windows' | wc -l` returns 0 (zero Windows-arm deletions).
- `grep -c '^pub fn \|^fn ' crates/nono-cli/src/hooks.rs` returns >= pre-plan baseline (no hook installer function deletion).
- `grep -cE 'claude-code|codex' crates/nono-cli/data/policy.json` returns >= pre-plan baseline (Phase 18.1-03 dependency preserved).
- `cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips` exits 0 (Phase 26 PKGS-02 Plugin variant round-trip survives any new pack-format type).

Push verification (Task 9):
- `git log origin/main..main --oneline | wc -l` returns 0 post-push.
- PR opened via `gh pr create`; PR URL recorded in SUMMARY.
</verification>

<success_criteria>
- 6-7 atomic commits on `main` (one per non-skipped C6 SHA + one Manual-replay summary commit), each carrying either D-19 trailer (cherry-picks) or `Manual-replay:` body (replay-intent commits) or DCO-only sign-off (summary commit).
- Registry-pack format awareness landed in `crates/nono-cli/src/package.rs` alongside (not replacing) the existing `ArtifactType` enum + Phase 26 `Plugin` variant.
- Install/uninstall hardening intent + re-pull hardening intent absorbed into the fork's `package_cmd.rs` install path.
- User-prompt UX for old-builtin-hook migration implemented as a new function in `hooks.rs`.
- Phase 18.1-03 Windows widening wiring in `package_cmd.rs` byte-identical on Windows arms.
- `validate_path_within` callsites count >= 9 (baseline) - Phase 22-03 PKG-04 + Phase 26-01 PKGS-02 defense-in-depth preserved.
- `crates/nono-cli/src/hooks.rs` retained as the sole hook-installation surface.
- `crates/nono-cli/data/policy.json` builtin entries (claude-code, codex) preserved.
- Phase 26 PKGS-02 `ArtifactType::Plugin` round-trip preserved.
- All 8 D-34-D2 close-gates green (or documented-skip with rationale for Gates 6-8).
- Zero edits to `*_windows.rs` files; D-34-E1 invariant held per commit.
- Manual-replay summary commit records the per-commit disposition + fork-only-surface-preserved + invariant verifications.
- `origin/main` advanced to plan-close HEAD; PR opened via `gh pr create`.
- Wave 3 sibling Plan 34-10 (C11 proxy TLS manual replay) cleared to start.
- Plan SUMMARY records the 6-7 commit hashes, pre-Plan-34-09 HEAD SHA, post-push origin/main SHA, PR URL, per-commit disposition decisions (cherry-pick vs replay vs skip), and explicit D-34-E1 + fork-divergence-sentinel results.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-09-SUMMARY.md` using the standard summary template. Required sections: Outcome ("C6 v0.44.0 pack migration manual-replayed; Phase 18.1-03 + Phase 22-03 PKG-04 + Phase 26-01 PKGS-02 retention preserved; Wave 3 sibling Plan 34-10 cleared"), What was done (one bullet per task), Per-commit disposition table (6 rows: SHA, subject, cherry-pick/replay/skip, rationale), Verification table (8 close-gates + 5 plan-specific sentinels with actual results), Files changed (`crates/nono-cli/src/{package_cmd.rs,package.rs,hooks.rs}`, `crates/nono-cli/data/policy.json`; ZERO Windows files), Commits (6-7-row table: SHA + subject + upstream tag + disposition + author), Pre/post baseline (validate_path_within count, hooks.rs fn count, Windows cfg-arm count, policy.json builtin count, Plugin variant presence), Status (complete), Deferred (any skipped commits + their rationale; any documented-skip gates).
</output>
