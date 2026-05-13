---
phase: 40-upst4-sync-execution
plan: 04
slug: release-ride
cluster_id: C7
type: execute
wave: 1
depends_on: ["40-02", "40-03"]
files_modified:
  - crates/nono/src/sandbox/linux.rs
  - crates/nono/src/diagnostic.rs
  - Cargo.toml
upstream_tag_range: v0.52.0..v0.53.0
upstream_commit_count: 5
autonomous: true
requirements: [REQ-UPST4-02]
tags: [upst4, c7, sandbox, landlock, diagnostic, release, wave-1]

must_haves:
  truths:
    - "All 5 cluster-C7 commits cherry-picked onto main in upstream chronological order"
    - "Every Plan 40-04 commit body carries the verbatim D-19 6-line trailer block (lowercase 'a' in Upstream-author)"
    - "5b61971 — fix(sandbox): cache Landlock ABI detection with OnceLock (v0.53.0)"
    - "5a61808 — fix: return full failure diagnostic (v0.53.0)"
    - "21bbb82 — chore: release v0.52.1 (Cargo.toml version bump)"
    - "e8bf014 — chore: release v0.52.2 (Cargo.toml version bump)"
    - "c4b25b8 — chore: release v0.53.0 (Cargo.toml version bump)"
    - "D-40-E1 invariant: zero edits to *_windows.rs or exec_strategy_windows/ for every commit"
    - "Release commits cherry-picked in upstream chronological order with D-19 trailers"
    - "All 8 D-40-C2 close-gates pass"
  artifacts:
    - path: "crates/nono/src/sandbox/linux.rs"
      provides: "Landlock ABI detection cached via OnceLock (5b61971)"
      grep_pattern: "OnceLock.*abi\|abi.*OnceLock\|LANDLOCK_ABI"
    - path: "crates/nono/src/diagnostic.rs"
      provides: "full failure diagnostic returned at supervisor boundaries (5a61808)"
      grep_pattern: "full.*diagnostic\|failure.*diagnostic"
    - path: "Cargo.toml"
      provides: "version bumps: v0.52.1 (21bbb82) + v0.52.2 (e8bf014) + v0.53.0 (c4b25b8)"
      grep_pattern: "version.*=.*\"0\\.53"
  key_links:
    - from: "crates/nono/src/sandbox/linux.rs ABI detection call"
      to: "OnceLock<LandlockAbi> static"
      via: "Landlock ABI cache — replaces repeated syscall per sandbox::apply() invocation"
      pattern: "OnceLock|once_lock|LANDLOCK_ABI_CACHE"
---

<objective>
Cluster C7 (upstream v0.52.1..v0.53.0, 5 commits): Landlock ABI cache via OnceLock + full failure-diagnostic preservation + 3 release version bumps.

Wave-1 plan. Depends on Wave 0 (40-02 + 40-03) so that SandboxState shape and scrub re-export are established. Runs in parallel with Plan 40-01 (Cluster C1 proxy hardening) — surfaces are disjoint (C7 touches crates/nono/src/sandbox/linux.rs + diagnostic.rs + Cargo.toml version bumps; C1 touches crates/nono-proxy/src/server.rs + Cargo.toml feature flags — NOTE: both touch Cargo.toml; check for conflicts).

Cargo.toml conflict note: Plan 40-01 and Plan 40-04 both touch Cargo.toml. If running in parallel, the second plan to land must rebase on top of the first's Cargo.toml edits. The release version bump commits (21bbb82 / e8bf014 / c4b25b8) are simple workspace version number changes that do not conflict with feature flag changes from abc86f6 (C1). If a conflict occurs: accept both changes (feature isolation + version bump).

Output: 5 atomic commits with D-19 trailers; PR opened.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/phases/40-upst4-sync-execution/40-CONTEXT.md
@.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md
@.planning/templates/upstream-sync-quick.md

<interfaces>
**Cluster C7 cherry-pick chain (5 commits, chronological):**

| Order | SHA | Tag | Subject | Files changed | Upstream Author |
|-------|-----|-----|---------|---------------|-----------------|
| 1 | `5b61971` | v0.53.0 | fix(sandbox): cache Landlock ABI detection with OnceLock | 1 | unknown (upstream) |
| 2 | `5a61808` | v0.53.0 | fix: return full failure diagnostic | 1 | unknown (upstream) |
| 3 | `21bbb82` | v0.52.1 | chore: release v0.52.1 | 1 | unknown (upstream) |
| 4 | `e8bf014` | v0.52.2 | chore: release v0.52.2 | 1 | unknown (upstream) |
| 5 | `c4b25b8` | v0.53.0 | chore: release v0.53.0 | 1 | unknown (upstream) |

Note: chronological order for upstream-tag assignment. The feature commits (5b61971, 5a61808) appear before the release commits in the DIVERGENCE-LEDGER table but are tagged v0.53.0 which is after v0.52.1 and v0.52.2. Cherry-pick the 2 feature commits first (they're the meaningful change), then the 3 release bumps in version order (v0.52.1 → v0.52.2 → v0.53.0).

**D-19 trailer shape (Upstream-tag varies per commit):**

Feature commits:
```
Upstream-commit: 5b61971
Upstream-tag: v0.53.0
Upstream-author: <Name> <<email>>
...
```

Release bump commits:
```
Upstream-commit: 21bbb82
Upstream-tag: v0.52.1
Upstream-author: <Name> <<email>>
...
```

**5b61971 special attention:**
- Linux-only optimization in crates/nono/src/sandbox/linux.rs
- OnceLock pattern: the fork already uses OnceLock elsewhere (e.g., LEGACY_OVERRIDE_DENY_WARNED in Phase 36 per DIVERGENCE-LEDGER rationale)
- Composes cleanly — no conflict with fork-only Windows sandbox (crates/nono/src/sandbox/windows.rs is D-11 excluded and not touched by this commit)
- Verify after cherry-pick: `grep -E 'OnceLock|LANDLOCK_ABI' crates/nono/src/sandbox/linux.rs` returns results

**5a61808 special attention:**
- Cross-platform diagnostic correctness fix in crates/nono/src/diagnostic.rs
- Improves error-reporting at supervisor boundaries
- Verify after cherry-pick: `grep -c 'full.*diagnostic\|failure.*diagnostic' crates/nono/src/diagnostic.rs` >= 1 (or search for the actual changed identifier from git show 5a61808)

**Release bumps (21bbb82 / e8bf014 / c4b25b8):**
- Each touches only Cargo.toml (workspace version field)
- Per Phase 33 / Phase 34 precedent: these always ride along with the parent release cluster chain
- If Cargo.toml conflicts with Plan 40-01's abc86f6 (feature flag changes): accept both
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — verify Wave 0 closed + fetch upstream</name>
  <files>(git operations only)</files>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-CONTEXT.md § D-40-A2 (Wave 1 depends on Wave 0)
    - .planning/phases/40-upst4-sync-execution/40-02-CLI-ALLOW-VALIDATE-SUMMARY.md
    - .planning/phases/40-upst4-sync-execution/40-03-SCRUB-MODULE-SUMMARY.md
  </read_first>
  <action>
    1. Verify Wave 0 closed:
       ```bash
       test -f .planning/phases/40-upst4-sync-execution/40-02-CLI-ALLOW-VALIDATE-SUMMARY.md || echo "BLOCKED: 40-02 not closed"
       test -f .planning/phases/40-upst4-sync-execution/40-03-SCRUB-MODULE-SUMMARY.md || echo "BLOCKED: 40-03 not closed"
       ```
    2. Fetch + verify all 5 C7 SHAs:
       ```bash
       git fetch upstream --tags
       for sha in 5b61971 5a61808 21bbb82 e8bf014 c4b25b8; do
         git cat-file -t $sha || echo "MISSING: $sha"
       done
       ```
    3. Check if Plan 40-01 has already landed (Cargo.toml version bump coordination):
       ```bash
       grep 'version' Cargo.toml | head -5   # See current version
       git log --oneline -5   # See recent commits for Plan 40-01 status
       ```
    4. Record Windows-only sentinel:
       ```bash
       git log -1 --format='%H' -- crates/nono-cli/src/exec_strategy_windows/
       ```
    5. Baseline build:
       ```bash
       cargo build --workspace
       ```
    6. Verify no unfilled placeholders in this PLAN.md (D-40-E5):
       ```bash
       grep -oE '\{[a-z_]+\}' .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-PLAN.md | wc -l  # Expected: 0
       ```
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - Wave 0 SUMMARY files both present; all 5 C7 SHAs reachable; Windows-only sentinel recorded; baseline build green; zero unfilled PLAN.md placeholders.
  </acceptance_criteria>
  <done>
    Ready for C7 chain.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 5 C7 commits with D-19 trailers</name>
  <files>
    crates/nono/src/sandbox/linux.rs
    crates/nono/src/diagnostic.rs
    Cargo.toml
  </files>
  <read_first>
    - crates/nono/src/sandbox/linux.rs (read current ABI detection logic before 5b61971)
    - crates/nono/src/diagnostic.rs (read current error reporting structure before 5a61808)
    - git show 5b61971 5a61808 21bbb82 e8bf014 c4b25b8 (read ALL 5 diffs before any cherry-pick)
    - .planning/templates/upstream-sync-quick.md § Fork-divergence catalog
    - .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md § Cluster C7 row
  </read_first>
  <action>
    Read all 5 diffs first. Then cherry-pick in order (feature commits first, release bumps second).

    **Commit 1/5: 5b61971 (fix(sandbox): cache Landlock ABI detection with OnceLock)**
    ```bash
    git show 5b61971
    git cherry-pick 5b61971
    cargo build --workspace
    # Verify OnceLock pattern landed:
    grep -E 'OnceLock|LANDLOCK_ABI' crates/nono/src/sandbox/linux.rs   # Must return >= 1 line
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit
    # Append:
    # Upstream-commit: 5b61971
    # Upstream-tag: v0.53.0
    # Upstream-author: <from git show> <<email>>
    # Co-Authored-By: <from git show> <<email>>
    # Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    # Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    ```

    **Commit 2/5: 5a61808 (fix: return full failure diagnostic)**
    ```bash
    git show 5a61808
    git cherry-pick 5a61808
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit
    # Append trailer (Upstream-tag: v0.53.0)
    ```

    **Commit 3/5: 21bbb82 (chore: release v0.52.1)**
    ```bash
    git show 21bbb82
    git cherry-pick 21bbb82
    # If Cargo.toml conflicts with Plan 40-01 abc86f6: accept both changes
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit
    # Append trailer (Upstream-tag: v0.52.1)
    ```

    **Commit 4/5: e8bf014 (chore: release v0.52.2)**
    ```bash
    git show e8bf014
    git cherry-pick e8bf014
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit
    # Append trailer (Upstream-tag: v0.52.2)
    ```

    **Commit 5/5: c4b25b8 (chore: release v0.53.0)**
    ```bash
    git show c4b25b8
    git cherry-pick c4b25b8
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit
    # Append trailer (Upstream-tag: v0.53.0)
    ```

    **Post-chain smoke:**
    ```bash
    git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: '   # MUST be 5
    git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-author: '   # MUST be 5 (lowercase 'a')
    git log --format='%B' HEAD~5..HEAD | grep -c '^Signed-off-by: '     # MUST be 10
    git log -1 --format='%H' -- crates/nono-cli/src/exec_strategy_windows/
    # MUST equal PRE_PLAN_WINDOWS_SHA from Task 1
    # Verify v0.53.0 version in Cargo.toml:
    grep '^version' Cargo.toml   # Should reflect v0.53.0
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: ' | grep -E '^5$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 5 commits with verbatim D-19 6-line trailers (lowercase 'a').
    - Per-commit D-40-E1: all 5 commits return 0 for Windows-file grep.
    - Windows-only sentinel SHA unchanged.
    - Landlock ABI OnceLock pattern present in linux.rs.
    - Cargo.toml workspace version reflects v0.53.0 (final release bump landed).
    - `cargo build --workspace` exits 0 after each commit.
  </acceptance_criteria>
  <done>
    C7 chain complete; Landlock ABI cached; diagnostic improved; version bumps to v0.53.0 landed.
  </done>
</task>

<task type="auto">
  <name>Task 3: D-40-C2 8-check close gate</name>
  <files>(read-only verification)</files>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-CONTEXT.md § D-40-C2
  </read_first>
  <action>
    ```bash
    # Gate 1
    cargo test --workspace --all-features

    # Gate 2
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used

    # Gate 3 (catches Landlock/Linux-gated OnceLock drift)
    cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used

    # Gate 4
    cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used

    # Gate 5
    cargo fmt --all -- --check

    # Gate 6: Phase 15 detached-console smoke — document PASS or skipped

    # Gate 7: wfp_port_integration
    cargo test --workspace --all-features -p nono-cli -- wfp_port_integration

    # Gate 8: learn_windows_integration
    cargo test --workspace --all-features -p nono-cli -- learn_windows_integration

    # D-19 smoke:
    git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: '   # MUST be 5
    # D-40-E1 final:
    git diff --stat HEAD~5 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    ```
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <acceptance_criteria>
    - Gates 1+2+5: PASS. Gates 3+4+6+7+8: PASS or documented-skipped.
    - D-19 smoke: 5 Upstream-commit: lines.
    - D-40-E1: 0 Windows-file edits.
  </acceptance_criteria>
  <done>
    Plan 40-04 close-gate cleared.
  </done>
</task>

<task type="auto">
  <name>Task 4: Push + PR</name>
  <files>(git push only)</files>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-CONTEXT.md § D-40-C1
  </read_first>
  <action>
    ```bash
    git push origin main
    gh pr create \
      --title "Plan 40-04 (C7): Landlock ABI OnceLock cache + full failure diagnostic + v0.52.1/v0.52.2/v0.53.0 release bumps (5 commits)" \
      --body "$(cat <<'EOF'
    Wave 1 plan (depends on Wave 0: 40-02 + 40-03). Absorbs upstream Cluster C7 (5 commits):

    - 5b61971: Landlock ABI detection cached via OnceLock (linux.rs)
    - 5a61808: full failure diagnostic returned at supervisor boundaries (diagnostic.rs)
    - 21bbb82: chore: release v0.52.1 (Cargo.toml version bump)
    - e8bf014: chore: release v0.52.2 (Cargo.toml version bump)
    - c4b25b8: chore: release v0.53.0 (Cargo.toml version bump)

    D-19 trailers: 5/5. D-40-E1 violations: 0. D-40-C2 gates: all pass.
    Fork now at upstream v0.53.0 for will-sync clusters.
    Part of Phase 40 UPST4 sync execution (REQ-UPST4-02).
    EOF
    )"
    ```
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline 2>/dev/null | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Pushed; PR created; origin/main updated.
  </acceptance_criteria>
  <done>
    Plan 40-04 published; Wave 1 C7 PR open.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| OnceLock static → Landlock ABI detection per-process | Cached ABI value must not be stale across sandbox::apply() calls |
| Supervisor → sandboxed child error path | Full failure diagnostic must be preserved through fork+exec boundary |
| Cargo.toml version bump → downstream build reproducibility | Version field must land correctly without conflicting with feature changes |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-40-04-01 | Tampering | D-40-E1 Windows-only files invariant | **HIGH** | mitigate (BLOCKING) | Per-commit grep gate; Windows-only sentinel SHA unchanged |
| T-40-04-02 | Repudiation | D-19 trailer missing | **HIGH** | mitigate (BLOCKING) | Post-chain `grep -c '^Upstream-commit: '` must equal 5 |
| T-40-04-03 | Denial of Service | OnceLock ABI cache poisoned by concurrent initialization race | medium | accept | OnceLock guarantees single initialization — Rust's standard library safety guarantee; no additional mitigation needed |
| T-40-04-04 | Tampering | Landlock ABI version cached at initialization then sandbox upgraded mid-process | low | accept | nono's process model is fork+exec; each child gets fresh process + fresh OnceLock initialization; no mid-process sandbox upgrade path exists |
| T-40-04-05 | Tampering | Release-bump Cargo.toml cherry-pick conflicts with Plan 40-01 abc86f6 feature flag edits | medium | mitigate | If Cargo.toml conflict on cherry-pick: accept both changes (version bump + feature isolation) — they edit different keys |
| T-40-04-06 | Information Disclosure | Full failure diagnostic exposes kernel path structures to sandboxed process | low | accept | Diagnostic is emitted to stderr by the supervisor process (unsandboxed); sandboxed child never reads it |
</threat_model>

<verification>
- All 8 D-40-C2 close-gates pass.
- `git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: '` returns 5.
- `git diff --stat HEAD~5 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns 0.
- `grep -E 'OnceLock|LANDLOCK_ABI' crates/nono/src/sandbox/linux.rs` returns at least 1 match.
- `grep '^version' Cargo.toml` reflects v0.53.0.
- origin/main advanced; PR created.
</verification>

<success_criteria>
- 5 atomic commits on main, each with verbatim D-19 6-line trailer.
- Landlock ABI detection cached via OnceLock (performance + correctness fix for Linux).
- Full failure diagnostic returned at supervisor boundaries (cross-platform correctness).
- Cargo.toml workspace version at v0.53.0 (release bumps landed).
- D-40-E1 invariant honored (0 Windows-file edits).
- All 8 D-40-C2 gates cleared.
- origin/main advanced; PR open.
</success_criteria>

<output>
After completion, create `.planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md`.
</output>
