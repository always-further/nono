---
phase: 40-upst4-sync-execution
plan: 05
slug: fp-profile-save
cluster_id: C4
type: execute
wave: 2
depends_on: ["40-01", "40-04"]
files_modified:
  - crates/nono-cli/src/profile_save_runtime.rs
  - crates/nono-cli/src/terminal_approval.rs
  - crates/nono-cli/src/policy.rs
  - crates/nono-cli/src/profile/mod.rs
upstream_tag_range: v0.52.1..v0.52.2
upstream_commit_count: 2
autonomous: true
requirements: [REQ-UPST4-02]
tags: [upst4, c4, fork-preserve, profile-save, d20-manual-replay, wave-2]

must_haves:
  truths:
    - "Diff-inspection step completed BEFORE any cherry-pick or manual-replay commit lands"
    - "Disposition documented in ## Disposition resolution section of this PLAN.md (or in a ## Disposition resolution note committed to main)"
    - "If upgraded to will-sync: 2 commits with verbatim D-19 6-line trailers"
    - "If stays D-20 manual replay: 1-3 commits with D-40-B3 commit body sections (no D-19 trailer)"
    - "D-40-E1 invariant: zero edits to *_windows.rs or exec_strategy_windows/ for every commit"
    - "Phase 18.1 Plan 18.1-01 terminal_approval.rs per-HandleKind build_prompt_text surface preserved"
    - "Phase 36/36.5 profile-drafts surface (REQ-PORT-CLOSURE-02/03) preserved"
    - "All 8 D-40-C2 close-gates pass"
  artifacts:
    - path: "crates/nono-cli/src/profile_save_runtime.rs"
      provides: "denied-path save suppression (upstream intent from 9b07bf7)"
      grep_pattern: "suppress.*deny|deny.*suppress|denied.*save|save.*denied"
    - path: "crates/nono-cli/src/terminal_approval.rs"
      provides: "per-HandleKind build_prompt_text preserved (Phase 18.1 D-04 locked surface)"
      grep_pattern: "build_prompt_text|HandleKind|per_kind"
  key_links:
    - from: "profile_save_runtime.rs denied-path detection"
      to: "terminal_approval.rs suppression decision"
      via: "save-profile flow calling approval gate"
      pattern: "denied.*path.*approve|approve.*denied.*path"
---

<objective>
Cluster C4 (upstream v0.52.1..v0.52.2, 2 commits): profile-save denial suppression (9b07bf7 feat: suppress save-profile prompts for denied paths + eb6cb09 fix: address suppression review feedback).

Wave-2 FORK-PRESERVE plan. Depends on Wave-1 (40-01 + 40-04 closed) so Cluster 4 reads the post-Wave-1 state of profile.rs / policy.rs / profile/mod.rs before making any disposition decision.

FIRST TASK IS THE DIFF-INSPECTION (D-40-B1 mandate). The disposition resolution (will-sync vs D-20 manual replay) is made in Task 1 and documented before any code changes land. If the upgrade fires: Task 2 is cherry-pick with D-19 trailers. If it does not fire: Task 2 is manual replay with D-40-B3 commit body.

The PLAN.md is written assuming D-20 manual replay (conservative default from D-40-B1) with the upgrade branch described in Task 2. If diff-inspection clears (zero fork-only-line conflicts + identical surface semantics), the executor upgrades in-place per the documented rule.

Output: 1-3 commits (D-19 cherry-picks if upgraded; D-20 manual replay commits otherwise); PR opened.
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
**Cluster C4 upstream commits:**

| SHA | Tag | Subject | Files changed |
|-----|-----|---------|---------------|
| `9b07bf7` | v0.52.2 | feat(profile-save): suppress save-profile prompts for denied paths | 11 |
| `eb6cb09` | v0.52.2 | fix(profile-save): address suppression review feedback | 1 |

**D-40-B1 UPGRADE RULE (strict):**

Upgrade from D-20 manual replay to D-19 cherry-pick IFF BOTH conditions pass:
1. Cherry-pick applies with ZERO fork-only-line conflicts (no hunk-level conflict with Windows-specific wiring, per-HandleKind surface, or profile-drafts surface)
2. Upstream feature semantics match what the fork already enforces (no behavioral surprise)

Upgrade is blocked if EITHER:
- The diff touches any `#[cfg(target_os = "windows")]` arms in terminal_approval.rs, profile_save_runtime.rs, policy.rs, or profile/mod.rs — without those arms being identical in upstream
- The diff intersects Phase 18.1 Plan 18.1-01 build_prompt_text per-HandleKind template surface (D-04-locked)
- The diff intersects Phase 36/36.5 profile-drafts surface (REQ-PORT-CLOSURE-02/03) via new Section values, promote subcommand, or --draft flag interaction

**D-40-B3 MANUAL REPLAY commit body sections (if disposition stays D-20):**

Each manual-replay commit MUST include ALL of these sections:
```
Upstream intent: [what the upstream commit was trying to do]

What was replayed: [the specific behavior carried into the fork]

What was NOT replayed and why: [the upstream code/wiring that would have collided with fork-only surface]

Fork-only wiring preserved: [explicit list of file paths/symbols/cfg-arms that the cherry-pick would have overwritten]

Upstream-replayed-from: 9b07bf7 (or eb6cb09)

Co-Authored-By: Claude <noreply@anthropic.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

NOTE: `Upstream-replayed-from:` does NOT match the `^Upstream-commit: ` grep pattern — this is intentional. Manual replay commits MUST NOT have `Upstream-commit:` lines.

**D-19 TRAILER (if upgraded to will-sync):**
Same 6-line shape as other plans (Upstream-commit: / Upstream-tag: v0.52.2 / Upstream-author: / Co-Authored-By: / Signed-off-by: × 2).

**Fork-only surface to preserve (D-40-B1 surface-overlap check targets):**
- `terminal_approval.rs` build_prompt_text per-HandleKind template (Phase 18.1 Plan 18.1-01, D-04-locked)
- `profile/mod.rs` Phase 36 deprecated_schema integration (REQ-PORT-CLOSURE-02)
- `profile/mod.rs` Phase 36.5 profile-drafts promote + --draft surface (REQ-PORT-CLOSURE-03)
- `policy.rs` Phase 36 bypass_protection rename (REQ-PORT-CLOSURE-02 / D-36-B4)
- Any `#[cfg(target_os = "windows")]` arms in the above files
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Diff-inspection — resolve C4 disposition (D-40-B1 mandate)</name>
  <files>(read-only diff inspection — no code changes)</files>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-CONTEXT.md § D-40-B1 (upgrade rule), D-40-B3 (manual replay body)
    - .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md (verify Wave 1 closed)
    - .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md (verify Wave 1 closed)
    - .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md § Cluster C4
    - crates/nono-cli/src/terminal_approval.rs (read BEFORE diff inspection — know the Phase 18.1 surface)
    - crates/nono-cli/src/profile_save_runtime.rs (read current save flow)
    - crates/nono-cli/src/policy.rs (read current policy shape — bypass_protection)
    - crates/nono-cli/src/profile/mod.rs (read current profile struct — deprecated_schema + profile-drafts surface)
  </read_first>
  <action>
    **Step 0: Verify Wave 1 closed (STOP if not) + placeholder smoke check:**
    ```bash
    test -f .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md || echo "BLOCKED: Wave 1 Plan 40-01 not closed"
    test -f .planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md || echo "BLOCKED: Wave 1 Plan 40-04 not closed"
    grep -oE '\{[a-z_]+\}' .planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-PLAN.md | wc -l  # Expected: 0
    ```

    **Step 1: Fetch and read the upstream diffs:**
    ```bash
    git fetch upstream --tags
    git show 9b07bf7    # Read FULL 11-file diff
    git show eb6cb09    # Read FULL 1-file review-fix diff
    ```

    **Step 2: Surface-overlap check (D-40-B1 criteria — answer each question explicitly):**

    For 9b07bf7:
    ```bash
    # Q1: Does the diff touch #[cfg(target_os = "windows")] arms in terminal_approval.rs?
    git show 9b07bf7 -- crates/nono-cli/src/terminal_approval.rs | grep -c 'cfg.*windows' || echo "0"

    # Q2: Does the diff touch profile_save_runtime.rs Windows arms?
    git show 9b07bf7 -- crates/nono-cli/src/profile_save_runtime.rs | grep -c 'cfg.*windows' || echo "0"

    # Q3: Does the diff touch policy.rs Windows arms?
    git show 9b07bf7 -- crates/nono-cli/src/policy.rs | grep -c 'cfg.*windows' || echo "0"

    # Q4: Does the diff touch profile/mod.rs Windows arms?
    git show 9b07bf7 -- crates/nono-cli/src/profile/mod.rs | grep -c 'cfg.*windows' || echo "0"

    # Q5: Does the diff touch build_prompt_text or per-HandleKind surface?
    git show 9b07bf7 | grep -c 'build_prompt_text\|HandleKind\|per_kind' || echo "0"

    # Q6: Does the diff touch profile-drafts surface (promote, --draft, package_status)?
    git show 9b07bf7 | grep -c 'promote\|draft\|package_status\|ProfileDraft' || echo "0"
    ```

    **Step 3: Trial cherry-pick (dry run to detect conflict lines):**
    ```bash
    git cherry-pick --no-commit 9b07bf7 2>&amp;1
    # If conflicts found: note which files and which hunks; revert
    git cherry-pick --abort 2>/dev/null; git checkout .
    # Or: git reset --hard HEAD
    ```

    **Step 4: Disposition decision (apply D-40-B1 upgrade rule):**

    UPGRADE to will-sync IFF:
    - Trial cherry-pick exits 0 (zero conflicts)
    - Q1–Q6 all return 0 (no fork-only surface intersection)
    - Reviewing the 11-file diff confirms no behavioral surprise vs fork's existing suppression logic

    STAY D-20 manual replay if ANY of:
    - Trial cherry-pick has conflicts
    - Any Q1–Q6 returned > 0
    - 11-file diff shows behavioral surprise (new prompt forms, different approval flow)

    **Step 5: Document the disposition decision:**

    Write the ## Disposition resolution section (insert INLINE into this PLAN.md file after this task completes, OR commit a brief resolution note to main):

    ```markdown
    ## Disposition resolution (D-40-B1)

    Inspection date: 2026-05-XX
    Upstream shas inspected: 9b07bf7 (11 files) + eb6cb09 (1 file)

    Surface-overlap check results:
    - Q1 (terminal_approval.rs cfg-windows): N
    - Q2 (profile_save_runtime.rs cfg-windows): N
    - Q3 (policy.rs cfg-windows): N
    - Q4 (profile/mod.rs cfg-windows): N
    - Q5 (build_prompt_text/HandleKind): N
    - Q6 (promote/draft/package_status): N

    Trial cherry-pick result: [zero conflicts / N conflicts in files X, Y]

    FINAL DISPOSITION: [will-sync (D-19 cherry-pick) / D-20 manual replay]
    Justification: [...]
    ```

    Proceed to Task 2 only after disposition is documented.
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; git cat-file -t 9b07bf7 &amp;&amp; git cat-file -t eb6cb09</automated>
  </verify>
  <acceptance_criteria>
    - Wave 1 SUMMARY files both present (else BLOCKED).
    - Zero unfilled PLAN.md placeholders confirmed.
    - git show 9b07bf7 and git show eb6cb09 both run successfully and diffs read.
    - All 6 surface-overlap questions answered with numeric output.
    - Trial cherry-pick attempted and result recorded.
    - ## Disposition resolution section written with final WILL-SYNC or D-20 decision.
    - No code changes committed in this task.
  </acceptance_criteria>
  <done>
    Disposition documented. Proceed to Task 2.
  </done>
</task>

<task type="auto">
  <name>Task 2: Implement C4 disposition (cherry-pick OR manual replay)</name>
  <files>
    crates/nono-cli/src/profile_save_runtime.rs
    crates/nono-cli/src/terminal_approval.rs
    crates/nono-cli/src/policy.rs
    crates/nono-cli/src/profile/mod.rs
  </files>
  <read_first>
    - The ## Disposition resolution section from Task 1 (determines which branch to follow)
    - crates/nono-cli/src/profile_save_runtime.rs (current state before modifications)
    - crates/nono-cli/src/terminal_approval.rs (especially build_prompt_text and HandleKind variants)
    - crates/nono-cli/src/policy.rs (bypass_protection shape from Phase 36 D-36-B4)
    - git show 9b07bf7 (re-read for implementation reference)
    - git show eb6cb09 (re-read for implementation reference)
  </read_first>
  <action>
    Follow the branch determined by Task 1 disposition:

    **BRANCH A — WILL-SYNC (disposition upgraded to D-19 cherry-pick):**

    ```bash
    # Cherry-pick 9b07bf7 with D-19 trailer:
    git cherry-pick 9b07bf7
    # Resolve any residual conflicts (should be zero per Task 1 dry-run)
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit
    # Append D-19 trailer:
    # Upstream-commit: 9b07bf7
    # Upstream-tag: v0.52.2
    # Upstream-author: <from git show> <<email>>
    # Co-Authored-By: <from git show> <<email>>
    # Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    # Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>

    # Cherry-pick eb6cb09 with D-19 trailer:
    git cherry-pick eb6cb09
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit
    # Append D-19 trailer (Upstream-tag: v0.52.2)

    # Post-chain smoke:
    git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream-commit: '   # MUST be 2
    ```

    **BRANCH B — D-20 MANUAL REPLAY (conservative; disposition stays fork-preserve):**

    One commit per semantic change per D-40-B3. The two upstream commits map to 1-3 manual replay commits:

    Commit 1: Replay profile-save denial suppression intent
    ```bash
    # Manually implement the denied-path suppression behavior in profile_save_runtime.rs
    # and terminal_approval.rs, WITHOUT:
    # - Touching build_prompt_text per-HandleKind template (Phase 18.1 D-04 locked)
    # - Removing bypass_protection / override_deny serde aliases (Phase 36 D-36-B3)
    # - Colliding with Phase 36.5 promote/--draft surface
    # - Adding new Windows-gated code (D-40-E6)

    # Commit body MUST have all 5 D-40-B3 sections + Co-Authored-By per D-40-B3:
    git add -p   # Stage only the denial-suppression behavior changes
    git commit -m "$(cat <<'EOF'
    feat(profile-save): suppress save-profile prompts for denied paths

    Upstream intent: upstream feat(profile-save) (9b07bf7) suppresses profile-save
    prompts when paths are in the deny list, avoiding confusing UX where saving a
    profile includes prompts for paths the user explicitly denied.

    What was replayed: The core suppression gate — checking whether a path is in the
    effective deny list before emitting a save-profile prompt — replayed in
    profile_save_runtime.rs and terminal_approval.rs at the approve() call site.

    What was NOT replayed and why: The upstream commit's rewiring of build_prompt_text
    and per-HandleKind template dispatch in terminal_approval.rs was not replayed
    because those paths are D-04-locked per Phase 18.1 Plan 18.1-01. The upstream
    approval-flow restructuring would overwrite fork's per-HandleKind prompt surface.

    Fork-only wiring preserved:
    - crates/nono-cli/src/terminal_approval.rs: build_prompt_text per-HandleKind dispatch
      (Phase 18.1 Plan 18.1-01, D-04-locked)
    - crates/nono-cli/src/policy.rs: bypass_protection / override_deny serde alias
      (Phase 36 D-36-B4)
    - crates/nono-cli/src/profile/mod.rs: deprecated_schema integration + profile-drafts
      promote/--draft surface (Phase 36 REQ-PORT-CLOSURE-02, Phase 36.5 REQ-PORT-CLOSURE-03)

    Upstream-replayed-from: 9b07bf7

    Co-Authored-By: Claude <noreply@anthropic.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    Commit 2 (if eb6cb09 review fix adds meaningfully different behavior — otherwise fold into Commit 1):
    ```bash
    # If eb6cb09 adds distinct semantic fix worth separate commit:
    git commit -m "$(cat <<'EOF'
    fix(profile-save): address suppression review feedback

    Upstream intent: eb6cb09 review fix to the 9b07bf7 suppression feature.

    What was replayed: [specific behavior from review fix]

    What was NOT replayed and why: [if any — review fix may be simpler and fold cleanly]

    Fork-only wiring preserved: [same list as above if any files touched]

    Upstream-replayed-from: eb6cb09

    Co-Authored-By: Claude <noreply@anthropic.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **After EITHER branch:**
    ```bash
    cargo build --workspace
    git diff --stat HEAD~2 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    # Verify D-19 trailer count (if will-sync branch: should be 2; if D-20 branch: should be 0)
    git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream-commit: '
    # Verify D-40-B3 sections present (if D-20 branch):
    git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream intent:'   # >= 1 if D-20
    git log --format='%B' HEAD~2..HEAD | grep -c '^Fork-only wiring preserved:'   # >= 1 if D-20
    # Verify Phase 18.1 surface preserved:
    grep -c 'build_prompt_text\|HandleKind' crates/nono-cli/src/terminal_approval.rs   # Must be >= pre-Task-1 count
    ```
  </action>
  <verify>
    <automated>cargo build --workspace &amp;&amp; cargo test --workspace --all-features 2>&amp;1 | tail -5</automated>
  </verify>
  <acceptance_criteria>
    - If WILL-SYNC branch: 2 commits with D-19 trailers (Upstream-commit: × 2, Upstream-author: × 2 lowercase 'a').
    - If D-20 branch: 1-2 commits with all 5 D-40-B3 sections; NO Upstream-commit: lines; each commit body includes `Co-Authored-By: Claude <noreply@anthropic.com>` per D-40-B3.
    - Either branch: D-40-E1 zero Windows-file edits; `cargo build --workspace` exits 0.
    - Phase 18.1 surface: `grep -c 'build_prompt_text\|HandleKind' crates/nono-cli/src/terminal_approval.rs` >= pre-plan count.
    - profile/mod.rs deprecated_schema + profile-drafts surface intact.
    - `cargo test --workspace --all-features` exits 0.
  </acceptance_criteria>
  <done>
    C4 implementation complete; disposition documented and commits land per chosen branch.
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

    # Gate 3
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

    # D-19 or D-20 branch-specific smoke:
    # If will-sync: git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream-commit: '  # MUST be 2
    # If D-20 replay: git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream-commit: '  # MUST be 0
    # If D-20 replay: git log --format='%B' HEAD~2..HEAD | grep -c '^Fork-only wiring preserved:'  # MUST be >= 1
    # If D-20 replay: Co-Authored-By check (D-40-B3 requirement):
    git log --format='%B' HEAD~2..HEAD | grep -c '^Co-Authored-By: Claude'   # MUST equal D-20 replay commit count

    # D-40-E1 final:
    git diff --stat HEAD~2 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    ```
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <acceptance_criteria>
    - Gates 1+2+5: PASS. Gates 3+4+6+7+8: PASS or documented-skipped.
    - Branch-appropriate trailer or body section check passes.
    - If D-20 replay: `git log --format='%B' HEAD~N..HEAD | grep -c '^Co-Authored-By: Claude'` equals replay-commit count.
    - D-40-E1: 0 Windows-file edits.
  </acceptance_criteria>
  <done>
    Plan 40-05 close-gate cleared. Wave 2 Plan 40-06 may proceed.
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
    # Use appropriate PR title based on disposition:
    DISPOSITION=$(git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream-commit: ' | tr -d ' ')
    if [ "$DISPOSITION" = "2" ]; then
      LABEL="will-sync upgrade (D-19 cherry-pick)"
    else
      LABEL="D-20 manual replay (fork-preserve)"
    fi
    gh pr create \
      --title "Plan 40-05 (C4): Profile-save denial suppression — $LABEL (v0.52.2)" \
      --body "Wave 2 plan (depends on Wave 1: 40-01 + 40-04). Absorbs Cluster C4.

    Upstream commits: 9b07bf7 (suppress save-profile prompts for denied paths, 11 files) + eb6cb09 (review fix).

    Disposition: $LABEL (D-40-B1 diff-inspection completed in Task 1; ## Disposition resolution documented).
    D-40-E1 violations: 0. D-40-C2 gates: all pass.
    Phase 18.1 build_prompt_text per-HandleKind surface preserved.
    Part of Phase 40 UPST4 sync execution (REQ-UPST4-02)."
    ```
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline 2>/dev/null | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Pushed; PR created with correct disposition label; origin/main updated.
  </acceptance_criteria>
  <done>
    Plan 40-05 published; Plan 40-06 (FP-PROXY-TLS) may now proceed.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| save-profile UX → denial suppression gate | Suppression of prompts for denied paths; must not silently drop prompts for paths users DID allow |
| Upstream cherry-pick → fork-only per-HandleKind prompt surface | Cherry-pick of 9b07bf7 risks overwriting Phase 18.1 D-04-locked build_prompt_text |
| D-40-B1 upgrade rule → cherry-pick vs manual replay decision | Incorrect upgrade fires a cherry-pick that overwrites Phase 36/36.5 profile surface |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-40-05-01 | Tampering | D-40-E1 Windows-only files invariant | **HIGH** | mitigate (BLOCKING) | Per-commit grep gate; Windows-only sentinel unchanged |
| T-40-05-02 | Tampering | Cherry-pick overwrites Phase 18.1 build_prompt_text per-HandleKind surface | **HIGH** | mitigate (BLOCKING) | Task 1 Q5 check; if > 0 → MUST stay D-20; post-commit grep confirms build_prompt_text + HandleKind present |
| T-40-05-03 | Tampering | Cherry-pick overwrites Phase 36 bypass_protection rename or Phase 36.5 profile-drafts surface | **HIGH** | mitigate (BLOCKING) | Task 1 Q6 check; if > 0 → MUST stay D-20; post-commit grep confirms deprecated_schema + promote surface intact |
| T-40-05-04 | Elevation of Privilege | Suppression gate silently suppresses prompts for paths user ALLOWED (not denied) | **HIGH** | mitigate | Task 2: implementation must gate on effective deny list, not allow list; test that allowed paths still prompt |
| T-40-05-05 | Repudiation | D-19 trailer on D-20 manual replay commit body | **HIGH** | mitigate (BLOCKING) | D-20 commits MUST NOT have Upstream-commit: lines; post-commit `grep -c '^Upstream-commit: '` must equal 0 for D-20 branch |
| T-40-05-06 | Repudiation | D-40-B3 commit body sections absent on D-20 commits | medium | mitigate | Post-commit: `grep -c '^Upstream intent:' + '^Fork-only wiring preserved:'` must be >= 1 each |
</threat_model>

<verification>
- All 8 D-40-C2 close-gates pass.
- ## Disposition resolution section documented (will-sync or D-20).
- If will-sync: `git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream-commit: '` returns 2.
- If D-20: `git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream-commit: '` returns 0; D-40-B3 sections present; `grep -c '^Co-Authored-By: Claude'` equals replay-commit count.
- `git diff --stat HEAD~2 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns 0.
- Phase 18.1 surface: `grep -c 'build_prompt_text\|HandleKind' crates/nono-cli/src/terminal_approval.rs` >= pre-plan count.
- profile/mod.rs deprecated_schema + profile-drafts intact.
- origin/main advanced; PR created.
</verification>

<success_criteria>
- Diff-inspection completed (Task 1) with ## Disposition resolution documented BEFORE any code changes.
- C4 implementation committed per chosen branch (D-19 will-sync or D-40-B3 D-20 replay).
- Profile-save denial suppression behavior absorbed into fork.
- Phase 18.1 build_prompt_text per-HandleKind surface preserved (D-04 locked).
- Phase 36/36.5 profile surface intact.
- D-40-E1 invariant honored.
- All 8 D-40-C2 gates cleared.
- origin/main advanced; PR open.
</success_criteria>

<output>
After completion, create `.planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-SUMMARY.md`.
Include the ## Disposition resolution outcome in the SUMMARY so Phase 40 final close-out (40-SUMMARY.md) can reference it.
</output>
