---
phase: 40-upst4-sync-execution
plan: 06
slug: fp-proxy-tls
cluster_id: C5
type: execute
wave: 2
depends_on: ["40-05"]
files_modified:
  - crates/nono-proxy/src/credential.rs
  - crates/nono-proxy/src/route.rs
  - crates/nono-proxy/src/server.rs
  - crates/nono-proxy/src/tls_intercept/handle.rs
upstream_tag_range: v0.52.2..v0.53.0
upstream_commit_count: 3
autonomous: true
requirements: [REQ-UPST4-02]
tags: [upst4, c5, fork-preserve, proxy-tls, d20-manual-replay, credential-matching, wave-2]

must_haves:
  truths:
    - "All 3 cluster-C5 upstream commits read and understood BEFORE any code changes"
    - "D-20 manual replay (NO upgrade attempt per D-40-B2 — conservative disposition is LOCKED)"
    - "Credential-match policy semantics replayed: absolute-match + 2-matches-deny + no-match-passthrough-no-creds (f77e0e3)"
    - "TLS trust + auth intercept + multi-route dispatch intent replayed WITHOUT touching fork's Windows credential-injection rewrite (8ddb143)"
    - "Each manual-replay commit has all 5 D-40-B3 commit body sections"
    - "NO Upstream-commit: lines in any D-20 manual replay commit"
    - "D-40-E1 invariant: zero edits to *_windows.rs or exec_strategy_windows/ for every commit"
    - "Fork-only Windows credential-injection rewrite (Phase 09 + Phase 11) preserved byte-identically"
    - "All 8 D-40-C2 close-gates pass"
  artifacts:
    - path: "crates/nono-proxy/src/credential.rs"
      provides: "credential-match policy: absolute match / 2 matches deny / no match passthrough with no creds"
      grep_pattern: "absolute.*match\|two.*match.*deny\|no.*match.*passthrough\|passthrough.*no.*cred"
    - path: "crates/nono-proxy/src/route.rs"
      provides: "multi-route dispatch intent from 8ddb143"
      grep_pattern: "multi.*route\|route.*dispatch\|route.*match"
    - path: "crates/nono-proxy/src/tls_intercept/handle.rs"
      provides: "TLS trust fix from 8ddb143 replayed"
      grep_pattern: "tls.*trust\|trust.*root\|intercept.*auth"
  key_links:
    - from: "nono-proxy credential matching"
      to: "Windows credential-store fallback behavior"
      via: "credential.rs absolute-match / 2-matches-deny / no-match-passthrough intersects fork-only Windows path"
      pattern: "windows.*credential\|credential.*windows\|credential_store"
---

<objective>
Cluster C5 (upstream v0.52.2..v0.53.0, 3 commits): proxy TLS trust + intercept auth + multi-route dispatch + credential matching. CONSERVATIVE D-20 MANUAL REPLAY — NO upgrade attempt (D-40-B2 LOCKED).

Wave-2 sequential plan. Depends on Plan 40-05 (C4 profile-save, Wave 2 first) so that post-C4 profile/policy state is settled before C5 reads the proxy + policy interaction surface.

The three upstream commits:
- `8ddb143` feat: fix upstream TLS trust, intercept auth, and multi-route dispatch (4 files: route.rs, credential.rs, server.rs, tls_intercept/handle.rs)
- `54c7552` fix: review comments (1 file — follow-on to 8ddb143)
- `f77e0e3` fix: absolute match / 2 matches = deny / no match = passthrough w no creds (2 files)

The fork's `crates/nono-proxy/src/credential.rs` was REWRITTEN on `windows-squash` for Windows credential injection (Phase 09 + Phase 11). Cherry-picking 8ddb143 directly would merge into the rewritten path. This plan replays the INTENT without the FORM.

Critical semantic contract from f77e0e3 that MUST be replayed because it intersects Windows credential-store fallback behavior: "absolute match / 2 matches = deny / no match = passthrough with no creds". This policy must be consciously adopted or rejected relative to the Windows-side credential-store fallback path.

Direct precedent: Phase 34 Plan 34-10 FP-PROXY-TLS replayed the analogous Phase 33 Cluster 11 surface.

Output: 2-4 D-20 manual replay commits (one per semantic change per D-40-B3); PR opened.
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
**Cluster C5 upstream commits (read ALL before touching fork code):**

| SHA | Tag | Subject | Files changed |
|-----|-----|---------|---------------|
| `8ddb143` | v0.53.0 | feat: fix upstream TLS trust, intercept auth, and multi-route dispatch. | 4 (route.rs, credential.rs, server.rs, tls_intercept/handle.rs) |
| `54c7552` | v0.53.0 | fix: review comments | 1 |
| `f77e0e3` | v0.53.0 | fix: absolute match / 2 matches = deny / no match = passthrough w no creds | 2 |

**D-40-B2 LOCK: no upgrade attempt.**
This is NOT like C4 where upgrade authority was granted. C5 is the direct follow-on to Phase 33 Cluster 11 (fork-preserve), which Phase 34 Plan 34-10 replayed. The same Windows credential-injection rewrite collision applies. D-40-B2 says: "keep conservative D-20 manual replay; no upgrade attempt." The executor MUST NOT attempt a trial cherry-pick of 8ddb143.

**D-40-B3 MANUAL REPLAY commit body sections (MANDATORY):**

Each commit MUST have:
```
Upstream intent: [what 8ddb143/54c7552/f77e0e3 was trying to do]

What was replayed: [the specific behavior carried into the fork]

What was NOT replayed and why: [upstream code/wiring that would collide with fork-only Windows surface]

Fork-only wiring preserved: [explicit list: credential.rs Windows injection, Phase 09 + 11 wiring symbols/paths]

Upstream-replayed-from: <sha>

Co-Authored-By: Claude <noreply@anthropic.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

Note: `Upstream-replayed-from:` does NOT trigger the `^Upstream-commit: ` grep; this is intentional.

**Fork-only Windows credential-injection surface (PRESERVE BYTE-IDENTICALLY):**
- `crates/nono-proxy/src/credential.rs` — Phase 09 + Phase 11 rewrite; Windows uses Windows Credential Manager via keyring v3. Read this file carefully BEFORE implementing any credential-match policy replay. The f77e0e3 policy semantics (absolute-match / 2-matches-deny / no-match-passthrough) must be implemented WITHOUT removing or overwriting the Windows Credential Manager path.
- `crates/nono-proxy/src/oauth2.rs` — Phase 22-04 OAuth2 credential cache; may be adjacent to credential.rs; do NOT touch unless audit of 8ddb143 diff shows it's in scope.

**Credential-match policy semantics from f77e0e3 (MUST be consciously replayed):**
- Absolute match (URL matches exactly one credential entry) → use that credential
- 2+ matches → DENY (ambiguous credential selection; fail secure)
- No match → PASSTHROUGH with no credentials injected
  - IMPORTANT: "no creds" passthrough intersects Windows credential-store fallback: if the Windows path has a fallback that injects credentials when no URL match exists, the f77e0e3 policy change makes that fallback semantically inconsistent. Document this explicitly in the commit body.

**Precedent for replay shape:**
- Phase 34 Plan 34-10-FP-PROXY-TLS-SUMMARY.md — read this for commit-body shape precedent
- Phase 26 Plan 26-01 PKGS-02 — D-40-B3 commit-body shape precedent

**Surface disjointness with Plan 40-05 (C4):**
- C5 touches nono-proxy/ (credential.rs, route.rs, server.rs, tls_intercept/)
- C4 touches nono-cli/ (profile_save_runtime.rs, terminal_approval.rs, policy.rs, profile/mod.rs)
- Plan 40-05 must be CLOSED before Plan 40-06 starts (Wave 2 sequential per D-40-A2).
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — read upstream diffs + fork-only surface audit</name>
  <files>(read-only — no code changes)</files>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-SUMMARY.md (verify Plan 40-05 closed)
    - .planning/phases/40-upst4-sync-execution/40-CONTEXT.md § D-40-B2 (lock — no upgrade), D-40-B3 (replay body)
    - .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md § Cluster C5
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-10-FP-PROXY-TLS-SUMMARY.md (direct precedent)
    - crates/nono-proxy/src/credential.rs (read the FULL file — know every symbol before touching anything)
    - crates/nono-proxy/src/route.rs (read current routing structure)
    - crates/nono-proxy/src/server.rs (read current server.rs — know what C1 already changed in Wave 1)
    - crates/nono-proxy/src/tls_intercept/handle.rs (read current TLS intercept handle)
  </read_first>
  <action>
    **Step 0: Verify Plan 40-05 closed + placeholder smoke check:**
    ```bash
    test -f .planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-SUMMARY.md || echo "BLOCKED: Plan 40-05 not closed"
    grep -oE '\{[a-z_]+\}' .planning/phases/40-upst4-sync-execution/40-06-FP-PROXY-TLS-PLAN.md | wc -l  # Expected: 0
    ```

    **Step 1: Fetch upstream + read all 3 C5 diffs:**
    ```bash
    git fetch upstream --tags
    git cat-file -t 8ddb143   # Expected: commit
    git cat-file -t 54c7552   # Expected: commit
    git cat-file -t f77e0e3   # Expected: commit
    git show 8ddb143   # Read FULL 4-file diff — most important
    git show 54c7552   # Read review-comments fix
    git show f77e0e3   # Read credential-match policy diff
    ```

    **Step 2: Map upstream intent vs fork-only surface:**
    For each file touched by 8ddb143:
    ```bash
    # route.rs: what does upstream add? multi-route dispatch logic?
    git show 8ddb143 -- crates/nono-proxy/src/route.rs | head -100

    # credential.rs: what does upstream add? This is the collision file.
    git show 8ddb143 -- crates/nono-proxy/src/credential.rs | head -200
    # Cross-reference with fork's credential.rs Windows injection wiring:
    grep -n 'windows\|Windows\|keyring\|Credential\|credential_store' crates/nono-proxy/src/credential.rs

    # server.rs: upstream vs fork's Wave-1 Plan 40-01 changes
    git show 8ddb143 -- crates/nono-proxy/src/server.rs | head -100

    # tls_intercept/handle.rs: what TLS trust fix is upstream applying?
    git show 8ddb143 -- crates/nono-proxy/src/tls_intercept/handle.rs
    ```

    **Step 3: f77e0e3 credential-match policy — Windows fallback audit:**
    ```bash
    git show f77e0e3   # Read credential-match policy change
    # Explicitly determine: does the fork's Windows Credential Manager path have a
    # "no match → fallback with injected creds" behavior?
    grep -n 'fallback\|no_match\|passthrough\|NoMatch' crates/nono-proxy/src/credential.rs
    # Document the answer: YES (fork has fallback) or NO (fork already has no-creds passthrough)
    ```

    **Step 4: Plan the replay commits:**
    Decide how to map 3 upstream commits to replay commits. Options:
    - 3 replay commits (one per upstream sha) — preferred for bisect per D-40-B3
    - 2 replay commits (8ddb143 + 54c7552 folded as feature+fix; f77e0e3 separate for policy semantics)
    Document the commit plan before proceeding to Task 2.

    **Step 5: Record Windows-only sentinel:**
    ```bash
    git log -1 --format='%H' -- crates/nono-cli/src/exec_strategy_windows/
    ```
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; git cat-file -t 8ddb143 &amp;&amp; git cat-file -t f77e0e3</automated>
  </verify>
  <acceptance_criteria>
    - Plan 40-05 SUMMARY present (else BLOCKED).
    - Zero unfilled PLAN.md placeholders confirmed.
    - All 3 C5 SHAs reachable.
    - Full diffs of all 3 commits read and understood.
    - Fork-only credential.rs Windows injection surface inventoried.
    - f77e0e3 policy semantics understood relative to Windows fallback behavior.
    - Replay commit plan documented (2 or 3 commits).
    - Windows-only sentinel recorded.
    - NO code changes in this task.
  </acceptance_criteria>
  <done>
    Upstream diffs read; fork-only surface audited; replay plan documented. Proceed to Task 2.
  </done>
</task>

<task type="auto">
  <name>Task 2: D-20 manual replay — TLS trust + multi-route + credential matching</name>
  <files>
    crates/nono-proxy/src/credential.rs
    crates/nono-proxy/src/route.rs
    crates/nono-proxy/src/server.rs
    crates/nono-proxy/src/tls_intercept/handle.rs
  </files>
  <read_first>
    - The replay commit plan from Task 1 (determines how many commits)
    - crates/nono-proxy/src/credential.rs (re-read current state — FULL FILE)
    - crates/nono-proxy/src/route.rs (re-read current state)
    - crates/nono-proxy/src/tls_intercept/handle.rs (re-read current state)
    - git show 8ddb143 (re-read for implementation reference)
    - git show f77e0e3 (re-read policy semantics for implementation reference)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-10-FP-PROXY-TLS-SUMMARY.md (commit body precedent)
  </read_first>
  <action>
    Implement per the Task 1 replay plan. Suggested commit grouping:

    **Replay Commit 1: TLS trust + multi-route dispatch + auth intercept (replaying 8ddb143 + 54c7552 intent)**

    For each of the 4 files 8ddb143 touches:
    - `route.rs`: replay multi-route dispatch logic. Do NOT import upstream's entire routing struct if it conflicts with fork's routing; instead port the dispatch algorithm.
    - `tls_intercept/handle.rs`: replay upstream's TLS trust fix. If upstream's change is structural (new parameters, new types), port the structural intent.
    - `server.rs`: replay any server-side changes from 8ddb143 that do NOT conflict with Plan 40-01's C1 review fixes already landed in Wave 1.
    - `credential.rs`: THIS IS THE CRITICAL FILE. Do NOT cherry-pick upstream's credential matching code directly. Instead:
      1. Read upstream's new credential-matching API surface (from git show 8ddb143 -- credential.rs)
      2. Identify what NEW behavior upstream introduced (not what it replaced)
      3. Add the new behavior ALONGSIDE fork's Windows Credential Manager path
      4. Gate Windows-specific fallback behind existing #[cfg(target_os = "windows")] arms

    ```bash
    # After implementing replay changes:
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    # Verify fork-only Windows credential path still present:
    grep -c 'cfg.*windows\|windows.*credential\|keyring\|Credential.*Manager' crates/nono-proxy/src/credential.rs
    # Must be >= pre-task count (not shrunk)

    git add -p   # Stage carefully — only replay changes, not accidental upstream code verbatim
    git commit -m "$(cat <<'EOF'
    feat(proxy): replay TLS trust fix + multi-route dispatch + auth intercept intent

    Upstream intent: 8ddb143 fixes upstream TLS trust root handling, adds auth
    intercept support, and implements multi-route dispatch in nono-proxy. The
    review fix 54c7552 addresses post-review comments.

    What was replayed: Multi-route dispatch algorithm in route.rs; TLS trust root
    fix in tls_intercept/handle.rs; server.rs auth intercept plumbing that does
    not conflict with Wave-1 Plan 40-01 (C1) review fixes already landed.

    What was NOT replayed and why: The upstream credential.rs rewrite (8ddb143's
    largest change) was NOT replayed directly because the fork's credential.rs was
    rewritten on windows-squash for Windows credential injection via Windows
    Credential Manager (Phase 09 + Phase 11). A direct cherry-pick would have
    deleted the Windows injection path. Instead, the new credential-lookup API
    surface from 8ddb143 was ported alongside the existing Windows injection code.

    Fork-only wiring preserved:
    - crates/nono-proxy/src/credential.rs: Windows Credential Manager injection
      path (Phase 09 + Phase 11 rewrite; #[cfg(target_os = "windows")] arms)
    - crates/nono-proxy/src/oauth2.rs: Phase 22-04 OAuth2 credential cache (not
      touched by this replay)

    Upstream-replayed-from: 8ddb143 54c7552

    Co-Authored-By: Claude <noreply@anthropic.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Replay Commit 2: Credential-match policy semantics (replaying f77e0e3 intent)**

    This is the most security-critical replay. The policy "absolute match / 2 matches = deny / no match = passthrough w no creds" MUST be replayed because it defines credential selection behavior that intersects the Windows-side credential-store fallback. Document the Windows fallback decision explicitly:

    ```bash
    # Implement f77e0e3 credential-match policy in credential.rs:
    # - Exact-URL match → inject that credential
    # - 2+ URL matches → DENY (fail secure; don't guess which credential to inject)
    # - No match → PASSTHROUGH with no credentials (no creds injected)
    # Windows path: if fork's Windows path has a fallback that injects creds when no URL match,
    # decide whether to:
    #   Option A: Apply upstream's "no match = passthrough no creds" uniformly (changes Windows behavior)
    #   Option B: Retain Windows fallback but add a WARNING log noting the inconsistency
    # Document the choice in the commit body.

    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    # Verify policy semantics present:
    grep -c 'passthrough\|no.*cred\|two.*match\|absolute.*match\|2.*match' crates/nono-proxy/src/credential.rs

    git add crates/nono-proxy/src/credential.rs
    git commit -m "$(cat <<'EOF'
    fix(proxy): replay credential-match policy — absolute-match / 2-match-deny / no-match-passthrough

    Upstream intent: f77e0e3 defines credential selection semantics: exact URL match
    injects that credential; 2+ matches deny the request (ambiguous selection; fail
    secure); no match passes through with no credentials injected.

    What was replayed: The three-case selection logic implemented in credential.rs
    alongside the existing Windows Credential Manager path. The 2-match-deny behavior
    strengthens the fork's security posture (fail secure on ambiguous credential
    selection is the correct behavior on all platforms).

    What was NOT replayed and why: The upstream credential.rs structure changes
    (new types, new function signatures) were not replayed directly — the fork's
    credential.rs has a structurally different Windows injection surface. The policy
    semantics were replayed as behavioral changes within the existing structure.

    Fork-only wiring preserved:
    - crates/nono-proxy/src/credential.rs Windows Credential Manager injection
      (Phase 09 + Phase 11). Decision on Windows fallback behavior: [document
      choice made: Option A (uniform no-creds passthrough) or Option B (retain
      fallback with warning log)].

    Windows fallback note: [document whether the Windows Credential Manager
    fallback is preserved, modified, or suppressed by this replay and why]

    Upstream-replayed-from: f77e0e3

    Co-Authored-By: Claude <noreply@anthropic.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Post-chain smoke:**
    ```bash
    COMMIT_COUNT=2   # Adjust if replay plan chose 3 commits
    git log --format='%B' HEAD~${COMMIT_COUNT}..HEAD | grep -c '^Upstream-commit: '   # MUST be 0
    git log --format='%B' HEAD~${COMMIT_COUNT}..HEAD | grep -c '^Upstream-replayed-from: '   # MUST be >= 1
    git log --format='%B' HEAD~${COMMIT_COUNT}..HEAD | grep -c '^Fork-only wiring preserved:'   # MUST be >= 1
    git log --format='%B' HEAD~${COMMIT_COUNT}..HEAD | grep -c '^Upstream intent:'   # MUST be >= 1
    git log --format='%B' HEAD~${COMMIT_COUNT}..HEAD | grep -c '^Co-Authored-By: Claude'   # MUST equal COMMIT_COUNT
    git log -1 --format='%H' -- crates/nono-cli/src/exec_strategy_windows/
    # MUST equal PRE_PLAN_WINDOWS_SHA from Task 1
    ```
  </action>
  <verify>
    <automated>cargo build --workspace &amp;&amp; grep -c 'Upstream-replayed-from' .git/COMMIT_EDITMSG 2>/dev/null || cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 2-3 manual replay commits (per Task 1 plan), each with all 5 D-40-B3 sections.
    - NO `Upstream-commit:` lines in any commit body (not D-19 cherry-picks).
    - Each D-20 replay commit body includes `Co-Authored-By: Claude <noreply@anthropic.com>` per D-40-B3; `git log --format='%B' HEAD~N..HEAD | grep -c '^Co-Authored-By: Claude'` equals replay-commit count.
    - D-40-E1: `git diff --stat HEAD~2 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns 0.
    - Windows-only sentinel SHA unchanged from Task 1 baseline.
    - `grep -c 'cfg.*windows\|windows.*credential\|keyring' crates/nono-proxy/src/credential.rs` >= pre-task count (Windows injection preserved).
    - f77e0e3 credential-match policy: absolute-match, 2-match-deny, no-match-passthrough logic present in credential.rs.
    - Windows fallback decision documented in Replay Commit 2 body.
    - `cargo build --workspace` exits 0.
  </acceptance_criteria>
  <done>
    C5 manual replay complete; TLS trust + multi-route dispatch + credential-match policy absorbed; Windows injection preserved.
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
    COMMIT_COUNT=2   # Adjust to match Task 2 actual commit count

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

    # D-20 smoke (MUST NOT have Upstream-commit: lines):
    git log --format='%B' HEAD~${COMMIT_COUNT}..HEAD | grep -c '^Upstream-commit: '   # MUST be 0
    # D-40-B3 section smoke:
    git log --format='%B' HEAD~${COMMIT_COUNT}..HEAD | grep -c '^Fork-only wiring preserved:'   # MUST be >= 1
    # D-40-B3 Co-Authored-By smoke (D-40-B3 requirement):
    git log --format='%B' HEAD~${COMMIT_COUNT}..HEAD | grep -c '^Co-Authored-By: Claude'   # MUST equal COMMIT_COUNT

    # D-40-E1 final:
    git diff --stat HEAD~${COMMIT_COUNT} HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0

    # REQ-UPST4-02 acceptance criterion 5 — fork-defense grep baselines preserved or grown:
    # (examples — adapt to actual fork-defense patterns)
    grep -r 'validate_path_within' crates/nono-proxy/src/ | wc -l
    # Must be >= pre-plan count (if validate_path_within used in proxy — else skip)
    ```
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <acceptance_criteria>
    - Gates 1+2+5: PASS. Gates 3+4+6+7+8: PASS or documented-skipped.
    - `git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream-commit: '` returns 0 (confirmed D-20 replay, not cherry-pick).
    - `git log --format='%B' HEAD~N..HEAD | grep -c '^Fork-only wiring preserved:'` returns >= 1.
    - `git log --format='%B' HEAD~N..HEAD | grep -c '^Co-Authored-By: Claude'` equals replay-commit count (D-40-B3 Co-Authored-By verified).
    - D-40-E1: 0 Windows-file edits across the replay chain.
    - Windows credential injection grep baseline preserved.
  </acceptance_criteria>
  <done>
    Plan 40-06 close-gate cleared. Phase 40 all-plans close-gate now complete (40-01 through 40-06).
  </done>
</task>

<task type="auto">
  <name>Task 4: Push + PR + Phase 40 close-out note</name>
  <files>(git push only)</files>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-CONTEXT.md § D-40-C1, D-40-D1
  </read_first>
  <action>
    1. Push and open PR:
       ```bash
       git push origin main
       gh pr create \
         --title "Plan 40-06 (C5): Proxy TLS trust + multi-route dispatch + credential-match policy — D-20 manual replay (v0.53.0)" \
         --body "$(cat <<'EOF'
       Wave 2 sequential plan (depends on 40-05). Final fork-preserve cluster. Absorbs Cluster C5 (3 commits) via D-20 manual replay per D-40-B2 (no upgrade attempt):

       - 8ddb143: TLS trust fix + auth intercept + multi-route dispatch — replayed intent without touching fork-only Windows credential-injection rewrite
       - 54c7552: review comments — folded into Replay Commit 1
       - f77e0e3: credential-match policy (absolute-match / 2-match-deny / no-match-passthrough) — replayed as Replay Commit 2; Windows fallback decision documented

       D-20 replay commits: Upstream-commit lines: 0. D-40-B3 sections: all present.
       D-40-E1 violations: 0. D-40-C2 gates: all pass.
       Fork's Windows credential injection (Phase 09 + 11) preserved byte-identically.
       Part of Phase 40 UPST4 sync execution (REQ-UPST4-02).
       EOF
       )"
       ```

    2. Phase 40 all-plans closure note:
       All 6 plans closed. The 40-SUMMARY.md (phase close-out) should include:
       - Cluster 3 (PTY scrollback) won't-sync inline section per D-40-D1:
         "Cluster 3 (PTY scrollback) won't-sync per Phase 39 DIVERGENCE-LEDGER row + Phase 33 Cluster 1 same-class precedent (D-11 excluded; Phase 17 + Phase 30 already satisfied Windows scrollback requirement)."
       This section is written in the final 40-SUMMARY.md after this plan closes — no separate plan or file needed.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline 2>/dev/null | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Pushed; PR created; origin/main updated.
    - Phase 40 all-plans close-out complete (6/6 plans).
  </acceptance_criteria>
  <done>
    Plan 40-06 published. Phase 40 UPST4 sync execution complete (REQ-UPST4-02 all acceptance criteria met).
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| nono-proxy credential lookup → credential injection | Credential-match policy governs which credential (if any) is injected into proxy requests |
| Upstream manual replay → fork Windows credential path | Replay of 8ddb143 must not overwrite Phase 09 + Phase 11 Windows injection surface |
| f77e0e3 no-match passthrough → Windows Credential Manager fallback | Policy change intersects fork-only Windows fallback behavior |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-40-06-01 | Tampering | D-40-E1 Windows-only files invariant | **HIGH** | mitigate (BLOCKING) | Per-commit grep gate; Windows-only sentinel unchanged |
| T-40-06-02 | Repudiation | Upstream-commit: trailer appears in D-20 replay commit (means wrong commit type) | **HIGH** | mitigate (BLOCKING) | Post-chain: `grep -c '^Upstream-commit: '` MUST return 0; if > 0 → wrong branch; revert |
| T-40-06-03 | Elevation of Privilege | 8ddb143 replay removes fork's Windows credential injection path (Phase 09 + 11) | **HIGH** | mitigate (BLOCKING) | credential.rs Windows injection grep baseline: `grep -c 'cfg.*windows\|keyring' crates/nono-proxy/src/credential.rs` >= pre-task count; Task 1 reads full file before any edit |
| T-40-06-04 | Elevation of Privilege | f77e0e3 "no match = passthrough no creds" silently disables Windows Credential Manager fallback | **HIGH** | mitigate | Task 2 Replay Commit 2 explicitly documents the Windows fallback decision in commit body (Option A or B); auditor can review the decision |
| T-40-06-05 | Spoofing | 2-match-deny policy not replayed — ambiguous credential selection proceeds with first match | **HIGH** | mitigate | Replay Commit 2 explicitly implements 2-match-deny; post-replay grep confirms pattern present in credential.rs |
| T-40-06-06 | Information Disclosure | TLS intercept trust root change (8ddb143 tls_intercept/handle.rs) weakens certificate pinning | medium | mitigate | Read git show 8ddb143 -- tls_intercept/handle.rs BEFORE replay; if it modifies root trust anchor behavior, document in Replay Commit 1 body what was accepted vs rejected |
| T-40-06-07 | Repudiation | D-40-B3 commit body sections absent (Upstream intent / What was NOT replayed / Fork-only wiring preserved) | medium | mitigate (BLOCKING) | Post-chain: `grep -c '^Fork-only wiring preserved:'` >= 1; `grep -c '^Upstream intent:'` >= 1 |
</threat_model>

<verification>
- All 8 D-40-C2 close-gates pass.
- `git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream-commit: '` returns 0 (D-20 replay confirmed).
- `git log --format='%B' HEAD~N..HEAD | grep -c '^Fork-only wiring preserved:'` returns >= 1.
- `git log --format='%B' HEAD~N..HEAD | grep -c '^Upstream intent:'` returns >= 1.
- `git log --format='%B' HEAD~N..HEAD | grep -c '^Co-Authored-By: Claude'` equals replay-commit count (D-40-B3 Co-Authored-By verified).
- `git diff --stat HEAD~N HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns 0.
- `grep -c 'cfg.*windows\|keyring' crates/nono-proxy/src/credential.rs` >= pre-plan count.
- f77e0e3 policy semantics: `grep -c 'passthrough\|no.*cred\|two.*match\|2.*match' crates/nono-proxy/src/credential.rs` >= 1.
- Windows fallback decision documented in Replay Commit 2 body.
- REQ-UPST4-02 acceptance criterion 5: fork-defense grep baselines preserved or grown.
- origin/main advanced; PR created.
</verification>

<success_criteria>
- 2-3 D-40-B3 manual replay commits on main (no D-19 trailers).
- Proxy TLS trust + multi-route dispatch intent absorbed.
- Credential-match policy semantics (absolute-match / 2-match-deny / no-match-passthrough) replayed in fork.
- Fork-only Windows credential injection (Phase 09 + 11) preserved byte-identically.
- Windows Credential Manager fallback decision explicitly documented in commit body.
- D-40-E1 invariant honored.
- All 8 D-40-C2 gates cleared.
- Phase 40 UPST4 sync execution complete: 6/6 plans executed; REQ-UPST4-02 met.
- origin/main advanced; PR open.
</success_criteria>

<output>
After completion, create `.planning/phases/40-upst4-sync-execution/40-06-FP-PROXY-TLS-SUMMARY.md`.

The SUMMARY must include:
1. Which 2-3 upstream commits were replayed and how many replay commits were created.
2. The Windows fallback decision (Option A or B from Task 2).
3. The `## Won't-sync clusters from Phase 39 ledger` section (D-40-D1):
   "Cluster 3 (PTY scrollback) won't-sync per Phase 39 DIVERGENCE-LEDGER row + Phase 33 Cluster 1 same-class precedent (D-11 excluded; Phase 17 + Phase 30 already satisfied Windows scrollback requirement)."
4. Phase 40 all-plans close confirmation (6/6 plans complete; REQ-UPST4-02 acceptance criteria 1–5 met).
</output>
