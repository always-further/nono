---
phase: 40-upst4-sync-execution
plan: 01
slug: proxy-hardening
cluster_id: C1
type: execute
wave: 1
depends_on: ["40-02", "40-03"]
files_modified:
  - crates/nono-proxy/src/server.rs
  - Cargo.toml
upstream_tag_range: v0.52.0..v0.52.1
upstream_commit_count: 5
autonomous: true
requirements: [REQ-UPST4-02]
tags: [upst4, c1, proxy, network, libdbus, node26, wave-1]

must_haves:
  truths:
    - "All 5 cluster-C1 commits cherry-picked onto main in upstream chronological order"
    - "Every Plan 40-01 commit body carries the verbatim D-19 6-line trailer block (lowercase 'a' in Upstream-author)"
    - "5e6e7ca — Update crates/nono-proxy/src/server.rs (review fix 1)"
    - "eedfbcd — Update crates/nono-proxy/src/server.rs (review fix 2)"
    - "be8cd00 — fix: provide more accurate warning message + doc comment update"
    - "abc86f6 — fix: prevent feature unification from linking libdbus in no-keyring builds"
    - "d57375e — fix(proxy): set NODE_USE_ENV_PROXY for Node 26"
    - "D-40-E1 invariant: zero edits to *_windows.rs or exec_strategy_windows/ for every commit"
    - "D-40-E6 surgical posture: NO fork-side WFP or Windows-credential-injection wiring added during cherry-picks"
    - "Cluster 5 (proxy TLS + credential matching) NOT touched — that is Plan 40-06 scope"
    - "All 8 D-40-C2 close-gates pass"
  artifacts:
    - path: "crates/nono-proxy/src/server.rs"
      provides: "review fixes (5e6e7ca, eedfbcd, be8cd00) + NODE_USE_ENV_PROXY for Node 26 (d57375e)"
      grep_pattern: "NODE_USE_ENV_PROXY|warning.*message|doc comment"
    - path: "Cargo.toml"
      provides: "libdbus feature-unification fix (abc86f6) — no-keyring builds avoid libdbus linkage"
      grep_pattern: "keyring|dbus|no-keyring"
  key_links:
    - from: "abc86f6 Cargo.toml feature flag"
      to: "no-keyring build path on Windows MSI installs"
      via: "Cargo feature unification avoidance"
      pattern: "keyring.*feature|feature.*keyring|dbus.*optional"
---

<objective>
Cluster C1 (upstream v0.52.0..v0.52.1, 5 commits): proxy/server.rs review fixes + libdbus feature-unification fix + NODE_USE_ENV_PROXY for Node 26 + accurate warning message + doc comment update.

Wave-1 plan. Depends on Wave-0 (40-02 + 40-03 closed) so that downstream SandboxState shape and nono::scrub re-export are established before proxy hardening lands. Runs in parallel with Plan 40-04 (Cluster 7 release ride-alongs) — surfaces are disjoint (C1 touches nono-proxy/src/server.rs + Cargo.toml; C7 touches nono/src/sandbox/linux.rs + Cargo.toml version bumps).

STOP: Cluster C5 (proxy TLS trust + credential matching) is Plan 40-06 scope — do NOT cherry-pick any C5 SHAs (8ddb143, 54c7552, f77e0e3) in this plan. This plan is C1 only.

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
**Cluster C1 cherry-pick chain (5 commits, chronological):**

| Order | SHA | Tag | Subject | Files changed | Upstream Author |
|-------|-----|-----|---------|---------------|-----------------|
| 1 | `5e6e7ca` | v0.52.1 | Update crates/nono-proxy/src/server.rs | 1 | unknown (upstream) |
| 2 | `eedfbcd` | v0.52.1 | Update crates/nono-proxy/src/server.rs | 1 | unknown (upstream) |
| 3 | `be8cd00` | v0.52.1 | fix: provide more accurate warning message + doc comment update | 1 | unknown (upstream) |
| 4 | `abc86f6` | v0.52.1 | fix: prevent feature unification from linking libdbus in no-keyring builds | 2 | unknown (upstream) |
| 5 | `d57375e` | v0.52.1 | fix(proxy): set NODE_USE_ENV_PROXY for Node 26 | 1 | unknown (upstream) |

**D-19 trailer shape:**

```
Upstream-commit: <8-char-sha>
Upstream-tag: v0.52.1
Upstream-author: <Name> <<email>>
Co-Authored-By: <Name> <<email>>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

**abc86f6 special attention:**
- Touches 2 files: crates/nono-proxy/src/server.rs + Cargo.toml (feature flags)
- Purpose: prevents feature-graph unification from pulling in libdbus on builds that use `--no-default-features` or no-keyring feature
- Fork context: Windows MSI installs do NOT have libdbus; this fix is critically important for fork's Windows distribution path (Windows uses Windows Credential Manager via keyring v3, not libsecret/dbus)
- If cherry-pick conflicts in Cargo.toml: preserve fork's [features] section that configures Windows keyring; apply upstream's no-keyring/dbus isolation around it

**d57375e special attention:**
- NODE_USE_ENV_PROXY was added because Node 26 changed HTTP_PROXY/HTTPS_PROXY env semantics
- Composes cleanly with fork's proxy interception path; no Windows-specific wiring needed
- D-40-E6: do NOT wire NODE_USE_ENV_PROXY into Windows-specific exec path

**Fork-divergence from template catalog:**
- `nono-proxy/src/oauth2.rs` (Phase 22-04 OAuth2): C1 does NOT touch oauth2.rs, only server.rs; no conflict expected
- If server.rs conflicts exist: read upstream diff first; resolve by accepting upstream changes around fork's Windows credential-injection wiring (which is in credential.rs, not server.rs — C5 owns that surface)
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — verify Wave 0 closed + fetch upstream</name>
  <files>(git operations only)</files>
  <read_first>
    - .planning/phases/40-upst4-sync-execution/40-CONTEXT.md § D-40-A2 (Wave 1 depends on Wave 0)
    - .planning/phases/40-upst4-sync-execution/40-02-CLI-ALLOW-VALIDATE-SUMMARY.md (verify Wave 0 Plan 40-02 closed)
    - .planning/phases/40-upst4-sync-execution/40-03-SCRUB-MODULE-SUMMARY.md (verify Wave 0 Plan 40-03 closed)
  </read_first>
  <action>
    1. Verify Wave 0 closed (both 40-02 + 40-03 SUMMARY files exist):
       ```bash
       test -f .planning/phases/40-upst4-sync-execution/40-02-CLI-ALLOW-VALIDATE-SUMMARY.md || echo "BLOCKED: Wave 0 Plan 40-02 not closed"
       test -f .planning/phases/40-upst4-sync-execution/40-03-SCRUB-MODULE-SUMMARY.md || echo "BLOCKED: Wave 0 Plan 40-03 not closed"
       ```
    2. Verify nono::scrub is exported from lib.rs (Wave 0 foundation):
       ```bash
       grep -E 'pub.*scrub|mod scrub' crates/nono/src/lib.rs   # Must return >= 1 line
       ```
    3. Fetch upstream + verify C1 SHAs:
       ```bash
       git fetch upstream --tags
       for sha in 5e6e7ca eedfbcd be8cd00 abc86f6 d57375e; do
         git cat-file -t $sha || echo "MISSING: $sha"
       done
       ```
    4. Verify C5 SHAs (8ddb143, 54c7552, f77e0e3) are NOT in the planned cherry-pick range for this plan.
    5. Record Windows-only sentinel:
       ```bash
       git log -1 --format='%H' -- crates/nono-cli/src/exec_strategy_windows/
       ```
    6. Baseline build:
       ```bash
       cargo build --workspace
       ```
    7. Verify no unfilled placeholders in this PLAN.md (D-40-E5):
       ```bash
       grep -oE '\{[a-z_]+\}' .planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-PLAN.md | wc -l  # Expected: 0
       ```
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - Wave 0 SUMMARY files both present; nono::scrub exported from lib.rs; all 5 C1 SHAs reachable; Windows-only sentinel recorded; baseline build green; zero unfilled PLAN.md placeholders.
  </acceptance_criteria>
  <done>
    Ready for C1 chain.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 5 C1 commits with D-19 trailers</name>
  <files>
    crates/nono-proxy/src/server.rs
    Cargo.toml
  </files>
  <read_first>
    - crates/nono-proxy/src/server.rs (read current proxy server structure before cherry-picks)
    - Cargo.toml (read current [features] section — understand keyring/dbus feature graph before abc86f6)
    - git show 5e6e7ca eedfbcd be8cd00 abc86f6 d57375e (read ALL 5 diffs before any cherry-pick)
    - .planning/templates/upstream-sync-quick.md § Fork-divergence catalog (Conflict-file inventory for nono-proxy paths)
    - .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md § Cluster C1 row
  </read_first>
  <action>
    Read all 5 diffs via `git show` before touching anything. Then cherry-pick in order.

    **Commit 1/5: 5e6e7ca (Update crates/nono-proxy/src/server.rs)**
    ```bash
    git show 5e6e7ca
    git cherry-pick 5e6e7ca
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit   # Append trailer
    # Upstream-commit: 5e6e7ca
    # Upstream-tag: v0.52.1
    # Upstream-author: <from git show> <<email>>
    # Co-Authored-By: <from git show> <<email>>
    # Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    # Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    ```

    **Commit 2/5: eedfbcd (Update crates/nono-proxy/src/server.rs)**
    ```bash
    git show eedfbcd
    git cherry-pick eedfbcd
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit   # Append trailer (Upstream-tag: v0.52.1)
    ```

    **Commit 3/5: be8cd00 (fix: provide more accurate warning message + doc comment update)**
    ```bash
    git show be8cd00
    git cherry-pick be8cd00
    cargo build --workspace
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit   # Append trailer (Upstream-tag: v0.52.1)
    ```

    **Commit 4/5: abc86f6 (fix: prevent feature unification from linking libdbus in no-keyring builds)**
    This commit touches 2 files (server.rs + Cargo.toml). Pay special attention to Cargo.toml conflict resolution:
    ```bash
    git show abc86f6
    git cherry-pick abc86f6
    # If Cargo.toml conflicts:
    # - Accept upstream's no-keyring / dbus feature isolation
    # - Preserve fork's existing Windows-keyring [features] entries
    # - Do NOT remove fork's 'keyring = ["keyring"]' or Windows-specific feature flags
    cargo build --workspace
    # Verify libdbus not pulled in on no-default-features build:
    cargo build --workspace --no-default-features 2>&amp;1 | grep -i dbus | grep -v 'optional\|feature' || echo "OK: libdbus not linked without keyring feature"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    git commit --amend --no-edit   # Append trailer (Upstream-tag: v0.52.1)
    ```

    **Commit 5/5: d57375e (fix(proxy): set NODE_USE_ENV_PROXY for Node 26)**
    ```bash
    git show d57375e
    git cherry-pick d57375e
    cargo build --workspace
    grep -r 'NODE_USE_ENV_PROXY' crates/nono-proxy/src/server.rs   # Must appear
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # MUST be 0
    # D-40-E6: verify no Windows-exec wiring for NODE_USE_ENV_PROXY
    grep -r 'NODE_USE_ENV_PROXY' crates/nono-cli/src/exec_strategy_windows/ 2>/dev/null | wc -l   # Expected: 0
    git commit --amend --no-edit   # Append trailer (Upstream-tag: v0.52.1)
    ```

    **Post-chain smoke:**
    ```bash
    git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: '   # MUST be 5
    git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-author: '   # MUST be 5 (lowercase 'a')
    git log --format='%B' HEAD~5..HEAD | grep -c '^Signed-off-by: '     # MUST be 10
    git log -1 --format='%H' -- crates/nono-cli/src/exec_strategy_windows/
    # MUST equal PRE_PLAN_WINDOWS_SHA from Task 1
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: ' | grep -E '^5$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 5 commits on main with verbatim D-19 6-line trailers (lowercase 'a').
    - Per-commit D-40-E1: all 5 commits return 0 for Windows-file grep.
    - Windows-only sentinel SHA unchanged from Task 1 baseline.
    - `grep -r 'NODE_USE_ENV_PROXY' crates/nono-proxy/src/server.rs` returns at least 1 match.
    - abc86f6 Cargo.toml: no-keyring build does not pull libdbus.
    - C5 SHAs (8ddb143, 54c7552, f77e0e3) NOT present in the cherry-pick chain (D-40 C1/C5 boundary preserved).
    - `cargo build --workspace` exits 0 after each commit.
  </acceptance_criteria>
  <done>
    C1 chain complete; proxy hardening landed; libdbus isolated; Node 26 proxy env set.
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

    # Gate 6: Phase 15 detached-console smoke
    # Document: PASS or documented-skipped

    # Gate 7: wfp_port_integration
    cargo test --workspace --all-features -p nono-cli -- wfp_port_integration

    # Gate 8: learn_windows_integration
    cargo test --workspace --all-features -p nono-cli -- learn_windows_integration

    # D-19 trailer smoke:
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
    - D-19 smoke: 5 Upstream-commit: lines across chain.
    - D-40-E1: 0 Windows-file edits across chain.
  </acceptance_criteria>
  <done>
    Plan 40-01 close-gate cleared.
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
      --title "Plan 40-01 (C1): Proxy server hardening — libdbus isolation + Node 26 NODE_USE_ENV_PROXY + review fixes (v0.52.1, 5 commits)" \
      --body "$(cat <<'EOF'
    Wave 1 plan (depends on Wave 0: 40-02 + 40-03). Absorbs upstream v0.52.1 Cluster C1 (5 commits):

    - 5e6e7ca + eedfbcd: server.rs review fixes
    - be8cd00: accurate warning message + doc comment
    - abc86f6: libdbus isolated from no-keyring builds (critical for Windows MSI distribution)
    - d57375e: NODE_USE_ENV_PROXY for Node 26 proxy env semantics

    D-19 trailers: 5/5. D-40-E1 violations: 0. D-40-C2 gates: all pass.
    C5 boundary preserved (TLS/credential changes stay in Plan 40-06).
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
    Plan 40-01 published; Wave 1 C1 PR open.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Build system feature unification → libdbus linkage | abc86f6 prevents transitive libdbus pull-in on no-keyring builds |
| Node 26 process environment → proxy bypass via HTTP_PROXY/HTTPS_PROXY semantics | d57375e sets NODE_USE_ENV_PROXY to maintain proxy enforcement |
| Upstream diff → fork integration | Server.rs review fixes may silently affect proxy credential or TLS intercept paths scoped to C5 |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-40-01-01 | Tampering | D-40-E1 Windows-only files invariant | **HIGH** | mitigate (BLOCKING) | Per-commit grep gate; Windows-only sentinel SHA unchanged from pre-plan baseline |
| T-40-01-02 | Repudiation | D-19 trailer missing | **HIGH** | mitigate (BLOCKING) | Post-chain `grep -c '^Upstream-commit: '` must equal 5 |
| T-40-01-03 | Elevation of Privilege | abc86f6 Cargo.toml conflict removes fork's Windows keyring feature | **HIGH** | mitigate (BLOCKING) | Read `git show abc86f6` before cherry-pick; preserve fork's keyring [features] entries; `cargo build --workspace --no-default-features` must not link libdbus |
| T-40-01-04 | Elevation of Privilege | C5 credential-matching SHAs (8ddb143, 54c7552, f77e0e3) accidentally cherry-picked in this plan | **HIGH** | mitigate (BLOCKING) | C5 SHAs not in C1 commit list; post-chain verify these SHAs are NOT reachable from HEAD via cherry-pick chain |
| T-40-01-05 | Spoofing | NODE_USE_ENV_PROXY wired into Windows exec path, enabling proxy bypass on Windows | medium | mitigate | D-40-E6: no Windows exec wiring; grep confirms `NODE_USE_ENV_PROXY` not in exec_strategy_windows/ |
| T-40-01-06 | Denial of Service | libdbus unintentionally linked in Windows MSI build | **HIGH** | mitigate | abc86f6 specifically prevents this; verify via `cargo build --no-default-features` on the abc86f6 commit |
| T-40-01-07 | Spoofing | server.rs review fixes (5e6e7ca + eedfbcd) alter proxy credential injection path | medium | accept | C1 review fixes are in server.rs logic unrelated to credential.rs (C5 owns credential path); accept if diff confirms no credential.rs edits |
</threat_model>

<verification>
- All 8 D-40-C2 close-gates pass.
- `git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: '` returns 5.
- `git diff --stat HEAD~5 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns 0.
- `grep -r 'NODE_USE_ENV_PROXY' crates/nono-proxy/src/server.rs` returns at least 1 match.
- No-keyring build does not link libdbus.
- C5 SHAs absent from the cherry-pick chain.
- origin/main advanced; PR created.
</verification>

<success_criteria>
- 5 atomic commits on main, each with verbatim D-19 6-line trailer.
- libdbus isolated from no-keyring builds (abc86f6 landed correctly — critical for Windows MSI).
- NODE_USE_ENV_PROXY set for Node 26 proxy env compatibility.
- Accurate proxy warning message + doc comment updated.
- D-40-E1 invariant honored (0 Windows-file edits).
- C1 / C5 boundary preserved.
- All 8 D-40-C2 gates cleared.
- origin/main advanced; PR open.
</success_criteria>

<output>
After completion, create `.planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md`.
</output>
