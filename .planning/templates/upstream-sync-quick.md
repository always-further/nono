<!--
  Upstream-sync quick task template.

  Usage:
    1. Copy this file to .planning/quick/YYMMDD-xxx-upstream-sync-vX.Y/PLAN.md
    2. Replace all {placeholder} markers with values for the upstream range you're absorbing.
    3. Run `make check-upstream-drift > drift.json` to inventory commits, then curate
       the categorized commit list into the "Drift inventory" section below.
    4. Cherry-pick per commit, applying the trailer block at the bottom of THIS file
       to every commit message (D-19 convention; see .planning/PROJECT.md
       § Upstream Parity Process for context).

  Smoke check before committing the filled-in PLAN.md:
    grep -oE '\{[a-z_]+\}' PLAN.md
  Should return zero matches. Any remaining {placeholder} is an unfilled blank.
-->

---
slug: {quick_slug}
created: {date}
type: upstream-sync
range: {from_tag}..{to_tag}
---

# Quick task: Sync upstream {from_tag} → {to_tag} into the fork

**Ask:** Absorb upstream's {from_tag} → {to_tag} cross-platform feature deltas into the fork
without breaking Windows parity. Per-commit cherry-picks preserve provenance via the D-19
trailer block.

**Scope:**
- Diff range: `{from_tag}..{to_tag}` ({commit_count} non-merge commits, ~{insertions} insertions / ~{deletions} deletions over cross-platform paths).
- Tags covered: <!-- list intermediate tags if range spans more than one release, e.g., v0.41.0, v0.42.0 -->
- Categories present (run `make check-upstream-drift ARGS="--from {from_tag} --to {to_tag} --format json"` to inventory): <!-- profile / policy / package / proxy / audit / other -->
- Deliverable: per-commit cherry-picks landing on `windows-squash` (or current parity branch), each carrying the D-19 trailer block.

**What I will NOT do:**
- No upstream merge (only per-commit cherry-pick — preserves windowed scope).
- No automated cherry-pick orchestration (each commit reviewed for Windows-retrofit hazards before landing).
- No changes to `.planning/ROADMAP.md` / `.planning/PROJECT.md` outside this quick task's scope.

**STATE.md update plan:** appended to "Quick Tasks Completed" table on close-out, with reference to this PLAN.md and the resulting commit chain.

---

## Drift inventory

<!--
  Run: make check-upstream-drift ARGS="--from {from_tag} --to {to_tag} --format json" > drift.json
  Then paste curated entries into the per-category sections below. Per D-14, this template
  does NOT auto-include the inventory — the maintainer reviews + categorizes manually.
-->

**Total unique commits in cross-platform path filter:** {commit_count}

**Per-category breakdown (from `make check-upstream-drift --format json`'s `by_category` field):**

| Category | Commits | Cherry-pick priority |
|----------|---------|----------------------|
| profile  | {n_profile} | <!-- 1=lowest risk, 5=highest risk; mirror Phase 22-01..05 ordering --> |
| policy   | {n_policy}  | |
| package  | {n_package} | |
| proxy    | {n_proxy}   | |
| audit    | {n_audit}   | |
| other    | {n_other}   | |

### Commits to absorb (per-category)

<!--
  For each category, list the commits the fork must absorb. Format per row:
    - {sha}  {subject}  ({adds}/{dels})
  Example:
    - 4f9552ec  feat(audit): add tamper-evident audit log integrity  (+1419/-226)
-->

#### profile
<!-- paste curated commit list -->

#### policy
<!-- paste curated commit list -->

#### package
<!-- paste curated commit list -->

#### proxy
<!-- paste curated commit list -->

#### audit
<!-- paste curated commit list -->

#### other
<!-- paste curated commit list (or note "no cross-platform impact, skipping" per commit) -->

---

## Baseline-aware CI gate

For upstream-sync waves landing on top of a known-green baseline, the close
gate flags ONLY `success → failure` transitions vs the baseline. Drift
accumulates across milestones; reset at each milestone-internal cleanup.

**Current baseline SHA:** `3f638dc6`
**Last reset:** Phase 46 close (REQ-CI-FU-03), 2026-05-23 → post-merge baseline for v2.6 windows-squash-merge + post-merge CI verifications + UAT backlog drain. Previous baseline: `13cc0628` (Phase 41 close, 2026-05-16, v2.5 precedent).
**Reset cadence:** Every milestone-internal cleanup phase (see Phase 41 + Phase 46 for the v2.5 + v2.6 precedents).

CI gate result interpretation:
- Lane was green on baseline AND is green on PR head: PASS.
- Lane was green on baseline AND is red on PR head: FAIL (real regression).
- Lane was red on baseline AND is red on PR head: PASS (carry-forward, not
  introduced by this PR).
- Lane was red on baseline AND is green on PR head: PASS + IMPROVEMENT.

---

## Conflict-file inventory

<!--
  Files in the fork that have diverged from upstream and will conflict on cherry-pick.
  Pre-populated from prior upstream syncs (Phase 22-03 PKG, Phase 20 UPST). Update for
  the current range based on `git diff --stat upstream/{from_tag}..upstream/{to_tag} -- <file>`.
-->

| File | Why it conflicts | Resolution pattern |
|------|------------------|---------------------|
| `crates/nono-cli/src/profile/mod.rs` | Fork added Windows-specific deserialization paths; upstream evolves the struct | Apply upstream's serde changes; keep fork's `#[cfg(target_os = "windows")]` arms |
| `crates/nono-cli/src/exec_strategy.rs` | Fork has 144+ lines of Windows-specific exec wiring | Apply upstream changes around the cfg-gated regions; do not touch the Windows arms unless audit explicitly requires |
| `crates/nono-cli/src/supervised_runtime.rs` | Heavy fork divergence (Phase 22-05 audit ledger + Plan 18.1-03 profile widening) | Hand-resolve; verify CLEAN-04 and AIPC invariants still hold post-resolution |
| `crates/nono-cli/src/rollback_runtime.rs` | +586 LOC upstream change; fork has Windows snapshot/rollback wiring | Resolve hunk-by-hunk; preserve fork's `prepare_live_windows_launch` callsite |
| `crates/nono-cli/src/package_cmd.rs` (and `crates/nono/src/package*`) | Fork ships Windows install_dir + long-path handling; upstream evolves the cross-platform shape | Apply upstream changes; verify Phase 22-03 PKG-02 acceptance still passes |
| `crates/nono-proxy/src/oauth2.rs` (Phase 22-04) | Fork's port may diverge if upstream evolves the credential-cache shape | Apply upstream changes; verify token cache + WSAStartup ordering preserved |

<!-- Add file rows specific to {from_tag}..{to_tag} as cherry-pick reveals new conflicts. -->

---

## Windows-specific retrofit checklist

<!--
  For each cross-platform feature absorbed, check the Windows path. If absent, add it
  behind `#[cfg(target_os = "windows")]` AND document why the cross-platform code path
  doesn't apply (e.g., uses Unix procfs that has no Windows analog, requires named
  semaphores not present in the WinAPI surface, etc.).
-->

For every cross-platform feature in the inventory above:

- [ ] **Profile struct change?** → Verify `crates/nono-cli/src/profile/mod.rs` deserialize works on Windows (smoke: `cargo test -p nono-cli --features windows-tests profile::tests`)
- [ ] **Policy fail-closed addition?** → Verify Windows fail-closed path matches macOS (smoke: `bash tests/integration/test_override_deny.sh`)
- [ ] **Package manager change?** → Verify `%LOCALAPPDATA%\nono\packages` resolution + long-path handling (smoke: Phase 22-03 PKG-02 regression test)
- [ ] **Proxy / OAuth2 change?** → Verify Windows nono-proxy stack + WSAStartup ordering (smoke: Phase 22-04 OAuth2 integration tests)
- [ ] **Audit / attestation change?** → Verify Windows ledger emission survives `AppliedLabelsGuard` Drop AND `exec_identity` resolves via `GetModuleFileNameW` (smoke: Phase 22-05 + Phase 23 AUD tests)
- [ ] **WFP / network change?** → Verify per-session-SID filter is still kernel-enforced; no AppID leak on detached path (smoke: `bash tests/integration/test_network_wfp.sh`)
- [ ] **For each new feature without a Windows code path:** explicit `#[cfg(not(target_os = "windows"))]` gate + comment documenting why no Windows analog is needed

---

## Fork-divergence catalog

<!--
  Decisions the fork has made that look "removable" on cherry-pick but MUST be preserved.
  Silently dropping these is the most common upstream-sync regression. Read this list
  in full before resolving any conflict.
-->

### `validate_path_within` defense-in-depth retention (Phase 22-03 PKG-04)

The fork retains `validate_path_within(child, parent)` calls even when upstream removed
them in `0cbb7e62 refactor(package): simplify artifact signer validation`. Reason: the
function is a structural defense-in-depth check against path-traversal in package
artifacts (`../`, UNC aliasing, symlink escapes). Upstream relies on `Path::canonicalize`
+ `starts_with`, which is the well-known footgun (string `starts_with("/home")` matches
`/homeevil`; CLAUDE.md § Common Footguns #1). The fork's `validate_path_within` uses
`Path::components()` iteration and is the correct primitive on Windows where paths can
take UNC, `\\?\`, and drive-letter forms.

**Action on cherry-pick:** When upstream commits remove `validate_path_within` calls,
KEEP them in the fork. Add a comment: `// Defense-in-depth (fork divergence: see Phase
22-03 PKG-04). Do not remove without security review.`

### Deferred enum variants (e.g., `ArtifactType::Plugin`)

Upstream's `ArtifactType` enum has more variants than the fork's port absorbed. When
cherry-picking commits that touch `match` arms over `ArtifactType`, the fork's narrower
enum will fail compile if the upstream commit adds a new variant.

**Action on cherry-pick:** Either add the variant to the fork's enum (preferred, tracks
upstream feature surface) OR add an explicit `_ => Err(NonoError::Unsupported(format!("variant not yet in fork: {:?}", v)))` arm with a comment pointing to a deferral ticket. Document the choice in the cherry-pick's commit message body.

### Async-runtime wrapping for `load_production_trusted_root`

Upstream evolved `load_production_trusted_root` to be async over time; the fork wraps
the synchronous call in a `tokio::task::spawn_blocking` at the call site. When upstream
introduces an async helper, the fork's wrapper becomes redundant.

**Action on cherry-pick:** Audit the call site. If upstream now provides an async
variant, switch the fork to it (delete the `spawn_blocking` wrapper). If upstream still
emits sync code under an async signature (anti-pattern), keep the fork's wrapping.

### Hooks subsystem ownership (`hooks.rs` retention)

Upstream removed the `claude-code integration package` in favor of bundling hooks into
the package manager. The fork keeps `crates/nono-cli/src/hooks.rs` as the sole
hook-installation surface (Phase 22-03 PKG-03 wiring routes through it).

**Action on cherry-pick:** Cherry-picks that delete `hooks.rs` or rewire it through the
package-manager path must be hand-resolved to preserve the fork's centralized hook
installer. Do NOT silently accept upstream's removal.

### Windows-only file globs (D-21 invariance)

Cherry-picks that touch cross-platform files MUST NOT also modify `*_windows.rs` /
`crates/nono-cli/src/exec_strategy_windows/` files unless the change is explicitly
Windows-targeting. When upstream's commit accidentally edits a Windows file (e.g., a
cross-platform refactor that leaks into a `#[cfg(windows)]` arm), revert the Windows
change in the cherry-pick.

**Verification:** `git diff --stat HEAD~1 HEAD -- crates/nono/src/ crates/nono-cli/src/ | grep -v _windows | grep -v exec_strategy_windows`. The output should match the upstream commit's intended scope.

---

## D-19 cherry-pick trailer block

<!--
  REQUIRED on EVERY cherry-pick commit. Verbatim shape (lowercase 'a' in 'Upstream-author';
  two Signed-off-by lines for DCO + GitHub attribution).

  Workflow:
    1. git cherry-pick {upstream_sha_full}
    2. git commit --amend  (to add the trailer block)
    3. Append the block below to the commit message body, separated by ONE blank line.

  Smoke check on the rebased branch before push:
    git log --format='%B' {fork_branch}~{commit_count}..{fork_branch} \
      | grep -c '^Upstream-commit: '
    Should equal {commit_count}.
-->

```
Upstream-commit: {upstream_sha_abbrev}
Upstream-tag: {upstream_tag}
Upstream-author: {upstream_author_name} <{upstream_author_email}>
Co-Authored-By: {upstream_author_name} <{upstream_author_email}>
Signed-off-by: {fork_author_name} <{fork_author_email}>
Signed-off-by: {fork_author_handle} <{fork_author_email}>
```

**Field rules (verified verbatim from commits 73e1e3b8, adf81aec, 869349df):**

1. Trailer block separated from body by EXACTLY ONE blank line.
2. Field order is FIXED: `Upstream-commit` → `Upstream-tag` → `Upstream-author` → `Co-Authored-By` → `Signed-off-by` (full name) → `Signed-off-by` (github handle).
3. `Upstream-author` and `Co-Authored-By` carry the SAME name + email.
4. TWO `Signed-off-by` lines: full name + github handle. Both required (DCO + GitHub attribution).
5. Field name is `Upstream-author` with LOWERCASE 'a' (NOT `Upstream-Author`).
6. Abbreviated 8-char SHA is the in-use convention for `Upstream-commit:` (the actual commit body may reference the full SHA, but the trailer uses 8-char).

---

## Acceptance

- [ ] All {commit_count} commits cherry-picked with D-19 trailer present
- [ ] Conflict-file inventory section reflects what actually conflicted
- [ ] Windows retrofit checklist all items either ✓ or explicitly N/A with reason
- [ ] Fork-divergence catalog reviewed; no entries silently dropped
- [ ] `cargo build --workspace` clean
- [ ] `cargo test --workspace` clean (or known-flake tests documented inline)
- [ ] `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` clean
- [ ] `cargo fmt --all -- --check` clean

## Out-of-scope deferrals

<!-- Track commits absorbed but with intentional deferrals (e.g., "ported deserialization
     but feature wiring deferred to Phase XX"). -->

---

*Quick task type: upstream-sync. Tooling: `make check-upstream-drift` (Plan 24-01). Long-form runbook: [`docs/cli/development/upstream-drift.mdx`](../../../docs/cli/development/upstream-drift.mdx).*
