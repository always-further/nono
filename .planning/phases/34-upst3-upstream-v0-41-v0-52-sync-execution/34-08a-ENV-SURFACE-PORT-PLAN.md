---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-08a
plan: 08a
slug: env-surface-port
cluster_id: C12-env-surface
parent_plan: 34-08 (archived)
type: execute
wave: 2
depends_on: ["34-04", "34-04b", "34-01", "34-02", "34-05", "34-07"]
blocks: ["34-08b"]
files_modified:
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/src/exec_strategy/env_sanitization.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/command_runtime.rs
  - crates/nono-cli/src/execution_runtime.rs
  - crates/nono-cli/src/launch_runtime.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/profile_runtime.rs
  - crates/nono-cli/src/sandbox_prepare.rs
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono/src/capability.rs
upstream_tag_range: v0.37.0+v0.52.0 (split)
upstream_commit_count: 5
disposition: fork-preserve-manual-replay-split
autonomous: false
requirements: [C12-env-surface]
tags: [upst3, c12-env-surface, env-sanitization, deny-vars, fork-preserve, manual-replay, d-20, wave-2, split-from-34-08]

must_haves:
  truths:
    - "All 5 upstream artifacts (1 D-20 manual replay of v0.37.0 env-filter surface `1b412a7` + 4 D-19 cherry-picks: `3657c935` deny_vars, `780965d7` empty-allow fail-closed, `a022e5c7` docs, `31f2fc27` release) READ in full and EXPLICITLY dispositioned in Task 2. Default dispositions pre-approved via /gsd-execute-phase 34 --wave 2 Option B. Resolved table written to /tmp/34-08a-disposition.txt."
    - "Upstream v0.37.0 env-filter surface (commit `1b412a7` and its descendents up to but NOT including `b4762e63` which the fork already partially ported in Phase 20-03) replayed manually onto fork's profile/mod.rs + exec_strategy/env_sanitization.rs + the 6+ runtime call-sites (command_runtime, execution_runtime, launch_runtime, main, profile_runtime, sandbox_prepare, exec_strategy). Replay commit body documents what was ported, cites Phase 20-03 b4762e63's deferral, explains why straight cherry-pick was infeasible (Phase 20-03 explicitly restricted to cli.rs; the rest of the surface was deferred). NO `Upstream-commit:` D-19 trailer on this commit; body uses `Manual-replay: 1b412a7` per D-20 convention (mirror 34-04b Task 3 + 34-09/34-10 commit-body precedent)."
    - "Plan 20-03 partial env-surface port PRESERVED: `--env-allow` / `--env-deny` flags + `parse_env_filter_pattern` (landed in fork commit `b4762e63`) UNCHANGED post-Task-3. Verified: `grep -c 'parse_env_filter_pattern\\|--env-allow\\|--env-deny\\|env_allow\\|env_deny' crates/nono-cli/src/cli.rs` >= 4 post-replay (pre-plan baseline captured in Task 1)."
    - "`EnvironmentConfig` struct lands in `crates/nono-cli/src/profile/mod.rs`; `Profile.environment: Option<EnvironmentConfig>` field lands; `ProfileDeserialize.environment` field lands. Verified: `grep -c 'EnvironmentConfig\\|environment:.*Option' crates/nono-cli/src/profile/mod.rs` >= 3 post-Task-3."
    - "`is_env_var_allowed` + `validate_allow_vars_pattern` helpers land in `crates/nono-cli/src/exec_strategy/env_sanitization.rs`. Verified: `grep -cE 'is_env_var_allowed|validate_allow_vars_pattern' crates/nono-cli/src/exec_strategy/env_sanitization.rs` >= 2 post-Task-3."
    - "Cherry-pick `3657c935` (deny_vars feature) lands `EnvironmentConfig.deny_vars: Vec<String>` field; operator-controlled denylist takes precedence over allow_vars in resolve order. Verified: `grep -c 'deny_vars' crates/nono-cli/src/exec_strategy/env_sanitization.rs` >= 1 AND `grep -c 'deny_vars' crates/nono-cli/src/profile/mod.rs` >= 1 post-Task-4; upstream's resolve-order regression test ports and `cargo test -p nono-cli env_sanitization::tests::deny_vars` (or equivalently-named) exits 0."
    - "Cherry-pick `780965d7` (empty-allow fail-closed security regression fix) preserves the invariant: `allow_vars: []` with no `deny_vars` results in DENY-ALL, not ALLOW-ALL. Verified: upstream's empty-allow regression test ports and `cargo test -p nono-cli env_sanitization::tests::empty_allow_fails_closed` (or equivalently-named) exits 0 post-Task-5."
    - "Cherry-pick `a022e5c7` (deny_vars + allow_vars usage docs) lands docs-only or near-docs-only changes per D-34-E1; no Windows-only-file touches."
    - "Cherry-pick `31f2fc27` (chore: release v0.52.0) lands CHANGELOG entry only; Cargo.toml + Cargo.lock version-bumps dropped per Plan 34-04 commits 3 + 12 + Plan 34-04b Task 5 partial-cherry-pick precedent."
    - "`crates/nono-cli/src/learn_windows.rs` SHA UNCHANGED across the entire 34-08a chain. Pre-plan baseline: `aa4d33dc801b631883ba9c5fc7917e0e194342a4` (captured at plan-write time 2026-05-12). Verified: `git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs` equals baseline post-Task-7 (D-11 + D-34-B2 ETW path invariant). NOTE: 34-08a does NOT touch the learn deprecation commit (`b34c2af6`) — that ships in 34-08b — but the env-surface port must preserve learn_windows.rs byte-identity."
    - "D-34-E1 Windows-only file invariant: per-commit `git diff --stat <prev>..<this> -- crates/ | grep -v '^#' | grep -E '_windows|exec_strategy_windows' | wc -l` returns 0 for EVERY commit in the 34-08a chain AND at plan close across the entire range."
    - "Fork-defense baselines PRESERVED post-Task-7 (pre-plan baselines captured in Task 1; all sentinels match Plan 34-04b close state): never_grant + apply_deny_overrides >= 21 in policy.rs; validate_path_within >= 9 in package_cmd.rs; capabilities.aipc / loaded_profile >= 17 in profile/mod.rs; find_denied_user_grants >= 1 in policy.rs; bypass_protection >= 1 in profile/mod.rs (post 34-04b canonical-schema state)."
    - "All cherry-pick commits (Tasks 4-7) carry the verbatim D-19 6-line trailer block (lowercase 'a' in `Upstream-author:`; 2 DCO Signed-off-by lines per commit). Task 3 manual-replay commit carries `Manual-replay: 1b412a7` (NOT `Upstream-commit:`); 2 DCO Signed-off-by lines."
    - "Plan-close smoke check: `git log --format='%B' <pre-plan-head>..HEAD | grep -v '^#' | grep -c '^Upstream-commit: '` returns exactly 4 (the 4 v0.52.0 cherry-picks: 3657c935 + 780965d7 + a022e5c7 + 31f2fc27); `grep -c '^Manual-replay: '` returns exactly 1 (the 1b412a7 v0.37.0 replay); `grep -c '^Upstream-Author:'` returns 0 (case-sensitivity invariant); `grep -c '^Signed-off-by: '` returns 2N where N = total commits in plan."
    - "D-34-D2 close-gates: Gates 1 (`cargo test --workspace --lib` Windows host), 2 (Windows clippy `-D warnings -D clippy::unwrap_used`), 5 (`cargo fmt --all -- --check`) PASS on dev host. Gates 3, 4 (Linux + macOS cross-target clippy) DOCUMENTED-SKIPPED with rationale 'deferred to CI per dev-host limitation; user accepted same posture at 34-04 and 34-04b close'. Gates 6, 7, 8 (Phase 15 5-row, wfp_port_integration, learn_windows_integration) DOCUMENTED-SKIPPED per 'admin / service / ETW provider not available on dev host' rationale (mirror 34-04b SUMMARY)."
    - "Plan 34-08a commits pushed to origin/main at plan close; per-plan PR opened per D-34-D1. `git log origin/main..main --oneline | wc -l` returns 0 post-push."
  artifacts:
    - path: "crates/nono-cli/src/profile/mod.rs"
      provides: "`EnvironmentConfig` struct (NEW from upstream v0.37.0 surface `1b412a7`); `Profile.environment: Option<EnvironmentConfig>` field (NEW); `ProfileDeserialize.environment` field (NEW); `EnvironmentConfig.deny_vars: Vec<String>` (post-cherry-pick `3657c935`); composes with Phase 22-01 ProfileDeserialize companion-struct pattern; Plan 18.1-03 `capabilities.aipc` / `loaded_profile` PRESERVED"
      grep_pattern: "EnvironmentConfig|environment:.*Option|deny_vars|allow_vars"
      grep_negative: "// removed capabilities.aipc|// dropped ProfileDeserialize"
      min_call_sites: 3
    - path: "crates/nono-cli/src/exec_strategy/env_sanitization.rs"
      provides: "`is_env_var_allowed` helper (NEW from v0.37.0 surface); `validate_allow_vars_pattern` helper (NEW); `deny_vars` precedence over `allow_vars` (post `3657c935`); empty-allow fail-closed semantics (post `780965d7`); composes with fork's existing partial Phase 20-03 env_sanitization port"
      grep_pattern: "is_env_var_allowed|validate_allow_vars_pattern|deny_vars|allow_vars"
      grep_negative: "// fallback allow|// empty allow_vars treats as allow_all"
    - path: "crates/nono-cli/src/cli.rs"
      provides: "`--env-allow` / `--env-deny` clap flags + `parse_env_filter_pattern` PRESERVED from Phase 20-03 commit b4762e63; any clap-flag adjustments from deny_vars cherry-pick (`3657c935`)"
      grep_pattern: "parse_env_filter_pattern|env.allow|env.deny|env_allow|env_deny"
      grep_negative: "// removed parse_env_filter_pattern|// dropped env-allow flag"
    - path: "crates/nono-cli/src/command_runtime.rs"
      provides: "env-filter call site wired against `EnvironmentConfig` (manual replay Task 3)"
      grep_pattern: "environment|EnvironmentConfig|sanitize_env|env_var"
    - path: "crates/nono-cli/src/execution_runtime.rs"
      provides: "env-filter call site wired against `EnvironmentConfig` (manual replay Task 3)"
      grep_pattern: "environment|EnvironmentConfig|sanitize_env|env_var"
    - path: "crates/nono-cli/src/launch_runtime.rs"
      provides: "env-filter call site wired against `EnvironmentConfig` (manual replay Task 3)"
      grep_pattern: "environment|EnvironmentConfig|sanitize_env|env_var"
    - path: "crates/nono-cli/src/sandbox_prepare.rs"
      provides: "env-filter call site wired against `EnvironmentConfig` (manual replay Task 3); SandboxArgs / PreparedSandbox carries Option<EnvironmentConfig> if upstream's shape requires"
      grep_pattern: "environment|EnvironmentConfig|sanitize_env|env_var"
  key_links:
    - from: "Plan 20-03 partial env-surface port (fork commit b4762e63 — only cli.rs flag-parsing slice landed; rest deferred)"
      to: "Plan 34-08a Task 3 D-20 manual-replay continuation"
      via: "Phase 20-03 explicitly restricted to cli.rs; this completes the v0.37.0 env-filter surface by adding the deferred profile/mod.rs + env_sanitization.rs + runtime call-site portions per D-34-E3"
      pattern: "EnvironmentConfig|environment:.*Option|is_env_var_allowed"
    - from: "Plan 34-08 (archived) attempted v0.52.0 cluster C12 (10-commit chain)"
      to: "34-08a (env-surface subset, 5 artifacts) + 34-08b (non-env subset, 5 commits)"
      via: "Plan 34-08 hit a cherry-pick wall at commit 1/10 (3657c935) because the fork's Phase 20-03 env-surface port was only partial; split per Phase 22-05a/22-05b + 34-04/34-04b precedent within Phase 34 itself"
      pattern: "Manual-replay: 1b412a7|Upstream-commit: (3657c93|780965d|a022e5c|31f2fc2)"
    - from: "Operator-defined `environment.deny_vars: ['AWS_*', 'GITHUB_TOKEN']` in profile JSON"
      to: "`exec_strategy::env_sanitization::sanitize_env`"
      via: "deny_vars takes precedence over allow_vars; fail-closed filter applied at exec-time before child process spawn; empty-allow semantics preserved (DENY-ALL not ALLOW-ALL)"
      pattern: "deny_vars.*sanitize|sanitize.*deny_vars|allow_vars.*deny_vars"
    - from: "Phase 22-01 `ProfileDeserialize` companion-struct pattern + Plan 34-04b canonical-schema state"
      to: "Plan 34-08a post-replay state — `Profile.environment` + `ProfileDeserialize.environment` both carry `Option<EnvironmentConfig>`"
      via: "manual replay composes the new field with fork's existing companion-struct pattern; preserves Phase 22-01 PROF-01..03 retained-fork-shape invariant"
      pattern: "ProfileDeserialize|struct ProfileDeserialize"
    - from: "`learn_windows.rs` last-touched SHA aa4d33dc... (D-11 + D-34-B2 ETW path invariant)"
      to: "Plan 34-08a close state"
      via: "env-surface port does NOT touch learn surface; per-commit + plan-close SHA-equality check verifies byte-identity preservation. NOTE: 34-08a does NOT touch the learn deprecation commit b34c2af6 (that ships in 34-08b); 34-08b assumes responsibility for its byte-identity invariant"
      pattern: "learn_windows.rs"
---

<objective>
Land the env-touching portion of cluster C12 (v0.52.0) that Plan 34-08 (archived) hit a cherry-pick wall on. Plan 34-08 attempted all 10 v0.52.0 C12 commits as a single autonomous chain; empirical discovery during execution showed the fork has only a PARTIAL Phase 20-03 env-filter surface port. CLI flag-parsing (`--env-allow` / `--env-deny` + `parse_env_filter_pattern`) landed in Phase 20-03 commit `b4762e63` ("Manual port of upstream 1b412a7 restricted to crates/nono-cli/src/cli.rs only"), but the rest of upstream's env-filter surface was DEFERRED:

- `EnvironmentConfig` struct (in `profile/mod.rs`)
- `Profile.environment: Option<EnvironmentConfig>` field
- `ProfileDeserialize.environment` field
- `is_env_var_allowed` helper (in `env_sanitization.rs`)
- `validate_allow_vars_pattern` helper
- Env-filter call sites in command_runtime, execution_runtime, launch_runtime, main, profile_runtime, sandbox_prepare, exec_strategy (~250 LOC of struct/deserialize/runtime wiring)

This deferral made the very first v0.52.0 cherry-pick (`3657c935` add deny_vars to env filter) infeasible without the base surface in place. Plan 34-08 was archived (`34-08-ENV-DENY-PLAN.archive.md`).

**This plan (34-08a)** lands the env-touching subset of C12:
1. **Task 3 (D-20 manual replay)** — port the v0.37.0 env-filter surface from upstream commit `1b412a7` (and its descendents up to but NOT including `b4762e63` which Phase 20-03 already partially ported). This is a D-20 manual replay per D-34-E3 ("Files in scope where fork drift is high are read-upstream-and-replay candidates per Phase 22 D-02 fallback rule"). Mirror Plan 34-04b Task 3 shape.
2. **Tasks 4-7 (D-19 cherry-picks)** — 4 v0.52.0 env-touching commits that compose with the base surface: `3657c935` (deny_vars feature), `780965d7` (empty-allow fail-closed security regression fix), `a022e5c7` (deny_vars + allow_vars docs), `31f2fc27` (chore: release v0.52.0 — CHANGELOG only, Cargo bumps dropped).

**Sibling plan (34-08b — parallel)** lands the 5 non-env-touching v0.52.0 cluster C12 commits: `1d491b4d` (macOS learn), `b5f0a3ab` (interactive), `b34c2af6` (learn deprecation), `bbdf7b85` (escaped quotes), `5d15b50e` (release).

**Why split:** mirrors Phase 22-05a/22-05b mid-plan-split precedent AND the 34-04/34-04b precedent within Phase 34 itself. The env-surface manual port is a D-20 candidate with security-critical regression risk (empty-allow fail-closed; deny_vars precedence); separating it from the non-env cherry-picks gives the manual port a dedicated `autonomous: false` checkpoint without forcing the safe-cherry-pick siblings onto a slow gate.

**`autonomous: false` rationale:**
1. **D-20 manual port surface area** — porting EnvironmentConfig + 6+ runtime call-sites against fork-divergent profile/mod.rs is non-trivial; risk of accidentally introducing a security regression (silent allow-all fallback) is medium-high.
2. **`3657c935` deny_vars is security-critical** — operator-controlled denylist; precedence-over-allow_vars logic; failure modes have security implications (silent allow of denylisted vars). Per-commit human checkpoint is appropriate.
3. **`780965d7` empty-allow fail-closed** — explicit security regression fix; verifying the regression test ports and the invariant survives the manual-replay base is a per-commit human-verification touchpoint.

Purpose: After 34-08a closes, the env-filter surface is at v0.52.0 parity (operator-controlled deny_vars + fail-closed empty-allow + helpers + docs + release CHANGELOG entry). 34-08b (the non-env cluster-C12 subset) can land immediately after as `autonomous: true` (no env entanglement). v2.4 milestone advances 1 step closer to upstream parity.

Output: 5 commits on `main` (1 D-20 manual-replay for `1b412a7` v0.37.0 env-filter surface + 4 D-19 cherry-picks for `3657c935`, `780965d7`, `a022e5c7`, `31f2fc27` v0.52.0) bringing fork's env-filter surface to upstream v0.52.0 parity.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08-ENV-DENY-PLAN.archive.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-PLAN.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-SUMMARY.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05a-AUD-CORE-PLAN.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05a-AUD-CORE-SUMMARY.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05b-AUD-RENAME-PLAN.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md
@.planning/templates/upstream-sync-quick.md
@crates/nono-cli/src/profile/mod.rs
@crates/nono-cli/src/exec_strategy/env_sanitization.rs
@crates/nono-cli/src/cli.rs
@crates/nono-cli/src/learn_windows.rs

<interfaces>
**Pre-plan HEAD (Plan 34-07 close state):** `c171f1c60ba9fc7359b3a087c67da322a8a49726` (captured at plan-write time, 2026-05-12).

**Pre-plan `learn_windows.rs` last-touched SHA:** `aa4d33dc801b631883ba9c5fc7917e0e194342a4` (captured at plan-write time; carries D-11 ETW path; D-34-B2 invariant: must be UNCHANGED at plan close).

**5 upstream artifacts in scope:**

| # | SHA (8) | Tag | Author | Disposition | Notes |
|---|---------|-----|--------|-------------|-------|
| 1 | `1b412a7` | v0.37.0 | upstream — confirm via Task 1 git log | **D-20 manual replay** | v0.37.0 env-filter surface base; Phase 20-03 ported only the cli.rs flag-parsing slice (`b4762e63`); this replay lands the deferred profile/mod.rs + env_sanitization.rs + runtime call-sites |
| 2 | `3657c935` | v0.52.0 | confirm Task 1 | **cherry-pick** | feat: add deny_vars to env filter; security-critical (operator-controlled denylist) |
| 3 | `780965d7` | v0.52.0 | confirm Task 1 | **cherry-pick** | fix: empty allow vars fails closed; security regression fix |
| 4 | `a022e5c7` | v0.52.0 | confirm Task 1 | **cherry-pick** | docs: deny_vars + allow_vars usage |
| 5 | `31f2fc27` | v0.52.0 | confirm Task 1 | **cherry-pick (partial)** | chore: release v0.52.0; CHANGELOG only; drop Cargo.toml + Cargo.lock version-bumps per Plan 34-04 commits 3 + 12 + Plan 34-04b Task 5 precedent |

**Fork's existing env-filter surface at HEAD c171f1c6 (already on main, do NOT overwrite):**

- `crates/nono-cli/src/cli.rs` — `--env-allow` / `--env-deny` flags + `parse_env_filter_pattern` function (landed Phase 20-03 commit `b4762e63`).
- `crates/nono-cli/src/exec_strategy/env_sanitization.rs` — partial helpers + cross-platform parser (already present per archived Plan 34-08's `files_modified`).
- `crates/nono-cli/src/learn_windows.rs` — fork-only Windows ETW path; D-11 excluded; D-34-B2 invariant byte-identity required.

**Fork-divergence surface that MUST survive the 34-08a chain (baselines captured at plan-write time; Task 1 re-captures):**

| Surface | File | Baseline (grep count) | Notes |
|---------|------|------------------------|-------|
| Plan 18.1-03 `capabilities.aipc` widening | crates/nono-cli/src/profile/mod.rs | **>= 17** | Phase 18.1-03 G-06 profile widening (Plan 34-04b close state) |
| Phase 22-01 `ProfileDeserialize` companion-struct pattern | crates/nono-cli/src/profile/mod.rs | **>= 1** | Fork-only deserialize pattern (Phase 22-01 PROF-01..03) |
| Plan 34-04b canonical-schema `bypass_protection` field | crates/nono-cli/src/profile/mod.rs | **>= 1** | Post Plan 34-04b state |
| Phase 19 v2.1 `never_grant` / `apply_deny_overrides` | crates/nono-cli/src/policy.rs | **>= 21** | Defense-in-depth gate |
| Phase 22-03 PKG-04 `validate_path_within` | crates/nono-cli/src/package_cmd.rs | **>= 9** | 9 callsites; defense-in-depth |
| 34-04 commit ac9f0a59 helper `find_denied_user_grants` | crates/nono-cli/src/policy.rs | **>= 1** | Added during 34-04 run |
| Phase 20-03 partial env-surface `parse_env_filter_pattern` + flags | crates/nono-cli/src/cli.rs | **>= 4** (counts: parse_env_filter_pattern, --env-allow, --env-deny, env_allow OR env_deny) | Must be preserved through Task 3 manual replay (the replay extends the surface, does NOT overwrite the cli.rs slice) |

**D-19 cherry-pick trailer block (verbatim — applies to the 4 cherry-pick commits 3657c935, 780965d7, a022e5c7, 31f2fc27):**

```
Upstream-commit: {8-char-sha}
Upstream-tag: v0.52.0
Upstream-author: {upstream_author_name} <{upstream_author_email}>
Co-Authored-By: {upstream_author_name} <{upstream_author_email}>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

Field rules per `.planning/templates/upstream-sync-quick.md` § D-19 cherry-pick trailer block:
- Lowercase 'a' in `Upstream-author:` (NOT `Upstream-Author:`).
- 8-character SHA abbrev in `Upstream-commit:`.
- `Upstream-author:` + `Co-Authored-By:` carry the SAME `name <email>`.
- Two `Signed-off-by:` lines (DCO full name + GitHub handle).
- Trailer block separated from body by EXACTLY ONE blank line.

**Manual-replay trailer block (verbatim — applies ONLY to the 1b412a7 replay commit in Task 3):**

```
{free-form prose body documenting (1) what upstream's 1b412a7 introduced,
 (2) what Phase 20-03 commit b4762e63 partially ported (cli.rs only) + what it deferred,
 (3) what this replay adds (EnvironmentConfig + helpers + runtime call-sites),
 (4) which fork-only paths were preserved (Phase 22-01 ProfileDeserialize; Plan 18.1-03 capabilities.aipc; Plan 34-04b bypass_protection canonical-schema),
 (5) why straight cherry-pick was infeasible (Phase 20-03 deferred the surface deliberately; without the deferred surface in place, every v0.52.0 env-touching cherry-pick — starting with 3657c935 — would fail-to-apply),
 (6) reference to Plan 34-08 archived plan for the original 10-commit attempt}

Manual-replay: 1b412a7
Upstream-tag: v0.37.0
Upstream-author: {confirm from Task 1 git log} <{confirm-email}>
Co-Authored-By: {same name} <{same email}>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

The `Manual-replay:` field SUBSTITUTES for `Upstream-commit:` per D-20 (mirror Plan 34-04b Task 3 + Plan 34-09 + Plan 34-10's read-and-document commit shape).

NOTE on DCO sign-off: do NOT use `git commit -s` — produces only ONE Signed-off-by line. Use explicit HEREDOC body to write BOTH lines per Phase 22 D-19.

**Plan-close smoke check (verbatim):**

```bash
PRE_HEAD=c171f1c60ba9fc7359b3a087c67da322a8a49726

# Expected: exactly 4 (3657c935 + 780965d7 + a022e5c7 + 31f2fc27)
git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Upstream-commit: '

# Expected: exactly 1 (the 1b412a7 manual replay)
git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Manual-replay: '

# Expected: 0 (case-sensitivity invariant)
git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Upstream-Author:'

# Expected: 2N where N = total commits in plan (DCO + GitHub handle per commit)
git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Signed-off-by: '

# Expected: aa4d33dc801b631883ba9c5fc7917e0e194342a4 (D-34-B2 invariant)
git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs
```

Note the `grep -v '^#'` filter per `<task_breakdown>` "Grep gate hygiene" rule (header prose / comments would trigger self-invalidating grep gates otherwise; per feedback memory + Plan 22-05a/22-05b + Plan 34-04b precedent).
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Read source artifacts + capture pre-34-08a baselines</name>
  <files>(read-only — no files modified; produces /tmp/34-08a-* state files)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08-ENV-DENY-PLAN.archive.md (FULL READ — the archived 10-commit plan; its `<interfaces>` § + threat-model + must_haves carry forward; understand WHY 34-08 was archived)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-PLAN.md (FULL READ — D-20 split-continuation plan shape; THIS plan's structural reference)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-SUMMARY.md (FULL READ — what landed; pragmatic Option C precedent for smaller-surface-than-full-upstream replay; close-gate posture for Gates 3/4/6/7/8 skip-rationale)
    - .planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05a-AUD-CORE-SUMMARY.md (STOP-trigger handling pattern + per-commit disposition table shape)
    - .planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05b-AUD-RENAME-PLAN.md (split-continuation shape — informs 34-08a's task structure)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A1..E5 (especially D-34-B2: learn_windows.rs byte-identity; D-34-E1: Windows-only file invariant; D-34-E3 verbatim "Files in scope where fork drift is high are read-upstream-and-replay candidates per Phase 22 D-02 fallback rule")
    - .planning/templates/upstream-sync-quick.md § D-19 cherry-pick trailer block (verbatim 6-line shape) + § D-20 manual-replay commit-body convention (Manual-replay: substitutes for Upstream-commit:)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md § C12 row (authoritative cluster inventory)
    - CLAUDE.md § "Environment variables in tests" convention (load-bearing for env_sanitization tests)
    - crates/nono-cli/src/profile/mod.rs (FULL READ — to know where EnvironmentConfig + Profile.environment + ProfileDeserialize.environment land; need to identify the fork-only regions Plan 18.1-03 capabilities.aipc, Phase 22-01 ProfileDeserialize, Plan 34-04b bypass_protection)
    - crates/nono-cli/src/exec_strategy/env_sanitization.rs (FULL READ — current partial helpers + cross-platform parser shape; understand where is_env_var_allowed + validate_allow_vars_pattern compose in)
    - crates/nono-cli/src/cli.rs § parse_env_filter_pattern + --env-allow + --env-deny flags (read in full — already-landed Phase 20-03 surface; MUST be preserved by the manual replay, NOT overwritten)
    - crates/nono-cli/src/learn_windows.rs § first 20 lines (read to confirm fork-only Phase 11 ETW path; this plan does NOT touch this file)
  </read_first>
  <action>
    Read the artifacts listed in <read_first>. Then:

    1. **Verify upstream remote + 5 artifact SHAs reachable:**
       ```bash
       git fetch upstream --tags
       for sha in 1b412a7 3657c935 780965d7 a022e5c7 31f2fc27; do
         git cat-file -e ${sha}^{commit} && echo "OK: $sha" || echo "MISSING: $sha"
       done
       # Expected: 5 OK lines, 0 MISSING. If MISSING: STOP + return PLAN BLOCKED.
       ```

    2. **Capture upstream metadata for trailer blocks (feeds Tasks 3-7):**
       ```bash
       for sha in 1b412a7 3657c935 780965d7 a022e5c7 31f2fc27; do
         echo "==== $sha ===="
         git log -1 $sha --format='full_sha=%H subject=%s author=%an email=%ae tag=%D'
         echo "---- stat ----"
         git show --stat $sha | tail -5
         echo "---- body ----"
         git log -1 $sha --format='%b' | head -30
       done > /tmp/34-08a-upstream-meta.txt
       wc -l /tmp/34-08a-upstream-meta.txt
       ```

    3. **Capture pre-Plan-34-08a HEAD + baseline build:**
       ```bash
       PRE_HEAD=$(git rev-parse HEAD)
       echo "PRE_HEAD=$PRE_HEAD" > /tmp/34-08a-baseline.txt
       # Expected at plan-write time: c171f1c60ba9fc7359b3a087c67da322a8a49726
       # (re-confirm; if HEAD has advanced due to other plans, capture the new value)

       cargo build --workspace
       ```

    4. **CRITICAL — Capture pre-Plan-34-08a `learn_windows.rs` last-touched SHA (D-34-B2 anchor):**
       ```bash
       LEARN_WINDOWS_SHA=$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)
       echo "LEARN_WINDOWS_SHA=$LEARN_WINDOWS_SHA" >> /tmp/34-08a-baseline.txt
       # Expected at plan-write time: aa4d33dc801b631883ba9c5fc7917e0e194342a4
       # This SHA MUST be unchanged at plan close (D-11 + D-34-B2 ETW path invariant).
       ```

    5. **Capture pre-34-08a fork-divergence baselines (record all to /tmp/34-08a-baseline.txt):**
       ```bash
       # Plan 18.1-03 capabilities.aipc + loaded_profile (expected >= 17)
       grep -c 'capabilities.aipc\|capabilities_aipc\|loaded_profile' crates/nono-cli/src/profile/mod.rs >> /tmp/34-08a-baseline.txt

       # Phase 22-01 ProfileDeserialize (expected >= 1)
       grep -c 'ProfileDeserialize\|struct ProfileDeserialize' crates/nono-cli/src/profile/mod.rs >> /tmp/34-08a-baseline.txt

       # Plan 34-04b canonical-schema bypass_protection (expected >= 1)
       grep -c 'bypass_protection' crates/nono-cli/src/profile/mod.rs >> /tmp/34-08a-baseline.txt

       # Phase 19 v2.1 never_grant + apply_deny_overrides (expected >= 21)
       grep -c 'never_grant\|apply_deny_overrides' crates/nono-cli/src/policy.rs >> /tmp/34-08a-baseline.txt

       # Phase 22-03 PKG-04 validate_path_within (expected >= 9)
       grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs >> /tmp/34-08a-baseline.txt

       # 34-04 commit ac9f0a59 find_denied_user_grants helper (expected >= 1)
       grep -c 'find_denied_user_grants' crates/nono-cli/src/policy.rs >> /tmp/34-08a-baseline.txt

       # Phase 20-03 partial env-surface in cli.rs (expected >= 4: parse_env_filter_pattern + --env-allow + --env-deny + at least one env_allow|env_deny variable reference)
       grep -cE 'parse_env_filter_pattern|env.allow|env.deny|env_allow|env_deny' crates/nono-cli/src/cli.rs >> /tmp/34-08a-baseline.txt

       # File line counts (informational; record for SUMMARY)
       wc -l crates/nono-cli/src/profile/mod.rs crates/nono-cli/src/exec_strategy/env_sanitization.rs crates/nono-cli/src/cli.rs >> /tmp/34-08a-baseline.txt

       cat /tmp/34-08a-baseline.txt
       ```

    6. **Workspace must be clean before starting:**
       ```bash
       git status --porcelain | wc -l   # Expected: 0
       ```

    7. **Verify 34-08-ENV-DENY-PLAN.archive.md exists (the parent plan that was archived):**
       ```bash
       test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08-ENV-DENY-PLAN.archive.md
       ```

    8. **Confirm Plan 34-04b SUMMARY exists (the immediate dependency that landed canonical-schema base):**
       ```bash
       test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-SUMMARY.md
       ```
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; for sha in 1b412a7 3657c935 780965d7 a022e5c7 31f2fc27; do git cat-file -e ${sha}^{commit} || exit 1; done &amp;&amp; test -f /tmp/34-08a-upstream-meta.txt &amp;&amp; test -f /tmp/34-08a-baseline.txt &amp;&amp; test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08-ENV-DENY-PLAN.archive.md &amp;&amp; test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-SUMMARY.md &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - All 5 upstream artifact SHAs (1b412a7 + 3657c935 + 780965d7 + a022e5c7 + 31f2fc27) reachable from upstream remote.
    - /tmp/34-08a-upstream-meta.txt records full_sha + subject + author + email + tag for all 5 artifacts (feeds D-19 + Manual-replay trailer blocks in Tasks 3-7).
    - /tmp/34-08a-baseline.txt records: PRE_HEAD, LEARN_WINDOWS_SHA (D-34-B2 anchor), capabilities.aipc count (>= 17), ProfileDeserialize count (>= 1), bypass_protection count (>= 1), never_grant+apply_deny_overrides count (>= 21), validate_path_within count (>= 9), find_denied_user_grants count (>= 1), Phase 20-03 cli.rs env-surface count (>= 4), and file line counts.
    - Workspace clean (`git status --porcelain` empty).
    - Archived 34-08 plan + 34-04b SUMMARY exist on disk.
    - Baseline `cargo build --workspace` exits 0.
  </acceptance_criteria>
  <done>
    Pre-state captured; 5 upstream artifacts reachable; fork-defense baselines recorded; learn_windows.rs SHA anchor captured; ready for disposition checkpoint.
  </done>
</task>

<task type="checkpoint:decision" gate="blocking">
  <name>Task 2: Disposition checkpoint — confirm 5-artifact disposition table</name>
  <files>/tmp/34-08a-disposition.txt</files>
  <read_first>
    - /tmp/34-08a-upstream-meta.txt (per-artifact author + subject + body captured in Task 1)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08-ENV-DENY-PLAN.archive.md § disposition rationale for archival
  </read_first>
  <action>
    **BLOCKING CHECKPOINT — pauses for user input.** The user has already approved the 34-08 → (34-08a + 34-08b) split shape via /gsd-execute-phase 34 --wave 2 with Option B. This checkpoint formally records the disposition table for downstream tasks and gives the user a final ratify-or-amend touch point before per-artifact execute tasks begin.

    **Default disposition table** (pre-approved; planner may adjust if upstream-meta from Task 1 reveals surprises):

    | # | SHA | Default disposition | Rationale |
    |---|-----|---------------------|-----------|
    | 1 | `1b412a7` (v0.37.0) | **D-20 manual replay** | v0.37.0 env-filter surface base; Phase 20-03 commit b4762e63 ported only the cli.rs flag-parsing slice; this replay lands the deferred profile/mod.rs + env_sanitization.rs + runtime call-sites |
    | 2 | `3657c935` (v0.52.0) | **straight cherry-pick** | feat: add deny_vars to env filter; security-critical; should be clean after Task 3's base surface lands |
    | 3 | `780965d7` (v0.52.0) | **straight cherry-pick** | fix: empty allow vars fails closed; security regression fix |
    | 4 | `a022e5c7` (v0.52.0) | **straight cherry-pick** | docs: deny_vars + allow_vars usage; small docs delta |
    | 5 | `31f2fc27` (v0.52.0) | **cherry-pick (partial)** | chore: release v0.52.0; drop Cargo.toml + Cargo.lock version-bumps; merge CHANGELOG entry only (mirror Plan 34-04 commits 3 + 12 + Plan 34-04b Task 5 partial-cherry-pick shape) |

    **Context:** Plan 34-08 (archived) attempted the v0.52.0 cluster C12 as a 10-commit autonomous cherry-pick chain. Empirical discovery on commit 1/10 (`3657c935`) showed the fork has only a PARTIAL Phase 20-03 env-filter surface port — CLI flag-parsing landed in Phase 20-03 (`b4762e63` "Manual port of upstream 1b412a7 restricted to crates/nono-cli/src/cli.rs only") but the rest of the surface (EnvironmentConfig, runtime wiring, env_sanitization.rs helpers) was deferred. Without the deferred surface in place, `3657c935`'s deny_vars feature cannot apply. 34-08a closes that deferral.

    **Resume options (reply with the bracketed token):**
    - `[proceed-default]` — approve the default disposition table (1 manual-replay + 4 cherry-picks, partial cherry-pick for 31f2fc27).
    - `[adjust-dispositions: <describe-changes>]` — modify the per-artifact disposition table before proceeding.

    After user reply, write the resolved dispositions to `/tmp/34-08a-disposition.txt`:
    ```
    1b412a7 → manual-replay
    3657c935 → cherry-pick
    780965d7 → cherry-pick
    a022e5c7 → cherry-pick
    31f2fc27 → cherry-pick-partial (drop Cargo.toml + Cargo.lock version bumps)
    ```
  </action>
  <verify>
    <automated>test -f /tmp/34-08a-disposition.txt &amp;&amp; test "$(grep -cE '^1b412a7|^3657c935|^780965d7|^a022e5c7|^31f2fc27' /tmp/34-08a-disposition.txt)" = "5"</automated>
  </verify>
  <acceptance_criteria>
    - /tmp/34-08a-disposition.txt records dispositions for all 5 upstream artifact SHAs.
    - User has approved or amended the default table.
  </acceptance_criteria>
  <done>
    Per-artifact dispositions recorded for all 5 upstream artifacts; user ratification captured.
  </done>
</task>

<task type="auto">
  <name>Task 3: D-20 manual replay — `1b412a7` v0.37.0 env-filter surface (Phase 20-03 deferral)</name>
  <files>
    crates/nono-cli/src/profile/mod.rs
    crates/nono-cli/src/exec_strategy/env_sanitization.rs
    crates/nono-cli/src/command_runtime.rs
    crates/nono-cli/src/execution_runtime.rs
    crates/nono-cli/src/launch_runtime.rs
    crates/nono-cli/src/main.rs
    crates/nono-cli/src/profile_runtime.rs
    crates/nono-cli/src/sandbox_prepare.rs
    crates/nono-cli/src/exec_strategy.rs
    crates/nono/src/capability.rs
  </files>
  <read_first>
    - `git show 1b412a7` (full upstream diff)
    - `git show 1b412a7 -- crates/nono-cli/src/` (production-code diff — focus on EnvironmentConfig struct + is_env_var_allowed + validate_allow_vars_pattern + call-site wiring)
    - `git show 1b412a7 -- crates/nono-cli/src/profile/` (profile-side changes — the deferred Phase 20-03 surface)
    - `git show 1b412a7 -- crates/nono-cli/src/exec_strategy/env_sanitization.rs` (the helpers to add)
    - `git log --oneline 1b412a7^..b4762e63 -- crates/nono-cli/src/cli.rs` (verify Phase 20-03 ported the cli.rs slice; understand what was deferred)
    - `git show b4762e63` (the partial Phase 20-03 port — fork's existing cli.rs surface; MUST NOT be overwritten)
    - .planning/templates/upstream-sync-quick.md § Fork-divergence catalog (validate_path_within retention; hooks ownership; D-21 Windows-only file globs) + § D-19 cherry-pick trailer block + § D-20 Manual-replay commit-body convention
    - /tmp/34-08a-upstream-meta.txt (upstream author metadata for the Manual-replay trailer)
    - /tmp/34-08a-disposition.txt (confirm manual-replay disposition from Task 2)
    - /tmp/34-08a-baseline.txt (capabilities.aipc + ProfileDeserialize + bypass_protection + never_grant + validate_path_within + Phase 20-03 cli.rs env-surface baselines)
  </read_first>
  <action>
    This is the **D-20 manual replay** for upstream commit `1b412a7` per D-34-E3. NO `git cherry-pick` — read upstream's diff in full, identify the INTENT (EnvironmentConfig struct + Profile.environment field + ProfileDeserialize.environment field + is_env_var_allowed + validate_allow_vars_pattern helpers + 6+ runtime call-sites), and apply the intent BY HAND against the fork's current state WITHOUT overwriting the Phase 20-03 already-landed cli.rs slice AND WITHOUT deleting fork-only paths (Plan 18.1-03 capabilities.aipc; Phase 22-01 ProfileDeserialize; Plan 34-04b bypass_protection canonical-schema).

    **Step 1: Read upstream's diff structure.**
    ```bash
    git show 1b412a7 --stat > /tmp/34-08a-1b412a7-stat.txt
    wc -l /tmp/34-08a-1b412a7-stat.txt
    git show 1b412a7 -- crates/nono-cli/src/profile/mod.rs > /tmp/34-08a-1b412a7-profile-diff.txt
    git show 1b412a7 -- crates/nono-cli/src/exec_strategy/env_sanitization.rs > /tmp/34-08a-1b412a7-env-diff.txt
    git show 1b412a7 -- crates/nono-cli/src/cli.rs > /tmp/34-08a-1b412a7-cli-diff.txt
    ```
    Identify the structural changes:
    - `EnvironmentConfig` struct (with `allow_vars: Vec<String>` field at minimum at v0.37.0; deny_vars comes in 3657c935 v0.52.0)
    - `Profile.environment: Option<EnvironmentConfig>` field
    - `ProfileDeserialize.environment: Option<EnvironmentConfig>` field
    - `is_env_var_allowed(name: &str, config: &EnvironmentConfig) -> bool` helper
    - `validate_allow_vars_pattern(pattern: &str) -> Result<...>` helper
    - Call-site wiring in command_runtime / execution_runtime / launch_runtime / main / profile_runtime / sandbox_prepare / exec_strategy
    - Any `crates/nono/src/capability.rs` env-filter capability hooks if upstream adds them at v0.37.0

    **Step 2: Apply the intent by hand against fork's current state.**

    Sub-step 2a: EnvironmentConfig + Profile.environment + ProfileDeserialize.environment (`profile/mod.rs`):
    - Add `EnvironmentConfig` struct to the appropriate section of profile/mod.rs (mirror upstream's location semantically; fork's profile/mod.rs is divergent but the canonical-schema sections from Plan 34-04b should make placement clear).
    - Add `environment: Option<EnvironmentConfig>` field to `Profile` struct.
    - Add `environment: Option<EnvironmentConfig>` field to `ProfileDeserialize` companion struct (Phase 22-01 PROF-01..03 retained pattern).
    - **PRESERVE** Plan 18.1-03 `capabilities.aipc` / `loaded_profile` paths.
    - **PRESERVE** Phase 22-01 `ProfileDeserialize` companion-struct pattern (compose the new environment field with the existing pattern).
    - **PRESERVE** Plan 34-04b `bypass_protection` canonical-schema field.

    Sub-step 2b: is_env_var_allowed + validate_allow_vars_pattern helpers (`exec_strategy/env_sanitization.rs`):
    - Add `is_env_var_allowed(name: &str, config: &EnvironmentConfig) -> bool` per upstream's v0.37.0 shape (deny_vars is NOT in v0.37.0; comes in cherry-pick 3657c935 below).
    - Add `validate_allow_vars_pattern(pattern: &str) -> Result<...>` per upstream's v0.37.0 shape.
    - **PRESERVE** fork's existing partial helpers + cross-platform parser (already present per archived Plan 34-08).
    - The new helpers compose with Phase 20-03's `parse_env_filter_pattern` from cli.rs.

    Sub-step 2c: Propagate the wiring through runtime call sites:
    - `crates/nono-cli/src/command_runtime.rs` — wire env-filter at command-exec boundary.
    - `crates/nono-cli/src/execution_runtime.rs` — wire env-filter at execution boundary.
    - `crates/nono-cli/src/launch_runtime.rs` — wire env-filter at launch boundary.
    - `crates/nono-cli/src/main.rs` — top-level env-filter wiring if upstream's v0.37.0 adds it here.
    - `crates/nono-cli/src/profile_runtime.rs` — wire env-filter at profile-runtime boundary.
    - `crates/nono-cli/src/sandbox_prepare.rs` — `PreparedSandbox` / `SandboxArgs` carries `Option<EnvironmentConfig>` if upstream's v0.37.0 shape requires.
    - `crates/nono-cli/src/exec_strategy.rs` — top-level env-filter wiring; emit env-filter call before child process spawn.
    - `crates/nono/src/capability.rs` — env-filter capability hooks if upstream's v0.37.0 adds them.

    Sub-step 2d: DO NOT touch:
    - `crates/nono-cli/src/cli.rs` parse_env_filter_pattern + --env-allow + --env-deny flags (Phase 20-03 `b4762e63` already ported these; this manual replay EXTENDS the surface, does NOT overwrite the cli.rs slice).
    - `crates/nono-cli/src/learn_windows.rs` (D-11 + D-34-B2 ETW path invariant; byte-identity required).
    - Any `*_windows.rs` or `exec_strategy_windows/` file (D-34-E1 invariant).

    Sub-step 2e: Build + test:
    ```bash
    cargo build --workspace
    # If build fails, hand-resolve until build is green. Likely failure modes:
    # - Missing import for EnvironmentConfig in runtime call-sites
    # - ProfileDeserialize companion-struct field-completeness assertion
    # - SandboxArgs constructor signature mismatch in callers
    # - Phase 22-01 PROF-01..03 deserialize visitor needs updating to include the new `environment` field

    cargo test -p nono-cli --lib profile           # Profile-module tests
    cargo test -p nono-cli --lib env_sanitization  # Env-sanitization tests
    # Tests should pass; if they fail with config-shape errors, hand-resolve.
    ```

    Sub-step 2f: CLAUDE.md test discipline (CRITICAL):
    - Any new tests touching `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, or custom env vars MUST save and restore the original value (Rust runs unit tests in parallel within the same process).
    - Use the save/restore pattern; keep the modified env-var window as short as possible.
    - This is load-bearing for env_sanitization tests in particular.

    **Step 3: Fork-divergence sentinels (run AFTER build green, BEFORE commit):**
    ```bash
    grep -c 'capabilities.aipc\|capabilities_aipc\|loaded_profile' crates/nono-cli/src/profile/mod.rs   # Expected: >= baseline from /tmp/34-08a-baseline.txt
    grep -c 'ProfileDeserialize\|struct ProfileDeserialize' crates/nono-cli/src/profile/mod.rs          # Expected: >= 1
    grep -c 'bypass_protection' crates/nono-cli/src/profile/mod.rs                                       # Expected: >= 1
    grep -c 'never_grant\|apply_deny_overrides' crates/nono-cli/src/policy.rs                           # Expected: >= 21
    grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs                                    # Expected: >= 9 (unchanged; this replay should not touch package_cmd.rs)
    grep -c 'find_denied_user_grants' crates/nono-cli/src/policy.rs                                      # Expected: >= 1
    grep -cE 'parse_env_filter_pattern|env.allow|env.deny|env_allow|env_deny' crates/nono-cli/src/cli.rs # Expected: >= baseline (Phase 20-03 surface preserved)

    # NEW surface from this replay
    grep -c 'EnvironmentConfig\|environment:.*Option' crates/nono-cli/src/profile/mod.rs                # Expected: >= 3 (struct + 2 field uses)
    grep -cE 'is_env_var_allowed|validate_allow_vars_pattern' crates/nono-cli/src/exec_strategy/env_sanitization.rs  # Expected: >= 2

    # D-34-B2 invariant: learn_windows.rs untouched
    LEARN_WINDOWS_SHA_NOW=$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)
    BASELINE_SHA=$(grep '^LEARN_WINDOWS_SHA=' /tmp/34-08a-baseline.txt | cut -d= -f2)
    test "$LEARN_WINDOWS_SHA_NOW" = "$BASELINE_SHA" || { echo "FAIL: learn_windows.rs touched: $LEARN_WINDOWS_SHA_NOW != $BASELINE_SHA"; exit 1; }
    ```

    ANY sentinel that returns LESS than baseline is a STOP trigger — revert the replay edits and re-investigate.

    **Step 4: Stage + commit with Manual-replay trailer.**
    ```bash
    # Pull author metadata from /tmp/34-08a-upstream-meta.txt
    UPSTREAM_AUTHOR_NAME=$(grep -A1 '==== 1b412a7' /tmp/34-08a-upstream-meta.txt | grep 'author=' | sed -E 's/.*author=([^ ]+).*/\1/')
    UPSTREAM_AUTHOR_EMAIL=$(grep -A1 '==== 1b412a7' /tmp/34-08a-upstream-meta.txt | grep 'email=' | sed -E 's/.*email=([^ ]+).*/\1/')
    # If the parsing above is unreliable for "First Last <email>" multi-word author names, source directly:
    UPSTREAM_AUTHOR=$(git log -1 1b412a7 --format='%an <%ae>')

    git add -A
    git commit -m "$(cat <<EOF
    feat(env-sanitization): port v0.37.0 env-filter surface (Phase 20-03 deferral)

    Upstream's 1b412a7 (v0.37.0) introduces the env-filter surface: EnvironmentConfig
    struct, Profile.environment + ProfileDeserialize.environment fields, is_env_var_allowed
    + validate_allow_vars_pattern helpers, and runtime call-site wiring across
    command_runtime, execution_runtime, launch_runtime, main, profile_runtime,
    sandbox_prepare, and exec_strategy.

    Phase 20-03 commit b4762e63 ("Manual port of upstream 1b412a7 restricted to
    crates/nono-cli/src/cli.rs only") ported the CLI flag-parsing slice
    (--env-allow / --env-deny flags + parse_env_filter_pattern function) but
    DELIBERATELY deferred the rest of the surface — profile/mod.rs struct/field
    additions, exec_strategy/env_sanitization.rs helpers, and runtime call-site
    wiring. This replay closes that deferral.

    Replayed by hand (D-20 per D-34-E3) rather than via straight cherry-pick because:
      - Phase 20-03 explicitly restricted to cli.rs; cherry-picking 1b412a7 directly
        would re-apply the cli.rs slice on top of fork's already-landed version,
        producing spurious conflicts.
      - Without the deferred surface (EnvironmentConfig, runtime wiring) in place,
        every v0.52.0 env-touching cherry-pick — starting with 3657c935 (deny_vars
        feature) — fails to apply. Plan 34-08 (archived as
        34-08-ENV-DENY-PLAN.archive.md) discovered this empirically on its first
        cherry-pick attempt.
      - Fork's profile/mod.rs carries deep divergence from Plan 18.1-03
        (capabilities.aipc widening), Phase 22-01 (ProfileDeserialize companion-struct
        pattern), and Plan 34-04b (canonical-schema bypass_protection state). A straight
        cherry-pick would risk silently deleting or shadowing these fork-only paths.

    Fork-only paths PRESERVED through this replay (baseline counts from /tmp/34-08a-baseline.txt):
      - Plan 18.1-03 capabilities.aipc / loaded_profile widening (>=17 callsites in profile/mod.rs)
      - Phase 22-01 ProfileDeserialize companion-struct pattern (>=1 callsite in profile/mod.rs)
      - Plan 34-04b canonical-schema bypass_protection field (>=1 callsite in profile/mod.rs)
      - Phase 19 v2.1 never_grant / apply_deny_overrides (21 callsites in policy.rs; not touched)
      - Phase 22-03 PKG-04 validate_path_within (9 callsites in package_cmd.rs; not touched)
      - Plan 34-04 commit ac9f0a59 find_denied_user_grants helper (>=1 callsite in policy.rs)
      - Phase 20-03 cli.rs env-surface slice (parse_env_filter_pattern + --env-allow + --env-deny;
        >=baseline callsites in cli.rs; not overwritten — this replay EXTENDS the surface)
      - D-11 + D-34-B2 learn_windows.rs ETW path (SHA aa4d33dc801b631883ba9c5fc7917e0e194342a4
        UNCHANGED; D-34-E1 Windows-only file invariant 0 hits)

    NEW surface added by this replay:
      - EnvironmentConfig struct (in profile/mod.rs) with allow_vars: Vec<String> at v0.37.0
        shape (deny_vars added separately in cherry-pick 3657c935 v0.52.0)
      - Profile.environment: Option<EnvironmentConfig> field
      - ProfileDeserialize.environment: Option<EnvironmentConfig> field
      - is_env_var_allowed helper (in exec_strategy/env_sanitization.rs)
      - validate_allow_vars_pattern helper
      - Env-filter call-site wiring in 6+ runtime modules

    Per D-20 (manual port for heavily-diverged files; Phase 22 D-19 lineage;
    Plan 34-04b Task 3 precedent for the same fork-preserve-manual-replay-split
    disposition class). The Manual-replay: trailer substitutes for Upstream-commit:
    per the convention.

    Plan 34-08 (archived) attempted v0.52.0 cluster C12 as a 10-commit autonomous
    cherry-pick chain; this plan (34-08a) closes the env-surface portion (5 artifacts:
    1 manual-replay + 4 cherry-picks). The non-env portion ships in 34-08b
    (5 commits: 1d491b4d + b5f0a3ab + b34c2af6 + bbdf7b85 + 5d15b50e).

    Manual-replay: 1b412a7
    Upstream-tag: v0.37.0
    Upstream-author: ${UPSTREAM_AUTHOR}
    Co-Authored-By: ${UPSTREAM_AUTHOR}
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Step 5: Per-commit verification (mandatory — STOP on failure):**
    ```bash
    # D-34-E1: Windows-only files NOT touched
    test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" || exit 1

    # Manual-replay trailer present, NOT Upstream-commit:
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Manual-replay: 1b412a7')" = "1" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: ')" = "0" || exit 1

    # 2 DCO Signed-off-by lines
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Signed-off-by: ')" = "2" || exit 1

    # Case-sensitivity invariant
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-Author:')" = "0" || exit 1

    # D-34-B2 invariant: learn_windows.rs SHA UNCHANGED
    BASELINE_SHA=$(grep '^LEARN_WINDOWS_SHA=' /tmp/34-08a-baseline.txt | cut -d= -f2)
    test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "$BASELINE_SHA" || exit 1

    # Fork-divergence sentinels (re-run after commit; must match Step 3 results)
    test "$(grep -c 'capabilities.aipc\|capabilities_aipc\|loaded_profile' crates/nono-cli/src/profile/mod.rs)" -ge "17" || exit 1
    test "$(grep -c 'ProfileDeserialize\|struct ProfileDeserialize' crates/nono-cli/src/profile/mod.rs)" -ge "1" || exit 1
    test "$(grep -c 'bypass_protection' crates/nono-cli/src/profile/mod.rs)" -ge "1" || exit 1
    test "$(grep -c 'never_grant\|apply_deny_overrides' crates/nono-cli/src/policy.rs)" -ge "21" || exit 1
    test "$(grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs)" -ge "9" || exit 1
    test "$(grep -cE 'parse_env_filter_pattern|env.allow|env.deny|env_allow|env_deny' crates/nono-cli/src/cli.rs)" -ge "4" || exit 1

    # NEW surface present
    test "$(grep -c 'EnvironmentConfig\|environment:.*Option' crates/nono-cli/src/profile/mod.rs)" -ge "3" || exit 1
    test "$(grep -cE 'is_env_var_allowed|validate_allow_vars_pattern' crates/nono-cli/src/exec_strategy/env_sanitization.rs)" -ge "2" || exit 1
    ```
  </action>
  <verify>
    <automated>test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" &amp;&amp; test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Manual-replay: 1b412a7')" = "1" &amp;&amp; test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: ')" = "0" &amp;&amp; test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "aa4d33dc801b631883ba9c5fc7917e0e194342a4" &amp;&amp; test "$(grep -c 'capabilities.aipc\|capabilities_aipc\|loaded_profile' crates/nono-cli/src/profile/mod.rs)" -ge "17" &amp;&amp; test "$(grep -c 'never_grant\|apply_deny_overrides' crates/nono-cli/src/policy.rs)" -ge "21" &amp;&amp; test "$(grep -c 'EnvironmentConfig\|environment:.*Option' crates/nono-cli/src/profile/mod.rs)" -ge "3" &amp;&amp; test "$(grep -cE 'is_env_var_allowed|validate_allow_vars_pattern' crates/nono-cli/src/exec_strategy/env_sanitization.rs)" -ge "2" &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - HEAD commit body carries `Manual-replay: 1b412a7` (NOT `Upstream-commit:`); 2 DCO Signed-off-by lines; lowercase 'a' in `Upstream-author:` line.
    - D-34-E1 invariant: zero hits on `*_windows.rs` or `exec_strategy_windows/`.
    - D-34-B2 invariant: `learn_windows.rs` SHA == `aa4d33dc801b631883ba9c5fc7917e0e194342a4` (unchanged from Task 1 baseline).
    - Fork-defense baselines preserved: capabilities.aipc/loaded_profile >= 17, ProfileDeserialize >= 1, bypass_protection >= 1, never_grant+apply_deny_overrides >= 21, validate_path_within >= 9, find_denied_user_grants >= 1, Phase 20-03 cli.rs env-surface >= 4.
    - NEW surface present: EnvironmentConfig + environment field references in profile/mod.rs >= 3; is_env_var_allowed + validate_allow_vars_pattern in env_sanitization.rs >= 2.
    - `cargo build --workspace` exits 0.
    - Replay commit body documents: (1) upstream's intent at v0.37.0, (2) Phase 20-03 b4762e63 partial port + deferred portions, (3) what this replay adds, (4) fork-only paths preserved, (5) Plan 34-08 archived context, (6) Manual-replay: convention rationale.
  </acceptance_criteria>
  <done>
    1b412a7 v0.37.0 env-filter surface manually replayed; Phase 20-03 deferral closed; fork-defense invariants preserved; build green.
  </done>
</task>

<task type="auto">
  <name>Task 4: Cherry-pick `3657c935` — feat: add deny_vars to env filter (security-critical)</name>
  <files>
    crates/nono-cli/src/profile/mod.rs
    crates/nono-cli/src/exec_strategy/env_sanitization.rs
    (+ test files per upstream's diff)
  </files>
  <read_first>
    - `git show 3657c935 --stat` (file count + insertion/deletion totals)
    - `git show 3657c935` (full diff — focus on EnvironmentConfig.deny_vars: Vec<String> field + resolve-order precedence-over-allow_vars logic + regression tests)
    - /tmp/34-08a-upstream-meta.txt (upstream author metadata)
    - /tmp/34-08a-disposition.txt (confirm cherry-pick disposition from Task 2)
  </read_first>
  <action>
    Security-critical cherry-pick. After Task 3's base surface lands, this should be a clean cherry-pick. Standard D-19 trailer block.

    **Step 1: Attempt cherry-pick.**
    ```bash
    git cherry-pick 3657c935
    ```

    **Step 2a: If clean (no conflicts):** proceed to Step 3.

    **Step 2b: If conflicts (D-02 trigger threshold per Plan 34-04 SUMMARY = conflicts > 50 lines OR > 2 files):**
    - Abort: `git cherry-pick --abort`.
    - Investigate: are conflicts on the new env-sanitization.rs surface (likely if Task 3 placement differs from upstream's)?
    - If conflicts are small (< 50 lines, <= 2 files): hand-resolve, preserving Task 3's manual-replay shape + the new deny_vars field + precedence-over-allow_vars logic, then `git cherry-pick --continue`.
    - If conflicts exceed threshold: STOP, escalate to user, propose D-20 manual replay for this commit (would amend Task 2 disposition).

    **Step 3: Amend with D-19 trailer.**
    ```bash
    UPSTREAM_AUTHOR=$(git log -1 3657c935 --format='%an <%ae>')
    UPSTREAM_SUBJECT=$(git show -s --format='%s' 3657c935)
    UPSTREAM_BODY=$(git show -s --format='%b' 3657c935)

    git commit --amend -m "$(cat <<EOF
    ${UPSTREAM_SUBJECT}

    ${UPSTREAM_BODY}

    Upstream-commit: 3657c935
    Upstream-tag: v0.52.0
    Upstream-author: ${UPSTREAM_AUTHOR}
    Co-Authored-By: ${UPSTREAM_AUTHOR}
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Step 4: Verify deny_vars composes correctly with allow_vars + Task 3's base.**
    ```bash
    cargo build --workspace
    cargo test -p nono-cli env_sanitization

    # Sentinels: deny_vars present in both env_sanitization and profile
    test "$(grep -c 'deny_vars' crates/nono-cli/src/exec_strategy/env_sanitization.rs)" -ge "1" || exit 1
    test "$(grep -c 'deny_vars' crates/nono-cli/src/profile/mod.rs)" -ge "1" || exit 1

    # Upstream's regression test (or equivalently-named) for deny_vars precedence
    # Test name may vary — accept any of these patterns:
    cargo test -p nono-cli 2>&1 | grep -iE 'deny_vars|deny.*precedence' | head -5 || echo "WARN: no deny_vars test visible — verify against upstream's test surface"
    ```

    **Step 5: Per-commit verification.**
    ```bash
    test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: 3657c935')" = "1" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-tag: v0.52.0')" = "1" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-author: ')" = "1" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-Author:')" = "0" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Signed-off-by: ')" = "2" || exit 1

    # D-34-B2 invariant: learn_windows.rs SHA UNCHANGED
    BASELINE_SHA=$(grep '^LEARN_WINDOWS_SHA=' /tmp/34-08a-baseline.txt | cut -d= -f2)
    test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "$BASELINE_SHA" || exit 1
    ```
  </action>
  <verify>
    <automated>test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: 3657c935')" = "1" &amp;&amp; test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" &amp;&amp; test "$(grep -c 'deny_vars' crates/nono-cli/src/exec_strategy/env_sanitization.rs)" -ge "1" &amp;&amp; test "$(grep -c 'deny_vars' crates/nono-cli/src/profile/mod.rs)" -ge "1" &amp;&amp; test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "aa4d33dc801b631883ba9c5fc7917e0e194342a4" &amp;&amp; cargo build --workspace &amp;&amp; cargo test -p nono-cli env_sanitization</automated>
  </verify>
  <acceptance_criteria>
    - HEAD commit carries D-19 trailer with `Upstream-commit: 3657c935` (lowercase 'a' in `Upstream-author:`); 2 Signed-off-by lines.
    - D-34-E1 invariant: zero hits on `*_windows.rs` or `exec_strategy_windows/`.
    - D-34-B2 invariant: learn_windows.rs SHA unchanged.
    - `deny_vars` field present in BOTH env_sanitization.rs AND profile/mod.rs (>= 1 each).
    - `cargo build --workspace` exits 0.
    - `cargo test -p nono-cli env_sanitization` exits 0 (composes cleanly with Task 3 base + Task 4 deny_vars).
  </acceptance_criteria>
  <done>
    3657c935 deny_vars feature landed; deny_vars precedence over allow_vars asserted; build + targeted tests green.
  </done>
</task>

<task type="auto">
  <name>Task 5: Cherry-pick `780965d7` — fix: empty allow_vars fails closed (security regression fix)</name>
  <files>
    crates/nono-cli/src/exec_strategy/env_sanitization.rs
    (+ test files per upstream's diff)
  </files>
  <read_first>
    - `git show 780965d7 --stat`
    - `git show 780965d7` (full diff — focus on empty-allow fail-closed invariant: `allow_vars: []` + no `deny_vars` → DENY-ALL, not ALLOW-ALL)
    - /tmp/34-08a-upstream-meta.txt (upstream author metadata)
  </read_first>
  <action>
    Security regression fix. Should be clean after Task 3 (base surface) + Task 4 (deny_vars) land. Standard D-19 trailer.

    **Step 1: Cherry-pick.**
    ```bash
    git cherry-pick 780965d7
    ```

    **Step 2: Hand-resolve any small conflicts** on env_sanitization.rs.

    **Step 3: Amend with D-19 trailer.**
    ```bash
    UPSTREAM_AUTHOR=$(git log -1 780965d7 --format='%an <%ae>')
    UPSTREAM_SUBJECT=$(git show -s --format='%s' 780965d7)
    UPSTREAM_BODY=$(git show -s --format='%b' 780965d7)

    git commit --amend -m "$(cat <<EOF
    ${UPSTREAM_SUBJECT}

    ${UPSTREAM_BODY}

    Upstream-commit: 780965d7
    Upstream-tag: v0.52.0
    Upstream-author: ${UPSTREAM_AUTHOR}
    Co-Authored-By: ${UPSTREAM_AUTHOR}
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Step 4: Verify empty-allow fail-closed invariant.**
    ```bash
    cargo build --workspace
    cargo test -p nono-cli env_sanitization

    # Smoke-check the upstream regression test landed and passes:
    # Test name may vary; accept these patterns:
    cargo test -p nono-cli 2>&1 | grep -iE 'empty_allow|fail_closed|allow_vars.*empty' | head -5
    # If no test name matches: STOP and verify the regression test ported correctly.
    # The invariant is: allow_vars: [] with no deny_vars → DENY-ALL (no env vars passed through).
    ```

    **Step 5: Per-commit verification.**
    ```bash
    test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: 780965d7')" = "1" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-Author:')" = "0" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Signed-off-by: ')" = "2" || exit 1

    # D-34-B2 invariant
    BASELINE_SHA=$(grep '^LEARN_WINDOWS_SHA=' /tmp/34-08a-baseline.txt | cut -d= -f2)
    test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "$BASELINE_SHA" || exit 1
    ```
  </action>
  <verify>
    <automated>test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: 780965d7')" = "1" &amp;&amp; test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" &amp;&amp; test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "aa4d33dc801b631883ba9c5fc7917e0e194342a4" &amp;&amp; cargo build --workspace &amp;&amp; cargo test -p nono-cli env_sanitization</automated>
  </verify>
  <acceptance_criteria>
    - HEAD commit carries D-19 trailer with `Upstream-commit: 780965d7`; 2 Signed-off-by lines.
    - D-34-E1 invariant: zero hits.
    - D-34-B2 invariant: learn_windows.rs SHA unchanged.
    - Empty-allow fail-closed regression test ports + passes (`allow_vars: []` + no `deny_vars` → DENY-ALL).
    - `cargo build --workspace` exits 0.
  </acceptance_criteria>
  <done>
    780965d7 empty-allow fail-closed security regression fix landed; invariant preserved through 34-08a base.
  </done>
</task>

<task type="auto">
  <name>Task 6: Cherry-pick `a022e5c7` — docs: deny_vars + allow_vars usage</name>
  <files>
    (mostly docs/*.mdx + maybe inline rustdoc comments; verify via `git show a022e5c7 --stat`)
  </files>
  <read_first>
    - `git show a022e5c7 --stat` (file count + insertion/deletion totals)
    - `git show a022e5c7` (full diff — likely docs-only or near-docs-only)
    - /tmp/34-08a-upstream-meta.txt (upstream author metadata)
  </read_first>
  <action>
    Docs cherry-pick. Should be clean. Standard D-19 trailer.

    **Step 1: Cherry-pick.**
    ```bash
    git cherry-pick a022e5c7
    ```

    **Step 2: Hand-resolve any small conflicts** (likely tiny — docs paths).

    **Step 3: Amend with D-19 trailer.**
    ```bash
    UPSTREAM_AUTHOR=$(git log -1 a022e5c7 --format='%an <%ae>')
    UPSTREAM_SUBJECT=$(git show -s --format='%s' a022e5c7)
    UPSTREAM_BODY=$(git show -s --format='%b' a022e5c7)

    git commit --amend -m "$(cat <<EOF
    ${UPSTREAM_SUBJECT}

    ${UPSTREAM_BODY}

    Upstream-commit: a022e5c7
    Upstream-tag: v0.52.0
    Upstream-author: ${UPSTREAM_AUTHOR}
    Co-Authored-By: ${UPSTREAM_AUTHOR}
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Step 4: Per-commit verification.**
    ```bash
    test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: a022e5c7')" = "1" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-Author:')" = "0" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Signed-off-by: ')" = "2" || exit 1

    # D-34-B2 invariant
    BASELINE_SHA=$(grep '^LEARN_WINDOWS_SHA=' /tmp/34-08a-baseline.txt | cut -d= -f2)
    test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "$BASELINE_SHA" || exit 1

    cargo build --workspace
    ```
  </action>
  <verify>
    <automated>test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: a022e5c7')" = "1" &amp;&amp; test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" &amp;&amp; test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "aa4d33dc801b631883ba9c5fc7917e0e194342a4" &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - HEAD commit carries D-19 trailer with `Upstream-commit: a022e5c7`; 2 Signed-off-by lines.
    - D-34-E1 invariant: zero hits.
    - D-34-B2 invariant: learn_windows.rs SHA unchanged.
    - `cargo build --workspace` exits 0.
  </acceptance_criteria>
  <done>
    a022e5c7 deny_vars + allow_vars usage docs landed.
  </done>
</task>

<task type="auto">
  <name>Task 7: Cherry-pick partial `31f2fc27` — chore: release v0.52.0 (drop Cargo version bumps; CHANGELOG only)</name>
  <files>
    CHANGELOG.md
  </files>
  <read_first>
    - `git show 31f2fc27 --stat` (file count — Cargo.toml bumps + CHANGELOG)
    - `git show 31f2fc27 -- CHANGELOG.md` (the entry to merge)
    - `git show 31f2fc27 -- '*.toml' Cargo.lock` (the version bumps to DROP)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04-PATH-CANON-SCHEMA-SUMMARY.md § Commits table § commits 3 + 12 (partial-cherry-pick shape precedent)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-PLAN.md § Task 5 (partial-cherry-pick precedent within Phase 34)
    - /tmp/34-08a-upstream-meta.txt (upstream author metadata)
  </read_first>
  <action>
    Partial cherry-pick. Mirror Plan 34-04 commits 3 (`d49585b8` v0.46.0 release) + 12 (`7a01e32a` v0.47.0 release) + Plan 34-04b Task 5 (`0cba04a5` v0.47.1 release) partial-cherry-pick shape: drop Cargo.toml/Cargo.lock version-bumps; merge CHANGELOG entry only.

    **Step 1: Cherry-pick with --no-commit.**
    ```bash
    git cherry-pick --no-commit 31f2fc27
    ```

    **Step 2: Reset Cargo.toml + Cargo.lock to fork's version (drop the bump).**
    ```bash
    git status --porcelain | grep -E 'Cargo.toml|Cargo.lock'

    # Reset each Cargo file to its pre-cherry-pick state
    for f in $(git diff --cached --name-only -- '*.toml' Cargo.lock); do
      git checkout HEAD -- "$f"
    done

    # Verify only CHANGELOG.md (and possibly some non-version doc files) remain staged
    git diff --cached --name-only
    # Expected: CHANGELOG.md only (verify against upstream's diff)
    ```

    **Step 3: Commit with D-19 trailer.**
    ```bash
    UPSTREAM_AUTHOR=$(git log -1 31f2fc27 --format='%an <%ae>')

    git commit -m "$(cat <<EOF
    chore: release v0.52.0

    Upstream version bumps in Cargo.toml + Cargo.lock NOT applied (fork tracks its own
    v2.3+/v2.4 versioning scheme per .planning/STATE.md). CHANGELOG entry for v0.52.0
    merged for downstream sync provenance only.

    Mirrors Plan 34-04 commits 3 (d49585b8 v0.46.0 release) and 12 (7a01e32a v0.47.0
    release) + Plan 34-04b Task 5 (0cba04a5 v0.47.1 release) partial-cherry-pick shape:
    drop upstream version bumps; merge CHANGELOG entry for traceability.

    Upstream-commit: 31f2fc27
    Upstream-tag: v0.52.0
    Upstream-author: ${UPSTREAM_AUTHOR}
    Co-Authored-By: ${UPSTREAM_AUTHOR}
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Step 4: Per-commit verification.**
    ```bash
    test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: 31f2fc27')" = "1" || exit 1
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-tag: v0.52.0')" = "1" || exit 1

    # Verify Cargo.toml/Cargo.lock NOT in the commit
    test "$(git diff --stat HEAD~1 HEAD -- 'Cargo.toml' '**/Cargo.toml' 'Cargo.lock' | wc -l)" = "0" || exit 1

    # D-34-B2 invariant
    BASELINE_SHA=$(grep '^LEARN_WINDOWS_SHA=' /tmp/34-08a-baseline.txt | cut -d= -f2)
    test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "$BASELINE_SHA" || exit 1

    cargo build --workspace
    ```
  </action>
  <verify>
    <automated>test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: 31f2fc27')" = "1" &amp;&amp; test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')" = "0" &amp;&amp; test "$(git diff --stat HEAD~1 HEAD -- 'Cargo.toml' '**/Cargo.toml' 'Cargo.lock' | wc -l)" = "0" &amp;&amp; test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "aa4d33dc801b631883ba9c5fc7917e0e194342a4" &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - HEAD commit carries D-19 trailer with `Upstream-commit: 31f2fc27`; 2 Signed-off-by lines.
    - Cargo.toml + Cargo.lock NOT modified by this commit (version bumps dropped per Plan 34-04 + 34-04b partial-cherry-pick precedent).
    - CHANGELOG entry for v0.52.0 present.
    - D-34-E1 invariant: zero hits.
    - D-34-B2 invariant: learn_windows.rs SHA unchanged.
    - `cargo build --workspace` exits 0.
  </acceptance_criteria>
  <done>
    31f2fc27 v0.52.0 release-bump landed (CHANGELOG only; Cargo bumps dropped); env-surface cluster C12 closed for 34-08a.
  </done>
</task>

<task type="auto">
  <name>Task 8: D-34-D2 8-gate close + plan-close smoke checks</name>
  <files>(read-only — verification only; produces /tmp/34-08a-close-gates.txt for SUMMARY)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D2 (8 close-gates)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-SUMMARY.md § Verification table (skip-rationale framing for Gates 3/4/6/7/8)
    - /tmp/34-08a-baseline.txt (pre-plan baselines for sentinel comparison)
  </read_first>
  <action>
    Run D-34-D2 8-gate close + plan-close smoke checks. Mirror Plan 34-04b Task 9 + Plan 34-04 SUMMARY § Verification table for skip-rationale framing.

    **Gate 1: Workspace tests (Windows host).**
    ```bash
    cargo test --workspace --lib 2>&1 | tail -20
    # Expected: all pass. If failures: investigate; revert offending commit if needed.

    # Specific to 34-08a: env_sanitization + profile tests must pass
    cargo test -p nono-cli env_sanitization
    cargo test -p nono-cli --lib profile
    ```

    **Gate 2: Windows clippy (`-D warnings -D clippy::unwrap_used`).**
    ```bash
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
    # Expected: zero warnings, zero unwrap_used.
    ```

    **Gate 3: Linux cross-target clippy (DOCUMENTED-SKIPPED per 34-04 + 34-04b close).**
    ```bash
    echo "Gate 3 (Linux cross-target clippy): SKIPPED - deferred to CI per dev-host limitation (x86_64-linux-gnu-gcc linker not installed; user accepted same posture at 34-04 close on 2026-05-11 + 34-04b close)." > /tmp/34-08a-close-gates.txt
    ```

    **Gate 4: macOS cross-target clippy (DOCUMENTED-SKIPPED).**
    ```bash
    echo "Gate 4 (macOS cross-target clippy): SKIPPED - deferred to CI per dev-host limitation (x86_64-apple-darwin cc toolchain not installed; user accepted same posture at 34-04 close on 2026-05-11 + 34-04b close)." >> /tmp/34-08a-close-gates.txt
    ```

    **Gate 5: `cargo fmt --all -- --check`.**
    ```bash
    cargo fmt --all -- --check
    # If fmt drift: run `cargo fmt --all`, stage, create a fork-only fmt-drift commit
    # (mirror Plan 34-04 commit 6d8a7e18 shape: NO Upstream-commit: trailer; just 2 DCO Signed-off-by lines).
    ```

    **Gate 6: Phase 15 5-row detached-console smoke (DOCUMENTED-SKIPPED).**
    ```bash
    echo "Gate 6 (Phase 15 5-row detached-console smoke): SKIPPED - requires admin-elevated session; not exercised on dev host (same posture as 34-04 + 34-04b SUMMARY)." >> /tmp/34-08a-close-gates.txt
    ```

    **Gate 7: `wfp_port_integration --ignored` (DOCUMENTED-SKIPPED).**
    ```bash
    echo "Gate 7 (wfp_port_integration --ignored): SKIPPED - requires admin + nono-wfp-service installed; not exercised on dev host (same posture as 34-04 + 34-04b SUMMARY)." >> /tmp/34-08a-close-gates.txt
    ```

    **Gate 8: `learn_windows_integration` (DOCUMENTED-SKIPPED).**
    ```bash
    echo "Gate 8 (learn_windows_integration): SKIPPED - requires elevated session + ETW provider; not exercised on dev host (same posture as 34-04 + 34-04b SUMMARY). NOTE: 34-08a does NOT touch the learn deprecation commit b34c2af6 (that ships in 34-08b); learn_windows.rs SHA UNCHANGED across 34-08a chain (D-34-B2 invariant)." >> /tmp/34-08a-close-gates.txt
    ```

    **Plan-close smoke check: D-19 + Manual-replay trailer count.**
    ```bash
    PRE_HEAD=$(grep '^PRE_HEAD=' /tmp/34-08a-baseline.txt | cut -d= -f2)
    TOTAL_COMMITS=$(git log --format='%H' $PRE_HEAD..HEAD | wc -l)
    UPSTREAM_COMMIT_TRAILERS=$(git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Upstream-commit: ')
    MANUAL_REPLAY_TRAILERS=$(git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Manual-replay: ')
    SIGNED_OFF_LINES=$(git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Signed-off-by: ')

    echo "Total commits in 34-08a: $TOTAL_COMMITS" >> /tmp/34-08a-close-gates.txt
    echo "Upstream-commit: trailers: $UPSTREAM_COMMIT_TRAILERS (expected: 4 = 3657c935 + 780965d7 + a022e5c7 + 31f2fc27)" >> /tmp/34-08a-close-gates.txt
    echo "Manual-replay: trailers: $MANUAL_REPLAY_TRAILERS (expected: 1 = 1b412a7)" >> /tmp/34-08a-close-gates.txt
    echo "Signed-off-by lines: $SIGNED_OFF_LINES (expected: 2 × $TOTAL_COMMITS = $((2 * TOTAL_COMMITS)))" >> /tmp/34-08a-close-gates.txt

    # Case-sensitivity invariant
    test "$(git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Upstream-Author:')" = "0" || { echo "FAIL: case-sensitivity invariant"; exit 1; }

    # Trailer-count invariants
    test "$UPSTREAM_COMMIT_TRAILERS" = "4" || { echo "FAIL: expected 4 Upstream-commit trailers, got $UPSTREAM_COMMIT_TRAILERS"; exit 1; }
    test "$MANUAL_REPLAY_TRAILERS" = "1" || { echo "FAIL: expected 1 Manual-replay trailer, got $MANUAL_REPLAY_TRAILERS"; exit 1; }

    # 2N Signed-off-by check
    test "$SIGNED_OFF_LINES" = "$((2 * TOTAL_COMMITS))" || { echo "FAIL: expected $((2 * TOTAL_COMMITS)) Signed-off-by lines, got $SIGNED_OFF_LINES"; exit 1; }
    ```

    **D-34-E1 per-commit invariant (re-check across entire chain).**
    ```bash
    for sha in $(git log --format='%H' $PRE_HEAD..HEAD); do
      count=$(git diff --stat $sha^..$sha -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows')
      if [ "$count" != "0" ]; then
        echo "FAIL: $sha touches Windows files: $count"
        exit 1
      fi
    done
    echo "D-34-E1 per-commit invariant: PASS (0 hits across all $TOTAL_COMMITS commits)" >> /tmp/34-08a-close-gates.txt
    ```

    **D-34-B2 plan-close anchor verification.**
    ```bash
    BASELINE_SHA=$(grep '^LEARN_WINDOWS_SHA=' /tmp/34-08a-baseline.txt | cut -d= -f2)
    LEARN_WINDOWS_SHA_NOW=$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)
    test "$LEARN_WINDOWS_SHA_NOW" = "$BASELINE_SHA" || { echo "FAIL: learn_windows.rs SHA changed: $LEARN_WINDOWS_SHA_NOW != $BASELINE_SHA"; exit 1; }
    echo "D-34-B2 anchor: learn_windows.rs SHA UNCHANGED at $LEARN_WINDOWS_SHA_NOW" >> /tmp/34-08a-close-gates.txt
    ```

    **Fork-defense final sentinels.**
    ```bash
    echo "--- Fork-defense final sentinels ---" >> /tmp/34-08a-close-gates.txt
    echo "capabilities.aipc/loaded_profile: $(grep -c 'capabilities.aipc\|capabilities_aipc\|loaded_profile' crates/nono-cli/src/profile/mod.rs) (baseline >= 17)" >> /tmp/34-08a-close-gates.txt
    echo "ProfileDeserialize: $(grep -c 'ProfileDeserialize\|struct ProfileDeserialize' crates/nono-cli/src/profile/mod.rs) (baseline >= 1)" >> /tmp/34-08a-close-gates.txt
    echo "bypass_protection: $(grep -c 'bypass_protection' crates/nono-cli/src/profile/mod.rs) (baseline >= 1)" >> /tmp/34-08a-close-gates.txt
    echo "never_grant+apply_deny_overrides: $(grep -c 'never_grant\|apply_deny_overrides' crates/nono-cli/src/policy.rs) (baseline >= 21)" >> /tmp/34-08a-close-gates.txt
    echo "validate_path_within: $(grep -c 'validate_path_within' crates/nono-cli/src/package_cmd.rs) (baseline >= 9)" >> /tmp/34-08a-close-gates.txt
    echo "find_denied_user_grants: $(grep -c 'find_denied_user_grants' crates/nono-cli/src/policy.rs) (baseline >= 1)" >> /tmp/34-08a-close-gates.txt
    echo "Phase 20-03 cli.rs env-surface: $(grep -cE 'parse_env_filter_pattern|env.allow|env.deny|env_allow|env_deny' crates/nono-cli/src/cli.rs) (baseline >= 4)" >> /tmp/34-08a-close-gates.txt
    echo "NEW: EnvironmentConfig + environment field: $(grep -c 'EnvironmentConfig\|environment:.*Option' crates/nono-cli/src/profile/mod.rs) (must be >= 3)" >> /tmp/34-08a-close-gates.txt
    echo "NEW: is_env_var_allowed + validate_allow_vars_pattern: $(grep -cE 'is_env_var_allowed|validate_allow_vars_pattern' crates/nono-cli/src/exec_strategy/env_sanitization.rs) (must be >= 2)" >> /tmp/34-08a-close-gates.txt
    echo "NEW: deny_vars: $(grep -c 'deny_vars' crates/nono-cli/src/exec_strategy/env_sanitization.rs) (must be >= 1) + $(grep -c 'deny_vars' crates/nono-cli/src/profile/mod.rs) (must be >= 1)" >> /tmp/34-08a-close-gates.txt

    cat /tmp/34-08a-close-gates.txt
    ```

    All sentinels MUST be >= /tmp/34-08a-baseline.txt values. If any are below: STOP, investigate, revert offending commit.
  </action>
  <verify>
    <automated>cargo test --workspace --lib &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check &amp;&amp; test -f /tmp/34-08a-close-gates.txt &amp;&amp; PRE_HEAD=$(grep '^PRE_HEAD=' /tmp/34-08a-baseline.txt | cut -d= -f2) &amp;&amp; test "$(git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Upstream-commit: ')" = "4" &amp;&amp; test "$(git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Manual-replay: ')" = "1" &amp;&amp; test "$(git log --format='%B' $PRE_HEAD..HEAD | grep -v '^#' | grep -c '^Upstream-Author:')" = "0" &amp;&amp; test "$(git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs)" = "aa4d33dc801b631883ba9c5fc7917e0e194342a4"</automated>
  </verify>
  <acceptance_criteria>
    - Gates 1, 2, 5 PASS on Windows host. env_sanitization + profile tests green.
    - Gates 3, 4 documented-skipped with rationale "deferred to CI per dev-host limitation; user accepted same posture at 34-04 + 34-04b close".
    - Gates 6, 7, 8 documented-skipped per "admin/service/ETW provider not available on dev host" rationale.
    - Plan-close smoke: `grep -c '^Upstream-commit: '` returns exactly 4 (3657c935 + 780965d7 + a022e5c7 + 31f2fc27).
    - Plan-close smoke: `grep -c '^Manual-replay: '` returns exactly 1 (1b412a7).
    - Case-sensitivity invariant: zero `^Upstream-Author:` hits.
    - 2N Signed-off-by check: equals 2 × total commit count.
    - D-34-E1 per-commit invariant: 0 Windows-file hits across all commits in the chain.
    - D-34-B2 plan-close anchor: learn_windows.rs SHA == `aa4d33dc801b631883ba9c5fc7917e0e194342a4` (unchanged from Task 1 baseline).
    - Fork-defense sentinels all >= pre-plan baselines.
    - NEW surface sentinels: EnvironmentConfig + environment >= 3; is_env_var_allowed + validate_allow_vars_pattern >= 2; deny_vars >= 1 in each of env_sanitization.rs + profile/mod.rs.
    - /tmp/34-08a-close-gates.txt produced for SUMMARY.
  </acceptance_criteria>
  <done>
    8 close-gates evaluated; D-34-E1 + D-34-B2 + fork-defense invariants preserved across the chain; plan ready for SUMMARY + push.
  </done>
</task>

<task type="auto">
  <name>Task 9: Write SUMMARY at 34-08a-ENV-SURFACE-PORT-SUMMARY.md</name>
  <files>
    .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-ENV-SURFACE-PORT-SUMMARY.md
  </files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-SUMMARY.md (SUMMARY shape precedent)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D1 (direct-on-main; one PR per plan)
    - /tmp/34-08a-disposition.txt + /tmp/34-08a-baseline.txt + /tmp/34-08a-close-gates.txt + /tmp/34-08a-upstream-meta.txt (SUMMARY inputs)
  </read_first>
  <action>
    **Write SUMMARY at `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-ENV-SURFACE-PORT-SUMMARY.md`.**

    Mirror the 34-04b SUMMARY shape:

    - **Frontmatter:** phase, plan_number=08a, slug=env-surface-port, cluster_id=C12-env-surface, parent_plan="34-08 (archived)", status=complete, outcome, subsystem=env-sanitization, tags=[upst3, c12-env-surface, env-sanitization, deny-vars, fork-preserve, manual-replay, d-20, wave-2, split-from-34-08], requirements=[C12-env-surface], metrics (duration, completed_date=2026-05-12, commits_landed, upstream_trailers=4, manual_replay_trailers=1, windows_file_touches=0, learn_windows_sha_pre, learn_windows_sha_post, all sentinel values), dependency_graph, tech_stack, key_files, decisions (D-34-08a-DEFERRAL-01 documenting Phase 20-03 closure rationale; D-34-08a-SPLIT-01 documenting 34-08 → 34-08a + 34-08b split; D-34-08a-FORK-01 documenting fork-defense preservation).
    - **Outcome paragraph:** 5 artifacts landed (1 manual-replay for 1b412a7 v0.37.0 env-filter surface + 4 cherry-picks for 3657c935/780965d7/a022e5c7/31f2fc27 v0.52.0). Phase 20-03 partial-port deferral closed. Wave 2 progresses; 34-08b unblocked.
    - **Pre-Plan-34-08a HEAD:** captured from /tmp/34-08a-baseline.txt.
    - **Plan-34-08a HEAD:** `git rev-parse HEAD` at this step.
    - **Commits table:** mirror 34-04 SUMMARY § Commits table shape:

    | # | Upstream SHA | Upstream Tag | Disposition | Landed Fork SHA | Trailer Type | Notes |
    |---|--------------|--------------|-------------|-----------------|--------------|-------|
    | 1 | `1b412a7` | v0.37.0 | D-20 manual replay | `{fork-sha}` | Manual-replay: | EnvironmentConfig + helpers + 6+ runtime call-sites |
    | 2 | `3657c935` | v0.52.0 | cherry-pick | `{fork-sha}` | Upstream-commit: | deny_vars feature; security-critical |
    | 3 | `780965d7` | v0.52.0 | cherry-pick | `{fork-sha}` | Upstream-commit: | empty-allow fail-closed regression fix |
    | 4 | `a022e5c7` | v0.52.0 | cherry-pick | `{fork-sha}` | Upstream-commit: | deny_vars + allow_vars docs |
    | 5 | `31f2fc27` | v0.52.0 | cherry-pick (partial) | `{fork-sha}` | Upstream-commit: | release v0.52.0 CHANGELOG; Cargo bumps dropped |

    - **Verification table:** mirror 34-04b SUMMARY § Verification table; reference /tmp/34-08a-close-gates.txt.
    - **D-34-E1 Windows-only file invariant section:** 0 hits per-commit and across-chain.
    - **D-34-B2 learn_windows.rs byte-identity section:** SHA `aa4d33dc801b631883ba9c5fc7917e0e194342a4` UNCHANGED.
    - **Fork-defense invariants section:** all sentinels at or above baseline.
    - **NEW surface section:** EnvironmentConfig + helpers + deny_vars counts.
    - **Deviations:** none expected if all steps clean; document any partial-cherry-pick details or fork-only fmt-drift commits per Task 8 Gate 5.
    - **Self-Check section:** verify all baselines preserved; verify Plan 34-08 archive cited correctly; verify split-precedent cited (Phase 22-05a/22-05b + Phase 34 34-04/34-04b).
    - **Next steps:** 34-08b ready to execute (5 non-env-touching commits: 1d491b4d + b5f0a3ab + b34c2af6 + bbdf7b85 + 5d15b50e). 34-09 / 34-10 (Wave 3 manual replays) on track.
  </action>
  <verify>
    <automated>test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-ENV-SURFACE-PORT-SUMMARY.md &amp;&amp; test "$(grep -c '^phase:\|^plan_number:\|^cluster_id:\|^parent_plan:\|^status:' .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-ENV-SURFACE-PORT-SUMMARY.md)" -ge "5"</automated>
  </verify>
  <acceptance_criteria>
    - SUMMARY exists at the expected path with frontmatter (phase, plan_number=08a, cluster_id=C12-env-surface, parent_plan="34-08 (archived)", status, outcome, requirements=[C12-env-surface], metrics).
    - Outcome paragraph documents: 1 manual-replay + 4 cherry-picks; Phase 20-03 deferral closed; 34-08b unblocked.
    - Commits table lists all 5 upstream artifacts + their dispositions + landed fork shas + trailer types.
    - Verification table documents D-34-D2 8-gate results.
    - D-34-E1 + D-34-B2 + fork-defense invariant sections present.
    - Self-Check section verifies all baselines preserved.
  </acceptance_criteria>
  <done>
    SUMMARY written; ready for push + PR.
  </done>
</task>

<task type="auto">
  <name>Task 10: Push to origin/main + open PR per D-34-D1 + commit SUMMARY</name>
  <files>(git push + gh pr create — produces /tmp/34-08a-pr-url.txt)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D1 (direct-on-main; one PR per plan)
  </read_first>
  <action>
    **Step 1: Commit the SUMMARY (fork-only commit; NO Upstream-commit: trailer).**
    ```bash
    git add .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-ENV-SURFACE-PORT-SUMMARY.md
    git commit -m "$(cat <<EOF
    docs(34-08a): SUMMARY for env-surface port + 4 v0.52.0 cherry-picks (Plan 34-08a close)

    Plan 34-08a closes the env-touching subset of cluster C12 (v0.52.0). 1 D-20 manual
    replay (1b412a7 v0.37.0 env-filter surface; closes Phase 20-03 b4762e63 partial-port
    deferral) + 4 D-19 cherry-picks (3657c935 deny_vars + 780965d7 empty-allow fail-closed
    + a022e5c7 docs + 31f2fc27 release-partial) landed on main.

    Phase 22-05a/22-05b + 34-04/34-04b mid-plan-split precedents followed for the
    34-08 → 34-08a + 34-08b split. 34-08b (5 non-env-touching commits: 1d491b4d +
    b5f0a3ab + b34c2af6 + bbdf7b85 + 5d15b50e) UNBLOCKED.

    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Step 2: Push to origin/main per D-34-D1.**
    ```bash
    git push origin main
    test "$(git log origin/main..main --oneline | wc -l)" = "0" || { echo "FAIL: local main not in sync with origin/main"; exit 1; }
    ```

    **Step 3: Open PR per D-34-D1 (one PR per plan).**
    ```bash
    PR_BODY=$(cat <<EOF
    ## Summary
    - Plan 34-08a closes the env-touching subset of cluster C12 (v0.52.0). Replaces the env-touching portion of archived Plan 34-08 (34-08-ENV-DENY-PLAN.archive.md).
    - 1 D-20 manual replay (1b412a7 v0.37.0 env-filter surface — closes Phase 20-03 b4762e63 partial-port deferral; adds EnvironmentConfig + 6+ runtime call-sites + is_env_var_allowed + validate_allow_vars_pattern helpers)
    - 4 D-19 cherry-picks (3657c935 deny_vars operator-controlled denylist; 780965d7 empty-allow fail-closed security regression fix; a022e5c7 deny_vars + allow_vars usage docs; 31f2fc27 chore: release v0.52.0 — CHANGELOG only, Cargo bumps dropped per Plan 34-04 + 34-04b partial-cherry-pick precedent)
    - Phase 22-05a/22-05b + 34-04/34-04b mid-plan-split precedents followed. 34-08b (non-env subset) UNBLOCKED.

    ## Test plan
    - [x] Gate 1: cargo test --workspace --lib (Windows host) PASS; env_sanitization + profile tests green
    - [x] Gate 2: Windows clippy -D warnings -D clippy::unwrap_used PASS
    - [ ] Gate 3: Linux cross-target clippy — deferred to CI (user accepted same posture at 34-04 + 34-04b close)
    - [ ] Gate 4: macOS cross-target clippy — deferred to CI (user accepted same posture at 34-04 + 34-04b close)
    - [x] Gate 5: cargo fmt --all --check PASS
    - [ ] Gate 6: Phase 15 5-row detached-console smoke — skipped (admin required)
    - [ ] Gate 7: wfp_port_integration --ignored — skipped (admin + nono-wfp-service)
    - [ ] Gate 8: learn_windows_integration — skipped (admin + ETW provider); learn_windows.rs SHA UNCHANGED at aa4d33dc... (D-34-B2 invariant preserved)
    - [x] D-34-E1 Windows-only file invariant: 0 hits per-commit AND across the entire chain
    - [x] D-34-B2 learn_windows.rs byte-identity: SHA aa4d33dc801b631883ba9c5fc7917e0e194342a4 UNCHANGED
    - [x] Empty-allow fail-closed security invariant: allow_vars: [] + no deny_vars → DENY-ALL (test ports + passes)
    - [x] deny_vars precedence over allow_vars (test ports + passes)
    - [x] Fork-defense sentinels: capabilities.aipc/loaded_profile >= 17, ProfileDeserialize >= 1, bypass_protection >= 1, never_grant+apply_deny_overrides >= 21, validate_path_within >= 9, find_denied_user_grants >= 1, Phase 20-03 cli.rs env-surface >= 4 — all preserved
    - [x] NEW surface: EnvironmentConfig + environment field references >= 3 in profile/mod.rs; is_env_var_allowed + validate_allow_vars_pattern >= 2 in env_sanitization.rs; deny_vars >= 1 in each

    🤖 Generated with [Claude Code](https://claude.com/claude-code)
    EOF
    )

    gh pr create --title "Phase 34 Plan 08a: C12-env-surface manual replay (v0.37.0) + 4 v0.52.0 cherry-picks" --body "$PR_BODY" | tee /tmp/34-08a-pr-url.txt
    ```

    **Step 4: Track any escalations in deferred-items.md (P34-DEFER-08a-N) if applicable.**
    ```bash
    # If any task escalated to a deferred-item disposition (e.g., Task 4 conflicts forced manual-replay path), append to deferred-items.md
    # Naming convention: P34-DEFER-08a-{NN}
    # Default: no deferrals expected since the manual-replay base in Task 3 should make Tasks 4-7 clean cherry-picks.
    ```

    Capture PR URL; record in /tmp/34-08a-pr-url.txt for SUMMARY backfill.
  </action>
  <verify>
    <automated>test "$(git log origin/main..main --oneline | wc -l)" = "0" &amp;&amp; test -f /tmp/34-08a-pr-url.txt</automated>
  </verify>
  <acceptance_criteria>
    - SUMMARY commit landed with 2 DCO Signed-off-by lines (NO Upstream-commit: trailer).
    - `git push origin main` succeeds.
    - `git log origin/main..main --oneline | wc -l` returns 0 post-push.
    - PR opened via `gh pr create`; URL captured for SUMMARY backfill in /tmp/34-08a-pr-url.txt.
    - Any escalations tracked in deferred-items.md as P34-DEFER-08a-N (default: none expected).
  </acceptance_criteria>
  <done>
    Plan 34-08a closed; cluster C12-env-surface complete; 34-08b unblocked.
  </done>
</task>

</tasks>

<non_goals>
**Out of scope for 34-08a (ships in 34-08b — non-env cluster C12 subset):**
- `1d491b4d` style: run cargo fmt (macOS-touching fmt cleanup)
- `b5f0a3ab` feat(cli): enhance macos learn and run diagnostics
- `b34c2af6` feat(cli): deprecate 'nono learn' and improve diagnostics — **D-34-B2 surgical posture commit; learn_windows.rs byte-identity invariant assumed by 34-08b**
- `bbdf7b85` fix(diagnostic): parse escaped quotes in structured properties
- `5d15b50e` chore: release v0.52.0 (full release commit; sibling to 31f2fc27 in upstream history; 34-08a takes 31f2fc27, 34-08b takes 5d15b50e — Task 2 confirms there's no double-CHANGELOG conflict; if there is, escalate)

**`learn_windows.rs` byte-identity:** 34-08a does NOT touch the learn surface at all. SHA `aa4d33dc801b631883ba9c5fc7917e0e194342a4` MUST be unchanged at plan close. The learn deprecation commit (`b34c2af6`) ships in 34-08b, which assumes responsibility for its own byte-identity invariant on the ETW path per D-34-B2 surgical posture.

**No Windows-only files touched.** D-34-E1 per-commit + plan-close invariant.

**No RESL flag rename.** G-25-DRIFT-01 was closed Plan 34-00 as no-divergence; 34-08a must not introduce a rename.

**No env_sanitization rewrite.** Task 3 manual replay EXTENDS the surface (adds the deferred Phase 20-03 portions); Tasks 4-7 cherry-picks layer on top. Fork's existing partial env-sanitization helpers + cross-platform parser remain intact.

**No CLI flag rename.** `--env-allow` / `--env-deny` flags from Phase 20-03 b4762e63 remain. If `3657c935` adds a CLI flag adjustment (e.g., expanding `--env-deny` to also cover deny_vars), accept that as-is per the cherry-pick.

**No Cargo.toml/Cargo.lock version bumps.** Task 7 drops the bumps per Plan 34-04 + 34-04b partial-cherry-pick precedent. Fork tracks its own v2.3+/v2.4 versioning scheme.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Operator-defined `environment.allow_vars` / `deny_vars` in profile JSON → Profile::load deserializer | New configuration primitives; fail-closed required for empty-allow (security invariant from `780965d7`). |
| Child process env vars ← sanitized parent env via `sanitize_env` / `is_env_var_allowed` | The env-filter crosses the supervisor/child boundary at every exec_strategy variant (Direct/Monitor/Supervised). |
| Upstream v0.37.0 `1b412a7` env-filter surface → fork's Phase-20-03-partial / Phase-22-01 / Plan-18.1-03 / Plan-34-04b divergent profile/mod.rs | D-20 manual replay must preserve fork-only paths while landing the deferred surface. |
| Phase 20-03 b4762e63 cli.rs slice → 34-08a Task 3 manual replay | Already-landed slice MUST NOT be overwritten; replay extends the surface, does NOT re-apply the cli.rs portion. |
| D-11 + D-34-B2 ETW path (`learn_windows.rs`) ← any 34-08a commit | Surgical-posture invariant: byte-identity required across the entire chain. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-08a-01 | T (Tampering) | D-11 + D-34-B2 `learn_windows.rs` ETW path byte-identity | **high** | mitigate (BLOCKING) | Per-commit + plan-close SHA-equality check: `git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs` MUST equal `aa4d33dc801b631883ba9c5fc7917e0e194342a4` (captured in Task 1). Explicit must_have on byte-identity. Tasks 3-7 individually + Task 8 across-chain assert this. STOP trigger if any commit changes the SHA. |
| T-34-08a-02 | T (Tampering) | D-34-E1 Windows-only files (`*_windows.rs` / `exec_strategy_windows/`) invariant | **high** | mitigate (BLOCKING) | Per-commit `git diff --stat <prev>..<this> -- crates/ | grep -v '^#' | grep -E '_windows|exec_strategy_windows' | wc -l` must return 0. Asserted in Tasks 3-7 individually AND across the full chain in Task 8. STOP trigger if any commit touches a Windows-gated file. |
| T-34-08a-03 | E (Elevation of Privilege) | `3657c935` `deny_vars` operator-controlled denylist precedence regression — allow_vars incorrectly composes with deny_vars (e.g., allow wins over deny, opening a path for un-denylisted env-var leakage to sandboxed child) | **high** | mitigate (BLOCKING) | Task 4 ports upstream's deny_vars precedence regression test (or equivalently-named test); `cargo test -p nono-cli env_sanitization` exits 0; sentinels `grep -c 'deny_vars' crates/nono-cli/src/exec_strategy/env_sanitization.rs >= 1` AND `grep -c 'deny_vars' crates/nono-cli/src/profile/mod.rs >= 1`. Explicit must_have on deny_vars precedence. |
| T-34-08a-04 | I (Information Disclosure) | `780965d7` empty-allow fail-closed security regression — empty `allow_vars` accidentally treated as allow-all (instead of fail-closed); manual replay in Task 3 could introduce a fallback-allow that silently revokes the security invariant | **high** | mitigate (BLOCKING) | Task 3 sub-step 2b: when porting `is_env_var_allowed` helper, explicitly DO NOT add a fallback-allow path; the v0.37.0 shape (pre-fix) may have had different semantics — Task 3 should bring the v0.37.0 base AND Task 5 cherry-pick (`780965d7`) confirms the fail-closed fix. Task 5 ports the upstream `empty_allow_fails_closed` regression test; `cargo test -p nono-cli env_sanitization::tests::empty_allow_fails_closed` (or equivalently-named) exits 0. Explicit must_have on `allow_vars: []` + no `deny_vars` → DENY-ALL on Windows AND POSIX paths. |
| T-34-08a-05 | R (Repudiation) | D-19 trailer-block missing on cherry-picks Tasks 4-7; Task 3 manual replay uses wrong trailer (Upstream-commit: instead of Manual-replay:) | **high** | mitigate (BLOCKING) | Per-commit verification in Tasks 3-7 + plan-close smoke check in Task 8: `grep -c '^Upstream-commit: '` = 4 + `grep -c '^Manual-replay: '` = 1 + `grep -c '^Upstream-Author:'` = 0 + `grep -c '^Signed-off-by: '` = 2N. Task 3 explicitly uses `Manual-replay: 1b412a7` (NOT `Upstream-commit:`). |
| T-34-08a-06 | T (Tampering) | Env-var test pollution — env_sanitization tests modify `HOME`, `PATH`, custom env vars without save/restore; Rust runs unit tests in parallel within the same process, causing flaky failures in unrelated tests (e.g., `config::check_sensitive_path`) | medium | mitigate | Per CLAUDE.md "Environment variables in tests" convention: any new test in Task 3 sub-step 2f or Tasks 4/5 that modifies `HOME`/`TMPDIR`/`XDG_CONFIG_HOME`/custom env vars MUST save and restore the original value with the save/restore pattern. Modified env-var window must be as short as possible. Task 3 sub-step 2f explicitly calls this out. Explicit acceptance criterion on test discipline. |
</threat_model>

<verification>
- All 5 upstream artifacts dispositioned (Task 2): 1 manual-replay + 4 cherry-picks (partial for 31f2fc27); default disposition approved or amended.
- `1b412a7` D-20 manually replayed (Task 3): EnvironmentConfig + Profile.environment + ProfileDeserialize.environment fields added; is_env_var_allowed + validate_allow_vars_pattern helpers added; 6+ runtime call-sites wired; Phase 20-03 cli.rs surface PRESERVED (not overwritten); fork-only paths PRESERVED.
- `3657c935` cherry-picked (Task 4) with D-19 trailer; deny_vars precedence over allow_vars asserted.
- `780965d7` cherry-picked (Task 5) with D-19 trailer; empty-allow fail-closed regression test ports + passes.
- `a022e5c7` cherry-picked (Task 6) with D-19 trailer; docs landed.
- `31f2fc27` partial-cherry-picked (Task 7) with D-19 trailer; Cargo bumps dropped; CHANGELOG entry only.
- D-34-D2 8-gate close (Task 8): Gates 1, 2, 5 PASS; Gates 3, 4, 6, 7, 8 documented-skipped per 34-04 + 34-04b SUMMARY precedent.
- Plan-close smoke (Task 8): `grep -c '^Upstream-commit: '` = 4; `grep -c '^Manual-replay: '` = 1; `grep -c '^Upstream-Author:'` = 0; `grep -c '^Signed-off-by: '` = 2N.
- D-34-E1 per-commit invariant (Task 8): 0 Windows-file hits across the entire chain.
- D-34-B2 anchor (Task 8): learn_windows.rs SHA == `aa4d33dc801b631883ba9c5fc7917e0e194342a4` unchanged from Task 1 baseline.
- Fork-defense sentinels (Task 8): all >= baseline (capabilities.aipc/loaded_profile >= 17; ProfileDeserialize >= 1; bypass_protection >= 1; never_grant+apply_deny_overrides >= 21; validate_path_within >= 9; find_denied_user_grants >= 1; Phase 20-03 cli.rs env-surface >= 4).
- NEW surface sentinels (Task 8): EnvironmentConfig + environment >= 3; is_env_var_allowed + validate_allow_vars_pattern >= 2; deny_vars >= 1 in each of env_sanitization.rs + profile/mod.rs.
- SUMMARY written (Task 9) + pushed to origin/main + PR opened (Task 10).
</verification>

<success_criteria>
- 6 commits on `main` (1 manual-replay for 1b412a7 + 4 cherry-picks for 3657c935/780965d7/a022e5c7/31f2fc27 + 1 SUMMARY commit; +/- 1 fork-only fmt-drift commit per Task 8 Gate 5 if needed).
- All cherry-pick commits (Tasks 4-7) carry verbatim D-19 trailer block (lowercase 'a' in `Upstream-author:`; 2 Signed-off-by lines per commit).
- Task 3 manual-replay commit carries `Manual-replay: 1b412a7` trailer (NOT `Upstream-commit:`); body documents Phase 20-03 deferral closure + fork-only preservation + Plan 34-08 archive context.
- Zero edits to `*_windows.rs` / `exec_strategy_windows/` files across the entire chain (D-34-E1 verified per-commit AND across-chain in Task 8).
- `learn_windows.rs` SHA `aa4d33dc801b631883ba9c5fc7917e0e194342a4` UNCHANGED at plan close (D-34-B2 invariant).
- All fork-defense sentinels preserved at or above baseline.
- NEW surface present: EnvironmentConfig + helpers + deny_vars + environment field references all at expected counts.
- Empty-allow fail-closed security invariant preserved + tested.
- deny_vars precedence over allow_vars asserted + tested.
- D-34-D2 8-gate close: Gates 1, 2, 5 PASS; Gates 3, 4, 6, 7, 8 documented-skipped per 34-04 + 34-04b SUMMARY precedent (user accepted same posture).
- `cargo build --workspace` exits 0 at HEAD.
- `cargo test -p nono-cli env_sanitization` exits 0; `cargo test -p nono-cli --lib profile` exits 0.
- Plan 34-08a SUMMARY exists at `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-ENV-SURFACE-PORT-SUMMARY.md`.
- `git log origin/main..main --oneline | wc -l` returns 0 post-push.
- PR opened via `gh pr create`; URL captured in /tmp/34-08a-pr-url.txt.
- 34-08b (sibling plan: 5 non-env cherry-picks) UNBLOCKED.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-ENV-SURFACE-PORT-SUMMARY.md` per Task 9 instructions. Frontmatter mirrors 34-04b SUMMARY shape with cluster_id: C12-env-surface; parent_plan: "34-08 (archived)"; status: complete; outcome paragraph documents the env-filter surface port outcome + Phase 20-03 deferral closure + the 4 v0.52.0 cherry-picks; commits table lists all 5 upstream artifacts + their dispositions + landed fork shas + landed Upstream-commit: OR Manual-replay: trailer; verification table documents D-34-D2 8-gate results; D-34-08a decisions section documents the split rationale (34-08 → 34-08a + 34-08b) + the fork-defense preservation + the D-11/D-34-B2 byte-identity invariant; NEW surface section documents EnvironmentConfig + helpers + deny_vars + environment field; Self-Check section verifies all baselines preserved.
</output>
