---
phase: 44-review-polish-test-hygiene-drain
audited: 2026-05-20
auditor: gsd-secure-phase
asvs_level: standard
block_on: critical_open
threats_total: 14
threats_closed: 13
threats_open: 1
verdict: OPEN_THREATS
unregistered_flags: 0
plans_audited:
  - 44-01-review-polish (8 threats)
  - 44-02-test-hygiene-drain (6 threats)
---

# Phase 44 Security Audit

**Phase:** 44 — review-polish-test-hygiene-drain
**Closed:** 13/14
**Open:** 1/14 (T-44-01 — CRITICAL/BLOCKER)
**ASVS Level:** standard
**Verdict:** OPEN_THREATS — blocking finding intersects 44-REVIEW.md CR-01

## Executive Summary

Plan 44-01's WR-09 P37 production wiring of `NONO_TRUST_OIDC_ISSUER` ships a
silent trust-anchor regression that deviates from the explicit D-44-B3
acceptance contract ("if unset, falls back to current behavior"). The pre-44
"current behavior" was an explicit fail-closed `ok_or_else(...)?` requiring
the operator to pass `--issuer` for keyless `nono trust verify`; the post-44
path silently substitutes the canonical GitHub Actions OIDC issuer
(`https://token.actions.githubusercontent.com`) when both `--issuer` AND
`NONO_TRUST_OIDC_ISSUER` are unset. This is the same finding raised
independently by the code reviewer as 44-REVIEW.md CR-01 (BLOCKER), and it
intersects T-44-01 (Spoofing) directly. The audit confirms T-44-01 is OPEN.

All 13 remaining threats (5 mitigate dispositions in 44-01, 2 accept
dispositions, 4 mitigate dispositions in 44-02, 2 accept dispositions)
verify CLOSED — implementation patterns match declared mitigations and
documentation/follow-up todo artifacts are present for accept dispositions.

No unregistered new-attack-surface flags surfaced from SUMMARY.md
`## Threat Flags` (both plans explicitly declared "None").

---

## Threat Verification Table

### Plan 44-01 (review-polish)

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-44-01 | Spoofing (S) | mitigate | **OPEN (BLOCKER)** | `crates/nono/src/trust/signing.rs:191` (fallback to `GITHUB_ACTIONS_OIDC_ISSUER` when env-var unset) wired at `crates/nono-cli/src/trust_cmd.rs:976-984` (multi-subject) + `1172-1180` (single-file). Pre-44 fail-closed `ok_or_else` requirement on `user_issuer` is gone. Intersects 44-REVIEW.md CR-01 BLOCKER. The unit-test `configured_oidc_issuer_falls_back_to_github_default_when_unset` actually **codifies** the regression (asserts default-fallback returns the canonical const). See § "Open Threats" below for full evidence cite. |
| T-44-02 | Tampering (T) | accept (per D-44-B4) | CLOSED | Doc comment present at `crates/nono/src/undo/snapshot.rs:594-609` ("**Residual race window:**...tracked as follow-up `.planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md`"). Follow-up todo file exists at the cited path with full scope, acceptance criteria, and ~2-3 week estimate. Accept disposition fully documented. |
| T-44-03 | Information disclosure (I) | mitigate | CLOSED | `crates/nono-cli/src/platform.rs:180-194` — malformed REG_DWORD bails to `None` after stripping `0x`/`0X` prefix; regression test `parse_windows_registry_value_rejects_malformed_dword` at lines 801-815 pins the None-return for `"0xZZZ"` and missing-prefix `"abc"`. |
| T-44-04 | Tampering (T) | mitigate | CLOSED | `crates/nono-cli/src/platform.rs:162` — `first.eq_ignore_ascii_case(name)` for value-name comparison. Regression test `parse_windows_registry_value_accepts_case_mismatch` at lines 780-793 pins case-insensitive match for `EditionId`/`EditionID`/`EDITIONID`/`editionid`. |
| T-44-05 | Denial of service (D) | mitigate | CLOSED | `refresh_synchronous` deleted from all source files (grep returns 0 source matches; only planning-doc references remain). Plan 44-01 SUMMARY confirms deletion in Task 5 commit `c6885f4e`. |
| T-44-06 | Elevation of privilege (E) | mitigate | CLOSED | `.github/scripts/check-cli-doc-flags.sh:54-61` — explicit `if (attr ~ /hide[[:space:]]*=[[:space:]]*true/)` skip on hidden flags. Hidden flags stay hidden; parser no longer exits non-zero on intentionally-hidden flags. |
| T-44-07 | Repudiation (R) | mitigate | CLOSED | All 8 Plan 44-01 task commits (c5b89ff5, 085a4461, babf83ca, c6885f4e, 45a6a832, d21157ad, 3f82b9ca, 6ff834b2) carry `Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>` trailer. Verified via `git log -1 --format="%(trailers:key=Signed-off-by,valueonly)"`. (Note: downstream meta-commits 0120c1d5, f18ad61e, 36871ccf, 5883db1b, cfa2c331, 99afc9ca lack DCO trailers but those are outside the threat-model scope which specified "Plan 44-01" task commits.) |
| T-44-08 | Information disclosure (I) | mitigate | CLOSED | `crates/nono/src/trust/bundle.rs:1146-1160` — pin-test `verification_policy_default_enables_sct_verification` asserts `VerificationPolicy::default().verify_sct == true`. Future minor bump that flips the default fails this test. |

### Plan 44-02 (test-hygiene-drain)

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-44-02-01 | Tampering (T) | mitigate | CLOSED | `44-02-SIBLING-COORDINATION.md:6-21` — URL derivation captured at execute-time from `git remote -v`; `DERIVED_ORG=always-further` matches historically-observed value; deviation gate auto-resolved Option A. Existence-check via `gh repo view` confirmed both sibling URLs resolve before clone (lines 23-28). |
| T-44-02-02 | Repudiation (R) | mitigate | CLOSED | Both sibling commits include `Signed-off-by:` trailer per Plan 44-02 SUMMARY § Verification line 204: "7/7 fork-side commits carry DCO `Signed-off-by` trailers". Sibling SHAs `61ee6aa164` (nono-py) + `1df3e16e6a` (nono-ts) verified via `git log -1 --format='%B' \| grep -i 'signed-off-by'` in each sibling worktree per SUMMARY § Automated checks. Fork-side commits 88a6dedd, 92ba36e9, 2bdea8ea, bfe5ea11, fa2f3cee, fc5cf737, d1798ea3, d182b525 all carry DCO sign-off (verified directly). |
| T-44-02-03 | Information disclosure (I) | accept (per D-44-C1) | CLOSED | `crates/nono-cli/tests/deny_overlap_run.rs:111-127` — either-or assertion present with inline comment explaining security equivalence (lines 111-116); assertion #3 `!stdout.contains("fake-test-secret")` is unchanged at lines 124-127 (the load-bearing security check). Follow-up todo `.planning/todos/pending/44-class-d-validator-preflight-investigation.md` files the latent validator bug per D-44-C3. |
| T-44-02-04 | Denial of service (D) | mitigate | CLOSED | `.config/nextest.toml` contains two `[[profile.default.overrides]]` blocks (lines 10-12, 14-16) with `threads-required = 'num-cpus'` for `windows_run_redirects_profile_state_vars_into_writable_allowlist` + `windows_run_redirects_temp_vars_into_writable_allowlist`. Source-side doc comments at `crates/nono-cli/tests/env_vars.rs:681,1046` cross-link to the nextest config. SC#3 50-runs determinism check is PARTIAL pending live CI (cargo-nextest not installed on Windows dev host) — documented in SIBLING-COORDINATION.md lines 94-120. |
| T-44-02-05 | Elevation of privilege (E) | mitigate | CLOSED | Sibling regression test SHAs recorded: nono-py `61ee6aa16449fcbdeccb819aec051dd7492c8b0b` + nono-ts `1df3e16e6ac8ccb676eb6ae7eb7553e715d46303` (both on `44-broker-ffi-lockstep` branches). PyO3 `to_py_err` and napi-rs `to_napi_err` wildcard arms cover the `BrokerNotFound → SandboxInit-equivalent` mapping; skip()-gated contract assertions document the binding boundary until siblings expose direct broker-argv surfaces. Fork-side regressions at `bindings/c/src/lib.rs:285-291` + `crates/nono-shell-broker/src/main.rs:535,562` continue to catch drift at the Rust layer. |
| T-44-02-06 | Spoofing (S) | accept (per D-44-D2) | CLOSED | `44-02-SIBLING-COORDINATION.md:11-17` — derivation flow proven to read from `git remote -v` at execute-time (raw `UPSTREAM_URL` + `DERIVED_ORG` captured in verifier-greppable form). Hard-coded `always-further` literals in PATTERNS.md docs are context-only; deviation gate fires if `DERIVED_ORG` differs. D-44-D2 documented in `44-CONTEXT.md:97`. |

---

## Open Threats (BLOCKERS)

### T-44-01 — `configured_oidc_issuer()` silent default fallback weakens D-32-08 fail-closed semantics

**Category:** Spoofing (S)
**Disposition (declared):** mitigate
**Status:** OPEN — implementation does not match declared mitigation
**Severity:** BLOCKER (intersects 44-REVIEW.md CR-01)

**Declared mitigation:**
> "The reader rejects unparseable URLs via `url::Url::parse` (NonoError::ConfigParse); whitespace-only env values are treated as unset (fall back to canonical default); the value is consumed by `validate_oidc_issuer` which enforces URL-component-level scheme+host+port equality (CLAUDE.md § Common Footguns #1). Test `configured_oidc_issuer_rejects_malformed_env_value` pins the fail-closed branch."

**Actual implementation gap:**

The mitigation plan asserted that `validate_oidc_issuer` would gate the trust
decision via URL-component equality against an explicit pin. But the
**pin itself** is now sourced from a function that returns a hard-coded
canonical default (`GITHUB_ACTIONS_OIDC_ISSUER` =
`https://token.actions.githubusercontent.com`) when both `--issuer` and the
env-var are unset. Consequently, an operator who runs:

```
nono trust verify --identity "<regex>" <bundle>
```

…against a GitHub-Actions-signed bundle (omitting `--issuer` and with no
`NONO_TRUST_OIDC_ISSUER` exported) will now succeed where pre-44 the verify
would have failed closed with "keyless bundle requires --issuer <OIDC_URL>".
The CLI doc at `cli.rs:3046-3049` still labels `--issuer` as "REQUIRED for
keyless verify; exact match against signer's iss claim" — that doc is now
misleading.

**Evidence cites:**

1. **`crates/nono/src/trust/signing.rs:177-193`** — `configured_oidc_issuer()` returns `Ok(GITHUB_ACTIONS_OIDC_ISSUER.to_string())` on the `_` arm (env-var unset OR whitespace-only). The fallback is the **hard-coded canonical default**, not an error.

2. **`crates/nono-cli/src/trust_cmd.rs:976-984`** (multi-subject keyless verify path):
   ```rust
   let env_issuer: String;
   let req_issuer: &str = match user_issuer {
       Some(s) => s,
       None => {
           env_issuer = trust::signing::configured_oidc_issuer()
               .map_err(|e| format!("OIDC issuer configuration failed: {e}"))?;
           &env_issuer
       }
   };
   ```
   The pre-44 `ok_or_else(|| "keyless bundle requires --issuer <OIDC_URL>")?` is replaced. When `user_issuer == None` AND `NONO_TRUST_OIDC_ISSUER` is unset, `req_issuer` silently becomes `https://token.actions.githubusercontent.com`.

3. **`crates/nono-cli/src/trust_cmd.rs:1172-1180`** (single-file keyless verify path) — identical pattern, same regression.

4. **`crates/nono/src/trust/signing.rs:1217-1224`** — the unit test `configured_oidc_issuer_falls_back_to_github_default_when_unset` **codifies the regression**: it asserts that `configured_oidc_issuer().unwrap() == GITHUB_ACTIONS_OIDC_ISSUER` when the env-var is removed. This test is the implementation contract; the threat model's mitigation cite (`configured_oidc_issuer_rejects_malformed_env_value`) covers only the malformed branch, not the unset-fallback branch.

5. **`.planning/phases/44-review-polish-test-hygiene-drain/44-CONTEXT.md:132`** — D-44-B3 acceptance spec: *"the env var is read; if set, asserts as the trusted OIDC issuer at signature verification time; **if unset, falls back to current behavior**"*. Pre-44 "current behavior" when both `--issuer` AND env-var were unset was an explicit `ok_or_else(...)?` fail-closed error. The implementation deviates from this written contract.

6. **`.planning/phases/44-review-polish-test-hygiene-drain/44-REVIEW.md:57-104`** — independent code-review BLOCKER finding CR-01 raised this exact gap and provided the fix shape (`Option<String>` reader for verify paths, separate `_required()` variant) that preserves D-32-08 fail-closed semantics.

**Required remediation:**

Either of:
- Split `configured_oidc_issuer` into `configured_oidc_issuer_or_default()` (current behavior, for non-verify call sites that need a default) and `configured_oidc_issuer_required()` returning `Option<String>` with no hard-coded fallback, then call the `_required()` variant at both `trust_cmd.rs:976-984` + `1172-1180`. The verify path retains the `ok_or_else(...)?` fail-closed shape when both `--issuer` AND env-var are unset.
- OR inline the env-var read at both verify sites (per 44-REVIEW.md CR-01 fix snippet) so the verify path requires either `--issuer` or an explicitly-set non-empty `NONO_TRUST_OIDC_ISSUER`.

Either remediation must preserve a regression test that proves the verify path errors fail-closed when both inputs are absent.

**Re-audit requirement:**

After remediation, re-run `/gsd-secure-phase` to flip T-44-01 to CLOSED.
The remediation should be tracked as a Phase-44 follow-up fix (or, per
44-REVIEW.md disposition, the issue is acknowledged by the orchestrator as
a known regression with a follow-up todo filed and the phase ships with a
documented accepted risk — but accepting a CLAUDE.md § Explicit Over Implicit
violation as v2.6 baseline is itself a policy decision that should be
explicit in PROJECT.md or REQUIREMENTS.md before SECURITY.md can flip the
threat to "accept").

---

## Accepted Risks Log

| Threat ID | Disposition Rationale | Documenting Artifact |
|-----------|------------------------|----------------------|
| T-44-02 | TOCTOU residual race between `validate_restore_target` lexical check and the non-atomic `create_dir_all`/`retrieve_to`/`set_permissions` sequence. Closure requires substantial cross-platform refactor (Linux nix `*at` syscalls + macOS `*at` + Windows NtCreateFile-or-equivalent). Threat is BOUNDED by requiring a local attacker with write access INSIDE the tracked tree. | Doc comment at `crates/nono/src/undo/snapshot.rs:596-609`; follow-up todo `.planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md` with full scope + acceptance criteria. D-44-B4 in `44-CONTEXT.md`. |
| T-44-02-03 | The Class D either-or assertion (`crates/nono-cli/tests/deny_overlap_run.rs:117-123`) accepts EITHER validator pre-flight diagnostic ("Landlock deny-overlap") OR runtime Landlock filesystem denial ("Permission denied" + "No path denials were observed") as equivalent. The mechanism varies but the security guarantee is preserved by the unchanged assertion #3 `!stdout.contains("fake-test-secret")`. The latent validator pre-flight bug is tracked separately. | Inline comment at `deny_overlap_run.rs:111-116`; follow-up todo `.planning/todos/pending/44-class-d-validator-preflight-investigation.md` with 5 hypothesis branches; D-44-C1 + D-44-C3 in `44-CONTEXT.md`. |
| T-44-02-06 | `always-further` org literal appearing in PATTERNS.md / docs is context-only; the actual derivation flow at execute-time reads from `git remote -v`. The deviation gate fires if `DERIVED_ORG` differs from historically-observed value. | Derivation log at `44-02-SIBLING-COORDINATION.md:6-21` (raw `UPSTREAM_URL` + `DERIVED_ORG` captured in verifier-greppable form); D-44-D2 in `44-CONTEXT.md:97`. |

**Note on WR-03 reviewer finding:** 44-REVIEW.md WR-03 raised a concern that
the either-or assertion `runtime_denial` branch requires BOTH "Permission
denied" AND "No path denials were observed" with AND. This is a test-shape
fragility concern, not a security guarantee gap — assertion #3 still proves
the secret is not leaked. T-44-02-03's accept disposition remains valid.

---

## Audit Trail

**Files loaded** (full required reading):
- `.planning/phases/44-review-polish-test-hygiene-drain/44-01-review-polish-PLAN.md` (offset 1473, threat model block)
- `.planning/phases/44-review-polish-test-hygiene-drain/44-02-test-hygiene-drain-PLAN.md` (offset 1045, threat model block)
- `.planning/phases/44-review-polish-test-hygiene-drain/44-01-SUMMARY.md`
- `.planning/phases/44-review-polish-test-hygiene-drain/44-02-SUMMARY.md`
- `.planning/phases/44-review-polish-test-hygiene-drain/44-CONTEXT.md`
- `.planning/phases/44-review-polish-test-hygiene-drain/44-REVIEW.md`
- `.planning/phases/44-review-polish-test-hygiene-drain/44-02-SIBLING-COORDINATION.md`
- `crates/nono/src/trust/signing.rs` (full file)
- `crates/nono-cli/src/trust_cmd.rs` (verify sites 950-1242)
- `crates/nono/src/undo/snapshot.rs` (validate_restore_target context 580-620)
- `crates/nono/src/trust/bundle.rs` (SCT pin-test 1137-1160)
- `crates/nono-cli/src/platform.rs` (registry parser + tests 140-815)
- `crates/nono-cli/src/pack_update_hint.rs` (refresh_synchronous deletion verification)
- `crates/nono-cli/tests/deny_overlap_run.rs` (full file)
- `crates/nono-cli/tests/env_vars.rs` (REQ-TEST-HYG-02 doc comments)
- `.config/nextest.toml` (full file)
- `.github/scripts/check-cli-doc-flags.sh` (full file)
- `.planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md`
- `CLAUDE.md` (project conventions — § Coding Standards + Security Considerations)

**Verification commands run:**
- `git log 34519423..HEAD --format="%H %s %(trailers:key=Signed-off-by)"` — confirmed DCO trailers on all 8 Plan 44-01 + 8 Plan 44-02 task commits
- `Grep refresh_synchronous` — confirmed deletion from all source files (only planning-doc references remain)
- `Grep eq_ignore_ascii_case` on platform.rs — confirmed at line 162
- `Grep REQ-TEST-HYG-02` on env_vars.rs — confirmed cross-link doc comments at both flaky tests
- `Grep TOCTOU|race window` on snapshot.rs — confirmed doc comment at lines 596-609
- `Grep hide.*true` on check-cli-doc-flags.sh — confirmed skip clause at line 58
- `Grep verify_sct` on bundle.rs — confirmed pin-test at lines 1146-1160
- `Grep configured_oidc_issuer` on signing.rs — confirmed default-fallback at line 191 (the regression cite)
- Read trust_cmd.rs:950-1242 — confirmed CR-01 / T-44-01 regression at both verify sites

**Unregistered Flags Check:**

Both plans' SUMMARY.md `## Threat Flags` sections explicitly state "None":
- Plan 44-01 SUMMARY.md § Threat Flags (line 327-334): "None — Plan 44-01 surfaces are all defensive (fix-class) or documentation-only; no new network endpoints, auth paths, or schema changes at trust boundaries were introduced."
- Plan 44-02 SUMMARY.md § Threat Flags (line 174-184): "None. All threat boundaries from the plan's `<threat_model>` are mitigated as documented" (followed by per-threat verification rows).

No unregistered new-attack-surface flags identified.

---

## Next Actions

1. **BLOCKER remediation required for T-44-01.** The phase should not be considered fully closed for security until either (a) the verify path is refactored to preserve D-32-08 fail-closed semantics, or (b) PROJECT.md / REQUIREMENTS.md is updated to explicitly accept the silent-default-trust-anchor regression as a v2.6 policy decision (which contradicts CLAUDE.md § Explicit Over Implicit and is not recommended).

2. **44-REVIEW.md CR-01 BLOCKER** must be tracked through to resolution. The threat audit and the code review surfaced the same finding independently from different evidence paths, which strengthens the BLOCKER signal.

3. **Live-CI deferrals** noted in Plan 44-02 SC#3 (50-runs nextest determinism check) and Plan 44-01 cross-target clippy (PARTIAL on Windows host) are operational verifications outside the security threat-audit scope; they remain tracked by the verifier / orchestrator.

4. **Re-run `/gsd-secure-phase`** after T-44-01 remediation to flip the verdict to SECURED. The remaining 13 threats already verify CLOSED and do not need re-audit unless their implementation surface changes.

---

*Audited: 2026-05-20*
*Auditor: gsd-secure-phase*
