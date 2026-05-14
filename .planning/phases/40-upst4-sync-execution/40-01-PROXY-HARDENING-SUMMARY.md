---
phase: 40-upst4-sync-execution
plan: 01
subsystem: proxy
tags: [upst4, c1, proxy, network, libdbus, node26, wave-1, v0.52.1]

# Dependency graph
requires:
  - phase: 39-upst4-audit
    provides: cluster C1 disposition (will-sync, 5 commits) + commit chain inventory
  - phase: 40-02-CLI-ALLOW-VALIDATE
    provides: Wave 0 foundation (CLI --allow validation, sandbox state shape)
  - phase: 40-03-SCRUB-MODULE
    provides: Wave 0 foundation (nono::scrub re-export from lib.rs)
provides:
  - libdbus isolated from no-keyring nono-ffi builds (critical for Windows MSI distribution)
  - NODE_USE_ENV_PROXY env var set in proxy child env for Node.js 20.6+ built-in fetch()
  - Accurate KeystoreAccess warning message + corrected CredentialStore::load() doc comment
  - Node 26 → Node 20.6+ comment refinements in server.rs (impl + test)
  - 5 cherry-picked commits with verbatim D-19 6-line trailer block
affects: [40-04-RELEASE-RIDE, 40-06-FP-PROXY-TLS]

# Tech tracking
tech-stack:
  added: []  # all commits are upstream-as-is; no new fork dependencies
  patterns:
    - "D-19 verbatim trailer block on each cherry-pick (lowercase 'Upstream-author:')"
    - "Wave 1 baseline-aware CI regression gate (Task 5)"
    - "Surgical retrofit: C1 surface absorbed, C5 (TLS/credential-matching) deferred to Plan 40-06"

key-files:
  created: []
  modified:
    - bindings/c/Cargo.toml (default-features = false on nono dep)
    - crates/nono-proxy/src/server.rs (NODE_USE_ENV_PROXY env var + test refinements)
    - crates/nono-proxy/src/credential.rs (KeystoreAccess warning message + doc comment)
    - crates/nono/src/keystore.rs (CR-A follow-on: gate system_keystore_label on system-keyring feature)

key-decisions:
  - "Cherry-picks applied in true upstream chronological order (abc86f6, d57375e, be8cd00, eedfbcd, 5e6e7ca), not the plan's listed order — per plan frontmatter must_haves.truths invariant."
  - "C1 / C5 boundary preserved at every conflict resolution: TLS-intercept env vars and OAuth2 credential blocks held back for Plan 40-06."
  - "abc86f6 Cargo.toml conflict resolved by preserving fork's version '0.53.0' while applying upstream's default-features = false flag."
  - "Wave 1 baseline-aware CI gate caught one regression (Verify FFI Header) caused directly by abc86f6's default-features change; fixed in commit 4665ae75 as Plan 40-01 CR-A follow-on (Phase 25 CR-A class)."

patterns-established:
  - "Baseline-aware CI regression diff: compare HEAD CI jobs against last code-touching commit's CI jobs (not the docs-only docs-changeskipped CI run). Pre-existing failures stay Phase 41 scope; only success→failure transitions are regressions."
  - "Cross-target feature-graph dead-code: Windows-host clippy cannot catch `#[cfg(feature = ...)]` dead-code regressions when default-features changes — must compile with --no-default-features locally OR rely on CI."

requirements-completed: [REQ-UPST4-02]

# Metrics
duration: ~90min
completed: 2026-05-14
---

# Phase 40 Plan 01: PROXY-HARDENING Summary

**Cluster C1 (v0.52.1, 5 commits) cherry-picked onto fork main with D-19 trailers — libdbus isolated from no-keyring builds, NODE_USE_ENV_PROXY set for Node 20.6+, accurate keystore warnings, with C1/C5 boundary preserved and one CR-A class regression caught + fixed via the Task 5 baseline-aware CI gate.**

## Performance

- **Duration:** ~90 min (including two CI run wait cycles)
- **Started:** 2026-05-14
- **Completed:** 2026-05-14
- **Tasks:** 5 plan tasks + 1 deviation-fix follow-on
- **Files modified:** 4 (`bindings/c/Cargo.toml`, `crates/nono-proxy/src/server.rs`, `crates/nono-proxy/src/credential.rs`, `crates/nono/src/keystore.rs`)
- **Commits landed:** 6 (5 cherry-picks + 1 CR-A follow-on)

## Accomplishments

- libdbus feature-unification isolated from no-keyring nono-ffi builds (critical for the fork's Windows MSI distribution path — Windows Credential Manager via keyring v3, not libsecret/dbus)
- NODE_USE_ENV_PROXY=1 set in `ProxyHandle::env_vars()` so Node.js 20.6+ built-in fetch() reads HTTPS_PROXY (covers Node 26 + undici 8.x and older)
- Accurate KeystoreAccess warning message ("Credential ... not available for route ... Managed-credential requests on this route will be denied until the credential is available.") and corrected doc comment on `CredentialStore::load()`
- Node 26 → Node 20.6+ comment refinement in `server.rs` impl + matching test assertion
- D-19 trailer block on every cherry-pick (5/5, verbatim 6-line shape with lowercase `Upstream-author:`)
- D-40-E1 holding (0 Windows-file edits across the 5-commit chain; pre-plan Windows sentinel SHA `96886ae9` unchanged)
- D-40-E6 holding (NODE_USE_ENV_PROXY in cross-platform `ProxyHandle::env_vars()` only; `grep -r 'NODE_USE_ENV_PROXY' crates/nono-cli/src/exec_strategy_windows/` returns 0)
- C1 / C5 boundary preserved (C5 SHAs `8ddb143`, `54c7552`, `f77e0e3` absent from the chain — verified via the post-chain smoke gate)
- PR #922 body appended with Plan 40-01's contribution section
- Task 5 baseline-aware CI gate caught one regression (`Verify FFI Header`) before it could merge silently — fix landed in 4665ae75; final CI diff = zero regressions

## Task Commits

Each task was committed atomically. Upstream chronological order:

1. **Task 2 cherry-pick 1/5:** abc86f6 — `fix: prevent feature unification from linking libdbus in no-keyring builds` → `3649d48d`
2. **Task 2 cherry-pick 2/5:** d57375e — `fix(proxy): set NODE_USE_ENV_PROXY for Node 26` → `320d1376`
3. **Task 2 cherry-pick 3/5:** be8cd00 — `fix: provide more accurate warning message + doc comment update` → `8c65999d`
4. **Task 2 cherry-pick 4/5:** eedfbcd — `Update crates/nono-proxy/src/server.rs` → `e418bbce`
5. **Task 2 cherry-pick 5/5:** 5e6e7ca — `Update crates/nono-proxy/src/server.rs` → `d47d6f37`
6. **Task 5 CR-A follow-on:** `fix(40-01): gate system_keystore_label on system-keyring feature` → `4665ae75`

(SUMMARY-doc commit follows separately.)

## Files Created/Modified

- `bindings/c/Cargo.toml` — added `default-features = false` to the `nono` dependency entry (preserves fork's version "0.53.0" pin). Prevents feature unification from forcing `system-keyring` (and transitively libdbus on Linux) into no-keyring nono-ffi consumers.
- `crates/nono-proxy/src/server.rs` — added the `NODE_USE_ENV_PROXY=1` env var push to `ProxyHandle::env_vars()` (3 lines + 8 comment lines) and updated the test assertion from `is_none()` to `is_some()` with value-check. Comment text refined to "Node.js 20.6+".
- `crates/nono-proxy/src/credential.rs` — applied upstream's KeystoreAccess match arm in the regular credential path; added `warn` to the `use tracing::` import line (required for the arm to compile, Rule 2); refined the doc comment on `CredentialStore::load()` and the KeystoreAccess warning message.
- `crates/nono/src/keystore.rs` — CR-A follow-on: gated `system_keystore_label()` with `#[cfg(feature = "system-keyring")]` to match its only callers, and tightened the Windows-only test's gate to `#[cfg(all(target_os = "windows", feature = "system-keyring"))]`. Fixes the `Verify FFI Header` CI regression caused by abc86f6's `default-features = false`.

## Decisions Made

- **DEC-1:** Cherry-picks applied in true upstream chronological order (`abc86f6 → d57375e → be8cd00 → eedfbcd → 5e6e7ca`), not the plan's `<interfaces>` table or Task 2 action-block order. Plan frontmatter `must_haves.truths` mandates chronological — that takes precedence over the action block when the two disagree.
- **DEC-2:** Each cherry-pick's conflict resolution was scoped against the C1 / C5 boundary documented in D-40-B2. Where upstream's commit reached into C5 surface (OAuth2 credential block in `credential.rs`, TLS-intercept env vars in `server.rs::ProxyHandle::env_vars`, `tls_connector` parameter on `CredentialStore::load`), the C5 hunks were held back for Plan 40-06.
- **DEC-3:** docs/cli/features/networking.mdx upstream sentence was skipped — the fork's networking.mdx is a much shorter, divergent shape that does not have the "Proxy Modes" paragraph upstream's one-line edit targets. Zero-net-edit on docs for this commit; deferred to a later docs-rebase phase.
- **DEC-4:** When Task 5's baseline-regression gate caught the `Verify FFI Header` job going `success → failure`, classified it as Rule 1 (mechanical, minimal-scope fix completing the abc86f6 pattern) rather than Rule 4 STOP. Reasoning: causation was crystal clear (abc86f6's `default-features = false` exposed an ungated `system_keystore_label()`), fix was a 1-line `#[cfg]` attribute, no architectural decision needed. The executor brief's "STOP on Windows-side regression" hedge was for ambiguous Windows-job failures where libdbus + BrokerPath might interact — but the FFI Header job runs on `ubuntu-latest` and the failure pointed at a non-Windows file.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Cherry-pick ordering mismatch between plan text and frontmatter invariant**
- **Found during:** Task 2 (first cherry-pick attempt of 5e6e7ca per the listed table order produced a conflict that would only resolve naturally if d57375e had landed first — confirming the chronological mismatch)
- **Issue:** Plan's `<interfaces>` table and Task 2 action block listed commits as `5e6e7ca eedfbcd be8cd00 abc86f6 d57375e` (last-tag-first walking), but `must_haves.truths` requires "upstream chronological order" which is `abc86f6 d57375e be8cd00 eedfbcd 5e6e7ca`.
- **Fix:** Aborted the first cherry-pick attempt; followed the frontmatter chronology instead.
- **Files modified:** none directly; affected which commits got applied in which sequence
- **Verification:** `git log -1 --format='%H %ai %s' <sha>` for each of the 5 SHAs confirmed the dates. Post-chain commit log matches frontmatter chronology.
- **Committed in:** body of commit `3649d48d` (DEV-2 note)

**2. [Rule 2 - Missing Critical] `warn` macro not in tracing import after abc86f6 merge**
- **Found during:** Task 2 commit 1/5 (abc86f6 build verification)
- **Issue:** The `KeystoreAccess` match arm landed by abc86f6 calls `warn!()`, but `crates/nono-proxy/src/credential.rs` only imported `tracing::debug`. Build failed with "cannot find macro `warn` in this scope".
- **Fix:** Changed `use tracing::debug;` to `use tracing::{debug, warn};`. Single-line edit consistent with abc86f6's intent (the commit body explicitly says it "handles KeystoreAccess errors gracefully").
- **Files modified:** `crates/nono-proxy/src/credential.rs`
- **Verification:** `cargo build --workspace` green; `cargo build --workspace --no-default-features` green
- **Committed in:** body of commit `3649d48d` (DEV-3 note)

**3. [Rule 1 - Bug] CR-A follow-on: `system_keystore_label` unused under default-features = false**
- **Found during:** Task 5 (post-push CI baseline-regression diff)
- **Issue:** `Verify FFI Header` CI job regressed from `success` (baseline `66c6e1da`) to `failure` (Wave 1 push `d47d6f37`). Root cause: abc86f6's `default-features = false` on the FFI's `nono` dependency disabled the `system-keyring` feature, which made `system_keystore_label()` in `crates/nono/src/keystore.rs:942` unused (its only callers are inside `load_single_secret` which is already `#[cfg(feature = "system-keyring")]`). The function itself was not gated → `-D dead-code` failure on `cargo build -p nono-ffi`.
- **Fix:** Gated `system_keystore_label()` with `#[cfg(feature = "system-keyring")]` to match its only callers; tightened the Windows-only test gate to `#[cfg(all(target_os = "windows", feature = "system-keyring"))]`.
- **Files modified:** `crates/nono/src/keystore.rs` (2 line changes)
- **Verification:** local `cargo build -p nono-ffi`, `cargo build --workspace --no-default-features`, `cargo clippy --workspace --all-targets -- -D warnings` all green; CI run `25878973341` Verify FFI Header job concluded `success`.
- **Committed in:** `4665ae75` (separate from the cherry-pick chain because it's a Plan 40-01-induced regression discovered only post-push; documented as CR-A class follow-on consistent with Phase 25 CR-A `feedback_clippy_cross_target` memory and Phase 41 tracker patterns)

---

**Total deviations:** 3 auto-fixed (1 Rule 1 ordering, 1 Rule 2 missing-import, 1 Rule 1 CR-A follow-on)
**Impact on plan:** All three auto-fixes were necessary for correctness and CI green. No scope creep; no Windows files touched. C1 / C5 boundary preserved at every resolution.

## Issues Encountered

- **Docs file divergence (server.rs networking.mdx):** d57375e's one-sentence doc edit lives in upstream's "Proxy Modes" paragraph which the fork's networking.mdx doesn't have. Resolution: skipped the docs edit; recorded in the commit body. Net-zero docs edit.
- **`gh run watch` stream errors:** GitHub's API returned `INTERNAL_ERROR; received from peer` partway through `gh run watch` calls on two separate CI runs. Worked around by polling `gh run view --json status` in a sleep loop. Did not affect outcome.
- **Baseline CI run = docs-only skip:** The CI run on `92b71c8f` (the commit immediately before the cherry-pick chain) was a docs-only run with all real jobs `skipped` by the change-classifier. The true baseline for regression comparison is `66c6e1da` (run `25873014843`) — the last code-touching commit. This matches the Phase 41 tracker pattern and is the load-bearing reason Task 5 doesn't simply pick "HEAD~5 CI run".

## D-40-C2 8-check close gate

| Gate | Description | Status | Notes |
|------|-------------|--------|-------|
| 1 | `cargo test --workspace --all-features` (Windows host) | **PASS** | 689 + 1031 + 40 + ... tests green |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | **PASS** | Clean |
| 3 | `cargo clippy --target x86_64-unknown-linux-gnu` | **load-bearing-skip → CI-verified** | C cross-compiler not available on Windows host; baseline = Phase 41 pre-existing red; Wave 1 CI confirms zero regression |
| 4 | `cargo clippy --target x86_64-apple-darwin` | **load-bearing-skip → CI-verified** | Same as gate 3; CI confirms zero regression |
| 5 | `cargo fmt --all -- --check` | **PASS** | Silent |
| 6 | Phase 15 5-row detached-console smoke | **environmental-skip** | Requires interactive Windows TTY session; cannot run in this executor context |
| 7 | `wfp_port_integration` tests | **environmental-skip** | Requires WFP service admin privileges; Phase 40 plans are documented-skip per `.continue-here.md` |
| 8 | `learn_windows_integration` tests | **environmental-skip** | Requires elevated Windows execution context; Phase 40 plans are documented-skip |

**Load-bearing skip categorization (per Phase 41 lesson):** Gates 3+4 are now treated as "load-bearing skip — CI must verify" rather than "documented-skip — none". The Task 5 baseline-aware CI gate substitutes for local cross-target clippy and caught one regression (Verify FFI Header) that would have silently shipped.

## Threat-model close-out

| Threat ID | Mitigation status | Evidence |
|-----------|-------------------|----------|
| T-40-01-01 (Tampering, D-40-E1) | **mitigated** | Pre-plan Windows sentinel SHA `96886ae9` unchanged across the 5-commit chain; `git diff --stat HEAD~5 HEAD -- crates/ \| grep -E '_windows\|exec_strategy_windows' \| wc -l` returns 0 |
| T-40-01-02 (Repudiation, D-19 trailer missing) | **mitigated** | `git log --format='%B' HEAD~5..HEAD \| grep -c '^Upstream-commit: '` returns 5 (lowercase `Upstream-author:` verified) |
| T-40-01-03 (Elevation, abc86f6 keyring feature removal) | **mitigated** | Fork's `[features]` section preserved across `bindings/c/Cargo.toml` conflict resolution; only the `default-features = false` flag was applied. `cargo build --no-default-features` green locally |
| T-40-01-04 (Elevation, C5 SHA in chain) | **mitigated** | C5 SHAs `8ddb143`, `54c7552`, `f77e0e3` absent — verified by `git log --format='%H' HEAD~5..HEAD \| grep -c <sha>` returning 0 for each |
| T-40-01-05 (Spoofing, NODE_USE_ENV_PROXY in Windows exec) | **mitigated** | `grep -r 'NODE_USE_ENV_PROXY' crates/nono-cli/src/exec_strategy_windows/` returns 0 |
| T-40-01-06 (DoS, libdbus in Windows MSI) | **mitigated** | abc86f6 landed with `default-features = false` flag intact; `cargo build --no-default-features` green locally; Linux CI verified via run `25878973341` (Test, Clippy jobs remain at pre-existing red levels — no new symptoms) |
| T-40-01-07 (Spoofing, server.rs review fixes alter credential injection) | **accepted, evidence confirmed** | 5e6e7ca + eedfbcd diffs verified to be test-assertion-message-only changes; no credential-path touch |

## Self-Check: PASSED

Verified files exist:
- `bindings/c/Cargo.toml` — present, contains `default-features = false`
- `crates/nono-proxy/src/server.rs` — present, contains 5 `NODE_USE_ENV_PROXY` matches
- `crates/nono-proxy/src/credential.rs` — present, contains `use tracing::{debug, warn};` and refined doc comment
- `crates/nono/src/keystore.rs` — present, `system_keystore_label` gated on `#[cfg(feature = "system-keyring")]`

Verified commits in git log:
- `3649d48d` (abc86f6), `320d1376` (d57375e), `8c65999d` (be8cd00), `e418bbce` (eedfbcd), `d47d6f37` (5e6e7ca), `4665ae75` (CR-A follow-on) — all reachable from `main`

Verified gates:
- D-19 trailer count: 5 ✓
- D-40-E1 windows-file edits: 0 ✓
- D-40-E6 NODE_USE_ENV_PROXY in exec_strategy_windows: 0 ✓
- C5 SHA absence: 3/3 ✓
- Final CI baseline diff: 0 regressions ✓

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- **Plan 40-04 (RELEASE-RIDE)** can proceed in parallel with this plan's PR review (both are Wave 1; surface-disjoint).
- **Plan 40-06 (FP-PROXY-TLS)** inherits the C5 surface that was deliberately held back here (OAuth2 credential block in `credential.rs`, TLS-intercept env vars in `server.rs`, `tls_connector` parameter on `CredentialStore::load`). The deferred hunks are documented in commit bodies `3649d48d` (abc86f6) and `320d1376` (d57375e) and `8c65999d` (be8cd00).
- **PR #922** body updated with Plan 40-01's contribution section; the umbrella PR is the single fork → upstream contribution for the Wave 0 + Wave 1 cluster of changes.
- **Phase 41 backlog** unchanged — no new failures introduced; pre-existing red Linux/macOS Clippy + Test jobs + 5 Windows job classes remain Phase 41 scope.

---

*Phase: 40-upst4-sync-execution*
*Completed: 2026-05-14*
