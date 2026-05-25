---
plan_id: 48-01
phase: 48
artifact: summary
status: shipped
plan_scope: "Plan 48-01 only (Wave 0, Cluster C4). Phase 48 = 9 plans total; this closes 1 of 9. REQ-UPST6-02 NOT yet satisfied."
cluster: C4
cluster_disposition: will-sync
requirement: REQ-UPST6-02 (partial — 1 of 9 clusters)
upstream_sha_range: c2c6f2ca..863bbfd3
upstream_tag: v0.55.0
upstream_commit_count: 9
baseline_sha: 3f638dc6
fork_branch: phase-48-01-landlock-v6-af-unix
fork_pre_merge_ref: oscarmackjr-twg:pre-merge
ci_verdict: regression-free vs baseline (all remaining red lanes pre-existing on main)
cr_a_fix_rounds: 3
generated: 2026-05-24
---

# Plan 48-01 — Final Summary (SHIPPED, regression-free)

Cherry-picks the 9-commit Cluster C4 (Landlock v6 signal scoping + abstract /
pathname af_unix socket mediation) from upstream `always-further/nono`
`v0.55.0` into the fork on branch `phase-48-01-landlock-v6-af-unix` off baseline
`3f638dc6`. Satisfies **REQ-UPST6-02**.

## Cherry-pick manifest (upstream → fork)

| # | Upstream SHA | Fork SHA | Subject |
|---|-------------|----------|---------|
| 1 | `c2c6f2ca` | `caab9967` | feat(landlock): add landlock v6 signal and abstract unix socket scoping |
| 2 | `b8a32006` | `a93b2bed` | docs(capability): clarify linux signal mode behavior with landlock |
| 3 | `858ad009` | `8a4bb02f` | feat(cli): add recursive unix socket directory grants |
| 4 | `bbc652a0` | `605eae2b` | feat(unix-socket): record explicit scope for grants |
| 5 | `1e9385a7` | `ffac4e89` | feat(sandbox): add explicit allowlist for pathname af_unix sockets |
| 6 | `98f8cb18` | `08637446` | test(supervisor-linux): add unix listener for connect capability test |
| 7 | `d146001b` | `14e5149c` | fix(sandbox): correctly resolve af_unix socket paths for seccomp |
| 8 | `a0222be2` | `b6a88fea` | feat(linux): implement af_unix pathname mediation |
| 9 | `863bbfd3` | `e7da4998` | refactor(supervisor): refine ipc denial reporting and audit timestamps |

DCO sign-off + verbatim 6-line `Upstream-*` D-19 trailers on all 9.

## CRITICAL PROCESS FINDING — the close-gate matrix was Windows-only and unreliable

`48-01-CLOSE-GATE.md` claimed **8/8 gates PASS** (build clean, 43 test suites /
0 failures, fork-invariant preservation, etc.). **Those claims were produced on
the Windows dev host, which does not compile `cfg(target_os = "linux")`,
`cfg(target_os = "macos")`, or the `nix`-dependent test modules.** Every error
below lived in code the Windows close-gate structurally could not see. The
"all 9 cherry-picks landed cleanly + 8/8 PASS" foundation only ever validated
the Windows compilation surface.

This is the `feedback_clippy_cross_target` failure mode, but deeper than a lint:
the conflict resolutions silently **dropped fork security invariants** (the
capability-request wire shape and the approval-decision API in the seccomp
approval path) and left the macOS af_unix feature **half-wired**. Surfaced only
after pushing to the fork-internal PR `oscarmackjr-twg#3` (`pre-merge → main`),
which is the first time the Linux + macOS CI lanes compiled this code.

**Lesson for future UPST cherry-pick plans:** the close-gate MUST include the
cross-target CI lane diff as a *blocking* gate, not a deferred one, for any
cluster touching `cfg(unix)`/`cfg(linux)`/`cfg(macos)` code. A Windows-host
`cargo build/test` PASS is not evidence for those branches. See updated memory
`feedback_clippy_cross_target`.

## Three CR-A fix rounds (post-push, on the fork-internal PR #3)

| Round | Fork SHA | Surface | Fixes |
|-------|----------|---------|-------|
| 1 | `f072eef7` | lib (Linux) | (a) remove duplicate `libc::AF_UNIX` match arm cp-conflict left in `sandbox/linux.rs` (E0063 missing `unix_kind`/`unix_path`); (b) `has_bind_ports` → `_has_bind_ports` unused param; (c) convert 3 Rust-2024 let-chains in `supervisor_linux.rs` (323/355/381) to nested if-let. Unblocked FFI Header + Phase 37 lanes. |
| 2 | `715f979b` | nono-cli (Linux + cross) | Restore fork invariants cp5 (`ffac4e89`) clobbered: (a) `CapabilityRequest` construction `#[allow(deprecated)]` + 4 AIPC-01 fields (`session_token`/`kind`/`target`/`access_mask`); (b) `decision.is_granted()` → `is_approved()` (Phase-45 D-45-C3 rename); (c) delete 4 duplicate test fns a cp re-added (E0428); (d) delete upstream-only `user_preferences_violation` test; (e) revert `should_offer_profile_save` test callsites 5-arg → fork 4-arg. Unblocked Linux Clippy/Test. |
| 3 | `4e3a7799` | nono (macOS) | Wire `emit_unix_socket_rules(&mut profile, caps)?` into the `Blocked` + `ProxyOnly` branches of `generate_profile` (sandbox/macos.rs). cp3 (`8a4bb02f`) added the helper + `regex_escape_path_for_seatbelt` but the conflict resolution dropped both call sites, leaving the macOS af_unix seatbelt feature dead (`-D warnings` dead-code). Restores upstream v0.55.0 wiring. |

All three rounds are **reverts/restorations to the fork's `3f638dc6` baseline
shape** (verified via per-symbol git diff) — not new design. The other
documented fork invariants were verified intact and NOT clobbered:
T-36-01-CANONICAL exhaustive `From<ProfileDeserialize>` (`linux: raw.linux`),
Phase-36-01b `add_deny_access`, `Arc<Mutex<AuditRecorder>>` as_deref pattern.

## FORK-BEHAVIOR DECISION (flagged — confirm before adopting upstream UX)

`should_offer_profile_save` was kept at the fork's **4-arg** signature (does NOT
offer profile-save on sandbox violations alone). Upstream's **5-arg** version
offers profile-save when violations occur even on zero exit, and the dropped
`test_profile_save_prompt_triggers_on_user_preferences_violation_with_zero_exit`
test exercised that behavior. Restored fork behavior per the conservative
preserve-fork default. **Open question for a future phase:** adopt upstream's
violations-aware profile-save UX? Not adopted here.

## Baseline-aware CI lane diff (PR #3) — regression-free verdict

Green lanes (were green on baseline, green on PR): Linux Clippy, Linux Test,
Verify FFI Header, Phase 37 PKGS-04, Phase 37 RESL-NIX, Windows Build/Smoke/
Integration/Security/Regression/Packaging, Classify Changes.

Red lanes — **ALL pre-existing on `main` before Phase 48** (Class B, deferred):

| Lane | Class B root cause (NOT Phase 48) |
|------|-----------------------------------|
| Clippy (macos) | Pre-existing macОS clippy debt: unneeded returns (`cli.rs:103` byte-identical to baseline; `exec_strategy.rs:123`), useless u64 conversions (`supervisor_macos.rs:121`, `exec_strategy.rs:940`), `map().flatten()` (`exec_strategy.rs:1394` — `.flatten()` count identical baseline vs HEAD), unused `format_bytes_short` / `resource_session_id` (occurrence count identical). All in `cfg(macos)` blocks; main's macОS Clippy was `failure` on every recent full-matrix run. |
| Test (macos), Integration | Same dead-code/unused items under `-D warnings`. |
| Rustfmt | Pre-existing drift in `deny_overlap_run.rs` + `resl_nix_linux.rs` (Phase-37/44 test files NOT in Phase 48 touch list). |
| Cargo Audit | `rustls-webpki` RUSTSEC-2026-0099/0098/0104/0049 (dependency graph; Phase 48 touched zero manifests). |
| Docs Checks | Pre-existing (fast-fail; not Phase-48 surface). |
| PR Title Lint | Cosmetic (the CI-signal draft PR title is non-conventional). |

**Verdict: Phase 48 introduced zero lane regressions.** Every PR-red lane was
also red on `main`. The C4 cherry-picks (with the 3 CR-A rounds) compile and
pass cross-platform everywhere the baseline was green.

## Deferred to a CI-cleanup effort (Class B)

The fork's `main` branch has been red across macОS clippy / Rustfmt / Cargo
Audit / Docs Checks for ~weeks — predating Phase 48 and spanning surfaces
unrelated to af_unix. Draining this is a distinct effort (candidate: the
deferred Phase 46 "post-merge CI verifications", or a new CI-cleanup phase), not
part of UPST6 C4 sync. Tracked as a carry-forward concern in STATE.md.

## Deviations from the original plan (vs the partial-summary's 4)

The partial-summary recorded 4 deviations. This SHIPPED summary adds the 3 CR-A
rounds above (8 additional fixes) — all attributable to the Windows-only
close-gate missing cross-target compilation. Net: the cherry-picks as originally
landed did NOT compile on Linux or macOS; they do now.

## Requirement status

**REQ-UPST6-02: IN PROGRESS — this plan closes 1 of 9 clusters.** Phase 48 is a
9-plan / 9-cluster / 4-wave phase covering 42 cross-platform commits across
`v0.54.0..v0.57.0` (per `48-CONTEXT.md`). This SUMMARY covers **only Plan 48-01
(Wave 0, Cluster C4 — af_unix/landlock-v6, 9 commits)**, fully discharged:
9 D-19 cherry-picks landed, fork invariants preserved (after 3 CR-A restoration
rounds), cross-platform compile + test green where baseline was green, D-19
trailers + Windows-only-files invariant honored, baseline-aware CI gate
executed (regression-free), landed on `main`.

**REQ-UPST6-02 is NOT yet satisfied** — Plans 48-02..48-09 (Waves 1-3: clusters
C1/C2/C5/C6/C7/C8/C9/C3, ~33 more commits) remain unexecuted. Run via
`/gsd-execute-phase 48`. v2.6 is NOT ready for milestone close.

**Process note:** the `HANDOFF.json` / `.continue-here.md` that drove this
session framed 48-01 as the *sole* plan in Phase 48 — an artifact of those files
being authored on the `pre-merge` branch, which forked from `3f638dc6` before
the 9 Phase 48 plan files were created on `main`. The true 9-plan scope surfaced
only when `pre-merge` was merged back to `main`.
