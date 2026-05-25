## Plan 48-02: Cluster C1 — Profile Shadowing + Pack Verification

This section covers the **9 commits comprising Cluster C1** (profile shadowing hardening +
pack signer verification + name-resolution polish) cherry-picked from upstream
`always-further/nono` into the fork. Cluster C1 is Wave 1 of Phase 48 UPST6 sync.

**Cluster:** C1 (profile shadowing checks + pack-signer verification + init polish)
**Disposition:** `will-sync` (per fork-side Phase 47 UPST6 audit ledger row for C1)
**Upstream SHA range:** `0b05508f..750f4653` (9 commits, authored 2026-05-13..19 by Luke Hinds)
**Upstream tags:** `v0.55.0` (C1-01..C1-03) + `v0.57.0` (C1-04..C1-09)
**Fork baseline:** `3f638dc6`
**Fork branch:** `main` (sequential execution on primary worktree; Wave 1)
**Plan:** `48-02`
**Requirement contribution:** REQ-UPST6-02 (C1 cluster of 9 commits discharged)

### Cherry-pick manifest (upstream → fork)

| # | Upstream SHA | Fork SHA | Subject |
|---|-------------|----------|---------|
| 1 | `0b05508f` | `5d52a918` | fix(profile-verification): strengthen profile and pack verification checks |
| 2 | `0015f348` | `d46447df` | feat(profile): ensure source pack is included for verification |
| 3 | `b3556139` | `15a9757e` | feat(profiles): verify pack signer identities |
| 4 | `c897c8cc` | `f1a4d979` | feat(profiles): expand shadowing checks to include pack profiles |
| 5 | `bd76c6b5` | `a3b1610b` | fix(profiles): address review points on shadow-check PR |
| 6 | `0a4db57e` | `8c7e1806` | fix(profiles): block profile init when name shadows builtin or pack profile |
| 7 | `3d3d239a` | `d0b09674` | feat(profile): refine profile name resolution and init validation |
| 8 | `316c6a2c` | `e0870727` | fix(profile): handle versioned package refs in fast path |
| 9 | `750f4653` | `882420be` | fix(profile): fix fmt and test assertion after shadow-check refactor |

### Key decisions

- **Sequential execution** on the primary worktree (`main` branch) per STATE.md
  2026-05-24 Unix-host execution decision.
- **NonoError::Cancelled added** (C1-07): upstream's C1-07 introduces a `Cancelled`
  pre-condition refusal variant. Fork adds it to `NonoError` enum and wires into FFI
  exhaustive match (maps to `ErrInvalidArg`) — necessary for the profile init shadow-check
  to return a structured error.
- **profile_save_runtime.rs test adaptation** (C1-09): upstream's test
  `suggested_run_profile_name` does not exist in fork (upstream-only function). The
  corresponding shadow-check behavior was already adapted in fork's C1-04/C1-06 commits
  using `would_shadow_existing_profile`. The fmt changes in profile_cmd.rs and profile/mod.rs
  from C1-09 were applied as-is.
- **Fast path update** (C1-08): `find_pack_store_profile` fast path updated from
  `split_once('/')` to `parse_package_ref` to support versioned `org/pack@version` refs.

### Fork-side deviations (1)

| # | Deviation | Class | Disposition |
|---|-----------|-------|-------------|
| 1 | C1-09 upstream test `suggested_run_profile_name(...) = Some("hermes-local")` → `Some("hermes")` does not apply to fork (upstream-only function absent in fork's profile_save_runtime.rs 1242 lines vs upstream's 1455+) | Structural: fork variant | C1-09 applied only the fmt changes; shadow semantics already captured by fork's `would_shadow_existing_profile` test suite |

### Fork-invariant preservation

1. **Phase 36-01b exhaustive match** — no new profile struct variants added by C1;
   `impl From<ProfileDeserialize> for Profile` exhaustive match unchanged through all 9 cherry-picks
2. **Phase 36-01c canonical name** — zero new `override_deny` references introduced by C1
   (`git diff 2fab35ed..HEAD -- crates/nono-cli/src/profile/mod.rs | grep "^+.*override_deny"` → empty)
3. **Windows-only files invariant** — zero files touched under exec_strategy_windows/,
   nono-shell-broker/, or *_windows.rs in C1 cherry-picks
4. **NonoError FFI exhaustive match** — Cancelled variant added to FFI match in C1-07

### Security posture (STRIDE coverage)

- **T-48-02-01 (Spoofing — profile shadowing):** Mitigated. C1-04/05/06 prevent user profiles
  from silently overriding pack/builtin profiles. Trust-boundary integrity enforced.
- **T-48-02-02 (Tampering — pack signer verification):** Mitigated. C1-01/02/03 add hard-block
  on trust-bundle-without-lockfile provenance and verify pack signer identities.
- **T-48-02-03 (Spoofing — exhaustive match break):** Mitigated. Compile-time enforcement
  passes (cargo build -p nono-cli exits 0).
- **T-48-02-04 (Tampering — override_deny regression):** Mitigated. No new override_deny
  references introduced by C1.

### CI status

Local macOS dev host: build clean, 1074 tests pass. 17 pre-existing test failures
(parallel env-var isolation conflicts) carry forward unchanged from baseline — not introduced
by C1. Cross-target CI deferred to operator push per STATE.md execution decision.

### Source artifacts

- [`48-02-CLOSE-GATE.md`](../tree/main/.planning/phases/48-upst6-sync-execution/48-02-CLOSE-GATE.md) — 9-gate matrix
- [`48-02-SUMMARY.md`](../tree/main/.planning/phases/48-upst6-sync-execution/48-02-SUMMARY.md) — plan close summary
