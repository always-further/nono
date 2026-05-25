---
title: "nono: upstream v0.55.0..v0.57.0 sync (Phase 48)"
target: always-further/nono:main
head: oscarmackjr-twg/nono:main
status: DRAFT — review before opening
---

# nono: upstream v0.55.0..v0.57.0 sync (Phase 48)

Syncs the `oscarmackjr-twg/nono` fork with upstream `always-further/nono` across
`v0.54.0..v0.57.0` (42 commits, 9 clusters). This is the Phase 48 UPST6 sync execution
umbrella — covering 8 will-sync clusters (D-19 cherry-picks) and 1 fork-preserve cluster
(D-20 manual-replay). All changes land in upstream-chronological order with verbatim
6-line D-19 attribution trailers on every cherry-picked commit.

---

## Cluster summary

| Plan | Cluster | Type | Upstream range | Commits | Tag |
|------|---------|------|---------------|---------|-----|
| 48-01 | C4: Landlock v6 signal/socket + af_unix | cherry-pick | `c2c6f2ca..863bbfd3` | 9 | v0.55.0 |
| 48-02 | C1: Profile shadowing + pack verification | cherry-pick | `0b05508f..750f4653` | 9 | v0.55.0+v0.57.0 |
| 48-03 | C2: Startup timeout + dead infra cleanup | cherry-pick | `2bed3565..50272a03` | 7 | v0.56.0 |
| 48-04 | C5: Linux deny-overlap diagnostic polish | cherry-pick | `4fa9f6a6..1122c315` | 3 | v0.55.0 |
| 48-05 | C6: macOS exact-path grant restore + localhost | cherry-pick | `2c3742ab..abca959a` | 3 | v0.55.0 |
| 48-06 | C7: PTY proxy + musl Ioctl portability | cherry-pick | `1f552106..279af554` | 4 | v0.55.0 |
| 48-07 | C8: Proxy credential_format on inject headers | cherry-pick | `57005737..530306ee` | 2 | v0.55.0 |
| 48-08 | C9: Package manifest + trust-bundle schema | D-20 manual-replay | `5f1c9c73..8d774753` | 2 | v0.55.0 |
| 48-09 | C3: Release-ride CHANGELOG absorption | stacked trailer | `35f9fea2..10cec984` | 1† | v0.55.0–v0.57.0 |

†C3 is one fork commit with 3 stacked D-19 trailer blocks (one per upstream release SHA) per D-48-D1 + Convention Pattern A.

**Total upstream SHAs absorbed: 42** (40 via `Upstream-commit:` D-19 trailers + 2 via `Upstream-replayed-from:` D-20 trailers)

---

## What changed

### C4 — Landlock v6 signal/socket + af_unix pathname mediation (Plan 48-01)

Adds Landlock v6 signal scoping and pathname af_unix socket mediation. New capability types:
`LandlockScopePolicy`, `landlock_scope_policy`, `landlock_scope_policy_with_abi`. Recursive
unix socket directory grants. Explicit allowlist for pathname af_unix sockets. Seatbelt
`emit_unix_socket_rules` wired into macOS generate_profile branches.

Fork adaptations: 3 post-cherry-pick reconciliation rounds to restore fork's AIPC-01
`CapabilityRequest` fields, Phase-45 `ApprovalDecision::is_approved` rename, and macOS
af_unix rule emission call sites that the cherry-picks dropped.

### C1 — Profile shadowing + pack signer verification (Plan 48-02)

Strengthens profile trust: blocks init when name shadows a builtin/pack profile, verifies
pack signer identities against trust bundle, ensures source pack is included for verification.
`NonoError::Cancelled` added for structured init refusal. Fast path updated to support
versioned `org/pack@version` refs via `parse_package_ref`.

### C2 — `--startup-timeout` flag + dead infrastructure removal (Plan 48-03)

Adds configurable process startup timeout (`--startup-timeout N`). Improves interactive
detection (alt-screen required). Removes dead `startup_prompt` infrastructure (193-line file
reduced to 54 lines). Fixes SIGTERM→SIGKILL inconsistency in Linux IPC supervisor timeout path.

### C5 — Linux deny-overlap diagnostic quieting (Plan 48-04)

Quiets per-deny `WARN` spam in `validate_deny_overlaps`. Conflicts now summarized in the
fatal `SandboxInit` error. `open_port 0` rejection check moved to top-level of
`apply_with_abi` (fires for all restricted-network modes, not just Landlock-net-enabled ABIs).

### C6 — macOS exact-path grant restore + localhost wildcard (Plan 48-05)

Unifies `restore_exact_path_capability` for macOS exact-path and future-file grants.
`open_port: [0]` treated as `localhost:*` TCP outbound wildcard on macOS (generates
`(allow network-outbound (remote tcp "localhost:*"))`). Linux rejects port 0 with
`NonoError::SandboxInit`.

### C7 — PTY proxy fixes + musl Ioctl portability (Plan 48-06)

Preserves child output without trailing newline on PTY detach. Fixes `libc::Ioctl` type
mismatches for `x86_64-unknown-linux-musl` (replaces `as libc::c_ulong` casts with
`as libc::Ioctl` / `as _`). Forwards bare ESC immediately in `filter_client_input`.

### C8 — Proxy `credential_format` on inject headers (Plan 48-07)

Makes `credential_format` `Option<String>` in `RouteConfig` / `CustomCredentialDef`. `None`
resolves to `Bearer {}` for `Authorization` headers, bare `{}` for all others, via new
`resolved_credential_format()` helper (case-insensitive `Authorization` match).

### C9 — Package manifest + trust-bundle schema extension (Plan 48-08) — D-20 manual-replay

Fork divergence (~6 conflict sites) made D-19 cherry-pick non-viable; replayed as D-20
manual-replay with `Upstream-replayed-from:` trailers. Equivalent security posture:

- `installed_artifact_relative_path` populates `installed_path` + `sha256_digest` in
  `.nono-trust.bundle` entries (enables precise offline artifact location for D-32-15).
- `validate_manifest_install_paths` pre-installation duplicate-path check.
- Guards reserved filenames (`package.json`, `.nono-trust.bundle`) against attacker-crafted manifests.
- Fork-authored: `validate_bundle_relative_path` (rejects traversal, absolute paths, empty strings).
- **D-48-C3 mandatory regression test** (`tests/offline_verify_extended_trust_bundle.rs`, 3 tests
  all green): extended bundle parsing, legacy bundle backwards compat, path traversal rejection.

Deferred: `infer_artifact_type` removal + `update_lockfile` manifest-param refactor (fork's
`Hook`/`Script` ArtifactType variants not in upstream; future plan).

### C3 — Release-ride CHANGELOG absorption (Plan 48-09)

One fork commit with 3 stacked D-19 trailer blocks absorbs CHANGELOG sections from
v0.55.0, v0.56.0, and v0.57.0 in chronological order. Upstream Cargo.toml + Cargo.lock
version bumps dropped (fork tracks its own version separately per release-ride convention).

---

## Fork-side deviations

| # | Cluster | Deviation | Class |
|---|---------|-----------|-------|
| 1 | C4 (48-01) | cp9 used `format!()` in post-fork child branch (CR-01 async-signal safety) | Rule 1 auto-fix: replaced with `const MSG_*: &[u8]` + `libc::write` |
| 2 | C4 (48-01) | Rust 2024 let-chain syntax in 2 sites; fork is Edition 2021 | Converted to nested `if let` |
| 3 | C4 (48-01) | cp8 touched `exec_strategy_windows/mod.rs` (9 lines — `RollbackExitContext` struct field compat) | D-48-E1 addendum: struct-compat, ≤9 lines, documented |
| 4 | C2 (48-03) | Rust 2024 let-chain syntax in 4 sites | Converted; C2-06 + C2-07 landed as empty commits |
| 5 | C8 (48-07) | `validate_proxy_override` dropped (references `ProxyInjectConfig` absent in fork) | Fork divergence; deferred to future plan |
| 6 | C8 (48-07) | mTLS/TLS-intercept/`RouteStore::lookup_*` upstream tests removed | Rule 1 auto-fix: APIs absent in fork |
| 7 | C9 (48-08) | Full cluster replayed as D-20 instead of cherry-picked | Fork divergence at 6 sites; documented in `48-08-DISPOSITION-RESOLUTION-DEFERRED.md` |

---

## Windows-only-files invariant (D-48-E1)

The only Windows-pathed file that appears in the diff is `exec_strategy_windows/mod.rs`
(Deviation 3 above, C4). The change is 9 lines of struct-field call-site update for
`RollbackExitContext` — zero hunks inside `#[cfg(target_os = "windows")]` blocks in any
shared file. Accepted per Phase 40 four-condition addendum (required cross-platform struct
field, default-factory only, ≤9 lines, documented).

---

## CI status

- **Baseline SHA:** `3f638dc6`
- **Fork-internal PR #3 (C4):** regression-free (all lanes that were green on baseline are green)
- **Plans 48-02..48-09:** local build + test suite passes (1830+ tests); cross-target CI deferred
  to operator push (musl + Linux cross-toolchain not installed on macOS dev host)
- **Pre-existing failures:** 1 test (`audit_verify_reports_signed_attestation_with_pinned_public_key`) —
  sandbox denies CWD read in the test runner; predates Phase 48; Class-B CI debt

---

## Requirement satisfied

**REQ-UPST6-02** — Upstream v0.54.0..v0.55.0+ sync execution: all 9 clusters discharged.
Phase 47 DIVERGENCE-LEDGER.md rows C1–C9 now closed.

---

## How to open this PR

```bash
# From the oscarmackjr-twg/nono fork, targeting always-further/nono:main
gh pr create \
  --repo always-further/nono \
  --head oscarmackjr-twg:main \
  --base main \
  --title "nono: upstream v0.55.0..v0.57.0 sync (Phase 48)" \
  --body-file .planning/phases/48-upst6-sync-execution/48-UPSTREAM-PR-DRAFT.md
```

After opening, update `48-SUMMARY.md` frontmatter:
  `pr_umbrella_url: "always-further/nono#<actual-number>"`
