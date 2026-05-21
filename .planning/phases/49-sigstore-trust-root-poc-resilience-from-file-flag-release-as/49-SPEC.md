# Phase 49: Sigstore trust-root POC resilience — Specification

**Created:** 2026-05-21
**Ambiguity score:** 0.152 (gate: ≤ 0.20)
**Requirements:** 3 locked

## Goal

POC users on Windows/Linux/macOS can populate `<nono_home>/.nono/trust-root/trusted_root.json` without depending on `sigstore_verify::TrustedRoot::production()` — by supplying a `--from-file` path that points at a known-good JSON (released as a sibling asset alongside the `nono` binary), with a documented maintainer cadence to keep the fork's frozen fixture fresh through Sigstore root rotations.

## Background

`nono setup --refresh-trust-root` calls `nono::trust::TrustedRoot::production()` (`crates/nono-cli/src/setup.rs:841`), which delegates to `sigstore_verify` and performs a full TUF verification against the embedded trust anchor. Sigstore rotates their root signing keys; once an embedded anchor loses all its valid keys against the published `root.json`, every `--refresh-trust-root` invocation fails with `Signature threshold of 3 not met for role root (0 valid signatures)`. The fork has hit this three times — bumping `sigstore-verify` 0.6.5 → 0.6.6 → 0.7.0, each time waiting on an upstream release that re-embeds the rotated anchor.

`nono trust verify` is already offline (Phase 32 D-32-15): it reads the on-disk cache via `nono::trust::bundle::load_production_trusted_root()` (`crates/nono/src/trust/bundle.rs:147`) using plain `TrustedRoot::from_file` (`bundle.rs:113`) plus a freshness gate (`check_trusted_root_freshness`, `bundle.rs:247`). Nothing on the verify path calls `sigstore_verify`'s TUF code. **This means a side-channel populate of the cache file is sufficient to unblock verify** — that is the structural opportunity Phase 49 exploits.

Today's POC users work around the failure with a manual `Invoke-WebRequest` documented in `docs/cli/development/windows-poc-handoff.mdx:182-220`. The doc cites `sigstore-verify 0.6.5` and references `P32-DEFER-005` in a `deferred-items.md` path that no longer exists. The fork also ships a `crates/nono/tests/fixtures/trust-root-frozen.json` (126 lines) used only by `#[cfg(test)] load_test_trusted_root()` (`crates/nono/src/trust/mod.rs:74`); the GitHub Release workflow uploads `*.tar.gz/.zip/.msi/.exe/.deb/SHA256SUMS.txt` but does NOT upload this JSON (`.github/workflows/release.yml:334-340`). The `.planning/templates/` directory contains `cross-target-verify-checklist.md` and `upstream-sync-quick.md` but no Sigstore-rotation cadence template.

## Requirements

1. **REQ-POC-TRUST-01: `--from-file` flag on `nono setup`**: A new `--from-file <PATH>` flag bypasses `TrustedRoot::production()` entirely and populates the on-disk cache from a user-supplied JSON.
   - Current: `SetupArgs` (`crates/nono-cli/src/cli.rs:2341-2385`) defines `--refresh-trust-root` (network fetch + TUF verify) but no `--from-file` analog; the only way to populate the cache is `--refresh-trust-root` or a manual `Invoke-WebRequest` workaround.
   - Target: `nono setup --from-file <PATH>` reads `<PATH>`, validates it via the same pipeline the verify path uses — `nono::trust::bundle::load_trusted_root` (deserialize via `TrustedRoot::from_file`) followed by `check_trusted_root_freshness` (D-32-03 tlog `valid_for.end` expiry gate) — then copies the validated bytes to `<nono_home>/.nono/trust-root/trusted_root.json` (overwriting any existing cache). `--from-file` and `--refresh-trust-root` are clap-level mutually exclusive on the same invocation. Fail-closed with a non-zero exit and a stderr message on invalid JSON, schema mismatch (via `TrustedRoot::from_file` deserialize error), all-tlog-keys-expired, missing `<PATH>`, or unreadable `<PATH>`; no partial cache file is written on any failure path.
   - Acceptance: (a) `nono setup --from-file <good>.json` exits 0 and the cache file at `<nono_home>/.nono/trust-root/trusted_root.json` is byte-identical to `<good>.json`; (b) `nono setup --from-file <expired>.json` (all tlog `valid_for.end` in the past) exits non-zero with a stderr message referencing freshness and does NOT create or modify the cache file; (c) `nono setup --from-file <malformed>.json` exits non-zero with a stderr message referencing parse failure and does NOT create or modify the cache file; (d) `nono setup --from-file <PATH> --refresh-trust-root` is rejected by clap with a non-zero exit and a `cannot be used with` style message; (e) following a successful `--from-file`, `nono trust verify` on a known-good keyless bundle succeeds end-to-end without any network call (verify-is-offline invariant per D-32-15 preserved); (f) the verify-is-offline upstream-drift sentinel at `tests/integration/test_upstream_drift.sh:257` is unchanged or its annotation is updated to also reference this phase.

2. **REQ-POC-TRUST-02: `trusted_root.json` shipped as a release asset**: Every GitHub Release publishes `trusted_root.json` alongside the binary artifacts so POC users can `--from-file` directly off the release page.
   - Current: `.github/workflows/release.yml:334-340` uploads `*.tar.gz/.zip/.msi/.exe/.deb/SHA256SUMS.txt`. No `trusted_root.json` asset; POC users either need to `--refresh-trust-root` (broken on stale anchors), perform a `raw.githubusercontent.com` fetch against a commit SHA, or do a manual `Invoke-WebRequest` (the documented workaround).
   - Target: The release workflow copies `crates/nono/tests/fixtures/trust-root-frozen.json` into `artifacts/trusted_root.json` verbatim (`cp` or equivalent — no transformation), asserts SHA-256 byte-identity with the source fixture at the release-tag commit, includes `artifacts/trusted_root.json` in the `softprops/action-gh-release` `files:` glob, and adds its hash to `SHA256SUMS.txt` so the asset is covered by the existing release-integrity gate.
   - Acceptance: (a) `.github/workflows/release.yml` `files:` block lists `artifacts/trusted_root.json` (or a matching glob); (b) a CI step computes SHA-256 of `crates/nono/tests/fixtures/trust-root-frozen.json` and `artifacts/trusted_root.json` and fails the release job with a non-zero exit if they differ; (c) `artifacts/SHA256SUMS.txt` includes a `trusted_root.json` line; (d) a fresh `gh release view <tag>` for the first release that lands this phase shows `trusted_root.json` as a downloadable asset; (e) `curl -L <release-asset-url> -o td.json && nono setup --from-file td.json` succeeds end-to-end on a clean POC host.

3. **REQ-POC-TRUST-03: Maintainer-cadence template + cached-bytes verify smoke script**: The fork ships a documented refresh procedure plus a tiny cross-platform smoke script so the frozen fixture stays fresh through Sigstore root rotations.
   - Current: No template exists; rotation-response is ad-hoc (search inbox for the Sigstore mailing-list announcement, manually capture the new `root.json`, hope the test fixture still matches). The `Known issue: Sigstore TUF root rotation (sigstore-verify 0.6.5)` subsection in `docs/cli/development/windows-poc-handoff.mdx:182` documents a workaround that references a non-existent `deferred-items.md` path and pins to a stale `sigstore-verify` version.
   - Target: (a) `.planning/templates/sigstore-rotation-refresh.md` documents the rotation-response steps: the trigger sources (Sigstore mailing list + Sigstore blog), the capture command for the new fixture (curl from upstream `sigstore/root-signing@main`), the byte-diff-vs-prior step, the `cargo test -p nono trust::bundle::load_test_trusted_root_smoke` regression check, the maintainer commit-and-tag step, and a forward pointer to the release-asset CI gate from REQ-POC-TRUST-02; (b) `scripts/verify-trust-root-cached.sh` is a new tiny smoke script (also runnable on Windows via Git Bash or its `.ps1` sibling) that takes a path to a candidate `trusted_root.json`, runs the equivalent of `NONO_TEST_HOME=<tmp> nono setup --from-file <path> && nono trust verify <known-good-bundle> <known-good-source>` end-to-end, and exits non-zero on any failure; the template references this script as the canonical pre-commit gate; (c) `docs/cli/development/windows-poc-handoff.mdx:182-220` is rewritten — `--from-file` (pointing at the release-asset URL) becomes the primary recommended path, the `Invoke-WebRequest` manual workaround is demoted to a "if you can't reach the release page" fallback, the stale `(sigstore-verify 0.6.5)` heading is corrected to a version-agnostic phrasing, and the broken `P32-DEFER-005` / `deferred-items.md` cross-reference is removed or corrected.
   - Acceptance: (a) `.planning/templates/sigstore-rotation-refresh.md` exists with the 6 sections listed in Target (a) above; (b) `scripts/verify-trust-root-cached.sh` (or `.ps1` sibling) exists, is executable, exits 0 on a known-good fixture, and exits non-zero on a tampered fixture (one-line mutation suffices); (c) the windows-poc-handoff.mdx subsection no longer contains the strings `sigstore-verify 0.6.5` (in a heading or first-line position implying current state) or `P32-DEFER-005`; (d) the subsection's first recommendation block now references `--from-file` and a release-asset URL placeholder pattern; (e) `grep -r "Known issue: Sigstore TUF root rotation" docs/cli/development/windows-poc-handoff.mdx` returns one match whose surrounding lines no longer pin the workaround to a `sigstore-verify` version.

## Boundaries

**In scope:**
- New CLI flag `--from-file <PATH>` on the `nono setup` subcommand (`crates/nono-cli/src/cli.rs` + `crates/nono-cli/src/setup.rs`).
- Reuse of the existing `nono::trust::bundle::load_trusted_root` + `check_trusted_root_freshness` validation pipeline for the new flag — no new schema validator, no new code paths in `crates/nono`.
- Clap-level `conflicts_with` between `--from-file` and `--refresh-trust-root`.
- Release-workflow change to copy `crates/nono/tests/fixtures/trust-root-frozen.json` to `artifacts/trusted_root.json` verbatim, with a CI-asserted SHA-256 byte-identity gate.
- Addition of `trusted_root.json` to the existing `SHA256SUMS.txt` and the `softprops/action-gh-release` `files:` glob.
- `.planning/templates/sigstore-rotation-refresh.md` maintainer-cadence template.
- `scripts/verify-trust-root-cached.sh` (or sibling `.ps1` for Windows) cross-platform cached-bytes verify smoke script.
- Rewrite of the `Known issue: Sigstore TUF root rotation` subsection in `docs/cli/development/windows-poc-handoff.mdx` to recommend `--from-file` as the primary path and to remove the stale `sigstore-verify 0.6.5` / `P32-DEFER-005` references.
- Unit + integration test coverage for the new flag (happy path, expired fixture, malformed input, missing path, clap-mutex collision).

**Out of scope:**
- Bumping `sigstore-verify` (e.g., 0.7.0 → 0.7.1+) — the entire point of Phase 49 is to *exit the dep-bump treadmill*, not run another lap. Future bumps remain possible but are not load-bearing for POC unblocking.
- Adding a `jsonschema`-crate-backed schema validator for `trusted_root.json` — chose to reuse the existing `TrustedRoot::from_file` deserialize as the schema oracle (round-1 decision). Adding a separate schema validator would double the surface to maintain across Sigstore rotations.
- Content-hash-pinning `--from-file` to a known-good list of SHA-256s baked into the binary — this couples the flag to the release cadence and defeats the "any release asset works" flexibility.
- A `--force` flag or freshness-aware overwrite protection — round-1 decision is simple "last writer wins" overwrite. Reconsider in a follow-up phase if a POC user accidentally overwrites a working cache with a stale drop.
- A separate cache path for user-supplied roots (`trusted_root.user.json`) — chosen against in round 1; cache-path collision keeps the verify-path lookup unchanged.
- Predictive rotation tooling / "fetch next root before it rotates" automation — out of scope; the maintainer cadence template + manual capture is sufficient for v2.6.
- An automated `scripts/refresh-trust-root-fixture.sh` harness that does capture + diff + commit on the maintainer's behalf — round-1 decision shipped steps-only template + companion smoke script, no automation harness; deferred to v2.7 if maintainer cadence proves error-prone.
- Bundling `trusted_root.json` into the Windows MSIs — the MSIs are signed artifacts; sliding a JSON inside requires re-spinning the MSI on every rotation and breaks the "rotate fixture independently of binary" invariant. Release-asset bundling is sufficient.
- Authenticode/Sigstore-signing the `trusted_root.json` release asset itself — the file is already a published Sigstore artifact (it's the trust anchor); fork-side signing would be redundant and would require key custody. Integrity is covered by `SHA256SUMS.txt` per the existing release-integrity gate.
- Touching the verify path in `crates/nono` — D-32-15 verify-is-offline invariant is inherited, not modified.
- Modifying `crates/nono-shell-broker/` or `*_windows.rs` files — Phase 49 surface is intentionally disjoint from Windows-only files (per ROADMAP "Depends on: Nothing structural" framing).
- Hot-reload / SIGHUP-style cache refresh while `nono trust verify` is running — verify reads the cache once per invocation; no live-reload needed.
- Cross-binding lockstep with `../nono-py/` + `../nono-ts/` — the new flag is `nono-cli`-only; Python/TS bindings expose the library directly and inherit verify-is-offline without change.

## Constraints

- **Verify-is-offline invariant (D-32-15) MUST be preserved.** No new code path in `crates/nono` introduces a network call on the verify path. The `--from-file` write is a setup-time operation only.
- **Clap-level conflict for `--from-file` vs `--refresh-trust-root`** — single-invocation mutex, not runtime check. `cargo run -- setup --from-file <p> --refresh-trust-root` must exit at argument-parse time with a non-zero code, before any filesystem write.
- **Byte-identity between `crates/nono/tests/fixtures/trust-root-frozen.json` and the released `trusted_root.json` asset.** Asserted by a CI step that computes both SHA-256s and compares; non-equal aborts the release job before `softprops/action-gh-release` runs.
- **Fail-closed on any validation failure.** Per CLAUDE.md "Fail Secure" principle: on schema parse failure, expired tlog keys, missing path, or unreadable path, exit non-zero and do NOT create or modify the cache file. The error message must name `nono setup --refresh-trust-root` OR a release-asset URL as the recovery path (per existing D-32-05 first-run UX convention).
- **No new dependencies in `crates/nono`** — REQ-POC-TRUST-01 reuses the existing `load_trusted_root` + `check_trusted_root_freshness` path. P32-CHK-002 / D-32-15 "no `dirs` crate in `crates/nono` production deps" remains in force; the `--from-file` flag lives in `nono-cli` where `dirs`-equivalent path resolution is already permitted.
- **Cross-target clippy required** per CLAUDE.md MUST/NEVER bullet. The phase touches `crates/nono-cli/src/cli.rs` and `setup.rs` which contain `#[cfg(target_os = "windows")]` and `#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]` blocks; workspace clippy on Windows host AND `--target x86_64-unknown-linux-gnu` AND `--target x86_64-apple-darwin` from the dev host (or PARTIAL deferral per `.planning/templates/cross-target-verify-checklist.md` if cross-toolchain unavailable).
- **Windows-only-files invariant (D-34-E1 / D-40-E1 / D-43-E1) MUST be honored** — phase commits do not touch `*_windows.rs`, `exec_strategy_windows/`, or `crates/nono-shell-broker/` beyond what is strictly required (expected: zero touches).
- **CLAUDE.md "no `#[allow(dead_code)]`" rule applies** — any helper added for `--from-file` must be wired into the live code path, not gated behind `#[cfg(test)]` if it's a production primitive.

## Acceptance Criteria

- [ ] `nono setup --from-file <good>.json` exits 0 and the cache file is byte-identical to the input
- [ ] `nono setup --from-file <expired>.json` exits non-zero with a freshness-error stderr message; cache file unchanged
- [ ] `nono setup --from-file <malformed>.json` exits non-zero with a parse-error stderr message; cache file unchanged
- [ ] `nono setup --from-file <missing_path>` exits non-zero with an IO-error stderr message; cache file unchanged
- [ ] `nono setup --from-file <p> --refresh-trust-root` is rejected at clap-parse time with a non-zero exit
- [ ] After a successful `--from-file`, `nono trust verify` on a known-good keyless bundle succeeds with zero network calls (verify-is-offline preserved per D-32-15)
- [ ] `.github/workflows/release.yml` `files:` glob includes `artifacts/trusted_root.json` (or matching pattern)
- [ ] Release CI asserts SHA-256 byte-identity between `crates/nono/tests/fixtures/trust-root-frozen.json` and `artifacts/trusted_root.json` (job fails on mismatch)
- [ ] `artifacts/SHA256SUMS.txt` includes a line for `trusted_root.json`
- [ ] First release after this phase shows `trusted_root.json` as a downloadable asset in `gh release view <tag>`
- [ ] `.planning/templates/sigstore-rotation-refresh.md` exists and references the 6 sections (trigger / capture / diff / regression test / commit / release-asset gate)
- [ ] `scripts/verify-trust-root-cached.sh` (or `.ps1`) exists, exits 0 on the current frozen fixture, exits non-zero on a one-byte-tampered copy
- [ ] `docs/cli/development/windows-poc-handoff.mdx` "Known issue: Sigstore TUF root rotation" subsection recommends `--from-file` as the primary path and no longer pins to `sigstore-verify 0.6.5`
- [ ] The broken `P32-DEFER-005` / `deferred-items.md` cross-reference in the same subsection is removed or corrected
- [ ] `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` passes on Windows host AND `--target x86_64-unknown-linux-gnu` AND `--target x86_64-apple-darwin` from the dev host (PARTIAL allowed only per `.planning/templates/cross-target-verify-checklist.md`)
- [ ] Phase 49 close SHA recorded in STATE.md as the v2.6 POC-resilience anchor

## Ambiguity Report

| Dimension          | Score | Min  | Status | Notes                                                                 |
|--------------------|-------|------|--------|-----------------------------------------------------------------------|
| Goal Clarity       | 0.92  | 0.75 | ✓      | 3 reqs each with current / target / acceptance triplet                |
| Boundary Clarity   | 0.80  | 0.70 | ✓      | 11-item out-of-scope list with reasoning per item                     |
| Constraint Clarity | 0.78  | 0.65 | ✓      | D-32-15 + clap-mutex + byte-identity + fail-closed + cross-target     |
| Acceptance Criteria| 0.85  | 0.70 | ✓      | 16 pass/fail checkboxes covering CLI, release, template, smoke script |
| **Ambiguity**      | 0.152 | ≤0.20| ✓      |                                                                       |

Status: ✓ = met minimum, ⚠ = below minimum (planner treats as assumption)

## Interview Log

| Round | Perspective    | Question summary                                                | Decision locked                                                                                       |
|-------|----------------|-----------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| 1     | Researcher     | What validation pipeline does `--from-file` use?                | Reuse existing `load_trusted_root` + `check_trusted_root_freshness`; no new schema validator           |
| 1     | Boundary Keeper| How does `--from-file` interact with `--refresh-trust-root`?    | Clap-level mutual exclusion + overwrite cache on success ("last writer wins")                          |
| 1     | Researcher     | What is the source-of-truth for the release-asset JSON?         | Verbatim copy of `crates/nono/tests/fixtures/trust-root-frozen.json` + CI SHA-256 byte-identity assert |
| 1     | Simplifier     | What fidelity for the maintainer-cadence template?              | Steps + reference to a new `scripts/verify-trust-root-cached.sh` cross-platform smoke script           |

---

*Phase: 49-sigstore-trust-root-poc-resilience-from-file-flag-release-as*
*Spec created: 2026-05-21*
*Next step: /gsd-discuss-phase 49 — implementation decisions (clap attribute syntax, setup.rs phase-index threading, CI step placement, smoke-script flavors)*
