---
phase: quick-260509-s9m
plan: 01
status: complete
verdict: Partial
type: verification
date: 2026-05-09
host: x86_64-pc-windows-msvc
tags: [sigstore, trust, windows, verification, tuf]
---

# Quick Task 260509-s9m: Sigstore on Windows Native Build — Verification Summary

## Verdict

**Partial — keyed/local sigstore signing + verification work end-to-end on Windows MSVC; the *Sigstore public-good TUF production trusted-root* path fails in 2 unit tests.**

The CLI builds, the trust subcommands are wired, all 4 end-to-end audit-attestation integration tests pass (sign → bundle → verify), and 181 of 183 trust unit tests pass. The 2 failures share a single root cause: `TrustedRoot::production().await` from `sigstore-verify` cannot validate the public TUF root metadata in this environment (signature threshold of 3 not met for role root, 0 valid signatures). This is the *keyless / public-good* path; the *keyed / local-public-key* path used by audit attestations works.

Strongest evidence:
- `cargo build --workspace --release` exit 0 → `build.log` (final line `EXIT_CODE=0`)
- `cargo test -p nono-cli --test audit_attestation` → 4 passed, 0 failed → `test-audit-attestation.log`
- `cargo test -p nono trust::` → `test result: FAILED. 181 passed; 2 failed; 0 ignored`. Both failures invoke `load_production_trusted_root()` → `test-trust-unit.log`

## Environment

- Host: Windows 11 (this machine)
- Target triple: `x86_64-pc-windows-msvc` (host, default toolchain)
- rustc version: `rustc 1.95.0 (59807616e 2026-04-14)`, LLVM 22.1.2 — see `rustc-version.log`
- sigstore-verify: 0.6.5 (`crates/nono/Cargo.toml`)
- sigstore-sign:   0.6.5 (`crates/nono-cli/Cargo.toml`)
- Worktree isolation: skipped (verification-only run; no source changes)

## Build (`cargo build --workspace --release`)

- Command: `cargo build --workspace --release`
- Profile: **release**
- Exit code: **0** (per trailing `EXIT_CODE=0` line in `build.log`)
- Result: **success**
- Duration: incremental finish in `1m 35s` (workspace was warm from prior runs)
- nono.exe present at `target/release/nono.exe` (14,336,000 bytes, mtime 2026-05-09)
- Tail of `build.log`:
  ```
  Blocking waiting for file lock on artifact directory
  Compiling nono-shell-broker v0.37.1 (C:\Users\OMack\Nono\crates\nono-shell-broker)
  Compiling nono-ffi v0.37.1 (C:\Users\OMack\Nono\bindings\c)
  Finished `release` profile [optimized] target(s) in 1m 35s
  EXIT_CODE=0
  ```

## Tests

### `nono trust::` unit tests (`cargo test -p nono trust::`)

- Command: `cargo test -p nono trust::`
- Exit code: **101** (because of 2 failing tests)
- Result: **`test result: FAILED. 181 passed; 2 failed; 0 ignored; 0 measured; 477 filtered out; finished in 0.06s`**
- Source: `test-trust-unit.log`

**Failing tests (2):**

1. `trust::bundle::tests::load_production_trusted_root_succeeds` — at `crates/nono/src/trust/bundle.rs:879`
   ```
   thread 'trust::bundle::tests::load_production_trusted_root_succeeds' panicked at
   crates\nono\src\trust\bundle.rs:879:9:
   assertion failed: root.is_ok()
   ```

2. `trust::bundle::tests::verify_bundle_with_invalid_digest` — at `crates/nono/src/trust/bundle.rs:917`
   ```
   thread 'trust::bundle::tests::verify_bundle_with_invalid_digest' panicked at
   crates\nono\src\trust\bundle.rs:917:57:
   called `Result::unwrap()` on an `Err` value:
   TrustPolicy("failed to load production trusted root:
     TUF error: TUF repository load failed:
     Failed to verify trusted root metadata:
     Signature threshold of 3 not met for role root (0 valid signatures)")
   ```

**Common root cause:** Both tests call `load_production_trusted_root()` (`crates/nono/src/trust/bundle.rs:136`) which delegates to `sigstore_verify::TrustedRoot::production()`. That call fetches the Sigstore public-good TUF root metadata at runtime; it is failing TUF root signature threshold verification (0 of 3 required signatures valid). The second test only `.unwrap()`s the production root *before* asserting the negative path (invalid digest), so it fails for the same upstream reason — not because the verify-bundle logic is broken.

### `nono-cli` audit-attestation integration suite (`cargo test -p nono-cli --test audit_attestation`)

- Command: `cargo test -p nono-cli --test audit_attestation`
- Exit code: **0**
- Result: **`test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.39s`**
- Source: `test-audit-attestation.log`

Per-test status (the four headline end-to-end sigstore tests):

| Test | Status |
|------|--------|
| `audit_verify_reports_signed_attestation_with_pinned_public_key` | **ok** |
| `rollback_signed_session_verifies_from_audit_dir_bundle` | **ok** |
| `combo_rollback_audit_session_findable_by_audit_verify` | **ok** |
| `combo_rollback_audit_session_findable_by_rollback_list` | **ok** |

These tests exercise the actual `nono trust sign` → `.bundle` → `nono audit verify` flow with locally-generated ECDSA P-256 keys and pinned public keys. They are the closest thing to a real-world sigstore use of the binary, and they all pass.

### Workspace test compile (`cargo test --workspace --no-run`)

- Exit code: **0** — every test crate in the workspace compiles cleanly on MSVC. Source: `test-compile.log`.

### Ignored sigstore tests

- `ignored-tests.txt` content: `(no #[ignore] attributes found in crates/nono/src/trust or crates/nono-cli/tests/audit_attestation.rs)`
- Confirms the comment at `crates/nono-cli/tests/audit_attestation.rs:288` (“previously-deferred ignore attributes are removed below”). The 22-05a / 27.2 sigstore re-enablement work is in effect — there are no remaining `#[ignore]`s on the sigstore path.

## CLI smoke test

`./target/release/nono.exe trust --help` printed the trust subcommand surface. First lines from `cli-trust-help.log`:

```
Manage file trust and attestation

USAGE
  nono trust <command>

COMMANDS:
  init         Create a trust-policy.json in the current directory
  sign         Sign a file, producing a .bundle alongside it
  sign-policy  Sign a trust policy file, producing a .bundle alongside it
  verify       Verify a file's bundle against the trust policy
  list         List files and their verification status
  keygen       Generate a new ECDSA P-256 signing key pair
  export-key   Export the public key for a signing key (base64 DER)
```

`./target/release/nono.exe trust keygen --help` also printed the expected usage with `--id`, `--keyref`, `--force` flags. All trust subcommands documented in `cli.rs` are wired into the MSVC release binary.

## Findings & Follow-ups

1. **Keyed-bundle path on Windows MSVC: works.** Sign + verify with locally-generated ECDSA P-256 keys (the path nono actually uses for self-signed audit attestations and `trust-policy.json`) is functional. 4/4 end-to-end integration tests pass.

2. **Public-good (Fulcio/Rekor + TUF root) path: cannot be exercised by these unit tests in this environment.** Two tests that depend on `TrustedRoot::production().await` panic with TUF root signature threshold not met. Possible explanations to investigate as part of Phase 32 (do **not** fix here — out of scope for this verification quick task):
   - sigstore-verify 0.6.5 may have a pinned/embedded TUF root that is now stale or rotated.
   - The Sigstore public-good TUF mirror metadata format may have changed in a way the 0.6.5 client doesn't accept.
   - Network egress to `tuf-repo-cdn.sigstore.dev` may be blocked or filtered on this host (the error wording — “0 valid signatures” — suggests metadata is being received but failing signature checks, which leans toward stale embedded root, not network).
   - These tests may be intended to be online-only and hit a rate limit / transient failure; they are not gated as `#[ignore]` though.

3. **Phase 32 (Sigstore Integration) recommendation:**
   - Phase 32 can build on the *confirmed working* foundation of nono's local-key signing + verifying (this is what most users will hit first via `nono trust sign` / `nono trust verify`).
   - Phase 32 should **explicitly include** a workstream for the keyless/public-good path: re-evaluate `load_production_trusted_root()`, decide whether to pin/embed a known-good trusted root, and either fix or `#[ignore]` (with a comment) the two failing unit tests.
   - Suggested phrasing for a Phase-32 success criterion: *“`cargo test -p nono trust::` is fully green on Windows MSVC, OR the production-root tests are explicitly gated behind a network/online feature.”*

4. **Flakiness / platform skips:** No flaky behavior observed in this run — all per-test outcomes were deterministic across the workspace. No tests were silently skipped on Windows; the `--workspace --no-run` compile pass confirms every test crate links on MSVC.

5. **No new `#[ignore]`s creeping in.** The sigstore re-enablement done in 22-05a and 27.2 is still holding — verified by direct grep over `crates/nono/src/trust` and `crates/nono-cli/tests/audit_attestation.rs`.

## Evidence Files

All paths relative to repo root, in `.planning/quick/260509-s9m-verify-that-the-sigstore-functionality-i/`:

| File | Description |
|------|-------------|
| `260509-s9m-PLAN.md` | The plan executed (provided) |
| `260509-s9m-SUMMARY.md` | This summary |
| `rustc-version.log` | `rustc -vV` output (host = x86_64-pc-windows-msvc, rustc 1.95.0) |
| `build.log` | `cargo build --workspace --release` output, exit 0 |
| `test-trust-unit.log` | `cargo test -p nono trust::` output, 181 passed / 2 failed / exit 101 |
| `test-audit-attestation.log` | `cargo test -p nono-cli --test audit_attestation` output, 4 passed / exit 0 |
| `test-compile.log` | `cargo test --workspace --no-run` output, exit 0 |
| `ignored-tests.txt` | grep result for `#[ignore` in trust module + audit_attestation.rs (none found) |
| `cli-trust-help.log` | Live `nono.exe trust --help` + `nono.exe trust keygen --help` output from `target/release/nono.exe` |

## Self-Check: PASSED

- [x] `build.log` exists and ends with `EXIT_CODE=0`
- [x] `test-trust-unit.log` exists and ends with `EXIT_CODE=101` (181 passed, 2 failed)
- [x] `test-audit-attestation.log` exists and ends with `EXIT_CODE=0` (4 passed)
- [x] `test-compile.log` exists and ends with `EXIT_CODE=0`
- [x] `ignored-tests.txt` exists with documented "(no #[ignore] attributes found ...)" content
- [x] `cli-trust-help.log` exists and contains the trust subcommand surface
- [x] All commit hashes recorded: `7ba11d60` (build evidence), `5d8ceb30` (test evidence)
- [x] Verdict supported by direct citations to log files captured in Tasks 1 and 2
- [x] No source code modified (verification-only quick task per `<constraints>`)
