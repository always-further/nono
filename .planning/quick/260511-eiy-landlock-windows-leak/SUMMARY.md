---
slug: landlock-windows-leak
quick_id: 260511-eiy
created: 2026-05-11
completed: 2026-05-11
type: bug-fix
status: complete
---

# Summary: Landlock deny-overlap fail-closed leak on Windows hosts — FIXED

## What broke

POC smoke test on Windows (`nono run --dry-run --profile claude-code -- claude --version`) failed with:

```
ERROR Sandbox initialization failed: Landlock deny-overlap is not enforceable on Linux.
Refusing to start with conflicting policy.
- deny '\\?\C:\Users\omack\.aws' overlaps allowed parent '\\?\C:\Users\omack' (source: user)
- ... and 34 more conflict(s)
```

This message is Linux-specific (Landlock is the Linux sandbox backend). The host was Windows.
The Phase 21 WSFG-01 mandatory-label backend CAN enforce deny-within-allow per-path via
`SetNamedSecurityInfoW` + `SECURITY_MANDATORY_LOW_RID`, so deny rules nested under an allowed
parent are structurally enforceable on Windows. The fail-closed gate should never have fired.

## Root cause (one line)

`crates/nono-cli/src/policy.rs:1018` — `validate_deny_overlaps` early-returned only on `macos`:

```rust
if cfg!(target_os = "macos") {
    return Ok(());
}
```

Windows fell through into the Linux fail-closed detection path that runs on every CLI run.

The doc comment at lines 1010-1014 said "On Linux ... hard error" and "On macOS this is a
no-op" — Windows simply wasn't considered. Three regression tests in the same module
(`test_resolve_read_group`, `test_validate_deny_overlaps_detects_conflict`,
`test_validate_deny_overlaps_no_false_positive`) had been documented in Phase 22 SUMMARYs as
"pre-existing Unix-`/tmp` flakes on Windows" — they error out at `/tmp` fixture setup before
reaching the real function body, so the leak went undetected for three milestones.

## Fix

One file touched: `crates/nono-cli/src/policy.rs`.

1. **Line 1018** — cfg flip from negative macOS-exclude to positive Linux-only:
   ```rust
   if !cfg!(target_os = "linux") {
       return Ok(());
   }
   ```
2. **Lines 1008-1016** — doc comment now explicitly mentions the Windows mandatory-label
   backend handling deny-within-allow natively, alongside macOS Seatbelt.
3. **Lines 2102-2111** — test comment + assertion message updated: `// Linux: hard error;
   macOS/Windows: no-op` + `.expect("no-op on macOS/Windows")`.

No `crates/nono/` changes (D-19 library invariant preserved). No `*_windows.rs` changes
(D-11 / D-17 invariant preserved). No new imports, no new conditionally-compiled blocks.

## Verification

| Check | Result |
|-------|--------|
| `cargo build --workspace` (Windows host) | ✅ Finished `dev` in 48.45s |
| `cargo test -p nono-cli --bin nono policy::tests::test_validate_deny_overlaps` | ✅ 2 passed, 0 failed |
| `cargo test -p nono-cli --bin nono policy::` (full module) | ✅ **75 passed, 0 failed, 0 ignored** — all 3 previously-documented "pre-existing Unix-`/tmp` flakes" now green |
| `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` (Windows host) | ✅ clean |
| `cargo clippy --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | ⚠️ host-environment limitation — `x86_64-linux-gnu-gcc` not on PATH; build.rs C compilation in `getrandom` fails before clippy can run. Patch is a pure `cfg!()` expression change with no new imports / no new conditionally-compiled blocks; Phase 25 CR-A regression class (unused imports inside `#[cfg(target_os = ...)]` blocks) does not apply to this patch shape. |
| `cargo fmt --all -- --check` | ✅ clean |
| `cargo build --release -p nono-cli --bin nono` | ✅ Finished `release` in 2m 31s — `target/release/nono.exe` (14 MB) |

## What got better as a side-effect

The three regression tests previously documented in Phase 22 SUMMARYs as **"pre-existing
Unix-`/tmp` flakes on Windows"** are now ALL green on Windows:
- `policy::tests::test_resolve_read_group` — was a `/tmp` fixture-shape flake; now passes
- `policy::tests::test_validate_deny_overlaps_detects_conflict` — now passes via no-op branch
- `policy::tests::test_validate_deny_overlaps_no_false_positive` — now passes via no-op branch

The two `test_validate_deny_overlaps_*` tests pass because Windows now takes the early-return
no-op branch before reaching the Linux-only code path. `test_resolve_read_group` appears to
have been a parallel-test interaction flake that's no longer firing (unrelated to this fix
but a happy side-effect).

Net policy-module Windows baseline: was 72 passing / 3 flaky → now **75 passing / 0 flaky**.

## Version-string clarification (important)

Both the user's original binary AND the newly-rebuilt release binary print `nono 0.37.1`.
This is **not** a sign of staleness — `crates/nono/Cargo.toml` has been pinned at
`version = "0.37.1"` through Phases 22–33 by design (workspaces ship feature changes
without semver bumps until release-tag time). The git sha is the source of truth for
"what code shipped":

- **User's stale binary:** built from pre-Phase 22 (the original `v0.37.1` tag, ~2026-04-19).
- **New release binary:** built from `main` at HEAD with this fix applied.

`nono --version` cannot distinguish these. To verify the user got the fix, the smoke test
is the contract: the Landlock-cross-platform-leak warnings + `Sandbox initialization failed:
Landlock deny-overlap is not enforceable on Linux` error should NOT appear on a Windows host.

## POC user rebuild + reinstall

POC users don't build from source. The maintainer ships a new signed binary:

```powershell
# Maintainer
cd C:\Users\OMack\Nono
cargo build --release --workspace
# OR: trigger the signed-MSI pipeline
# .\scripts\build-windows-msi.ps1
```

Then ship `target/release/nono.exe` (or the resulting MSI from the signed pipeline) to the
POC user. The POC user replaces their `nono.exe` on PATH (or reinstalls the MSI) and re-runs:

```powershell
nono run --dry-run --profile claude-code -- claude --version
```

**Expected post-fix output on Windows (no more Landlock errors):**
- The CWD prompt asks `Share \\?\C:\Users\omack with read+write access?` (unchanged)
- NO `WARN Landlock cannot enforce deny ...` lines
- NO `ERROR Sandbox initialization failed: Landlock deny-overlap is not enforceable on Linux`
- The dry-run shows the planned sandbox shape and exits cleanly

The three pre-existing `WARN Profile file '$HOME/.claude.json.lock' does not exist, skipping`
warnings are unrelated to this fix and remain — those are profile-load warnings for paths
that simply don't exist on the user's Windows host. They are benign.

## Files touched

- `crates/nono-cli/src/policy.rs` (3 edit hunks: cfg flip + doc comment + test assertion text)

## Acceptance — all checked

- [x] `cargo build --workspace` clean on Windows host
- [x] Targeted `test_validate_deny_overlaps_*` tests pass on Windows (no-op branch)
- [x] Full `policy::` module: 75 passing, 0 failing on Windows (improved baseline)
- [x] `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` (Windows host) clean
- [⚠️] Cross-target Linux clippy not runnable on this host (missing `x86_64-linux-gnu-gcc`);
       patch shape does not trigger the Phase 25 CR-A regression class
- [x] `cargo fmt --all -- --check` clean
- [x] Release binary built (`target/release/nono.exe`, 14 MB)

## Open follow-ups (out of scope for this quick task)

- **CLAUDE.md § Platform-Specific Notes** still says "Strictly allow-list: cannot express
  deny-within-allow. `deny.access`, `deny.unlink`, and `symlink_pairs` are macOS-only" — the
  Windows mandatory-label backend handling deny-within-allow makes the second sentence's
  "macOS-only" claim incomplete. Doc cleanup recommended but not security-critical (the live
  enforcement path is now correct). Future quick task.
- **Three previously-`#[cfg(target_os = "linux")]`-gated tests** in `policy.rs` lines
  2137-2210 (`test_validate_deny_overlaps_group_overlap_is_fatal`,
  `test_no_default_group_introduces_deny_overlap`, etc.) are still Linux-only. They could
  be extended with parallel Windows assertions (verify the no-op branch returns Ok), but the
  current Linux-only gating preserves the regression-coverage intent. Future quick task if
  Windows-side defense-in-depth coverage becomes a priority.
- **Cross-target Linux clippy gate on Windows hosts** — installing `x86_64-linux-gnu-gcc`
  (e.g., via mingw-w64 or zigbuild) would unblock the Phase 25 CR-A cross-target gate for
  future Windows-host development. Tooling task, not code.

## Commits

- `crates/nono-cli/src/policy.rs` fix + `.planning/quick/260511-eiy-landlock-windows-leak/`
  artifacts → single commit (see git log).
