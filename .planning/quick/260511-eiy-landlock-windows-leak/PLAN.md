---
slug: landlock-windows-leak
quick_id: 260511-eiy
created: 2026-05-11
type: bug-fix
status: in-progress
---

# Quick task: Fix Landlock deny-overlap fail-closed leak on Windows hosts

## Problem

POC smoke test on Windows (`nono run --dry-run --profile claude-code -- claude --version`) fails with:

```
ERROR Sandbox initialization failed: Landlock deny-overlap is not enforceable on Linux.
Refusing to start with conflicting policy.
- deny '\\?\C:\Users\omack\.aws' overlaps allowed parent '\\?\C:\Users\omack' (source: user)
- ... and 34 more conflict(s)
```

But the host is Windows — Landlock is the Linux backend. Windows uses WFP + mandatory-label
(Phase 21 WSFG-01) backend which CAN enforce deny-within-allow per-path via `SetNamedSecurityInfoW`
with `SECURITY_MANDATORY_LOW_RID` ACEs (mode-derived mask per D-01 encoding table).

## Root cause

`crates/nono-cli/src/policy.rs:1018` early-return only excludes macOS:

```rust
pub fn validate_deny_overlaps(deny_paths: &[PathBuf], caps: &CapabilitySet) -> Result<()> {
    if cfg!(target_os = "macos") {
        return Ok(());
    }
    // ... Linux-specific Landlock-incapability detection runs on Windows too ...
}
```

Windows falls through into the Linux fail-closed path. The doc comment at 1010-1014 explicitly
frames the check as Linux-specific ("Landlock is strictly allow-list...") — Windows was simply
not considered when the gate was written.

Three regression tests in the same module (`test_validate_deny_overlaps_*`) are documented as
"pre-existing Unix-`/tmp` flakes on Windows" in Phase 22 SUMMARYs — they hardcode `/tmp` so
they error out on Windows before they could have caught this leak.

## Two callsites both leak

- `crates/nono-cli/src/sandbox_prepare.rs:424` — `prepare_caps` live execution path
- `crates/nono-cli/src/capability_ext.rs:638` — `CapabilitySet::from_args` CLI argument resolution

The user's smoke test fails via `capability_ext` (CLI argument parse + group resolve).

## Fix shape

**One-line cfg flip:**

```rust
// Before
if cfg!(target_os = "macos") {
    return Ok(());
}

// After — Linux-only positive check
if !cfg!(target_os = "linux") {
    return Ok(());
}
```

**Update doc comments:**
- Function-level doc (lines 1008-1016): mention Windows mandatory-label backend handles
  deny-within-allow natively, alongside macOS Seatbelt
- `resolve_override_deny_caps` doc (line 792): wording stays Linux-specific (already correct
  in framing); no edit needed unless drift surfaces

**Update test at lines 2069-2107 (`test_validate_deny_overlaps_detects_conflict`):**
- Currently: `if cfg!(target_os = "linux") { expect_err } else { expect Ok (macOS no-op) }`
- After: same branch shape — `linux: expect_err`, `else: expect Ok` (Windows + macOS both no-op now)
- Comment text inside the test that says "macOS: no-op" → "macOS/Windows: no-op"

**Drive-by fix for Unix-`/tmp` flakes (per `test_validate_deny_overlaps_*`):** NOT in scope —
those tests are Linux-fixture-shaped by construction; fixing them is its own task. The cfg flip
already makes Windows skip the function entirely, so the tests' broken Windows behavior is
moot once the fix lands (they fail at `/tmp` setup, not at `validate_deny_overlaps` itself —
they were never exercising the real bug).

## What I will NOT do

- Touch `crates/nono/` (D-19 invariant — library byte-identical; bug is in CLI policy layer).
- Touch `*_windows.rs` (D-11 / D-17 invariant — Windows-only files structurally invariant for
  cross-platform CLI changes).
- Refactor `validate_deny_overlaps` body or callers — the cfg flip is the entire fix.
- Re-enable the three `test_validate_deny_overlaps_*` tests on Windows by rewriting `/tmp`
  fixtures (separate quick task if user wants).
- Touch `CLAUDE.md`'s "Strictly allow-list ... `deny.access`/`deny.unlink`/`symlink_pairs`
  are macOS-only" note — that wording is correct in saying Linux can't express deny-within-allow;
  the Windows mandatory-label backend is a separate enforcement path. Doc cleanup if needed
  is a separate quick task.

## Files touched

1. `crates/nono-cli/src/policy.rs` — cfg flip at line 1018; doc comment edits at lines 1008-1016;
   test branch text update at lines 2097-2107.

## Acceptance

- [ ] `cargo build --workspace` clean on Windows host.
- [ ] `cargo test -p nono-cli --bin nono policy::tests::test_validate_deny_overlaps_detects_conflict`
      passes on Windows (no-op branch). Existing Linux-path test behavior preserved.
- [ ] `cargo test -p nono-cli --bin nono policy::` passes overall (preserves prior baseline of
      3 pre-existing Unix-`/tmp` test flakes — those remain unrelated to this fix).
- [ ] `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` (Windows host) clean.
- [ ] `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`
      clean (Phase 25 CR-A lesson — Windows-host clippy can't catch `#[cfg(target_os = "linux")]`
      drift).
- [ ] `cargo fmt --all -- --check` clean.
- [ ] Manual smoke (developer or POC user): rebuild + reinstall, then `nono run --dry-run
      --profile claude-code -- claude --version` no longer prints Landlock-cross-platform-leak
      messages on Windows.

## POC user rebuild guidance (post-fix)

POC users don't build from source. After this patch lands on `main`, ship a new signed
release binary:

```powershell
# Maintainer build steps
cd C:\Users\OMack\Nono
cargo build --release --workspace
# Or trigger the signed-MSI pipeline per scripts/build-windows-msi.ps1
```

POC users reinstall the new binary (MSI or copy `target/release/nono.exe` onto PATH), then
re-run the smoke test. `nono --version` should print the new sha (not v0.37.1).
