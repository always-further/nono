---
slug: 260507-uow-fix-unlink-overrides-windows
date: 2026-05-07
status: complete
commit: 48a2abcb
type: bug-fix
---

# Fix: `apply_unlink_overrides` is now Seatbelt-only

## What changed

Single-file commit `48a2abcb` in `crates/nono-cli/src/policy.rs`:

| Line | Change |
|------|--------|
| 946-953 | Early-return condition flipped from `cfg!(target_os = "linux")` to `!cfg!(target_os = "macos")`. Comment expanded to explain why Windows had to be excluded too. |
| 2674-2701 (new) | `#[cfg(not(target_os = "macos"))]` regression test `test_apply_unlink_overrides_no_op_on_non_macos`. Exercises a writable fs cap through `apply_unlink_overrides` and asserts `platform_rules` stays empty. |

Net diff: +37, -2.

## Verification

- `cargo test -p nono-cli --bin nono test_apply_unlink_overrides`: 1 passed (the new non-macOS test).
- `cargo test -p nono-cli --bin nono`: 823 passed, 0 failed.
- Pre-existing clippy errors in `crates/nono/src/manifest.rs:95,103` are unrelated (confirmed via `git stash` round-trip on main HEAD prior to this commit).

## Field validation pending

This fix unblocks the cookbook's recommended path (`nono shell --profile claude-code --allow-cwd` from commit 0c69bd4b), but the test machine still has the pre-fix binary. Validation steps:

1. `cargo build -p nono-cli --release --target x86_64-pc-windows-msvc`
2. Replace the test machine's `nono.exe` with the rebuilt one.
3. `nono shell --profile claude-code --allow-cwd` — should drop into a sandboxed shell with no `Platform not supported` error.
4. Inside the sandboxed shell, run `claude` — TUI should come up cleanly via ConPTY.
5. Ask claude to read `~/.ssh/id_rsa` — should see `[NONO SANDBOX - PERMISSION DENIED]` hook output.

If steps 3–5 all pass, the POC is unblocked and ready to ship the rebuilt MSI to users.

## Diagnostic trail

The bug surfaced in real Windows POC testing on 2026-05-07 when the user ran `nono shell --profile claude-code --allow-cwd` from a fresh PowerShell. The error text was:

```
Platform not supported: Windows cannot enforce the requested sandbox
controls for this nono shell run (platform-specific sandbox rules).
Use `nono shell --dry-run ...` to validate policy, or rerun without
those controls.
```

Trace:
1. `crates/nono/src/sandbox/windows.rs:179-181` — `caps.platform_rules()` non-empty → reasons list gains "platform-specific sandbox rules".
2. `crates/nono/src/sandbox/windows.rs:266-274` — `validate_preview_entry_point` for `Shell` returns `UnsupportedPlatform` error.
3. `crates/nono-cli/src/policy.rs:946-989` — `apply_unlink_overrides` only early-returned on Linux, so Windows fell through and added Seatbelt-syntax rules.
4. The `unlink_protection` group (set on the claude-code profile via `policy.json:678`) drives `unlink_override_for_user_writable: true`, which triggers the deferred `apply_unlink_overrides` call after writable paths are finalized.

Resolver behavior on `deny.access`/`deny.unlink` is correctly platform-gated elsewhere (see `add_deny_access_rules` line 653 — macOS-only; line 419 — `cfg!(target_os = "macos")` guard on the raw deny.unlink). `apply_unlink_overrides` was the one site where the platform gate was written incorrectly, and it happened to be the one that fired for claude-code on Windows.

## Follow-ups

1. **Rebuild + reinstall + revalidate the cookbook** on the test box. (Action item for the user.)
2. **Audit other `add_platform_rule` call sites** for similar miswritten platform gates. Cursory check while diagnosing: `add_deny_access_rules` (line 603), the macOS branches at lines 435 and 716 — all gated correctly. The `apply_macos_keychain_db_exception` function name carries the constraint in its name. No other obvious offenders, but a deliberate audit is warranted.
3. **Restore ConPTY allocation in `nono run` on Windows** (supervised_runtime.rs:101-111). The cookbook routes around this via `nono shell`, but `nono run -- <TUI>` remains broken. Tracked as a follow-up `/gsd-debug` candidate; not POC-blocking.
4. **Pre-existing clippy errors in `crates/nono/src/manifest.rs:95,103`** ("this `if` can be collapsed into the outer `match`"). Trivial fix, but unrelated to this commit.
