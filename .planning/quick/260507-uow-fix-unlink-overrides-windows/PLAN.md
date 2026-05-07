---
slug: 260507-uow-fix-unlink-overrides-windows
date: 2026-05-07
status: in-progress
type: bug-fix
---

# Fix `apply_unlink_overrides` to be Seatbelt-only (skip on Windows + Linux)

## Goal

`apply_unlink_overrides` at `crates/nono-cli/src/policy.rs:946` is documented as Seatbelt-specific (the comment on line 948 says exactly that), but its early-return condition only excludes Linux:

```rust
if cfg!(target_os = "linux") {
    return; // Unlink overrides are Seatbelt-specific
}
```

On Windows the function falls through and emits Seatbelt-syntax `(allow file-write-unlink (subpath "..."))` rules into `caps.platform_rules()`. Those rules cannot be enforced by the Windows backend, but they trip the live-run gate at `crates/nono/src/sandbox/windows.rs:179-181`:

```rust
if !caps.platform_rules().is_empty() {
    reasons.push("platform-specific sandbox rules");
}
```

That gate is what made `nono shell --profile claude-code --allow-cwd` fail with `Platform not supported: Windows cannot enforce the requested sandbox controls for this nono shell run (platform-specific sandbox rules)` in real-world POC testing on 2026-05-07.

## Tasks

1. **Flip the early-return condition in `policy.rs:947`** from `cfg!(target_os = "linux")` to `!cfg!(target_os = "macos")`. The comment already documents the intent ("Unlink overrides are Seatbelt-specific") — this is a one-character semantic alignment.

2. **Add a `#[cfg(not(target_os = "macos"))]` test** that exercises `apply_unlink_overrides` with a writable fs capability and asserts `caps.platform_rules()` stays empty. Mirror the structure of the existing `#[cfg(target_os = "macos")]` test `test_apply_unlink_overrides_emits_literal_rule_for_writable_file_caps` at `policy.rs:2640-2666`.

3. **Run `cargo test -p nono-cli --lib policy`** to confirm:
   - The new non-macOS test passes on Windows.
   - Existing tests (`test_unlink_protection`, `test_apply_unlink_overrides_emits_literal_rule_for_writable_file_caps` on macOS) are not regressed.

## Why this fixes the POC blocker

After the flip:
- Windows: `apply_unlink_overrides` early-returns. `claude-code` profile → no platform_rules → live-run gate passes. `nono shell --profile claude-code --allow-cwd` works.
- Linux: behavior unchanged (still early-returns; Landlock has no deny semantics for unlink overrides anyway).
- macOS: behavior unchanged (still falls through and emits Seatbelt rules).

Combined with the existing `nono shell` ConPTY support on Windows 10 build 17763+, the cookbook's recommended happy path (commit 0c69bd4b) becomes the working happy path.

The separate gap #1 (`nono run` cannot host TUI agents on Windows) remains, but POC users won't hit it because the cookbook now routes through `nono shell` for interactive sessions.

## Out of scope

- Restoring ConPTY allocation in `nono run` on Windows. That's the deeper supervised_runtime.rs:101-111 work and needs to demonstrate the original `STATUS_DLL_INIT_FAILED` cascade does not regress. Tracked as a separate follow-up `/gsd-debug` candidate.
- Auditing other places where Seatbelt syntax may leak into `platform_rules` on non-macOS platforms. This fix addresses the one site confirmed as the POC blocker; an audit of all `add_platform_rule` call sites is reasonable but can land separately.

## Commit plan

- Single commit: `fix(windows): apply_unlink_overrides must be Seatbelt-only` (covers the source fix + the new test).
- Follow-up: `docs(state): record quick task 260507-uow complete`.
- DCO: `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>`.

## Validation steps after commit lands

1. `cargo build -p nono-cli --release --target x86_64-pc-windows-msvc` — produces a fresh binary.
2. Replace the test machine's `nono.exe` with the rebuilt one.
3. `nono shell --profile claude-code --allow-cwd` — should drop into a sandboxed shell with no `Platform not supported` error.
4. Inside the sandboxed shell, run `claude` — TUI should come up cleanly.
5. Ask claude to read `~/.ssh/id_rsa` — should see the `[NONO SANDBOX - PERMISSION DENIED]` hook output.
