---
status: complete
phase: 08-conpty-shell
source: [PHASE8-BRIEF.md]
started: 2026-04-07T00:00:00Z
updated: 2026-04-07T00:00:00Z
---

## Current Test

[testing complete]

## Tests

### 1. nono shell launches on Windows 10 build 17763+
expected: `nono shell` launches an interactive PowerShell or cmd.exe session inside a Job Object + WFP sandbox on Windows 10 build 17763+.
result: pass

### 2. Terminal resize forwarded via ResizePseudoConsole
expected: Terminal resize events sent to the host are forwarded to the child shell via `ResizePseudoConsole`.
result: pass

### 3. Ctrl-C forwarded without terminating supervisor
expected: Ctrl-C is forwarded to the child process without terminating the supervisor process.
result: pass

### 4. Pre-17763 build produces clear error, no silent fallback
expected: Running `nono shell` on Windows build < 17763 produces a clear error message and exits with no silent fallback to a non-PTY path.
result: pass

### 5. Job Object + WFP enforced before ResumeThread
expected: Job Object and WFP enforcement apply to the shell child process at the moment of spawn, before `ResumeThread` is called.
result: pass

### 6. Coding standards: clippy + fmt clean
expected: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::unwrap_used` both pass with zero warnings.
result: pass

### 7. Library and FFI tests pass
expected: `cargo test -p nono` and `cargo test -p nono-ffi` pass with no failures.
result: pass

### 8. CLI tests pass (pre-existing failure acceptable)
expected: `cargo test -p nono-cli` passes. One pre-existing failure allowed: `profile::builtin::tests::test_all_profiles_signal_mode_resolves` fails on Windows because `XDG_CONFIG_HOME=/home/nono-test/.config` is rejected as non-absolute — this is a pre-existing host-environment issue unrelated to Phase 8.
result: pass
notes: "Pre-existing failure in profile::builtin::tests::test_all_profiles_signal_mode_resolves (XDG_CONFIG_HOME non-absolute on Windows) confirmed unrelated to Phase 8. All other CLI tests pass."

## Summary

total: 8
passed: 8
issues: 0
pending: 0
skipped: 0

## Notes

- `make ci` not run: `make` not installed on this Windows host. Individual CI components run and passed separately.
- `cargo audit` not run: `cargo-audit` subcommand not installed.
- Existing local edits in `crates/nono-cli/src/session_commands_windows.rs` and `crates/nono-cli/src/setup.rs` left untouched as instructed.

## Gaps

[none]
