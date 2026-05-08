---
quick_id: 260508-m99
slug: broker-process-poc-minimal-rust-binary-t
type: research-code
completed: 2026-05-08T20:11:30Z
tasks_completed: 3/3
commits:
  - 2cb4071b: scaffold standalone poc-broker crate (Task 1)
  - 0095ab4a: implement Win32 broker mechanism (Task 2)
  - f5eebfc3: add user-runnable README (Task 3)
key_files:
  created:
    - .planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/Cargo.toml
    - .planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/src/main.rs
    - .planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/README.md
  modified: []
---

# Quick Task 260508-m99: Broker-Process PoC Summary

## One-liner

Standalone Rust binary (`poc-broker`) that sequences `AllocConsole` + `DuplicateTokenEx(SecurityAnonymous, TokenPrimary)` + `SetTokenInformation(TokenIntegrityLevel, Low)` + `CreateProcessAsUserW(dwCreationFlags=0)` to validate whether a Low-IL child inherits the broker's console without retriggering CSRSS ALPC at Low IL (RESEARCH.md Assumption A1).

## What Was Built

**Crate:** `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/`
**Binary name:** `poc-broker.exe`
**Source:** `src/main.rs` — 196 lines including comments

**Structural isolation:**
- `Cargo.toml` contains `[workspace]` empty section — prevents Cargo crawling up to the parent nono workspace
- `windows-sys = "0.59"` under `[target.'cfg(windows)'.dependencies]` — matches workspace pin
- Parent workspace `Cargo.toml` `[workspace.members]` is unchanged (nono, nono-cli, nono-proxy, bindings/c only)

**Implementation steps:**
1. `AllocConsole()` — attaches to console at Medium IL; non-fatal if parent already has one
2. `OpenProcessToken(GetCurrentProcess(), ...)` — opens current token for duplication
3. `DuplicateTokenEx(SecurityAnonymous, TokenPrimary)` — mirrors launch.rs:1103-1108 (CR-01 hygiene)
4. `CreateWellKnownSid(WinLowLabelSid)` + `TOKEN_MANDATORY_LABEL` inline construction
5. `SetTokenInformation(TokenIntegrityLevel, Low)` — lowers duplicate token to Low IL
6. `CreateProcessAsUserW` with `dwCreationFlags=0` — no CREATE_NEW_CONSOLE; child inherits broker console
7. Wait + exit code decode: PASS (0) / FAIL-A (0xC0000142 STATUS_DLL_INIT_FAILED) / FAIL-B (other)
8. `CloseHandle` cleanup on all four handles

All `unsafe` blocks carry `// SAFETY:` comments. Non-Windows stub included for Linux/macOS builds.

## Build Status

Build not run by executor — Windows-only binary. The `cfg(not(windows))` stub compiles on Linux/macOS
but Win32 wiring activates only on `x86_64-pc-windows-msvc`.

**Field test pending:** User runs on Windows 10/11 test box.

```powershell
cd .planning\quick\260508-m99-broker-process-poc-minimal-rust-binary-t\poc-broker
cargo build --release --target x86_64-pc-windows-msvc
.\target\release\poc-broker.exe
```

## Next Step

User runs `poc-broker.exe` on Windows test box (normal Medium-IL PowerShell, not Administrator)
and reports the exit code. Consult RESEARCH.md §8 decision matrix for the full decision path:
`.planning/quick/260508-lqh-scope-phase-31-broker-process-implementa/RESEARCH.md`

| Result | Exit code    | Decision                                                              |
|--------|--------------|-----------------------------------------------------------------------|
| PASS   | 0x00000000   | Commit to Phase 31 broker-process implementation (~7 days)           |
| FAIL-A | 0xC0000142   | Escalate discuss-phase: AppContainer (6a) vs deferral (7c/7d)        |
| FAIL-B | other        | Capture ProcMon trace; new failure mode to investigate               |

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- poc-broker/Cargo.toml: FOUND
- poc-broker/src/main.rs: FOUND (196 lines)
- README.md: FOUND
- Commit 2cb4071b (scaffold): FOUND
- Commit 0095ab4a (Win32 impl): FOUND
- Commit f5eebfc3 (README): FOUND
- Parent Cargo.toml members: UNCHANGED (no poc-broker added)
