---
slug: nono-shell-status-dll-init-failed
status: resolved
resolved_by: phase-30-plan-05
resolution_doc: .planning/phases/30-windows-nono-shell-architecture/30-WAVE-2-PROCMON.md
trigger: "nono shell --profile claude-code --allow-cwd silently exits on Windows test box with STATUS_DLL_INIT_FAILED (0xC0000142, decimal -1073741502). Field validation per HANDOFF.json after today's apply_unlink_overrides fix (commit 48a2abcb)."
created: 2026-05-07T19:30:00Z
updated: 2026-05-08T14:15:00Z
host: windows-test-box
binary: target/x86_64-pc-windows-msvc/release/nono.exe
binary_built: 2026-05-07T15:06
binary_commit: 48a2abcb
related_phases: [14, 15, 17, 21, 27.1]
related_phase: 30-windows-nono-shell-architecture
related_commits:
  - 48a2abcb (today: apply_unlink_overrides Seatbelt-only)
  - da25619 (Phase 21: ownership-skip in try_set_mandatory_label)
  - 938887f (2026-04-20: WRITE_RESTRICTED capability pipe SDDL)
  - e4c1bfa (2026-04-20: WSAStartup gap fix)
  - 17-01 plans (anonymous-pipe stdio shape for detached path)
  - 14-01 / 15 plans (original 0xC0000142 fix for nono run Direct)
specialist_hint: rust-windows
---

# Debug: nono shell exits with STATUS_DLL_INIT_FAILED (0xC0000142)

## Symptoms

**Expected:** `nono shell --profile claude-code --allow-cwd` opens an interactive Low-IL sandboxed shell; user runs `claude` inside to start the Claude Code TUI.

**Actual:** Process prints capabilities banner, "Applying sandbox...", 10 label-guard warnings, then exits without dropping into a shell. PowerShell `$LASTEXITCODE` = `-1073741502` = `0xC0000142` = `STATUS_DLL_INIT_FAILED`.

**Error messages:** No explicit error printed by nono. The 10 label-guard warnings are informational ("skipping apply + revert"), not failures:

```
WARN label guard: path has pre-existing mandatory-label ACE; skipping apply + revert
  path=C:\Users\OMack\.cache\claude prior_rid="0x1000" prior_mask="0x4"
  path=C:\Users\OMack\.cargo prior_rid="0x1000" prior_mask="0x5"
  path=C:\Users\OMack\.claude prior_rid="0x1000" prior_mask="0x4"
  path=C:\Users\OMack\.config\git\ignore prior_rid="0x1000" prior_mask="0x5"
  path=C:\Users\OMack\.gitconfig prior_rid="0x1000" prior_mask="0x5"
  path=C:\Users\OMack\.local\bin prior_rid="0x1000" prior_mask="0x5"
  path=C:\Users\OMack\.rustup prior_rid="0x1000" prior_mask="0x5"
  path=C:\Users\OMack\AppData\Roaming\nono\profiles prior_rid="0x1000" prior_mask="0x4"
  path=C:\Users\OMack\Nono prior_rid="0x1000" prior_mask="0x4"
WARN label guard: path not owned by current user; skipping mandatory label apply
  path=C:\Windows access=Read
```

`prior_rid="0x1000"` = Low integrity (SECURITY_MANDATORY_LOW_RID). All 9 user-home paths already carry Low-IL ACEs from a prior `nono` run that never reverted (likely AppliedLabelsGuard Drop did not fire — process killed mid-run).

**Exit code:** `-1073741502` (signed 32-bit) = `0xC0000142` (NTSTATUS) = `STATUS_DLL_INIT_FAILED`.

**Timeline:** First field-validation run today on freshly-built `nono.exe` (commit `48a2abcb`, built 15:06, body of fix scoped to `apply_unlink_overrides` Seatbelt-only). Has the same exit-code shape as the bug Phase 15 fixed for `nono run` Direct — but `nono shell` uses the ConPTY interactive path, NOT the detached/Direct path Phase 15 patched.

**Reproduction:** On Windows test box, run `.\nono.exe shell --profile claude-code --allow-cwd`. Process exits with -1073741502 immediately after the C:\Windows ownership-skip warning.

## Hypotheses (initial, ranked by likelihood)

### H1 (HIGH) — STATUS_DLL_INIT_FAILED in the ConPTY child shell
The sandboxed shell child (PowerShell, cmd, or whichever shell `nono shell` spawns) fails to initialize its DLLs at Low-IL. Phase 15 fixed this for `nono run` Direct's detached-console path; `nono shell` uses a different ConPTY interactive path that may have the same class of bug unfixed.

### H2 (MEDIUM) — Pre-existing leaked Low-IL labels on home paths cause shell-init failure
9 home paths carry `prior_rid="0x1000"` from a prior `nono` run.

### H3 (LOW) — `apply_unlink_overrides` fix from today (48a2abcb) regressed nono shell

### H4 (LOW) — ConPTY path uses different stdio shape than Phase 17 anonymous-pipe fix covered

## Current Focus

**hypothesis:** H5 (HIGH) — `nono shell`'s code path differs from `nono run`'s Direct path in a way that breaks DLL init for ANY child under WRITE_RESTRICTED + ConPTY. cmd.exe ALSO fails (Experiment A 2026-05-07T19:58Z), so the trigger is not CLR-specific. Most likely difference: ConPTY interactive-pty allocation, stdio inheritance shape, or proc-attribute list.
**test:** (1) Get `-vv` tracing output to localize where the supervisor reaches before child death. (2) Compare `nono shell` vs `nono run` Phase 15 smoke-gate command line + token + proc-attribute flags side-by-side. (3) Optionally check leaked Low-IL labels by clearing them and re-running.
**expecting:** -vv output should reveal which supervisor stage is the last one to log before the child dies. The diff between `nono run` (works for cmd /c) and `nono shell` (fails for cmd) should be in: (a) `interactive_pty=true` vs false, (b) ConPTY stdio handle setup, (c) command-line composition (cmd.exe with no `/c` arg vs `cmd /c "echo hello"`).
**next_action:** Ask user to rerun with `-vv` and capture full output. While waiting, prepare a side-by-side static diff of `nono run -- cmd /c "echo hello"` (Phase 15 smoke-gate path, KNOWN GOOD) vs `nono shell --shell cmd.exe` (current symptom path, FAILING) to localize the divergence.
**reasoning_checkpoint:** H1 was specific (PowerShell CLR DllMain). The smoking-gun in Experiment A — cmd.exe ALSO fails — collapses the CLR-specific framing. The new framing: SOMETHING about how `nono shell` invokes `CreateProcessAsUserW` differs enough from `nono run` that even cmd.exe's bare loader can't init. The latent-bug-revealed-by-48a2abcb story still holds, but the actual trigger is broader than CLR.

## Evidence

- timestamp: 2026-05-07T19:23:15Z
  observation: $LASTEXITCODE=-1073741502=0xC0000142=STATUS_DLL_INIT_FAILED on Windows test box
  source: user field-validation run

- timestamp: 2026-05-07T19:23:15Z
  observation: 9 user-home paths already carry Low-IL mandatory-label ACEs at run START; not applied by this nono run (label guard "skipping apply + revert"). Indicates a prior nono process leaked labels by exiting before AppliedLabelsGuard Drop ran.
  source: nono shell tracing output

- timestamp: 2026-05-07
  observation: STATE.md cross-references — Phase 15 fixed STATUS_DLL_INIT_FAILED for `nono run` Direct strategy via should_allocate_pty gate at supervised_runtime.rs:88-94 (preserved byte-identical by Phase 17). The fix lives on the Direct path, NOT the supervised-ConPTY path that `nono shell` takes.
  source: .planning/STATE.md key-decisions block

- timestamp: 2026-05-07T19:50:00Z
  observation: Static call-graph trace from `Commands::Shell` → `command_runtime::run_shell` → `execute_sandboxed` → `execute_supervised_runtime` → `should_allocate_pty(session) == true` (because `interactive_pty: true` is hard-coded at command_runtime.rs:132) → `execute_supervised` (Windows arm) → `spawn_windows_child` with `pty: Some(pty_pair)` → CreateProcessAsUserW path with EXTENDED_STARTUPINFO_PRESENT + PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE + WRITE_RESTRICTED token (because `config.session_sid.is_some()` — the supervised path always sets it).
  source: code reading — crates/nono-cli/src/command_runtime.rs:47-138; crates/nono-cli/src/supervised_runtime.rs:105-111, 332; crates/nono-cli/src/exec_strategy_windows/launch.rs:1114-1349

- timestamp: 2026-05-07T19:50:00Z
  observation: `command_runtime::run_shell` at command_runtime.rs:49-63 selects `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` if it exists, else falls back to `C:\Windows\System32\cmd.exe`. On the user's host (Windows 11 Enterprise), powershell.exe exists, so the launched binary is **Windows PowerShell 5.1** (the .NET-Framework-CLR-hosted version), NOT pwsh.exe (PowerShell 7+ which uses CoreCLR).
  source: crates/nono-cli/src/command_runtime.rs:49-63

- timestamp: 2026-05-07T19:50:00Z
  observation: Phase 15 smoke gate (`.planning/debug/resolved/windows-supervised-exec-cascade.md` § "Phase 15 Smoke Gate") explicitly verified non-detached `nono run --allow-cwd -- cmd /c "echo hello"` PASSED with WRITE_RESTRICTED + ConPTY. Phase 15 NEVER smoke-tested `nono shell` (which spawns powershell.exe) end-to-end — its row 3 is `cmd /c`, not powershell. This is a v2.1 verification gap.
  source: `.planning/debug/resolved/windows-supervised-exec-cascade.md` lines 209-220

- timestamp: 2026-05-07T19:50:00Z
  observation: `restricted_token::create_restricted_token_with_sid` (restricted_token.rs:34-121) creates the child token with `WRITE_RESTRICTED` flag and **does NOT call `SetTokenInformation(TokenIntegrityLevel)`**. The child therefore inherits Medium IL from the supervisor (default behavior). Consequence: the leaked Low-IL labels on user home paths (NO_WRITE_UP|NO_EXECUTE_UP for mask=0x5, NO_EXECUTE_UP for mask=0x4) do NOT block the child's reads of those paths — Medium-IL subjects are not subject to those NO_*_UP rules.
  source: crates/nono-cli/src/exec_strategy_windows/restricted_token.rs:34-121 (no integrity-label set); crates/nono-cli/src/exec_strategy_windows/launch.rs:1140-1160 (token branch order — restricted_token wins over create_low_integrity_primary_token whenever session_sid is Some)

- timestamp: 2026-05-07T19:50:00Z
  observation: Today's commit 48a2abcb scoped `apply_unlink_overrides` to macOS-only. Verified: the function is now a no-op on Windows, so the Windows preview gate's `platform_rules` check at sandbox/windows.rs:105-110 no longer trips. This UNMASKED the underlying STATUS_DLL_INIT_FAILED — `nono shell --profile claude-code` previously failed earlier with "Platform not supported" (the platform_rules check), now reaches CreateProcessAsUserW and exposes the latent CLR-init bug. So 48a2abcb is **not the cause**; it's the **revealer**.
  source: 48a2abcb commit message; crates/nono/src/sandbox/windows.rs:105-110

- timestamp: 2026-05-07T19:50:00Z
  observation: Windows PowerShell 5.1 (`powershell.exe`) hosts the .NET Framework CLR (`clr.dll`). CLR initialization performs `NtCreateSection` / `NtMapViewOfSection` operations on named sections (e.g. `\BaseNamedObjects\NLS_*`, ngen image cache) with SECTION_MAP_WRITE access for COW segments. Under a `WRITE_RESTRICTED` token whose restricting SID is the synthetic per-session `S-1-5-117-*` SID (absent from every system DACL), every WRITE-type access check is double-gated against the session SID and fails with STATUS_ACCESS_DENIED. CLR's `DllMain` propagates the failure as a DLL init failure → loader returns STATUS_DLL_INIT_FAILED (0xC0000142) to the kernel, which exits the process with that code. cmd.exe does not host CLR and therefore was not affected by the same Phase-15-verified shape.
  source: code path analysis + Win32 documentation cross-reference (CreateRestrictedToken with WRITE_RESTRICTED gates writes against restricting SIDs; CLR loader writable-section semantics)

## Investigation summary (reasoning checkpoint)

**Call graph (verified):**

```
nono shell --profile claude-code --allow-cwd
  → cli.rs Commands::Shell
  → app_runtime.rs:50  run_shell(*args, silent)
  → command_runtime.rs:47-138  run_shell()
       shell_path = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe   (line 49-63)
       interactive_shell: true, interactive_pty: true                            (lines 126, 132)
       → execute_sandboxed(LaunchPlan)
  → execution_runtime.rs:335 forwards interactive_shell to ExecConfig
  → execute_supervised_runtime() in supervised_runtime.rs:175
       supervisor_cfg.session_sid = config.session_sid  (Some — set by launch_runtime)
       supervisor_cfg.interactive_shell = true
       should_allocate_pty(session) = session.interactive_pty = true             (line 105-111, Windows arm)
       pty_pair = Some(pty_proxy::open_pty()?)                                    (line 161)
       → exec_strategy::execute_supervised(...)  (Windows arm)
  → exec_strategy_windows/mod.rs:685 execute_supervised
       → spawn_windows_child(config, ..., pty=Some(pty_pair), ...)               (line 788)
  → exec_strategy_windows/launch.rs:1114 spawn_windows_child
       is_windows_detached_launch = false  (no NONO_DETACHED_LAUNCH=1)
       config.session_sid = Some(...)
       → h_token = create_restricted_token_with_sid(sid)  (WRITE_RESTRICTED + S-1-5-117-* restricting SID, MEDIUM IL — no integrity drop)
       PTY branch (line 1178-1276):
         CreateProcessAsUserW(
           h_token,
           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
           ...,
           CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
           ...,
           startup_info_ex (with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attached),
         )
  → child process initializes, loads ntdll, kernel32, kernelbase, USER32, ADVAPI32 (all OK)
  → child loads clr.dll (.NET Framework CLR)
  → CLR DllMain attempts NtCreateSection/NtMapViewOfSection with SECTION_MAP_WRITE
    on named-objects under \BaseNamedObjects (or per-session subdirectory)
  → SECTION_MAP_WRITE is a WRITE-type access → double-gated against restricting SID S-1-5-117-*
  → S-1-5-117-* not in any object DACL → STATUS_ACCESS_DENIED
  → CLR DllMain returns FALSE
  → loader maps the failure to STATUS_DLL_INIT_FAILED (0xC0000142)
  → ResumeThread succeeded (suspend was lifted), process exits with that NTSTATUS
  → nono.exe supervisor polls poll_exit_code(), sees -1073741502, propagates
```

**Why H2 is downgraded:** the leaked Low-IL labels are mostly cosmetic in this run because the child token is Medium IL, not Low IL. Reading `~/.cargo` (mask=0x5: NO_WRITE_UP|NO_EXECUTE_UP) from a Medium IL subject is unaffected (NO_*_UP rules only apply to lower-IL subjects accessing higher-IL objects). Nevertheless the label leak is a real lifecycle bug worth tracking separately — it IS the smoking gun that a prior session crashed without revert.

**Why H3 is eliminated:** today's 48a2abcb fix early-returned on non-macOS. Before that fix, `nono shell --profile claude-code` failed earlier with "Platform not supported: Windows cannot enforce the requested sandbox controls" — so this run is the FIRST time the supervised-shell path was reached end-to-end on Windows. 48a2abcb is the revealer, not the cause.

**Why H4 is downgraded:** the Phase 17 anonymous-pipe stdio change is gated by `pty.is_none() && is_windows_detached_launch`. `nono shell` has `pty.is_some()`, so the new pipe code is unreachable here. The PTY branch (lines 1178-1276) is the original Phase 14/15 code path, byte-identical to what was smoke-gated.

**The verification gap:** Phase 15 smoke gate row 3 used `cmd /c "echo hello"`. cmd.exe is a flat win32 console app with minimal DLL deps (no CLR). PowerShell.exe v5.1 hosts the .NET Framework CLR, which makes WRITE-type access checks during DllMain that the session-SID restricting token denies. **This is why the bug was latent: nobody ran a CLR-bearing process under the WRITE_RESTRICTED + session-SID token until today.**

## Proposed verification (USER-CHECKPOINT — DO NOT FIX YET)

Two single-line experiments to confirm the diagnosis. The user should report exit codes only.

**Experiment A (binary dimension):** Force `nono shell` to use cmd.exe instead of powershell.exe.

```powershell
.\target\x86_64-pc-windows-msvc\release\nono.exe shell --profile claude-code --allow-cwd --shell C:\Windows\System32\cmd.exe
```

Expected if H1 is correct: cmd.exe prompt appears (`C:\Users\OMack\Nono>`), user can type `exit` to leave cleanly. Exit code 0.

If this PASSES, the bug is binary-specific (PowerShell only) → fix is in the `nono shell` shell-default selection logic OR a deeper change to the WRITE_RESTRICTED shape that supports CLR.

**Experiment B (profile dimension):** Run `nono shell` with NO profile, just `--allow-cwd`.

```powershell
.\target\x86_64-pc-windows-msvc\release\nono.exe shell --allow-cwd
```

Expected if H1 is correct: SAME 0xC0000142 failure (the issue is the WRITE_RESTRICTED token, not the profile-specific FS caps).

If this PASSES, the bug IS profile-specific (something in claude-code's resolved policy is the trigger) → reconsider hypothesis.

**Experiment C (token shape, optional):** If A passes and B fails as expected, run `nono run` with PowerShell to confirm the bug also affects `nono run`-spawned PowerShell:

```powershell
.\target\x86_64-pc-windows-msvc\release\nono.exe run --profile claude-code --allow-cwd -- powershell.exe -NoLogo -Command "Write-Host hello"
```

Expected: ALSO 0xC0000142 (the WRITE_RESTRICTED+session-SID+CLR combo is the issue, not the ConPTY shape).

## Eliminated

- **H3 (today's 48a2abcb regressed nono shell):** Eliminated. 48a2abcb's `apply_unlink_overrides` Seatbelt-only fix is unreachable from the Windows live path; the function is now a no-op on Windows. The fix UNMASKED the underlying CLR-init bug (which had been hidden behind the earlier "platform_rules nonempty → Platform not supported" gate). Verified by reading 48a2abcb's diff and the comment at sandbox/windows.rs:105-110.
- **H4 (ConPTY stdio shape regression from Phase 17):** Eliminated. Phase 17's anonymous-pipe stdio code at launch.rs:1283-1287 is gated by `pty.is_none() && is_windows_detached_launch`. `nono shell` has `pty.is_some()`, so the new code is unreachable. The PTY branch is byte-identical to Phase 14/15.

## Resolution (proposed — pending user verification)

**status:** root-cause-identified, fix-deferred-to-checkpoint

**root_cause (preliminary, awaiting Experiment A confirmation):**
Windows PowerShell 5.1 (`powershell.exe`) loads `clr.dll` (.NET Framework CLR) during process initialization. CLR's `DllMain` performs WRITE-type access operations (most likely SECTION_MAP_WRITE on named sections, or registry SetValue against `HKCU\Software\Microsoft\.NETFramework`) that under the WRITE_RESTRICTED token are double-gated against the synthetic per-session restricting SID `S-1-5-117-*`. Because this SID is absent from every object's DACL, the check fails with STATUS_ACCESS_DENIED, CLR's DllMain returns FALSE, and the loader exits the process with STATUS_DLL_INIT_FAILED (0xC0000142). cmd.exe does not host CLR, which is why Phase 15's smoke gate (cmd-only) did not catch this.

**fix (preliminary — three options, ranked by risk):**

1. **Option 1 (lowest risk, recommended for v2.1.x patch):** Change the default shell selection in `crates/nono-cli/src/command_runtime.rs:49-63` to prefer `cmd.exe` on Windows, with PowerShell as an explicit opt-in via `--shell powershell.exe`. Update the cookbook (`docs/cli/development/windows-poc-handoff.mdx`) to document cmd.exe as the default.
   - Pros: 1-line code change, no security model impact, immediately unblocks the user's Claude Code field validation.
   - Cons: cmd.exe is a worse interactive experience than PowerShell. Doesn't fix the underlying token-CLR mismatch.
   - D-21 invariance: only `target_os = "windows"` arm of `run_shell` changes.

2. **Option 2 (medium risk, follow-up Phase 28):** Replace the synthetic session-SID restricting SID with the user's logon SID (`S-1-5-5-X-Y`) on the `nono shell` interactive path. The logon SID IS present in many system object DACLs because Windows uses it for per-logon-session resource isolation. Re-evaluate the WFP `FWPM_CONDITION_ALE_USER_ID` filter — it may need to be replaced or supplemented by AppID-based filtering for `nono shell`.
   - Pros: lets PowerShell work under restricted token. Preserves WFP kernel network identity (via AppID fallback).
   - Cons: requires re-validation of the security waiver matrix in `.planning/debug/resolved/windows-supervised-exec-cascade.md`. Per-session SID network differentiation is partially lost (two concurrent `nono shell` sessions of the same binary share AppID — same trade-off as the Phase 15 detached path).
   - D-21 invariance: `cfg(target_os = "windows")` gated.

3. **Option 3 (highest risk, deferred):** Add the session SID as a token GROUP (not as a restricting SID) and remove `WRITE_RESTRICTED`. Use Job Object + capability set + AppID WFP for isolation only.
   - Pros: most permissive token, lowest CLR-compatibility risk.
   - Cons: undoes the Phase-15-2026-04-17 WRITE_RESTRICTED security hardening. Significantly weakens the kernel boundary. Would need a fresh security review.

**Recommended:** Option 1 for the v2.1.x patch (unblocks the field validation), Option 2 as the proper Phase 28 fix.

**verification:**
- (pending Experiment A) confirm cmd.exe under the same configuration prints the prompt and accepts `dir` etc.
- (pending Experiment B) confirm `nono shell --allow-cwd` (no profile) ALSO fails 0xC0000142, ruling out profile-specific FS-cap issues.
- After fix: re-run `nono shell --profile claude-code --allow-cwd` on the test host, expect cmd prompt, exit 0 on `exit`.
- Add unit test asserting Windows arm of `run_shell` selects `cmd.exe` first when `args.shell` is None. Update cookbook.

**files_changed (Option 1):**
- `crates/nono-cli/src/command_runtime.rs` (1 hunk: swap powershell/cmd preference order)
- `crates/nono-cli/src/command_runtime.rs` tests (add a Windows-arm test)
- `docs/cli/development/windows-poc-handoff.mdx` (update default-shell mention)

**Side issue (record but do NOT fix in this debug task):**
The 9 leaked Low-IL labels on home paths from a prior crash/kill of `nono` are evidence of an `AppliedLabelsGuard` lifecycle bug. The Drop-on-panic / Drop-on-signal path is not firing. This is a separate debug session (suggested slug: `nono-labels-guard-leak`) — it does not block the current `nono shell` fix but should be tracked for v2.2 hardening.

---

## Update Log

### 2026-05-07T20:08Z — H7 confirmed via static analysis + Phase 15 replay

User ran `nono run --allow-cwd -- cmd /c "echo hello"` on the test box: `hello` printed, exit 0. **Phase 15's smoke-gate Row 3 still works on this host** — bug is `nono shell`-specific, NOT host-state-shift.

Reading code + the resolved Phase 15 debug session at `.planning/debug/resolved/windows-supervised-exec-cascade.md:233-234` confirms:

- Phase 15 INTRODUCED `should_allocate_pty()` gating ConPTY allocation. On Windows, ConPTY is allocated ONLY for `nono shell` (interactive_pty=true). `nono run` does NOT allocate ConPTY.
- Phase 15 Row 3's parenthetical "full WRITE_RESTRICTED + ConPTY" was imprecise wording. Row 3 ran with WRITE_RESTRICTED + **NO** ConPTY.
- The actual Phase 15 bug-fix pattern was: `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE + DETACHED_PROCESS = 0xC0000142`. Solved by removing ConPTY from the detached path.

Today's bug is the SECOND instance of the same brittle interaction:
```
PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE + WRITE_RESTRICTED + session-SID = 0xC0000142
```

The pattern: ConPTY pseudoconsole DLL init is fragile under non-default token shapes. WRITE_RESTRICTED + restricting-SID denies something the pseudoconsole's bootstrap requires (likely ALPC/section access against `\Device\ConDrv` or conhost.exe's named-port).

### Updated fix space

- **Option A (mirror Phase 15 — recommended):** drop WRITE_RESTRICTED + session-SID on the interactive-shell ConPTY path. Use `null_mut()` token so CreateProcessW runs cmd.exe/powershell.exe with the caller's token. Same security trade-off as Phase 15's detached fix: per-session SID WFP differentiation lost (falls back to AppID-based filtering); WRITE_RESTRICTED hardening waived for `nono shell`. Job Object + filesystem sandbox (CapabilitySet) remain as primary isolation. Code change ~5 lines in `exec_strategy_windows/launch.rs`'s `spawn_windows_child` — gate the token swap on `pty.is_some() && !is_windows_detached_launch()`.
- **Option B (drop ConPTY for interactive shell):** make `nono shell --shell cmd.exe` inherit the parent's console handles instead of creating a pseudoconsole. Preserves WRITE_RESTRICTED; loses some interactive features (resize relay, ANSI sequence translation may not work cleanly with cmd's legacy console mode under restricted token). Higher impact on UX for the `claude` TUI inside.
- **Option C (defer):** declare `nono shell` Windows-unsupported until Phase 28+ kernel-driver work. Use `nono run -- claude` (Direct, no PTY, no ConPTY) for the POC. The cookbook (today's commit `0c69bd4b`) explicitly recommends `nono shell` for TUI agents because `nono run`'s supervised path on Windows lacks ConPTY for TUIs — but Direct `nono run` may still work for Claude Code's TUI if Claude Code can fall back to non-PTY stdio mode. Needs verification.

**Recommendation:** Option A. Cleanest mirror of Phase 15. Same security waivers, already documented + accepted by Phase 15.

### Open questions before applying Option A

1. Can we confirm via `-vv` tracing that the supervisor reaches CreateProcessAsUserW + ResumeThread, then the child dies during DLL init? (Localizes the failure stage to confirm it's not a supervisor-side bug.)
2. Are there any additional security implications of dropping WRITE_RESTRICTED on `nono shell` that don't apply to Phase 15's detached fix? `nono shell` is interactive and long-lived; the detached path is one-shot. Long-lived sessions have more time to be exploited from inside.
3. Should we remove ConPTY for `nono shell` AND keep WRITE_RESTRICTED (Option B)? The cookbook commit 0c69bd4b's premise — `nono shell` supports `claude` TUI on Windows — may need re-validation if interactive ConPTY isn't available.

### Next user action

Choose between gathering `-vv` data first OR applying Option A immediately. Both paths are reasonable; Option A is faster but skips one corroboration step.

### 2026-05-07T20:35Z — Option A REVERTED, replaced with Low-IL primary token

**Field finding that triggered the revert:** From inside the Option-A-built sandboxed PowerShell, the user successfully read `~/.ssh/id_ed25519` (private SSH key) directly via `cat`. Initially flagged as a security regression. **On closer reading of `restricted_token.rs:82-93` and `sandbox/windows.rs:35-44`**, this is *expected* nono Windows behavior: WRITE_RESTRICTED only blocks writes (reads pass with normal user-SID checks); the cookbook's `~/.ssh/id_rsa` test was always meant to be intercepted by the **Claude Code PreToolUse hook**, not by OS-level FS denial. So that read is not the regression.

However, Option A's null-token-at-Medium-IL approach DID lose:

- WRITE_RESTRICTED's write-deny double-gate (per `restricted_token.rs:82-93`)
- Mandatory-label write enforcement (Low-IL labels at `prior_rid=0x1000` only fire for Low-IL subjects; null token gives the child the user's full Medium IL)

Net: Option A's child has no OS-level write protection at all on Windows. That's a real regression — `nono run` keeps its WRITE_RESTRICTED-based write deny, but `nono shell` would not.

Per `nono setup --check-only` on the test box, `Token Integrity level support: OK` — so the OS supports a Low-IL primary-token approach. Option A reverted in favor of:

### Option D — Low-IL primary token for ConPTY path (applied 2026-05-07T20:35Z)

**Files changed (replacing Option A):**

- `crates/nono-cli/src/exec_strategy_windows/launch.rs`:
  - Reverted the `should_use_null_token(is_detached, has_pty)` gate + helper + 4 added tests (no longer the right abstraction).
  - Restructured `spawn_windows_child`'s token selection into a 5-arm cascade: `if is_windows_detached_launch` → null token (Phase 15 detached fix, unchanged); `else if pty.is_some()` → **Low-IL primary token via `create_low_integrity_primary_token()`** (NEW: avoids WRITE_RESTRICTED+ConPTY brittleness while preserving mandatory-label write enforcement); `else if config.session_sid.is_some()` → WRITE_RESTRICTED + session-SID (Phase 15 supervised non-PTY, unchanged); `else if should_use_low_integrity_windows_launch(config.caps)` → Low-IL primary (legacy Direct, unchanged); `else` → null fallback (unchanged).
  - Updated the inline comment block to document both 0xC0000142 trigger paths and the asymmetric fixes (null token for detached; Low-IL primary for interactive PTY).
- `docs/cli/development/windows-poc-handoff.mdx` — revised the security-envelope paragraph: `nono shell` now runs the child under a Low-IL primary token (no WRITE_RESTRICTED, no session-SID). Mandatory-label write enforcement preserved. Network falls back to AppID WFP.

**Verification (matches Phase 15's verification discipline):**

- `cargo build -p nono-cli --target x86_64-pc-windows-msvc` — clean
- `cargo test -p nono-cli --bin nono detached_token_gate_tests --target x86_64-pc-windows-msvc` — 3/3 PASS (Phase 15's originals)
- `cargo fmt --all -- --check` — clean
- D-21 invariance: change is fully scoped to `exec_strategy_windows/launch.rs` (Windows-only file) + cookbook (Windows section). Linux/macOS code paths untouched.

**Pending:**

1. Field validation: user re-runs `.\nono.exe shell --profile claude-code --allow-cwd` with the rebuilt binary. Expectations:
   - Shell launches (no 0xC0000142). If it does fail, Low-IL+ConPTY has the same brittleness as WRITE_RESTRICTED+ConPTY and we need a deeper investigation (likely ProcMon trace).
   - `Out-File` to `C:\Users\OMack\Desktop\anything.txt` from inside the sandboxed shell should fail with "Access denied" (mandatory-label NO_WRITE_UP block; Low-IL subject vs. Medium-IL Desktop).
2. Hook investigation (separate): the Claude Code PreToolUse hook did not fire when Claude read `desktop\nono-test.txt` outside the grant set. `nono setup --check-only` doesn't surface hook installation status. Likely tracked separately via `nono hooks`/`crates/nono-cli/src/hooks.rs`. NOT blocking the launch fix; track in a follow-up debug session.

### Open question after Option D field test

If Low-IL+ConPTY ALSO fails 0xC0000142, neither token shape is viable for the interactive PTY path. Fall-back options:
- Disable ConPTY for `nono shell` and use anonymous-pipe stdio (Phase 17's pattern). Loses interactive ANSI/resize features but preserves WRITE_RESTRICTED's write-deny.
- Investigate whether the failure is in the pseudoconsole's ALPC-port DACL (does `\Device\ConDrv` deny Low-IL clients?). May require kernel-level debugging.
- Drop ConPTY pursuit and document `nono shell` as Windows-unsupported until a kernel driver lands.

### 2026-05-07T20:55Z — Pause + revert; planning checkpoint requested by user

User chose to step back from token-shape iteration. The pattern of "try a token shape → field-test → discover it either crashes or doesn't enforce → try the next shape" was producing motion without progress. The actual question is architectural, not a token tweak.

**Working-tree state at pause:**
- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — reverted to HEAD (Option D removed).
- `docs/cli/development/windows-poc-handoff.mdx` — reverted to HEAD (security-envelope paragraph removed).
- This debug session file (`.planning/debug/nono-shell-status-dll-init-failed.md`) — preserved with full investigation trail; it IS the planning input.
- `target/x86_64-pc-windows-msvc/release/nono.exe` — built from Option D (Low-IL primary token branch); on disk only, NOT representative of HEAD. Do not ship; rebuild from HEAD before any further field test.
- The user's test box has whichever binary they last copied across (Option A or Option D). They should not treat that binary as a working sandbox; rebuild + redeploy from HEAD before next field run.

**What we know (confirmed):**
- The original `nono shell --profile claude-code` path (HEAD) fails immediately with `STATUS_DLL_INIT_FAILED (0xC0000142)`. Trigger: `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` + `WRITE_RESTRICTED` + session-SID. Confirmed by static analysis + Phase 15 smoke-gate replay (`nono run -- cmd /c "echo hello"` still PASSES on this host).
- 9 user-home paths carry leaked Low-IL labels (`prior_rid="0x1000"`) from a prior nono crash that bypassed `AppliedLabelsGuard` Drop. Separate bug; tracked as `nono-labels-guard-leak` candidate.
- `nono setup --check-only` on the test box: WFP service is missing/not registered (per the cookbook's known per-user-MSI limitation — network filtering is already off on this host regardless of the shell-launch fix). `Token Integrity level support: OK` (so Low-IL approaches are feasible).
- The Claude Code PreToolUse hook did not fire when Claude (running inside an Option-A-built sandbox) read `desktop\nono-test.txt` outside the grant set. Hook installation status is NOT surfaced by `nono setup --check-only`. This is a separate concern from the launch fix; tracked as a follow-up debug session.

**What we do not know:**
- Whether Option D (Low-IL primary token + ConPTY) launches cleanly or also fails 0xC0000142. Build artifact exists; was not field-tested before pause.
- Whether ConPTY on Windows is fundamentally incompatible with any non-default token shape, or only with WRITE_RESTRICTED specifically.
- Whether nono's interactive-shell-on-Windows story should be redesigned away from ConPTY (e.g., anonymous-pipe stdio per Phase 17's pattern, accepting loss of ANSI/resize) or away from token restrictions (accept the security waiver per Phase 15).

**Recommended planning-checkpoint frame (for next session):**

The right question is not "which token shape unblocks ConPTY" but "what is the supported-and-shippable interactive-shell story on Windows for v2.3+?" Architectural options to put on the table:

1. **`nono shell` on Windows is unsupported until v3.0 kernel-driver work.** Revert today's cookbook commit (`0c69bd4b`) that recommended `nono shell` for TUIs. Document `nono run -- claude` as the only Windows path; accept that it can't host a TUI (Claude Code falls back to non-PTY mode if available, or we ship without TUI on Windows POC).
2. **`nono shell` with anonymous-pipe stdio** (no ConPTY). Mirror Phase 17's detached-path stdio pattern for the interactive supervised path. Keep WRITE_RESTRICTED + session-SID. Lose ANSI sequences, resize, raw mode — likely breaks `claude` TUI rendering. Test whether a degraded `claude` is usable.
3. **`nono shell` with ConPTY + Low-IL primary token (Option D, untested).** Field-test the existing build artifact OR rebuild + test from a fresh branch. If it launches AND mandatory-label write-deny works, this is a viable middle path.
4. **`nono shell` with ConPTY + null token (Option A, tested, regresses write protection).** Document the security waiver explicitly. Match Phase 15's detached-path waiver but for a long-lived interactive shell — which is a stronger threat model than detached. Likely not acceptable, but worth being explicit about.
5. **Investigate the actual Win32 mechanism** of the ConPTY+restricted-token failure (ProcMon trace, possibly Windows Internals consultation). Could surface a fifth option none of us has thought of.

These choices have different costs (engineering, security, UX). Pick the right framework — `/gsd-discuss-phase` style discussion — before more code edits.

**Hook firing concern (separate from the architectural question):** `nono setup --check-only` doesn't surface Claude Code hook installation. The cookbook's `~/.ssh/id_rsa` test was supposed to validate the hook. On this host, the hook didn't fire for at least one tool call inside Claude. Possible causes: hook never installed by `nono setup` on this profile; `~/.claude/settings.json` doesn't reference the hook; hook script can't find the active nono session. Worth a separate `/gsd-debug` session with explicit hook-installation focus before declaring the POC end-to-end working. Reference: `crates/nono-cli/src/hooks.rs`, `crates/nono-cli/data/hooks/nono-hook.sh`.

**Files changed:**

- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — gate the WRITE_RESTRICTED + session-SID token on `!should_use_null_token(is_windows_detached_launch, pty.is_some())`. Added the `should_use_null_token(is_detached, has_pty) -> bool` helper above the existing `is_windows_detached_launch()` to make the gate testable. Updated the inline comment to document both 0xC0000142 trigger paths (DETACHED_PROCESS — Phase 15; PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE — this debug session). Added 4 unit tests asserting the helper truth table (`null_token_used_for_detached_launch`, `null_token_used_for_interactive_pty`, `null_token_used_when_both_set`, `restricted_token_used_for_supervised_non_pty_non_detached`).
- `docs/cli/development/windows-poc-handoff.mdx` — added "Related security envelope for `nono shell` on Windows" paragraph in the existing "Known limitation: `nono run` cannot host TUI agents on Windows" section. Documents the security trade-off (null token mirrors the `nono run --detached` waiver: AppID-based WFP fallback; Job Object + CapabilitySet remain primary isolation).

**Verification:**

- `cargo build -p nono-cli --target x86_64-pc-windows-msvc` — clean
- `cargo test -p nono-cli --bin nono detached_token_gate_tests --target x86_64-pc-windows-msvc` — **7/7 PASS** (3 pre-existing + 4 new)
- `cargo fmt --all -- --check` — clean (zero diff)
- `cargo clippy -p nono-cli --target x86_64-pc-windows-msvc --all-targets` — no NEW warnings introduced by this edit. Pre-existing warnings (`nono::manifest.rs:95+103` collapsible_match; doc list-without-indentation) are tracked in Phase 23's deferred-items per CLAUDE.md.
- D-21 invariance: change is fully scoped to `exec_strategy_windows/launch.rs` (Windows-only file). No diff to Linux/macOS code paths.

**Pending:** field validation on the test box. User runs `.\nono.exe shell --profile claude-code --allow-cwd` again; expects to land in PowerShell 5.1 sandboxed shell, with `claude` startable inside, and `[NONO SANDBOX - PERMISSION DENIED]` hook firing on a blocked path read.

User ran `.\nono.exe shell --profile claude-code --allow-cwd --shell C:\Windows\System32\cmd.exe`. Exit code: `-1073741502` = `0xC0000142` = `STATUS_DLL_INIT_FAILED` (same as repro). cmd.exe is CLR-free, so the CLR-DllMain framing in the original diagnosis is wrong. Status reverted to `investigating`.

**New focus:** the failure is not binary-specific (PowerShell vs cmd) — it's path-specific (`nono shell` vs `nono run`). Phase 15's smoke gate proved `nono run --allow-cwd -- cmd /c "echo hello"` PASSED with WRITE_RESTRICTED + ConPTY on the same code path; `nono shell --shell cmd.exe` FAILS on what is supposed to be a near-identical path.

**Top candidates for the divergence (H5):**
- Different `interactive_pty` setting between `run` and `shell` → different ConPTY allocation order
- Different command-line shape: `nono run -- cmd /c "echo hello"` vs `nono shell` (which spawns cmd.exe with no `/c` arg → cmd reads from console for input)
- Different stdio inheritance — interactive ConPTY needs bidirectional read from the user
- Different proc-attribute list

**Action:** request `-vv` tracing output to localize the last-good supervisor stage before child death. Avoid spinning more code analysis without that data — static analysis already produced one wrong answer (H1).

## Wave 1 Field Smoke Outcome

**Date:** 2026-05-07 (Phase 30 Plan 30-04, Wave 2 trigger path)

**Outcome:** Acceptance #1 FAIL (silent launch). Wave 1 cascade arm landed but does NOT produce a runnable Low-IL child on this test box.

**Diagnostic evidence** (manual override of harness — see "Harness collateral" below):

| Probe | Outer (before `nono shell`) | "Inner" (after `nono shell`) |
|---|---|---|
| `whoami /groups` mandatory label | Medium S-1-16-8192 | **Medium S-1-16-8192** (unchanged) |
| `$PID` | 4708 | **4708** (same process — never left outer) |
| `Get-Process nono` | — | **(empty)** (supervisor exited silently) |

The supervisor printed the capability banner, applied filesystem capabilities (label-guard warnings visible — D-09 leaked-Low-IL noise expected), then the child never materialized and control returned to the outer Medium-IL PowerShell. Same shape as the pre-Phase-30 baseline this debug session was opened to fix; Wave 1's `WindowsTokenArm::LowIlPrimary` cascade-arm landing did not change observable behavior.

**Acceptance verdicts:**
- #1 (shell launches at Low-IL): **FAIL** (silent exit; no Low-IL child)
- #2 (TUI renders inside sandbox): **RETROACTIVELY UNTESTED** — Checkpoint 1's `tui-pass` was a false positive; `claude` ran in the OUTER shell (RESEARCH Pitfall 2 silent-failure mode realized in practice — exactly the failure mode the runbook warned about, and that visual TUI quality alone cannot detect)
- #3 (write-deny outside grant set): **UNTESTED** (couldn't enter sandbox)
- #4 (read-still-works on granted path): **UNTESTED** (couldn't enter sandbox)

**Harness collateral** (must be addressed in Plan 30-05 OR a separate harness-rework plan before Wave 2 ProcMon is meaningful):

1. `scripts/test-windows-shell-write-deny.ps1:113` — PowerShell `$p:` parser ambiguity (drive-qualifier collision). Fixed inline to `${p}:`.
2. The harness invokes `nono shell --shell powershell.exe -- -NoLogo -NoProfile -Command <injected>`, but `nono shell` is purely interactive — no positional/trailing-args surface, no `-c`-style command injection. Result: `error: unexpected argument '-NoLogo' found`. Plan 30-05 (or a sibling) must decide between (a) adding `nono shell --command` flag, (b) rewriting harness to use stdin / `nono wrap`, or (c) converting Acceptance #3/#4 to fully manual diagnostics like the IL/PID assertions used to detect the silent launch above.
3. The harness's `Out-File '$path' 'content'` syntax is invalid PowerShell (positional arg interpreted as `-Encoding`). Plan 30-05 should normalize all harness write attempts to `Set-Content -Path -Value` or pipeline-style `'content' | Out-File -FilePath`.

**Log files:** `ci-logs-local/test-windows-shell-write-deny-20260507-214336.log` (harness's INDETERMINATE first attempt, before manual override).

**Plan 30-05 input:** ProcMon trace `nono shell --profile claude-code --allow-cwd` against the current binary (commit `a496734b`). Watch for `\Device\ConDrv` ALPC + ImageLoad chain in conhost.exe; cross-check whether the Low-IL primary token's CreateProcess succeeds at all (process create event with the supervisor as parent and conhost/powershell as child) versus failing pre-create. The diagnostic that the supervisor itself exits — not just the child — narrows the hypothesis to a parent-side failure after capability application: pipe-server bring-up, ConPTY allocation, or the cascade-arm decision producing a token shape that fails downstream.

## Resolution

**Resolved by:** Phase 30 Plan 30-05 — Wave 2 ProcMon investigation exhausted without surfacing a workable user-mode option within the D-04 3-5 working day timebox.

**Outcome:** `nono shell --profile claude-code --allow-cwd` on Windows 10/11 is structurally incompatible with simultaneous WRITE_RESTRICTED + ConPTY + Low-IL primary token at user-mode. The Wave 2 ProcMon investigation localized the failure precisely:

- powershell.exe child (PID 35976 in trace) created under Plan 30-02's Low-IL primary token cascade arm.
- Process exits with `STATUS_DLL_INIT_FAILED (0xC0000142, decimal -1073741502)` after a ~35 ms lifespan.
- Process loaded its own image + `ntdll` + `kernel32` + `KernelBase`, then died within 6.8 ms after KernelBase Load Image notification fired.
- **Zero further Load Image events** in the death window — failure is in the static-init / DllMain chain of those four DLLs.
- Sub-classification: **CSRSS console-subsystem ALPC handshake denied at Low-IL** during `KernelBase!BaseDllInitialize` → `ConClntInitialize`. The CSRSS ALPC port DACL excludes Low-IL clients; the connect call fails synchronously; KernelBase's DllMain returns FALSE; the loader sets `STATUS_DLL_INIT_FAILED` and the process exits before reaching `main()`.
- The PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE inherited handles do NOT bypass this — they're a separate communication path (terminal I/O between `nono.exe` ↔ `conhost.exe`).

This is RESEARCH Pitfall 2 (Microsoft-documented integrity-mismatch failure) confirmed in the field on the supervised+ConPTY path. Phase 15 fixed the same `STATUS_DLL_INIT_FAILED` signature for the **detached** `nono run` path via `should_allocate_pty` gate at `supervised_runtime.rs:88-94`; Phase 30 cannot apply Phase 15's gate because `nono shell` requires interactive ConPTY by definition (D-04 explicitly rejected the Phase 15 detached waiver).

**Phase 30 ships failure-mode finding:**
- SHELL-01 PROJECT.md row → ✘ deferred to v3.0.
- Cookbook (`docs/cli/development/windows-poc-handoff.mdx`) reverted per RESEARCH §"Cookbook Rollback Path" Option Rev-B (text replacement, NOT git revert): stripped the `<Note>` recommendation, Step 4 `nono shell` instruction, Step 5 "Interactive verification (manual)" block, and Step 6 `nono shell` rows; KEPT the "Known limitation" section (factually correct); ADDED new "`nono shell` on Windows is deferred to v3.0" section with the four-failure-mode evidence.
- POC users get `nono run -- claude --version` (and similar non-TUI invocations) on Windows until v3.0 kernel mini-filter driver work or a Phase 31 broker-process pattern lands.
- Wave 1 cascade arm code stays in tree — the `WindowsTokenArm::LowIlPrimary` enum + `select_windows_token_arm` helper + `pty_token_gate_tests` (6/6) + Windows-only `low_integrity_primary_token_sets_low_il` runtime test all pass; the helpers are guards on the underlying mechanism for whenever v3.0 / Phase 31 activates this path.

**Six sixth-option candidates analyzed in `30-WAVE-2-PROCMON.md`** (all viable user-mode paths exceed D-04 timebox):

- **6a — AppContainer model** (1-2 weeks): replace Low-IL primary token with LOWBOX SID + capabilities; CSRSS works for AppContainers natively. Phase 31 candidate.
- **6b — Broker-process pattern** (~1 week): small Medium-IL intermediary attaches to CSRSS, lowers self to Low-IL, spawns PowerShell as Low-IL child inheriting attached console. Microsoft-documented; **strongest Phase 31 candidate**.
- **6c — Pre-AllocConsole sequencing** (1-2 days experimental): theoretically fails because PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE replaces inherited console; KernelBase still calls CSRSS attach. Not chosen.
- **6d — Job Object UI restrictions instead of mandatory-label IL**: violates CONTEXT D-06 (mandatory-label NO_WRITE_UP requirement). Not viable for Phase 30 contract.
- **6e — Defer to v3.0 / kernel-driver** (~1 day): chosen path. Honest disposition; preserves evidence.
- **6f — Pipe-stdio instead of ConPTY**: violates CONTEXT D-05 (TUI rendering requirement). Not viable for Phase 30 contract.

**Cross-references:**
- Phase 30 CONTEXT: `.planning/phases/30-windows-nono-shell-architecture/30-CONTEXT.md`
- Phase 30 RESEARCH: `.planning/phases/30-windows-nono-shell-architecture/30-RESEARCH.md`
- Phase 30 Wave 1 field smoke: `.planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md`
- Phase 30 Wave 2 ProcMon evidence: `.planning/phases/30-windows-nono-shell-architecture/30-WAVE-2-PROCMON.md`
- Cookbook revert: `docs/cli/development/windows-poc-handoff.mdx` § "`nono shell` on Windows is deferred to v3.0"
- PROJECT.md SHELL-01 row (✘ deferred): `.planning/PROJECT.md` § "Validated requirements"
- STATE.md Key Decisions Phase 30 entry: `.planning/STATE.md` § "Key Decisions (v2.3)"
- Phase 15 parallel-pattern resolution (detached path; Phase 30 cannot reuse): `.planning/debug/resolved/windows-supervised-exec-cascade.md`

**v3.0 / Phase 31 follow-up scope:**

The deferred work is the broker-process pattern (6b) or a kernel mini-filter driver. Either delivers `nono shell` on Windows with full TUI + write-deny. CONTEXT.md `<deferred>` block enumerates the shape; this Resolution doesn't pre-bind to a v3.0 architecture — Phase 31 will re-discuss-phase based on which option proves viable.

**Out-of-scope sibling concerns** (not closed by this resolution):

- **D-08:** Claude Code PreToolUse hook not firing — separate debug session at `.planning/debug/claude-code-hook-not-firing.md` (not yet created; v2.4 candidate per CONTEXT.md `<deferred>` block).
- **D-09:** AppliedLabelsGuard label leak (9 leaked Low-IL paths in user home — Plan 30-04 + Plan 30-05 evidence both observe `prior_rid="0x1000"` on `.cache\claude`, `.cargo`, `.claude`, `.config\git\ignore`, `.gitconfig`, `.local\bin`, `.rustup`, `AppData\Roaming\nono\profiles`, `Nono`). The harness's `icacls /setintegritylevel "(NX)Medium"` clear in `test-windows-shell-write-deny.ps1` Step 2 returns "The parameter is incorrect" — separate debug session at `.planning/debug/nono-labels-guard-leak.md` (not yet created; v2.4 candidate per CONTEXT.md `<deferred>` block).
- **Field-smoke harness collateral (Plan 30-05 inheritance for Phase 31):** (a) `nono shell` does not accept positional/trailing args after `--` — `scripts/test-windows-shell-write-deny.ps1` invocation is structurally incompatible with the current CLI; (b) `Out-File '<path>' '<content>'` invalid PowerShell syntax in same harness. Both surfaced and documented in `30-WAVE-2-PROCMON.md`; Phase 31 inherits the rework.

---

## Postscript: broker-pattern PoC validated A1 same-day (2026-05-08)

After this session was resolved as failure-mode finding, quick-task `260508-m99` shipped a standalone Rust binary that executes the broker-process pattern's core mechanism (Plan 30-05 Wave 2 option 6b). User ran it on Windows test box: child PID matches `$PID` from spawned shell; `whoami /groups` confirms `Mandatory Label\Low Mandatory Level S-1-16-4096`; child ran interactively to clean exit; `[POC] Child exit code: 0x00000000 (0)`. PSReadLine `Access to the path '...' is denied` on `AppData\Roaming\...\ConsoleHost_history.txt` confirmed mandatory-label NO_WRITE_UP enforcement is firing as designed.

**RESEARCH.md A1 empirically validated:** KernelBase's `ConClntInitialize` does skip the CSRSS ALPC connect when the Low-IL child inherits its parent's already-attached console — provided the parent (the broker) is at Medium-IL and holds the console attachment. The CSRSS denial that this debug session originally surfaced applies to the *direct* CreateProcessAsUserW path that Plan 30-02 wired into `launch.rs`, NOT to the broker-mediated indirect path.

**Resolution updated:** This debug session stays at `status: resolved` with the failure-mode finding intact for the direct path (which is the path Phase 30 production code took). The follow-up mechanism integration — wiring `nono.exe` to dispatch through a Medium-IL broker that spawns the Low-IL `powershell.exe` — is **Phase 31's deliverable**, not a re-opening of this session. PROJECT.md SHELL-01 row revised from `✘ deferred to v3.0` to `⚠ Phase 31 candidate (broker-process PoC validated 2026-05-08)`.

**PoC artifacts (preserved as Phase 31 reference):**
- `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/src/main.rs` (196 lines, working broker mechanism)
- `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/SUMMARY.md` (field-test outcome with verbatim user transcript)
- `.planning/quick/260508-lqh-scope-phase-31-broker-process-implementa/RESEARCH.md` §6 + §Assumptions Log A1 (the assumption now validated)

**Phase 31 effort estimate** (from RESEARCH.md, revised post-PoC): ~7 days for the production lift (was 7-9; the 1.5-day PoC step is complete). Lift broker mechanism into `crates/nono-shell-broker/`, dispatch from `launch.rs`, fix harness `Out-File` false-PASS bug, re-run field smoke for Acceptance #1-#4, ship cookbook update flipping SHELL-01 ✘→✔.

***

## Postscript 2: Phase 31 closure (2026-05-09)

Phase 31 (Broker-Process Architecture, SHELL-01) shipped with all Acceptance #1-#4 + #7 PASS on the user's Windows test box. The broker pattern (Medium-IL intermediary spawning Low-IL child via CreateProcessAsUserW with dwCreationFlags=EXTENDED_STARTUPINFO_PRESENT) bypasses the CSRSS console-subsystem ALPC denial that blocked the direct Low-IL spawn from `nono.exe`. RESEARCH Assumption A1 ("KernelBase ConClntInitialize skips the CSRSS ALPC connect when the child inherits the parent's console") is now both PoC-validated (2026-05-08) and production-validated (2026-05-09).

This debug session is fully resolved. SHELL-01 → ✔ validated v2.3 Phase 31. Cookbook updated. Closing line of bug → PoC → Phase 31 closure.

References:
- PoC: `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/SUMMARY.md`
- Phase 31 plans: `.planning/phases/31-broker-process-architecture-shell-01/31-{01..06}-PLAN.md`
- Phase 31 field-smoke: `.planning/phases/31-broker-process-architecture-shell-01/31-FIELD-SMOKE.md`
- Phase 31 final summary: `.planning/phases/31-broker-process-architecture-shell-01/31-06-SUMMARY.md`
