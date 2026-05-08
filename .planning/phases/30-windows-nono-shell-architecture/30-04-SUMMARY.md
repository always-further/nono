---
phase: 30-windows-nono-shell-architecture
plan: 04
subsystem: windows-shell-architecture
tags: [windows, field-smoke-execution, bookkeeping-outcome-flip, wave2-trigger, silent-launch-failure]

requires:
  - phase: 30-windows-nono-shell-architecture
    provides: cascade arm (30-02), field-smoke harness scripts + runbook (30-03), bookkeeping prelude (30-01)
provides:
  - "Wave 1 field smoke executed on Windows test box"
  - "Acceptance #1 silent launch failure documented with diagnostic evidence (whoami /groups + $PID + Get-Process nono)"
  - "Wave 2 trigger path bookkeeping atomically committed (PROJECT.md + STATE.md + debug session + FIELD-SMOKE operator log)"
  - "Field-smoke harness scripts shipped with one inline parser fix; two open issues documented for Plan 30-05"
affects: [Plan 30-05, Phase 30, SHELL-01, debug/nono-shell-status-dll-init-failed]

tech-stack:
  added: []
  patterns:
    - "Two-tier checkpoint diagnostics: harness-driven Acceptance #1/#2 + manual IL/PID assertions when harness path is structurally blocked"

key-files:
  created:
    - scripts/test-windows-shell-tui.ps1 (from Plan 30-03; shipped here per plan's deferred-commit clause)
    - scripts/test-windows-shell-write-deny.ps1 (from Plan 30-03 + inline parser fix at line 113)
    - .planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md (operator log row added)
  modified:
    - .planning/PROJECT.md (SHELL-01 row narrative flipped to Wave 2 ProcMon)
    - .planning/STATE.md (Key Decisions v2.3 block created with Phase 30 partial entry; stopped_at updated)
    - .planning/debug/nono-shell-status-dll-init-failed.md (status flipped; Wave 1 Field Smoke Outcome section appended)

key-decisions:
  - "Checkpoint 3 outcome: wave2-trigger-launch (Acceptance #1 FAIL — silent launch; supervisor exits without spawning Low-IL child)"
  - "Checkpoint 1 PASS retroactively reclassified as false positive — claude TUI rendered in OUTER shell, not the sandbox (RESEARCH Pitfall 2 silent-failure mode realized)"
  - "Debug session NOT moved to resolved/ — Phase 30 Wave 2 (Plan 30-05) owns the final disposition"
  - "Harness's `nono shell --shell powershell.exe -- -NoLogo -Command <x>` invocation is structurally incompatible with the current `nono shell` CLI (no positional/trailing-args surface); Checkpoint 2 driven via manual IL/PID diagnostics instead"
  - "Cookbook security-envelope paragraph NOT added (success-path-only per plan; gated on Wave 2 outcome)"

patterns-established:
  - "Manual IL/PID diagnostic pattern for verifying sandbox actually applied — `whoami /groups`+`$PID`+`Get-Process nono` before/after, looking for Mandatory Label transition + new PID + supervisor process alive. Catches silent-launch failures that visual TUI quality alone cannot detect."

requirements-completed: []  # Phase 30 has no formal REQ-IDs (D-coverage gate only; D-04 + D-10 partial — D-05 + D-06 + D-07 untested)

duration: ~70 min (interactive checkpoint-driven execution; iterations on harness bugs and diagnostic methodology)
completed: 2026-05-08
---

# Phase 30 Plan 30-04: Wave 1 field smoke surfaced silent-launch failure → wave2-trigger-launch

**Field smoke on Windows test box revealed `nono shell` silently exits without spawning a Low-IL child; Wave 2 (Plan 30-05) ProcMon investigation triggered.**

## Performance

- **Duration:** ~70 min interactive (3 checkpoints + Wave 2 trigger path bookkeeping)
- **Started:** 2026-05-07 ~21:30 EDT
- **Completed:** 2026-05-08 02:48 UTC
- **Tasks:** 5 (3 checkpoints + Task 5 bookkeeping; Task 4 cookbook SKIPPED — success-path-only)
- **Files committed:** 6

## Accomplishments

- Drove all three Plan 30-04 checkpoints (Acceptance #1 silent-launch field smoke, Acceptance #3/#4 manual override after harness CLI gap surfaced, Wave 2 trigger decision)
- Surfaced and documented the false-positive Checkpoint 1 PASS — exactly the RESEARCH Pitfall 2 silent-failure mode the runbook warned about
- Atomically committed Wave 2 trigger path bookkeeping (PROJECT.md + STATE.md + debug session + 30-FIELD-SMOKE operator log + harness scripts) per plan's single-commit discipline
- Established a manual IL/PID diagnostic pattern that future field-smoke harnesses (and Plan 30-05) can reuse to detect silent-launch failures structurally

## Task Commits

This plan's work landed across 1 atomic commit per the plan's `<action>` directive:

1. **Wave 2 trigger bookkeeping (PROJECT/STATE/debug/FIELD-SMOKE + 30-03 harness scripts shipped)** — `a86e6db3` (docs)

Plan 30-03 ships its harness scripts here (per Plan 30-03's `<output>` clause: "None committed yet (Plan 30-04 commits them along with field-smoke evidence)"). The write-deny script gained one inline fix during execution: PowerShell parser ambiguity `$p:` → `${p}:` at line 113.

## Files Created/Modified

- `.planning/PROJECT.md` — SHELL-01 row updated: ⚠ stays, narrative flipped from "needs-rework pending Phase 30 outcome" to "Wave 2 ProcMon investigation in flight (Plan 30-05, 3-5 working day timebox per CONTEXT D-04)"
- `.planning/STATE.md` — new `### Key Decisions (v2.3)` block created; Phase 30 Wave 1 partial entry appended; `stopped_at` flipped to "Phase 30 Wave 1 partial — Wave 2 ProcMon in flight (Plan 30-05; launch silent-failure)"; `last_updated` bumped
- `.planning/debug/nono-shell-status-dll-init-failed.md` — status flipped to `architecture-decided-wave-2-investigating`; `## Wave 1 Field Smoke Outcome` section appended with diagnostic table + acceptance verdicts + harness collateral; file NOT moved to resolved/
- `.planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md` — operator log row filled with `2026-05-07 | FAIL | UNTESTED | UNTESTED | UNTESTED | ...`
- `scripts/test-windows-shell-tui.ps1` — shipped from Plan 30-03 unchanged
- `scripts/test-windows-shell-write-deny.ps1` — shipped from Plan 30-03 + inline `$p:` → `${p}:` parser fix at line 113

## Field-smoke evidence

### Checkpoint 1 (TUI runbook): originally tui-pass — RETROACTIVELY UNTESTED

The user reported `tui-pass` for `pwsh -File scripts/test-windows-shell-tui.ps1`. After Checkpoint 2's diagnostics surfaced silent-launch failure, this was reclassified as a false positive. The runbook only checks visual TUI quality (does claude render correctly?) and does not verify the user is actually inside a Low-IL sandbox. Since the supervisor was silently exiting, claude was running in the OUTER Medium-IL shell, where it renders perfectly. RESEARCH Pitfall 2 anticipated this exact mode.

### Checkpoint 2 (write-deny): blocked by harness CLI gap → manual IL/PID override

`pwsh -File scripts/test-windows-shell-write-deny.ps1` first failed on a PowerShell parser bug (`$p:` ambiguity). After fixing that, the harness still failed because its core invocation is structurally incompatible with `nono shell`:

```
nono.exe shell --profile claude-code --allow-cwd --shell powershell.exe -- -NoLogo -NoProfile -Command <injected>
→ error: unexpected argument '-NoLogo' found
```

`nono shell` is purely interactive — no positional/trailing-args surface, no `-c`-style command injection. Checkpoint 2 was driven via manual diagnostics in an interactive `nono shell` session:

| Probe | Outer (before `nono shell`) | "Inner" (after `nono shell`) |
|---|---|---|
| `whoami /groups` mandatory label | `Medium S-1-16-8192` | **`Medium S-1-16-8192` (unchanged)** |
| `$PID` | 4708 | **4708 (unchanged — same process)** |
| `Get-Process nono` | — | **(empty — supervisor exited)** |

Diagnostic conclusion: the supervisor printed the capability banner, applied filesystem capabilities (label-guard warnings visible), then exited silently and returned control to the outer shell. No Low-IL child ever materialized.

### Checkpoint 3 (decision): wave2-trigger-launch

Per the 30-FIELD-SMOKE.md decision matrix `FAIL | * | * | * | wave2-trigger-launch`, the user selected **wave2-trigger-launch**.

## Open Issues for Plan 30-05

1. **Harness/CLI mismatch.** `nono shell` does not accept positional/trailing args after `--`. Plan 30-05 must either (a) add a `nono shell --command "..."` flag for non-interactive scripted use, (b) rewrite the harness to use stdin / `nono wrap` semantics, or (c) convert Acceptance #3/#4 to fully manual diagnostics like the IL/PID assertions used here.
2. **Out-File harness syntax.** `Out-File '$path' '$content'` in `test-windows-shell-write-deny.ps1` is invalid PowerShell — the second positional binds to `-Encoding` which `ValidateSet` rejects. Should be `Set-Content -Path -Value` or pipeline-style.
3. **Silent supervisor exit.** Wave 2 ProcMon investigation should localize whether `CreateProcessAsUserW` succeeds-then-child-dies-immediately or fails pre-create; the symptom (supervisor itself exits, not just the child) narrows the hypothesis to a parent-side failure after capability application — pipe-server bring-up, ConPTY allocation, or the Plan 30-02 cascade-arm decision producing a token shape that fails downstream in a way the unit-test runtime probe (`low_integrity_primary_token_sets_low_il`) does not exercise.
4. **D-09 leaked Low-IL labels.** 9 user-home paths still carry `prior_rid="0x1000"` from prior leaked runs. The `icacls /setintegritylevel "(NX)Medium"` clear in the harness's Step 2 logs `The parameter is incorrect` for all 9 — the syntax may be wrong, or the label-clear path needs different ACL surgery. Tracked separately as a sibling debug session per CONTEXT D-08/D-09.

## Self-Check: PASSED

All Plan 30-04 Wave 2 trigger acceptance gates verified before commit:

- [x] PROJECT.md `⚠ **SHELL-01**` with `Wave 2 ProcMon` (1 match)
- [x] STATE.md `Phase 30 Wave 1 partial` (2 matches: entry + stopped_at)
- [x] STATE.md `stopped_at: "Phase 30 Wave 1 partial` (1 match)
- [x] debug/nono-shell-status-dll-init-failed.md exists at non-resolved location
- [x] debug/resolved/nono-shell-status-dll-init-failed.md does NOT exist
- [x] debug session `status: architecture-decided-wave-2-investigating` (1 match)
- [x] debug session `## Wave 1 Field Smoke Outcome` heading (1 match)
- [x] 30-FIELD-SMOKE.md operator log filled with 2026-05-07 FAIL row
- [x] STATE.md mentions Phase 30 (6 matches; ≥2 required)
- [x] PROJECT.md mentions Phase 30 (1 match; ≥1 required)
- [x] Single atomic commit `a86e6db3` with DCO sign-off
