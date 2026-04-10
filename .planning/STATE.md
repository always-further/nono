---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: executing
stopped_at: Completed 07-02-PLAN.md
last_updated: "2026-04-08T15:17:25.194Z"
last_activity: 2026-04-08
progress:
  total_phases: 11
  completed_phases: 7
  total_plans: 19
  completed_plans: 19
  percent: 0
---

# Project State: nono - Windows Gap Closure

## Project Reference

**Core Value:** Every nono command that works on Linux/macOS should work on Windows with equivalent security guarantees, or be explicitly documented as intentionally unsupported with a clear rationale.

**Current Focus:** Phase 07 — quick-wins

## Current Position

Phase: 07 (quick-wins) — EXECUTING
Plan: 2 of 2
Status: Ready to execute
Last activity: 2026-04-08

```
Progress: [░░░░░░░░░░░░░░░░░░░░] 0% (0/5 phases, 0/12 plans)
```

## Accumulated Context

### Key Decisions (carried from v1.0)

- **Supervisor-Broker Pattern:** Research confirms this is the only way to manage elevated tasks like WFP while maintaining user-level CLI (2026-04-04).
- **WFP as Primary Network Backend:** Moving away from temporary firewall rules for true kernel-level enforcement (2026-04-04).
- **Named Job Objects:** Chosen for agent lifecycle management to ensure atomic stop/list capabilities (2026-04-04).
- **SID-Based Filtering:** Prioritized over App-ID to ensure child processes inherit network restrictions (2026-04-04).
- **Double-Launch Strategy:** Used `DETACHED_PROCESS` to decouple the supervisor from the parent terminal (2026-04-04).
- **Restricted Tokens:** Used to apply the session-unique SID to the process tree (2026-04-04).
- **RFC 3161 Timestamping:** Upgraded from legacy /t to /tr + /td sha256 (2026-04-05).
- **WFP Startup Orphan Sweep:** Enumerates NONO_SUBLAYER_GUID filters and removes stale ones at startup (2026-04-05).
- **Machine MSI Owns EventLog Registration:** SYSTEM\CurrentControlSet\Services\EventLog\Application\nono-wfp-service (2026-04-05).
- **MSRV 1.77:** Bumped from 1.74 to align with windows-sys 0.59 (2026-04-05).
- **WaitNamedPipeW Readiness Probe:** run_detached_launch() uses WaitNamedPipeW(50ms) per iteration on Windows (2026-04-05).
- **Single SID Generation Point:** Session SID generated once at ExecConfig construction (2026-04-06).
- **Driver Gate Removed:** activate_policy_mode no longer checks for a kernel driver binary artifact (2026-04-06).

### Key Decisions (v2.0)

- **Phase ordering A→B:** Phase 7 validates the entry-point guard removal pattern before Phase 8 layers ConPTY complexity on top (2026-04-06).
- **Phases 9, 10, 11 are independent:** Can be planned and executed in any order relative to each other and to Phase 7/8 (2026-04-06).
- **Single IPC version bump for Phase 9:** Gaps 4 (proxy) and 5 (port filtering) grouped in one phase to avoid two separate `nono-wfp-service` deployments (2026-04-06).
- **ETW library decision deferred to Phase 10 plan 10-01:** `ferrisetw` vs direct `windows-sys` bindings must be evaluated and documented before any ETW code is written (2026-04-06).
- **Gap 6b deferred to v3.0:** Kernel minifilter driver required; no user-mode workaround acceptable (2026-04-06).
- **Minimum build for ConPTY and ETW:** Windows 10 build 17763 (1809); enforced via `RtlGetVersion` at runtime; no silent fallback (2026-04-06).
- **Anonymous Job Object for wrap:** Pass `None` to `execute_direct` for Direct strategy; empty session_id would produce malformed Job Object name `Local\nono-session-` (2026-04-08).
- **nono wrap available on Windows:** Direct strategy with Job Object + WFP enforcement; documented with "no exec-replace, unlike Unix" qualifier per WRAP-01 (2026-04-08).

### Research Flags (open)

- **Phase 10 (10-01):** ETW library decision (`ferrisetw` vs `windows-sys` direct) must be resolved before any ETW code is written. Check `ferrisetw` crates.io for current version and open issues at 10-01 start.
- **Phase 10 (10-01):** Verify `Win32_System_Diagnostics_Etw` feature flag in `windows-sys 0.59` compiles cleanly before committing to the implementation approach.
- **Phase 11 (11-01):** Read `crates/nono/src/supervisor/socket_windows.rs` `create_named_pipe` SDDL before planning. If `S:(ML;;NW;;;LW)` is absent, 11-01 must add it; this changes scope.

### Todos

- [ ] Discuss Phase 4 filesystem strategy (VSS vs Merkle Trees)

### Blockers

- None currently identified.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260405-v0e | investigate and fix exec_strategy.rs uncommitted changes | 2026-04-06 | b6e20e4 | [260405-v0e-investigate-and-fix-exec-strategy-rs-unc](./quick/260405-v0e-investigate-and-fix-exec-strategy-rs-unc/) |
| 260405-vjj | Fix PR 555 DCO signoffs, commit PR 583 review feedback fixes, push current changes | 2026-04-06 | 4880c03 | [260405-vjj-fix-pr-555-signoffs-and-merge-conflicts-](./quick/260405-vjj-fix-pr-555-signoffs-and-merge-conflicts-/) |
| 260406-ajy | Assess Windows functional equivalence to macOS and Linux | 2026-04-06 | — | [260406-ajy-assess-windows-functional-equivalence-to](./quick/260406-ajy-assess-windows-functional-equivalence-to/) |
| 260406-bem | Research Windows gaps and create WINDOWS-V2-ROADMAP.md | 2026-04-06 | b67f74a | [260406-bem-research-and-roadmap-windows-gap-closure](./quick/260406-bem-research-and-roadmap-windows-gap-closure/) |

## Session Continuity

**Current Milestone:** v2.0 Windows Gap Closure
**Last Activity:** 2026-04-08
**Stopped At:** Completed 07-02-PLAN.md
**Next Steps:** `/gsd:plan-phase 7` for Quick Wins (still pending). Phases 9, 10, and 11 can be planned independently.
