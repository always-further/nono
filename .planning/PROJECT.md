# nono - Windows Parity Milestone

## Current Milestone: v2.0 Windows Gap Closure

**Goal:** Close the 7 remaining feature gaps between Windows and Unix platforms, achieving full cross-platform parity for everyday CLI usage, network policy, and developer tooling.

**Target features:**
- `nono wrap` on Windows (Direct strategy with Job Object + WFP enforcement)
- Session log commands (`nono logs`, `nono inspect`, `nono prune`) on Windows
- Interactive `nono shell` via ConPTY (`CreatePseudoConsole`)
- Port-granular WFP network policy + proxy credential injection
- `nono learn` on Windows via ETW (Event Tracing for Windows)
- (Stretch) Runtime capability expansion over named pipe

---

## What This Is

nono is a capability-based sandboxing system for running untrusted AI agents with OS-enforced isolation. This project focuses on bringing the Windows implementation to full cross-platform parity with Linux and macOS, covering supervisor lifecycle, kernel-level network enforcement, interactive shell hosting, path discovery, and developer tooling.

## Core Value

Windows security must be as structurally impossible and feature-complete as Unix platforms, ensuring the dangerous bits are kernel-enforced without compromising the supervisor-led security model.

## Requirements

### Validated

- ✔ Landlock sandbox (Linux) — core library
- ✔ Seatbelt sandbox (macOS) — core library
- ✔ Windows capability subset enforcement (WFP network + Low Integrity filesystem)
- ✔ CLI capability builder (`--allow`, `--read`, `--block-net`, profile-backed policy)
- ✔ Built-in profiles (claude-code, codex, opencode, openclaw, swival)
- ✔ Windows alignment (WIN-1706): Library/CLI contract unified
- ✔ Windows release automation (signed .exe, machine MSI, user MSI, zip)
- ✔ C FFI bindings (nono-ffi)
- ✔ Windows CI lanes (build, smoke, integration, security, parity-regression, packaging)
- ✔ Supervisor parity (attach, detach, ps, stop) — v1.0 Phases 1–2
- ✔ WFP promotion to primary enforced network backend — v1.0 Phase 06
- ✔ Snapshot/rollback for Windows filesystems — v1.0 Phase 4
- ✔ MSI packaging and code signing automation — v1.0 Phase 4

### Active (v2.0)

- [ ] **WRAP-01**: User can run `nono wrap <cmd>` on Windows using Direct strategy with Job Object + WFP enforcement.
- [ ] **SESS-01**: User can run `nono logs`, `nono inspect`, `nono prune` on Windows session records.
- [ ] **SHELL-01**: User can run `nono shell` to launch an interactive PowerShell/cmd session inside a Job Object + WFP sandbox via ConPTY.
- [ ] **PORT-01**: User can specify port-level network allowlists via WFP permit filters (`--allow-port`, bind/connect/localhost).
- [ ] **PROXY-01**: User can route sandboxed agent traffic through a local proxy with `HTTPS_PROXY` credential injection enforced by WFP.
- [ ] **LEARN-01**: User can run `nono learn <cmd>` on Windows to capture file and network access patterns via ETW.
- [ ] **TRUST-01** *(stretch)*: A sandboxed child process can request additional capabilities from the supervisor at runtime over named pipe.

### Out of Scope

- Gap 6b (runtime trust interception via kernel minifilter) — requires signed kernel driver; deferred to v3.0.
- Full feature parity for experimental Unix features not yet stabilized.

## Context

- Windows parity is the current "honesty gap" in the product; users expect the same CLI experience across all supported OSs.
- The technically challenging core of this milestone is the Supervisor IPC (named pipes) and WFP driver/service orchestration.
- Previous work (PRs 530, 555, 583) has laid the foundation for native Windows functionality.
- Dark factory rules apply: fail closed, no silent fallback, no broadening claims beyond enforcement.

## Constraints

- **Security**: Fail secure on any unsupported shape â€” never silently degrade.
- **Compatibility**: Must support Windows 10/11 (modern Job Objects and WFP).
- **Performance**: Zero startup latency must be maintained for the Windows backend.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Supervisor Parity as Priority | Essential for "attach/detach" workflow used by long-running agents. | â€” Pending |
| WFP over Temporary Firewall | Kernel-level enforcement is the “nono way”; temporary rules are a stopgap. | ✔ Complete — Phase 06 wired SID end-to-end, removed driver gate, cleaned duplicate activation path |
| Intentional `shell`/`wrap` omission | Lack of credible enforcement model on Windows; avoiding security over-claims. | âœ“ Good |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? â†’ Move to Out of Scope with reason
2. Requirements validated? â†’ Move to Validated with phase reference
3. New requirements emerged? â†’ Add to Active
4. Decisions to log? â†’ Add to Key Decisions
5. "What This Is" still accurate? â†’ Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check â€” still the right priority?
3. Audit Out of Scope â€” reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-06 — Milestone v2.0 started (Windows Gap Closure)*
