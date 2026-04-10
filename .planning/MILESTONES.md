# Milestones

## v1.0 — WIN-1706 Option 1: Windows Library/Runtime Alignment

**Status:** In Progress
**Started:** 2026-04-03
**Goal:** Promote Windows from "supported CLI + partial library" to one aligned support contract across library, CLI, tests, CI, and docs.

**Phases:** 4 (see ROADMAP.md)

**Definition of Done:**
1. `Sandbox::support_info()` no longer reports Windows as `partial` for the supported Windows contract
2. `Sandbox::apply()` on Windows no longer returns generic `UnsupportedPlatform` for supported shapes
3. CLI support output no longer needs a "CLI supported, library partial" split
4. Windows docs and README describe Windows as first-class supported without qualification
5. Full verification gate passes (fmt, build, clippy, test, Windows regression)
