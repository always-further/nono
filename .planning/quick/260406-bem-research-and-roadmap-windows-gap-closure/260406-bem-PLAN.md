---
phase: quick
plan: 260406-bem
type: execute
wave: 1
depends_on: []
files_modified:
  - .planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/WINDOWS-V2-ROADMAP.md
  - .planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/260406-bem-SUMMARY.md
autonomous: true
requirements: []
must_haves:
  truths:
    - "A complete milestone roadmap exists for closing all 7 Windows gaps"
    - "Each gap from the research maps to exactly one phase in the roadmap"
    - "Deferred items are explicitly listed with rationale"
    - "Phase ordering reflects dependency analysis from research"
  artifacts:
    - path: ".planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/WINDOWS-V2-ROADMAP.md"
      provides: "Complete v2.0 Windows gap closure milestone roadmap"
      min_lines: 100
    - path: ".planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/260406-bem-SUMMARY.md"
      provides: "Quick task summary"
  key_links:
    - from: "WINDOWS-V2-ROADMAP.md"
      to: "260406-bem-RESEARCH.md"
      via: "Gap IDs map to phases"
      pattern: "Gap [1-7]"
---

<objective>
Create a complete milestone roadmap for the Windows v2.0 gap closure effort, informed by the research findings in 260406-bem-RESEARCH.md.

Purpose: Provide a structured, dependency-aware plan for closing all remaining Windows feature gaps identified in the equivalence assessment and research phase.
Output: WINDOWS-V2-ROADMAP.md + quick task summary
</objective>

<execution_context>
@C:/Users/omack/.claude/get-shit-done/workflows/execute-plan.md
@C:/Users/omack/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/260406-bem-RESEARCH.md
</context>

<tasks>

<task type="auto">
  <name>Task 1: Write WINDOWS-V2-ROADMAP.md</name>
  <files>.planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/WINDOWS-V2-ROADMAP.md</files>
  <action>
Create a complete milestone roadmap document. Use the style and structure of `.planning/ROADMAP.md` (the v1.0 milestone roadmap) as the template.

**Milestone header:**
- Name: "Windows v2.0 — Gap Closure"
- Goal: Close the remaining 7 feature gaps between Windows and Unix platforms, bringing nono to full cross-platform parity for everyday CLI usage, network policy, and developer tooling.
- Core Value: Every nono command that works on Linux/macOS should work on Windows with equivalent security guarantees, or be explicitly documented as intentionally unsupported with a clear rationale.

**Phase structure (5 phases, derived from RESEARCH.md "Recommended Milestone Phasing"):**

Phase A: Quick Wins (wrap + session commands)
- Goal: Unblock everyday UX with trivial effort
- Covers: Gap 2 (wrap) and Gap 7 (logs/inspect/prune)
- Complexity: S+S
- Dependencies: None
- Plans: 1-2 plans
- Success criteria:
  1. `nono wrap <cmd>` executes on Windows with Job Object + WFP enforcement
  2. `nono logs`, `nono inspect`, `nono prune` work on Windows session records
  3. Help text documents the behavioral difference (wrap does not exec-replace on Windows)
- Requirements: WRAP-01, SESS-01

Phase B: ConPTY Shell
- Goal: Enable interactive `nono shell` on Windows via ConPTY
- Covers: Gap 1 (shell)
- Complexity: M
- Depends on: Phase A (validate_preview_entry_point pattern established)
- Plans: 2 plans (ConPTY wiring + enforcement validation, then I/O relay + resize)
- Success criteria:
  1. `nono shell` launches an interactive PowerShell/cmd session inside a sandbox
  2. Terminal resize events propagate correctly
  3. Job Object and WFP enforcement apply to the shell process
  4. Minimum Windows 10 1809 enforced with clear error on older builds
- Requirements: SHELL-01

Phase C: WFP Port-Level + Proxy Filtering
- Goal: Enable port-granular network policy and proxy credential injection on Windows
- Covers: Gap 4 (proxy filtering) and Gap 5 (port filtering)
- Complexity: M+M
- Depends on: None (WFP IPC already in place from v1.0 Phase 6)
- Plans: 2-3 plans (WFP IPC contract extension for both, proxy filtering, port filtering)
- Note: Gaps 4 and 5 share the WfpRuntimeActivationRequest extension — do in same phase to avoid multiple IPC contract bumps
- Success criteria:
  1. `--allow-port 8080` creates a WFP permit filter for the specified port
  2. `--proxy-only` mode routes through localhost proxy with WFP enforcement
  3. Port bind and connect allowlists work independently
  4. Credential injection via HTTPS_PROXY env var reaches the sandboxed child
- Requirements: PORT-01, PROXY-01

Phase D: ETW-Based Learn Command
- Goal: Implement syscall-based path discovery on Windows using ETW
- Covers: Gap 3 (learn)
- Complexity: L
- Depends on: None (independent)
- Plans: 2-3 plans (ETW integration + ferrisetw evaluation, file I/O tracing, network tracing + output format)
- Success criteria:
  1. `nono learn <cmd>` captures file and network access on Windows
  2. Output format matches Unix learn output (paths, access modes)
  3. Admin requirement is documented and enforced with clear error
  4. ferrisetw (or direct windows-sys ETW) evaluated and chosen
- Requirements: LEARN-01

Phase E: Runtime Capability Expansion (Deferred/Future)
- Goal: Enable runtime capability requests from sandboxed child to supervisor
- Covers: Gap 6a (runtime capability expansion)
- Complexity: M
- Depends on: Named-pipe supervisor IPC (already in place)
- Plans: 1-2 plans
- Note: This is a stretch goal. Include in roadmap but mark as "stretch" — can be deferred to v2.1 if timeline is tight
- Success criteria:
  1. Sandboxed child can request additional capabilities via named pipe
  2. Supervisor prompts user for approval via TerminalApproval
  3. Session token authentication on capability requests
- Requirements: TRUST-01

**Gap coverage table:**
Map each gap (1-7) from RESEARCH.md to the phase that closes it. Use a markdown table.

| Gap | Description | Phase | Complexity |
|-----|-------------|-------|------------|
| Gap 1 | nono shell (ConPTY) | Phase B | M |
| Gap 2 | nono wrap | Phase A | S |
| Gap 3 | nono learn (ETW) | Phase D | L |
| Gap 4 | Proxy filtering | Phase C | M |
| Gap 5 | Port-level filtering | Phase C | M |
| Gap 6a | Runtime capability expansion | Phase E (stretch) | M |
| Gap 6b | Runtime trust interception | Deferred | XL |
| Gap 7 | Session log commands | Phase A | S |

**Deferred items section:**
- Gap 6b: Runtime Trust Interception — Requires a signed kernel-mode minifilter driver (FltMgr). This is equivalent to building an endpoint security product component. Out of scope for v2.0. The Windows trust model is pre-exec verification only. Document this explicitly in help text and product docs.
- User-mode API hooking (Detours) — Rejected as unreliable and triggers antivirus false positives.
- ETW-based blocking — ETW is observe-only; cannot block operations. Not viable for trust interception.

**Open questions section (from research):**
Include the 4 open questions from RESEARCH.md verbatim or lightly edited.

**Progress table:**
Include an empty progress table matching the v1.0 format, with all phases showing "Not Started".

**Dependency diagram:**
```
Phase A (wrap + logs)     ──> Phase B (shell)
Phase C (WFP port+proxy)  [independent]
Phase D (ETW learn)        [independent]
Phase E (runtime caps)     [stretch, independent]
```

Phases A, C, D can run in parallel. Phase B depends on Phase A. Phase E is stretch/independent.
  </action>
  <verify>
    <automated>wc -l .planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/WINDOWS-V2-ROADMAP.md</automated>
  </verify>
  <done>WINDOWS-V2-ROADMAP.md exists with 100+ lines, covers all 7 gaps, has 5 phases with success criteria, gap coverage table, deferred items, and progress table matching v1.0 style</done>
</task>

<task type="auto">
  <name>Task 2: Write quick task summary</name>
  <files>.planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/260406-bem-SUMMARY.md</files>
  <action>
Create the quick task summary documenting what was produced.

Format:
```markdown
# Quick Task Summary: 260406-bem

## What Was Done
Created WINDOWS-V2-ROADMAP.md — a complete milestone roadmap for closing the 7 remaining Windows feature gaps.

## Artifacts
- `WINDOWS-V2-ROADMAP.md` — v2.0 milestone roadmap (5 phases, A through E)

## Key Decisions
- Phase ordering follows research recommendation: quick wins first (A), then parallel workstreams (B, C, D), stretch goal last (E)
- Gaps 4+5 (port filtering + proxy) grouped in same phase to share WFP IPC contract bump
- Gap 6b (runtime trust interception) deferred — requires kernel minifilter driver, out of scope
- Gap 6a (runtime capability expansion) included as stretch goal in Phase E

## Next Steps
- Review WINDOWS-V2-ROADMAP.md
- When ready to start, create `.planning/` milestone artifacts (PROJECT.md update, STATE.md, formal ROADMAP.md) via `/gsd:kickoff`
```
  </action>
  <verify>
    <automated>test -f .planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/260406-bem-SUMMARY.md && echo "exists"</automated>
  </verify>
  <done>Summary file exists documenting the roadmap creation and next steps</done>
</task>

</tasks>

<verification>
- WINDOWS-V2-ROADMAP.md exists and is 100+ lines
- All 7 gaps from research are mapped to phases
- Deferred items section exists with rationale
- Style matches v1.0 ROADMAP.md format
- Summary file exists
</verification>

<success_criteria>
A complete, actionable milestone roadmap exists that maps every researched Windows gap to a phase with success criteria, dependencies, and complexity estimates. The roadmap can be used directly as input to `/gsd:kickoff` for the v2.0 milestone.
</success_criteria>

<output>
After completion, the summary is at `.planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/260406-bem-SUMMARY.md`
</output>
