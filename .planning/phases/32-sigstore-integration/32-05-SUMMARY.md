---
phase: 32
plan: "05"
subsystem: docs
tags: [sigstore, adr, cookbook, documentation, audit, deferred-items]
dependency_graph:
  requires: ["32-02", "32-03", "32-04"]
  provides: ["broker-trust-anchor-adr", "sigstore-tuf-cache-adr", "windows-poc-handoff-sigstore-section", "release-pipeline-audit-verdict"]
  affects: []
tech_stack:
  added: []
  patterns:
    - "ADR convention mirroring docs/architecture/audit-bundle-target.md"
    - "Cookbook structural-parallelism pattern: sigstore prereq mirrors WFP block-net prereq from Step 5"
    - "Deferred-items entry format mirroring P32-DEFER-001"
key_files:
  created:
    - docs/architecture/broker-trust-anchor.md
    - docs/architecture/sigstore-tuf-cache.md
    - .planning/phases/32-sigstore-integration/32-05-SUMMARY.md
  modified:
    - .planning/phases/32-sigstore-integration/32-CONTEXT.md
    - .planning/phases/32-sigstore-integration/deferred-items.md
    - docs/cli/development/windows-poc-handoff.mdx
decisions:
  - "Audit verdict Option A — keep keyed signing posture; record migration as v2.4+ deferred (P32-DEFER-002), human reviewer signed off 2026-05-10"
  - "Plan 05 executed inline by orchestrator, not via gsd-executor subagent — worktree ID-collision risk (orchestrator's session worktree shared an ID with Plan 32-03's executor) made another worktree dispatch fragile; the plan is docs-only with a human-verify checkpoint mid-plan, so inline execution was clearly safer"
  - "P32-CHK-014 backfill: 32-CONTEXT.md launch.rs anchor corrected from line range past 2000 (test module) to :1246-1438 (broker dispatch arm); historical correction note kept for traceability"
metrics:
  duration: "~30 minutes"
  completed: "2026-05-10"
  tasks_completed: 3
  files_modified: 5
  files_created: 3
---

# Phase 32 Plan 05: Documentation + Release-Pipeline Audit Summary

Two new ADRs document Phase 32's novel decisions; cookbook gains a Sigstore-prereq
section parallel to the WFP service prereq pattern; release-pipeline audit
verdict recorded as v2.4+ deferred per D-32-10's explicit deferral. Phase 32
ships working code, working operator-facing docs, and a clean v2.4+ runway.

## One-liner

Two ADRs (broker-trust-anchor + sigstore-tuf-cache) + Windows POC handoff
cookbook Sigstore section + release.yml audit verdict (P32-DEFER-002 keep-keyed)
+ CONTEXT.md anchor backfill (P32-CHK-014).

## Tasks Executed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Two ADRs + CONTEXT.md backfill | 581a7e58 | broker-trust-anchor.md, sigstore-tuf-cache.md, 32-CONTEXT.md |
| 2 | Release-pipeline audit (checkpoint:human-verify) | 9e7049ac | deferred-items.md |
| 3 | Windows POC handoff cookbook Sigstore section | cce24bf9 | windows-poc-handoff.mdx |

## Implementation Details

### Task 1: Two ADRs + CONTEXT.md backfill

**`docs/architecture/broker-trust-anchor.md`** (119 lines): documents the D-32-13
self-trust-anchor decision. Decision table contrasts the chosen self-introspection
approach against three rejected alternatives (baked-in CN constant, config-file
trust anchor, Sigstore bundle alongside binary) — all of which have a chicken-and-egg
problem where the trust source itself becomes a target. The chosen pattern reads
`nono.exe`'s OWN Authenticode signature at every broker dispatch and requires the
broker to match (subject + thumbprint). Skip mechanism documented: install-layout
substring detector (NOT `#[cfg(debug_assertions)]`) per Pitfall 6 — `cargo test --release`
compiles WITHOUT debug_assertions, so a `#[cfg(debug_assertions)]` gate would fail-closed
against unsigned dev brokers under release-mode test runs. Threat model + consequences
sections enumerate accepted residual risks (compromised release pipeline; TOCTOU;
dev-build skip) with explicit mitigations.

**`docs/architecture/sigstore-tuf-cache.md`** (119 lines): documents the D-32-01
cached-root design rationale. Three problems surfaced together that drove this
decision: (a) `production()` fails on sigstore-verify 0.6.5 with the threshold-of-3
issue; (b) every keyless verify becomes a Sigstore-uptime dependency + privacy leak;
(c) async wrapper at 6 caller sites was a Tokio-runtime-per-verify cost. Decision
table contrasts the chosen sync-cache-read against three alternatives. The
verify-is-offline invariant is documented as both structural (source-grep absence
of network primitives in the verify path) and dynamic (the
`verify_path_uses_no_async_network_io` test runs verify on a non-runtime
`std::thread`). Includes the date-comparison strategy (Howard Hinnant civil-from-days
preserving D-19 no-chrono invariant), Pitfall 3 caveat about expired-retired tlogs
being normal, and the frozen-fixture test seam (D-32-06 indefinite pin).

Both ADRs cross-reference each other and follow `docs/architecture/audit-bundle-target.md`'s
ADR convention (Status / Date / Phase / Decision IDs / Context / Goals / Non-goals /
Decision Table / Decision / Consequences / References).

**P32-CHK-014 backfill:** the Phase 32 CONTEXT.md cited `launch.rs:2173+` for the
broker dispatch arm in three places. The actual broker dispatch arm is at
`launch.rs:1246-1438` (verified during PATTERNS.md preparation). All three citations
corrected; a parenthetical historical correction note retained at the canonical_refs
entry for traceability (the historical-anchor description was rephrased to avoid
the literal `:2173+` substring per the plan's grep-zero acceptance criterion).

### Task 2: Release-pipeline audit (CHECKPOINT)

Read `.github/workflows/release.yml` end-to-end. Audit findings:

- **Mechanism:** Authenticode `signtool` via `scripts/sign-windows-artifacts.ps1`,
  triggered by `WINDOWS_SIGNING_CERT` (base64) + `WINDOWS_SIGNING_CERT_PASSWORD`
  GitHub repo secrets.
- **Artifacts signed:** `nono.exe`, `nono-shell-broker.exe`, machine MSI, user MSI,
  zip payload (Phase 31 Plan 04 extension).
- **Timestamping:** RFC 3161 (`signtool /tr /td sha256`).
- **Verification:** `signtool verify` then `Get-AuthenticodeSignature` (D-13
  fail-closed; both must pass before any upload step).
- **Sigstore presence:** **None.** No `cosign sign-blob`. No `id-token: write`
  permission (`permissions:` block has only `contents: write`). No Sigstore bundles
  next to release artifacts.
- **Linux/macOS signing:** unsigned beyond GitHub-Release-level integrity (SHA256SUMS.txt).

**Verdict (human reviewer signed off 2026-05-10):** Option A — keep keyed; record
migration as v2.4+ deferred (`P32-DEFER-002` in
`.planning/phases/32-sigstore-integration/deferred-items.md`). The deferred-items
entry includes:

- Trigger (Phase 32 Plan 05 audit)
- Current posture table (mechanism, cert source, artifacts, timestamping, verification, Sigstore presence, Linux/macOS signing)
- Why deferred — five concrete migration steps (OIDC permission wiring, Sigstore Bundle artifact packaging, consumer-side verify wiring, secret rotation operations, Authenticode posture decision)
- Entry criteria for v2.4+ promotion (compliance ask, secret-rotation pain, Sigstore ecosystem maturity)
- Closures NOT carried forward (mock Fulcio/Rekor capture and broker-mismatch-stub
  fixture were closed by Plans 03 and 04 implementation; see P32-CHK-005/008/010/011)
- Related files (release.yml, sign-windows-artifacts.ps1, trust-policy-keyless-template.json,
  windows-signing-guide.mdx, 32-CONTEXT.md)

The verdict honors D-32-10's explicit "Migration to keyless explicitly out of scope"
language. Phase 32 ships forward-compatible groundwork: the cached TUF root
infrastructure + identity-pinned trust-policy template means a future v2.4+
migration only needs to add the producer-side Sigstore Bundle generation —
the consumer-side verify path is already in place.

### Task 3: Windows POC handoff cookbook updates

Added a new top-level "## Sigstore Trust Root Setup (one-time per user)" section
between Step 4 and Step 5 of the cookbook, mirroring the WFP service prereq pattern
(explicit operator action up front, fail-closed-with-recovery-hint at runtime, no
implicit network on the verify path). Three subsections:

1. **Setup procedure**: `nono setup --refresh-trust-root` one-time-per-user invocation;
   `nono setup --check-only` status reporting (`OK` / `STALE` / `NOT INITIALIZED`).
2. **"Verifying Keyless-Signed Artifacts"**: canonical `--issuer` + `--identity`
   examples for GitHub Actions (with the always-further/nono concrete example) and
   GitLab CI; cross-link to the baked-in `trust-policy-keyless-template.json`;
   local-dev keyref guidance.
3. **"Broker.exe Verification at Launch"**: D-32-13 self-trust-anchor explanation;
   fail-mode error text matching Plan 04 verbatim; dev-build install-layout
   substring detector rationale (Pitfall 6 — NOT `#[cfg(debug_assertions)]`).

Cross-references added to "Related docs" footer for both new ADRs and Phase 32
CONTEXT.md.

## Acceptance Criteria

| Criterion | Status |
|-----------|--------|
| `docs/architecture/broker-trust-anchor.md` exists, ≥80 lines, has `## Status: Accepted`, has `## References`, contains `self-trust-anchor` ≥2x, contains `D-32-13` | ✓ (119 lines, 3 self-trust-anchor occurrences) |
| `docs/architecture/sigstore-tuf-cache.md` exists, ≥80 lines, has `## Status: Accepted`, has `## References`, contains `verify-is-offline`, contains `D-32-01` | ✓ (119 lines) |
| ADRs cross-reference each other | ✓ |
| `grep -c ":2173+" 32-CONTEXT.md` returns 0 | ✓ |
| `grep -c ":1246-1438" 32-CONTEXT.md` returns ≥1 | ✓ (3 occurrences) |
| deferred-items.md has Phase 32 v2.4+ entry with trigger, current posture, why deferred, entry criteria, references | ✓ (P32-DEFER-002) |
| Mock-Fulcio/Rekor + broker-mismatch-stub recorded as closures, not carry-forwards | ✓ |
| Cookbook has `nono setup --refresh-trust-root` ≥2x | ✓ (2 occurrences) |
| Cookbook has `--issuer` ≥3x and `--identity` ≥3x | ✓ (5 each) |
| Cookbook has `always-further/nono` ≥1x | ✓ |
| Cookbook has `token.actions.githubusercontent.com` ≥1x | ✓ (2 occurrences) |
| Cookbook has `Authenticode signature does not match` exactly 1x | ✓ |
| Cookbook cross-links broker-trust-anchor, sigstore-tuf-cache, trust-policy-keyless-template | ✓ |
| All commits have DCO sign-off | ✓ |

## Deviations

**Task 2 checkpoint signal:** the plan's `<resume-signal>` block specified that the
human reviewer should type `audit-complete keyed-stays` to proceed. The orchestrator
used `AskUserQuestion` to gather the verdict (Option A / Option B / Audit-blocked)
since this maps cleanly to the three documented choices. The reviewer selected
Option A; the deferred-items.md entry was committed with the human-reviewer-signed-off
note dated 2026-05-10.

**Plan execution mode:** Plan 05 was executed inline by the orchestrator, not via a
spawned `gsd-executor` subagent. Rationale recorded in the frontmatter `decisions:`
block: the orchestrator's session worktree had earlier collided with Plan 32-03's
executor agent ID (both ended up on `worktree-agent-a101355bbf72f9b06`); spawning
another worktree-mode executor risked a similar collision; Plan 05 is documentation-only
with a human-verify checkpoint mid-plan, so inline execution was clearly safer than
re-rolling the dice on worktree allocation. All commits land directly on `main` with
DCO sign-offs and Co-Authored-By Claude lines.

**Original `:2173+` substring grep:** the plan's `<acceptance_criteria>` calls for
`grep -c ":2173+" 32-CONTEXT.md` to return 0, but the plan's own example diff at
the action block retained `:2173+` inside the historical correction note. Reconciled
by rephrasing the historical note to avoid the literal substring while keeping the
correction's traceability ("Original CONTEXT.md cited a line range past 2000 that
pointed into the test module"). Grep returns 0; correction history preserved.

## Pointers

- Two ADRs land the design rationale for the Phase 32 novel decisions (D-32-13
  broker self-trust-anchor; D-32-01 cached TUF root + verify-is-offline invariant).
  Both follow `docs/architecture/audit-bundle-target.md`'s ADR convention.
- `P32-DEFER-002` records the v2.4+ keyless migration audit verdict per D-32-10.
- The cookbook now mirrors the WFP service prereq pattern for Sigstore: explicit
  setup, fail-closed-with-recovery, offline verify path.
- Phase 32 closes for v2.3 milestone purposes; `/gsd-complete-milestone` can run
  once the orchestrator's verifier confirms the must-haves.
