---
quick_id: 260428-rsu
slug: refresh-stack-onto-upstream-tip
description: Refresh the stack (PRs 725 + 726) onto upstream's new tip before a human reviewer engages
started: 2026-04-28
resumed: 2026-04-29
closed: 2026-05-23
status: closed-via-v2.6-rollout
closure_disposition: feature-flag-equivalent rollout per ROADMAP § Phase 46 SC#1 (D-46-A1); maintainer-response triggers retained per D-46-A3 — see ADR.
adr: .planning/architecture/v2.6-upstream-merge-deferral-ADR.md
deferred_until: maintainer-response on PRs 725/726 (see Outreach posted 2026-04-29)
runbook: 260428-rsu-PLAN.md
---

> **2026-05-23 update (Phase 46 close, D-46-A1/A2/A3/A4):**
> Closed via the SC#1 "feature-flag-equivalent rollout with the gate-state explicitly documented" path. The 504-commit / 77-conflict rebase scope and the maintainer-non-response since 2026-04-29 outreach were not improving; Phase 46 Plan 46-01 lands a new ADR at `.planning/architecture/v2.6-upstream-merge-deferral-ADR.md` capturing alternative paths considered, why feature-flag-equivalent was chosen, the maintainer-response revival trigger set, and the per-phase umbrella PR pattern as the go-forward upstream-contribution mode. PRs 725/726 remain OPEN; the 2026-04-29 outreach remains the canonical comm. Revival on maintainer response only (no fork-side calendar trigger).
>
> The "Re-deferral conditions" section below remains accurate — the new ADR codifies them as the revival trigger set rather than supersedes them.

# Quick Task 260428-rsu — Summary: RE-DEFERRED (awaiting maintainer response)

**Status:** Re-deferred 2026-04-29 after rebase attempt revealed scope beyond runbook assumptions. Outreach posted to upstream maintainer; awaiting direction.

## Timeline

- **2026-04-28** — `/gsd-quick --discuss` surfaced 4 gray areas; decisions locked. Runbook (5 tasks) captured. Initial deferral.
- **2026-04-29** — Trigger #1 fired (PR #785 merged on upstream at 11:19Z). `/gsd-quick resume` invoked. Rebase attempted; aborted; outreach posted.

## Decisions made on 2026-04-28 (still LOCKED unless maintainer response invalidates them)

| Decision | Locked answer |
|---|---|
| Timing vs upstream PRs | Wait for #785 (claude-pack-migration) + #777/#778 (sigstore bumps) to land |
| Phase 22 stack disposition | Hold Phase 22 + 24 work on local `main` until 725+726 merge |
| Rebase shape | Re-squash on upstream/main (preserve 1-commit-per-milestone) |
| Conflict resolution authority | Stop at each conflict; surface to user before resolving |

## Trigger state at 2026-04-29 resume

| Trigger | State |
|---|---|
| #785 (claude-pack-migration) MERGED | ✓ FIRED — 2026-04-29T11:19Z, upstream commit `078e49f2` |
| #777 (sigstore-verify 0.6.4 → 0.6.5) | ✗ CLOSED unmerged — sigstore bump rejected upstream |
| #778 (sigstore-sign 0.6.4 → 0.6.5) | ✗ CLOSED unmerged — companion to #777 |
| Human reviewer engagement on 725/726 | None yet (10 automated reviews on #725, 2 on #726, no human comments) |
| 2026-05-12 soft deadline | Not yet reached |

The "wait-for-#785-and-sigstore" timing decision was structured as OR semantics in CONTEXT.md `<deferred>` block; #785's firing alone is sufficient to authorize execution. The sigstore-bump trigger is now permanently dead (companion v2.3 audit-attestation hardening sweep loses one of its planned unblocks).

## Rebase attempt (2026-04-29) — aborted at conflict checkpoint

Approach: switched from runbook's `git apply --3way --index` (failed atomically due to binary-file index errors — `AGENTS.md.bundle: does not exist in index`) to canonical `git rebase --onto upstream/main 063ebad6 origin/v2.0-pr` for the single squashed commit. Same target outcome, more robust binary handling.

### Drift quantified

- **504 upstream commits** between v2.0-pr's old merge-base (`063ebad6`) and current upstream tip (`34725154`)
- **4 minor releases absorbed:** v0.41 → v0.42 → v0.43 → v0.43.1 → v0.44
- **Notable upstream PRs landed since branch:**
  - **#594** — Consolidated `nono policy` subcommands under `nono profile` (deprecation alias + relocation; killed `policy_cmd.rs`, split into `policy.rs` / `network_policy.rs` / `deprecated_policy.rs`)
  - **#785** — Moved `claude-code` and `codex` builtin profiles into package-registry-pack format
  - Workspace version 0.30.1 → 0.44.0; new default `system-keyring` feature flag

### Conflict scope: 77 files

| Type | Count | Notes |
|---|---|---|
| `UU` content | 49 | Includes all CONTEXT.md watchlist files: `cli.rs`, `Cargo.toml`, `profile/builtin.rs`, `data/policy.json`, `nono-proxy/src/reverse.rs` |
| `AA` add/add | 26 | **16 of these are `crates/nono-cli/src/*_runtime.rs`** — common ancestor `063ebad6` does NOT contain these files; both upstream and v2.0-pr added them independently with different content. Architectural collision, not drift. |
| `DU` delete/modified | 2 | `policy_cmd.rs` and `tests/policy_cmd.rs` upstream-deleted (per #594); v2.0-pr's modifications need remap onto split structure |

### Key finding: AA cluster is parallel-evolution, not simple add/add

Probe via `git ls-tree`:
- `crates/nono-cli/src/command_runtime.rs` does not exist in `063ebad6` (common ancestor)
- Upstream/main adds it as blob `4fb78ea0`
- v2.0-pr adds it as blob `d288f547`

Conclusion: upstream did the same runtime refactor v2.0-pr did, but with different specifics. Each of the 16 runtime files needs architectural review against its upstream counterpart rather than textual merge — beyond the runbook's "drift-only" scope assumption.

### Rebase aborted cleanly

- `git rebase --abort` ran; `v2.0-pr-rebase-260428` staging branch deleted
- `main` HEAD restored to `a9c92200` (Phase 23 work intact)
- Working tree clean (only the same untracked items present at task start)
- No origin pushes occurred — `--force-with-lease` gate never crossed

## Outreach posted 2026-04-29

Comments posted to both PRs requesting maintainer direction:

- **PR #725:** [issuecomment-4345050113](https://github.com/always-further/nono/pull/725#issuecomment-4345050113)
- **PR #726:** [issuecomment-4345050118](https://github.com/always-further/nono/pull/726#issuecomment-4345050118)

The comments offer three paths and ask the maintainer to pick one:

1. Push through the rebase as-is (with maintainer input on architectural conflicts inline)
2. Close 725/726 and reopen as a per-phase PR series against current upstream
3. Different approach the maintainer prefers

## Re-deferral conditions

This task is now blocked on maintainer response. Re-resume when ANY of:

1. **Maintainer comments on #725 or #726 with a directional answer** — execute that direction (rebase, close-and-restage, or alternate)
2. **Maintainer takes a substantive action on either PR** (review submitted, label change, close, etc.) — re-evaluate scope
3. **2026-05-12 soft deadline still applies** — if no maintainer response by then, escalate (consider closing PRs and committing fully to the v2.2-merged-into-main flow)

## What did NOT happen today

- No source-code commits landed (rebase aborted; no force-push)
- Phase 22 + 23 work on local `main` is unchanged (held per locked `phase22_disposition: hold-local-until-merge`)
- `windows-squash` source-of-truth branch is untouched (read-only per locked decision)

## Files produced (cumulative)

- `260428-rsu-CONTEXT.md` — decisions locked 2026-04-28; durable artifact
- `260428-rsu-PLAN.md` — 5-task runbook (Tasks 1–5: rebase v2.0-pr, rebase v2.1-pr, smoke-test, force-push, cleanup)
- `260428-rsu-SUMMARY.md` — this file (re-deferral disposition)

## Watch-list

Run any time to see if a re-deferral trigger has fired:

```bash
gh pr view 725 --repo always-further/nono --json comments,reviews,state
gh pr view 726 --repo always-further/nono --json comments,reviews,state
```
