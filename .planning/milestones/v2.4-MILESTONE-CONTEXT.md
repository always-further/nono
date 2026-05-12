---
target_milestone: v2.4
target_milestone_name: (to be locked at /gsd-new-milestone — see scope-themes below)
captured: 2026-05-12
captured_via: /gsd-new-milestone (aborted; v2.3 close pending)
status: scope-preview
---

# v2.4 Milestone Context (scope preview)

**This file was captured during an aborted `/gsd-new-milestone` invocation on 2026-05-12** because the orchestrator detected that v2.3 had open phases (Plans 25-01 + 26-02 execution-pending; Phase 27 REQ-AAH-01 deferred to v2.4 per PROJECT.md) and the user chose to close v2.3 first via `/gsd-complete-milestone`.

When `/gsd-new-milestone` re-runs after v2.3 close, this file's scope-themes section is the captured input for the milestone goals questioning (step 2 of the workflow).

## Scope themes (user-selected)

The user selected three themes (multi-select) at the abort checkpoint:

### Theme 1 — Complete the partial upstream ports

Address Phase 34's 10 NEEDS-FOLLOW-UP-PLAN deferrals as a coherent theme. Per Phase 34 VERIFICATION.md strategic recommendation.

Candidate deferrals + effort estimates (from Phase 34 `deferred-items.md` and the upstream-fork-release-grid quick task):

| Deferral | Effort | Theme |
|---|---|---|
| P34-DEFER-04b-1 | ~1-2 weeks | Full Option C `deprecated_schema` module port (~824 LOC + 210-callsite internal rename + JSON schema fixture restructure + docs migration) |
| P34-DEFER-04b-2 | ~1 week | Upstream `829c341a` profile drafts feature (`nono profile promote`, `--draft` flag, package_status.rs, profile-drafts directory infrastructure) |
| P34-DEFER-06-1 | ~2-3 weeks | yaml_merge wiring trio (blocked by unported `24d8b924` base port ~1761 LOC) |
| P34-DEFER-08a-1 | ~3-5 days | Windows `exec_strategy_windows/` env-filter wiring (deny_vars + allowed_env_vars consumption on Windows path) |
| P34-DEFER-08b-1 | ~1-2 weeks | `b5f0a3ab` deep ExecConfig refactor (11 files / 721 insertions; macos learn + run diagnostics) |
| P34-DEFER-08b-2 | ~3-5 days | `bbdf7b85` escape-quote structured-property pipeline (depends on 08b-1) |
| P34-DEFER-09-1 | ~2-3 days | Linux Landlock profiles-dir pre-creation (from upstream `bdf183e9`) |
| P34-DEFER-09-2 | ~2-3 weeks | Full upstream `wiring.rs` abstraction (idempotent JSON-merge install records) |
| P34-DEFER-01-1 / P34-DEFER-10-1 | ~3-5 days | Windows test-harness hygiene (`query_ext::test_query_path_denied` UNC path flake + policy show/diff Rust Debug leak) |

**Total rough estimate:** ~8-12 weeks of partial-port closure if all are absorbed. Could split into a v2.4 / v2.5 sequence.

### Theme 2 — Execute v2.3 carry-forwards

Close the v2.3 promises that were execution-deferred:

- **Phase 25 Plan 25-01** — RESL Unix backends: Linux cgroup v2 (`memory.max` / `cpu.max` / `pids.max` / `cgroup.kill`) + macOS `setrlimit` (`RLIMIT_AS` / `RLIMIT_NPROC`; CPU-percent fail-closed unsupported on macOS). Removes the four "not enforced" stderr warnings. **Requires Linux/macOS host coverage.**
- **Phase 26 Plan 26-02** — PKGS streaming + auto-pull: REQ-PKGS-01 (port upstream `9ebad89a` streaming refactor) + REQ-PKGS-04 (port upstream `115b5cfa` `load_registry_profile` auto-pull). **Requires Linux/macOS host coverage.**
- **Phase 27 REQ-AAH-01** — Audit-attestation hardening: re-enable 2 `#[ignore]`'d fixture-driven tests. Path B fixture redesign attempt surfaced 3 Windows-host test-harness blockers; resumption path documented in `27-01-SUMMARY.md` requires either Linux/macOS host verification OR `NONO_TEST_HOME` production-code seam.

### Theme 3 — Next upstream sync (UPST4 for v0.53+)

Phase 33 ADR's "per upstream release, lazily-evaluated" cadence rule fires. **Upstream has shipped 3 minor releases since Phase 33's audit cutoff:**

- `v0.52.1` (sha `21bbb82e`) — post-Phase-34-audit minor
- `v0.52.2` (sha `e8bf0148`) — post-Phase-34-audit minor
- `v0.53.0` (sha `c4b25b82`) — post-Phase-34-audit minor (audit HEAD at Phase 33 close was `54f7c32a`, so v0.53.0 = audit-HEAD now)

UPST4 scope: audit + disposition + execution of v0.52.1..v0.53.0 (or a wider range if more lands by milestone start).

## Other deferred items from PROJECT.md (consider for v2.4 inclusion)

From PROJECT.md v2.3 "Out of scope (explicit deferrals to v2.4)":

- ~~Upstream v0.41–v0.43 ingestion~~ — **already covered by Phase 34 (UPST3); REMOVE from v2.4 deferral list when PROJECT.md is updated**
- AIPC G-04 wire-protocol compile-time tightening (cascades into 23 pre-existing tests + child SDK demultiplexer)
- ~~`windows-squash` → `main` merge~~ — **already happened at commit `1ef30c63`; REMOVE from v2.4 deferral list**
- Cross-platform drift QA + Docs pass — bundles with v0.53+ ingestion (Theme 3)
- WR-02 EDR HUMAN-UAT — v3.0-deferred (NOT v2.4)

## Suggested v2.4 phase structure (planner-of-record will refine)

| Phase | Cluster | Scope | Notes |
|---|---|---|---|
| **Phase 35** | UPST3-closure | Plan-level absorption of Theme 1's high-value/low-effort deferrals (08a-1, 09-1, 08b-2 — ~2 weeks total) | Quick wins; keeps the deferral count down |
| **Phase 36** | UPST3-deep-closure | Theme 1's heavy items (04b-1 deprecated_schema, 06-1 yaml_merge base port, 09-2 wiring.rs abstraction) | 4-6 weeks; the load-bearing partial-port closures |
| **Phase 37** | v2.3-carry-forward-linux | Theme 2's Plan 25-01 RESL Unix backends + Plan 26-02 PKGS-01/04 (Linux/macOS host required) | Closes v2.3 promises; needs different host than Windows-only dev environment |
| **Phase 38** | v2.3-carry-forward-aah | Theme 2's Phase 27 REQ-AAH-01 (Windows-host or `NONO_TEST_HOME` seam) | Reopens Phase 27; resumption documented |
| **Phase 39** | UPST4-audit | Theme 3's v0.52.1..v0.53+ audit (DIVERGENCE-LEDGER format) | Mirrors Phase 33 audit shape |
| **Phase 40** | UPST4-sync | Theme 3's UPST4 execution per UPST4-audit dispositions | Mirrors Phase 34 execution shape |

Phase numbering continues from Phase 34 (the current highest); the SDK's `state.milestone-switch` does not reset phase numbers unless `--reset-phase-numbers` flag is passed.

## Decision deferred: theme prioritization

User selected all 3 themes but did not prioritize them. The new-milestone questioning (step 2) should:

1. Confirm all 3 themes are in scope (or de-scope one)
2. Decide phase ordering — Theme 1 first (quick closure of partial ports) vs Theme 3 first (upstream cadence) vs Theme 2 first (v2.3 promises)
3. Decide milestone bound — "all 3 themes" implies a 12-16 week milestone; "ship in 4-6 weeks" implies one theme + start of another

## Reference

- Phase 34 VERIFICATION.md strategic recommendation
- Phase 34 SUMMARY + deferred-items.md
- `.planning/quick/20260512-upstream-fork-release-grid/RESULT.md` — full v0.37→v0.52 mapping
- PROJECT.md § Current Milestone (v2.3 still in-flight as of capture date)

---

**Next step:** Run `/gsd-complete-milestone` to close v2.3 with explicit carry-forward declarations, then re-run `/gsd-new-milestone` to formalize v2.4 with this scope preview as input.
