---
slug: gap-v039-linux-poc-vs-windows-fork-tip
created: 2026-04-29
type: research-only
---

# Quick task: Gap matrix — upstream v0.39.0 (Linux POC) vs fork tip (post-v2.2 Windows-tested)

**Ask:** User is running a POC demo using `nono` v0.39.0 on Linux. They want to know which functional capabilities the **fork's tested Windows-native build** has that the **upstream v0.39 Linux binary** does not, and a short remediation phase scoped against those gaps.

**Scope:**
- Read-only research. No code changes.
- Diff range: `v0.39.0..HEAD` (191 commits in `crates/`).
- Upstream v0.39.0 release date: 2026-04-21 (`6a284447`). Fork HEAD: 2026-04-29 post-v2.2 (`b9963323`).
- Deliverable: this PLAN.md — gap matrix + demo-strategy recommendation + proposed v2.3 remediation phase.

---

## Gap matrix

Three buckets. Each row is a feature cluster, not a commit.

### Bucket A — Cross-platform features in fork tip that v0.39 Linux binary lacks

These land on the user's Linux POC if they switch from upstream-v0.39-binary to a fork-Linux-build.

| Cluster | Capability | Source | Demo-able on fork-Linux? |
|---|---|---|---|
| AUD-01 | `--audit-integrity` hash-chained Merkle-rooted ledger | upstream `4f9552ec` (v0.40); fork `50a03eca`..`a16704e8` | 🟢 Yes |
| AUD-02 | `nono audit verify <id>` cryptographic proof recheck + `--public-key-file` pinning + DSSE bundle verification | upstream `0b1822a9` (v0.40); fork `3544d600` + `2ab53fec` + `cffb43b1` (HG-01-H) | 🟢 Yes |
| AUD-03 | Executable identity (path + SHA-256) recorded to session metadata | upstream `02ee0bd1` / `7b7815f7` (v0.40); fork `71c2643b` | 🟡 Partial — Authenticode discriminant is Windows-only; field omitted on Linux |
| AUD-04 | `nono session cleanup` + `nono audit cleanup` (with `--dry-run` / `--keep` / `--older-than`); legacy `nono prune` hidden alias | upstream v0.40; fork `5d41a71c` + `3da595e3` | 🟢 Yes |
| PROF-01..04 | Profile fields `unsafe_macos_seatbelt_rules`, `packs`, `command_args`, `custom_credentials.oauth2` deserialize on all platforms; `claude-no-keychain` builtin | upstream v0.38–v0.40; fork `d12b6535`..`52d4ee49` | 🟢 Yes |
| POLY-01..03 | Orphan `override_deny` fails closed at profile load; `--rollback`/`--no-audit` clap mutex; `.claude.lock` moved to `allow_file` | upstream `5c301e8d` (v0.39); fork `490a8a5c` | 🟢 Yes |
| PKG-01..04 | `nono pull / remove / update / search / list` flat-shape subcommand tree with signed-artifact verification + Claude-Code hook registration | upstream v0.38; fork `73e1e3b8` (6/8 cherry-picks; streaming follow-up deferred to v2.3) | 🟢 Yes |
| OAUTH-01..03 | `nono-proxy` OAuth2 client-credentials Bearer-token injection; reverse-proxy HTTP upstream loopback-only by default; `--allow-domain` strict-proxy composition | upstream v0.39; fork `5c8df06a` | 🟢 Yes |

### Bucket B — Windows-only features in fork tip with no Linux equivalent

These compile on Linux as cross-platform code, but have no enforcement or are returned as `UnsupportedPlatform`.

| Cluster | Linux behavior | Demo-able on Linux? |
|---|---|---|
| AIPC handle brokering (Socket / Pipe / JobObject / Event / Mutex) | Child-side `request_*` SDK methods compile but immediately return `NonoError::UnsupportedPlatform`; supervisor-side broker dispatch is `#[cfg(target_os = "windows")]` and absent from Linux binaries entirely | 🔴 No |
| WSFG single-file Low-IL mandatory-label grants | Windows-only module; not built on Linux | 🔴 No |
| Job Object resource limits — `--cpu-percent`, `--memory`, `--timeout`, `--max-processes` | Flags accepted; Linux issues a "not enforced on linux" warning at runtime per cap (silent no-op enforcement) | 🟡 Stub — visibly degraded |
| ConPTY interactive shell | Linux uses `/bin/bash` directly; not a fork gap (upstream parity) | n/a |
| ETW-based `nono learn` | No ETW on Linux; not a fork gap | n/a |
| Authenticode exec-identity discriminant (AUD-03 Windows portion) | Field omitted from session metadata silently on Linux | 🟡 Stub — silent omission |
| AUD-05 AIPC ledger emissions | AIPC SDK returns `UnsupportedPlatform` immediately; no ledger records possible | 🔴 No |

### Bucket C — Demo-blockers regardless of binary choice

Features available in fork-Linux source but not meaningfully demonstrable without the Windows-side broker, or known limitations the user will trip over:

- **AIPC client SDK** — child-side `request_*` calls fail at runtime on Linux because there's no Linux supervisor broker to accept the requests. Works on Windows fork; fails on Linux fork.
- **RESL on Linux/macOS** — `--cpu-percent` / `--memory` / `--timeout` / `--max-processes` are silent no-ops with stderr warnings. Already enumerated in v2.3 backlog ("Cross-platform RESL Unix backends — cgroup v2 / rlimit ports of Windows Job Object caps").

---

## Demo-strategy recommendation

**Recommended: (c) Hybrid — fork-Linux-build with managed expectations.**

| Choice | Verdict |
|---|---|
| (a) Switch to fork-Linux-build, demo everything | ❌ Risky — RESL flags surface "not enforced" warnings; AIPC calls visibly fail. Looks unpolished. |
| (b) Stick with upstream v0.39 binary | ❌ Loses 6 months of fork work — no audit-integrity, no `audit verify`, no PKG, no OAuth2. |
| **(c) Fork-Linux-build + scripted demo caveats** | ✅ **Best.** Demo Bucket A as marquee wins; explicitly call out Bucket B/C as "Windows-first" features. |

**Concrete demo script for (c):**
1. **Lead with audit-integrity.** `nono run --audit-integrity bash` → `nono audit show` shows hash-chain. `nono audit verify <id>` recomputes proof. 🟢 Cross-platform. Strong opener.
2. **Show `nono session cleanup`** with `--dry-run` and `--older-than 7d`. 🟢 Cross-platform. Tangible operational improvement over v0.39.
3. **Show profile + policy tightening.** `nono policy show claude-no-kc` and a deliberate orphan-`override_deny` fail-closed example. 🟢 Cross-platform.
4. **Show OAuth2 proxy** with a token-cached upstream call. 🟢 Cross-platform. Differentiating feature vs upstream v0.39.
5. **Skip RESL flags entirely.** If asked, say: *"On Linux, CPU/memory caps land via cgroup v2 in v2.3 (Q3 candidate). Windows ships them today via Job Object."* Converts a 🟡 stub into a roadmap statement.
6. **Skip AIPC entirely.** If asked: *"AIPC handle brokering is Windows-native (Job Objects, Events, Mutexes don't have direct Unix analogs). Unix equivalent via `SCM_RIGHTS` for sockets/pipes is being scoped for v2.3+."*

**If demo must include RESL or AIPC** → fall back to upstream-v0.39 baseline and frame as: *"This POC is on upstream baseline. Fork v2.2 adds audit-integrity, package management, OAuth2 — shown separately to avoid mixing baseline behavior with Windows-only enforcement."*

---

## Proposed v2.3 remediation phase

**Phase shape:** 1 phase, 2 plans. Lightweight scope. Subsumes the existing v2.3 backlog item "Cross-platform RESL Unix backends" and adds an exploratory AIPC-Unix-design plan alongside.

**Phase title (candidate):** `25 — Cross-Platform RESL + AIPC Unix Design`

**Plan 25-01 — Cross-platform RESL Unix backends (3–4 days)**
- Implement Linux RESL via cgroup v2 controllers: `memory.max` (RESL-02), `cpu.max` (RESL-01), pid count via `pids.max` (RESL-04). Wall-clock timeout (RESL-03) stays supervisor-side `Instant` + SIGKILL on the cgroup.
- Implement macOS RESL via `setrlimit` — RLIMIT_AS (RESL-02), RLIMIT_CPU (RESL-03 — caveat: CPU-time vs wall-clock), RLIMIT_NPROC (RESL-04). Document the wall-clock vs CPU-time gap.
- Wire flag→backend dispatch in `crates/nono-cli/src/exec_strategy*.rs`; remove the four "not enforced on linux" warnings.
- Reuse the v2.1 Phase 16 acceptance criteria; add Linux-specific cgroup-v2 + macOS rlimit tests behind `#[cfg(target_os = "linux")]` / `target_os = "macos"`.
- **Subsumes** the v2.3 backlog row from PROJECT.md verbatim.

**Plan 25-02 — AIPC Unix futures design sketch (1–2 days, exploratory)**
- Design doc only — no implementation. Decide which AIPC HandleKinds have a defensible Unix analog and which are inherently Windows-only:
  - **Socket / Pipe** → Unix-domain socket + `SCM_RIGHTS` file-descriptor passing. Plausible.
  - **JobObject** → No direct Unix analog (cgroup is per-tree, not handle-brokerable). Architectural deferral.
  - **Event / Mutex** → No direct Unix analog (Linux `eventfd` and pthread mutexes don't broker the same way). Architectural deferral.
- Output: ADR or design note in `docs/architecture/aipc-unix-futures.md` documenting Decision D-NN: "AIPC HandleKinds 0–2 (File/Socket/Pipe) admit Unix backends; HandleKinds 3–5 (JobObject/Event/Mutex) are Windows-only by design."
- Feed into v2.4+ as a real implementation candidate or close as won't-fix.

**Why short:** This phase has zero protocol changes, no compile-time tightening, and reuses existing test harnesses. The hard part is honest scoping (Plan 25-02), not implementation (Plan 25-01).

**Why this phase, why now:** The Linux POC the user is running today exposes the gap experientially. Plan 25-01 closes the most embarrassing 🟡 stubs (silent RESL no-ops) into real enforcement. Plan 25-02 prevents future Linux-vs-Windows AIPC drift from re-opening the same uncertainty.

---

## What I did NOT do

- No upstream merge / cherry-pick.
- No code changes — this is a research deliverable.
- No changes to ROADMAP.md or PROJECT.md (v2.3 milestone is unscoped; phase scoping belongs in `/gsd-new-milestone v2.3` when the user is ready).
- The existing `Cross-platform RESL Unix backends` row in PROJECT.md § Next Milestone remains as-is and is referenced by Plan 25-01's "subsumes" clause above.

## STATE.md update

Append to "Quick Tasks Completed" table on commit; reference this PLAN.md as the deliverable.

---

*Sources: research agent inventory of `git log v0.39.0..HEAD -- crates/` (191 commits), cross-referenced against `.planning/MILESTONES.md` v2.2 entry, `.planning/PROJECT.md` § Next Milestone v2.3 backlog, and Phase 22/23 SUMMARY files.*
