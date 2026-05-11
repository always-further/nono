---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-10
plan: 10
slug: fp-proxy-tls
cluster_id: C11
type: execute
wave: 3
depends_on: ["34-02", "34-09"]
blocks: []
files_modified:
  - crates/nono-cli/src/audit_ledger.rs
  - crates/nono-cli/src/audit_session.rs
  - crates/nono-cli/src/audit_commands.rs
  - crates/nono-proxy/src/audit.rs
  - crates/nono-proxy/src/server.rs
upstream_tag_range: v0.51.0
upstream_commit_count: 5
disposition: fork-preserve-manual-replay-split
autonomous: false
requirements: [C11, won-t-sync-addendum-C1, won-t-sync-addendum-C3]
tags: [upst3, c11, proxy-tls, audit-context, fork-preserve, manual-replay, d-20, wave-3, phase-close]

produces_artifact:
  - path: .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md
    why: "D-34-A3 won't-sync addendum for C1 (PTY attach/detach polish) and C3 (Unix-socket capability). Co-located with Phase 34 directory rather than mutating the closed Phase 33 DIVERGENCE-LEDGER.md."

must_haves:
  truths:
    - "Commit `9300de9` (structured audit context for network events) cherry-picked or manually replayed onto `main`; the replay composes with Phase 23 REQ-AUD-05's audit ledger surface (audit_ledger.rs / audit_session.rs / audit_commands.rs)"
    - "The `9300de9` fork-side commit body carries the verbatim D-19 6-line trailer block (lowercase 'a' in Upstream-author:); smoke check `git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: 9300de9'` returns exactly 1"
    - "Commits `149abde`, `879562c`, `8db8919`, `dcf2d29` each produce a fork-side documentation-only commit (D-20 manual-replay shape; NO upstream cherry-pick). Commit body documents upstream sha + subject + rationale-for-non-port + fork-only wiring being preserved. Grep patterns: each commit body contains `Read upstream` and `Not ported because`"
    - "The 4 TLS-interception documentation commits do NOT carry an `Upstream-commit:` trailer (they are explicit non-cherry-picks); smoke check `git log --format='%B' HEAD~5..HEAD | grep -v '^#' | grep -c '^Upstream-commit: '` returns exactly 1 (only the 9300de9 replay)"
    - "Windows credential-injection rewrite (Phase 09 + Phase 11) is byte-identical post-plan: pre/post sha256 on `crates/nono-proxy/src/credential.rs` shows ZERO change; Windows-gated arms in `server.rs`/`route.rs`/`oauth2.rs` unchanged"
    - "Phase 22-04 OAuth2 WSAStartup ordering preserved in `crates/nono-proxy/src/server.rs` (pre/post grep equivalence on WSAStartup-relevant initialization)"
    - "D-34-E1 invariant: the single `9300de9` cherry-pick / replay produces ZERO hits in `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows'`. (The 4 documentation commits do not modify files; no D-34-E1 check applies.)"
    - "`.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md` exists at plan close and contains documented won't-sync rows for cluster C1 (PTY attach/detach polish) and cluster C3 (Unix-socket capability), quoting Phase 33 DIVERGENCE-LEDGER.md headline language verbatim with rationale cites for D-11 (cluster C1) and D-19 (cluster C3)"
    - "All 8 D-34-D2 close-gates pass on the Windows host (workspace test + 3-target clippy + fmt + 5-row detached console smoke + wfp_port + learn_windows)"
    - "Phase 23 REQ-AUD-05 audit-ledger integrity tests remain green post-replay: `cargo test -p nono-cli --features windows-tests audit_integrity` exits 0"
    - "Plan 34-10 commits pushed to `origin/main` at plan-close; per-plan PR opened per D-34-D1"
  artifacts:
    - path: "crates/nono-cli/src/audit_ledger.rs"
      provides: "Structured audit-event context shape from upstream `9300de9` composed with Phase 23 REQ-AUD-05 ledger envelope (NetworkAuditContext or equivalent fields per upstream's shape; named per fork's existing AuditEvent struct conventions)"
      grep_pattern: "NetworkAuditContext|network_context|audit_context|destination_host|destination_port"
    - path: "crates/nono-cli/src/audit_session.rs"
      provides: "If `9300de9` extends session-level context, the extension lands here without disturbing Phase 22-05a session-management semantics"
      grep_pattern: "audit_context|network_events"
    - path: "crates/nono-cli/src/audit_commands.rs"
      provides: "If `9300de9` extends `nono audit show` display fields, the display fields land here without regressing Phase 22-05a CLI surface"
      grep_pattern: "show|display"
    - path: "crates/nono-proxy/src/audit.rs"
      provides: "Proxy-side audit emission for structured network-event context (per upstream `9300de9`); does NOT add TLS-interception machinery"
      grep_pattern: "audit_context|network_event"
      grep_negative: "tls_intercept|TlsIntercept"
    - path: "crates/nono-proxy/src/server.rs"
      provides: "Audit-context wiring point only. NO TLS-interception added (D-34-B1 fork-preserve). Windows credential-injection paths byte-identical pre/post (Phase 09 + Phase 11)."
      grep_pattern: "audit"
      grep_negative: "tls_intercept|TlsInterceptor|managed_auth"
    - path: ".planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md"
      provides: "D-34-A3 won't-sync addendum for clusters C1 (PTY) and C3 (Unix-socket); Phase 34 outcome summary co-located with phase directory"
      grep_pattern: "Won.t-sync clusters|C1|C3"
      min_lines: 30
  key_links:
    - from: "Cluster C11 disposition row (Phase 33 DIVERGENCE-LEDGER.md line 234)"
      to: "Plan 34-10 split execution: 1 clean replay (`9300de9`) + 4 read-and-document (`149abde`, `879562c`, `8db8919`, `dcf2d29`)"
      via: "D-34-B1 verbatim instruction: replay audit-context shape only; TLS-interception cherry-pick would delete the fork's Windows credential-injection rewrite"
      pattern: "9300de9|fork-preserve"
    - from: "Fork's Phase 23 REQ-AUD-05 audit ledger surface (commit `263795a9` and successors)"
      to: "Upstream `9300de9` structured network-event context shape"
      via: "compose cleanly — upstream's context fields extend the fork's existing AuditEvent envelope without altering the integrity-protection / merkle / chain-head invariants"
      pattern: "NetworkAuditContext|audit_context|destination_host"
    - from: "Fork's nono-proxy Windows credential-injection rewrite (Phase 09 + Phase 11)"
      to: "Upstream TLS-interception machinery (`tls_intercept` module, managed-auth audit context, git CA trust, AKID leaf cert fix)"
      via: "fork-preserve: documented non-port. Upstream's TLS-interception assumes a UNIX socket trust-store layout that the fork's Windows credential-store path does not match. Cherry-pick would delete fork-only Windows code paths."
      pattern: "credential_injection|inject_credential|managed_auth"
    - from: "Plan 34-10 close (terminal Phase 34 plan per D-34-A3)"
      to: "34-PHASE-OUTCOMES.md won't-sync addendum"
      via: "documents cluster C1 (PTY ConPTY structural divergence per D-11) and cluster C3 (Unix-socket Unix-only per D-19) as explicit non-ports for future-audit traceability"
      pattern: "Won.t-sync clusters|C1|C3"
---

<objective>
Cluster C11 (upstream v0.51.0, 5 in-scope commits — 1 release-tag commit excluded). Disposition: **fork-preserve, split execution per D-34-B1.**

- **Commit `9300de9` (structured audit context for network events) → CLEAN REPLAY.** Phase 23 REQ-AUD-05 already shipped richer Windows AIPC ledger emissions; upstream's structured-context shape composes cleanly with the fork's existing `audit_ledger.rs` / `audit_session.rs` / `audit_commands.rs` envelope. Carries the D-19 6-line trailer.
- **Commits `149abde`, `879562c`, `8db8919`, `dcf2d29` (TLS-interception machinery + git CA trust + AKID leaf-cert fix) → READ AND DOCUMENT ONLY.** Each gets a fork-side documentation-only commit (no upstream cherry-pick). Commit body documents: upstream sha + subject + rationale-for-non-port (the fork's `nono-proxy` was rewritten on `windows-squash` for Windows credential injection; upstream's TLS-interception pattern assumes a UNIX socket trust-store layout incompatible with the fork's Windows credential-store path) + explicit pointer to the fork-only wiring being preserved.

**Why split:** D-34-B1 verbatim: "for the TLS-interception commits (`149abde`, `879562c`, `8db8919`, `dcf2d29`) — read upstream's structure, document the delta as fork-preserve (Windows credential-injection rewrite would be deleted by cherry-pick), and replay only the audit-context shape."

**Phase 34 close-out responsibility (D-34-A3):** Plan 34-10 is the **terminal Phase 34 plan**. It writes `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md` containing the inline won't-sync addendum for clusters C1 (PTY attach/detach polish — fork's ConPTY structurally different per D-11) and C3 (Unix-socket capability — Unix-only by construction, would violate D-19). The PHASE-OUTCOMES.md shape is chosen over a Phase 33 DIVERGENCE-LEDGER.md amendment because (a) Phase 33 is an audit-complete artifact and should not be mutated post-close, and (b) co-locating the outcome summary with the Phase 34 directory aids future-audit traceability.

Purpose: A Windows user running `nono run --audit-integrity ... -- curl https://example.com` post-Plan-34-10 produces an audit-ledger entry whose network-event row carries the upstream-aligned structured context (destination host/port, etc.) while the fork's Windows credential-injection path (Phase 09 + Phase 11) and OAuth2 WSAStartup ordering (Phase 22-04) remain byte-identical. The Phase 34 outcome ledger has explicit closure rows for C1 + C3.

Output: 5 atomic commits on `main` (1 D-19-trailered replay + 4 documentation-only commits), zero changes to Windows credential-injection code paths, and a new `34-PHASE-OUTCOMES.md` artifact closing Phase 34.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@.planning/PROJECT.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-04-OAUTH-PLAN.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05a-AUD-CORE-PLAN.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-PATTERNS.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-CONTEXT.md
@.planning/phases/26-pkg-streaming-followup/26-CONTEXT.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-02-PROXY-NET-PLAN.md
@.planning/templates/upstream-sync-quick.md
@crates/nono-proxy/src/server.rs
@crates/nono-proxy/src/audit.rs
@crates/nono-proxy/src/credential.rs
@crates/nono-cli/src/audit_ledger.rs
@crates/nono-cli/src/audit_session.rs
@crates/nono-cli/src/audit_commands.rs

<interfaces>
**Cluster C11 commit inventory (per Phase 33 DIVERGENCE-LEDGER.md, lines 237–244):**

| Order | SHA (8-char) | Tag | Subject | Categories | Files | Disposition |
|-------|--------------|-----|---------|------------|-------|-------------|
| 1 | `149abde` | v0.51.0 | feat(proxy): add tls interception for l7-bearing connect routes | audit, other, proxy | 21 | **READ-AND-DOCUMENT** (would delete Windows credential-injection rewrite) |
| 2 | `879562c` | v0.51.0 | feat(proxy): enhance audit context for managed auth and harden tls ca dir | other, proxy | 5 | **READ-AND-DOCUMENT** (managed-auth context depends on 149abde) |
| 3 | `8db8919` | v0.51.0 | feat(proxy): extend ca trust to git clients | proxy | 1 | **READ-AND-DOCUMENT** (depends on TLS-interception trust store) |
| 4 | `9300de9` | v0.51.0 | feat(audit): add structured context to network audit events | audit, other, proxy | 12 | **CLEAN REPLAY** (Phase 23 REQ-AUD-05 composes cleanly) |
| 5 | `dcf2d29` | v0.51.0 | fix(tls_intercept): add authority key identifier to leaf certs | proxy | 1 | **READ-AND-DOCUMENT** (fix to TLS-interception leaf-cert generation) |

(Release-tag commit `da60dae` not in scope for replay.)

**Plan dependency rationale:**
- `depends_on: ["34-02", "34-09"]`. **34-02** (cluster C4 — proxy/network hardening) closes BEFORE 34-10 so the proxy surface is at its final post-Wave-2 state when this plan's audit-context replay touches `crates/nono-proxy/src/audit.rs` and `crates/nono-proxy/src/server.rs`. **34-09** (cluster C6 — pack migration manual replay) is the other Wave 3 plan; per D-34-A2 Wave 3 sequences sequentially.
- `blocks: []` — 34-10 is the terminal Phase 34 plan. Phase 34 closes when this plan's close-gate passes and the PR merges.

**D-19 trailer block (verbatim 6-line shape; lowercase 'a' in `Upstream-author:`) — applies ONLY to the `9300de9` replay:**

```
Upstream-commit: 9300de9
Upstream-tag: v0.51.0
Upstream-author: {upstream_author_name} <{upstream_author_email}>
Co-Authored-By: {upstream_author_name} <{upstream_author_email}>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

Resolve `{upstream_author_name}` / `{upstream_author_email}` via `git show -s --format='%an <%ae>' 9300de9` at execute time.

For the 4 documentation-only commits: **NO `Upstream-commit:` trailer** (mirror Plan 34-00 non-cherry-pick commit shape). Only DCO `Signed-off-by:` lines (2 of them, one for full name + one for github handle).

**Fork-divergence catalog cross-check (`.planning/templates/upstream-sync-quick.md`):**
- **`crates/nono-proxy/src/oauth2.rs` (Phase 22-04 OAUTH wiring)** — load-bearing for C11. WSAStartup ordering + token cache + `Zeroizing<String>` token handling must remain byte-identical. Verified in Task 8 close-gate.
- **Windows credential-injection rewrite (`credential.rs` + Windows-gated arms in `server.rs`/`route.rs`)** — the structural reason the 4 TLS commits are read-and-document. Pre/post byte-identical retention verified in Task 8 close-gate.
- **Async-runtime wrapping for `load_production_trusted_root`** — not directly touched by `9300de9` (audit-context shape, not trust-root code); flagged for cross-check during conflict resolution.
- **D-21 Windows-only file globs** — applies to the single `9300de9` replay. The 4 documentation commits modify no files; D-34-E1 invariant is vacuously satisfied for them.

**Phase 23 REQ-AUD-05 audit-ledger composition (the reason `9300de9` clean-replays):**
The fork's `audit_ledger.rs` + `audit_session.rs` + `audit_commands.rs` ship via Phase 22-05a (commit `02ee0bd1` + chain) and Phase 23 (commit `263795a9`). Upstream `9300de9` adds structured-context fields (destination host, destination port, etc.) to the network-event row of the audit envelope. These fields extend the fork's envelope without altering the integrity-protection / merkle / chain-head / signing invariants — composition is additive.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Read C11 source artifacts + resolve per-commit dispositions + capture baselines</name>
  <files>(read-only; git operations only)</files>
  <read_first>
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md (cluster 11 row at lines 231–244; cluster 1 row at lines 60–74; cluster 3 row at lines 91–102 — last two for Task 7 won't-sync addendum content)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md (D-34-A3 won't-sync addendum scope; D-34-B1 C11 split disposition; D-34-D2 close-gates; D-34-E1 invariant)
    - .planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-04-OAUTH-PLAN.md (proxy-half shape analog)
    - .planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05a-AUD-CORE-PLAN.md (audit-half shape analog; Phase 23 REQ-AUD-05 lineage)
    - .planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-CONTEXT.md § D-20 (manual-port shape)
    - .planning/phases/26-pkg-streaming-followup/26-CONTEXT.md (most-recent D-20 manual-replay precedent)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-02-PROXY-NET-PLAN.md (sibling Wave 2 proxy plan; closes before this one)
    - .planning/templates/upstream-sync-quick.md § Fork-divergence catalog (OAuth2/WSAStartup/credential-cache entries load-bearing)
    - crates/nono-proxy/src/audit.rs (current audit emission shape on the proxy side)
    - crates/nono-proxy/src/server.rs (current WSAStartup ordering + credential-injection seams)
    - crates/nono-proxy/src/credential.rs (Windows credential-injection rewrite — must remain byte-identical)
    - crates/nono-cli/src/audit_ledger.rs (Phase 22-05a AuditEvent shape)
    - crates/nono-cli/src/audit_session.rs (session-management surface)
    - crates/nono-cli/src/audit_commands.rs (`nono audit show` display)
  </read_first>
  <action>
    1. Read the artifacts listed in `<read_first>`. Confirm the 5-commit C11 inventory against DIVERGENCE-LEDGER.md (1 replay + 4 read-and-document).
    2. `git fetch upstream --tags`. Verify all 5 C11 shas reachable:
       ```bash
       for sha in 9300de9 149abde 879562c 8db8919 dcf2d29; do
         git cat-file -e ${sha}^{commit} || { echo "MISSING: $sha"; exit 1; }
       done
       ```
    3. For each of the 5 commits, capture upstream author + email + full sha:
       ```bash
       for sha in 9300de9 149abde 879562c 8db8919 dcf2d29; do
         echo "=== $sha ==="
         git show -s --format='full_sha=%H subject=%s author=%an email=%ae' $sha
       done > /tmp/34-10-upstream-authors.txt
       ```
       Values feed the commit bodies in Tasks 2–6.
    4. Capture Plan 34-10 pre-state baselines (post-34-09 close):
       ```bash
       PRE_HEAD=$(git rev-parse HEAD)
       echo "PRE_HEAD=$PRE_HEAD" > /tmp/34-10-baseline.txt

       # Windows credential-injection byte-identity baseline (must remain unchanged post-plan):
       git log -1 --format='%H' -- crates/nono-proxy/src/credential.rs >> /tmp/34-10-baseline.txt
       sha256sum crates/nono-proxy/src/credential.rs >> /tmp/34-10-baseline.txt

       # WSAStartup ordering baseline (Phase 22-04 OAUTH; preserved via 34-02 already, re-baseline here):
       grep -n -A 2 'WSAStartup\|wsa_startup\|nono-proxy.*windows' crates/nono-proxy/src/server.rs >> /tmp/34-10-baseline.txt 2>/dev/null || true

       # Windows-only file invariant baseline (must remain unchanged post-plan):
       git log -1 --format='%H' -- crates/nono-cli/src/exec_strategy_windows/ >> /tmp/34-10-baseline.txt
       ```
    5. Verify Phase 34 plans 34-02 (C4) and 34-09 (C6) are already closed and pushed to `origin/main`:
       ```bash
       git fetch origin
       test "$(git log origin/main..main --oneline | wc -l)" = "0"  # local main == origin/main
       test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-02-SUMMARY.md
       test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-09-SUMMARY.md
       ```
    6. Record per-commit disposition decisions in `/tmp/34-10-disposition.txt`:
       - `9300de9` -> CLEAN REPLAY (composes with `audit_ledger.rs` Phase 22-05a + Phase 23 REQ-AUD-05 surface)
       - `149abde`, `879562c`, `8db8919`, `dcf2d29` -> READ-AND-DOCUMENT (cherry-pick would delete Windows credential-injection rewrite)
    7. `cargo build --workspace` (baseline green).
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; for sha in 9300de9 149abde 879562c 8db8919 dcf2d29; do git cat-file -e ${sha}^{commit} || exit 1; done &amp;&amp; test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-02-SUMMARY.md &amp;&amp; test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-09-SUMMARY.md &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - All 5 C11 shas reachable from upstream remote.
    - `/tmp/34-10-upstream-authors.txt` records author + email for all 5 commits.
    - `/tmp/34-10-baseline.txt` records pre-plan `crates/nono-proxy/src/credential.rs` sha256 + WSAStartup ordering grep + last-touched-sha for `exec_strategy_windows/`.
    - Per-commit disposition rationale recorded in `/tmp/34-10-disposition.txt`.
    - Plans 34-02 + 34-09 closed (SUMMARY files exist; origin/main == local main).
    - `cargo build --workspace` exits 0 (baseline build green).
  </acceptance_criteria>
  <done>
    Pre-state captured; 5-commit disposition split confirmed; ready for replay + document chain.
  </done>
</task>

<task type="auto">
  <name>Task 2: Clean replay — `9300de9` (structured audit context for network events) with D-19 trailer</name>
  <files>
    crates/nono-cli/src/audit_ledger.rs
    crates/nono-cli/src/audit_session.rs
    crates/nono-cli/src/audit_commands.rs
    crates/nono-proxy/src/audit.rs
    crates/nono-proxy/src/server.rs
  </files>
  <read_first>
    - `git show 9300de9 --stat` (12 files; audit/other/proxy)
    - `git show 9300de9 -- crates/nono-cli/src/` (audit-cli portion of upstream diff)
    - `git show 9300de9 -- crates/nono-proxy/src/` (proxy-side network-event emitter portion of upstream diff)
    - crates/nono-cli/src/audit_ledger.rs § current `AuditEvent` shape (Phase 22-05a + Phase 23 REQ-AUD-05 surface — what `9300de9` extends)
    - crates/nono-proxy/src/audit.rs § current network-event emission shape
    - .planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-CONTEXT.md § D-20 manual-port shape (fallback if cherry-pick conflicts on fork-only audit-ledger surface)
    - .planning/templates/upstream-sync-quick.md § D-19 cherry-pick trailer block (verbatim 6-line shape)
  </read_first>
  <action>
    Attempt clean cherry-pick first. If conflicts on fork-only audit-ledger surface (likely, given Phase 22-05a / Phase 23 REQ-AUD-05 divergence), fall back to D-20 manual-replay shape — same outcome, same trailer.

    **Step 1: Try clean cherry-pick.**
    ```bash
    git cherry-pick 9300de9
    ```

    **Step 2a: If cherry-pick succeeds cleanly:**
    - `cargo build --workspace` (must succeed; if not, see Step 2b).
    - Verify D-34-E1 invariant: `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns 0.
    - Verify Windows credential-injection retention: `sha256sum crates/nono-proxy/src/credential.rs` matches baseline in `/tmp/34-10-baseline.txt`.
    - Verify WSAStartup ordering preserved: `grep -n -A 2 'WSAStartup\|wsa_startup\|nono-proxy.*windows' crates/nono-proxy/src/server.rs` matches baseline.
    - Skip to Step 3.

    **Step 2b: If cherry-pick conflicts on fork-only audit-ledger surface (expected; Phase 22-05a / Phase 23 REQ-AUD-05 divergence):**
    - Abort: `git cherry-pick --abort`.
    - Read upstream's diff to extract the audit-context structural shape:
      ```bash
      git show 9300de9 -- crates/nono-cli/src/ | head -300
      git show 9300de9 -- crates/nono-proxy/src/ | head -200
      ```
    - Hand-edit the fork's `audit_ledger.rs` / `audit_session.rs` / `audit_commands.rs` to absorb the structural shape (destination host/port fields on the network-event row, etc.) without touching the integrity-protection / merkle / chain-head / signing invariants that Phase 22-05a established. Hand-edit `crates/nono-proxy/src/audit.rs` to emit the new fields at the proxy boundary.
    - `cargo build --workspace` (must succeed).
    - `cargo test -p nono-cli --features windows-tests audit_integrity` (must remain green — fork's Phase 23 REQ-AUD-05 audit-ledger integrity tests must not regress).
    - Stage the changes: `git add crates/nono-cli/src/audit_ledger.rs crates/nono-cli/src/audit_session.rs crates/nono-cli/src/audit_commands.rs crates/nono-proxy/src/audit.rs crates/nono-proxy/src/server.rs`.

    **Step 3: Amend (or write, if D-20 replay) the commit message with the D-19 trailer block.**

    Resolve upstream author + email from `/tmp/34-10-upstream-authors.txt`:
    ```bash
    UPSTREAM_AUTHOR=$(grep '^=== 9300de9 ===' -A 1 /tmp/34-10-upstream-authors.txt | tail -1 | sed -E 's/.*author=([^ ]+ [^ ]*)[[:space:]]*email=([^ ]+).*/\1 <\2>/')
    ```

    Then:
    ```bash
    git commit --amend -m "$(cat <<EOF
    feat(audit): add structured context to network audit events

    [If D-20 replay was used, include here: "Replayed structurally against the fork's
    Phase 23 REQ-AUD-05 audit ledger envelope (audit_ledger.rs / audit_session.rs /
    audit_commands.rs). Direct cherry-pick was infeasible because the fork's
    AuditEvent shape (post-Phase 22-05a commit 02ee0bd1 + Phase 23 commit 263795a9)
    extends the upstream envelope with merkle/chain-head/signing fields that
    upstream's 9300de9 emitter is unaware of. Replayed fields: <list>. No
    behavioral divergence vs upstream's network-event context contract.
    Per D-20 (manual port for heavily-diverged files; Phase 22 D-19 lineage)."]

    Upstream-commit: 9300de9
    Upstream-tag: v0.51.0
    Upstream-author: ${UPSTREAM_AUTHOR}
    Co-Authored-By: ${UPSTREAM_AUTHOR}
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Step 4: Per-commit verification.**
    ```bash
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    git log -1 --format='%B' | grep -c '^Upstream-commit: 9300de9'   # Expected: 1
    git log -1 --format='%B' | grep -c '^Upstream-tag: v0.51.0'      # Expected: 1
    git log -1 --format='%B' | grep -c '^Upstream-author: '          # Expected: 1 (lowercase 'a')
    git log -1 --format='%B' | grep -c '^Co-Authored-By: '           # Expected: 1
    git log -1 --format='%B' | grep -c '^Signed-off-by: '            # Expected: 2

    # Windows credential-injection byte-identical:
    diff <(sha256sum crates/nono-proxy/src/credential.rs) <(grep credential.rs /tmp/34-10-baseline.txt)

    # Phase 23 REQ-AUD-05 audit-ledger integrity tests green:
    cargo test -p nono-cli --features windows-tests audit_integrity
    ```
  </action>
  <verify>
    <automated>test "$(git log -1 --format='%B' | grep -c '^Upstream-commit: 9300de9')" = "1" &amp;&amp; test "$(git diff --stat HEAD~1 HEAD -- crates/ | grep -cE '_windows|exec_strategy_windows')" = "0" &amp;&amp; cargo build --workspace &amp;&amp; cargo test -p nono-cli --features windows-tests audit_integrity</automated>
  </verify>
  <acceptance_criteria>
    - HEAD commit carries D-19 trailer with `Upstream-commit: 9300de9` (lowercase 'a' in `Upstream-author:`); 2 `Signed-off-by:` lines.
    - D-34-E1 invariant: zero hits on `*_windows.rs` or `exec_strategy_windows/`.
    - `crates/nono-proxy/src/credential.rs` sha256 unchanged from baseline (Windows credential-injection retained).
    - `cargo build --workspace` exits 0.
    - `cargo test -p nono-cli --features windows-tests audit_integrity` exits 0 (Phase 23 REQ-AUD-05 integrity tests green).
  </acceptance_criteria>
  <done>
    Audit-context replay landed; Windows credential-injection byte-identical; D-19 trailer carried; audit-integrity tests green.
  </done>
</task>

<task type="auto">
  <name>Task 3: Documentation-only commit — `149abde` (TLS interception for L7 CONNECT routes) — D-20 read-and-document</name>
  <files>(no file modifications; commit-body only via `git commit --allow-empty`)</files>
  <read_first>
    - `git show 149abde --stat` (21 files; audit/other/proxy)
    - `git show 149abde -- crates/nono-proxy/` (upstream's TLS-interception structural shape)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md § Cluster 11 row (verbatim rationale to quote)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-B1
    - crates/nono-proxy/src/credential.rs (fork-only Windows credential-injection — what cherry-pick would delete)
    - /tmp/34-10-upstream-authors.txt (upstream author + email for `149abde`)
  </read_first>
  <action>
    Resolve upstream metadata + create the documentation-only commit (NO file modifications; `--allow-empty`).

    Substitution variables:
    ```bash
    SHA_FULL=$(grep '^=== 149abde ===' -A 1 /tmp/34-10-upstream-authors.txt | tail -1 | sed -E 's/.*full_sha=([^ ]+).*/\1/')
    SUBJECT=$(git show -s --format='%s' 149abde)
    ```

    Commit body (NO `Upstream-commit:` trailer — explicit non-cherry-pick):
    ```
    docs(34-10): document C11 TLS-interception read-and-document disposition (149abde)

    Read upstream <SHA_FULL> ("<SUBJECT>"), tagged v0.51.0.

    Not ported because the fork's nono-proxy interception path was rewritten on
    windows-squash for Windows credential injection (Phase 09 + Phase 11). Upstream's
    tls-interception pattern assumes a UNIX socket trust-store layout that the fork's
    Windows credential-store path does not match. A direct cherry-pick would delete
    fork-only Windows credential-injection code paths in:
      - crates/nono-proxy/src/credential.rs (Windows-gated credential injection)
      - crates/nono-proxy/src/server.rs (Windows-only WSAStartup ordering, Phase 22-04)
      - crates/nono-proxy/src/route.rs and crates/nono-proxy/src/connect.rs
        (Windows-gated CONNECT path wiring around credential injection)

    Per D-34-B1 (Phase 34 CONTEXT.md): TLS-interception commits are read-and-document
    only; the audit-context shape from 9300de9 is the only C11 surface replayed
    (see preceding commit in this plan).

    Per D-20 (manual port for heavily-diverged files; Phase 22 D-19 lineage; Phase 26
    Plan 26-01 PKGS-02 precedent for the same fork-preserve disposition class).

    Phase 33 DIVERGENCE-LEDGER.md cluster 11 row records the disposition rationale:
      "Cherry-picking would merge a 21-file proxy-side change into crates/nono-proxy/
       — but the fork's nono-proxy interception path was rewritten on windows-squash
       for Windows credential injection (Phase 09 + Phase 11) and the upstream
       tls-interception pattern assumes a UNIX socket trust-store layout that the
       fork's Windows credential-store path does not match."

    Future re-evaluation trigger: if upstream's tls-interception module is
    restructured to support pluggable trust-store backends, re-audit this disposition
    in a future UPST phase.

    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    ```

    Create the commit:
    ```bash
    git commit --allow-empty -m "$(cat <<EOF
    [body above, with ${SHA_FULL} and ${SUBJECT} substituted]
    EOF
    )"
    ```

    Verify:
    ```bash
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: ')" = "0"
    test "$(git log -1 --format='%B' | grep -c 'Read upstream')" -ge "1"
    test "$(git log -1 --format='%B' | grep -c 'Not ported because')" -ge "1"
    test "$(git log -1 --format='%B' | grep -c '149abde')" -ge "1"
    test "$(git diff --stat HEAD~1 HEAD | wc -l)" = "0"
    test "$(git log -1 --format='%B' | grep -c '^Signed-off-by: ')" = "2"
    ```
  </action>
  <verify>
    <automated>test "$(git log -1 --format='%B' | grep -c 'Read upstream')" -ge "1" &amp;&amp; test "$(git log -1 --format='%B' | grep -c 'Not ported because')" -ge "1" &amp;&amp; test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: ')" = "0" &amp;&amp; test "$(git diff --stat HEAD~1 HEAD | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Empty commit on HEAD (zero file modifications; `git diff --stat HEAD~1 HEAD` returns empty).
    - Commit body contains required documentation patterns: `Read upstream`, `Not ported because`, the full sha for `149abde`.
    - Commit body does NOT carry an `Upstream-commit:` trailer.
    - 2 DCO `Signed-off-by:` lines present.
  </acceptance_criteria>
  <done>
    `149abde` documented as fork-preserve non-port.
  </done>
</task>

<task type="auto">
  <name>Task 4: Documentation-only commit — `879562c` (managed-auth audit context + tls CA dir hardening) — D-20 read-and-document</name>
  <files>(no file modifications; commit-body only via `git commit --allow-empty`)</files>
  <read_first>
    - `git show 879562c --stat` (5 files; other/proxy)
    - `git show 879562c -- crates/nono-proxy/` (managed-auth audit context extension; bundled with TLS-interception from `149abde`)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md § Cluster 11 row
    - /tmp/34-10-upstream-authors.txt
  </read_first>
  <action>
    Mirror Task 3's shape. Substitution variables:
    ```bash
    SHA_FULL=$(grep '^=== 879562c ===' -A 1 /tmp/34-10-upstream-authors.txt | tail -1 | sed -E 's/.*full_sha=([^ ]+).*/\1/')
    SUBJECT=$(git show -s --format='%s' 879562c)
    ```

    Commit body:
    ```
    docs(34-10): document C11 TLS-interception read-and-document disposition (879562c)

    Read upstream <SHA_FULL> ("<SUBJECT>"), tagged v0.51.0.

    Not ported because the managed-auth audit-context extension and the tls CA dir
    hardening introduced here both compose against the tls-interception machinery
    added in 149abde (see preceding commit in this plan). Cherry-picking 879562c
    in isolation would either:
      - require the 149abde tls-interception scaffolding (which D-34-B1 explicitly
        marks fork-preserve), or
      - silently disable the managed-auth audit-context path, producing a
        partial-replay surface that diverges from upstream contract without
        ledger-visible justification.

    The audit-context shape that DOES land in Plan 34-10 is the structured
    network-event context from 9300de9 (replayed against the fork's Phase 23
    REQ-AUD-05 audit ledger envelope; see first commit in this plan). 879562c's
    managed-auth audit-context is a strict superset that requires the tls-intercept
    scaffolding to emit; it cannot be replayed independently.

    Per D-34-B1 (Phase 34 CONTEXT.md) and D-20 (manual port for heavily-diverged
    files; Phase 22 D-19 lineage).

    Future re-evaluation trigger: re-audit alongside any future re-evaluation of
    149abde tls-interception in a subsequent UPST phase.

    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    ```

    Create commit via `git commit --allow-empty -m "..."` (substitute `${SHA_FULL}` + `${SUBJECT}`).

    Verify (mirrors Task 3):
    ```bash
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: ')" = "0"
    test "$(git log -1 --format='%B' | grep -c 'Read upstream')" -ge "1"
    test "$(git log -1 --format='%B' | grep -c 'Not ported because')" -ge "1"
    test "$(git log -1 --format='%B' | grep -c '879562c')" -ge "1"
    test "$(git diff --stat HEAD~1 HEAD | wc -l)" = "0"
    ```
  </action>
  <verify>
    <automated>test "$(git log -1 --format='%B' | grep -c 'Read upstream')" -ge "1" &amp;&amp; test "$(git log -1 --format='%B' | grep -c 'Not ported because')" -ge "1" &amp;&amp; test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: ')" = "0" &amp;&amp; test "$(git diff --stat HEAD~1 HEAD | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Empty commit on HEAD (zero file modifications).
    - Commit body contains: `Read upstream`, `Not ported because`, full sha for `879562c`.
    - NO `Upstream-commit:` trailer.
    - 2 DCO `Signed-off-by:` lines.
  </acceptance_criteria>
  <done>
    `879562c` documented as fork-preserve non-port.
  </done>
</task>

<task type="auto">
  <name>Task 5: Documentation-only commit — `8db8919` (extend CA trust to git clients) — D-20 read-and-document</name>
  <files>(no file modifications; commit-body only via `git commit --allow-empty`)</files>
  <read_first>
    - `git show 8db8919 --stat` (1 file; proxy category)
    - `git show 8db8919` (one-file change; extends CA trust to git clients on top of the tls-interception trust store)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md § Cluster 11 row
    - /tmp/34-10-upstream-authors.txt
  </read_first>
  <action>
    Mirror Task 3's shape. Substitution variables:
    ```bash
    SHA_FULL=$(grep '^=== 8db8919 ===' -A 1 /tmp/34-10-upstream-authors.txt | tail -1 | sed -E 's/.*full_sha=([^ ]+).*/\1/')
    SUBJECT=$(git show -s --format='%s' 8db8919)
    ```

    Commit body:
    ```
    docs(34-10): document C11 TLS-interception read-and-document disposition (8db8919)

    Read upstream <SHA_FULL> ("<SUBJECT>"), tagged v0.51.0.

    Not ported because extending CA trust to git clients depends on the
    tls-interception trust-store machinery added in 149abde (see commit two before
    this in the plan). Without the upstream tls_intercept CA dir from 149abde +
    879562c, there is no fork-side trust-store surface for this commit to compose
    against.

    The fork's git-client CA-trust path on Windows flows through Windows Credential
    Manager / Windows trust store (Phase 09 + Phase 11 credential-injection
    rewrite). A direct cherry-pick would either compile-fail (referencing the
    absent tls_intercept module) or silently no-op (if the cherry-pick edits an
    abstraction the fork no longer has).

    Per D-34-B1 (Phase 34 CONTEXT.md) and D-20 (manual port for heavily-diverged
    files; Phase 22 D-19 lineage).

    Future re-evaluation trigger: re-audit alongside future re-evaluation of
    149abde tls-interception.

    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    ```

    Create commit via `git commit --allow-empty -m "..."`.

    Verify (mirrors Task 3):
    ```bash
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: ')" = "0"
    test "$(git log -1 --format='%B' | grep -c 'Read upstream')" -ge "1"
    test "$(git log -1 --format='%B' | grep -c 'Not ported because')" -ge "1"
    test "$(git log -1 --format='%B' | grep -c '8db8919')" -ge "1"
    test "$(git diff --stat HEAD~1 HEAD | wc -l)" = "0"
    ```
  </action>
  <verify>
    <automated>test "$(git log -1 --format='%B' | grep -c 'Read upstream')" -ge "1" &amp;&amp; test "$(git log -1 --format='%B' | grep -c 'Not ported because')" -ge "1" &amp;&amp; test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: ')" = "0" &amp;&amp; test "$(git diff --stat HEAD~1 HEAD | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Empty commit on HEAD.
    - Commit body contains: `Read upstream`, `Not ported because`, full sha for `8db8919`.
    - NO `Upstream-commit:` trailer.
    - 2 DCO `Signed-off-by:` lines.
  </acceptance_criteria>
  <done>
    `8db8919` documented as fork-preserve non-port.
  </done>
</task>

<task type="auto">
  <name>Task 6: Documentation-only commit — `dcf2d29` (AKID on tls_intercept leaf certs) — D-20 read-and-document</name>
  <files>(no file modifications; commit-body only via `git commit --allow-empty`)</files>
  <read_first>
    - `git show dcf2d29 --stat` (1 file; proxy category)
    - `git show dcf2d29` (AKID extension fix on tls_intercept leaf certificate generation)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md § Cluster 11 row
    - /tmp/34-10-upstream-authors.txt
  </read_first>
  <action>
    Mirror Task 3's shape. Substitution variables:
    ```bash
    SHA_FULL=$(grep '^=== dcf2d29 ===' -A 1 /tmp/34-10-upstream-authors.txt | tail -1 | sed -E 's/.*full_sha=([^ ]+).*/\1/')
    SUBJECT=$(git show -s --format='%s' dcf2d29)
    ```

    Commit body:
    ```
    docs(34-10): document C11 TLS-interception read-and-document disposition (dcf2d29)

    Read upstream <SHA_FULL> ("<SUBJECT>"), tagged v0.51.0.

    Not ported because the Authority Key Identifier (AKID) X.509 extension fix
    targets leaf certificates generated by the tls_intercept module from 149abde
    (see first documentation commit in this plan). Without 149abde landing in the
    fork, there is no leaf-cert generation surface for this fix to apply to.

    The fork does not synthesize leaf certificates at runtime; outbound TLS on the
    fork's nono-proxy passthrough path uses upstream server certificates verified
    through the fork's Windows credential-injection / Windows trust-store path
    (Phase 09 + Phase 11).

    Per D-34-B1 (Phase 34 CONTEXT.md) and D-20 (manual port for heavily-diverged
    files; Phase 22 D-19 lineage).

    Future re-evaluation trigger: re-audit alongside future re-evaluation of
    149abde tls-interception.

    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    ```

    Create commit via `git commit --allow-empty -m "..."`.

    Verify (mirrors Task 3):
    ```bash
    test "$(git log -1 --format='%B' | grep -v '^#' | grep -c '^Upstream-commit: ')" = "0"
    test "$(git log -1 --format='%B' | grep -c 'Read upstream')" -ge "1"
    test "$(git log -1 --format='%B' | grep -c 'Not ported because')" -ge "1"
    test "$(git log -1 --format='%B' | grep -c 'dcf2d29')" -ge "1"
    test "$(git diff --stat HEAD~1 HEAD | wc -l)" = "0"
    ```

    **Cumulative plan-range smoke check (after Task 6 completes):**
    ```bash
    # Total commits in plan range = 5 (1 replay + 4 documentation):
    test "$(git log --oneline HEAD~5..HEAD | wc -l)" = "5"

    # Exactly ONE Upstream-commit: trailer in the 5-commit plan range:
    test "$(git log --format='%B' HEAD~5..HEAD | grep -v '^#' | grep -c '^Upstream-commit: ')" = "1"
    test "$(git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: 9300de9')" = "1"

    # All 5 commits carry DCO Signed-off-by lines (2 per commit = 10 total):
    test "$(git log --format='%B' HEAD~5..HEAD | grep -c '^Signed-off-by: ')" = "10"
    ```
  </action>
  <verify>
    <automated>test "$(git log -1 --format='%B' | grep -c 'Read upstream')" -ge "1" &amp;&amp; test "$(git log -1 --format='%B' | grep -c 'Not ported because')" -ge "1" &amp;&amp; test "$(git log --format='%B' HEAD~5..HEAD | grep -v '^#' | grep -c '^Upstream-commit: ')" = "1" &amp;&amp; test "$(git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: 9300de9')" = "1"</automated>
  </verify>
  <acceptance_criteria>
    - Empty commit on HEAD.
    - Commit body contains: `Read upstream`, `Not ported because`, full sha for `dcf2d29`.
    - NO `Upstream-commit:` trailer.
    - Cumulative plan range (HEAD~5..HEAD): exactly 1 `Upstream-commit:` trailer (the `9300de9` replay) and 10 `Signed-off-by:` lines (2 per commit × 5 commits).
  </acceptance_criteria>
  <done>
    `dcf2d29` documented as fork-preserve non-port; 5-commit plan range complete.
  </done>
</task>

<task type="auto">
  <name>Task 7: Write 34-PHASE-OUTCOMES.md — D-34-A3 won't-sync addendum for C1 (PTY) + C3 (Unix-socket)</name>
  <files>.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md</files>
  <read_first>
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md lines 60–74 (cluster 1 PTY row — verbatim disposition rationale to cite)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md lines 91–102 (cluster 3 Unix-socket row — verbatim disposition rationale to cite)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A3 (won't-sync addendum scope: "no code change, no separate plan; future audits can see they were considered and rejected with rationale")
    - .planning/phases/24-parity-drift-prevention/24-CONTEXT.md § D-11 (cited as cluster C1 rationale: `*_windows.rs` + `exec_strategy_windows/` filter excludes the fork's ConPTY path from drift-tool walk)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-19 / D-34-E2 (cited as cluster C3 rationale: atomic commit-per-semantic-change requires NO library mutation that exposes a no-op enum variant on the Windows backend)
  </read_first>
  <action>
    Create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md`. The file is a Phase 34 outcome summary co-located with the phase directory (chosen over a Phase 33 DIVERGENCE-LEDGER.md amendment to avoid mutating an audit-complete artifact).

    Required structure (markdown):

    ```markdown
    # Phase 34 Outcomes

    **Phase:** 34-upst3-upstream-v0-41-v0-52-sync-execution
    **Date closed:** <YYYY-MM-DD when Plan 34-10 closes>
    **Upstream range absorbed:** v0.41.0..v0.52.0
    **Cluster disposition summary (from Phase 33 DIVERGENCE-LEDGER.md):**
    - 8 `will-sync` clusters: C2, C4, C5, C7, C8, C9, C10, C12 — landed via Plans 34-01..34-08 + 34-04 (cherry-pick chains with D-19 trailers)
    - 2 `fork-preserve` clusters: C6 (Plan 34-09, pack migration manual replay), C11 (Plan 34-10, proxy TLS interception + audit-context split replay)
    - 2 `won't-sync` clusters: C1, C3 (documented below per D-34-A3)

    ## Won't-sync clusters

    Per D-34-A3 (Phase 34 CONTEXT.md): "Won't-sync clusters documented as one inline
    ledger update (no dedicated plan). Clusters C1 (PTY attach/detach) and C3
    (Unix-socket capability) get explicit `won't-sync` rows in Phase 34's plan-close
    ledger update so future audits can see they were considered and rejected with
    rationale. No code change, no separate plan."

    ### C1 — PTY attach/detach polish (v0.41.0)

    **Disposition:** won't-sync
    **Commits in scope (per Phase 33 DIVERGENCE-LEDGER.md):**
    - `2ac3409` feat(pty): enhance detach notice and terminal cleanup
    - `95f2218` fix(pty-proxy): ensure full scrollback on reattach for normal screen
    - `d0fa303` feat(pty): preserve outer terminal scrollback on attach
    - `e3fdcb9` fix(cli): improve attach/detach scrollback and alt-screen
    - `e8c848f` Update crates/nono-cli/src/pty_proxy.rs
    - `fef06f3` feat(pty-proxy): scroll viewport to native scrollback on detach
    - `be05217` fix(signals): prevent signal swallowing

    **Rationale (verbatim from Phase 33 DIVERGENCE-LEDGER.md cluster 1 row):**

    > Upstream changes touch `crates/nono-cli/src/pty_proxy.rs` (cross-platform PTY
    > proxy used on Linux/macOS attach paths); the fork's Windows attach path lives
    > in `pty_proxy_windows.rs` (D-11 excluded; ConPTY-based, structurally different
    > from upstream's portable_pty primitives). The Unix-side scrollback/alt-screen
    > behavior is consumed only by macOS attach in the fork (Linux is a POC); the
    > fork's own Phase 17 live-stream attach work (v2.1) already satisfied the
    > user-visible scrollback requirement on the supported Windows path. Cherry-
    > picking would add Unix attach polish that does not flow into Windows ConPTY
    > behavior.

    **Decision rationale cites:**
    - **D-11 (Phase 24 CONTEXT.md):** `*_windows.rs` + `exec_strategy_windows/` are
      drift-tool filtered. The fork's `pty_proxy_windows.rs` (ConPTY attach path)
      is structurally distinct from upstream's `pty_proxy.rs` (portable_pty
      primitives). Upstream's scrollback polish is in cross-platform code paths
      that the fork's Windows attach does not traverse.
    - **Phase 17 (v2.1) live-stream attach** already satisfied the user-visible
      scrollback requirement on Windows. No outstanding gap for upstream's polish
      to close.

    **Future re-evaluation trigger:** if the fork ever unifies its Windows attach
    path with a portable_pty-equivalent abstraction, re-audit this disposition
    against the then-current upstream pty_proxy.rs shape.

    ### C3 — Unix-socket capability (v0.42.0)

    **Disposition:** won't-sync
    **Commits in scope (per Phase 33 DIVERGENCE-LEDGER.md):**
    - `85708ca` feat(cli): add --allow-unix-socket flag family + profile schema
    - `a9a8b6c` feat(capability): add UnixSocketCapability and UnixSocketMode
    - `1d789aa` fix(supervisor(linux)): allow pathname af_unix sockets in network seccomp
    - `a87c6ae` chore: release v0.42.0

    **Rationale (verbatim from Phase 33 DIVERGENCE-LEDGER.md cluster 3 row):**

    > Upstream adds `UnixSocketCapability` + `UnixSocketMode` + `--allow-unix-socket`
    > flag family + Linux seccomp `af_unix` plumbing. The capability shape is
    > Unix-specific (Windows IPC uses Named Pipes — see Phase 18 AIPC pipe/socket
    > brokering); adding a `UnixSocketCapability` to `crates/nono/` would expose an
    > enum variant that no Windows backend can honor and would violate D-19 (no
    > library mutation in this audit; a sync-time addition would need its own
    > Windows-no-op handling decision). Fork users on Windows do not consume Unix
    > sockets; macOS users get unsigned Unix-socket access today via the broader
    > macOS Seatbelt allowlist — a typed capability is not a regression.

    **Decision rationale cites:**
    - **D-19 / D-34-E2 (atomic commit-per-semantic-change):** A typed
      `UnixSocketCapability` lands in `crates/nono/src/capability.rs` (the library).
      Adding the enum variant would either expose a no-op match arm on the Windows
      backend (violating fail-secure: no silent degradation) or require a parallel
      Windows IPC capability decision that is out of Phase 34 scope.
    - **Phase 18 AIPC pipe/socket brokering** already addresses the fork's Windows
      IPC needs via Named Pipes. A Unix-socket-typed capability is not the right
      abstraction for the fork's Windows surface.

    **Future re-evaluation trigger:** if a future phase decides to define a
    cross-platform "stream socket" capability that abstracts over Unix sockets
    (Linux/macOS) and Named Pipes (Windows), upstream's `UnixSocketCapability`
    shape becomes a candidate to absorb as the Linux/macOS arm of that abstraction.

    ---

    *Phase 34 closes with all 12 cluster dispositions resolved. Future UPST phases
    (UPST4, v0.53.0+) fire per the Phase 33 ADR's "per upstream release, lazily-
    evaluated" cadence rule.*
    ```

    Substitute `<YYYY-MM-DD when Plan 34-10 closes>` with the current date at execute time. Write the file via the Write tool (NOT heredoc).

    Cross-check the addendum content against Phase 33 ledger headlines:
    ```bash
    # C1 disposition language quoted verbatim:
    diff <(grep -A 5 'Cluster: PTY attach' .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md | grep -E 'Disposition.*won')  <(grep -E 'C1.*won.t-sync' .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md) || echo "Cross-check note: addendum cites Phase 33 disposition rationale verbatim"

    # C3 disposition language quoted verbatim:
    grep -E 'UnixSocketCapability' .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md

    # File structure verification:
    test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md
    test "$(grep -c "Won't-sync clusters" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "1"
    test "$(grep -c "### C1" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "1"
    test "$(grep -c "### C3" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "1"
    test "$(grep -c "D-11" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "1"
    test "$(grep -c "D-19\|D-34-E2" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "1"
    test "$(wc -l < .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "30"
    ```

    Stage and commit the new artifact:
    ```bash
    git add .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md
    git commit -m "$(cat <<'EOF'
    docs(34-10): record won't-sync addendum for clusters C1 (PTY) and C3 (Unix-socket) per D-34-A3

    Creates 34-PHASE-OUTCOMES.md co-located with the Phase 34 directory (chosen
    over a Phase 33 DIVERGENCE-LEDGER.md amendment to avoid mutating an
    audit-complete artifact).

    Documents:
    - Cluster C1 (PTY attach/detach polish, v0.41.0): won't-sync per D-11
      (fork's ConPTY path is structurally different from upstream's pty_proxy.rs)
    - Cluster C3 (Unix-socket capability, v0.42.0): won't-sync per D-19 / D-34-E2
      (adding UnixSocketCapability would expose a no-op enum variant on the
      Windows backend, violating fail-secure)

    Closes Phase 34's terminal documentation responsibility per D-34-A3.

    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```
  </action>
  <verify>
    <automated>test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md &amp;&amp; test "$(grep -c "Won't-sync clusters" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "1" &amp;&amp; test "$(grep -c "### C1" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "1" &amp;&amp; test "$(grep -c "### C3" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "1" &amp;&amp; test "$(grep -c "D-11" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "1" &amp;&amp; test "$(wc -l < .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md)" -ge "30"</automated>
  </verify>
  <acceptance_criteria>
    - `34-PHASE-OUTCOMES.md` exists at `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/`.
    - Contains `## Won't-sync clusters` header.
    - Contains `### C1 —` header citing PTY cluster.
    - Contains `### C3 —` header citing Unix-socket cluster.
    - C1 row cites D-11 rationale.
    - C3 row cites D-19 / D-34-E2 rationale.
    - Phase 33 ledger language quoted verbatim for both rows.
    - File is at least 30 lines long.
    - Commit lands on `main` with the artifact staged + 2 DCO `Signed-off-by:` lines.
  </acceptance_criteria>
  <done>
    Won't-sync addendum captured; Phase 34 terminal documentation responsibility complete.
  </done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <name>Task 8: D-34-D2 close-gate verification (8 gates) + manual-replay review checkpoint</name>
  <files>(read-only verification across the full plan-34-10 commit range; no file modifications)</files>
  <action>Run the verification steps detailed in &lt;how-to-verify&gt; below. See &lt;how-to-verify&gt; for the full 8-gate D-34-D2 close-gate sequence + 7 plan-specific verifications (PV-1..PV-7). This task is a human checkpoint: user inspects gate outputs and approves only when all gates pass (or skips are documented with explicit reason).</action>
  <verify>
    &lt;automated&gt;cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check &amp;&amp; test "$(git log --format='%B' HEAD~6..HEAD | grep -v '^#' | grep -c '^Upstream-commit: ')" = "1" &amp;&amp; test "$(git diff --stat HEAD~6 HEAD -- crates/ | grep -cE '_windows|exec_strategy_windows')" = "0"&lt;/automated&gt;
  </verify>
  <what-built>
    Plan 34-10 produces 6 commits on `main`:
    - Commit 1: D-19-trailered audit-context replay for upstream `9300de9` (modifies audit_ledger.rs / audit_session.rs / audit_commands.rs / nono-proxy/audit.rs / nono-proxy/server.rs)
    - Commits 2–5: documentation-only commits (--allow-empty) for `149abde`, `879562c`, `8db8919`, `dcf2d29`
    - Commit 6: 34-PHASE-OUTCOMES.md (D-34-A3 won't-sync addendum for C1 + C3)

    Plan 34-10 is the terminal Phase 34 plan. Phase 34 closes when this checkpoint clears.
  </what-built>
  <how-to-verify>
    Run all 8 D-34-D2 close-gates on the Windows host. Each gate must pass with zero exit code (or documented-skip with explicit reason).

    **Gate 1 — workspace test (Windows):**
    ```bash
    cargo test --workspace --all-features
    ```
    Expected: 0 exit. Phase 23 REQ-AUD-05 audit-integrity tests green.

    **Gate 2 — Windows-host clippy:**
    ```bash
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
    ```
    Expected: 0 exit.

    **Gate 3 — Linux-target clippy (Phase 25 CR-A lesson; catches `#[cfg(target_os = "linux")]` drift):**
    ```bash
    cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
    ```
    Expected: 0 exit.

    **Gate 4 — macOS-target clippy:**
    ```bash
    cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used
    ```
    Expected: 0 exit.

    **Gate 5 — formatter check:**
    ```bash
    cargo fmt --all -- --check
    ```
    Expected: 0 exit.

    **Gate 6 — Phase 15 5-row detached-console smoke gate:**
    ```bash
    # Manual sequence (human verifies stdout/stderr; record outputs):
    nono run --detached --profile <test-profile> -- ping 127.0.0.1
    nono ps
    nono attach <session-id>  # confirm scrollback intact
    # detach via Ctrl+Q
    nono stop <session-id>
    ```
    Expected: 5 rows complete; attach scrollback intact; stop returns 0.

    **Gate 7 — wfp_port_integration test suite:**
    ```bash
    cargo test -p nono-cli --features windows-tests wfp_port_integration
    ```
    Expected: 0 exit, OR documented-skip if WFP service not available on the host (record skip reason).

    **Gate 8 — learn_windows_integration test suite:**
    ```bash
    cargo test -p nono-cli --features windows-tests learn_windows_integration
    ```
    Expected: 0 exit, OR documented-skip if ETW not available on the host (record skip reason).

    **Plan-specific verifications (in addition to D-34-D2 gates):**

    **PV-1 — single Upstream-commit trailer in plan range:**
    ```bash
    test "$(git log --format='%B' HEAD~6..HEAD | grep -v '^#' | grep -c '^Upstream-commit: ')" = "1"
    test "$(git log --format='%B' HEAD~6..HEAD | grep -c '^Upstream-commit: 9300de9')" = "1"
    ```

    **PV-2 — Windows credential-injection byte-identical:**
    ```bash
    diff <(sha256sum crates/nono-proxy/src/credential.rs) <(grep credential.rs /tmp/34-10-baseline.txt)
    ```
    Expected: identical.

    **PV-3 — WSAStartup ordering preserved:**
    ```bash
    diff <(grep -n -A 2 'WSAStartup\|wsa_startup\|nono-proxy.*windows' crates/nono-proxy/src/server.rs) <(grep -A 2 'WSAStartup' /tmp/34-10-baseline.txt) || echo "Verify manually if grep formatting differs; structural equivalence is the bar"
    ```

    **PV-4 — Windows-only files invariant (cumulative across plan range):**
    ```bash
    git diff --stat HEAD~6 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l
    ```
    Expected: 0.

    **PV-5 — 34-PHASE-OUTCOMES.md content cross-check:**
    ```bash
    grep -c "### C1" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md
    grep -c "### C3" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md
    grep -c "D-11\|D-19\|D-34-E2" .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md
    ```

    **PV-6 — Documentation commits empty:**
    ```bash
    # Commits HEAD~5, HEAD~4, HEAD~3, HEAD~2 should all be empty:
    for offset in 5 4 3 2; do
      test "$(git diff --stat HEAD~${offset}~1 HEAD~${offset} | wc -l)" = "0" || echo "FAIL: HEAD~${offset} is not empty"
    done
    ```

    **PV-7 — Phase 22-04 OAuth2 integration tests:**
    ```bash
    cargo test -p nono-proxy oauth2  # OAuth2 token cache + WSAStartup ordering
    ```
    Expected: 0 exit (Phase 22-04 surface unchanged).
  </how-to-verify>
  <resume-signal>
    Type `approved` if all 8 D-34-D2 gates pass + all 7 plan-specific verifications pass. Document any gate-7/gate-8 skips with skip reason. If any gate fails, describe the failure; planner-of-record decides whether to split or revert per D-34-D2 STOP-trigger rules.
  </resume-signal>
  <acceptance_criteria>
    - All 8 D-34-D2 close-gates: pass or documented-skip with reason.
    - All 7 plan-specific verifications pass.
    - User approves.
  </acceptance_criteria>
  <done>
    Close-gate cleared; Plan 34-10 ready to publish.
  </done>
</task>

<task type="auto">
  <name>Task 9: Push to origin/main + open per-plan PR (D-34-D1)</name>
  <files>(git push + gh pr create only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D1 (direct-on-main; one PR per plan)
  </read_first>
  <action>
    1. Push commits:
       ```bash
       git push origin main
       ```
    2. Open per-plan PR:
       ```bash
       gh pr create --title "Plan 34-10 (C11): Proxy TLS fork-preserve + audit-context replay (v0.51, 1 replay + 4 doc-only) + 34-PHASE-OUTCOMES.md" --body "$(cat <<'EOF'
       ## Summary
       - Plan 34-10 closes Phase 34 (UPST3 — Upstream v0.41–v0.52 Sync Execution). Cluster C11 disposition per D-34-B1: 1 clean replay (`9300de9` audit-context shape into Phase 23 REQ-AUD-05 ledger surface) + 4 documentation-only commits (`149abde`, `879562c`, `8db8919`, `dcf2d29` — TLS-interception machinery; not ported because cherry-pick would delete fork's Windows credential-injection rewrite).
       - Adds `34-PHASE-OUTCOMES.md` documenting won't-sync clusters C1 (PTY, per D-11) and C3 (Unix-socket, per D-19 / D-34-E2) per D-34-A3.
       - Windows credential-injection rewrite (Phase 09 + Phase 11) byte-identical. Phase 22-04 OAuth2 WSAStartup ordering preserved. Phase 23 REQ-AUD-05 audit-integrity tests green.

       ## Test plan
       - [x] All 8 D-34-D2 close-gates pass on Windows host (workspace test + 3-target clippy + fmt + Phase 15 5-row detached console smoke + wfp_port + learn_windows)
       - [x] `cargo test -p nono-cli --features windows-tests audit_integrity` exits 0 (Phase 23 REQ-AUD-05)
       - [x] `cargo test -p nono-proxy oauth2` exits 0 (Phase 22-04 ordering preserved)
       - [x] Single `Upstream-commit:` trailer in plan range (only the `9300de9` replay)
       - [x] 4 documentation-only commits are empty diffs (verified per-commit)
       - [x] `crates/nono-proxy/src/credential.rs` sha256 unchanged from pre-plan baseline
       - [x] D-34-E1 invariant: zero hits on `*_windows.rs` / `exec_strategy_windows/` across plan range
       - [x] `34-PHASE-OUTCOMES.md` exists with C1 + C3 rows citing D-11 + D-19 rationale
       EOF
       )"
       ```
    3. Verify push succeeded:
       ```bash
       git fetch origin
       test "$(git log origin/main..main --oneline | wc -l)" = "0"
       ```
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - `git push origin main` exit 0.
    - PR opened via `gh pr create`; PR URL returned.
    - `origin/main` advanced; local main == origin/main.
  </acceptance_criteria>
  <done>
    Plan 34-10 published; Phase 34 closed.
  </done>
</task>

</tasks>

<non_goals>
**TLS-interception machinery NOT added to the fork.** D-34-B1 fork-preserve disposition for `149abde`, `879562c`, `8db8919`, `dcf2d29`. The fork's `crates/nono-proxy/` continues to use the Phase 09 + Phase 11 Windows credential-injection rewrite. Future re-evaluation only if upstream restructures `tls_intercept` to support pluggable trust-store backends.

**No `*_windows.rs` files touched** by the audit-context replay (D-34-E1 invariant).

**No changes to fork's Phase 22-04 OAuth2 surface** (`crates/nono-proxy/src/oauth2.rs`). WSAStartup ordering + token cache + `Zeroizing<String>` handling all byte-identical.

**No retrofit of upstream's git CA trust extension** to the fork's Windows trust-store path. Out of scope per D-34-B2 surgical retrofit posture.

**No mutation of Phase 33 `DIVERGENCE-LEDGER.md`.** Won't-sync addendum lives in a new Phase 34 artifact (`34-PHASE-OUTCOMES.md`) per D-34-A3 planner discretion.

**No Phase 33 gap reopening.** G-25-DRIFT-01 closed in Plan 34-00; Phase 33 audit-complete artifact is immutable.

**No work on TLS-interception machinery cherry-pick** as a future Phase 34 task. Future re-evaluation is a separate UPST phase decision.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Sandboxed agent → nono-proxy CONNECT request | Existing proxy interception surface; cluster C11 audit-context replay adds structured network-event context to audit emission without changing the interception path. |
| nono-proxy → upstream TLS server | Existing fork passthrough path with Windows credential injection; cluster C11 TLS-interception commits NOT ported (would replace passthrough with MITM-style cert generation incompatible with fork's Windows credential-store). |
| nono-cli audit ledger → on-disk audit session | Phase 22-05a + Phase 23 REQ-AUD-05 integrity envelope; cluster C11 `9300de9` extends the network-event row of the envelope additively. |
| Plan 34-10 commit chain → main branch | D-19 trailer + D-20 disposition documentation per commit; cluster-11 disposition split (1 replay + 4 doc-only) recorded in commit bodies for future audit traceability. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-10-01 | Tampering | Cherry-pick of TLS-interception commits (`149abde` / `879562c` / `8db8919` / `dcf2d29`) silently deletes the fork's Windows credential-injection rewrite (Phase 09 + Phase 11) | **high** | mitigate (BLOCKING) | D-34-B1 disposition split: only `9300de9` cherry-picks/replays; TLS-interception commits are explicit `git commit --allow-empty` documentation-only commits (no cherry-pick). Per-commit acceptance criterion in Tasks 3–6 confirms zero `Upstream-commit:` trailer on the 4 doc commits. Task 8 PV-2 verifies `crates/nono-proxy/src/credential.rs` sha256 unchanged from baseline. |
| T-34-10-02 | Tampering | D-34-E1 Windows-only-files invariant violated by the `9300de9` audit-context replay (e.g., upstream's commit accidentally edits a `#[cfg(windows)]` arm in audit_session.rs or audit_commands.rs) | **high** | mitigate (BLOCKING) | Task 2 per-commit grep gate: `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns 0. Task 8 PV-4 cumulative grep gate across full plan range. The 4 documentation commits modify no files; D-34-E1 vacuously holds. |
| T-34-10-03 | Repudiation | D-19 trailer-block missing on the `9300de9` replay (the documentation commits don't need it; the audit-context replay MUST have it) | **high** | mitigate (BLOCKING) | Task 2 amend step writes the verbatim 6-line trailer (lowercase 'a' in `Upstream-author:`); Task 8 PV-1 confirms exactly ONE `Upstream-commit:` trailer in the plan range (only `9300de9`). 4 documentation commits explicitly do NOT carry the trailer (verified per-commit in Tasks 3–6). |
| T-34-10-04 | Tampering | Audit-context replay regression — `9300de9` composes incorrectly with Phase 23 REQ-AUD-05 surface, producing a tamper-detectable ledger gap or breaking merkle/chain-head invariants | **high** | mitigate | Task 2 acceptance criterion: `cargo test -p nono-cli --features windows-tests audit_integrity` exits 0 (Phase 23 REQ-AUD-05 integrity tests must remain green); Task 8 Gate 1 re-runs the full workspace test. If D-20 manual replay is needed (Step 2b in Task 2), the commit body explicitly documents what was replayed and why, so future audits can verify shape correctness. |
| T-34-10-05 | Tampering | WSAStartup ordering regression — Plan 34-02 (C4 proxy net) and 34-10 audit-context replay both touch proxy surface; ordering could break WSAStartup initialization on Windows | **medium** | mitigate | 34-10 sequenced AFTER 34-02 (`depends_on: ["34-02", "34-09"]`); Task 1 captures pre-plan WSAStartup grep baseline; Task 8 PV-3 verifies pre/post equivalence. Phase 22-04 OAuth2 integration tests (`cargo test -p nono-proxy oauth2`, Task 8 PV-7) catch any drift. |
| T-34-10-06 | Repudiation | Won't-sync addendum drift — `34-PHASE-OUTCOMES.md` content drifts from Phase 33 DIVERGENCE-LEDGER.md headlines (C1/C3 rows quote stale or misrepresented disposition rationale) | **medium** | mitigate | Task 7 acceptance criterion includes Phase 33 ledger cross-reference: `### C1` row quotes upstream's `pty_proxy.rs` rationale verbatim; `### C3` row quotes the UnixSocketCapability rationale verbatim. Both rows cite the specific decision IDs (D-11 for C1; D-19 / D-34-E2 for C3). Future-audit verifiability is the primary mitigation: any future re-audit can diff the addendum against the source ledger row and find drift if present. |
</threat_model>

<verification>
**Plan-range smoke checks (cumulative, run at Task 8):**

- `test "$(git log origin/main..main --oneline | wc -l)" = "6"` — Plan 34-10 produces exactly 6 new commits (1 audit-context replay + 4 documentation-only + 1 34-PHASE-OUTCOMES.md).
- `test "$(git log --format='%B' HEAD~6..HEAD | grep -v '^#' | grep -c '^Upstream-commit: ')" = "1"` — Exactly ONE `Upstream-commit:` trailer in plan range (the `9300de9` replay).
- `test "$(git log --format='%B' HEAD~6..HEAD | grep -c '^Upstream-commit: 9300de9')" = "1"` — Trailer is for `9300de9` specifically.
- `test "$(git diff --stat HEAD~6 HEAD -- crates/ | grep -cE '_windows|exec_strategy_windows')" = "0"` — D-34-E1 invariant cumulative across plan range.
- `sha256sum crates/nono-proxy/src/credential.rs` matches the pre-plan baseline in `/tmp/34-10-baseline.txt` — Windows credential-injection byte-identical.
- `cargo test -p nono-cli --features windows-tests audit_integrity` exits 0 — Phase 23 REQ-AUD-05 audit-integrity tests green.
- `cargo test -p nono-proxy oauth2` exits 0 — Phase 22-04 OAuth2 surface unchanged.

**D-34-D2 close-gates (run at Task 8):**

1. `cargo test --workspace --all-features` (Windows host).
2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host).
3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`.
4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`.
5. `cargo fmt --all -- --check`.
6. Phase 15 5-row detached-console smoke gate.
7. `wfp_port_integration` test suite.
8. `learn_windows_integration` test suite.

**Won't-sync addendum content checks (run at Task 7):**

- `test -f .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md`
- `grep -c "Won't-sync clusters" 34-PHASE-OUTCOMES.md` ≥ 1
- `grep -c "### C1" 34-PHASE-OUTCOMES.md` ≥ 1 (cluster C1 row)
- `grep -c "### C3" 34-PHASE-OUTCOMES.md` ≥ 1 (cluster C3 row)
- `grep -c "D-11" 34-PHASE-OUTCOMES.md` ≥ 1 (cluster C1 rationale cite)
- `grep -c "D-19\|D-34-E2" 34-PHASE-OUTCOMES.md` ≥ 1 (cluster C3 rationale cite)
- File at least 30 lines long.
</verification>

<success_criteria>
- 6 atomic commits on `main` for Plan 34-10:
  - 1 D-19-trailered audit-context replay (`9300de9`)
  - 4 documentation-only commits (`149abde`, `879562c`, `8db8919`, `dcf2d29` — all empty, no `Upstream-commit:` trailer)
  - 1 commit landing `34-PHASE-OUTCOMES.md` (D-34-A3 won't-sync addendum for C1 + C3)
- Windows credential-injection rewrite byte-identical pre/post.
- Phase 22-04 OAuth2 WSAStartup ordering preserved.
- Phase 23 REQ-AUD-05 audit-integrity tests green.
- D-34-E1 invariant: zero `*_windows.rs` / `exec_strategy_windows/` hits across plan range.
- All 8 D-34-D2 close-gates green (or documented-skip for gates 7/8 with reason).
- `origin/main` advanced; per-plan PR opened (D-34-D1).
- Phase 34 closes when this plan's PR merges. All 12 cluster dispositions resolved (8 will-sync via plans 34-01..34-08 + 34-04; 2 fork-preserve via 34-09 + 34-10; 2 won't-sync documented in 34-PHASE-OUTCOMES.md).
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-10-SUMMARY.md`.
</output>
