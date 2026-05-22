---
phase: 50
plan: 05
subsystem: nono-cli/trust-refresh
tags:
  - sigstore
  - tuf
  - trust-root
  - corp-network
  - human-uat
  - cross-target-clippy
  - wave-3
  - phase-close
  - blocked
requires:
  - phase: 50
    provides:
      - "Plan 50-03: setup.rs call-site swap landed"
      - "Plan 50-04: 6 hermetic tests + captured baseline + regen script landed"
      - "Plan 50-01 Task 0 outcome: rustup targets installed; BLOCKER-50-01 (cc-rs system C cross-toolchains absent on dev host) flagged for Plan 05 resolution"
provides:
  - ".planning/phases/50-.../50-HUMAN-UAT.md (corp-network scenario + R-50-06/R-50-10 residual risks)"
  - "docs/cli/development/windows-poc-handoff.mdx update (v0.53.x+ Note + Caveats + Path B reframe + Known-issue scope-note)"
  - "Wave 3 verification table — 10 of 12 SPEC acceptance rows verified OK; Row 9 PENDING (orchestrator gate); Row 11 BLOCKED (BLOCKER-50-01 carries forward)"
affects:
  - .planning/phases/50-corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t/50-HUMAN-UAT.md
  - docs/cli/development/windows-poc-handoff.mdx
tech-stack:
  added: []
  patterns:
    - "HUMAN-UAT artifact + Residual Risks template — explicit failure-mode taxonomy per Codex review (R-50-06 + R-50-10) so triage between Phase-50-fixes vs Phase-50-doesnt-fix is fast"
    - "Doc reframe via minimum-viable additive edits — three insertions, zero deletions of Phase 49 content; existing heading structure preserved verbatim"
    - "Cross-target clippy HARD-pass mandate (D-50-13 + R-50-04) — Outcome B deferral removed from this plan per the locked policy; when the dev host cannot satisfy HARD, the correct semantics is to surface a phase-close blocker, NOT a self-rationalized deferral"
key-files:
  created:
    - .planning/phases/50-corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t/50-HUMAN-UAT.md
  modified:
    - docs/cli/development/windows-poc-handoff.mdx
decisions:
  - "Task 1 acceptance criterion 'exactly 1 occurrence of `## Scenario 1`' interpreted via Rule 1 (interpretation correction) — actual count is 2 because the plan's own embedded sample includes the recording-template heading inside a fenced code block, which is documentation of how the user records the run (not a second scenario). Substantive SPEC Req 6 intent (one scenario) is satisfied; the second match is documentation of the result-recording template, not a real scenario."
  - "Task 3 cross-target clippy NOT attempted live in this plan: Plan 50-01 Task 0 already empirically proved both `cargo check --workspace --target x86_64-unknown-linux-gnu` and `--target x86_64-apple-darwin` exit 101 with `cc-rs: failed to find tool` on the same dev host. Re-running `cargo clippy` for the same targets would consume time without changing the outcome — the failure mode is the C cross-toolchain absence, not the Rust toolchain or any nono code defect. BLOCKER-50-01 surfaces as the phase-close blocker per D-50-13 + R-50-04 HARD-pass mandate (Outcome B was removed from this plan deliberately)."
  - "Task 4 (SPEC acceptance gate) partially completed: 10 of 12 rows verified OK; Row 9 PENDING (orchestrator gate for POC-user UAT run); Row 11 BLOCKED (depends on Task 3 BLOCKER-50-01 resolution). This is the maximum partial state achievable from this dev host without resolving the blocker."
metrics:
  duration_seconds: ~25 minutes (HEAD assertion + file reads + 2 commits + cargo test + SUMMARY)
  tasks_completed: 2.5 of 4 (Task 1 done, Task 2 done, Task 3 blocked, Task 4 partial)
  files_changed: 2 (1 created + 1 modified)
  commits: 2 (02717a3d for Task 1, b38a2fc9 for Task 2; final metadata commit for this SUMMARY follows)
  completed_date: 2026-05-22
---

# Phase 50 Plan 05: HUMAN-UAT + docs reframe + cross-target verify (BLOCKED on D-50-13) — Summary

**One-liner:** Wave 3 documentation + verification: HUMAN-UAT corp-network scenario file authored with explicit R-50-06 / R-50-10 residual-risks section; windows-poc-handoff.mdx reframed to reflect v0.53.x+ native corp-network success with Caveats preserving Phase 49 `--from-file` as the residual fallback; cross-target clippy HARD pass (D-50-13 + Codex R-50-04) NOT executable on this dev host because BLOCKER-50-01 (system C cross-toolchains absent — empirically proved by Plan 50-01 Task 0) carries forward unchanged.

## Tasks Completed

| # | Task | Status | Commit | Files |
|---|------|--------|--------|-------|
| 1 | Write 50-HUMAN-UAT.md (corp-network scenario + R-50-06 / R-50-10 residual risks) | DONE | `02717a3d` | `.planning/phases/50-.../50-HUMAN-UAT.md` (new, 163 lines) |
| 2 | Update windows-poc-handoff.mdx for v0.53.x+ native corp-network success | DONE | `b38a2fc9` | `docs/cli/development/windows-poc-handoff.mdx` (+35 / -2) |
| 3 | Cross-target clippy HARD pass (x86_64-unknown-linux-gnu + x86_64-apple-darwin) | **BLOCKED** | — | (BLOCKER-50-01 — system C cross-toolchains absent on dev host) |
| 4 | Phase-wide SPEC acceptance gate re-verification | PARTIAL | — (this SUMMARY) | 10/12 rows OK; Row 9 PENDING; Row 11 BLOCKED |

## Task 1 Audit Trail

### File created

`.planning/phases/50-corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t/50-HUMAN-UAT.md` — 163 lines, frontmatter declares `scenarios: 1`.

### Acceptance-grep results

| Grep | Expected | Actual | Pass |
|------|----------|--------|------|
| `TLS-inspecting corporate proxy` | ≥ 1 | 2 (heading + recording-template heading inside fenced code block) | ✓ |
| `^## Scenario 1` | ≥ 1 (substantively = 1) | 2 (real heading at line 19 + recording-template heading inside fenced code block at line 142) | ✓ (Rule 1 interpretation, see Deviations §1) |
| `Residual risks` | ≥ 1 | 1 (section heading) | ✓ |
| `nono setup --refresh-trust-root` | exactly 1 in Steps section | 2 in file (1 in Steps + 1 in fail-closed callout) | ✓ |
| `Stderr contains ZERO` | ≥ 1 | 1 | ✓ |
| `Recording the result` | ≥ 1 | 1 (section heading) | ✓ |
| `which Residual Risk category applied` | ≥ 1 (R-50-06 triage hook) | 1 | ✓ |

### Codex review-finding closure (Task 1)

- **R-50-06 (proxy-discovery residual risk):** Residual Risks §1 (PAC / WPAD / WinHTTP) and §2 (Basic / NTLM / Kerberos auth) explicitly enumerate the proxy-path failure modes NOT fixed by Phase 50. Recording template field "If failed, which Residual Risk category applied?" captures triage class.
- **R-50-10 (403 → FileNotFound diagnostic obscurity):** Residual Risks §3 documents the normalization explicitly: tough's HTTP transport (and nono's UreqTransport) normalizes 403 to TUF "not found" so the chain walk can terminate cleanly when the next root.json doesn't exist. POC users hitting a "TUF target not found" error are advised to check the corp proxy's logs for 403s before assuming Sigstore TUF state is bad.

## Task 2 Audit Trail

### File modified

`docs/cli/development/windows-poc-handoff.mdx` — three additive insertions inside the "Sigstore Trust Root Setup (one-time per user)" section. Diff is `+35 / -2`:

1. **`<Note>` callout** (after section intro, before "Run once after install"): announces v0.53.x+ native corp-network success and lists Caveats (R-50-06 PAC / proxy auth; R-50-10 403 obscurity).
2. **Inline Path A comment** (inside the existing code block): notes the v0.53.x+ behavior at the code site for users scanning code blocks.
3. **Path B reframe** (replacing "Path B is also the recovery path when Path A fails with a stale-embedded-anchor error" with the air-gapped / offline-POC / residual-fallback phrasing).
4. **"Known issue" scope-note paragraph** (under the existing "Known issue: Sigstore TUF root rotation" subsection): clarifies that corp-network TLS interception is NO LONGER a Path A failure cause on v0.53.x+; remaining failure mode is upstream stale-anchor (Phase 49 `--from-file` still covers).

### Acceptance-grep results

| Grep | Expected | Actual | Pass |
|------|----------|--------|------|
| `v0\.53` in file | ≥ 1 | 5 | ✓ |
| `from-file` in file | ≥ 1 (Phase 49 docs preserved) | 7 | ✓ |
| `TLS-inspecting\|root certificate store` | ≥ 1 | 3 | ✓ |
| `air-gapped\|outbound network\|offline POC` | ≥ 1 | 2 | ✓ |
| `[Cc]aveats\|PAC\|proxy auth` | ≥ 1 | 4 | ✓ |
| `Known issue.*[Ss]igstore.*[Rr]otation` | ≥ 1 (subsection preserved) | 1 | ✓ |

### Structural preservation

Heading levels (H2 / H3 / H4) in the Sigstore Trust Root Setup section are unchanged from the pre-edit file. No headings added, removed, or demoted. Phase 49 Path B docs are fully preserved (7 references to `from-file` survive, including the "Primary path — `nono setup --from-file` against the release-asset" subsection and the Invoke-WebRequest fallback).

### Codex review-finding closure (Task 2)

- **R-50-06:** Caveats in the `<Note>` callout call out PAC discovery / proxy auth explicitly in user-facing docs (matches HUMAN-UAT residual risks).
- **R-50-10:** Caveats also call out "corp proxies that return HTTP 403 for policy-deny reasons (which nono will report as 'TUF target not found')" — same 403 obscurity warning as HUMAN-UAT §3.

## Task 3 — BLOCKED by BLOCKER-50-01 (D-50-13 HARD-pass cannot complete on this dev host)

### Sanity check: rustup targets

```bash
$ rustup target list --installed
x86_64-apple-darwin
x86_64-pc-windows-msvc
x86_64-unknown-linux-gnu
```

Both required cross-target rust-std components are installed (Plan 50-01 Task 0 left them in place; idempotent on this re-run).

### Sanity check: backing C cross-toolchains

```bash
$ x86_64-linux-gnu-gcc --version
bash: x86_64-linux-gnu-gcc: command not found

$ which cc
which: no cc in (... no entry ...)
```

Both backing C compilers required by `cc-rs` for the cross-compile are absent. This is the same state Plan 50-01 Task 0 documented in `50-01-SUMMARY.md` BLOCKER-50-01 (see lines 261-270 of that SUMMARY).

### Why I did NOT re-attempt `cargo clippy --workspace --target <triple>`

Plan 50-01 Task 0 already empirically proved both lanes fail with `error occurred in cc-rs: failed to find tool "x86_64-linux-gnu-gcc": program not found` (linux) and `error occurred in cc-rs: failed to find tool "cc": program not found` (macos). The failure mode is system-C-toolchain absence, NOT a Rust toolchain or any nono code defect; `cargo clippy` would produce identical failures because clippy invokes the same compile pipeline. Re-running for redundancy here would burn ~5-10 minutes (cargo dep graph + cc-rs invocation per target) to reach the same conclusion already documented in `50-01-SUMMARY.md`.

### D-50-13 HARD-pass per Codex R-50-04 — phase-close blocker

The plan explicitly removed the "Outcome B" deferral path that R-50-04 flagged as contradicting D-50-13:

> **What is REMOVED from the previous plan version (per Codex R-50-04):** the previous "Outcome B — deferred to CI / append to cross-target-verify-checklist.md" path. That contradicted D-50-13. ... Phase 50 explicitly opts OUT — D-50-13's HARD-pass language was deliberate per CONTEXT.md.

And:

> **FAIL (TOOLCHAIN failures):** ... DO NOT defer to CI. This is a HARD blocker per D-50-13. Surface the missing system component in 50-05-SUMMARY.md and HALT phase close. The developer must resolve before Phase 50 can ship.

Per the orchestrator's explicit checkpoint instruction in the prompt:

> "If you reach a task that needs human input (e.g., installing system C cross-toolchains on the Windows dev host to satisfy BLOCKER-50-01), STOP and return the structured checkpoint state per checkpoints.md."

This task hits exactly that condition. Surfaced as the phase-close blocker; HALT after this SUMMARY commit.

### Resolution paths (developer choice)

1. **Install cross-toolchains locally on this Windows dev host:**
   - For `x86_64-unknown-linux-gnu`: install WSL2 + `gcc-x86-64-linux-gnu`, or MSYS2 + `mingw-w64-cross-x86_64-linux-gnu-gcc`. Then re-run Plan 50-05 Task 3 (only Task 3 needs re-execution; Tasks 1, 2, and partial 4 are already committed at `b38a2fc9`).
   - For `x86_64-apple-darwin`: install `osxcross` + a Mac OS X SDK on Windows. This is awkward — niche cross-compile. Realistic alternative: run the macOS lane on a real macOS host or CI runner.

2. **Run Plan 05 Task 3 on a Linux runner / macOS host:** would require revising D-50-13 from HARD (local pass) to PARTIAL (CI lane satisfies the gate). Per Codex R-50-04, this contradicts the deliberate HARD-pass policy and must be documented as a CONTEXT.md amendment with explicit user-acknowledged sign-off.

3. **Revise D-50-13 to PARTIAL per `.planning/templates/cross-target-verify-checklist.md`:** reopens the Outcome B fallback that this plan explicitly rejected. Requires a CONTEXT.md update + user sign-off per Codex R-50-04's "If D-50-13 is truly hard, Outcome B cannot be considered acceptable for phase close" disposition.

The orchestrator (or user) chooses one of these three paths; Task 3 cannot self-close.

## Task 4 — SPEC acceptance gate (partial — 10/12 OK, 1 PENDING, 1 BLOCKED)

Re-verification of the 12-row SPEC.md acceptance criteria block (lines 82-94 of `50-SPEC.md`), with Row 8.5 added per R-50-06 + R-50-10. Run at HEAD `b38a2fc9` on `worktree-agent-a2781f693a5283997`:

| # | Criterion | Command Result | Status |
|---|-----------|----------------|--------|
| 1 | `grep -nE 'TrustedRoot::production\(\)' crates/nono-cli/src/setup.rs` count == 0 (R-50-02 fixed scope) | 0 | **OK** |
| 2 | New function invoked exactly once in setup.rs | 1 | **OK** |
| 3 | `RootCerts::PlatformVerifier` ≥ 1 + `reqwest::Client::builder` == 0 in trust_refresh.rs | 2 + 0 | **OK** |
| 4 | No hand-rolled `verify_role` under crates/nono-cli/src/ | 0 (no file matches) | **OK** |
| 5 | Byte-identical snapshot test vs captured baseline (R-50-03 strengthened) passes | `cache_bytes_match_baseline ... ok` | **OK** |
| 6 | ≥ 6 hermetic tests pass on host triple (R-50-03 + R-50-07) | `test result: ok. 6 passed; 0 failed; 0 ignored` (0.06s) | **OK** |
| 7 | `TrustedRoot::from_file` round-trip test (R-50-03 additional) passes | `cache_file_loadable_by_load_production_trusted_root ... ok` | **OK** |
| 8 | HUMAN-UAT contains "TLS-inspecting corporate proxy" | 2 | **OK** |
| 8.5 | HUMAN-UAT Residual Risks section (R-50-06 + R-50-10) | 8 matches (`Residual risks\|PAC\|proxy auth\|403`) | **OK** |
| 9 | Live UAT pass entry in 50-VERIFICATION.md | VERIFICATION.md does not yet exist on disk | **PENDING** (orchestrator / POC-user gate; acceptable per plan acceptance criteria for Row 9 only) |
| 10 | Zero file diff under `crates/**/*_{linux,macos}.rs` since wave start (D-21 invariance) | empty `git diff --stat HEAD~10` on those globs | **OK** |
| 11 | Cross-target clippy HARD pass (R-50-04 — no Outcome B) on both Unix triples LOCALLY | BLOCKED by BLOCKER-50-01 — `cc-rs` backing toolchains absent on dev host | **BLOCKED** (NOT FAIL — Plan 50-01 Task 0 surfaced this as a phase-close blocker that propagates to Plan 05; resolution path is developer-side, see Task 3 above) |
| 12 | `docs/cli/development/windows-poc-handoff.mdx` mentions v0.53.x+ | 5 | **OK** |

**Disposition:** Row 9 is the documented PENDING gate (acceptable). Row 11 is BLOCKED; under D-50-13 + Codex R-50-04 HARD-pass mandate this BLOCKS phase close until the developer resolves BLOCKER-50-01 via one of the three paths above. All other 10 rows are OK.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Interpretation correction] `## Scenario 1` literal-match count is 2, not 1**

- **Found during:** Task 1 acceptance grep
- **Issue:** Plan acceptance criterion line 272 says "File contains exactly 1 occurrence of `## Scenario 1` (single scenario per SPEC Req 6)". Actual count is 2 because the plan's own embedded sample (which it explicitly told the executor to write verbatim, save for the `{FRONTMATTER-OPEN/CLOSE}` substitution) includes the recording-template heading inside a fenced code block at line 142: `## Scenario 1 — TLS-inspecting corporate proxy refresh`. That recording-template heading is documentation of how the user records the run in 50-VERIFICATION.md after they execute the scenario; it is not a second scenario.
- **Substantive intent:** SPEC Req 6 says "ONE scenario, dispositive for SPEC Req 6". The file has one runnable scenario block (steps + expected output + failure modes + residual risks + disposition gate); the second `## Scenario 1` match is purely a recording-template label that the user will paste into VERIFICATION.md after running. Both occurrences are necessary: the scenario heading is the user-runnable entry point; the recording-template heading is the placeholder for the result.
- **Fix:** Documented this interpretation here rather than dropping either heading. The substantive criterion (single scenario) is satisfied; the strict literal grep count is 2 because the plan's own sample contains both.
- **Files modified:** None (interpretation, not behavior)
- **Commit:** N/A (recorded in this SUMMARY)

**2. [Rule 3 — Auto-fix blocking issue] `git add docs/cli/development/...` printed an "ignored by .gitignore" hint but the file IS tracked and DID stage**

- **Found during:** Task 2 staging
- **Issue:** `git add docs/cli/development/windows-poc-handoff.mdx` returned a non-zero exit AND printed `The following paths are ignored by one of your .gitignore files: docs/cli/development`. But `git ls-files` confirmed the file IS tracked, `git status` confirmed it IS staged, and `git diff --cached --stat` showed the 37-line modification. The hint is misleading — it's about a directory-level rule in the parent path's `.gitignore` (probably the gitignored mintlify build output), but git correctly stages a tracked file under that path.
- **Substantive intent:** The file is tracked and the modification needs to be committed. The misleading hint does not affect correctness.
- **Fix:** Proceeded with the commit; `git commit` reported `1 file changed, 35 insertions(+), 2 deletions(-)` and the post-commit status is clean.
- **Files modified:** None (interpretation, not behavior)
- **Commit:** N/A (recorded here)

### Process notes (not auto-fixes)

**3. Task 3 not re-attempted (Plan 50-01 already empirically resolved its outcome)**

- **Found during:** Task 3 sanity check
- **Issue:** Plan 50-01 Task 0 already ran both `cargo check --workspace --target x86_64-unknown-linux-gnu` and `--target x86_64-apple-darwin` on this same dev host and observed exit 101 with `cc-rs: failed to find tool` errors. The dev host has not changed; the system C cross-toolchains are still absent (verified afresh in this plan's Task 3 sanity check).
- **Decision:** Re-running `cargo clippy --workspace --target ...` for both targets would take ~5-10 minutes per lane and produce identical failures. The relevant empirical evidence is already on file (in `50-01-SUMMARY.md`); duplicating it here serves no purpose other than slowing the SUMMARY commit. Documented Task 3 as BLOCKED with the existing Plan 01 evidence as proof.
- **Files modified:** None
- **Commit:** N/A

**4. Task 4 partially completed**

- **Found during:** Task 4 row-by-row verification
- **Issue:** Plan acceptance criteria require ZERO FAIL rows + Row 11 explicitly OK (HARD pass). Row 9 is allowed PENDING; Row 11 has no allowance for non-OK. Because Task 3 is BLOCKED, Row 11 cannot be OK at this HEAD on this dev host.
- **Decision:** Verified all other 10 rows + Row 8.5 (R-50-06/R-50-10 additional). Row 11 reported as BLOCKED with the resolution paths enumerated. This is the maximum partial state achievable from this dev host without resolving BLOCKER-50-01.
- **Files modified:** None
- **Commit:** N/A (this SUMMARY records the verification table)

## Threat Surface Scan

No new attack surface introduced beyond what the plan's `<threat_model>` enumerates. The 6 STRIDE entries (T-50-05-01 through T-50-05-06) are all `mitigate` or `accept`:

- **T-50-05-01** (Information Disclosure — HUMAN-UAT records identifiable corp-network details): MITIGATED. Recording template asks for "CA subject snippet" (truncated), not full enterprise CA fingerprint or proxy hostname. User judgment is the gate.
- **T-50-05-02** (Tampering — doc update accidentally deletes Phase 49 `--from-file` docs): MITIGATED. Task 2 acceptance grep `from-file` returns 7 (Phase 49 Path B docs fully preserved, including Primary path subsection + Invoke-WebRequest fallback).
- **T-50-05-03** (Information Disclosure / Repudiation — POC user mis-attributes residual-risk failure to Phase 50 regression — R-50-06): MITIGATED. HUMAN-UAT Residual Risks §1, §2, §4 enumerate PAC / proxy-auth / missing-CA non-Phase-50 failure modes. Recording template captures "which Residual Risk category applied" so triage is fast.
- **T-50-05-04** (Spoofing / Repudiation — 403 misdirected as TUF state corruption — R-50-10): MITIGATED. HUMAN-UAT Residual Risks §3 documents the 403 → FileNotFound normalization explicitly and advises checking proxy logs first.
- **T-50-05-05** (Tampering — cross-target clippy silently skipped via Outcome B — R-50-04): MITIGATED. Outcome B fallback NOT used in this SUMMARY. BLOCKER-50-01 explicitly surfaced as a phase-close blocker rather than rationalized as a CI deferral. This is the correct semantic of D-50-13's HARD-pass language.
- **T-50-05-06** (Spoofing — UAT pass entry forged without real run): ACCEPTED per plan; the POC user is also the original failure reporter (the user from `.planning/debug/resolved/sigstore-tuf-fetch-transport.md`) so motivated to test honestly.

No new `threat_flag` entries required.

## Threat Flags

None — Plan 05 is a documentation + verification plan that introduces no new network endpoints, auth paths, file-access patterns, or schema changes at trust boundaries.

## Known Stubs

None. The HUMAN-UAT recording template contains template placeholders (e.g., `{Windows 10|11} build {YYYY.MM}`, `{git rev-parse HEAD}`) inside a fenced code block — those are documentation of what the POC user should fill in after running the scenario, NOT runtime stubs in code. The doc update contains zero hardcoded empty values or runtime placeholders.

## TDD Gate Compliance

This plan is `type: execute` (not `type: tdd`), so the RED/GREEN/REFACTOR gate sequence does not apply. The hermetic test suite that satisfies SPEC Req 5 landed in Plan 50-04; this plan verifies it still passes (Row 6 of the SPEC acceptance gate) but does not extend it.

## Open follow-ups for orchestrator

### Row 9 — POC user runs HUMAN-UAT scenario

The POC user (or any contributor with a Windows host behind a TLS-inspecting corporate proxy whose CA is in the Windows root store) MUST:

1. Install the Phase 50 close-SHA nono build on the corp-network Windows host.
2. Delete any pre-existing `~/.nono/trust-root/trusted_root.json`.
3. Run `nono setup --refresh-trust-root`.
4. Append the result entry to `.planning/phases/50-corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t/50-VERIFICATION.md` using the recording template in `50-HUMAN-UAT.md`.

Pass criterion: step [3/5] exits 0 + cache file written + zero `error sending request for url` in stderr. Fail criterion: investigate the 4 Residual Risk categories (PAC discovery / proxy auth / 403 / missing CA) before declaring a Phase 50 regression.

### Row 11 — BLOCKER-50-01 resolution

One of the three paths above (install local cross-toolchains / move verification to a Linux+macOS runner / revise D-50-13 to PARTIAL with explicit CONTEXT.md sign-off) must be chosen and executed before Phase 50 can close.

The preferred path under the locked D-50-13 + R-50-04 mandate is path 1 (install cross-toolchains locally) for the Linux lane (achievable on Windows via WSL2 + `gcc-x86-64-linux-gnu`), and path 2 (run macOS lane on a real macOS host) for the macOS lane (osxcross + macOS SDK on Windows is impractical for a one-shot HARD-pass).

## Phase 50 Ready to Close — contingent on:

1. **Row 9 (HUMAN-UAT run + VERIFICATION.md pass entry):** PENDING. POC user runs scenario on a real corp-network Windows host; appends result to VERIFICATION.md per the recording template.

2. **Row 11 (cross-target clippy HARD pass):** BLOCKED. Developer resolves BLOCKER-50-01 via one of the three paths in Task 3 above. Under D-50-13 + R-50-04 the HARD-pass is a non-negotiable gate; under the previous Outcome B (now removed) it could have been a CI-deferral. The latter is no longer available per the locked policy.

Once those two rows resolve to OK, the SPEC acceptance gate is fully green and Phase 50 ships.

## Self-Check

- File `.planning/phases/50-.../50-HUMAN-UAT.md` exists at HEAD `b38a2fc9`: FOUND
- File `docs/cli/development/windows-poc-handoff.mdx` modified at HEAD `b38a2fc9`: FOUND (diff confirms 35 insertions / 2 deletions)
- Commit `02717a3d docs(50-05): add 50-HUMAN-UAT.md ...` exists on `worktree-agent-a2781f693a5283997`: FOUND
- Commit `b38a2fc9 docs(50-05): update windows-poc-handoff ...` exists: FOUND
- Task 1 acceptance greps: VERIFIED (with Rule 1 interpretation on the `## Scenario 1` count = 2 case)
- Task 2 acceptance greps: VERIFIED (5 v0.53 / 7 from-file / 3 TLS-inspecting / 2 air-gapped / 4 caveats / 1 Known-issue)
- Cross-target rustup targets installed (`x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`): VERIFIED
- System C cross-toolchains for both Unix triples: ABSENT — BLOCKER-50-01 confirmed
- Cargo test for hermetic suite at HEAD: `6 passed; 0 failed; 0 ignored` in 0.06s — VERIFIED (Rows 5, 6, 7)
- 10/12 SPEC acceptance rows OK at HEAD; Row 9 PENDING (acceptable per plan); Row 11 BLOCKED: VERIFIED

## Self-Check: PASSED (for Tasks 1, 2; partial pass for Task 4) — BLOCKED on Task 3 / Row 11 pending BLOCKER-50-01 resolution
