---
phase: 49
plan: 03
type: execute
wave: 1
depends_on: []
files_modified:
  - .planning/templates/sigstore-rotation-refresh.md
  - scripts/verify-trust-root-cached.sh
  - scripts/verify-trust-root-cached.ps1
  - docs/cli/development/windows-poc-handoff.mdx
autonomous: false
requirements: [REQ-POC-TRUST-03]
tags: [sigstore, trust-root, docs, maintainer-cadence, smoke-test]
must_haves:
  truths:
    - "`.planning/templates/sigstore-rotation-refresh.md` exists with the 6 mandated sections (trigger / capture / diff / regression / commit / release-asset gate)"
    - "`scripts/verify-trust-root-cached.sh` exists, is executable, and exits 0 on the current frozen fixture"
    - "`scripts/verify-trust-root-cached.ps1` exists and propagates `$LASTEXITCODE` from every native command invocation (F-03-05 mitigation)"
    - "`docs/cli/development/windows-poc-handoff.mdx` no longer contains `sigstore-verify 0.6.5`, `P32-DEFER-005`, or `deferred-items.md` substrings"
    - "The `Known issue: Sigstore TUF root rotation` subsection recommends `nono setup --from-file` as the primary recovery path"
    - "The `Run once after install` block at lines 166-180 mentions `--from-file` as an alternative path"
  artifacts:
    - path: ".planning/templates/sigstore-rotation-refresh.md"
      provides: "Maintainer-cadence template for Sigstore TUF root rotations"
      contains: "sigstore-rotation-refresh"
      min_lines: 60
    - path: "scripts/verify-trust-root-cached.sh"
      provides: "Bash smoke script wrapping nono setup --from-file + cache-validation invariant"
      contains: "set -euo pipefail"
      min_lines: 15
    - path: "scripts/verify-trust-root-cached.ps1"
      provides: "PowerShell smoke script (Windows-first POC UX)"
      contains: "LASTEXITCODE"
      min_lines: 15
    - path: "docs/cli/development/windows-poc-handoff.mdx"
      provides: "Rewritten Known issue subsection + Run once after install consistency edits"
      contains: "--from-file"
  key_links:
    - from: ".planning/templates/sigstore-rotation-refresh.md"
      to: "scripts/verify-trust-root-cached.sh"
      via: "pre-commit gate cross-reference"
      pattern: "verify-trust-root-cached"
    - from: ".planning/templates/sigstore-rotation-refresh.md"
      to: ".github/workflows/release.yml"
      via: "forward pointer to Plan 49-02 byte-identity assert step"
      pattern: "release.yml"
    - from: "docs/cli/development/windows-poc-handoff.mdx::Known issue subsection"
      to: "scripts/verify-trust-root-cached.ps1"
      via: "documented primary path via --from-file"
      pattern: "--from-file"
---

<objective>
Close REQ-POC-TRUST-03 by shipping (a) a maintainer-cadence template at `.planning/templates/sigstore-rotation-refresh.md` for refreshing `crates/nono/tests/fixtures/trust-root-frozen.json` on each Sigstore root rotation, (b) a matched pair of cross-platform smoke scripts (`.sh` + `.ps1`) that validate a candidate `trusted_root.json` end-to-end via `nono setup --from-file`, and (c) a rewrite of the `Known issue: Sigstore TUF root rotation` subsection in `docs/cli/development/windows-poc-handoff.mdx` to recommend `--from-file` as the primary recovery path and remove the stale `sigstore-verify 0.6.5` / `P32-DEFER-005` / `deferred-items.md` references.

Purpose: Operationalize the fixture-refresh cadence so future Sigstore rotations require only a fixture refresh (per the new template), not a `sigstore-verify` Cargo.toml bump. Exits the dep-bump treadmill on the docs + process side, matching the structural CLI fix (Plan 49-01) and the release-asset story (Plan 49-02).

Output: 1 new template + 2 new smoke scripts (matched `.sh` + `.ps1`) + 1 rewritten POC-handoff subsection.

Implements: REQ-POC-TRUST-03 (per D-49-A1, D-49-C1, D-49-C2, D-49-C3).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-CONTEXT.md
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-SPEC.md
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-PATTERNS.md
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-VALIDATION.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md

<interfaces>
<!-- Existing template structural shape to mirror -->
From `.planning/templates/cross-target-verify-checklist.md` (78 lines — verified). Section structure:
- `# {Title}`
- intro line "Read this template before {action}."
- "**Source:** {origin phase/lesson reference}"
- `## Scope` — when this checklist applies / does NOT apply
- `## Decision Tree` — numbered Questions with Yes/No branches
- `## {Setup or Helpers}` — one-time prereqs if any
- `## PARTIAL Disposition` (optional — only if a partial state is meaningful)
- `## Anti-Patterns (do NOT do)` — numbered with rationale
- `## Enforcement` — who reads this and when

<!-- Existing scripts/ conventions (verified via ls) -->
- `scripts/*.sh` files use `#!/usr/bin/env bash` + a strict mode at the top (varies — some use `set -euo pipefail`, some don't; the new script MUST use `set -euo pipefail`).
- `scripts/*.ps1` files use `#Requires -Version 5.1` + `$ErrorActionPreference = 'Stop'` + explicit `$LASTEXITCODE` checks (verified in `scripts/build-windows-msi.ps1` and `scripts/sign-windows-artifacts.ps1`).

<!-- Current windows-poc-handoff.mdx state (verified lines 160-234) -->
- Line 167: `nono setup --refresh-trust-root` recommended as the post-install command.
- Line 182: `#### Known issue: Sigstore TUF root rotation (sigstore-verify 0.6.5)` — version-pinned heading.
- Lines 184-191: ERROR block pasted (the signature-threshold failure message).
- Lines 193-196: prose pinning workaround to `sigstore-verify 0.6.5` upstream.
- Lines 198-202: prose pointing at `crates/nono/tests/fixtures/trust-root-frozen.json` as the maintainer-captured root.
- Lines 204-212: PowerShell `Invoke-WebRequest` workaround pasted; comment cites "P32-DEFER-005 in .planning/phases/32-sigstore-integration/deferred-items.md".
- Lines 214-216: "After that, `nono trust verify` with --issuer + --identity works offline".
- Lines 218-221: prose pinning recovery to "sigstore-verify dep is upgraded to 0.6.6+" — the dep-treadmill prose Phase 49 exits.

<!-- Available trust fixtures (verified) -->
- `crates/nono/tests/fixtures/trust-root-frozen.json` — 126-line frozen TUF root fixture; current SHA-256 = `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`. THIS is the only trust fixture in the repo.
- `crates/nono-cli/tests/fixtures/` — empty (only `.gitkeep`).

**Smoke-script scope (load-bearing decision):** RESEARCH.md's skeleton mentioned `nono trust verify <BUNDLE> <SOURCE>` as a follow-on invocation, but there is NO hermetic bundle+source fixture pair in the repo for the smoke script to consume (verified). The smoke script's verifiable behavior is constrained to:
1. `nono setup --from-file <PATH>` succeeds (exit 0).
2. The cache file at `$NONO_TEST_HOME/.nono/trust-root/trusted_root.json` exists and is byte-identical to the input (`cmp -s` check).

The `nono trust verify` follow-on is documented in the maintainer-cadence template as a manual post-smoke step using the maintainer's local signed-file inventory — NOT wired into the smoke script (which would require shipping a signed fixture pair, increasing the per-rotation maintenance surface).

Per D-49-C2 ("smoke inputs reuse existing trust-test fixtures") — the only existing trust fixture is `trust-root-frozen.json`. The smoke script's input arg is a candidate `trusted_root.json` path (the script's CALLER supplies what to validate); no internal fixture lookup.
</interfaces>
</context>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Maintainer process -> committed fixture | Maintainer captures a new `trusted_root.json` from upstream `sigstore/root-signing@main`; the template defines the validation steps before commit. |
| Smoke-script invocation -> exit code | Smoke scripts return exit 0 only when both `nono setup --from-file` succeeds AND the cache file is byte-identical to the candidate input. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-49-05 | Tampering | Smoke-script silent-failure (script exits 0 on `nono setup` failure because `$LASTEXITCODE` was not checked or `set -e` was missing) | mitigate | `.sh`: `set -euo pipefail` at top — propagates any non-zero exit through the pipeline. `.ps1`: `$ErrorActionPreference = 'Stop'` PLUS explicit `if ($LASTEXITCODE -ne 0) { throw }` after every native command invocation (F-03-05 mitigation; `$ErrorActionPreference = 'Stop'` does NOT trap native-command failures). |
| T-49-08 | Information Disclosure / Maintainer Error | Maintainer commits a non-fresh fixture (e.g., a stale capture or one with truncated tlogs) | mitigate | Template Step 4 mandates running the smoke script as a pre-commit gate. Template Step 5 references the Plan 49-02 byte-identity assert as the post-commit + at-release gate. Two-stage gate: smoke-script catches stale/malformed at commit time; release.yml catches drift at release time. |
| T-49-09 | Tampering | Stale doc references mislead POC users into running the broken `--refresh-trust-root` path or following the dep-bump prose | mitigate | Doc rewrite removes ALL three stale references (`sigstore-verify 0.6.5`, `P32-DEFER-005`, `deferred-items.md`) AND removes the "will start working again once the dep is upgraded" prose. Acceptance criteria use negative-grep gates to enforce zero matches. |
</threat_model>

<verification_strategy>
## Failure Mode Coverage (Nyquist Dimension 8)

Cites IDs from `49-VALIDATION.md § Failure Modes -> REQ-POC-TRUST-03`. All 5 failure modes covered.

| Failure Mode | Validation Gate | Command |
|--------------|-----------------|---------|
| F-03-01 cadence template absent | `test -f .planning/templates/sigstore-rotation-refresh.md` | `test -f .planning/templates/sigstore-rotation-refresh.md` |
| F-03-02 smoke script absent or non-executable | `test -f scripts/verify-trust-root-cached.sh && [ -x scripts/verify-trust-root-cached.sh ]` AND `test -f scripts/verify-trust-root-cached.ps1` | Same as gate column |
| F-03-03 doc stale cross-references | `! grep -E '(sigstore-verify 0\.6\.5\|P32-DEFER-005\|deferred-items\.md)' docs/cli/development/windows-poc-handoff.mdx` exits 0 (zero matches) | Same as gate column |
| F-03-04 "Run once after install" inconsistency | `grep -A 8 'Run once after install' docs/cli/development/windows-poc-handoff.mdx \| grep -q -- '--from-file'` exits 0 | Same as gate column |
| F-03-05 PowerShell script silent-failure | Manual: run `.ps1 /nonexistent/path` and verify exit code != 0 + check `$LASTEXITCODE` is referenced in the script body via grep | `grep -nc "LASTEXITCODE" scripts/verify-trust-root-cached.ps1` >= 2 (one per native command invocation) AND manual run with bad input exits non-zero |

## Pre-Commit Verification Block

```bash
# F-03-01
test -f .planning/templates/sigstore-rotation-refresh.md

# F-03-02 (smoke script existence + executable bit)
test -f scripts/verify-trust-root-cached.sh
test -x scripts/verify-trust-root-cached.sh  # bit set via `git update-index --chmod=+x`
test -f scripts/verify-trust-root-cached.ps1

# F-03-03 (negative-grep: zero stale references)
! grep -E '(sigstore-verify 0\.6\.5|P32-DEFER-005|deferred-items\.md)' docs/cli/development/windows-poc-handoff.mdx

# F-03-04 (positive-grep: --from-file mentioned near Run once after install)
grep -A 8 'Run once after install' docs/cli/development/windows-poc-handoff.mdx | grep -q -- '--from-file'

# F-03-05 (PowerShell exit-code propagation prose presence)
[ "$(grep -c 'LASTEXITCODE' scripts/verify-trust-root-cached.ps1)" -ge 2 ]

# Sanity: smoke script positive-self-test (after Plan 49-01 lands; before that, manual `set -e` syntax check only).
bash -n scripts/verify-trust-root-cached.sh

# Bash + PowerShell static checks (if installed):
shellcheck -s bash scripts/verify-trust-root-cached.sh   # PARTIAL allowed if shellcheck unavailable
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path scripts/verify-trust-root-cached.ps1" || echo "PSScriptAnalyzer unavailable — PARTIAL"
```

## Manual-Only Verifications (per VALIDATION.md § Manual-Only)

- `.ps1` smoke script on a real Windows host (Windows shell semantics + `$LASTEXITCODE` propagation easier to validate by hand than via WSL/`pwsh-in-CI`).
- POC-handoff prose quality (not grep-checkable; reviewer reads the rewritten subsection + adjacent "Run once after install" block).
- Cadence template followed on the next real Sigstore root rotation event.

These are documented in SUMMARY as STRUCTURALLY-COMPLETE-PENDING-MANUAL.
</verification_strategy>

<tasks>

<task type="auto" tdd="false">
  <name>Task 1: Create `.planning/templates/sigstore-rotation-refresh.md` maintainer-cadence template</name>
  <files>.planning/templates/sigstore-rotation-refresh.md</files>
  <read_first>
    - .planning/templates/cross-target-verify-checklist.md (entire file — 78 lines; the structural mirror for sections, prose tone, and Anti-Patterns/Enforcement framing)
    - .planning/templates/upstream-sync-quick.md (skim — second prior-art template; CONTEXT.md notes both)
    - crates/nono/tests/fixtures/trust-root-frozen.json (confirm path + that it exists at the cited location)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md § "REQ-POC-TRUST-03 -> Existing template structural shape" (lines 372-405)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-PATTERNS.md § ".planning/templates/sigstore-rotation-refresh.md" (lines 137-152)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-SPEC.md REQ-POC-TRUST-03 Target (a) — 6 sections enumerated (trigger / capture / diff / regression / commit / release-asset gate)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-CONTEXT.md D-49-C3 (smoke-script is maintainer-only — template cites it as pre-commit gate)
  </read_first>
  <behavior>
    - File exists at the exact path `.planning/templates/sigstore-rotation-refresh.md`.
    - All 6 SPEC-required sections present and content-bearing (not empty placeholders).
    - References `scripts/verify-trust-root-cached.sh` / `.ps1` as the pre-commit gate (D-49-C3).
    - References `.github/workflows/release.yml`'s byte-identity assert step (Plan 49-02) as the post-commit gate.
    - Mentions DCO sign-off requirement in the commit-and-tag section.
    - Lists 3+ Anti-Patterns specific to fixture refresh (do not commit without smoke script pass; do not ship without bumping a release tag; etc.).
    - Total length: roughly 60-100 lines (comparable to cross-target-verify-checklist.md's 78 lines).
  </behavior>
  <action>
Use the Write tool to create `.planning/templates/sigstore-rotation-refresh.md` with the EXACT content below. The structure mirrors `.planning/templates/cross-target-verify-checklist.md` (which has 78 lines, 8 H2 sections).

```markdown
# Sigstore Trust-Root Rotation Refresh Checklist

**Read this template before committing a refreshed `crates/nono/tests/fixtures/trust-root-frozen.json`.**

**Source:** Phase 49 (Sigstore TUF root rotation resilience, v2.6) — supersedes P32-DEFER-005. Established 2026-05-21 after three recurrences of the `sigstore-verify` embedded-anchor staleness failure (0.6.5 → 0.6.6 → 0.7.0).

---

## Scope

This checklist applies whenever Sigstore announces a TUF root rotation (root signing-key set change). Indicators:
- Sigstore mailing list announcement on https://groups.google.com/g/sigstore-dev.
- Sigstore blog post tagged with "root rotation" or "root signing".
- `sigstore-rs` CI failures on `TrustedRoot::production()` after an upstream key rotation.
- Local POC user report: `nono setup --refresh-trust-root` fails with `Signature threshold of N not met for role root (0 valid signatures)`.

Does NOT apply to:
- `sigstore-verify` minor version bumps that do NOT involve a root rotation (those go through the standard UPST cadence).
- POC user reports of a STALE cache that resolves with a successful `nono setup --refresh-trust-root` (no fixture refresh needed).

## Decision Tree

**Step 1 — Capture the new root.** Fetch the current upstream root:

```bash
curl -L https://raw.githubusercontent.com/sigstore/root-signing/main/repository/trusted_root.json -o /tmp/trusted_root.new.json
```

If `sigstore/root-signing@main` has moved to a different layout, consult the Sigstore blog or `sigstore/cosign` README for the current canonical path. Do NOT capture from a CDN that re-serializes — bytes must round-trip cleanly.

**Step 2 — Byte-diff vs the current frozen fixture.**

```bash
diff -u crates/nono/tests/fixtures/trust-root-frozen.json /tmp/trusted_root.new.json | head -100
```

Inspect the diff. Expect: changed `keyId`, `rawBytes`, `validFor.start` per rotated tlog/CA/CT-log key. If the diff is empty, no refresh needed (the upstream has not rotated since the last capture).

**Step 3 — Replace and run the regression smoke.**

```bash
cp /tmp/trusted_root.new.json crates/nono/tests/fixtures/trust-root-frozen.json
cargo test -p nono trust::bundle::load_test_trusted_root_smoke
```

The `load_test_trusted_root_smoke` test deserializes the fixture and exercises the same code path `nono trust verify` uses. If it fails, the new fixture is malformed at the schema layer — do NOT commit.

**Step 4 — Run the cross-platform smoke script as the pre-commit gate** (D-49-C3):

```bash
# Unix:
./scripts/verify-trust-root-cached.sh crates/nono/tests/fixtures/trust-root-frozen.json

# Windows:
pwsh scripts/verify-trust-root-cached.ps1 crates/nono/tests/fixtures/trust-root-frozen.json
```

Exit 0 confirms `nono setup --from-file <fixture>` succeeds and the cache is populated byte-identically. Non-zero exit means the fixture fails the same fail-closed contract Phase 49-01 enforces — do NOT commit. Re-capture from a clean source.

**Step 5 — Commit, with DCO sign-off:**

```bash
git add crates/nono/tests/fixtures/trust-root-frozen.json
git commit -s -m "chore(trust-root): refresh frozen fixture for Sigstore root rotation <date>"
```

DCO sign-off (`-s`) is mandatory per CLAUDE.md § Coding Standards → Commits. The commit message should reference the Sigstore announcement (mailing-list archive URL or blog post URL) in the body.

**Step 6 — Forward pointer to the release-asset gate.** The next tagged release will run the byte-identity assert at `.github/workflows/release.yml`'s `Generate checksums` step (Phase 49-02). After the release tag is pushed, verify:

```bash
gh release view <tag> --json assets | jq '.assets[].name' | grep trusted_root.json   # asset present
gh release download <tag> -p trusted_root.json
diff trusted_root.json crates/nono/tests/fixtures/trust-root-frozen.json   # exit 0
```

Both gates green = end-to-end provenance chain holds: committed fixture → CI byte-identity assert → release asset → POC user `--from-file`.

## Anti-Patterns (do NOT do)

- **Anti-pattern 1:** Refresh without running the regression smoke in Step 3. A malformed capture (truncated, re-serialized with different whitespace, missing tlog entries) will deserialize-fail at `nono trust verify` time — POC users see the bug, not the maintainer.
- **Anti-pattern 2:** Commit a fixture that the smoke script (`scripts/verify-trust-root-cached.{sh,ps1}`) rejects. The smoke script exercises the same fail-closed contract `nono setup --from-file` enforces; if it rejects the fixture, the fixture is broken.
- **Anti-pattern 3:** Ship a refresh without bumping a release tag. POC users `--from-file` against the GitHub Release asset; if the maintainer commits a new fixture but the most recent release still ships the old one, the release asset is silently stale.
- **Anti-pattern 4:** Skip DCO sign-off. The repo's DCO policy is workspace-wide (CLAUDE.md); commits without `-s` will be rejected by the upstream PR gates.
- **Anti-pattern 5:** Bump `sigstore-verify` as the response to a rotation. This template exists specifically to exit the dep-bump treadmill (Phase 49 D-49-A1 + SPEC.md "out of scope: bumping sigstore-verify"). Dep bumps belong in UPST cadence, not in rotation response.

## Enforcement

This checklist is referenced from:
- `docs/cli/development/windows-poc-handoff.mdx` § Known issue: Sigstore TUF root rotation (Plan 49-03).
- `.github/workflows/release.yml` Generate checksums step inline comment (Plan 49-02).
- Future `/gsd-verify-phase` invocations on phases that touch `crates/nono/tests/fixtures/trust-root-frozen.json` (verifier reads this template before flipping POC-TRUST REQs to VERIFIED).

Established 2026-05-21 by Phase 49 Plan 49-03 (REQ-POC-TRUST-03) — closes the maintainer-cadence gap that left previous rotations as ad-hoc inbox-scrolling exercises.
```

**Step 2: Verify the file passes the grep gates.**

```bash
test -f .planning/templates/sigstore-rotation-refresh.md
grep -c "^## " .planning/templates/sigstore-rotation-refresh.md   # should be >= 4 (Scope / Decision Tree / Anti-Patterns / Enforcement)
grep -q "P32-DEFER-005" .planning/templates/sigstore-rotation-refresh.md   # MUST contain (supersedes reference)
grep -q "verify-trust-root-cached" .planning/templates/sigstore-rotation-refresh.md
grep -q ".github/workflows/release.yml" .planning/templates/sigstore-rotation-refresh.md
grep -q "DCO sign-off\|-s -m\|Signed-off-by" .planning/templates/sigstore-rotation-refresh.md
```
  </action>
  <verify>
    <automated>test -f .planning/templates/sigstore-rotation-refresh.md &amp;&amp; awk 'END { exit (NR &gt;= 60 ? 0 : 1) }' .planning/templates/sigstore-rotation-refresh.md &amp;&amp; grep -q "verify-trust-root-cached" .planning/templates/sigstore-rotation-refresh.md &amp;&amp; grep -q "release.yml" .planning/templates/sigstore-rotation-refresh.md &amp;&amp; grep -q "sign-off\|Signed-off-by" .planning/templates/sigstore-rotation-refresh.md</automated>
  </verify>
  <acceptance_criteria>
    - `test -f .planning/templates/sigstore-rotation-refresh.md` exits 0.
    - `wc -l .planning/templates/sigstore-rotation-refresh.md` returns >= 60 lines.
    - `grep -c "^## " .planning/templates/sigstore-rotation-refresh.md` returns >= 4 (Scope, Decision Tree, Anti-Patterns, Enforcement).
    - `grep -n "Step 1\|Step 2\|Step 3\|Step 4\|Step 5\|Step 6" .planning/templates/sigstore-rotation-refresh.md` returns 6 matches (6-step Decision Tree per SPEC).
    - `grep -q "verify-trust-root-cached" .planning/templates/sigstore-rotation-refresh.md` (smoke-script cross-reference).
    - `grep -q ".github/workflows/release.yml" .planning/templates/sigstore-rotation-refresh.md` (release-asset gate forward pointer).
    - `grep -q "sigstore/root-signing@main\|sigstore/root-signing" .planning/templates/sigstore-rotation-refresh.md` (capture-command source per RESEARCH.md).
    - `grep -q "sign-off\|Signed-off-by\|DCO" .planning/templates/sigstore-rotation-refresh.md` (DCO mandate per CLAUDE.md).
    - `grep -q "P32-DEFER-005" .planning/templates/sigstore-rotation-refresh.md` (supersedes reference).
    - `grep -c "Anti-pattern" .planning/templates/sigstore-rotation-refresh.md` returns >= 3 (Anti-Patterns section has multiple entries).
    - Validates: F-03-01.
  </acceptance_criteria>
  <done>
    Template exists at `.planning/templates/sigstore-rotation-refresh.md` with all 6 SPEC-required sections, references both the smoke script (Plan 49-03) and the release-asset gate (Plan 49-02), and mandates DCO sign-off.
  </done>
</task>

<task type="auto" tdd="false">
  <name>Task 2: Create matched `scripts/verify-trust-root-cached.sh` + `.ps1` smoke scripts</name>
  <files>scripts/verify-trust-root-cached.sh, scripts/verify-trust-root-cached.ps1</files>
  <read_first>
    - scripts/build-windows-msi.ps1 (skim — prior-art `.ps1` with `$LASTEXITCODE` handling)
    - scripts/sign-windows-artifacts.ps1 (skim — second `.ps1` prior-art)
    - scripts/check-upstream-drift.sh (skim — prior-art `.sh` shape)
    - scripts/test-linux.sh (skim — second `.sh` prior-art)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md § "REQ-POC-TRUST-03 -> Smoke script signature" (lines 407-462)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-PATTERNS.md § "scripts/verify-trust-root-cached.sh" + ".ps1" (lines 154-180)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-CONTEXT.md D-49-C1 (matched .sh + .ps1 pair, ~20 lines each), D-49-C2 (smoke inputs reuse existing fixtures), D-49-C3 (maintainer-only, NOT wired into PR CI)
  </read_first>
  <behavior>
    - Both scripts take ONE positional argument: path to a candidate `trusted_root.json`.
    - Both scripts:
      1. Validate the arg (exists, readable).
      2. Create a per-invocation temp dir (and clean up on exit).
      3. Set `NONO_TEST_HOME` + `XDG_CONFIG_HOME` to the temp dir.
      4. Invoke `nono setup --from-file <CANDIDATE>` — must exit 0.
      5. Assert the cache file at `$TMP/.nono/trust-root/trusted_root.json` exists.
      6. Assert the cache file is byte-identical to the candidate (`cmp` on Unix, `Compare-Object` or hash-compare on Windows).
      7. Exit 0 on full pass; exit non-zero on any failure with a clear stderr message.
    - `.sh`: `set -euo pipefail` at top.
    - `.ps1`: `$ErrorActionPreference = 'Stop'` + explicit `$LASTEXITCODE` check after EVERY native command invocation (F-03-05 mitigation).
    - `.sh` has executable bit set via `git update-index --chmod=+x`.
    - The scripts do NOT invoke `nono trust verify` — that requires a hermetic signed-file fixture that doesn't exist in the repo. The template documents the manual post-smoke `nono trust verify` step as the maintainer's responsibility.
  </behavior>
  <action>
**Step 1: Create `scripts/verify-trust-root-cached.sh` with the EXACT content:**

```bash
#!/usr/bin/env bash
# Phase 49 REQ-POC-TRUST-03: Sigstore trusted-root cache smoke script.
#
# Usage:
#   scripts/verify-trust-root-cached.sh <path-to-candidate-trusted_root.json>
#
# Validates that `nono setup --from-file <CANDIDATE>` succeeds and produces
# a cache file byte-identical to the input. Exits 0 on success; non-zero
# on any failure. Maintainer-only (D-49-C3) — not wired into PR CI.
#
# Pre-commit gate for `.planning/templates/sigstore-rotation-refresh.md`
# Step 4. See that template for the full rotation-response procedure.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <path-to-candidate-trusted_root.json>" >&2
  exit 2
fi

CANDIDATE="$1"
if [ ! -f "$CANDIDATE" ]; then
  echo "ERROR: candidate path does not exist or is not a file: $CANDIDATE" >&2
  exit 2
fi

TMP=$(mktemp -d -t nono-trust-root-smoke-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
export NONO_TEST_HOME="$TMP"
export XDG_CONFIG_HOME="$TMP"
export NONO_NO_UPDATE_CHECK=1

echo "Running: nono setup --from-file $CANDIDATE"
nono setup --from-file "$CANDIDATE"

CACHE="$TMP/.nono/trust-root/trusted_root.json"
if [ ! -f "$CACHE" ]; then
  echo "ERROR: cache file was not created at $CACHE" >&2
  exit 1
fi

if ! cmp -s "$CANDIDATE" "$CACHE"; then
  echo "ERROR: cache file is not byte-identical to candidate" >&2
  echo "  candidate: $CANDIDATE" >&2
  echo "  cache:     $CACHE" >&2
  exit 1
fi

echo "PASS: $CANDIDATE accepted by 'nono setup --from-file' and cache is byte-identical."
```

After writing, set the executable bit:

```bash
git update-index --add --chmod=+x scripts/verify-trust-root-cached.sh
```

(Or `chmod +x scripts/verify-trust-root-cached.sh` then `git add` if the executor is on Windows and `git update-index --chmod=+x` is the cleaner cross-platform path.)

**Step 2: Create `scripts/verify-trust-root-cached.ps1` with the EXACT content:**

```powershell
#Requires -Version 5.1
# Phase 49 REQ-POC-TRUST-03: Sigstore trusted-root cache smoke script (Windows).
#
# Usage:
#   pwsh scripts/verify-trust-root-cached.ps1 <path-to-candidate-trusted_root.json>
#
# Validates that `nono setup --from-file <CANDIDATE>` succeeds and produces
# a cache file byte-identical to the input. Exits 0 on success; non-zero
# on any failure. Maintainer-only (D-49-C3) — not wired into PR CI.
#
# Pre-commit gate for .planning/templates/sigstore-rotation-refresh.md
# Step 4. See that template for the full rotation-response procedure.

param(
    [Parameter(Mandatory=$true)]
    [string]$Candidate
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
    Write-Error "candidate path does not exist or is not a file: $Candidate"
    exit 2
}

$tmpName = "nono-trust-root-smoke-" + [System.Guid]::NewGuid().ToString("N").Substring(0,8)
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP $tmpName) -Force

try {
    $env:NONO_TEST_HOME = $tmp.FullName
    $env:XDG_CONFIG_HOME = $tmp.FullName
    $env:NONO_NO_UPDATE_CHECK = '1'

    Write-Host "Running: nono setup --from-file $Candidate"
    & nono setup --from-file $Candidate
    if ($LASTEXITCODE -ne 0) {
        throw "nono setup --from-file failed with exit code $LASTEXITCODE"
    }

    $cache = Join-Path $tmp.FullName ".nono\trust-root\trusted_root.json"
    if (-not (Test-Path -LiteralPath $cache -PathType Leaf)) {
        throw "cache file was not created at $cache"
    }

    $candHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Candidate).Hash
    $cacheHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $cache).Hash
    if ($candHash -ne $cacheHash) {
        throw "cache file is not byte-identical to candidate; candidate=$candHash cache=$cacheHash"
    }

    Write-Host "PASS: $Candidate accepted by 'nono setup --from-file' and cache is byte-identical (SHA-256: $candHash)."
    exit 0
}
catch {
    Write-Error $_
    exit 1
}
finally {
    if ($tmp -and (Test-Path -LiteralPath $tmp.FullName)) {
        Remove-Item -Recurse -Force -LiteralPath $tmp.FullName -ErrorAction SilentlyContinue
    }
}
```

**Step 3: Verify executable bit on `.sh`:**

```bash
git ls-files -s scripts/verify-trust-root-cached.sh
# Output should start with "100755" (executable). If "100644", run:
#   git update-index --chmod=+x scripts/verify-trust-root-cached.sh
```

**Step 4: Static syntax checks:**

```bash
bash -n scripts/verify-trust-root-cached.sh   # bash parse syntax check
```

If `shellcheck` is available:
```bash
shellcheck -s bash scripts/verify-trust-root-cached.sh
```

If PowerShell available (`pwsh` or Windows PowerShell):
```bash
pwsh -NoProfile -Command "[scriptblock]::Create((Get-Content -Raw scripts/verify-trust-root-cached.ps1)) | Out-Null; if ($?) { 'ps1 syntax OK' }"
```

PARTIAL allowed for shellcheck or PSScriptAnalyzer if not installed — record in SUMMARY.

**Step 5: Optional positive self-test (only if Plan 49-01 has landed on the same branch — otherwise skip and document deferral):**

```bash
./scripts/verify-trust-root-cached.sh crates/nono/tests/fixtures/trust-root-frozen.json
# Expected output: "PASS: <abs_path> accepted by 'nono setup --from-file' and cache is byte-identical."
echo $?   # 0
```

If Plan 49-01 has NOT yet landed, the `nono setup --from-file` invocation will fail with clap "unknown argument" — that's expected. Document in SUMMARY that the smoke-script self-test is deferred to the wave-close integration check.
  </action>
  <verify>
    <automated>test -f scripts/verify-trust-root-cached.sh &amp;&amp; test -f scripts/verify-trust-root-cached.ps1 &amp;&amp; bash -n scripts/verify-trust-root-cached.sh &amp;&amp; [ "$(grep -c 'LASTEXITCODE' scripts/verify-trust-root-cached.ps1)" -ge 1 ] &amp;&amp; grep -q "set -euo pipefail" scripts/verify-trust-root-cached.sh &amp;&amp; grep -q "ErrorActionPreference = 'Stop'" scripts/verify-trust-root-cached.ps1 &amp;&amp; awk 'END { exit (NR &gt;= 15 ? 0 : 1) }' scripts/verify-trust-root-cached.sh &amp;&amp; awk 'END { exit (NR &gt;= 15 ? 0 : 1) }' scripts/verify-trust-root-cached.ps1</automated>
  </verify>
  <acceptance_criteria>
    - `test -f scripts/verify-trust-root-cached.sh` exits 0.
    - `test -f scripts/verify-trust-root-cached.ps1` exits 0.
    - `git ls-files -s scripts/verify-trust-root-cached.sh | awk '{print $1}'` returns `100755` (executable bit set per F-03-02).
    - `bash -n scripts/verify-trust-root-cached.sh` exits 0 (valid bash syntax).
    - `grep -q "set -euo pipefail" scripts/verify-trust-root-cached.sh` (F-03-05-equivalent for bash).
    - `grep -q "ErrorActionPreference = 'Stop'" scripts/verify-trust-root-cached.ps1`.
    - `grep -c "LASTEXITCODE" scripts/verify-trust-root-cached.ps1` returns >= 1 (F-03-05 — at minimum one explicit check after the `nono setup` invocation; the rest are guarded by `$ErrorActionPreference = 'Stop'` + PowerShell exceptions from `Test-Path` / `Get-FileHash` / `throw`).
    - `grep -q "cmp -s\|cmp -s " scripts/verify-trust-root-cached.sh` (byte-identity check via `cmp`).
    - `grep -q "Get-FileHash" scripts/verify-trust-root-cached.ps1` (byte-identity via SHA-256 hash compare).
    - `grep -q "trap.*rm -rf" scripts/verify-trust-root-cached.sh` (TempDir cleanup on exit).
    - `grep -q "finally" scripts/verify-trust-root-cached.ps1` (try/finally TempDir cleanup).
    - `wc -l scripts/verify-trust-root-cached.sh` returns >= 15 (~40 lines including comments).
    - `wc -l scripts/verify-trust-root-cached.ps1` returns >= 15 (~50 lines including comments).
    - Validates: F-03-02 (file existence + executable bit), F-03-05 (PowerShell exit-code propagation).
  </acceptance_criteria>
  <done>
    Both smoke scripts exist with the prescribed shape; `.sh` has executable bit set; `.ps1` checks `$LASTEXITCODE` after the `nono setup` native command; bash syntax valid; cleanup-on-exit handlers present.
  </done>
</task>

<task type="auto" tdd="false">
  <name>Task 3: Rewrite `Known issue` subsection in `docs/cli/development/windows-poc-handoff.mdx`</name>
  <files>docs/cli/development/windows-poc-handoff.mdx</files>
  <read_first>
    - docs/cli/development/windows-poc-handoff.mdx (lines 160-234 — the current `Run once after install` block + Known issue subsection that gets rewritten)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md § "REQ-POC-TRUST-03 -> POC handoff doc rewrite source" (lines 464-477) — enumerates all 5 stale lines with replacement guidance
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-PATTERNS.md § "docs/cli/development/windows-poc-handoff.mdx" (lines 122-133)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-SPEC.md REQ-POC-TRUST-03 Target (c) + Acceptance (c)/(d)/(e)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-CONTEXT.md Claude's Discretion: "POC-handoff docs rewrite scope" (lines 117-118)
  </read_first>
  <behavior>
    - The "Run once after install" block at lines 166-180 (current state) ADDS a parenthetical mention of `nono setup --from-file <PATH>` as an alternative path; keeps `--refresh-trust-root` as the primary recommendation for network-reachable hosts (F-03-04 mitigation).
    - The `Known issue: Sigstore TUF root rotation (sigstore-verify 0.6.5)` H4 heading at line 182 is rewritten to remove the `(sigstore-verify 0.6.5)` version pin → just `Known issue: Sigstore TUF root rotation`.
    - The body of the Known issue subsection (lines 184-221) is rewritten to:
      1. Keep the ERROR-block example (the actual error POC users see).
      2. Replace dep-treadmill prose with structural-fix prose pointing at `nono setup --from-file` as the primary recovery path.
      3. The primary recommended block is now: download from the GitHub Release asset URL, then `nono setup --from-file <downloaded.json>`.
      4. The `Invoke-WebRequest` direct-into-cache block is demoted to a "if you can't reach github.com/releases" fallback subsection.
      5. The `P32-DEFER-005` / `deferred-items.md` comment in the workaround block is REPLACED with a reference to Phase 49 and `.planning/templates/sigstore-rotation-refresh.md`.
      6. The "will start working again once the dep is upgraded" prose at line 218 is DELETED entirely.
    - After the rewrite, the doc has ZERO matches for `sigstore-verify 0.6.5`, `P32-DEFER-005`, and `deferred-items.md`.
    - Other sections of the doc (Step 5 WFP service, broker.exe verification, etc.) are UNTOUCHED — scope creep avoided.
  </behavior>
  <action>
**Step 1: Read the current state of lines 160-234** to confirm the exact text being replaced. The Read tool was already used in `<read_first>`; verify the literals match the targeted edits below.

**Step 2: Apply the rewrite via the Edit tool.** The rewrite is in two parts:

**Part A — Rewrite the "Run once after install" block (lines 166-180).** Find the text:

```
Run once after install:

```powershell
nono setup --refresh-trust-root
```

The command fetches TUF metadata from `https://tuf-repo-cdn.sigstore.dev` and
writes the verified trusted root to your per-user cache. Subsequent keyless
`nono trust verify` invocations run offline against that cache.
```

(The triple-backtick fences in markdown source — preserve them.)

Replace with:

```
Run once after install (pick ONE of the two):

```powershell
# Path A — for hosts with reachable network to https://tuf-repo-cdn.sigstore.dev:
nono setup --refresh-trust-root

# Path B — for offline / network-restricted hosts (or when Path A fails with a
# stale-embedded-anchor error per the Known issue section below):
#   1. Download the trusted_root.json release asset from the GitHub Releases page.
#   2. Hand the local path to --from-file.
nono setup --from-file C:\path\to\downloaded\trusted_root.json
```

Either path writes a verified trusted root to your per-user cache. Subsequent
keyless `nono trust verify` invocations run offline against that cache.
```

**Part B — Rewrite the `Known issue` subsection (lines 182-221).** Find the entire block from `#### Known issue: Sigstore TUF root rotation (sigstore-verify 0.6.5)` through (and including) the closing paragraph at line 221 (`...the manual file drop is the supported workaround for POC use.`).

Replace with:

```
#### Known issue: Sigstore TUF root rotation

If `nono setup --refresh-trust-root` fails with:

```
ERROR Setup error: Failed to fetch Sigstore trusted root from
  https://tuf-repo-cdn.sigstore.dev: TUF error: TUF repository load failed:
  Failed to verify trusted root metadata:
  Signature threshold of 3 not met for role root (0 valid signatures)
```

…then your binary is hitting a Sigstore TUF root rotation. Sigstore periodically
rotates the root signing keys; once `sigstore-verify`'s embedded trust anchor
loses all of its valid keys against the published `root.json`, every
`--refresh-trust-root` invocation fails until the dep ships a new anchor.

The verify path is structurally offline (Phase 32 D-32-15), so a manually-placed
`trusted_root.json` works around this without waiting on the dep. Phase 49 ships
two supported recovery paths in priority order.

**Primary path — `nono setup --from-file` against the release-asset
`trusted_root.json`:**

1. Open the most recent GitHub Release for the fork:
   `https://github.com/oscarmackjr-twg/nono/releases/latest`
2. Download `trusted_root.json` from the release assets list (sibling to `nono.exe`).
3. Run:

```powershell
nono setup --from-file C:\path\to\downloaded\trusted_root.json
```

The flag validates the JSON (schema + tlog freshness gate, same code path
`nono trust verify` uses) and writes a byte-identical copy to your per-user
cache. The asset is covered by the release-integrity gate in `SHA256SUMS.txt`
(Phase 49-02 release-workflow change).

**Fallback path — direct `Invoke-WebRequest` into the cache directory:**

If you cannot reach `github.com/releases` (network-restricted host, offline
POC environment), capture the fixture directly from the fork's repository:

```powershell
# Phase 49 ships --from-file as the supported path; this Invoke-WebRequest
# fallback remains for hosts that cannot reach the GitHub Releases page.
# Maintainer-cadence procedure for refreshing the upstream fixture lives at
# .planning/templates/sigstore-rotation-refresh.md.
$cacheDir = "$env:USERPROFILE\.nono\trust-root"
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
Invoke-WebRequest -UseBasicParsing `
  -Uri "https://raw.githubusercontent.com/oscarmackjr-twg/nono/main/crates/nono/tests/fixtures/trust-root-frozen.json" `
  -OutFile "$cacheDir\trusted_root.json"
```

After either path, `nono trust verify` with `--issuer` + `--identity` works
offline against the cached file. `nono setup --check-only` should report
`Trust root cache: OK` once the file is in place.
```

(Use the Edit tool with the EXACT current text as `old_str` and the new text as `new_str`. If a single Edit call cannot capture the full block due to size, split into two consecutive Edit calls — first for the Run once block, then for the Known issue subsection.)

**Step 3: Verify negative-grep (zero matches for stale references):**

```bash
! grep -E '(sigstore-verify 0\.6\.5|P32-DEFER-005|deferred-items\.md)' docs/cli/development/windows-poc-handoff.mdx
# Above must exit 0 (no matches).
```

If ANY match remains, locate it via:
```bash
grep -nE '(sigstore-verify 0\.6\.5|P32-DEFER-005|deferred-items\.md)' docs/cli/development/windows-poc-handoff.mdx
```
…and remove the offending line.

**Step 4: Verify positive-grep (new `--from-file` references):**

```bash
grep -A 8 'Run once after install' docs/cli/development/windows-poc-handoff.mdx | grep -q -- '--from-file'   # F-03-04
grep -A 30 '#### Known issue: Sigstore TUF root rotation' docs/cli/development/windows-poc-handoff.mdx | grep -q 'nono setup --from-file'
```

Both must exit 0.

**Step 5: Verify `sigstore-rotation-refresh.md` reference exists in the doc:**

```bash
grep -q 'sigstore-rotation-refresh' docs/cli/development/windows-poc-handoff.mdx
```

(This is in the `Invoke-WebRequest` fallback's comment — it's the doc → template forward pointer.)

**Step 6: Confirm no other doc sections were touched:**

```bash
git diff --stat docs/cli/development/windows-poc-handoff.mdx   # one file
git diff docs/cli/development/windows-poc-handoff.mdx | grep -c "^[+-]"   # bounded line-count
```

Expected: only `windows-poc-handoff.mdx` modified; the diff is bounded to the two regions identified (Run once block + Known issue subsection), no surprise edits elsewhere.
  </action>
  <verify>
    <automated>! grep -E '(sigstore-verify 0\.6\.5|P32-DEFER-005|deferred-items\.md)' docs/cli/development/windows-poc-handoff.mdx &amp;&amp; grep -A 8 'Run once after install' docs/cli/development/windows-poc-handoff.mdx | grep -q -- '--from-file' &amp;&amp; grep -A 30 '#### Known issue: Sigstore TUF root rotation' docs/cli/development/windows-poc-handoff.mdx | grep -q 'nono setup --from-file' &amp;&amp; grep -q 'sigstore-rotation-refresh' docs/cli/development/windows-poc-handoff.mdx</automated>
  </verify>
  <acceptance_criteria>
    - `grep -E '(sigstore-verify 0\.6\.5|P32-DEFER-005|deferred-items\.md)' docs/cli/development/windows-poc-handoff.mdx` exits 1 (no matches — F-03-03).
    - `grep -A 8 'Run once after install' docs/cli/development/windows-poc-handoff.mdx | grep -q -- '--from-file'` exits 0 (F-03-04).
    - `grep -A 30 '#### Known issue: Sigstore TUF root rotation' docs/cli/development/windows-poc-handoff.mdx | grep -q 'nono setup --from-file'` exits 0 (primary recommendation mentions --from-file).
    - `grep -c '#### Known issue: Sigstore TUF root rotation' docs/cli/development/windows-poc-handoff.mdx` returns exactly 1 (heading exists exactly once, with no version pin).
    - `grep -q 'sigstore-rotation-refresh' docs/cli/development/windows-poc-handoff.mdx` (forward pointer to the new template).
    - `git diff --stat docs/cli/development/windows-poc-handoff.mdx | awk '/files? changed/ { print $1 }'` returns `1`.
    - No other .mdx files in `docs/` were modified.
    - Validates: F-03-03 (zero stale references), F-03-04 (--from-file mentioned near Run once block).
  </acceptance_criteria>
  <done>
    `docs/cli/development/windows-poc-handoff.mdx` no longer references `sigstore-verify 0.6.5`, `P32-DEFER-005`, or `deferred-items.md`; the Run once block mentions `--from-file`; the Known issue subsection recommends `--from-file` as primary with `Invoke-WebRequest` as fallback; the new `sigstore-rotation-refresh.md` template is referenced.
  </done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <name>Task 4: Manual `.ps1` exit-code propagation check on a real Windows host</name>
  <what-built>Task 2 created `scripts/verify-trust-root-cached.ps1` with explicit `$LASTEXITCODE` checks after `nono setup --from-file` (F-03-05 mitigation). PowerShell native-command failures do NOT throw exceptions even when `$ErrorActionPreference = 'Stop'` is set, so the `$LASTEXITCODE` check is the only mechanism that catches a failed `nono setup` and propagates the failure to the script's exit code.</what-built>
  <how-to-verify>
1. On a Windows host with `nono.exe` on PATH (or with the freshly-built `target/debug/nono.exe`):
   ```powershell
   # Positive test (requires Plan 49-01 landed):
   pwsh scripts/verify-trust-root-cached.ps1 crates\nono\tests\fixtures\trust-root-frozen.json
   echo $LASTEXITCODE   # must be 0
   ```
2. Negative test (always works regardless of Plan 49-01 status):
   ```powershell
   pwsh scripts/verify-trust-root-cached.ps1 C:\does-not-exist.json
   echo $LASTEXITCODE   # must be 2 (the param-validation early-exit)
   ```
3. Negative test (Plan 49-01 dependent — simulates a broken `nono setup`):
   - If Plan 49-01 has NOT landed: `nono.exe` will reject `--from-file` at clap-parse time with exit code != 0; the smoke script must propagate this and exit non-zero.
   ```powershell
   pwsh scripts/verify-trust-root-cached.ps1 crates\nono\tests\fixtures\trust-root-frozen.json
   echo $LASTEXITCODE   # must be 1 (the script's `throw` after $LASTEXITCODE check)
   ```
4. If positive (1) returns 0, negative (2) returns 2, and the dependent negative (3) returns 1 — the F-03-05 mitigation works. Reply `clean`.
5. If any positive returns non-zero OR any negative returns 0 — F-03-05 is failing. Reply with the actual exit codes observed.

If no Windows host is available, mark this verification PARTIAL per VALIDATION.md § Manual-Only. Reply `PARTIAL: no Windows host available`.
  </how-to-verify>
  <resume-signal>Type `clean`, `PARTIAL: no Windows host`, or paste the actual exit codes observed.</resume-signal>
  <files>scripts/verify-trust-root-cached.ps1 (read-only - verification target)</files>
  <action>Execute the three exit-code scenarios from the &lt;how-to-verify&gt; block above on a Windows host with `nono.exe` available (either on PATH or via the freshly-built target\debug
ono.exe). Record exit codes for: (1) positive run against `crates/nono/tests/fixtures/trust-root-frozen.json` - expect 0 IF Plan 49-01 has landed, otherwise expect 1; (2) param-validation early-exit against `C:\does-not-exist.json` - expect 2 (always); (3) Plan 49-01-dependent failure-propagation check - expect 1 when `nono setup --from-file` fails. If no Windows host is available, document PARTIAL and defer to a Windows-host follow-up. Do NOT mark F-03-05 closed without either positive-host signal or formal PARTIAL.</action>
  <verify>
    <automated>grep -c "LASTEXITCODE" scripts/verify-trust-root-cached.ps1 | awk '$1 &gt;= 1 { exit 0 } { exit 1 }'</automated>
  </verify>
  <done>At minimum: the `grep -c LASTEXITCODE` check passes (proves the explicit-check is statically present in the script). Optimally: one of (a) Windows-host live exit-code verification produces the expected 0/2/1 triple, OR (b) PARTIAL recorded with explicit Windows-host follow-up deferral.</done>
  <acceptance_criteria>
    - At least the two host-independent checks attempted: param-validation early-exit returns exit 2; bash-extracted PowerShell syntax via `pwsh -NoProfile -Command "..."` is parseable.
    - If a Windows host is available: all three exit-code scenarios match the expected values (0, 2, 1).
    - If no Windows host: PARTIAL recorded with explicit deferral to a Windows-host follow-up.
    - Validates: F-03-05.
  </acceptance_criteria>
</task>

</tasks>

<verification>
- File existence: `test -f .planning/templates/sigstore-rotation-refresh.md` + both `scripts/verify-trust-root-cached.{sh,ps1}`.
- Executable bit on `.sh`: `git ls-files -s scripts/verify-trust-root-cached.sh` shows `100755`.
- Bash syntax: `bash -n scripts/verify-trust-root-cached.sh` exits 0.
- PowerShell exit-code propagation: `grep -c LASTEXITCODE scripts/verify-trust-root-cached.ps1 >= 1`; Task 4 manual run.
- Negative-grep on doc: zero matches for `sigstore-verify 0.6.5`, `P32-DEFER-005`, `deferred-items.md`.
- Positive-grep on doc: `--from-file` appears near `Run once after install`; `sigstore-rotation-refresh` appears in the fallback comment.
- Diff scope bounded to 4 files (3 new + 1 modified).
- shellcheck / PSScriptAnalyzer / yamllint either pass or document PARTIAL.

Manual-Only (per VALIDATION.md):
- `.ps1` smoke script on a Windows host (Task 4 checkpoint).
- POC-handoff prose-quality review (reviewer reads the rewritten subsection).
- Cadence template followed on the next real Sigstore root rotation event.
</verification>

<success_criteria>
- [ ] `.planning/templates/sigstore-rotation-refresh.md` exists with the 6 mandated sections + references to smoke scripts + release.yml + DCO sign-off (F-03-01).
- [ ] `scripts/verify-trust-root-cached.sh` exists, has executable bit set, passes `bash -n`, uses `set -euo pipefail` (F-03-02).
- [ ] `scripts/verify-trust-root-cached.ps1` exists, references `$LASTEXITCODE` at least once explicitly after the `nono setup` native command (F-03-05).
- [ ] `docs/cli/development/windows-poc-handoff.mdx` has ZERO matches for `sigstore-verify 0.6.5`, `P32-DEFER-005`, `deferred-items.md` (F-03-03).
- [ ] `docs/cli/development/windows-poc-handoff.mdx` mentions `--from-file` within 8 lines of `Run once after install` (F-03-04).
- [ ] `docs/cli/development/windows-poc-handoff.mdx` mentions `--from-file` as the primary recommendation inside the rewritten Known issue subsection.
- [ ] `docs/cli/development/windows-poc-handoff.mdx` references the new `.planning/templates/sigstore-rotation-refresh.md` template (forward pointer).
- [ ] No other files in `docs/` modified beyond `windows-poc-handoff.mdx`.
- [ ] DCO sign-off on commits.
</success_criteria>

<commit_shape>
Planner picks: ONE atomic `docs(49-03):` commit OR three split commits (template / scripts / docs rewrite). Per D-49-A1 + Claude's Discretion on per-plan commit shape, both are acceptable. Recommendation: ONE atomic commit unless the reviewer prefers per-file scope.

Single atomic option:
```
docs(49-03): sigstore rotation cadence + smoke scripts + POC handoff rewrite

Phase 49 REQ-POC-TRUST-03. Ship three artifacts that operationalize the
Sigstore trust-root rotation response so future rotations require only a
fixture refresh (per the new cadence template), not a sigstore-verify
Cargo.toml bump.

1. .planning/templates/sigstore-rotation-refresh.md — 6-step maintainer
   procedure mirroring the cross-target-verify-checklist.md shape:
   trigger sources, capture command, byte-diff, regression test, smoke
   gate, commit-and-tag with DCO. References Plan 49-02 release.yml
   byte-identity assert as the post-commit gate. Supersedes P32-DEFER-005.

2. scripts/verify-trust-root-cached.{sh,ps1} — matched cross-platform
   smoke scripts wrapping `nono setup --from-file <PATH>` + byte-identity
   cache check. Maintainer-only (D-49-C3), not wired into PR CI. .ps1
   uses explicit $LASTEXITCODE checks after every native command
   invocation to avoid PowerShell's native-command silent-failure mode
   (F-03-05).

3. docs/cli/development/windows-poc-handoff.mdx — rewrite the "Known
   issue: Sigstore TUF root rotation" subsection to recommend
   `nono setup --from-file` against the release-asset URL (Plan 49-02)
   as the primary recovery path; demote the Invoke-WebRequest direct-
   into-cache block to a fallback for network-restricted hosts. Removes
   the stale `sigstore-verify 0.6.5` version pin, the broken
   `P32-DEFER-005` / `deferred-items.md` cross-reference, and the
   dep-treadmill prose ("will start working again once the dep is
   upgraded").

Live-host verifications (PowerShell exit-code propagation; cadence
follow-through on the next rotation) recorded as Manual-Only per
VALIDATION.md.

Signed-off-by: Oscar Mack Jr. <oscar.mack.jr@gmail.com>
```
</commit_shape>

<output>
After completion, create `.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-03-SUMMARY.md` per the summary template. Required sections:
- Verification: per-task automated commands run + outcomes + Manual-Only deferrals.
- PowerShell exit-code check: clean / PARTIAL with explicit Windows-host deferral if applicable.
- Files modified: 4 (1 new template + 2 new scripts + 1 modified .mdx).
- Diff scope: bounded — only the 4 files; no other doc / script edits.
- Commit SHA(s): single atomic OR three split commits per planner choice.
</output>
