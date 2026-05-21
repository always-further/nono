---
phase: 49
plan: 02
type: execute
wave: 1
depends_on: []
files_modified:
  - .github/workflows/release.yml
autonomous: true
requirements: [REQ-POC-TRUST-02]
tags: [sigstore, trust-root, ci, release, packaging]
must_haves:
  truths:
    - "`crates/nono/tests/fixtures/trust-root-frozen.json` is byte-identical to the `trusted_root.json` release asset at every release tag"
    - "Release CI fails (non-zero exit) on byte-identity mismatch — the gate is asserted, not contractual"
    - "`artifacts/trusted_root.json` appears in the `softprops/action-gh-release` `files:` glob"
    - "`SHA256SUMS.txt` includes a `trusted_root.json` line"
    - "The new CI step uses `set -euo pipefail` (no silent-pass on `cut` pipe failures)"
  artifacts:
    - path: ".github/workflows/release.yml"
      provides: "Release pipeline that ships trusted_root.json as a release asset alongside nono / nono.exe"
      contains: "trusted_root.json"
  key_links:
    - from: ".github/workflows/release.yml::Generate checksums step"
      to: "crates/nono/tests/fixtures/trust-root-frozen.json"
      via: "cp + sha256sum byte-identity assert"
      pattern: "trust-root-frozen.json"
    - from: ".github/workflows/release.yml::Create GitHub Release step"
      to: "artifacts/trusted_root.json"
      via: "softprops/action-gh-release files: glob"
      pattern: "artifacts/trusted_root.json"
---

<objective>
Extend `.github/workflows/release.yml` so every GitHub Release ships `trusted_root.json` as a sibling asset alongside `nono` / `nono.exe` binaries, with a CI-asserted SHA-256 byte-identity gate between the source fixture (`crates/nono/tests/fixtures/trust-root-frozen.json`) and the released asset.

Purpose: Complete the end-to-end provenance chain for REQ-POC-TRUST-02 — what the maintainer commits to the frozen fixture is what CI uploads, is what POC users download and `--from-file` (Plan 49-01). Without this gate, the byte-identity claim is contractual prose; with this gate, it is mechanically enforced.

Output: Three minimal-diff insertions in the existing `release.yml`'s `release` job: (1) `cp` + `sha256sum` byte-identity assert inside the existing `Generate checksums` step, (2) conditional `sha256sum trusted_root.json >> SHA256SUMS.txt` in the aggregation block, (3) `artifacts/trusted_root.json` line in the `softprops/action-gh-release` `files:` glob.

Implements: REQ-POC-TRUST-02 (per D-49-A1).
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
@CLAUDE.md

<interfaces>
<!-- Current .github/workflows/release.yml release-job shape (verified at execute-time). -->

From `.github/workflows/release.yml:308-326` (the `Generate checksums` step — the working directory is `artifacts/` because the step's first command is `cd artifacts`):
```
      - name: Generate checksums
        run: |
          cd artifacts
          find . -name "*.tar.gz" -exec mv {} . \;
          find . -name "*.zip" -exec mv {} . \;
          find . -name "*.msi" -exec mv {} . \;
          find . -name "*.exe" -exec mv {} . \;
          find . -name "*.deb" -exec mv {} . \;
          sha256sum *.tar.gz > SHA256SUMS.txt
          if ls *.zip >/dev/null 2>&1; then
            sha256sum *.zip >> SHA256SUMS.txt
          fi
          ...
          cat SHA256SUMS.txt
```

**Working directory note (load-bearing per F-02-05):** the step uses `cd artifacts` at the top, so all subsequent paths are relative to `artifacts/`. The source fixture lives at `crates/nono/tests/fixtures/trust-root-frozen.json` from REPO ROOT — that path becomes `../crates/nono/tests/fixtures/trust-root-frozen.json` once `cd artifacts` has run. Plan 49-02 inserts the cp/assert INSIDE this `cd artifacts`-scoped block.

From `.github/workflows/release.yml:328-340` (the `Create GitHub Release` step `files:` glob):
```
      - name: Create GitHub Release
        uses: softprops/action-gh-release@153bb8e04406b158c6c84fc1615b65b24149a1fe # v2
        with:
          tag_name: ${{ env.RELEASE_TAG }}
          draft: false
          generate_release_notes: true
          files: |
            artifacts/*.tar.gz
            artifacts/*.zip
            artifacts/*.msi
            artifacts/*.exe
            artifacts/*.deb
            artifacts/SHA256SUMS.txt
```

The `files:` glob runs from REPO ROOT (default working directory; `softprops/action-gh-release` does not honor the prior step's `cd`). The new entry `artifacts/trusted_root.json` is repo-root-relative.

From `crates/nono/tests/fixtures/trust-root-frozen.json` — 126-line JSON, 6.6 KB; the byte-identity source.
</interfaces>
</context>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Repo fixture -> release asset | Bytes flow from `crates/nono/tests/fixtures/trust-root-frozen.json` at the release-tag commit through the CI runner's `artifacts/` working directory to GitHub Release storage. |
| Release asset -> POC user | POC users download `trusted_root.json` from `https://github.com/.../releases/download/<tag>/trusted_root.json` and feed it into `nono setup --from-file <PATH>`. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-49-04 | Tampering | maintainer-side leak (release asset not byte-identical to committed fixture) | mitigate | Step 1 inserts `sha256sum SRC` + `sha256sum DST` + explicit equality check inside the same job that builds the release asset, BEFORE `softprops/action-gh-release` runs. Any drift exits the job non-zero. F-02-01. |
| T-49-04b | Tampering | release-asset omission (asset built but not uploaded) | mitigate | Step 3 adds `artifacts/trusted_root.json` to the `files:` glob; `gh release view <tag> --json assets` post-tag confirms presence. F-02-02. |
| T-49-04c | Tampering | hash omission from `SHA256SUMS.txt` (asset uploaded but not covered by the existing release-integrity gate) | mitigate | Step 2 extends the SHA256SUMS aggregation. POC users running `sha256sum -c SHA256SUMS.txt` against downloaded assets get a covered check for `trusted_root.json`. F-02-03. |
| T-49-06 | CI silent-pass | the new CI step exits 0 on internal failure (e.g., `sha256sum \| cut` pipe failure masks the hash) | mitigate | Top of the new block sets `set -euo pipefail` — required per F-02-04. Bare `if [ ... ]` returns 0 on syntax errors without `-e`; `\| cut` masks failures without `-o pipefail`. |
| T-49-07 | Working-dir mismatch | `cp` runs from one cwd, `sha256sum` runs from another, paths don't compose | mitigate | Step 1 is folded INSIDE the existing `cd artifacts`-scoped block; source path becomes `../crates/nono/tests/fixtures/trust-root-frozen.json`, destination is `trusted_root.json` (cwd-relative inside `artifacts/`). F-02-05. |
</threat_model>

<verification_strategy>
## Failure Mode Coverage (Nyquist Dimension 8)

Cites IDs from `49-VALIDATION.md § Failure Modes -> REQ-POC-TRUST-02`. All 5 failure modes covered.

| Failure Mode | Validation Gate | Command |
|--------------|-----------------|---------|
| F-02-01 byte-identity drift | The new CI step's `[ "$SRC_SHA" != "$DST_SHA" ] && exit 1` block | Local dry-run (see Task 2 verify) |
| F-02-02 release-asset omission | `grep -n "artifacts/trusted_root.json" .github/workflows/release.yml` returns at least one match in the `files:` block | Post-release: `gh release view <tag> --json assets \| jq '.assets[].name'` contains `trusted_root.json` (Manual-Only per VALIDATION.md) |
| F-02-03 SHA256SUMS omission | `grep -n "sha256sum trusted_root.json" .github/workflows/release.yml` returns at least one match | Post-release: `gh release download <tag> -p SHA256SUMS.txt && grep trusted_root.json SHA256SUMS.txt` exits 0 (Manual-Only) |
| F-02-04 CI silent-pass | `grep -n "set -euo pipefail" .github/workflows/release.yml` returns the line inside the new block | shellcheck on the extracted bash block (see Task 2 verify) |
| F-02-05 working-directory mismatch | The new block is folded INSIDE the existing `cd artifacts`-scoped step; manual review of the diff confirms paths compose | Plan-time: read the diff via `git diff .github/workflows/release.yml` after Task 1 |

## Manual-Only (live-release verification)

REQ-POC-TRUST-02 acceptance criteria (d) and (e) require a real tagged release to verify. Per VALIDATION.md § "Manual-Only Verifications", these are documented to be checked on the next tagged release (e.g., `v2.6.0`) by running:

```
gh release view <tag> --json assets | jq '.assets[].name'   # must list trusted_root.json
gh release download <tag> -p trusted_root.json
diff trusted_root.json crates/nono/tests/fixtures/trust-root-frozen.json   # must exit 0
gh release download <tag> -p SHA256SUMS.txt
grep trusted_root.json SHA256SUMS.txt   # must exit 0
```

This SUMMARY.md must record "STRUCTURALLY-COMPLETE-PENDING-LIVE-RELEASE" in the verification section.
</verification_strategy>

<tasks>

<task type="auto" tdd="false">
  <name>Task 1: Insert byte-identity assert + SHA256SUMS extension + files-glob entry in release.yml</name>
  <files>.github/workflows/release.yml</files>
  <read_first>
    - .github/workflows/release.yml (entire `release` job; especially lines 294-340 — the `Generate checksums` step + the `Create GitHub Release` step's `files:` block)
    - crates/nono/tests/fixtures/trust-root-frozen.json (confirm it exists and is exactly 126 lines / ~6.6 KB)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md § "REQ-POC-TRUST-02 -> Plan 49-02 minimal-diff insertion" (lines 295-369) — provides verbatim YAML for all three insertions
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-PATTERNS.md § ".github/workflows/release.yml" (lines 109-120)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-CONTEXT.md D-49-A1 (one plan per REQ) — confirms 49-02 is single-file-single-purpose
  </read_first>
  <behavior>
    - The `Generate checksums` step (currently lines 308-326) copies `../crates/nono/tests/fixtures/trust-root-frozen.json` to `trusted_root.json` (cwd-relative inside `artifacts/`) and asserts SHA-256 equality between source and dest. On mismatch, exits non-zero with a clear error message naming both SHAs.
    - The same step's SHA256SUMS aggregation block appends a `trusted_root.json` line.
    - The `Create GitHub Release` step's `files:` block lists `artifacts/trusted_root.json` (repo-root-relative, since this glob runs from repo root).
    - `set -euo pipefail` is present at the top of the new bash block (the existing `Generate checksums` step does NOT have it — Task 1 adds it as part of folding the new logic inside, which also improves the existing block's hygiene).
    - All paths compose correctly: the assert step's source path `../crates/nono/tests/fixtures/trust-root-frozen.json` resolves to the same file as the repo-root-relative `crates/nono/tests/fixtures/trust-root-frozen.json` (since the step runs `cd artifacts` first).
  </behavior>
  <action>
**Step 1: Edit `.github/workflows/release.yml`.** Locate the existing `Generate checksums` step (lines 308-326). Replace its `run:` block with the following (folds the new logic INSIDE the existing `cd artifacts` scope so paths compose — F-02-05 mitigation):

```
      - name: Generate checksums
        run: |
          set -euo pipefail
          cd artifacts
          find . -name "*.tar.gz" -exec mv {} . \;
          find . -name "*.zip" -exec mv {} . \;
          find . -name "*.msi" -exec mv {} . \;
          find . -name "*.exe" -exec mv {} . \;
          find . -name "*.deb" -exec mv {} . \;

          # Phase 49 REQ-POC-TRUST-02: ship trusted_root.json as a release asset
          # alongside the binaries. Byte-identity assert closes the maintainer-side
          # provenance chain (D-49-B1) - what the maintainer commits to the frozen
          # fixture is what CI uploads.
          SRC=../crates/nono/tests/fixtures/trust-root-frozen.json
          DST=trusted_root.json
          cp "$SRC" "$DST"
          SRC_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)
          DST_SHA=$(sha256sum "$DST" | cut -d' ' -f1)
          if [ "$SRC_SHA" != "$DST_SHA" ]; then
            echo "ERROR: trusted_root.json byte-identity assert failed" >&2
            echo "  src ($SRC): $SRC_SHA" >&2
            echo "  dst ($DST): $DST_SHA" >&2
            exit 1
          fi
          echo "trusted_root.json byte-identity verified: $SRC_SHA"

          sha256sum *.tar.gz > SHA256SUMS.txt
          if ls *.zip >/dev/null 2>&1; then
            sha256sum *.zip >> SHA256SUMS.txt
          fi
          if ls *.msi >/dev/null 2>&1; then
            sha256sum *.msi >> SHA256SUMS.txt
          fi
          if ls *.exe >/dev/null 2>&1; then
            sha256sum *.exe >> SHA256SUMS.txt
          fi
          if ls trusted_root.json >/dev/null 2>&1; then
            sha256sum trusted_root.json >> SHA256SUMS.txt
          fi
          cat SHA256SUMS.txt
```

**Three substantive changes vs the existing step:**
1. `set -euo pipefail` added at the top (F-02-04 mitigation — preserves existing semantics in the happy path, fails fast on any internal error).
2. New byte-identity assert block (between the `find -name "*.deb"` line and the `sha256sum *.tar.gz` line) — `cp` + `SRC_SHA` + `DST_SHA` + equality check + diagnostic message.
3. New conditional aggregation entry: `if ls trusted_root.json >/dev/null 2>&1; then sha256sum trusted_root.json >> SHA256SUMS.txt; fi` (BEFORE `cat SHA256SUMS.txt`). Mirrors the existing pattern for `*.zip` / `*.msi` / `*.exe`.

**Step 2:** In the `Create GitHub Release` step (currently lines 328-340), extend the `files:` block by adding one line `            artifacts/trusted_root.json` between the existing `artifacts/*.deb` and `artifacts/SHA256SUMS.txt` lines:

```
      - name: Create GitHub Release
        uses: softprops/action-gh-release@153bb8e04406b158c6c84fc1615b65b24149a1fe # v2
        with:
          tag_name: ${{ env.RELEASE_TAG }}
          draft: false
          generate_release_notes: true
          files: |
            artifacts/*.tar.gz
            artifacts/*.zip
            artifacts/*.msi
            artifacts/*.exe
            artifacts/*.deb
            artifacts/trusted_root.json
            artifacts/SHA256SUMS.txt
```

(Exact indentation: 12 spaces — match the surrounding `files:` block.)

**Step 3:** Do NOT change any other line in `release.yml`. This plan's diff scope is intentionally tight: 1 step body replaced + 1 line added in another step. No version pin updates, no other step changes.
  </action>
  <verify>
    <automated>python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/release.yml')); print('yaml valid')" &amp;&amp; grep -q "set -euo pipefail" .github/workflows/release.yml &amp;&amp; grep -q "byte-identity verified" .github/workflows/release.yml &amp;&amp; grep -q "sha256sum trusted_root.json" .github/workflows/release.yml &amp;&amp; grep -q "artifacts/trusted_root.json" .github/workflows/release.yml</automated>
  </verify>
  <acceptance_criteria>
    - `python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` exits 0 (YAML valid; no indent breakage).
    - `grep -nc "trusted_root.json" .github/workflows/release.yml` returns a count >= 5 (the new `SRC=` path, the `DST=` assignment, the byte-identity ERROR message, the conditional `sha256sum`, and the `files:` glob entry).
    - `grep -n "set -euo pipefail" .github/workflows/release.yml` returns at least one match (must be near the top of the `Generate checksums` step).
    - `grep -n "byte-identity verified" .github/workflows/release.yml` returns exactly one match (the success diagnostic).
    - `grep -n "byte-identity assert failed" .github/workflows/release.yml` returns exactly one match (the ERROR message).
    - `grep -n "sha256sum trusted_root.json >> SHA256SUMS.txt" .github/workflows/release.yml` returns exactly one match.
    - `grep -n "^            artifacts/trusted_root.json$" .github/workflows/release.yml` returns exactly one match (12-space-indented line inside the `files:` block).
    - `git diff --stat .github/workflows/release.yml` shows only `.github/workflows/release.yml` modified; no other workflow file touched.
    - The diff is bounded: roughly +20 lines inside `Generate checksums` step + 1 line inside `Create GitHub Release` step; no other steps modified.
    - Validates: F-02-01 (byte-identity drift), F-02-02 (release-asset omission), F-02-03 (SHA256SUMS omission), F-02-04 (CI silent-pass), F-02-05 (working-directory mismatch).
  </acceptance_criteria>
  <done>
    `release.yml` has the byte-identity assert + SHA256SUMS extension + files-glob entry; YAML is structurally valid; all 5 grep-verifiable conditions pass.
  </done>
</task>

<task type="auto" tdd="false">
  <name>Task 2: Local dry-run + shellcheck + yamllint validation of the modified release.yml</name>
  <files>.github/workflows/release.yml</files>
  <read_first>
    - .github/workflows/release.yml (the modified file from Task 1)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-VALIDATION.md § "Failure Modes -> REQ-POC-TRUST-02" (lines 70-78) — F-02-04 (shellcheck) + F-02-05 (working-directory mismatch via local dry-run)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md § "Validation Architecture -> Verification commands -> Plan 49-02" (lines 543-552)
  </read_first>
  <behavior>
    - YAML linter accepts the modified workflow.
    - The extracted bash block from the `Generate checksums` step passes `shellcheck -s bash`.
    - A local dry-run of the byte-identity logic (manually composed `cp` + `sha256sum` outside the GHA runner) succeeds when fed the actual frozen fixture.
    - A negative-test local dry-run (simulating a corruption) produces a non-zero exit code from the assert block — proves the gate has teeth.
  </behavior>
  <action>
**Step 1: YAML lint.**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" && echo "YAML valid"
```

If `yamllint` is installed in the environment, also run:
```bash
yamllint -d '{extends: relaxed, rules: {line-length: disable}}' .github/workflows/release.yml
```

(If `yamllint` is not installed, the `python -c` YAML.safe_load is sufficient — record in SUMMARY which path was used.)

**Step 2: Extract the modified `Generate checksums` step's bash and shellcheck it.**

Two viable extraction methods — pick whichever the environment supports:

(a) Python-based extraction (no dependency on `yq`):
```bash
python <<'PY' > /tmp/cksum.sh
import yaml
with open('.github/workflows/release.yml') as f:
    wf = yaml.safe_load(f)
for step in wf['jobs']['release']['steps']:
    if step.get('name') == 'Generate checksums':
        print(step['run'])
        break
PY
shellcheck -s bash /tmp/cksum.sh
```

(b) Manual extraction: open the file, copy the `run:` block content (the literal block scalar under `Generate checksums`), save to `/tmp/cksum.sh`, run `shellcheck -s bash /tmp/cksum.sh`.

If `shellcheck` is not installed, mark this verify as PARTIAL in SUMMARY and record the dry-run + grep gates as the substitute evidence. Do NOT skip silently.

**Step 3: Positive dry-run.** Simulate the CI step's behavior locally:

```bash
mkdir -p /tmp/release-dry-pos/artifacts
cd /tmp/release-dry-pos/artifacts
set -euo pipefail
SRC=$OLDPWD/../crates/nono/tests/fixtures/trust-root-frozen.json
# Adjust SRC to your actual repo root if running from elsewhere.
# Easier: use an absolute path:
SRC="$HOME/Nono/crates/nono/tests/fixtures/trust-root-frozen.json"
DST=trusted_root.json
cp "$SRC" "$DST"
SRC_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)
DST_SHA=$(sha256sum "$DST" | cut -d' ' -f1)
if [ "$SRC_SHA" != "$DST_SHA" ]; then
  echo "FAIL"; exit 1
fi
echo "PASS: byte-identity verified: $SRC_SHA"
cd -
```

Expected: `PASS: byte-identity verified: <hex>` printed, no failure.

**Step 4: Negative dry-run.** Prove the assert has teeth by deliberately tampering the destination after `cp`:

```bash
mkdir -p /tmp/release-dry-neg/artifacts
cd /tmp/release-dry-neg/artifacts
set +e
SRC="$HOME/Nono/crates/nono/tests/fixtures/trust-root-frozen.json"
DST=trusted_root.json
cp "$SRC" "$DST"
echo "tampered" >> "$DST"  # corrupt the destination
SRC_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)
DST_SHA=$(sha256sum "$DST" | cut -d' ' -f1)
if [ "$SRC_SHA" != "$DST_SHA" ]; then
  echo "EXPECTED FAIL (tampered dst): src=$SRC_SHA dst=$DST_SHA"
  EXIT_CODE=1
else
  echo "UNEXPECTED PASS (tampered dst should not match)"
  EXIT_CODE=0
fi
set -e
cd -
# EXIT_CODE must be 1 to prove the gate has teeth.
[ "$EXIT_CODE" -eq 1 ] && echo "NEGATIVE DRY-RUN PASSED" || { echo "NEGATIVE DRY-RUN FAILED — assert has no teeth"; exit 1; }
```

Expected: `NEGATIVE DRY-RUN PASSED` printed.

**Step 5: Record outcomes in SUMMARY.** The SUMMARY must list:
- YAML lint outcome (python `yaml.safe_load` and/or `yamllint`).
- Shellcheck outcome (or PARTIAL if shellcheck unavailable).
- Positive dry-run SHA (the hash of the current `trust-root-frozen.json`).
- Negative dry-run outcome (assert correctly rejected the tampered DST).
- Note: live-release verification (acceptance criteria d/e) is STRUCTURALLY-COMPLETE-PENDING-LIVE-RELEASE per VALIDATION.md § Manual-Only.
  </action>
  <verify>
    <automated>python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" &amp;&amp; bash -c 'set -euo pipefail; SRC="crates/nono/tests/fixtures/trust-root-frozen.json"; mkdir -p /tmp/release-dry-pos/artifacts; cp "$SRC" /tmp/release-dry-pos/artifacts/trusted_root.json; SRC_SHA=$(sha256sum "$SRC" | cut -d" " -f1); DST_SHA=$(sha256sum /tmp/release-dry-pos/artifacts/trusted_root.json | cut -d" " -f1); [ "$SRC_SHA" = "$DST_SHA" ] || exit 1; rm -rf /tmp/release-dry-pos; echo PASS'</automated>
  </verify>
  <acceptance_criteria>
    - `python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` exits 0.
    - Positive local dry-run (cp + sha256sum + equality check) exits 0 against the actual `crates/nono/tests/fixtures/trust-root-frozen.json`.
    - Negative local dry-run (cp + tamper-dst + sha256sum + equality check) returns the expected mismatch and the wrapper exits with EXIT_CODE=1 (the assert correctly rejected the tampered DST).
    - If `shellcheck` is installed: `shellcheck -s bash /tmp/cksum.sh` exits 0 (no warnings on the extracted block) OR a documented PARTIAL with the specific shellcheck warning IDs recorded.
    - If `yamllint` is installed: `yamllint .github/workflows/release.yml` exits 0 or shows only style warnings (no errors).
    - Validates: F-02-01 (byte-identity drift — positive/negative dry-run), F-02-04 (set -euo pipefail enforced + shellcheck if available).
  </acceptance_criteria>
  <done>
    YAML valid; positive dry-run passes; negative dry-run correctly rejects tampered DST; shellcheck either clean or PARTIAL with a recorded reason.
  </done>
</task>

</tasks>

<verification>
- `python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` (Task 1 — YAML structurally valid).
- Grep gates on the modified file (Task 1 acceptance criteria — at least 5 `trusted_root.json` mentions, `set -euo pipefail`, byte-identity prose, conditional sha256sum, files-glob entry).
- Positive local dry-run of the byte-identity logic against the actual frozen fixture (Task 2).
- Negative local dry-run with a deliberately-tampered DST (Task 2 — proves the gate has teeth).
- shellcheck on the extracted bash block (Task 2 — PARTIAL allowed if shellcheck unavailable).
- yamllint on the workflow (Task 2 — PARTIAL allowed if yamllint unavailable; python yaml.safe_load is the floor).

Manual-Only (live-release verification — recorded in SUMMARY as STRUCTURALLY-COMPLETE-PENDING-LIVE-RELEASE):
- On the next tagged release: `gh release view <tag> --json assets | jq '.assets[].name'` lists `trusted_root.json`.
- `gh release download <tag> -p trusted_root.json && diff trusted_root.json crates/nono/tests/fixtures/trust-root-frozen.json` exits 0.
- `gh release download <tag> -p SHA256SUMS.txt && grep trusted_root.json SHA256SUMS.txt` exits 0.
</verification>

<success_criteria>
- [ ] `release.yml` `Generate checksums` step copies `../crates/nono/tests/fixtures/trust-root-frozen.json` to `trusted_root.json` (cwd-relative inside `artifacts/`) and asserts SHA-256 equality (F-02-01).
- [ ] The new bash block starts with `set -euo pipefail` (F-02-04).
- [ ] `if ls trusted_root.json >/dev/null 2>&1; then sha256sum trusted_root.json >> SHA256SUMS.txt; fi` is present in the aggregation block (F-02-03).
- [ ] `artifacts/trusted_root.json` is listed in the `softprops/action-gh-release` `files:` glob (F-02-02).
- [ ] All paths in the new block compose correctly inside the existing `cd artifacts` scope (F-02-05).
- [ ] `python -c "yaml.safe_load(...)"` passes; `yamllint` and `shellcheck` either pass or document a PARTIAL.
- [ ] Positive local dry-run passes; negative local dry-run (tampered DST) is correctly rejected.
- [ ] DCO sign-off on the single atomic `chore(49-02):` commit.
- [ ] SUMMARY records "STRUCTURALLY-COMPLETE-PENDING-LIVE-RELEASE" for acceptance criteria (d)/(e) (live-release verification per VALIDATION.md § Manual-Only).
</success_criteria>

<commit_shape>
Single atomic commit:

```
chore(49-02): ship trusted_root.json as a release asset

Extend .github/workflows/release.yml to copy
crates/nono/tests/fixtures/trust-root-frozen.json into
artifacts/trusted_root.json on every tagged release, with a CI-asserted
SHA-256 byte-identity gate between the source fixture and the released
asset. The new step folds into the existing Generate checksums block so
paths compose inside the `cd artifacts` scope, and `set -euo pipefail`
guards against silent-pass on internal pipe failures.

Adds artifacts/trusted_root.json to both the SHA256SUMS.txt aggregation
and the softprops/action-gh-release files: glob so POC users can
`--from-file` directly off the release page with full integrity
coverage from the existing release-integrity gate.

REQ-POC-TRUST-02. Closes the maintainer-side provenance leak so the
"--from-file release-asset" story (Plan 49-01) holds end-to-end.

Live-release acceptance criteria (gh release view + diff) are
STRUCTURALLY-COMPLETE-PENDING-LIVE-RELEASE per Phase 49 VALIDATION.md
§ Manual-Only.

Signed-off-by: Oscar Mack Jr. <oscar.mack.jr@gmail.com>
```
</commit_shape>

<output>
After completion, create `.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-02-SUMMARY.md` per the summary template. Required sections:
- Verification: YAML lint outcome + shellcheck outcome (or PARTIAL reason) + positive dry-run SHA + negative dry-run outcome.
- Live-release status: explicit STRUCTURALLY-COMPLETE-PENDING-LIVE-RELEASE callout pointing at acceptance criteria (d)/(e).
- Files modified: 1 (.github/workflows/release.yml).
- Diff scope: ~+22 lines (set -euo pipefail + byte-identity block + conditional sha256sum + files-glob entry).
- Commit SHA: single atomic `chore(49-02):` commit.
</output>
