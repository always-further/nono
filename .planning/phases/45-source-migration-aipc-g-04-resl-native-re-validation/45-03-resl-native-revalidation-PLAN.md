---
phase: 45-source-migration-aipc-g-04-resl-native-re-validation
plan: 03
type: execute
wave: 1
depends_on: []
files_modified:
  - .github/workflows/phase-45-resl-native-host.yml
  - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md
autonomous: true
requirements:
  - REQ-RESL-NIX-04
requirements_addressed:
  - REQ-RESL-NIX-04
must_haves:
  truths:
    - "`.github/workflows/phase-45-resl-native-host.yml` exists, is YAML-valid, and has `workflow_dispatch:` as its ONLY trigger (no `pull_request:` / `push:` / `schedule:`) — D-45-D2"
    - "The workflow exposes an `inputs.gh_runner_os` choice input with options `[ubuntu-24.04, macos-latest, both]` and default `both` — D-45-D2"
    - "The workflow defines two jobs (Linux + macOS), each guarded by an `if:` on `inputs.gh_runner_os`, each `runs-on:` the matching runner, each `continue-on-error: true` so one OS green is sufficient per SC#3 — D-45-D1"
    - "Each job runs `cargo test -p nono-cli --test audit_attestation -- --include-ignored` against the Phase 27.2 audit-attestation test surface (the canonical regression target re-validated by this REQ)"
    - "All `actions/*` SHA pins in the workflow are lifted VERBATIM from `.github/workflows/phase-37-linux-resl.yml` per RESEARCH Open Question #4 recommendation (`actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6`, `dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7 # stable`, `actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7 # v5`)"
    - "`.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` exists and documents the SC#3 decision tree (coverage matches OR gap surfaced) + expected `cargo test` output + Phase 46 orchestrator hand-off instructions (D-45-D1)"
    - "REQ-RESL-NIX-04 closes as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN per D-45-D1 + `.planning/templates/cross-target-verify-checklist.md` PARTIAL semantics; the live workflow run is deferred to Phase 46 orchestrator via `gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` — D-45-D2"
    - "Two atomic commits land on the Phase 45 feature branch: `feat(45-03):` for the workflow + `docs(45-03):` for the protocol doc"
    - "Every commit carries DCO `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>` trailer — CLAUDE.md § Coding Standards"
    - "Plan 45-03 makes ZERO source-tree edits (no `crates/`, no `bindings/`, no `Cargo.toml`); surface is strictly CI infra + planning artifact (RESEARCH.md § Validation Architecture Wave 0)"
  artifacts:
    - path: ".github/workflows/phase-45-resl-native-host.yml"
      provides: "workflow_dispatch-only RESL native re-validation workflow with ubuntu-24.04 + macos-latest matrix"
      contains: "workflow_dispatch:"
      must_not_contain: "pull_request:"
    - path: ".planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md"
      provides: "SC#3 decision tree + expected cargo test output + Phase 46 orchestrator hand-off instructions + (optional) Phase 27.2 transitive-closure mapping"
      contains: "SC#3"
  key_links:
    - from: ".github/workflows/phase-45-resl-native-host.yml"
      to: "crates/nono-cli/tests/audit_attestation.rs (Phase 27.2 re-enabled test surface)"
      via: "cargo test -p nono-cli --test audit_attestation -- --include-ignored"
      pattern: "audit_attestation"
    - from: ".planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md"
      to: ".github/workflows/phase-45-resl-native-host.yml (workflow_dispatch trigger)"
      via: "gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both (Phase 46 orchestrator action)"
      pattern: "gh workflow run phase-45-resl-native-host.yml"
    - from: ".planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md"
      to: ".planning/phases/27.2-audit-attestation-test-re-enablement/27.2-VERIFICATION.md (Phase 27.2 transitive closure baseline)"
      via: "(a) coverage matches OR (b) host-native gap surfaced — SC#3 decision tree"
      pattern: "Phase 27.2"
---

<objective>
Ship the structural artifacts that close REQ-RESL-NIX-04 as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN per D-45-D1. Produce two NEW artifacts:

1. `.github/workflows/phase-45-resl-native-host.yml` — a `workflow_dispatch`-only GitHub Actions workflow exposing an `inputs.gh_runner_os` choice (`[ubuntu-24.04, macos-latest, both]`, default `both`) that runs `cargo test -p nono-cli --test audit_attestation -- --include-ignored` against the Phase 27.2 audit-attestation test surface on a native Linux + macOS runner matrix. The workflow mirrors `.github/workflows/phase-37-linux-resl.yml` in layout (matrix runner + `RUSTFLAGS: -Dwarnings` + `actions/setup-rust` + `actions/cache` + cargo test invocation) but scales DOWN to manual-trigger-only per D-45-D2. Action SHA pins are REUSED verbatim from `phase-37-linux-resl.yml` per RESEARCH Open Question #4.

2. `45-03-NATIVE-RESL-PROTOCOL.md` — a verification-protocol doc capturing the SC#3 decision tree (a-coverage-matches vs b-gap-surfaced), the expected `cargo test` output shape (the Phase 27.2 closure-output verbatim per RESEARCH.md), and the Phase 46 orchestrator hand-off instructions (`gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` then capture run-ID + verdict in `45-VERIFICATION.md` or `46-VERIFICATION.md`).

Purpose: REQ-RESL-NIX-04 closure. The Phase 38 REQ-AAHX-HOST-01 native re-validation has been host-blocked from the Windows dev host since v2.4 close. Plan 45-03 ships the verification infrastructure now so Phase 46's orchestrator action can invoke it explicitly. The live CI run does NOT block Phase 45 close per SC#3 ("tactical confirmation pass only — does not block phase close if no gap is found"). The workflow is intentionally `workflow_dispatch`-only (deletable in v2.7 once the verdict is recorded) per D-45-D2 — this is NOT a permanent CI lane.

Output: 2 atomic commits on the Phase 45 feature branch:
- `feat(45-03): add phase-45 native RESL re-validation workflow (workflow_dispatch)` — the YAML workflow
- `docs(45-03): document native RESL re-validation protocol` — the protocol doc

ZERO source-tree edits. ZERO `Cargo.toml` changes. ZERO test-file edits. Surface stays strictly within `.github/workflows/` (CI tier) + `.planning/phases/45-.../` (planning artifact tier).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/REQUIREMENTS.md
@.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-CONTEXT.md
@.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-RESEARCH.md
@.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-PATTERNS.md
@.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-VALIDATION.md
@.github/workflows/phase-37-linux-resl.yml
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md

<interfaces>
<!-- The exact workflow shape Plan 45-03 must author. Lifted verbatim from PATTERNS.md § Plan 45-03 (lines 510-633) and RESEARCH.md § Pattern 3 / § Plan 45-03. -->

Phase 37 workflow precedent (`.github/workflows/phase-37-linux-resl.yml:1-26`) — Plan 45-03 mirrors layout but scales DOWN to workflow_dispatch:
```yaml
# Phase 37 — Linux RESL backends + PKGS auto-pull verification
name: Phase 37 Linux RESL

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

permissions:
  contents: read
```

Plan 45-03 deviation per D-45-D2 (workflow_dispatch-only with gh_runner_os choice):
```yaml
name: Phase 45 RESL Native Host Re-validation

on:
  workflow_dispatch:
    inputs:
      gh_runner_os:
        description: Which OS matrix to run
        type: choice
        options: [ubuntu-24.04, macos-latest, both]
        default: both

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

permissions:
  contents: read
```

Action SHA pins to REUSE verbatim (Open Question #4 recommendation; lifted from phase-37-linux-resl.yml:35-48):
```yaml
- name: Checkout
  uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6

- name: Install Rust toolchain
  uses: dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7 # stable
  with:
    toolchain: stable

- name: Cache cargo registry + target
  uses: actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7 # v5
  with:
    path: |
      ~/.cargo/registry
      ~/.cargo/git
      target
    key: ${{ runner.os }}-phase45-resl-${{ hashFiles('**/Cargo.lock') }}
    restore-keys: |
      ${{ runner.os }}-phase45-resl-
```

Job matrix pattern (per-OS, `if:` gate on `inputs.gh_runner_os`; `continue-on-error: true` per SC#3):
```yaml
jobs:
  resl-nix:
    if: ${{ inputs.gh_runner_os == 'ubuntu-24.04' || inputs.gh_runner_os == 'both' }}
    name: Phase 45 RESL native (Linux)
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    continue-on-error: true
    steps:
      - name: Checkout
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6
      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7 # stable
        with:
          toolchain: stable
      - name: Cache cargo registry + target
        uses: actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7 # v5
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-phase45-resl-${{ hashFiles('**/Cargo.lock') }}
      - name: Build workspace
        run: cargo build --workspace --release --verbose
      - name: Run audit-attestation regression
        run: cargo test -p nono-cli --test audit_attestation -- --include-ignored

  resl-darwin:
    if: ${{ inputs.gh_runner_os == 'macos-latest' || inputs.gh_runner_os == 'both' }}
    name: Phase 45 RESL native (macOS)
    runs-on: macos-latest
    timeout-minutes: 30
    continue-on-error: true
    steps:
      # mirror Linux job; same cargo test invocation
```

Cargo test invocation (canonical per Phase 27.2 closure; from PATTERNS.md § Cargo test invocation):
```bash
cargo test -p nono-cli --test audit_attestation -- --include-ignored
# Expected output (Phase 27.2 closure baseline):
# running 2 tests
# test audit_verify_reports_signed_attestation_with_pinned_public_key ... ok
# test rollback_signed_session_verifies_from_audit_dir_bundle ... ok
# test result: ok. 2 passed; 0 failed; 0 ignored
```
</interfaces>
</context>

<tasks>

<task type="auto" tdd="false">
  <name>Task 1: Author .github/workflows/phase-45-resl-native-host.yml (workflow_dispatch-only, ubuntu-24.04 + macos-latest matrix)</name>
  <files>.github/workflows/phase-45-resl-native-host.yml</files>
  <read_first>
    - .github/workflows/phase-37-linux-resl.yml (full file — the layout precedent)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-PATTERNS.md § Plan 45-03 (lines 510-633 — exact YAML shape)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-RESEARCH.md § Pattern 3 (workflow_dispatch trigger) + § Open Question #4 (SHA pin REUSE policy) + § Plan 45-03 native-host invocation (lines 463-476)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-CONTEXT.md § D-45-D1 + D-45-D2 (locked decisions)
    - crates/nono-cli/tests/audit_attestation.rs (verify the test file exists; planner does NOT edit it)
  </read_first>
  <action>
Author `.github/workflows/phase-45-resl-native-host.yml` from scratch (the file does not yet exist; this is a Wave 0 NEW artifact per VALIDATION.md). The YAML MUST match the shape laid out in PATTERNS.md § Plan 45-03 verbatim (modulo header comment + final whitespace). Required content, top-to-bottom:

1. **Header comment block** explaining tactical intent:
```yaml
# Phase 45 — Native RESL re-validation (REQ-RESL-NIX-04)
#
# Tactical confirmation pass: verifies the Phase 27.2 audit-attestation
# transitive-closure (REQ-AAHX-01..03) holds on a native Linux + macOS host.
# Closes the Phase 38 REQ-AAHX-HOST-01 deferral folded into v2.6 as
# REQ-RESL-NIX-04 per ROADMAP § Phase 45 (success criterion 3).
#
# workflow_dispatch-only (NOT a permanent CI lane) per D-45-D2.
# Deletable in v2.7 once the verdict is recorded in
# 45-03-NATIVE-RESL-PROTOCOL.md § Closure Disposition.
#
# Invocation (Phase 46 orchestrator action):
#   gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both
#   gh run watch
#
# SC#3 explicitly says this REQ does not block phase close if no gap is
# found. continue-on-error: true on both jobs so one OS green is sufficient.
```

2. **Workflow name + trigger** per D-45-D2 (workflow_dispatch ONLY; no `pull_request:` or `push:` triggers):
```yaml
name: Phase 45 RESL Native Host Re-validation

on:
  workflow_dispatch:
    inputs:
      gh_runner_os:
        description: Which OS matrix to run
        type: choice
        options:
          - ubuntu-24.04
          - macos-latest
          - both
        default: both
```

3. **Env + permissions** (mirror phase-37-linux-resl.yml):
```yaml
env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

permissions:
  contents: read
```

4. **Two parallel jobs** (`resl-nix` for Linux, `resl-darwin` for macOS), each guarded by an `if:` on `inputs.gh_runner_os` AND each `continue-on-error: true` per SC#3. Action SHA pins are REUSED VERBATIM from `phase-37-linux-resl.yml` per RESEARCH Open Question #4 (DO NOT pull current SHAs — minimize audit-trail divergence; the workflow is tactical and deletable in v2.7).

Linux job:
```yaml
jobs:
  resl-nix:
    if: ${{ inputs.gh_runner_os == 'ubuntu-24.04' || inputs.gh_runner_os == 'both' }}
    name: Phase 45 RESL native (Linux)
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    continue-on-error: true
    steps:
      - name: Checkout
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7 # stable
        with:
          toolchain: stable

      - name: Cache cargo registry + target
        uses: actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7 # v5
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-phase45-resl-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-phase45-resl-

      - name: Build workspace
        run: cargo build --workspace --release --verbose

      - name: Run audit-attestation regression
        run: cargo test -p nono-cli --test audit_attestation -- --include-ignored
```

macOS job (mirrors Linux exactly except `runs-on:`, `name:`, and the `if:` condition):
```yaml
  resl-darwin:
    if: ${{ inputs.gh_runner_os == 'macos-latest' || inputs.gh_runner_os == 'both' }}
    name: Phase 45 RESL native (macOS)
    runs-on: macos-latest
    timeout-minutes: 30
    continue-on-error: true
    steps:
      - name: Checkout
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7 # stable
        with:
          toolchain: stable

      - name: Cache cargo registry + target
        uses: actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7 # v5
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-phase45-resl-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-phase45-resl-

      - name: Build workspace
        run: cargo build --workspace --release --verbose

      - name: Run audit-attestation regression
        run: cargo test -p nono-cli --test audit_attestation -- --include-ignored
```

5. **YAML validity check** (offline syntax verification before commit):
   - Open the file in a Read tool to confirm structure.
   - Run a lightweight syntax check if available: `python -c "import yaml; yaml.safe_load(open('.github/workflows/phase-45-resl-native-host.yml'))"` (Python ships with PyYAML on this host) OR use `node -e "require('js-yaml').load(require('fs').readFileSync('.github/workflows/phase-45-resl-native-host.yml', 'utf8'))"` if Node is available. If neither tool is present, skip and rely on the post-commit grep verification (next step).

6. **Pre-commit grep verifications:**
   - `grep -c 'workflow_dispatch:' .github/workflows/phase-45-resl-native-host.yml` = 1 (only trigger).
   - `grep -cE '^on:|^  pull_request:|^  push:|^  schedule:' .github/workflows/phase-45-resl-native-host.yml` should be 1 (only `on:` itself; the others must NOT appear).
   - `grep -c 'gh_runner_os' .github/workflows/phase-45-resl-native-host.yml` ≥ 3 (input def + 2 job if-conditions).
   - `grep -c 'ubuntu-24.04' .github/workflows/phase-45-resl-native-host.yml` ≥ 2 (option + runs-on).
   - `grep -c 'macos-latest' .github/workflows/phase-45-resl-native-host.yml` ≥ 2 (option + runs-on).
   - `grep -c 'continue-on-error: true' .github/workflows/phase-45-resl-native-host.yml` = 2 (one per job — SC#3 "one or both per host availability").
   - `grep -c 'actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd' .github/workflows/phase-45-resl-native-host.yml` = 2 (SHA pin REUSED in both jobs per Open Question #4).
   - `grep -c 'dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7' .github/workflows/phase-45-resl-native-host.yml` = 2.
   - `grep -c 'actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7' .github/workflows/phase-45-resl-native-host.yml` = 2.
   - `grep -c 'audit_attestation -- --include-ignored' .github/workflows/phase-45-resl-native-host.yml` = 2.

7. **Stage + commit:**
```
git add .github/workflows/phase-45-resl-native-host.yml
git commit -m "$(cat <<'EOF'
feat(45-03): add phase-45 native RESL re-validation workflow (workflow_dispatch)

Adds .github/workflows/phase-45-resl-native-host.yml — a workflow_dispatch-only
GitHub Actions workflow that invokes `cargo test -p nono-cli --test
audit_attestation -- --include-ignored` on a matrix of ubuntu-24.04 +
macos-latest runners. Closes the structural half of REQ-RESL-NIX-04
(STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN per D-45-D1). The live run is
deferred to the Phase 46 orchestrator action (`gh workflow run
phase-45-resl-native-host.yml -f gh_runner_os=both`).

Layout mirrors .github/workflows/phase-37-linux-resl.yml (RUSTFLAGS,
actions/setup-rust, actions/cache, cargo test invocation) scaled DOWN to
workflow_dispatch-only per D-45-D2. Action SHA pins are REUSED verbatim from
phase-37-linux-resl.yml per RESEARCH Open Question #4 (minimize audit-trail
divergence; workflow is tactical and deletable in v2.7 once verdict is
recorded).

continue-on-error: true on both jobs per SC#3 ("one or both per host
availability — does not block phase close if no gap is found").

Closes (structural half): REQ-RESL-NIX-04

Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
EOF
)"
```
  </action>
  <verify>
    <automated>(cd C:/Users/OMack/Nono && test -f .github/workflows/phase-45-resl-native-host.yml) && (cd C:/Users/OMack/Nono && grep -c 'workflow_dispatch:' .github/workflows/phase-45-resl-native-host.yml) && (cd C:/Users/OMack/Nono && grep -cE '^  pull_request:|^  push:|^  schedule:' .github/workflows/phase-45-resl-native-host.yml) && (cd C:/Users/OMack/Nono && grep -c 'continue-on-error: true' .github/workflows/phase-45-resl-native-host.yml) && (cd C:/Users/OMack/Nono && grep -c 'audit_attestation -- --include-ignored' .github/workflows/phase-45-resl-native-host.yml)</automated>
  </verify>
  <acceptance_criteria>
    - **Workflow file exists (maps to VALIDATION row REQ-RESL-NIX-04 STRUCTURAL "`.github/workflows/phase-45-resl-native-host.yml` exists; YAML-valid; `workflow_dispatch`-only"):** `test -f .github/workflows/phase-45-resl-native-host.yml` exits 0.
    - **workflow_dispatch-ONLY trigger (per D-45-D2):**
      - `grep -c 'workflow_dispatch:' .github/workflows/phase-45-resl-native-host.yml` = 1
      - **W10 fix (regex tightened + yaml.safe_load assertion to defeat comment-line false positives + structural validation):**
        - Regex form (allow any indent, allow trailing whitespace): `grep -cE '^[[:space:]]+(pull_request|push|schedule):' .github/workflows/phase-45-resl-native-host.yml` = 0 (no auto-triggers — matches VALIDATION.md row's `grep -cE '^  pull_request:\|^  push:'` = 0 requirement, hardened against comment-line false positives by anchoring on whitespace-indent-only prefixes)
        - Structural assertion via yaml.safe_load (defeats ALL textual false positives — comment lines, embedded literals in env values, etc.): `python -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/phase-45-resl-native-host.yml')); assert list(d['on'].keys()) == ['workflow_dispatch'], list(d['on'].keys())"` exits 0 (iff `workflow_dispatch` is the SOLE top-level key under `on:`)
    - **gh_runner_os input + matrix gates:**
      - `grep -c 'gh_runner_os' .github/workflows/phase-45-resl-native-host.yml` ≥ 3
      - `grep -c 'options:' .github/workflows/phase-45-resl-native-host.yml` ≥ 1
      - `grep -c 'default: both' .github/workflows/phase-45-resl-native-host.yml` = 1
    - **Two jobs with continue-on-error per SC#3:**
      - `grep -c 'runs-on: ubuntu-24.04' .github/workflows/phase-45-resl-native-host.yml` = 1
      - `grep -c 'runs-on: macos-latest' .github/workflows/phase-45-resl-native-host.yml` = 1
      - `grep -c 'continue-on-error: true' .github/workflows/phase-45-resl-native-host.yml` = 2
    - **Action SHA pins REUSED verbatim from phase-37-linux-resl.yml (Open Question #4):**
      - `grep -c 'actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd' .github/workflows/phase-45-resl-native-host.yml` = 2
      - `grep -c 'dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7' .github/workflows/phase-45-resl-native-host.yml` = 2
      - `grep -c 'actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7' .github/workflows/phase-45-resl-native-host.yml` = 2
    - **Cargo test invocation present in both jobs:** `grep -c 'cargo test -p nono-cli --test audit_attestation -- --include-ignored' .github/workflows/phase-45-resl-native-host.yml` = 2.
    - **RUSTFLAGS strict (mirror phase-37 precedent):** `grep -c 'RUSTFLAGS: -Dwarnings' .github/workflows/phase-45-resl-native-host.yml` ≥ 1.
    - **Commit shape:** `git log --pretty=format:'%s' -1` = `feat(45-03): add phase-45 native RESL re-validation workflow (workflow_dispatch)` AND `git log --pretty=format:'%b' -1 | grep -c '^Signed-off-by: oscarmackjr-twg'` = 1.
    - **No source-tree edits in this task:** `git diff --cached --stat HEAD~1..HEAD -- 'crates/' 'bindings/' 'Cargo.toml' 'Cargo.lock' 2>/dev/null | wc -l` = 0 (the commit touches ONLY `.github/workflows/phase-45-resl-native-host.yml`).
  </acceptance_criteria>
  <done>
    `.github/workflows/phase-45-resl-native-host.yml` exists with `workflow_dispatch:` as its only trigger, `gh_runner_os` choice input with default `both`, two `continue-on-error: true` jobs targeting ubuntu-24.04 + macos-latest, action SHA pins REUSED verbatim from phase-37-linux-resl.yml, `cargo test -p nono-cli --test audit_attestation -- --include-ignored` invocation in both jobs. Committed as `feat(45-03): add phase-45 native RESL re-validation workflow (workflow_dispatch)` with DCO sign-off.
  </done>
</task>

<task type="auto" tdd="false">
  <name>Task 2: Author 45-03-NATIVE-RESL-PROTOCOL.md (SC#3 decision tree + expected output + Phase 46 hand-off)</name>
  <files>.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md</files>
  <read_first>
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-CONTEXT.md § D-45-D1 + § Claude's Discretion (protocol doc content depth)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-RESEARCH.md § Plan 45-03 native-host invocation (lines 463-476 — Phase 27.2 closure-output verbatim)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-PATTERNS.md § Plan 45-03 (lines 510-641, especially the protocol-doc minimum content list at lines 635-641)
    - .planning/phases/27.2-audit-attestation-test-re-enablement/27.2-VERIFICATION.md (if exists — Phase 27.2 transitive-closure baseline; cited by SC#3 (a)-branch)
    - .planning/templates/cross-target-verify-checklist.md (STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN semantics that REQ-RESL-NIX-04 inherits per D-45-D1)
    - ROADMAP.md § Phase 45 Success Criterion 3 (verbatim quote in protocol doc)
  </read_first>
  <action>
Author `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` — a new planning artifact documenting the verification protocol that the Phase 46 orchestrator will execute. There is no exact prior analog (Phase 45 introduces this pattern per PATTERNS.md § No Analog Found); the planner has discretion on structure per CONTEXT.md § Claude's Discretion. Required content, in this order:

1. **YAML frontmatter:**
```yaml
---
phase: 45
slug: source-migration-aipc-g-04-resl-native-re-validation
plan: 03
req: REQ-RESL-NIX-04
disposition: STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN
created: <today's date YYYY-MM-DD>
verifier: oscarmackjr-twg
phase_46_handoff: true
---
```

2. **§ Purpose:**
A short paragraph stating that REQ-RESL-NIX-04 closes the Phase 38 REQ-AAHX-HOST-01 native re-validation deferral (folded into v2.6 at milestone-open per ROADMAP.md § Phase 38 number reservation); the requirement is a tactical confirmation pass that the Phase 27.2 audit-attestation transitive closure (REQ-AAHX-01..03) holds on a native Linux + macOS host; the live workflow run is deferred to Phase 46 orchestrator action; this doc + `.github/workflows/phase-45-resl-native-host.yml` together discharge the structural half of the REQ.

3. **§ Workflow Invocation (Phase 46 orchestrator):**
```markdown
The Phase 46 orchestrator triggers the workflow exactly once:

\`\`\`
gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both
gh run list --workflow=phase-45-resl-native-host.yml --limit 1
gh run watch <run-id>
\`\`\`

The default `gh_runner_os=both` runs both jobs in parallel. Operator may
select `ubuntu-24.04` or `macos-latest` individually if one host is
unavailable (SC#3 explicitly says "one or both per host availability").
```

4. **§ Expected `cargo test` Output (Phase 27.2 closure baseline):**
Verbatim from RESEARCH.md § Plan 45-03 native-host invocation:
```
running 2 tests
test audit_verify_reports_signed_attestation_with_pinned_public_key ... ok
test rollback_signed_session_verifies_from_audit_dir_bundle ... ok

test result: ok. 2 passed; 0 failed; 0 ignored
```
Source cite: `.planning/phases/27.2-audit-attestation-test-re-enablement/27.2-04-SUMMARY.md` § Post-execution closure (2026-05-09 — fix commit `2b7425e7`).

5. **§ SC#3 Decision Tree** (verbatim ROADMAP success criterion + branch logic):
```markdown
ROADMAP Phase 45 § Success Criterion 3:
> Phase 38 REQ-AAHX-HOST-01 native re-validation runs on a Linux host
> (one or both per host availability) and reports either:
> (a) `audit-attestation` regression coverage matches the Phase 27.2
>     transitive closure, OR
> (b) a host-native gap is surfaced with a documented follow-up disposition.
> Tactical confirmation pass only — does not block phase close if no gap
> is found.

Branch (a) — Coverage matches:
  - Both jobs (Linux + macOS) exit 0 with the expected 2-tests-pass output.
  - REQ-RESL-NIX-04 flips from PARTIAL → VERIFIED.
  - Phase 46 orchestrator records the verdict in
    `.planning/phases/45-.../45-03-SUMMARY.md` § Closure Disposition AND
    in `46-VERIFICATION.md` § Linked Closures.
  - The workflow is a candidate for deletion in v2.7 per D-45-D2.

Branch (b) — Host-native gap surfaced:
  - One or both jobs report a failure that the Phase 27.2 transitive
    closure did NOT predict (e.g., a Linux-only symptom in
    `audit_verify_reports_signed_attestation_with_pinned_public_key`
    that did not surface on Windows host).
  - Capture the failing test name + stderr verbatim.
  - File a follow-up todo at `.planning/todos/pending/45-resl-nix-04-host-native-gap-<short-id>.md`
    with: (i) failing test name, (ii) host (Linux or macOS), (iii) stderr
    excerpt, (iv) hypothesis (host-native symptom vs Phase 27.2 fix
    regression).
  - REQ-RESL-NIX-04 closes as PARTIAL with the explicit gap reference;
    Phase 46 records the disposition in 46-VERIFICATION.md.
  - This is NOT a Phase 45 close blocker (SC#3 "does not block phase
    close if no gap is found"); however, the follow-up todo MUST be filed
    so the gap is not lost.
```

6. **§ Phase 27.2 Transitive-Closure Mapping** (optional but recommended per Claude's Discretion):
```markdown
Phase 38 REQ-AAHX-HOST-01 was originally a "Phase 27 reopen" per
.planning/PROJECT.md § v2.4 archive. Phase 27.2 (audit-attestation test
re-enablement; commits closed at SHA `2b7425e7`) transitively closed
REQ-AAH-01 + REQ-NTH-03 via:

  - `crates/nono-cli/tests/audit_attestation.rs::audit_verify_reports_signed_attestation_with_pinned_public_key`
    (REQ-AAH-01 — audit-bundle verification + pinned-public-key validation)
  - `crates/nono-cli/tests/audit_attestation.rs::rollback_signed_session_verifies_from_audit_dir_bundle`
    (REQ-NTH-03 — rollback verification from audit dir bundle)

Both tests are `#[ignore]`-by-default on Windows host (they require a
working `signed_session` flow that depends on Unix-native filesystem
semantics); `--include-ignored` re-enables them. The Phase 27.2 closure
was on Linux + macOS via `2b7425e7`; Plan 45-03's workflow is the live
re-validation of that closure on native runners post-v2.6 quiet-baseline.
```

7. **§ Closure Disposition (template — Phase 46 orchestrator fills this in):**
```markdown
This section is left empty by Plan 45-03 close. Phase 46 orchestrator
populates after `gh workflow run` completes:

\`\`\`
Disposition: [VERIFIED | PARTIAL | DEVIATED]
Linux job run-id: <id>
Linux job verdict: [pass | fail | skipped]
macOS job run-id: <id>
macOS job verdict: [pass | fail | skipped]
Closure branch: [(a) coverage matches | (b) gap surfaced]
Follow-up todo (if branch b): <path>
Recorded at: <YYYY-MM-DD>
Recorded by: orchestrator
\`\`\`
```

8. **§ Deletion / Cleanup (v2.7 candidate):**
A short note that per D-45-D2 the workflow is tactical (not a permanent CI lane) and may be deleted in v2.7 once the verdict is recorded; the cleanup should NOT delete this protocol doc (it's part of the v2.6 audit trail).

9. **§ References:**
Pointers to:
- `.planning/ROADMAP.md` § Phase 45 SC#3 (binding success criterion)
- `.planning/REQUIREMENTS.md` § REQ-RESL-NIX-04 (binding requirement)
- `.planning/phases/45-.../45-CONTEXT.md` § D-45-D1 + D-45-D2 (locked decisions)
- `.planning/phases/45-.../45-RESEARCH.md` § Plan 45-03 (research-supported invocation pattern)
- `.planning/phases/27.2-.../27.2-04-SUMMARY.md` § Post-execution closure (Phase 27.2 baseline)
- `.github/workflows/phase-45-resl-native-host.yml` (the workflow this doc orchestrates)
- `.github/workflows/phase-37-linux-resl.yml` (layout precedent)
- `.planning/templates/cross-target-verify-checklist.md` (STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN closure semantics — inherited shape)

After writing the file:

10. **Stage + commit:**
```
git add .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md
git commit -m "$(cat <<'EOF'
docs(45-03): document native RESL re-validation protocol

Adds 45-03-NATIVE-RESL-PROTOCOL.md — the verification protocol doc for
REQ-RESL-NIX-04. Captures the SC#3 decision tree (coverage matches OR
gap surfaced), the expected `cargo test` output (Phase 27.2 closure
baseline at fix commit `2b7425e7`), and the Phase 46 orchestrator
hand-off instructions (`gh workflow run phase-45-resl-native-host.yml
-f gh_runner_os=both`). Also includes the Phase 27.2 transitive-closure
mapping (REQ-AAH-01 + REQ-NTH-03) per CONTEXT.md § Claude's Discretion
recommended depth.

REQ-RESL-NIX-04 closes as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN per
D-45-D1 + `.planning/templates/cross-target-verify-checklist.md` PARTIAL
semantics; the live workflow run is deferred to Phase 46 orchestrator.

Closes (structural half + protocol): REQ-RESL-NIX-04

Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
EOF
)"
```
  </action>
  <verify>
    <automated>(cd C:/Users/OMack/Nono && test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md) && (cd C:/Users/OMack/Nono && grep -c 'SC#3' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md) && (cd C:/Users/OMack/Nono && grep -c 'gh workflow run phase-45-resl-native-host.yml' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md) && (cd C:/Users/OMack/Nono && grep -c 'STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md)</automated>
  </verify>
  <acceptance_criteria>
    - **File exists (maps to VALIDATION row REQ-RESL-NIX-04 STRUCTURAL "`45-03-NATIVE-RESL-PROTOCOL.md` exists; documents SC#3 decision tree"):** `test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` exits 0.
    - **SC#3 decision tree present:** `grep -c 'SC#3' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` ≥ 1 AND `grep -c 'Branch (a)' <file>` = 1 AND `grep -c 'Branch (b)' <file>` = 1 AND `grep -c 'coverage matches' <file>` ≥ 1 AND `grep -c 'gap surfaced' <file>` ≥ 1.
    - **Phase 46 hand-off invocation present:** `grep -c 'gh workflow run phase-45-resl-native-host.yml' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` ≥ 1 AND `grep -c 'gh_runner_os=both' <file>` ≥ 1.
    - **STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN disposition recorded:** `grep -c 'STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` ≥ 1.
    - **Expected cargo-test output verbatim:** `grep -c 'audit_verify_reports_signed_attestation_with_pinned_public_key' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` ≥ 1 AND `grep -c 'rollback_signed_session_verifies_from_audit_dir_bundle' <file>` ≥ 1 AND `grep -c 'test result: ok. 2 passed; 0 failed' <file>` ≥ 1.
    - **YAML frontmatter present:** `head -10 .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md | grep -c 'req: REQ-RESL-NIX-04'` = 1 AND `head -10 <file> | grep -c 'disposition: STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN'` = 1.
    - **Phase 27.2 mapping present (Claude's Discretion recommended):** `grep -c 'Phase 27.2' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` ≥ 1 AND `grep -c '2b7425e7' <file>` ≥ 1.
    - **Closure Disposition template present (Phase 46 fills in):** `grep -c 'Phase 46 orchestrator populates' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` ≥ 1.
    - **Commit shape:** `git log --pretty=format:'%s' -1` = `docs(45-03): document native RESL re-validation protocol` AND `git log --pretty=format:'%b' -1 | grep -c '^Signed-off-by: oscarmackjr-twg'` = 1.
    - **No source-tree edits:** `git diff --cached --stat HEAD~1..HEAD -- 'crates/' 'bindings/' 'Cargo.toml' 2>/dev/null | wc -l` = 0 (the commit touches ONLY the protocol doc).
  </acceptance_criteria>
  <done>
    `45-03-NATIVE-RESL-PROTOCOL.md` exists at `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` with YAML frontmatter, § Purpose, § Workflow Invocation, § Expected cargo-test Output, § SC#3 Decision Tree (branches a + b), § Phase 27.2 Transitive-Closure Mapping, § Closure Disposition template (left blank for Phase 46), § Deletion / Cleanup, § References. Committed as `docs(45-03): document native RESL re-validation protocol` with DCO sign-off. REQ-RESL-NIX-04 closure disposition recorded as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Workflow YAML → GitHub Actions runtime | The workflow definition crosses from the repo into GitHub's hosted runner; action SHA pins prevent supply-chain mutation of pinned action versions. |
| Phase 45 close → Phase 46 orchestrator action | The protocol doc + workflow together hand off live verification to a future phase's orchestrator action; the protocol doc IS the contract between the two phases. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-45-03-01 | Tampering / Supply Chain | Mutable action versions (`actions/checkout@v6` without SHA pin) could be substituted by upstream to inject malicious steps into the workflow runtime. | mitigate | Plan 45-03 Task 1 REUSES the verbatim 40-char SHA pins from `phase-37-linux-resl.yml` per RESEARCH Open Question #4 recommendation: `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6`, `dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7 # stable`, `actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7 # v5`. Acceptance criteria explicitly grep for each SHA pin appearing twice (once per job). |
| T-45-03-02 | Repudiation | Loss of audit trail across the Phase 45 → Phase 46 hand-off — if the protocol doc is missing key context (SC#3 decision tree, expected output, hand-off instructions), Phase 46 orchestrator might fail to recognize a gap or might run the workflow with wrong inputs. | mitigate | Plan 45-03 Task 2 authors `45-03-NATIVE-RESL-PROTOCOL.md` with EXPLICIT § SC#3 Decision Tree (branches a + b), § Expected `cargo test` Output (verbatim from Phase 27.2 closure), § Workflow Invocation (exact `gh workflow run` command), § Closure Disposition (template for Phase 46 to fill in). Acceptance criteria grep for each required marker. |
| T-45-03-03 | Elevation of Privilege | Workflow `permissions:` block too permissive — default GHA permissions grant `contents: write`; the audit-attestation regression only needs `contents: read`. | mitigate | Plan 45-03 Task 1 sets `permissions: contents: read` per phase-37-linux-resl.yml precedent. No write access; cannot mutate the repo. |
| T-45-03-04 | Denial of Service | Always-on trigger (`pull_request:` / `push:`) would burn CI minutes on every PR for a tactical confirmation pass; this is what D-45-D2 explicitly rejects. | mitigate | Plan 45-03 Task 1 uses `workflow_dispatch` ONLY; acceptance criteria grep for `pull_request:` / `push:` / `schedule:` returning 0. Workflow is deletable in v2.7 once verdict is recorded. |
| T-45-03-05 | Tampering | Future v2.7 cleanup mistakenly deletes the protocol doc along with the workflow (D-45-D2 says the workflow is deletable; the doc is NOT — it's part of the v2.6 audit trail). | accept (with documentation mitigation) | Plan 45-03 Task 2's `45-03-NATIVE-RESL-PROTOCOL.md` § Deletion / Cleanup explicitly states "the cleanup should NOT delete this protocol doc (it's part of the v2.6 audit trail)." This is documentation defense; final enforcement is at v2.7 review time. |
| T-45-03-06 | Spoofing | Phase 27.2 closure baseline could be misattributed in the protocol doc (e.g., wrong fix commit SHA), leading Phase 46 to compare against the wrong baseline and either miss a real gap or report a false gap. | mitigate | Plan 45-03 Task 2's § Phase 27.2 Transitive-Closure Mapping cites the EXACT fix commit `2b7425e7` per RESEARCH.md § Plan 45-03 (verified by RESEARCH against `27.2-04-SUMMARY.md § Post-execution closure (2026-05-09)`). Acceptance criteria grep for `2b7425e7` in the protocol doc. |
</threat_model>

<verification>
**Plan-close gate (run before flipping plan status to complete):**
1. `test -f .github/workflows/phase-45-resl-native-host.yml` exits 0 — workflow exists.
2. `grep -c 'workflow_dispatch:' .github/workflows/phase-45-resl-native-host.yml` = 1 AND `grep -cE '^  pull_request:|^  push:|^  schedule:' .github/workflows/phase-45-resl-native-host.yml` = 0 — workflow_dispatch-ONLY per D-45-D2.
3. `grep -c 'continue-on-error: true' .github/workflows/phase-45-resl-native-host.yml` = 2 — both jobs SC#3-compliant.
4. `grep -c 'actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd' .github/workflows/phase-45-resl-native-host.yml` = 2 AND same for `dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7` AND same for `actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7` — SHA pins REUSED verbatim per Open Question #4.
5. `grep -c 'cargo test -p nono-cli --test audit_attestation -- --include-ignored' .github/workflows/phase-45-resl-native-host.yml` = 2 — correct test invocation in both jobs.
6. `test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` exits 0 — protocol doc exists.
7. `grep -c 'SC#3' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` ≥ 1 AND `grep -c 'STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN' <file>` ≥ 1 AND `grep -c 'gh workflow run phase-45-resl-native-host.yml' <file>` ≥ 1 AND `grep -c '2b7425e7' <file>` ≥ 1.
8. `git log --pretty=format:'%s' main..HEAD | grep -c '^feat(45-03): add phase-45 native RESL re-validation workflow'` = 1 AND `git log --pretty=format:'%s' main..HEAD | grep -c '^docs(45-03): document native RESL re-validation protocol'` = 1 — both commits landed.
9. `git log --pretty=format:'%b' main..HEAD | grep -c '^Signed-off-by: oscarmackjr-twg'` = 2 — every commit DCO-signed.
10. `git diff main..HEAD -- 'crates/' 'bindings/' 'Cargo.toml' 'Cargo.lock'` is empty — ZERO source-tree edits.
11. Workspace still builds + tests pass at Plan 45-03 close (transitive verification — Plan 45-03 makes no source changes, so this is expected to be the unchanged state from before Plan 45-03 started). `cargo build --workspace --all-features` exits 0.
</verification>

<success_criteria>
Plan 45-03 satisfies REQ-RESL-NIX-04 (STRUCTURAL closure) when ALL of these are true:
- `.github/workflows/phase-45-resl-native-host.yml` exists, is YAML-valid, has `workflow_dispatch:` as its only trigger, exposes `inputs.gh_runner_os` choice with options `[ubuntu-24.04, macos-latest, both]` and default `both`, defines two jobs (Linux + macOS) each `continue-on-error: true`, and runs `cargo test -p nono-cli --test audit_attestation -- --include-ignored` against the Phase 27.2 audit-attestation test surface — D-45-D1 + D-45-D2.
- All action SHA pins (`actions/checkout`, `dtolnay/rust-toolchain`, `actions/cache`) are REUSED VERBATIM from `.github/workflows/phase-37-linux-resl.yml` (each pin appears exactly twice — once per job) per RESEARCH Open Question #4.
- `45-03-NATIVE-RESL-PROTOCOL.md` exists with YAML frontmatter (`req: REQ-RESL-NIX-04`, `disposition: STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN`), § Purpose, § Workflow Invocation (with exact `gh workflow run` command), § Expected cargo-test Output (verbatim Phase 27.2 closure baseline citing commit `2b7425e7`), § SC#3 Decision Tree (Branch a + Branch b explicit), § Phase 27.2 Transitive-Closure Mapping, § Closure Disposition (template for Phase 46), § Deletion/Cleanup, § References.
- Two atomic commits landed on Phase 45 feature branch: `feat(45-03): add phase-45 native RESL re-validation workflow (workflow_dispatch)` + `docs(45-03): document native RESL re-validation protocol` — both DCO-signed.
- Plan 45-03 makes ZERO source-tree edits (no `crates/`, no `bindings/`, no `Cargo.toml`, no `Cargo.lock` mutations) — `git diff main..HEAD -- 'crates/' 'bindings/' 'Cargo.toml' 'Cargo.lock'` is empty.
- REQ-RESL-NIX-04 closes as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN per D-45-D1 + `.planning/templates/cross-target-verify-checklist.md` PARTIAL semantics; the live workflow run is deferred to Phase 46 orchestrator via the documented `gh workflow run` command.
</success_criteria>

<output>
After completion, create `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-SUMMARY.md` with:
- Frontmatter: `phase`, `plan`, `req: REQ-RESL-NIX-04`, `commits: 2`, `status: structurally_complete_pending_live_run`.
- § Closure Disposition — REQ-RESL-NIX-04 status STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN; Phase 46 orchestrator action `gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` documented as the live-run trigger; SC#3 explicitly says "does not block phase close if no gap is found".
- § Commit Manifest — `feat(45-03):` SHA + subject; `docs(45-03):` SHA + subject.
- § Artifacts Authored — pointer to `.github/workflows/phase-45-resl-native-host.yml` (workflow) + `.planning/phases/45-.../45-03-NATIVE-RESL-PROTOCOL.md` (protocol doc).
- § Phase 46 Hand-off — explicit instructions: trigger via `gh workflow run`, watch via `gh run watch`, record verdict in `45-03-NATIVE-RESL-PROTOCOL.md` § Closure Disposition + in `46-VERIFICATION.md` § Linked Closures.
- § Source-Tree Edits — explicit statement: ZERO source-tree mutations; surface stayed strictly within `.github/workflows/` + `.planning/phases/45-.../`.
- § Cross-Phase Invariants — D-34-E1 / D-40-E1 / D-43-E1 Windows-only-files invariant trivially honored (no source touches at all).
</output>
