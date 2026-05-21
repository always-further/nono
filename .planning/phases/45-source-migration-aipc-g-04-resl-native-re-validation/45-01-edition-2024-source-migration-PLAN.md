---
phase: 45-source-migration-aipc-g-04-resl-native-re-validation
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - bindings/c/src/capability_set.rs
  - bindings/c/src/lib.rs
  - bindings/c/src/fs_capability.rs
  - bindings/c/src/sandbox.rs
  - bindings/c/src/state.rs
  - bindings/c/src/query.rs
  - .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md
  - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md
autonomous: true
requirements:
  - REQ-PORT-CLOSURE-08
requirements_addressed:
  - REQ-PORT-CLOSURE-08
must_haves:
  truths:
    - "All 39 `#[no_mangle]` sites in bindings/c/src/ replaced with `#[unsafe(no_mangle)]` (16+4+7+3+5+4=39, per file: capability_set.rs ×16, lib.rs ×4, fs_capability.rs ×7, sandbox.rs ×3, state.rs ×5, query.rs ×4) — D-45-B1 + ROADMAP SC#1"
    - "Each of the 6 per-file commits carries `chore(45-01):` tag + `Replay-of: 79715aa5 (Phase 43 Plan 43-01b DEC-3 split-disposition close)` annotation in body, NOT a D-19 `Upstream-commit:` trailer block — D-45-B1"
    - "Every commit carries a DCO `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>` trailer — CLAUDE.md § Coding Standards"
    - "cbindgen-generated bindings/c/include/nono.h is byte-identical to pre-phase state after the 6 per-file commits (`git diff bindings/c/include/nono.h` returns empty) — D-45-B3"
    - "DIVERGENCE-LEDGER Cluster 2 disposition `split → closed` is recorded as a final 7th commit on the same plan, with back-reference to upstream `79715aa5` AND the Phase 45 commit range — D-45-B2"
    - "`cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 on Windows host post-migration — ROADMAP SC#1 + SC#5"
    - "Cross-target Linux + macOS clippy were attempted from the Windows dev host AND documented in `45-01-CLIPPY-CROSS-TARGET.md` per `.planning/templates/cross-target-verify-checklist.md` (PARTIAL disposition acceptable when C cross-linker absent) — D-44-E2 carry-forward + CLAUDE.md MUST/NEVER"
    - "No `#[allow(clippy::unwrap_used)]` or `#[allow(dead_code)]` introduced anywhere in the 6 files (mechanical sweep should never need these) — CLAUDE.md § Unwrap Policy + § Lazy use of dead code"
    - "Plan 45-01 surface stays strictly within `bindings/c/src/` (FFI library tier) — no CLI-policy concepts introduced per CLAUDE.md § Library vs CLI Boundary"
  artifacts:
    - path: "bindings/c/src/capability_set.rs"
      provides: "16 #[unsafe(no_mangle)] FFI exports for CapabilitySet"
      contains: "#[unsafe(no_mangle)]"
      must_not_contain: "#[no_mangle]"
    - path: "bindings/c/src/lib.rs"
      provides: "4 #[unsafe(no_mangle)] FFI root exports (error store + version helpers)"
      contains: "#[unsafe(no_mangle)]"
      must_not_contain: "#[no_mangle]"
    - path: "bindings/c/src/fs_capability.rs"
      provides: "7 #[unsafe(no_mangle)] FFI exports for FsCapability"
      contains: "#[unsafe(no_mangle)]"
      must_not_contain: "#[no_mangle]"
    - path: "bindings/c/src/sandbox.rs"
      provides: "3 #[unsafe(no_mangle)] FFI exports for Sandbox apply/support"
      contains: "#[unsafe(no_mangle)]"
      must_not_contain: "#[no_mangle]"
    - path: "bindings/c/src/state.rs"
      provides: "5 #[unsafe(no_mangle)] FFI exports for SandboxState"
      contains: "#[unsafe(no_mangle)]"
      must_not_contain: "#[no_mangle]"
    - path: "bindings/c/src/query.rs"
      provides: "4 #[unsafe(no_mangle)] FFI exports for QueryContext"
      contains: "#[unsafe(no_mangle)]"
      must_not_contain: "#[no_mangle]"
    - path: ".planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md"
      provides: "Cluster 2 final disposition closed (was split)"
      contains: "Final disposition:** closed"
    - path: ".planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md"
      provides: "Cross-target Linux + macOS clippy verification protocol artifact (CLOSED or PARTIAL)"
      contains: "PARTIAL"
  key_links:
    - from: "bindings/c/src/*.rs"
      to: "bindings/c/include/nono.h"
      via: "bindings/c/build.rs invoking cbindgen::Builder"
      pattern: "cbindgen"
    - from: ".planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md (Cluster 2 line)"
      to: "upstream commit 79715aa5"
      via: "Final disposition: closed + commit-range back-reference"
      pattern: "79715aa5"
---

<objective>
Apply the deferred upstream Edition 2024 source migration to `bindings/c/src/` — close out the `split` disposition from Phase 43 Plan 43-01b DEC-3 (commit `79715aa5`). Replace all 39 `#[no_mangle]` attribute sites across the six FFI files with `#[unsafe(no_mangle)]` per Rust Edition 2024 semantics. The change is purely mechanical (one literal substitution per site); cbindgen-generated `bindings/c/include/nono.h` MUST remain byte-identical, and DIVERGENCE-LEDGER Cluster 2 MUST flip from `split → closed`.

Purpose: REQ-PORT-CLOSURE-08 closure. The Edition 2024 workspace edits (MSRV 1.95, nix/landlock/getrandom workspace deps) landed in v2.5 Phase 43 Plan 43-01b; this plan closes the source-file half of the split-disposition. After Plan 45-01 closes, no fork-internal divergence remains against upstream `79715aa5`. The plan also produces the `45-01-CLIPPY-CROSS-TARGET.md` close-gate artifact per the cross-target-verify-checklist.md PARTIAL protocol (Windows dev host has Rust targets installed for both `x86_64-unknown-linux-gnu` and `x86_64-apple-darwin` but lacks the C cross-linkers — 3-precedent pattern at Phase 41 + 43-01b + 44 close as PARTIAL with live GH Actions Linux/macOS Clippy lanes as decisive signal).

Output: 7 atomic commits on a Phase 45 feature branch — six per-file `chore(45-01):` syntax sweeps + one final `chore(45-01):` DIVERGENCE-LEDGER amendment — each carrying a DCO sign-off and a `Replay-of: 79715aa5` annotation (NOT a D-19 trailer block). Plan-close artifacts: `45-01-CLIPPY-CROSS-TARGET.md` (cross-target verification report) + clean `cargo build -p nono-ffi` showing byte-identical `nono.h`.
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
@.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md

<interfaces>
<!-- Existing primitives the executor preserves verbatim. Extracted from codebase. -->
<!-- The 6 files only need a literal attribute substitution; everything below stays as-is. -->

From bindings/c/src/capability_set.rs:1-6 (imports — DO NOT change):
```rust
//! FFI wrapper for `nono::CapabilitySet`.

use std::os::raw::c_char;

use crate::types::{validate_access_mode, NonoErrorCode};
use crate::{c_str_to_str, map_error, rust_string_to_c, set_last_error};
```

Canonical attribute sites pre-rewrite (representative — `capability_set.rs:28-31` and `:41-50`):
```rust
#[no_mangle]
pub extern "C" fn nono_capability_set_new() -> *mut NonoCapabilitySet { ... }

#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_free(caps: *mut NonoCapabilitySet) { ... }
```

Post-rewrite shape (literal substitution; no body/signature changes):
```rust
#[unsafe(no_mangle)]
pub extern "C" fn nono_capability_set_new() -> *mut NonoCapabilitySet { ... }

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_capability_set_free(caps: *mut NonoCapabilitySet) { ... }
```

cbindgen build entry point (DO NOT change):
```rust
// bindings/c/build.rs uses cbindgen::Builder::new().with_crate(&crate_dir).with_config(config).generate();
// Generates bindings/c/include/nono.h. Plan 45-01 D-45-B3 byte-identical gate runs this.
```

DIVERGENCE-LEDGER target line (`.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md:76`):
```markdown
- **Disposition:** split — workspace edits in Phase 43 Plan 43-01b, source migration deferred to v2.6 / UPST6
```

Append target (preserves audit traceability of original `split` line):
```markdown
- **Final disposition:** closed (Phase 45 Plan 45-01 commits <range>, ledger amended in this commit). Source migration absorbed; cluster fully synchronized with upstream `79715aa5`.
```
</interfaces>
</context>

<tasks>

<task type="auto" tdd="false">
  <name>Task 1: Replay upstream 79715aa5 Edition 2024 sweep across all 6 bindings/c/src/ files (one commit per file)</name>
  <files>bindings/c/src/capability_set.rs, bindings/c/src/lib.rs, bindings/c/src/fs_capability.rs, bindings/c/src/sandbox.rs, bindings/c/src/state.rs, bindings/c/src/query.rs</files>
  <read_first>
    - bindings/c/src/capability_set.rs (full file — verify 16 `#[no_mangle]` sites match pre-rewrite shape)
    - bindings/c/src/lib.rs (full file — verify 4 sites)
    - bindings/c/src/fs_capability.rs (full file — verify 7 sites)
    - bindings/c/src/sandbox.rs (full file — verify 3 sites)
    - bindings/c/src/state.rs (full file — verify 5 sites)
    - bindings/c/src/query.rs (full file — verify 4 sites)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-PATTERNS.md § Plan 45-01 (rewrite rule + commit body template at lines 102-143)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-CONTEXT.md § D-45-A2 (per-file commit order) + § D-45-B1 (Replay-of annotation, NOT D-19 trailer)
    - CLAUDE.md § Coding Standards (DCO sign-off required on every commit)
  </read_first>
  <action>
Apply six sequential per-file commits in EXACTLY this order (D-45-A2). Each commit is a LITERAL substitution `#[no_mangle]` → `#[unsafe(no_mangle)]` on every matching attribute line in the file — NO body changes, NO signature changes, NO import changes, NO new `unsafe` block wrapping. Stage and commit ONE file per commit:

**Commit 1** — `bindings/c/src/capability_set.rs` (16 sites):
1. Run `git status` to confirm clean working tree (no other modifications pending).
2. Edit capability_set.rs replacing every occurrence of `#[no_mangle]` with `#[unsafe(no_mangle)]`. The 16 sites are on attribute-only lines; no other text changes.
3. Verify locally: `grep -c '#\[unsafe(no_mangle)\]' bindings/c/src/capability_set.rs` returns 16 AND `grep -c '#\[no_mangle\]' bindings/c/src/capability_set.rs` returns 0.
4. `git add bindings/c/src/capability_set.rs`
5. `git commit` with the body:
   ```
   chore(45-01): bindings/c capability_set.rs Edition 2024 no_mangle (16 sites)

   Sweep 16 #[no_mangle] sites to #[unsafe(no_mangle)] per Rust Edition 2024
   semantics. No behavior change; no signature change; cbindgen output remains
   byte-identical (verified at Plan 45-01 close).

   Replay-of: 79715aa5 (Phase 43 Plan 43-01b DEC-3 split-disposition close)
   Cluster: 2 (Rust edition 2024 + workspace dependency centralization)
   DIVERGENCE-LEDGER: see .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md
                      § "Cluster: Rust edition 2024" — disposition split → closed
                      at Plan 45-01 close.

   Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
   ```

**Commit 2** — `bindings/c/src/lib.rs` (4 sites):
Repeat the procedure. Verify: `grep -c '#\[unsafe(no_mangle)\]' bindings/c/src/lib.rs` = 4 AND `grep -c '#\[no_mangle\]' bindings/c/src/lib.rs` = 0. Commit body: replace "capability_set.rs Edition 2024 no_mangle (16 sites)" with "lib.rs Edition 2024 no_mangle (4 sites)" and "Sweep 16 #[no_mangle]" with "Sweep 4 #[no_mangle]". All other lines (Replay-of, Cluster, DIVERGENCE-LEDGER, Signed-off-by) identical.

**Commit 3** — `bindings/c/src/fs_capability.rs` (7 sites):
Same pattern. Verify: 7 `#[unsafe(no_mangle)]` AND 0 `#[no_mangle]`. Commit message: "fs_capability.rs Edition 2024 no_mangle (7 sites)" / "Sweep 7 #[no_mangle]".

**Commit 4** — `bindings/c/src/sandbox.rs` (3 sites):
Same pattern. Verify: 3 / 0. Commit message: "sandbox.rs Edition 2024 no_mangle (3 sites)" / "Sweep 3 #[no_mangle]".

**Commit 5** — `bindings/c/src/state.rs` (5 sites):
Same pattern. Verify: 5 / 0. Commit message: "state.rs Edition 2024 no_mangle (5 sites)" / "Sweep 5 #[no_mangle]".

**Commit 6** — `bindings/c/src/query.rs` (4 sites):
Same pattern. Verify: 4 / 0. Commit message: "query.rs Edition 2024 no_mangle (4 sites)" / "Sweep 4 #[no_mangle]".

**After all 6 commits:** run `cargo build --workspace --all-features` once to confirm the workspace still builds. If it fails with any Edition 2024 non-mechanical surface (e.g., a new `unsafe extern "C"` block wrapping requirement), DO NOT silently fix — surface as a deviation per D-45-B3 ("Header diff = deviation, do not auto-close") and STOP. Otherwise proceed to Task 2.

DO NOT touch `bindings/c/include/nono.h` directly (it is cbindgen-generated). DO NOT touch any file outside the 6 listed source files in this task.
  </action>
  <verify>
    <automated>(cd C:/Users/OMack/Nono && grep -c '#\[unsafe(no_mangle)\]' bindings/c/src/capability_set.rs) && (cd C:/Users/OMack/Nono && grep -c '#\[no_mangle\]' bindings/c/src/capability_set.rs) ; (cd C:/Users/OMack/Nono && cargo build --workspace --all-features)</automated>
  </verify>
  <acceptance_criteria>
    - **Per-file substitution counts (maps to VALIDATION row REQ-PORT-CLOSURE-08 "39 #[unsafe(no_mangle)] rewrites land"):**
      - `grep -c '#\[unsafe(no_mangle)\]' bindings/c/src/capability_set.rs` = 16 AND `grep -c '#\[no_mangle\]' bindings/c/src/capability_set.rs` = 0
      - `grep -c '#\[unsafe(no_mangle)\]' bindings/c/src/lib.rs` = 4 AND `grep -c '#\[no_mangle\]' bindings/c/src/lib.rs` = 0
      - `grep -c '#\[unsafe(no_mangle)\]' bindings/c/src/fs_capability.rs` = 7 AND `grep -c '#\[no_mangle\]' bindings/c/src/fs_capability.rs` = 0
      - `grep -c '#\[unsafe(no_mangle)\]' bindings/c/src/sandbox.rs` = 3 AND `grep -c '#\[no_mangle\]' bindings/c/src/sandbox.rs` = 0
      - `grep -c '#\[unsafe(no_mangle)\]' bindings/c/src/state.rs` = 5 AND `grep -c '#\[no_mangle\]' bindings/c/src/state.rs` = 0
      - `grep -c '#\[unsafe(no_mangle)\]' bindings/c/src/query.rs` = 4 AND `grep -c '#\[no_mangle\]' bindings/c/src/query.rs` = 0
      - Phase-total: `grep -rc '#\[no_mangle\]' bindings/c/src/ | grep -v ':0$' | wc -l` = 0 (no file retains any old-form attribute)
    - **Per-commit shape (6 commits):** `git log --pretty=format:'%s' -6` lists exactly six `chore(45-01): bindings/c <file> Edition 2024 no_mangle (<count> sites)` subjects in the order capability_set.rs → lib.rs → fs_capability.rs → sandbox.rs → state.rs → query.rs.
    - **Per-commit DCO + Replay-of annotation:** `git log --pretty=format:'%b' -6 | grep -c '^Replay-of: 79715aa5'` = 6 AND `git log --pretty=format:'%b' -6 | grep -c '^Signed-off-by: oscarmackjr-twg'` = 6 AND `git log --pretty=format:'%b' -6 | grep -c '^Upstream-commit:'` = 0 (must NOT be a D-19 trailer block).
    - **Build still passes:** `cargo build --workspace --all-features` exits 0.
    - **No silenced lints introduced:** `git diff main -- bindings/c/src/ | grep -c '#\[allow(clippy::unwrap_used)\]\|#\[allow(dead_code)\]'` = 0.
    - **Maps to VALIDATION.md row:** "REQ-PORT-CLOSURE-08 | 45-01 | 39 `#[unsafe(no_mangle)]` rewrites land; cargo clippy clean on Windows host".
  </acceptance_criteria>
  <done>
    All 6 per-file Edition 2024 sweep commits are landed on the Phase 45 feature branch with verified per-file substitution counts (16/4/7/3/5/4 = 39), each commit carries `chore(45-01):` subject + `Replay-of: 79715aa5` annotation + DCO sign-off, no D-19 `Upstream-commit:` trailer block, no `#[allow(...)]` workarounds, and `cargo build --workspace --all-features` exits 0 post-Task-1.
  </done>
</task>

<task type="auto" tdd="false">
  <name>Task 2: Run cbindgen byte-identical gate + close-gate clippy + cross-target verification artifact + DIVERGENCE-LEDGER amendment</name>
  <files>.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md, .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md</files>
  <read_first>
    - .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md (lines 70-89 — Cluster 2 block; line 76 is the current `split` disposition line)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-PATTERNS.md § DIVERGENCE-LEDGER amendment (lines 145-158 — exact append shape)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-CONTEXT.md § D-45-B2 (single-commit ledger amend) + § D-45-B3 (cbindgen byte-identical gate mechanics)
    - .planning/templates/cross-target-verify-checklist.md (full file — PARTIAL Disposition § + Anti-patterns + Enforcement)
    - .planning/phases/44-review-polish-test-hygiene-drain/44-01-CLIPPY-CROSS-TARGET.md (existing precedent artifact — mirror this layout for 45-01-CLIPPY-CROSS-TARGET.md)
    - bindings/c/include/nono.h (pre-Task-2 state — capture once before re-running cbindgen)
    - bindings/c/build.rs (read-only — confirms cbindgen invocation)
    - bindings/c/cbindgen.toml (read-only — confirms config)
  </read_first>
  <action>
This task has THREE sub-steps that must run in this order: (A) cbindgen byte-identical gate, (B) cross-target clippy verification + artifact authoring, (C) DIVERGENCE-LEDGER amendment commit.

**Sub-step A — cbindgen byte-identical gate (D-45-B3):**
1. Capture the current generated header before re-running cbindgen — Windows shell: `Copy-Item bindings/c/include/nono.h bindings/c/include/nono.h.pre-45-01` OR Unix: `cp bindings/c/include/nono.h /tmp/nono.h.pre-45-01`. (Even though the file is in git, an explicit pre-capture avoids races with the build.)
2. Force-regenerate the header: `cargo clean -p nono-ffi && cargo build -p nono-ffi --release` (clean ensures `build.rs` actually re-runs cbindgen).
3. Diff: `git diff --exit-code bindings/c/include/nono.h`. If the exit code is 0, the header is byte-identical — proceed to Sub-step B. If non-zero, STOP — Edition 2024 has surfaced a non-mechanical cbindgen output change. Per D-45-B3 this is a deviation: do NOT auto-close, surface to user with the exact diff text and pause Plan 45-01.
4. Clean up the temp capture: `rm bindings/c/include/nono.h.pre-45-01` (or `Remove-Item`).

**Sub-step B — Cross-target clippy verification + `45-01-CLIPPY-CROSS-TARGET.md` artifact (per cross-target-verify-checklist.md § Enforcement):**
1. Run Windows-host clippy first (the always-required local gate):
   ```
   cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
   ```
   This MUST exit 0. Capture the exit code + any output.
2. Attempt cross-target Linux clippy from the Windows dev host:
   ```
   cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
   ```
   Per RESEARCH.md § Phase 45 Cross-Target Posture, the Rust target is installed but the C cross-linker is absent — the expected outcome is `error: linker x86_64-linux-gnu-gcc not found` or equivalent. Capture the actual exit code + stderr.
3. Attempt cross-target macOS clippy from the Windows dev host:
   ```
   cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used
   ```
   Expected: similar toolchain-missing error per 3-precedent (Phase 41 + 43-01b + 44). Capture exit code + stderr.
4. Author `45-01-CLIPPY-CROSS-TARGET.md` at `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md`. Use the Phase 44 `.planning/phases/44-review-polish-test-hygiene-drain/44-01-CLIPPY-CROSS-TARGET.md` layout as a structural model. The file MUST contain:
   - YAML frontmatter: `phase: 45`, `plan: 01`, `req: REQ-PORT-CLOSURE-08`, `disposition: PARTIAL` (or CLOSED if both cross-target lanes ran clean on this host — highly unlikely per precedent), `created: <today>`, `verifier: oscarmackjr-twg`.
   - § Scope — explicit statement that Plan 45-01 touched `bindings/c/src/` (cross-platform FFI consumed by Unix runtimes) per § Scope of cross-target-verify-checklist.md.
   - § Decision Tree Walkthrough — Question 1 (touches in-scope file: YES, the 6 bindings/c/src/ files), Question 2 (Linux cross-target clippy: toolchain-missing per checklist), Question 3 (macOS: toolchain-missing per checklist).
   - § Local Evidence — the Windows-host clippy command + exit-0 confirmation; the captured stderr from the Linux + macOS attempts.
   - § Codebase Evidence — the EXACT prose from cross-target-verify-checklist.md § PARTIAL Disposition step 4:
     > Cross-target clippy gate SKIPPED on Windows dev host due to missing toolchain (x86_64-unknown-linux-gnu C linker; Darwin SDK absent). The live GH Actions Linux Clippy and macOS Clippy lanes on the Phase 45 head SHA are the decisive signal per .planning/templates/cross-target-verify-checklist.md. REQ-PORT-CLOSURE-08 marked PARTIAL pending CI confirmation.
   - § Closure path — explicit statement that the live GH Actions Linux Clippy + macOS Clippy lanes on the Phase 45 head SHA close the REQ; Phase 46 orchestrator records the verdict.
   - § Anti-pattern checks — explicit statement that no `#[allow(clippy::unwrap_used)]` or `#[allow(dead_code)]` was added (per Anti-pattern 2) and that `cargo check` was NOT substituted for clippy (per Anti-pattern 3).

**Sub-step C — DIVERGENCE-LEDGER amendment (D-45-B2 — 7th commit closing Plan 45-01):**
1. Open `.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` at line 76. The current line reads:
   ```
   - **Disposition:** split — workspace edits in Phase 43 Plan 43-01b, source migration deferred to v2.6 / UPST6
   ```
   DO NOT replace this line — preserve it for audit traceability per PATTERNS.md recommendation.
2. Capture the Phase 45 Plan 45-01 commit range: `git log --pretty=format:'%H' -7 main..HEAD | tail -n 1` (the first commit of the 6-file sweep) and `git log --pretty=format:'%H' -7 main..HEAD | head -n 1` (the most recent commit before this amendment). Combine into a short range like `<sha1>..<sha6>` (use 8-char abbreviations).
3. Immediately after line 76, append a new bullet (preserving indentation; line 77 begins the "Original disposition" or status block — verify alignment by reading lines 70-89 first):
   ```
   - **Final disposition:** closed (Phase 45 Plan 45-01 commits <sha1>..<sha6>, ledger amended in this commit). Source migration absorbed; cluster fully synchronized with upstream `79715aa5`.
   ```
   The phrase "ledger amended in this commit" deliberately omits a self-referential SHA (W5 fix). The amendment commit's identity is uniquely recoverable post-fact via `git log -1 --follow -- .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` (which returns this commit by construction), so a literal SHA value in the line body is redundant. No `git commit --amend` and no `TBD-amend-sha` placeholder are required — commit once, no fork.
4. Stage + commit:
   ```
   git add .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md
   git commit
   ```
   Commit body:
   ```
   chore(45-01): DIVERGENCE-LEDGER Cluster 2 split → closed (79715aa5 close)

   Flip Cluster 2 final disposition from `split` to `closed` after Plan 45-01's
   per-file Edition 2024 source migration commits landed on the Phase 45 feature
   branch. Preserves the original `split` disposition line at :76 for audit
   traceability; appends a `Final disposition: closed` bullet with back-reference
   to upstream commit `79715aa5` AND the Phase 45 Plan 45-01 commit range.

   Also adds .planning/phases/45-.../45-01-CLIPPY-CROSS-TARGET.md per
   cross-target-verify-checklist.md § Enforcement: Windows-host clippy clean;
   cross-target Linux + macOS clippy SKIPPED (C linker absent) — PARTIAL
   disposition with live GH Actions Linux Clippy + macOS Clippy lanes on
   Phase 45 head SHA as decisive close signal.

   Replay-of: 79715aa5 (Phase 43 Plan 43-01b DEC-3 split-disposition close)
   Cluster: 2 (Rust edition 2024 + workspace dependency centralization)

   Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
   ```
  </action>
  <verify>
    <automated>(cd C:/Users/OMack/Nono && cargo clean -p nono-ffi && cargo build -p nono-ffi --release && git diff --exit-code bindings/c/include/nono.h) && (cd C:/Users/OMack/Nono && grep -c 'Final disposition:\*\* closed' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md) && (cd C:/Users/OMack/Nono && test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md)</automated>
  </verify>
  <acceptance_criteria>
    - **cbindgen byte-identical gate (maps to VALIDATION row "cbindgen header bindings/c/include/nono.h byte-identical post-migration"):** `git diff --exit-code bindings/c/include/nono.h` exits 0 after `cargo clean -p nono-ffi && cargo build -p nono-ffi --release` re-runs cbindgen. If non-zero, plan is DEVIATED per D-45-B3.
    - **DIVERGENCE-LEDGER amended (maps to VALIDATION row "Cluster 2 disposition `split → closed` with back-reference to `79715aa5`"):** `grep -c '\*\*Final disposition:\*\* closed' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` = 1 AND `grep -c '79715aa5' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` ≥ 1 (back-reference present) AND `grep -c '\*\*Disposition:\*\* split' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` ≥ 1 (original `split` line preserved for audit traceability per PATTERNS.md).
    - **Cross-target artifact exists (maps to VALIDATION manual-only row "Cross-target Linux clippy lane" + "Cross-target macOS clippy lane"):** `test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md` exits 0 AND `grep -c 'PARTIAL' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md` ≥ 1 AND `grep -c 'live GH Actions' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md` ≥ 1 AND `grep -c 'cargo check' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md` ≥ 1 (Anti-pattern 3 acknowledgement).
    - **Windows-host clippy clean (maps to VALIDATION row "cargo clippy clean on Windows host"):** `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
    - **7th commit shape:** `git log --pretty=format:'%s' -1` returns `chore(45-01): DIVERGENCE-LEDGER Cluster 2 split → closed (79715aa5 close)` AND `git log --pretty=format:'%b' -1 | grep -c '^Signed-off-by: oscarmackjr-twg'` = 1.
    - **Total Plan 45-01 commits = 7:** `git log --pretty=format:'%s' main..HEAD | wc -l` = 7 AND `git log --pretty=format:'%s' main..HEAD | grep -c '^chore(45-01):'` = 7.
  </acceptance_criteria>
  <done>
    cbindgen-generated `bindings/c/include/nono.h` is byte-identical (`git diff` empty); `45-01-CLIPPY-CROSS-TARGET.md` is committed with PARTIAL disposition + verbatim cross-target-verify-checklist.md PARTIAL prose + anti-pattern acknowledgements; DIVERGENCE-LEDGER Cluster 2 has a `Final disposition: closed` bullet with back-reference to `79715aa5` AND the Phase 45 Plan 45-01 commit range; the 7th commit `chore(45-01): DIVERGENCE-LEDGER Cluster 2 split → closed (79715aa5 close)` is landed with DCO sign-off; `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 on Windows host.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Rust → C (FFI) | `extern "C" fn` exports in `bindings/c/src/*` cross the safe-Rust / unsafe-C ABI boundary. Caller passes raw pointers; we de-reference under `// SAFETY:` contracts. |
| Source → cbindgen-generated header | `bindings/c/build.rs` reads `bindings/c/src/*.rs` AT COMPILE TIME and emits `bindings/c/include/nono.h`. Plan 45-01 attribute substitution MUST NOT change the emitted header (D-45-B3 byte-identical gate). |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-45-01-01 | Elevation of Privilege | `#[no_mangle]` bare attribute on cross-language FFI exports — Edition 2024 explicitly upgrades the attribute to `#[unsafe(no_mangle)]` because exporting Rust symbols at the C ABI is an unsafe boundary (linker-level name collisions, ODR violations). | mitigate | Plan 45-01 Task 1 substitutes all 39 sites; this IS the mitigation. Aligns with CLAUDE.md § Security Considerations "Explicit Over Implicit" — the unsafe-ness of the FFI export is now declared at the attribute, not hidden in the language version. |
| T-45-01-02 | Tampering | cbindgen-generated header drift — if the Edition 2024 substitution silently changes the emitted C header (e.g., visibility annotations), downstream C consumers (`../nono-py/`, `../nono-ts/`, MSI) see an unintended ABI mutation. | mitigate | Plan 45-01 Task 2 Sub-step A runs `cargo clean -p nono-ffi && cargo build -p nono-ffi --release && git diff --exit-code bindings/c/include/nono.h` — non-zero exit halts the plan with deviation per D-45-B3. |
| T-45-01-03 | Repudiation | DIVERGENCE-LEDGER amendment without back-reference would lose the audit chain Phase 43 Plan 43-01b → Phase 45 Plan 45-01 closure → upstream `79715aa5`. | mitigate | Plan 45-01 Task 2 Sub-step C appends a `Final disposition: closed` bullet with EXPLICIT back-reference to commit `79715aa5` AND to the Phase 45 Plan 45-01 commit range; original `split` line at :76 preserved for audit traceability per PATTERNS.md. |
| T-45-01-04 | Tampering / Repudiation | Cross-target Linux + macOS clippy drift silently hiding cfg-gated FFI bugs on Unix runtimes (Phase 41 twice-mis-verified precedent). | mitigate | Plan 45-01 Task 2 Sub-step B authors `45-01-CLIPPY-CROSS-TARGET.md` with PARTIAL disposition + verbatim cross-target-verify-checklist.md PARTIAL prose + live GH Actions Linux Clippy + macOS Clippy lanes on the Phase 45 head SHA as the decisive close signal. The artifact explicitly forbids `cargo check` substitution per Anti-pattern 3. |
| T-45-01-05 | Elevation of Privilege | Silenced lints (`#[allow(clippy::unwrap_used)]` or `#[allow(dead_code)]`) introduced as Edition 2024 "workarounds" would violate CLAUDE.md § Unwrap Policy + § Lazy use of dead code AND cross-target-verify-checklist.md Anti-pattern 2. | accept | The substitution is purely literal — no body or signature changes — so no new `unwrap`/`expect` callsites are created. Task 1 acceptance criteria explicitly grep for `#[allow(clippy::unwrap_used)]` / `#[allow(dead_code)]` introductions and require count = 0. |
| T-45-01-06 | Tampering | Library vs CLI boundary violation — Plan 45-01 touching `bindings/c/src/` could inadvertently introduce CLI-policy concepts (group resolvers, profile loaders) into the FFI library tier. | accept | Task 1 scope is bounded to attribute-only substitution; no new imports, no new functions, no new modules. CLAUDE.md § Library vs CLI Boundary remains intact by construction. |
</threat_model>

<verification>
**Plan-close gate (run before flipping plan status to complete):**
1. `cargo build --workspace --all-features` exits 0 — workspace builds across all crates.
2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 — Windows-host strict clippy clean.
3. `cargo test --workspace --all-features` exits 0 — full test suite green (≥ 2197 passing per Phase 43-01b baseline; Plan 45-01 does not add/remove tests, so the count should be unchanged).
4. `cargo build -p nono-ffi --release` followed by `git diff --exit-code bindings/c/include/nono.h` exits 0 — cbindgen byte-identical gate green.
5. `grep -rc '#\[no_mangle\]' bindings/c/src/` lists each of the 6 files with count `0` (i.e., zero remaining bare attributes); `grep -rc '#\[unsafe(no_mangle)\]' bindings/c/src/` sums to 39 across the 6 files.
6. `git log --pretty=format:'%s' main..HEAD | grep -c '^chore(45-01):'` = 7 (six file commits + one ledger commit).
7. `git log --pretty=format:'%b' main..HEAD | grep -c '^Signed-off-by: oscarmackjr-twg'` ≥ 7 — every commit DCO-signed.
8. `grep -c '\*\*Final disposition:\*\* closed' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` = 1 AND `grep -c '79715aa5' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` ≥ 1.
9. `test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md` AND `grep -c 'PARTIAL' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md` ≥ 1.
10. `git diff --stat main..HEAD -- 'crates/**/*_windows.rs' 'crates/nono-cli/src/exec_strategy_windows/**' 'crates/nono-shell-broker/**'` is empty (Windows-only-files invariant honored — Plan 45-01 does not touch Windows-only files; SC#4 satisfied at plan scope).
</verification>

<success_criteria>
Plan 45-01 satisfies REQ-PORT-CLOSURE-08 when ALL of these are true:
- All 39 `#[no_mangle]` → `#[unsafe(no_mangle)]` substitutions are committed across the 6 `bindings/c/src/` files (per-file counts: 16/4/7/3/5/4) — REQ-PORT-CLOSURE-08 acceptance line 1.
- DIVERGENCE-LEDGER Cluster 2 disposition reads `split` (original, preserved) AND `Final disposition: closed` (new, with back-reference to `79715aa5` and Phase 45 Plan 45-01 commit range) — REQ-PORT-CLOSURE-08 acceptance line 2 + D-45-B2.
- `bindings/c/include/nono.h` is byte-identical pre- and post-migration (`git diff --exit-code` exits 0 after `cargo clean -p nono-ffi && cargo build -p nono-ffi --release`) — D-45-B3 byte-identical gate.
- `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 on Windows host — ROADMAP SC#1 local gate.
- `45-01-CLIPPY-CROSS-TARGET.md` exists with PARTIAL disposition + verbatim cross-target-verify-checklist.md PARTIAL prose; live GH Actions Linux Clippy + macOS Clippy lanes on Phase 45 head SHA are documented as the decisive close signal — ROADMAP SC#1 cross-target gate + Phase 46 hand-off.
- All 7 commits (6 per-file + 1 ledger amend) carry `chore(45-01):` subject + `Replay-of: 79715aa5` annotation + DCO sign-off; no D-19 `Upstream-commit:` trailer block; no `#[allow(...)]` introductions.
- Windows-only-files invariant honored (`git diff --stat main..HEAD -- 'crates/**/*_windows.rs' 'crates/nono-cli/src/exec_strategy_windows/**' 'crates/nono-shell-broker/**'` is empty) — ROADMAP SC#4 at plan scope.
</success_criteria>

<output>
After completion, create `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-SUMMARY.md` with:
- Frontmatter: `phase`, `plan`, `req: REQ-PORT-CLOSURE-08`, `commits: 7`, `status: complete` (or `partial` if cross-target lanes pending live CI).
- § Closure Disposition — REQ-PORT-CLOSURE-08 status (CLOSED if PARTIAL gate cleared via captured GH Actions verdict, else STRUCTURALLY-COMPLETE-PENDING-CROSS-TARGET-CI).
- § Commit Manifest — list of all 7 commit SHAs + subjects.
- § Verification — outputs of the 10 verification gates listed above.
- § Cross-Target Posture — pointer to `45-01-CLIPPY-CROSS-TARGET.md` + Phase 46 orchestrator hand-off note.
- § Anti-pattern Audit — explicit confirmation that no `#[allow(...)]` was introduced and `cargo check` was not substituted for clippy.
</output>
