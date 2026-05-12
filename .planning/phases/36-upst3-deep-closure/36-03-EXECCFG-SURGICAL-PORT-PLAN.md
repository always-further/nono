---
phase: 36-upst3-deep-closure
plan: 03
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono/src/diagnostic.rs
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/execution_runtime.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/profile_save_runtime.rs
  - crates/nono-cli/src/pty_proxy.rs
  - crates/nono-cli/src/sandbox_log.rs
  - crates/nono-cli/src/startup_prompt.rs
autonomous: true
requirements:
  - REQ-PORT-CLOSURE-05
tags:
  - phase-36
  - port-closure
  - execcfg-surgical
  - b5f0a3ab
  - bbdf7b85
  - escape-quote
  - pty-quiet-period
  - p34-defer-08b-1
  - p34-defer-08b-2
  - d-20-manual-replay
  - d-19-cherry-pick
  - d-36-d1
  - d-36-d2
  - d-36-d3

must_haves:
  truths:
    - "Plan 36-03 lands as exactly 3 sequenced git commits (per D-36-D2). Commit 1 (b5f0a3ab surgical diagnostic.rs restoration) and Commit 2 (b5f0a3ab surgical exec_strategy + helpers + LearnArgs.trace) use D-20 manual-replay shape (NO `Upstream-commit:` trailer); Commit 3 (bbdf7b85 escape-quote body rewrite) uses D-19 cherry-pick shape with the verbatim 6-line `Upstream-commit: bbdf7b85` trailer block (lowercase 'a' in `Upstream-author:`)."
    - "The smoke check `git log --format='%B' main~3..main | grep -c '^Upstream-commit: '` returns EXACTLY 1 — only Commit 3 carries the D-19 trailer (per D-36-D2 close-gate)."
    - "`crates/nono-cli/src/exec_strategy.rs` `pub struct ExecConfig<'a>` at line 276 is UNCHANGED in field count, field names, field types, and field order — fork's 17-field shape is preserved verbatim (per D-36-D1 invariant). All new helpers + the new `POST_EXIT_PTY_DRAIN_TIMEOUT` const are module-level additions, NOT struct-level mutations."
    - "The 4 diagnostic helpers (`extract_path_after_syscall_word`, `infer_access_from_structured_syscall_line`, `extract_structured_path_property`, `extract_structured_string_property`) are RESTORED to `crates/nono/src/diagnostic.rs` AND wired into `analyze_error_output` at ~line 215. Both deferred-state comment blocks (lines 402-419 + 2258-2267) are REMOVED in Commit 1."
    - "`crates/nono-cli/src/exec_strategy.rs`'s existing `clear_signal_forwarding_target()` helper at line 1987 is NOT redefined; Commit 2 ADDS a NEW callsite immediately before the profile-save prompt — total callsites go from 2 (lines 825, 2047) to 3 (per RESEARCH.md Drift Note 2)."
    - "`crates/nono-cli/src/cli.rs` `LearnArgs` struct at lines 2263-2295 is extended with `pub trace: bool` field (per upstream b5f0a3ab); the `\\ Timeout in seconds...` typo at line 2272 — IF present at execution time per RESEARCH.md Drift Note 4 — is fixed to canonical `/// ` shape in the same commit pass."
    - "`POST_EXIT_PTY_DRAIN_TIMEOUT` constant is reduced from 250ms to 100ms (per upstream b5f0a3ab). Phase 17 attach-streaming tests (`crates/nono-cli/tests/attach_streaming_integration.rs`) remain green; Phase 31 broker ConPTY 5-row detached-console smoke gate (close-gate step 6) remains green. If a flake surfaces, the compromise is 150ms OR rollback the rider entirely per D-36-D3 + v2.5-FU-6 deferral."
    - "Plan 34-08b's `print_macos_run_guidance` absorption + Phase 10 / D-02 Windows admin gate in `learn_runtime.rs` are NOT regressed by Commit 2."
  artifacts:
    - path: "crates/nono/src/diagnostic.rs"
      provides: "4 helpers restored at appropriate module-level positions (mirroring `extract_relative_write_path_from_line` sibling shape at line 421); wired into `analyze_error_output` at line ~226 inside the existing `for line in error_output.lines()` loop. Test `test_analyze_error_output_detects_node_eperm_mkdir_as_write` restored. Deferred-state comment blocks at lines 402-419 + 2258-2267 DELETED. (Commit 1 surface; Commit 3 also touches: body rewrite of `extract_structured_string_property` + 2 new tests.)"
      contains: "fn extract_path_after_syscall_word"
    - path: "crates/nono-cli/src/exec_strategy.rs"
      provides: "Module-level additions (Commit 2): `fn should_offer_profile_save(...)`, `const POST_EXIT_PTY_DRAIN_TIMEOUT: Duration = Duration::from_millis(100)`, startup-timeout machinery integration. NEW 3rd callsite of existing `clear_signal_forwarding_target()` (line 1987 — DO NOT redefine) placed immediately before the profile-save prompt. `pub struct ExecConfig<'a>` at line 276 UNCHANGED."
      contains: "POST_EXIT_PTY_DRAIN_TIMEOUT"
    - path: "crates/nono-cli/src/execution_runtime.rs"
      provides: "Module-level additions (Commit 2): `fn should_apply_startup_timeout(...)`, `fn startup_timeout_profile(...)`, `fn compute_executable_identity(...)`. New `#[cfg(test)] mod tests` entries for startup-timeout interactive-vs-non-interactive arms (mirror existing test mod at line 465-486)."
      contains: "fn should_apply_startup_timeout"
    - path: "crates/nono-cli/src/cli.rs"
      provides: "`LearnArgs` struct (currently lines 2263-2295) extended with `pub trace: bool` field as sibling to `verbose`, `all`, `no_rdns`. If line 2272 carries `\\ Timeout...` typo, fix to `/// Timeout...` canonical shape in same commit pass. (Commit 2 surface.)"
      contains: "pub trace: bool"
    - path: "crates/nono/src/diagnostic.rs"
      provides: "(Commit 3 surface, D-19 cherry-pick of bbdf7b85): body rewrite of `extract_structured_string_property` to handle escape-quoted characters (e.g., `path: '/Users/luke/it\\'s/pkg'`); 2 NEW tests: `test_analyze_error_output_detects_structured_node_eperm_mkdir_path` (from b5f0a3ab) + `test_analyze_error_output_detects_structured_path_with_escaped_quote` (from bbdf7b85)."
      contains: "test_analyze_error_output_detects_structured_path_with_escaped_quote"
  key_links:
    - from: "crates/nono/src/diagnostic.rs::analyze_error_output (line ~215)"
      to: "crates/nono/src/diagnostic.rs::extract_structured_string_property (restored Commit 1; body-rewritten Commit 3)"
      via: "structured-property dispatch in the lines-iterator loop"
      pattern: "extract_structured_string_property|extract_structured_path_property"
    - from: "crates/nono-cli/src/exec_strategy.rs (Commit 2 new callsite before profile-save prompt)"
      to: "crates/nono-cli/src/exec_strategy.rs::clear_signal_forwarding_target (line 1987, EXISTING; NOT redefined)"
      via: "NEW 3rd callsite (lines 825 + 2047 existing + new pre-profile-save)"
      pattern: "clear_signal_forwarding_target\\(\\)"
    - from: "crates/nono/src/diagnostic.rs::extract_structured_string_property (Commit 3 body rewrite)"
      to: "test_analyze_error_output_detects_structured_path_with_escaped_quote"
      via: "test exercises escape-quote handling in structured properties"
      pattern: "structured_path_with_escaped_quote"
---

<objective>
Land the surgical port of upstream `b5f0a3ab` (v0.52.0, Luke Hinds; macOS learn + run diagnostics + PTY-quiet-period + profile-save resilience) PLUS the dependent `bbdf7b85` escape-quote pipeline tail (v0.52.0, Luke Hinds) into the fork as **3 sequenced commits in a single PLAN.md / single PR** per D-36-D2. Fork's `ExecConfig` 17-field shape is PRESERVED verbatim per D-36-D1 — NO struct mutation. Closes REQ-PORT-CLOSURE-05 + P34-DEFER-08b-1 + P34-DEFER-08b-2.

**Commit shape (D-36-D2 locked invariant — DO NOT REORDER):**
- **Commit 1 (D-20 manual-replay)**: b5f0a3ab surgical diagnostic.rs restoration. Restore 4 helpers + wire into `analyze_error_output` + restore 1 test + DELETE 2 deferred-state comment blocks. NO `Upstream-commit:` trailer.
- **Commit 2 (D-20 manual-replay)**: b5f0a3ab surgical exec_strategy + execution_runtime + cli.rs + 4 ancillary refinements. NEW callsite of existing `clear_signal_forwarding_target` (NOT helper restoration). NO `Upstream-commit:` trailer.
- **Commit 3 (D-19 cherry-pick)**: bbdf7b85 escape-quote body rewrite + 2 new tests. Full 6-line `Upstream-commit:` trailer block citing `bbdf7b85` (lowercase 'a' in `Upstream-author:`). This is the ONE commit in Phase 36 that carries the D-19 trailer.

**Smoke check at plan close (D-36-D2):** `git log --format='%B' main~3..main | grep -c '^Upstream-commit: '` returns EXACTLY 1.

**Purpose:** Upstream `b5f0a3ab` (11 files, +721/-118) carries user-visible improvements (better profile-save UX, faster PTY drain, startup-timeout for stuck agents, macOS learn diagnostics) AND the diagnostic helper restoration that bbdf7b85's escape-quote body rewrite depends on. Surgical port: keep fork's ExecConfig + 8+ load-bearing fork fields intact (Phase 18 capability_elevation, Phase 26 bypass_protection, Phase 27 audit_signer, Phase 31 broker ConPTY threading, Phase 34-08a env-filter, Phase 35 env-filter Windows wiring); absorb the helpers and the const change without restructuring the struct.

**Output:** 3 git commits / 8 files modified. ~244 LOC delta in `exec_strategy.rs`, ~46 in `execution_runtime.rs`, ~10-20 in `cli.rs`, body-level changes in `diagnostic.rs` + ancillary refinements in profile_save_runtime/pty_proxy/sandbox_log/startup_prompt.

**Scope ceiling (D-36-D1):** ExecConfig struct shape FROZEN. NO refactor to upstream's b5f0a3ab struct shape (deferred to v2.5-FU-4). NO new audit-event hooks (D-34-B2). NO new error variants beyond what upstream b5f0a3ab / bbdf7b85 carry.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/36-upst3-deep-closure/36-CONTEXT.md
@.planning/phases/36-upst3-deep-closure/36-RESEARCH.md
@.planning/phases/36-upst3-deep-closure/36-PATTERNS.md
@.planning/phases/36-upst3-deep-closure/36-VALIDATION.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-DIAG-EXEC-SUMMARY.md
@.planning/templates/upstream-sync-quick.md

<interfaces>
<!-- ExecConfig PRESERVATION invariant (PATTERNS.md § Code Examples Pattern 4 + D-36-D1). -->

From `crates/nono-cli/src/exec_strategy.rs` line 276 — DO NOT MODIFY in Commit 2:
```rust
pub struct ExecConfig<'a> {
    pub command: &'a [String],
    pub resolved_program: &'a std::path::Path,
    pub caps: &'a CapabilitySet,
    pub env_vars: Vec<(&'a str, &'a str)>,
    pub cap_file: Option<&'a std::path::Path>,
    pub current_dir: &'a std::path::Path,
    pub no_diagnostics: bool,
    pub threading: ThreadingContext,
    pub protected_paths: &'a [std::path::PathBuf],
    pub profile_save_base: Option<&'a str>,
    pub startup_timeout: Option<StartupTimeoutConfig<'a>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub seccomp_proxy_fallback: bool,
    pub allowed_env_vars: Option<Vec<String>>,
    pub denied_env_vars: Option<Vec<String>>,
}
```

<!-- EXISTING helper at line 1987 — NOT to be redefined; Commit 2 adds a NEW 3rd callsite (RESEARCH.md Drift Note 2). -->

From `crates/nono-cli/src/exec_strategy.rs` lines 1987-1991:
```rust
fn clear_signal_forwarding_target() {
    CHILD_PID.store(0, std::sync::atomic::Ordering::SeqCst);
    PTY_MASTER_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
    close_pause_pipe();
}
```

Existing callsites: line 825 + line 2047 (inside `impl Drop for SignalForwardingGuard`).
Commit 2 adds a NEW 3rd callsite immediately before the profile-save prompt.

<!-- analyze_error_output engine loop (Commit 1 wires helpers INTO this loop). -->

From `crates/nono/src/diagnostic.rs` lines 226-273:
```rust
for line in error_output.lines() {
    if blocked_protected_file.is_none() {
        blocked_protected_file = detect_protected_file_in_error_line(protected_paths, line);
    }
    if non_sandbox_failure.is_none() {
        non_sandbox_failure = detect_non_sandbox_failure_line(line);
    }
    if let Some(path) =
        current_dir.and_then(|cwd| extract_relative_write_path_from_line(line, cwd))
    {
        pending_relative_write = Some(path);
    }
    // [...]
}
```

Commit 1 ADDS new structured-property dispatch arms here using the 4 restored helpers — additive only, preserves `extract_relative_write_path_from_line` fallback chain.

<!-- Deferred-state comment blocks to DELETE in Commit 1 (PATTERNS.md § diagnostic.rs Commit 1). -->

From `crates/nono/src/diagnostic.rs` lines 402-419:
```rust
// NOTE (P34-DEFER-08b-2): upstream `b5f0a3ab` + `bbdf7b85` together add a
// structured-property parsing pipeline (extract_path_after_syscall_word,
// infer_access_from_structured_syscall_line, extract_structured_path_property,
// extract_structured_string_property) plus the wiring into `analyze_error_output`
// that consumes them. [...]
//
// Restoration plan: a dedicated D-20 manual-replay plan will (1) port the
// `b5f0a3ab` analyze_error_output refactor on top of fork's diagnostic engine,
// (2) restore the four helper functions, and (3) restore both tests. [...]
```

Matching block at lines 2258-2267. BOTH blocks DELETED in Commit 1 once helpers + wiring + test land.

<!-- D-19 trailer block (VERBATIM 6-line shape for Commit 3 ONLY; lowercase 'a' in 'Upstream-author'). -->

From `.planning/templates/upstream-sync-quick.md` § D-19 cherry-pick trailer block, lines 219-235:
```
Upstream-commit: bbdf7b85
Upstream-tag: v0.52.0
Upstream-author: Luke Hinds <lhinds@example.com>
Co-Authored-By: Luke Hinds <lhinds@example.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
**Field rules (verbatim from upstream-sync-quick.md):**
1. Trailer block separated from body by EXACTLY ONE blank line.
2. Field order FIXED: `Upstream-commit` → `Upstream-tag` → `Upstream-author` → `Co-Authored-By` → `Signed-off-by` (full name) → `Signed-off-by` (github handle).
3. `Upstream-author` + `Co-Authored-By` carry SAME name + email.
4. TWO `Signed-off-by:` lines (DCO + GitHub attribution).
5. **`Upstream-author` LOWERCASE 'a'** (NOT `Upstream-Author`).
6. Abbreviated 8-char SHA convention for `Upstream-commit:`.

NOTE: The email `<lhinds@example.com>` is a placeholder in the template. Resolve the actual upstream author email via `git show --format='%an <%ae>' bbdf7b85` before drafting Commit 3.

<!-- LearnArgs current state — `pub trace: bool` ABSENT; line 2272 typo verification deferred to execution time (RESEARCH.md Drift Note 4). -->

From `crates/nono-cli/src/cli.rs` lines 2261-2295 (current state, NO trace field):
```rust
#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct LearnArgs {
    /// Use a named profile to compare against (shows only missing paths)
    #[arg(long, short = 'p', value_name = "NAME", help_heading = "OPTIONS")]
    pub profile: Option<String>,

    /// Output discovered paths as JSON fragment for profile
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Timeout in seconds (default: run until command exits)
    #[arg(long, value_name = "SECS", help_heading = "OPTIONS")]
    pub timeout: Option<u64>,

    // ... continues with all, no_rdns, verbose, command, help fields
}
```

Commit 2 ADDS `pub trace: bool` as sibling to `verbose` with `#[arg(long, help_heading = "OPTIONS")]`. Doc-comment: `/// Enable detailed strace/dtrace output for path-discovery diagnostics`.
</interfaces>

<drift_notes>
1. **`clear_signal_forwarding_target` already exists** at exec_strategy.rs:1987 with 2 callsites (lines 825, 2047) — RESEARCH.md Drift Note 2. Commit 2 task is "ADD a new pre-profile-save callsite", NOT "restore the helper."
2. **`cli.rs:2272` typo verification deferred to execution time** — RESEARCH.md Drift Note 4. Current state per RESEARCH.md is canonical `///`; if a `\\ Timeout...` typo is present at execution time, Commit 2 fixes it inline alongside `LearnArgs.trace` restoration.
3. **`policy_cmd.rs` does NOT exist in fork** — Plan 36-03 does NOT touch this non-existent file. RESEARCH.md Drift Note 1.
4. **`bbdf7b85` upstream author email is `lhinds@example.com` in upstream-sync-quick.md template** — this is a placeholder. Resolve actual email via `git show --format='%an <%ae>' bbdf7b85` before Commit 3 trailer drafted.
5. **ExecConfig 17-field shape vs CONTEXT.md 11-field enumeration** (RESEARCH.md Code Examples Pattern 4 Note + Assumption A4) — D-36-D1 invariant is "preserve the shape," not "preserve a specific enumeration." Commit 2 confirms via grep that no field is removed; Plan 36-03 Commit 2 commit body enumerates the 17 actual fields it observes.
</drift_notes>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1 (Commit 1): Restore 4 diagnostic.rs helpers + wire into analyze_error_output + restore 1 test + delete 2 deferred-state comment blocks (b5f0a3ab surgical, D-20 manual-replay)</name>
  <files>crates/nono/src/diagnostic.rs</files>
  <read_first>
    - crates/nono/src/diagnostic.rs (full file structure — 3368 LOC; specifically lines 215-280 [analyze_error_output engine], lines 402-419 [deferred-state comment block 1 to DELETE], lines 421-440 [extract_relative_write_path_from_line sibling shape], lines 2258-2270 [deferred-state comment block 2 to DELETE])
    - upstream source for the 4 helpers: `git show upstream/b5f0a3ab -- crates/nono/src/diagnostic.rs` (capture exact upstream helper bodies + their wiring shape)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § crates/nono/src/diagnostic.rs — Plan 36-03 Commit 1
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-DIAG-EXEC-SUMMARY.md (records what Plan 34-08b absorbed vs deferred; the 4 helpers landed in Plan 34-08b commit 2/5 but were REMOVED in commit 4/5 to avoid `-D warnings dead-code` failures because their wiring was deferred)
    - CLAUDE.md § Coding Standards (no .unwrap; library should almost never panic — diagnostic.rs is in `crates/nono/` library tier; use Option<T> returns for parse helpers)
  </read_first>
  <behavior>
    - Test 1 (`test_analyze_error_output_detects_node_eperm_mkdir_as_write`): the restored test (per RESEARCH.md — landed in Plan 34-08b commit 2/5 but failed without wiring). Verifies `analyze_error_output` detects a Node.js EPERM mkdir error message as a write-access denial via the structured-property pipeline.
  </behavior>
  <action>
    1. **Capture upstream source for the 4 helpers**: run `git show upstream/b5f0a3ab -- crates/nono/src/diagnostic.rs > /tmp/b5f0a3ab-diagnostic.diff` and inspect. Identify:
       - Exact body of `extract_path_after_syscall_word`
       - Exact body of `infer_access_from_structured_syscall_line`
       - Exact body of `extract_structured_path_property`
       - Exact body of `extract_structured_string_property`
       - Exact wiring shape into `analyze_error_output` (which dispatch arms to add to the lines-iterator loop)
       - Exact body of `test_analyze_error_output_detects_node_eperm_mkdir_as_write`
    2. **Restore the 4 helpers** as module-level `fn`s in `crates/nono/src/diagnostic.rs`. Position them near the existing sibling `extract_relative_write_path_from_line` at line 421-440. Use `Option<T>` returns (library-tier "almost never panic" invariant); NO `.unwrap()` / `.expect()`.
    3. **Wire all 4 into `analyze_error_output`** at line ~215. Add structured-property dispatch arms inside the existing `for line in error_output.lines() { ... }` loop (lines 226-273). Additive only — preserve the existing `detect_protected_file_in_error_line`, `detect_non_sandbox_failure_line`, and `extract_relative_write_path_from_line` fallback chain.
    4. **Restore the test** `test_analyze_error_output_detects_node_eperm_mkdir_as_write` (from Plan 34-08b commit 2/5 history; if absent in git history, port verbatim from upstream `b5f0a3ab`). Inline in the existing `#[cfg(test)] mod tests` block at the bottom of `diagnostic.rs`.
    5. **DELETE the 2 deferred-state comment blocks** at lines 402-419 + 2258-2267 (or whichever lines they occupy at execution time — grep for `NOTE (P34-DEFER-08b-2)` and `Restoration plan: a dedicated D-20 manual-replay plan` to find them).
    6. Run `cargo build -p nono` — must succeed.
    7. Run `cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_node_eperm_mkdir_as_write` — must pass.
    8. Run `cargo clippy -p nono --all-targets -- -D warnings -D clippy::unwrap_used` — must be clean (the 4 helpers are now WIRED so no dead-code warnings).
    9. **Commit 1 git commit** with this body shape (D-20 manual-replay, NO `Upstream-commit:` trailer):
       ```
       refactor(36-03/1): restore b5f0a3ab diagnostic structured-property helpers + wiring

       Commit 1/3 of Plan 36-03 (D-20 manual-replay of upstream b5f0a3ab).

       Restores 4 helpers in crates/nono/src/diagnostic.rs that landed in
       Plan 34-08b commit 2/5 but were removed in commit 4/5 to avoid
       `-D warnings dead-code` failures (wiring was deferred to Phase 36):
         - extract_path_after_syscall_word
         - infer_access_from_structured_syscall_line
         - extract_structured_path_property
         - extract_structured_string_property

       Wires all 4 into `analyze_error_output` (lines 226-273 engine loop) as
       additive dispatch arms — preserves existing detect_protected_file_in_
       error_line / detect_non_sandbox_failure_line / extract_relative_write_
       path_from_line fallback chain.

       Restores test_analyze_error_output_detects_node_eperm_mkdir_as_write.

       Deletes 2 deferred-state NOTE blocks at lines 402-419 + 2258-2267
       (no longer needed post-restoration).

       Foundation for Commit 3 (bbdf7b85 escape-quote body rewrite — applies
       cleanly once the helpers + wiring are present).

       Library-tier discipline preserved: Option<T> returns; no .unwrap;
       library should almost never panic.

       Design source (D-20 manual replay):
       - b5f0a3ab (upstream v0.52.0, Luke Hinds): macos learn + run
         diagnostics surface

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
  </action>
  <verify>
    <automated>cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_node_eperm_mkdir_as_write 2>&amp;1 | tail -10 &amp;&amp; cargo clippy -p nono --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; grep -c 'NOTE (P34-DEFER-08b-2)' crates/nono/src/diagnostic.rs</automated>
  </verify>
  <acceptance_criteria>
    - All 4 helpers exist in `crates/nono/src/diagnostic.rs` (grep: `grep -cE 'fn extract_path_after_syscall_word|fn infer_access_from_structured_syscall_line|fn extract_structured_path_property|fn extract_structured_string_property' crates/nono/src/diagnostic.rs` returns 4).
    - 4 helpers WIRED into `analyze_error_output` (grep: `grep -A 80 'fn analyze_error_output' crates/nono/src/diagnostic.rs | grep -cE 'extract_structured_path_property|extract_structured_string_property|extract_path_after_syscall_word|infer_access_from_structured_syscall_line'` returns ≥ 2).
    - Deferred-state comment blocks DELETED (grep: `grep -c 'NOTE (P34-DEFER-08b-2)' crates/nono/src/diagnostic.rs` returns 0).
    - Test restored + passes: `cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_node_eperm_mkdir_as_write` exits 0.
    - Clippy clean (no dead-code warnings now that helpers are wired): `cargo clippy -p nono --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
    - No `.unwrap()` / `.expect()` in restored helpers (grep `extract_path_after_syscall_word` body etc.): `grep -A 20 'fn extract_path_after_syscall_word' crates/nono/src/diagnostic.rs | grep -c '\.unwrap()'` returns 0.
    - **D-20 manual-replay shape**: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0 (Commit 1 has NO D-19 trailer).
    - Commit body cites `b5f0a3ab` design source: `git log --format='%B' main~1..main | grep -c 'b5f0a3ab'` returns ≥ 1.
    - Test ID **36-03-c1-* / T-36-03-DIAG-HELPERS**: helpers restored + wired + test passes.
  </acceptance_criteria>
  <done>Commit 1 landed on `main`. 4 helpers restored + wired + 1 test passes; deferred-state comment blocks gone; Commit 3's bbdf7b85 cherry-pick now has its diff-target lines present.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2 (Commit 2): b5f0a3ab surgical exec_strategy + execution_runtime + cli.rs LearnArgs.trace + 4 ancillary refinements (D-20 manual-replay; D-36-D1 ExecConfig shape FROZEN)</name>
  <files>crates/nono-cli/src/exec_strategy.rs, crates/nono-cli/src/execution_runtime.rs, crates/nono-cli/src/cli.rs, crates/nono-cli/src/profile_save_runtime.rs, crates/nono-cli/src/pty_proxy.rs, crates/nono-cli/src/sandbox_log.rs, crates/nono-cli/src/startup_prompt.rs</files>
  <read_first>
    - crates/nono-cli/src/exec_strategy.rs (lines 270-330 — ExecConfig struct boundary; lines 825 + 1987 + 2047 — clear_signal_forwarding_target helper + 2 existing callsites; full file 4148 LOC)
    - crates/nono-cli/src/execution_runtime.rs (lines 11-50 — existing helper shape `apply_pre_fork_sandbox`, `cleanup_capability_state_file`, `next_capability_state_file_path`; lines 465-486 — existing `#[cfg(test)] mod tests` shape)
    - crates/nono-cli/src/cli.rs (lines 2263-2295 — current LearnArgs struct; line 2272 — verify typo state at execution time per RESEARCH.md Drift Note 4)
    - upstream source: `git show upstream/b5f0a3ab -- crates/nono-cli/src/exec_strategy.rs crates/nono-cli/src/execution_runtime.rs crates/nono-cli/src/cli.rs` (capture upstream's exact helper bodies + LearnArgs.trace field shape)
    - crates/nono-cli/src/profile_save_runtime.rs, pty_proxy.rs, sandbox_log.rs, startup_prompt.rs (capture pre-plan state; identify the minor refinements b5f0a3ab carries)
    - crates/nono-cli/tests/attach_streaming_integration.rs (existence per RESEARCH.md A3 verification — Phase 17 regression coverage)
    - crates/nono-shell-broker/src/main.rs (existence per RESEARCH.md A3 — Phase 31 broker ConPTY)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § exec_strategy.rs + § execution_runtime.rs + § cli.rs LearnArgs.trace restoration
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08b-DIAG-EXEC-SUMMARY.md
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-D3 (PTY-quiet-period regression coverage requirement)
  </read_first>
  <behavior>
    - Test 1 (in execution_runtime.rs `#[cfg(test)] mod tests`): `test_should_apply_startup_timeout_interactive_arm` — for interactive context, returns the appropriate boolean per upstream b5f0a3ab semantics.
    - Test 2: `test_should_apply_startup_timeout_non_interactive_arm` — non-interactive context returns the other arm.
    - Test 3: `test_startup_timeout_profile_returns_config` — verifies the helper returns the expected `Option<StartupTimeoutConfig<'_>>` shape for the timeout-set case.
    - Test 4: `test_compute_executable_identity_resolves_path` — passes a known path; verifies identity is computed deterministically.
    - Phase 17 attach-streaming regression: `cargo test -p nono-cli --test attach_streaming_integration` continues to pass (validates POST_EXIT_PTY_DRAIN_TIMEOUT 100ms doesn't regress attach-streaming).
  </behavior>
  <action>
    1. **Capture upstream source** for all Commit 2 surfaces: `git show upstream/b5f0a3ab -- crates/nono-cli/src/exec_strategy.rs crates/nono-cli/src/execution_runtime.rs crates/nono-cli/src/cli.rs crates/nono-cli/src/profile_save_runtime.rs crates/nono-cli/src/pty_proxy.rs crates/nono-cli/src/sandbox_log.rs crates/nono-cli/src/startup_prompt.rs > /tmp/b5f0a3ab-cli.diff`. Inspect each file.
    2. **`exec_strategy.rs`**:
       - **VERIFY ExecConfig struct UNCHANGED** (D-36-D1 invariant). Before any edit, `grep -A 25 'pub struct ExecConfig' crates/nono-cli/src/exec_strategy.rs` and record the 17-field shape. After all edits, re-grep and DIFF — must be identical. If any field is added / removed / reordered / retyped: STOP and escalate.
       - **ADD `fn should_offer_profile_save(...)` predicate** at module-level near the profile-save call path. Mirror upstream b5f0a3ab's signature; use `&ExecConfig<'_>` or threading state as args, NOT new struct fields.
       - **ADD `const POST_EXIT_PTY_DRAIN_TIMEOUT: Duration = Duration::from_millis(100)`** at module scope near other timing constants (search `Duration::from_millis` for placement). Comment block (PATTERNS.md exact target):
         ```rust
         // Plan 36-03 Commit 2: per upstream b5f0a3ab, the post-exit PTY drain
         // quiet period is reduced from 250ms to 100ms.
         //
         // REGRESSION COVERAGE per D-36-D3: this MUST NOT regress Phase 17
         // attach-streaming (crates/nono-cli/tests/attach_streaming_integration.rs)
         // or Phase 31 broker ConPTY (crates/nono-shell-broker/). Phase 15 5-row
         // detached-console smoke gate (close-gate step 6) double-checks.
         ```
         If a previous `POST_EXIT_PTY_DRAIN_TIMEOUT 250ms` const exists in fork, REPLACE its value (250 → 100). Verify via grep before the change.
       - **ADD NEW pre-profile-save callsite of existing `clear_signal_forwarding_target()`**. Helper at line 1987 stays as-is. Find the profile-save prompt location (search `profile_save_base` reads + `should_offer_profile_save` calls). Add a single `clear_signal_forwarding_target();` line immediately BEFORE the prompt is shown. Total callsites go from 2 to 3.
       - **ADD startup-timeout machinery integration**. Per upstream b5f0a3ab: integrate `StartupTimeoutConfig` consumption at the existing field-read site (`config.startup_timeout` references in exec_strategy.rs). Logic per upstream: if `startup_timeout` is set + the timeout fires → terminate child + emit diagnostic.
    3. **`execution_runtime.rs`**:
       - **ADD `fn should_apply_startup_timeout(...)`** as module-level helper. Mirror existing helper shape at lines 34-50.
       - **ADD `fn startup_timeout_profile(...)`** returning `Option<StartupTimeoutConfig<'_>>`.
       - **ADD `fn compute_executable_identity(...)`** returning the identity type (capture upstream's return-type shape).
       - **ADD 4 tests** to existing `#[cfg(test)] mod tests` at line 465 — mirror its shape. Tests enumerated in `<behavior>`.
    4. **`cli.rs` `LearnArgs.trace` restoration**:
       - Open lines 2263-2295. Verify current state matches `<interfaces>` block above.
       - ADD `pub trace: bool` as sibling to `verbose`:
         ```rust
         /// Enable detailed strace/dtrace output for path-discovery diagnostics
         #[arg(long, help_heading = "OPTIONS")]
         pub trace: bool,
         ```
       - **Verify line 2272 typo state** (RESEARCH.md Drift Note 4). Run `sed -n '2270,2275p' crates/nono-cli/src/cli.rs`. If line 2272 reads `/// Timeout in seconds (default: run until command exits)` → canonical, no fix needed. If line 2272 reads `\\ Timeout...` → fix to canonical `///` shape inline.
    5. **Ancillary refinements** in `profile_save_runtime.rs`, `pty_proxy.rs`, `sandbox_log.rs`, `startup_prompt.rs`: apply the minor b5f0a3ab refinements per upstream diff. Read upstream source via `git show upstream/b5f0a3ab -- <file>`; apply each refinement individually. KEEP fork's existing surface intact where upstream's change conflicts (D-34-B1 fork-divergence catalog; verify each).
    6. **Phase 17 attach-streaming regression check** (D-36-D3): run `cargo test -p nono-cli --test attach_streaming_integration` — MUST pass. If it surfaces a flake from the 250→100ms timeout change:
       - First retry 3 times to rule out timing noise.
       - If consistent flake: investigate; compromise to 150ms per D-36-D3 if needed; OR rollback the timeout-rider entirely (Plan 36-03 still ships b5f0a3ab helpers + LearnArgs.trace + bbdf7b85, just without the quiet-period change). Document choice in Commit 2 body.
    7. **Phase 31 broker ConPTY smoke gate** (D-36-D3): if Windows shell + broker available locally, run the 5-row detached-console smoke flow. If not available, skip-document per close-gate step 6 with rationale.
    8. **Phase 10 / D-02 Windows admin gate non-regression** check: verify `crates/nono-cli/src/learn_runtime.rs` still carries `print_macos_run_guidance` + `command_display::format_command_line` import from Plan 34-08b (grep both).
    9. Run `cargo build --workspace --all-features` + `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` + `cargo test --workspace --all-features`. All green.
    10. **Commit 2 git commit** with this body shape (D-20 manual-replay, NO `Upstream-commit:` trailer):
        ```
        feat(36-03/2): port b5f0a3ab surgical exec_strategy + execution_runtime + cli.rs LearnArgs.trace

        Commit 2/3 of Plan 36-03 (D-20 manual-replay of upstream b5f0a3ab).

        Surgical port keeping fork's ExecConfig 17-field shape intact per D-36-D1:
        [enumerate the 17 fields here — verified unchanged at commit time].

        exec_strategy.rs changes:
          - ADD should_offer_profile_save() predicate guarding profile-save prompt.
          - ADD const POST_EXIT_PTY_DRAIN_TIMEOUT = 100ms (was 250ms; D-36-D3
            regression coverage: Phase 17 attach-streaming green, Phase 31
            broker ConPTY 5-row smoke green).
          - ADD new pre-profile-save callsite of existing clear_signal_forwarding_
            target (helper at line 1987 unchanged; total callsites 2 → 3).
          - ADD startup-timeout machinery integration consuming the existing
            ExecConfig.startup_timeout field.

        execution_runtime.rs changes:
          - ADD should_apply_startup_timeout helper.
          - ADD startup_timeout_profile helper.
          - ADD compute_executable_identity helper.
          - ADD 4 tests for startup-timeout interactive vs non-interactive arms.

        cli.rs changes:
          - RESTORE LearnArgs.trace field (sibling to verbose; doc-comment
            covers strace/dtrace surface).
          - [If line 2272 typo present at execution time: fix \\ Timeout → ///
            Timeout per RESEARCH.md Drift Note 4. If canonical already: no-op.]

        Ancillary refinements (profile_save_runtime.rs, pty_proxy.rs,
        sandbox_log.rs, startup_prompt.rs): apply b5f0a3ab minor edits per
        upstream diff; fork retention preserved per D-34-B1 where upstream
        conflicts.

        Regression coverage (D-36-D3):
          - Phase 17 attach-streaming: cargo test --test attach_streaming_
            integration GREEN.
          - Phase 31 broker ConPTY: Phase 15 5-row detached-console smoke
            GREEN [or documented-skipped].
          - Phase 10 / D-02 Windows admin gate in learn_runtime.rs: verified
            print_macos_run_guidance import + Windows admin gate preserved
            (Plan 34-08b absorption intact).

        Design source (D-20 manual replay):
        - b5f0a3ab (upstream v0.52.0, Luke Hinds): exec-strategy + diagnostics

        Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
        Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
        ```
  </action>
  <verify>
    <automated>cargo test --workspace --all-features 2>&amp;1 | tail -10 &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; grep -c 'POST_EXIT_PTY_DRAIN_TIMEOUT' crates/nono-cli/src/exec_strategy.rs &amp;&amp; grep -c 'clear_signal_forwarding_target' crates/nono-cli/src/exec_strategy.rs &amp;&amp; grep -c 'pub trace: bool' crates/nono-cli/src/cli.rs &amp;&amp; cargo test -p nono-cli --test attach_streaming_integration 2>&amp;1 | tail -10</automated>
  </verify>
  <acceptance_criteria>
    - **ExecConfig struct UNCHANGED**: field count + names + types verified identical pre-/post-Commit-2. Acceptance command: `grep -A 25 'pub struct ExecConfig' crates/nono-cli/src/exec_strategy.rs > /tmp/post.txt; diff /tmp/pre.txt /tmp/post.txt` returns empty diff. (Capture `/tmp/pre.txt` before any Commit 2 edit.)
    - `should_offer_profile_save` exists (grep: `grep -c 'fn should_offer_profile_save' crates/nono-cli/src/exec_strategy.rs` returns 1).
    - `POST_EXIT_PTY_DRAIN_TIMEOUT` set to 100ms (grep: `grep -A 2 'POST_EXIT_PTY_DRAIN_TIMEOUT' crates/nono-cli/src/exec_strategy.rs | grep -c 'from_millis(100)'` returns 1).
    - `clear_signal_forwarding_target` helper preserved + 3 total callsites (grep: `grep -c 'clear_signal_forwarding_target' crates/nono-cli/src/exec_strategy.rs` returns ≥ 4 — 1 definition + 3 callsites).
    - 3 new `execution_runtime.rs` helpers exist (grep: `grep -cE 'fn should_apply_startup_timeout|fn startup_timeout_profile|fn compute_executable_identity' crates/nono-cli/src/execution_runtime.rs` returns 3).
    - `LearnArgs.trace` restored (grep: `grep -A 35 'pub struct LearnArgs' crates/nono-cli/src/cli.rs | grep -c 'pub trace: bool'` returns 1).
    - cli.rs line 2272 canonical `///` shape (grep: `sed -n '2270,2275p' crates/nono-cli/src/cli.rs | grep -c '^[[:space:]]*///'` returns ≥ 1).
    - Phase 17 attach-streaming regression PASSES: `cargo test -p nono-cli --test attach_streaming_integration` exits 0.
    - Phase 10 / D-02 Windows admin gate preserved (grep: `grep -c 'print_macos_run_guidance' crates/nono-cli/src/learn_runtime.rs` returns ≥ 1).
    - 4 new execution_runtime tests pass: `cargo test -p nono-cli --lib execution_runtime::tests` includes the 4 startup-timeout tests; all green.
    - `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` clean.
    - **D-20 manual-replay shape**: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0 (Commit 2 has NO D-19 trailer).
    - Commit body cites `b5f0a3ab` design source: `git log --format='%B' main~1..main | grep -c 'b5f0a3ab'` returns ≥ 1.
    - Test IDs **36-03-c2-* / T-36-03-EXEC-HELPERS** + **T-36-03-PTY-QUIET**: helpers exist, callsite added, ExecConfig preserved, Phase 17 + Phase 31 non-regression.
  </acceptance_criteria>
  <done>Commit 2 landed on `main`. b5f0a3ab surgical port complete with fork ExecConfig 17-field shape preserved; PTY-quiet-period change non-regressive; LearnArgs.trace restored.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3 (Commit 3): bbdf7b85 escape-quote body rewrite + 2 new tests (D-19 cherry-pick with verbatim 6-line trailer block — THIS IS THE ONE D-19 COMMIT IN PHASE 36)</name>
  <files>crates/nono/src/diagnostic.rs</files>
  <read_first>
    - crates/nono/src/diagnostic.rs (post-Commit-1 state with the 4 restored helpers + their wiring; `extract_structured_string_property` is the body-rewrite target)
    - upstream commit: `git show upstream/bbdf7b85` (full diff — this commit's diff-target lines exist in fork ONLY AFTER Commit 1 lands; cherry-pick should now apply cleanly or near-cleanly)
    - `git show --format='%an <%ae>' upstream/bbdf7b85` — get actual upstream author email (RESEARCH.md drift note 4 — placeholder `lhinds@example.com` in upstream-sync-quick.md; use the real email)
    - .planning/templates/upstream-sync-quick.md § D-19 cherry-pick trailer block (lines 219-235 — verbatim 6-line shape; lowercase 'a' in `Upstream-author:`)
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-D2 (smoke check: `git log --format='%B' main~3..main | grep -c '^Upstream-commit: '` MUST equal exactly 1 after Plan 36-03 closes)
  </read_first>
  <behavior>
    - Test 1 (`test_analyze_error_output_detects_structured_node_eperm_mkdir_path`): from b5f0a3ab — exercises the structured-property pipeline with a Node.js mkdir EPERM error carrying a structured path.
    - Test 2 (`test_analyze_error_output_detects_structured_path_with_escaped_quote`): from bbdf7b85 — exercises escape-quoted character handling in `extract_structured_string_property` (e.g., `path: '/Users/luke/it\'s/pkg'`).
  </behavior>
  <action>
    1. **Verify Commit 1 landed cleanly** (helpers restored + wiring + Commit 1 test passing). Without Commit 1, bbdf7b85 has no diff-target lines.
    2. **Resolve actual upstream author email**: `git show --format='%an <%ae>' upstream/bbdf7b85`. Record exactly — this is the email used in BOTH the `Upstream-author:` line AND the `Co-Authored-By:` line of the D-19 trailer.
    3. **Attempt clean cherry-pick**: `git cherry-pick upstream/bbdf7b85 -- crates/nono/src/diagnostic.rs`. If it applies cleanly: proceed. If it conflicts (because Plan 34-08b previously modified the surrounding context): resolve manually, preserving the bbdf7b85 INTENT (body rewrite of `extract_structured_string_property` + 2 new tests) on top of fork's current `analyze_error_output` shape.
    4. **Verify the body rewrite**: `extract_structured_string_property` now handles escape-quoted characters per bbdf7b85. Run `git diff upstream/bbdf7b85^..upstream/bbdf7b85 -- crates/nono/src/diagnostic.rs` to capture upstream's exact diff; verify the rewrite landed.
    5. **Verify the 2 new tests** landed:
       - `test_analyze_error_output_detects_structured_node_eperm_mkdir_path` (from b5f0a3ab, but bbdf7b85 carries it forward)
       - `test_analyze_error_output_detects_structured_path_with_escaped_quote` (native to bbdf7b85)
    6. Run both tests: `cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_structured_node_eperm_mkdir_path` AND `cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_structured_path_with_escaped_quote`. Both must pass.
    7. Run `cargo clippy -p nono --all-targets -- -D warnings -D clippy::unwrap_used` — clean.
    8. **Amend the commit message** to attach the verbatim 6-line D-19 trailer block (`.planning/templates/upstream-sync-quick.md` § D-19). Use `git commit --amend` (this is amending the CHERRY-PICKED commit, not amending a prior commit — the cherry-pick creates a new commit on top of Commit 2, and we amend its message ONLY before push). The full commit message:
       ```
       fix(diagnostic): parse escaped quotes in structured properties

       Body-rewrite extract_structured_string_property to handle escape-quoted
       characters in structured path properties (e.g., `path: '/Users/luke/it\'s/pkg'`).
       Adds 2 tests:
       - test_analyze_error_output_detects_structured_node_eperm_mkdir_path
       - test_analyze_error_output_detects_structured_path_with_escaped_quote

       Commit 3/3 of Plan 36-03 (the ONE D-19 cherry-pick in Phase 36, per
       D-36-D2). Cherry-picks cleanly on top of Plan 36-03 Commit 1's helper
       restoration + analyze_error_output wiring — without Commit 1, this
       commit's diff-target lines don't exist in fork.

       Closes REQ-PORT-CLOSURE-05 acceptance #4 (bbdf7b85 escape-quote test
       passes).

       Upstream-commit: bbdf7b85
       Upstream-tag: v0.52.0
       Upstream-author: Luke Hinds <[ACTUAL_EMAIL_FROM_STEP_2]>
       Co-Authored-By: Luke Hinds <[ACTUAL_EMAIL_FROM_STEP_2]>
       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
       **CRITICAL trailer rules (verbatim per upstream-sync-quick.md):**
       - Exactly ONE blank line between body and trailer block.
       - Field order FIXED: `Upstream-commit` → `Upstream-tag` → `Upstream-author` → `Co-Authored-By` → `Signed-off-by` (full name) → `Signed-off-by` (github handle).
       - `Upstream-author` and `Co-Authored-By` carry the SAME name + email.
       - Lowercase 'a' in `Upstream-author:` (NOT `Upstream-Author`).
       - Abbreviated 8-char SHA for `Upstream-commit:` (not full 40-char).
       - DCO sign-off duplicated (full name + GitHub handle).
    9. **Plan-close smoke check** (D-36-D2 invariant): `git log --format='%B' main~3..main | grep -c '^Upstream-commit: '` — MUST return exactly 1 (Commit 1 + Commit 2 have NO trailer; Commit 3 has the ONE trailer).
  </action>
  <verify>
    <automated>cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_structured_node_eperm_mkdir_path 2>&amp;1 | tail -5 &amp;&amp; cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_structured_path_with_escaped_quote 2>&amp;1 | tail -5 &amp;&amp; git log --format='%B' main~3..main | grep -c '^Upstream-commit: '</automated>
  </verify>
  <acceptance_criteria>
    - Both tests pass:
      - `cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_structured_node_eperm_mkdir_path` exits 0
      - `cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_structured_path_with_escaped_quote` exits 0
    - Both tests exist in source (grep: `grep -cE 'fn test_analyze_error_output_detects_structured_node_eperm_mkdir_path|fn test_analyze_error_output_detects_structured_path_with_escaped_quote' crates/nono/src/diagnostic.rs` returns 2).
    - Clippy clean: `cargo clippy -p nono --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
    - **D-19 trailer present and VERBATIM** on Commit 3 (HEAD):
      - `git log --format='%B' -n 1 HEAD | grep -c '^Upstream-commit: bbdf7b85'` returns 1
      - `git log --format='%B' -n 1 HEAD | grep -c '^Upstream-tag: v0.52.0'` returns 1
      - `git log --format='%B' -n 1 HEAD | grep -c '^Upstream-author: '` returns 1 (lowercase 'a' — `grep -c '^Upstream-Author: '` should return 0)
      - `git log --format='%B' -n 1 HEAD | grep -c '^Co-Authored-By: '` returns 1
      - `git log --format='%B' -n 1 HEAD | grep -c '^Signed-off-by: '` returns ≥ 2 (DCO + GitHub handle)
    - **D-36-D2 smoke check passes**: `git log --format='%B' main~3..main | grep -c '^Upstream-commit: '` returns EXACTLY 1.
    - Test ID **36-03-c3-* / T-36-03-ESCAPE-QUOTE**: escape-quote handling + D-19 trailer provenance verified.
  </acceptance_criteria>
  <done>Commit 3 landed on `main` with the verbatim D-19 trailer; smoke check confirms only this commit (not Commits 1 or 2) carries `Upstream-commit:`. Plan 36-03's 3-commit sequence complete.</done>
</task>

<task type="auto">
  <name>Task 4: Plan-close 8-step gate + smoke verification (per D-36-A5 + D-36-D2)</name>
  <files>(verification only — 3 commits already landed)</files>
  <read_first>
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-A5 (close-gate steps; macOS clippy step 4 LOAD-BEARING per b5f0a3ab macOS surface)
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-D2 (3-commit smoke check)
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-D3 (regression coverage final)
    - memory/feedback_clippy_cross_target.md
  </read_first>
  <action>
    1. Run all 8 D-36-A5 close-gate steps on Windows host. ALL 8 are load-bearing for Plan 36-03 (b5f0a3ab touches macOS-gated paths + PTY-quiet-period affects Windows broker + LearnArgs.trace touches learn integration):
       1. `cargo test --workspace --all-features` — must include all new tests from Commits 1+2+3; all green
       2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used`
       3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`
       4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` — **LOAD-BEARING** per CONTEXT.md D-36-A5 step 4: b5f0a3ab introduces macOS `print_macos_run_guidance` + macOS-gated learn diagnostics; PTY-quiet-period change touches macOS-relevant code paths
       5. `cargo fmt --all -- --check`
       6. **Phase 15 5-row detached-console smoke gate** (Windows host): `nono run --detached <cmd>` → `nono ps` → `nono attach <id>` → detach (Ctrl-A D) → `nono stop <id>`. Must complete without hang or timeout. If Windows shell + admin not available locally: skip-document with rationale + flag for follow-up.
       7. `cargo test -p nono-cli --test wfp_port_integration` (or documented-skipped if WFP host coverage unavailable).
       8. `cargo test -p nono-cli --test learn_windows_integration` (or documented-skipped if learn integration host coverage unavailable). LearnArgs.trace restoration in Commit 2 may interact with this; preferred to run.
    2. **D-36-D2 smoke check** (final): `git log --format='%B' main~3..main | grep -c '^Upstream-commit: '` MUST return exactly 1.
    3. **D-36-D3 regression coverage final verification**:
       - Phase 17 attach-streaming: `cargo test -p nono-cli --test attach_streaming_integration` exits 0
       - Phase 31 broker ConPTY: 5-row smoke from step 6 above passed (or documented-skipped)
       - Phase 10 / D-02 Windows admin gate: `grep -c 'print_macos_run_guidance' crates/nono-cli/src/learn_runtime.rs` returns ≥ 1 (Plan 34-08b absorption preserved)
    4. **DO NOT amend or rewrite any of Commit 1, 2, or 3.** If any close-gate step fails, fix forward with a NEW commit (Commit 4 if needed), document in commit body. Per CLAUDE.md git-safety, NEVER `--amend` a published commit.
  </action>
  <verify>
    <automated>cargo test --workspace --all-features 2>&amp;1 | tail -10 &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; cargo fmt --all -- --check &amp;&amp; git log --format='%B' main~3..main | grep -c '^Upstream-commit: ' &amp;&amp; cargo test -p nono-cli --test attach_streaming_integration 2>&amp;1 | tail -5</automated>
  </verify>
  <acceptance_criteria>
    - Close-gate steps 1, 2, 3, 4, 5 exit 0. Step 4 (macOS cross-target clippy) explicitly green — load-bearing per D-36-A5.
    - **D-36-D2 smoke check passes**: `git log --format='%B' main~3..main | grep -c '^Upstream-commit: '` returns exactly 1.
    - **D-36-D3 regression coverage**: Phase 17 attach-streaming PASSES (`cargo test --test attach_streaming_integration` exits 0); Phase 31 broker ConPTY PASSES OR documented-skipped; Phase 10 / D-02 Windows admin gate preserved.
    - 3 commits visible on `main`: `git rev-list --count main~3..main` returns 3.
    - Per-commit trailer audit:
      - Commit `main~2` (Commit 1): `git log --format='%B' -n 1 main~2 | grep -c '^Upstream-commit: '` returns 0
      - Commit `main~1` (Commit 2): `git log --format='%B' -n 1 main~1 | grep -c '^Upstream-commit: '` returns 0
      - Commit `HEAD` (Commit 3): `git log --format='%B' -n 1 HEAD | grep -c '^Upstream-commit: bbdf7b85'` returns 1
    - DCO trailer on all 3 commits: `git log --format='%B' main~3..main | grep -c '^Signed-off-by: '` returns ≥ 3 (≥ 1 per commit × 3 commits).
  </acceptance_criteria>
  <done>All 8 close-gate steps green; D-36-D2 smoke check satisfied; D-36-D3 regression coverage verified; 3 commits of Plan 36-03 complete on `main`.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Child process error output → `analyze_error_output` library function | Untrusted input; lines may contain malformed structured properties; library MUST NOT panic on any byte sequence |
| `extract_structured_string_property` parsing escape-quoted characters | Trusted normalization boundary; bbdf7b85 closes a Information Disclosure / Tampering vuln where attacker-controlled diagnostic output could spoof structured paths |
| `clear_signal_forwarding_target` callsite ordering | Trusted ordering; the new pre-profile-save callsite must execute BEFORE the user is prompted; race here creates Information Disclosure (PTY state visible to user post-child-exit) |
| `POST_EXIT_PTY_DRAIN_TIMEOUT` reduction (250→100ms) | Tampering / Information Disclosure boundary; faster drain risks losing legitimate child output OR exposing partial state (D-36-D3 regression coverage) |
| `LearnArgs.trace` field exposure | New CLI surface; user-supplied trace flag triggers strace/dtrace surface — must compose with existing learn-runtime privilege model |
| ExecConfig 17-field shape | Trusted invariant boundary; D-36-D1 forbids struct mutation — any field add/remove/reorder would regress Phase 18/26/27/31/34-08a/35-01 fork surfaces |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-36-03-DIAG-HELPERS | Tampering | Restored diagnostic helpers (`extract_path_after_syscall_word`, etc.) accept malformed structured properties and panic | mitigate | Commit 1 helpers use `Option<T>` returns (library-tier discipline per CLAUDE.md "library should almost never panic"). NO `.unwrap()` outside `#[cfg(test)]`. `analyze_error_output` engine loop handles `None` returns by continuing to the next dispatch arm — fail-safe by construction. |
| T-36-03-EXEC-HELPERS | Tampering / Elevation of Privilege | New helpers in execution_runtime.rs / exec_strategy.rs incorrectly compute startup-timeout or executable-identity, causing wrong child to be terminated or wrong identity recorded in audit log | mitigate | Task 2 includes 4 tests for interactive-vs-non-interactive arms + executable-identity resolution. `compute_executable_identity` uses path canonicalization (CLAUDE.md § Path Handling). |
| T-36-03-EXECCFG-SHAPE-DROP | Elevation of Privilege | ExecConfig struct silently mutated by Commit 2 — a fork-only field (e.g., `audit_signer`, `capability_elevation`, `bypass_protection_paths`) is removed, regressing Phase 18/26/27/31 surfaces | mitigate | Task 2 step 2 explicit pre-/post-diff capture (`grep -A 25 'pub struct ExecConfig' > /tmp/pre.txt`, then diff post-edit). Acceptance criterion enforces zero diff on the struct boundary. |
| T-36-03-PTY-QUIET | Information Disclosure | `POST_EXIT_PTY_DRAIN_TIMEOUT` 100ms drains too fast, leaking partial child process state OR truncating legitimate child output | mitigate | Task 2 step 6 + Task 4 verify Phase 17 attach-streaming + Phase 31 broker ConPTY tests pass. D-36-D3 + v2.5-FU-6 deferral path: if a flake surfaces, compromise to 150ms OR rollback the quiet-period rider entirely (document choice in Commit 2 body). |
| T-36-03-CLEAR-SIGNAL-ORDER | Race / Information Disclosure | New pre-profile-save `clear_signal_forwarding_target()` callsite is placed AFTER the prompt instead of BEFORE, leaking signal-forwarding state to user-input handling | mitigate | Task 2 step 2 instructs callsite placement IMMEDIATELY BEFORE the prompt. Phase 17 attach-streaming integration coverage catches signal-state regressions. PATTERNS.md § exec_strategy.rs Commit 2 invariant locks this. |
| T-36-03-LEARN-TRACE-PRIV | Elevation of Privilege | New `LearnArgs.trace` flag triggers strace/dtrace surface that requires elevated privileges; if the privilege gate is missing, low-priv user can crash nono or escape sandbox | accept | upstream b5f0a3ab is the source of `LearnArgs.trace`; the privilege gate is upstream's responsibility. Phase 10 / D-02 Windows admin gate (in `learn_runtime.rs`) is preserved per Task 2 step 8. If a privilege regression surfaces during execution, escalate via D-36-A5 STOP trigger. |
| T-36-03-ESCAPE-QUOTE | Information Disclosure / Tampering | `extract_structured_string_property` mishandles escape-quoted characters, allowing attacker to spoof diagnostic output (e.g., inject false path claims) | mitigate | Commit 3 (bbdf7b85 D-19 cherry-pick) body-rewrite handles escape-quoted characters per upstream's locked invariant. Test `test_analyze_error_output_detects_structured_path_with_escaped_quote` locks the parsing invariant. |
| T-36-03-D19-TRAILER-DRIFT | Repudiation | D-19 trailer on Commit 3 deviates from verbatim 6-line shape (wrong case in `Upstream-author`, wrong field order, missing DCO sign-off, etc.); upstream provenance lost | mitigate | Task 3 step 8 explicit trailer-block specification with CRITICAL rules enumerated. Acceptance criteria explicitly grep each field's exact shape (lowercase 'a' in Upstream-author, field order, DCO duplication). D-36-D2 smoke check confirms exactly 1 trailer on the 3-commit chain. |
| T-36-03-COMMIT-AMEND-PUBLIC | Repudiation | Plan 36-03 amends one of the 3 published commits (violating CLAUDE.md git-safety) | mitigate | Task 4 step 4 explicitly forbids `--amend` on published commits. Fix-forward with new commit if any post-commit issue arises. |
| T-36-03-LIB-NONO-PANIC | Denial of Service | Diagnostic helpers in `crates/nono/` library tier panic on malformed input | mitigate | Library tier discipline: CLAUDE.md "Libraries should almost never panic." Commit 1 helpers use `Option<T>` returns; NO `.unwrap()` / `.expect()` in non-test code. Clippy `unwrap_used` gate catches violations. |
| T-36-03-CFG-MACOS-DROP | Tampering | macOS-gated code from b5f0a3ab (e.g., `print_macos_run_guidance` integration) silently regresses because Windows-host dev environment doesn't exercise it | mitigate | Close-gate step 4 (`cargo clippy --target x86_64-apple-darwin`) is LOAD-BEARING for Plan 36-03 per D-36-A5. Task 4 explicitly verifies macOS clippy step 4 green. |
</threat_model>

<verification>
## Per-Plan Verification

1. **3-commit shape verified:**
   ```bash
   git rev-list --count main~3..main
   # Expected: 3
   ```

2. **D-36-D2 smoke check (the central Plan 36-03 invariant):**
   ```bash
   git log --format='%B' main~3..main | grep -c '^Upstream-commit: '
   # Expected: EXACTLY 1 (only Commit 3)
   ```

3. **Per-commit trailer audit:**
   ```bash
   git log --format='%B' -n 1 main~2 | grep -c '^Upstream-commit: '  # Commit 1: expected 0
   git log --format='%B' -n 1 main~1 | grep -c '^Upstream-commit: '  # Commit 2: expected 0
   git log --format='%B' -n 1 HEAD    | grep -c '^Upstream-commit: bbdf7b85'  # Commit 3: expected 1
   ```

4. **D-19 trailer verbatim shape on Commit 3:**
   ```bash
   git log --format='%B' -n 1 HEAD | grep -c '^Upstream-author: '
   # Expected: 1 (lowercase 'a')
   git log --format='%B' -n 1 HEAD | grep -c '^Upstream-Author: '
   # Expected: 0 (wrong case rejected)
   git log --format='%B' -n 1 HEAD | grep -c '^Signed-off-by: '
   # Expected: ≥ 2 (DCO + GitHub handle)
   ```

5. **4 diagnostic helpers restored + wired:**
   ```bash
   grep -cE 'fn extract_path_after_syscall_word|fn infer_access_from_structured_syscall_line|fn extract_structured_path_property|fn extract_structured_string_property' crates/nono/src/diagnostic.rs
   # Expected: 4
   grep -c 'NOTE (P34-DEFER-08b-2)' crates/nono/src/diagnostic.rs
   # Expected: 0 (comment blocks deleted)
   ```

6. **ExecConfig struct UNCHANGED (D-36-D1):**
   - Pre-Commit-2 capture: `grep -A 25 'pub struct ExecConfig' > /tmp/pre.txt`
   - Post-Commit-2 capture + diff: must be empty (verifies struct preservation)

7. **POST_EXIT_PTY_DRAIN_TIMEOUT = 100ms:**
   ```bash
   grep -A 2 'POST_EXIT_PTY_DRAIN_TIMEOUT' crates/nono-cli/src/exec_strategy.rs | grep -c 'from_millis(100)'
   # Expected: 1
   ```

8. **`clear_signal_forwarding_target` 3 callsites:**
   ```bash
   grep -c 'clear_signal_forwarding_target' crates/nono-cli/src/exec_strategy.rs
   # Expected: ≥ 4 (1 definition + 3 callsites)
   ```

9. **`LearnArgs.trace` restored:**
   ```bash
   grep -A 35 'pub struct LearnArgs' crates/nono-cli/src/cli.rs | grep -c 'pub trace: bool'
   # Expected: 1
   ```

10. **Regression coverage (D-36-D3) green:**
    - `cargo test -p nono-cli --test attach_streaming_integration` exits 0 (Phase 17)
    - Phase 15 5-row smoke passes OR documented-skipped (Phase 31 broker ConPTY)
    - `grep -c 'print_macos_run_guidance' crates/nono-cli/src/learn_runtime.rs` returns ≥ 1 (Phase 10 / D-02)

11. **Close-gate (D-36-A5) green** — ALL 8 steps; macOS clippy step 4 explicitly LOAD-BEARING for Plan 36-03:
    - Windows clippy + Linux cross-target clippy + macOS cross-target clippy + fmt-check + workspace tests all exit 0

12. **bbdf7b85 tests pass:**
    - `cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_structured_node_eperm_mkdir_path` exits 0
    - `cargo test -p nono --lib diagnostic::tests::test_analyze_error_output_detects_structured_path_with_escaped_quote` exits 0
</verification>

<success_criteria>
- Plan 36-03 lands as EXACTLY 3 sequenced commits on `main`:
  - Commit 1 (D-20): b5f0a3ab diagnostic.rs restoration (4 helpers + wiring + 1 test + 2 comment-block deletions)
  - Commit 2 (D-20): b5f0a3ab exec_strategy + execution_runtime + cli.rs LearnArgs.trace + 4 ancillary refinements; ExecConfig 17-field shape PRESERVED per D-36-D1
  - Commit 3 (D-19): bbdf7b85 escape-quote body rewrite + 2 new tests; verbatim 6-line D-19 trailer with lowercase 'a' in Upstream-author
- D-36-D2 smoke check satisfied: `git log --format='%B' main~3..main | grep -c '^Upstream-commit: '` returns EXACTLY 1.
- D-36-D3 regression coverage:
  - Phase 17 attach-streaming tests green
  - Phase 31 broker ConPTY 5-row smoke green OR documented-skipped
  - Phase 10 / D-02 Windows admin gate in learn_runtime.rs preserved
- All 8 D-36-A5 close-gate steps green (macOS cross-target clippy step 4 explicitly load-bearing for b5f0a3ab macOS surface).
- REQ-PORT-CLOSURE-05 acceptance criteria #1 (ExecConfig preserved per D-36-D1) + #2 (macOS learn diagnostic improvements present) + #3 (PTY-quiet-period absorbed without regression) + #4 (bbdf7b85 escape-quote test passes) all met.
- P34-DEFER-08b-1 + P34-DEFER-08b-2 closed.
- DCO `Signed-off-by:` on all 3 commits.
- NO `--amend` on any published commit (CLAUDE.md git-safety).
</success_criteria>

<output>
After completion, create `.planning/phases/36-upst3-deep-closure/36-03-EXECCFG-SURGICAL-PORT-SUMMARY.md` documenting:
- 3-commit SHA chain (Commit 1, 2, 3 hashes)
- ExecConfig pre-/post-Commit-2 grep diff (must be empty)
- Per-commit trailer audit (Commits 1+2 = no D-19; Commit 3 = verbatim D-19)
- D-36-D2 smoke check result
- D-36-D3 regression coverage outcomes (Phase 17, Phase 31, Phase 10/D-02)
- All 4 helpers + their wiring landed (Commit 1)
- New helpers + const + callsite + LearnArgs.trace (Commit 2)
- bbdf7b85 body rewrite + 2 new tests (Commit 3)
- Close-gate run outcomes (all 8 steps; macOS step 4 load-bearing flagged)
- PTY-quiet-period final disposition: 100ms locked / compromise to 150ms / rolled back (with rationale)
- Hand-off + carry-forward note: v2.5-FU-4 covers full upstream-shape ExecConfig adoption; v2.5-FU-6 covers PTY-quiet-period parametric proptest
</output>
</content>
</invoke>
