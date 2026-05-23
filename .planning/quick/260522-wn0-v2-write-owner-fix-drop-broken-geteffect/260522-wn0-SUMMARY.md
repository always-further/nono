---
phase: quick-260522-wn0
plan: 01
subsystem: windows-il
tags: [windows, integrity-label, write-owner, poc-unblock, revert-v14-preflight]
one_liner: v2 of the WRITE_OWNER fix — drop the structurally-unsound `GetEffectiveRightsFromAclW` pre-flight + its FFI surface; route the WRITE_OWNER directive hint through the existing `SetNamedSecurityInfoW(LABEL_*)` `ERROR_ACCESS_DENIED` arm, gated by `path_is_owned_by_current_user` which uses the same UAC-filtered token the apply call runs under (judgment matches reality on both full and filtered tokens).
dependency_graph:
  requires:
    - existing `path_is_owned_by_current_user(path: &Path) -> Result<bool>` (line 845 of `crates/nono/src/sandbox/windows.rs`, unchanged)
    - existing `NonoError::LabelApplyFailed { path, hresult, hint }` variant (unchanged in `error.rs`)
    - windows-sys 0.59 — Win32_Security_Authorization feature (no net change vs v1; we drop 6 imports, retain the rest)
  provides:
    - revised `try_set_mandatory_label` that branches on path ownership at the ACCESS_DENIED arm — user-owned paths get the WRITE_OWNER directive hint; non-user-owned or ownership-query-error get the existing catch-all hint
  affects:
    - `crates/nono-cli/src/exec_strategy_windows/labels_guard.rs` (no breakage — regression test `guard_apply_then_drop_reverts_label_for_fresh_file` passes unchanged)
    - POC pilot user UAT — same expected directive hint as v1 (verbatim hint string), now structurally trustworthy under UAC-filtered token
tech-stack:
  added: []
  patterns:
    - "Ownership-conditional hint dispatch in the catch-all error arm — uses an existing helper (`path_is_owned_by_current_user`) that already runs under the same effective identity as the failing call"
    - "Fall-through error policy on the ownership query — `Err(_)` falls through to the catch-all hint rather than propagating, so the actual apply-failure status code surfaces unchanged"
key-files:
  created: []
  modified:
    - crates/nono/src/sandbox/windows.rs
decisions:
  - "Removed the v1 `GetEffectiveRightsFromAclW` pre-flight: it walked group memberships from the FullToken but `SetNamedSecurityInfoW(LABEL_*)` runs under the UAC-filtered token — false positives for local admins (LOCKED #2)."
  - "Did NOT introduce `AccessCheck` + `DuplicateTokenEx(Impersonation)` — too much new unsafe FFI surface for a diagnostic-only defense-in-depth gate (LOCKED #2)."
  - "Kept both hint strings as separate branches at the ACCESS_DENIED arm — no mega-hint merge (LOCKED #4); user-owned → WRITE_OWNER directive (v1 hint verbatim), not-user-owned / ownership-query-error → catch-all 'writable...NTFS...'."
  - "`error.rs` untouched — same `NonoError::LabelApplyFailed` variant, different hint string at the call site only. Cross-target clippy gate N/A because `windows.rs` is `#[cfg(target_os = \"windows\")]`-gated and no Unix cfg branches were touched (LOCKED #8)."
  - "No workspace version bump — v1 + v2 land within the same in-flight 0.53.1 release cycle (LOCKED #9)."
  - "Single atomic commit with DCO sign-off + Claude Code Co-Authored-By trailer (LOCKED #10)."
metrics:
  duration: ~25m
  completed: 2026-05-22T20:00:00Z
  tasks_completed: 1
  files_modified: 1
threat_flags: []
---

# Quick Task 260522-wn0: v2 WRITE_OWNER Fix — Drop Broken GetEffectiveRightsFromAclW Pre-Flight

## One-liner

The Windows mandatory-integrity-label backend no longer pre-flights via `GetEffectiveRightsFromAclW` (which walked group memberships from the FullToken and gave false positives to local admins on the POC user's machine). Instead, the existing `SetNamedSecurityInfoW(LABEL_*)` `ERROR_ACCESS_DENIED` catch-all arm now dispatches on `path_is_owned_by_current_user` — emitting the WRITE_OWNER directive hint (v1 hint string verbatim) when the path is user-owned, and the existing "writable...NTFS..." catch-all otherwise. The dispatch helper runs under the same UAC-filtered token as the failing apply call, so its judgment is structurally trustworthy.

## What was built

### Production code

**`crates/nono/src/sandbox/windows.rs` — net deletion of ~242 lines (63 inserted, 305 deleted):**

1. **Removed entirely:** the `pub fn path_has_write_owner(path: &Path) -> Result<bool>` function (was at line 1050) and its full doc-comment header (was at line 1027). ~226 lines including all its FFI: `GetNamedSecurityInfoW(DACL)`, `OpenProcessToken`, `GetTokenInformation(TokenUser)`, `TRUSTEE_W` struct synthesis, `GetEffectiveRightsFromAclW`.

2. **Removed entirely:** the v1 pre-flight block at the top of `try_set_mandatory_label` body (was at lines 684-712 — the 12-line comment header + the `if !path_has_write_owner(path)? { return Err(...) }` block). The function body's first statement after the local `use windows_sys::Win32::Foundation::{...};` is now the existing `let wide_path: Vec<u16> = ...`.

3. **Upgraded:** the `ERROR_ACCESS_DENIED | ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED` arm of the catch-all `let hint = match status { ... }` block at the bottom of `try_set_mandatory_label`. The matcher itself is unchanged; the body is now:

   ```rust
   match path_is_owned_by_current_user(path) {
       Ok(true) => format!(
           "The current user lacks WRITE_OWNER (0x00080000) on this path. \
            Mandatory integrity labels require WRITE_OWNER, which is NOT implicit for path owners. \
            User-created subdirectories of a drive root (e.g. C:\\poc\\) inherit the default C:\\ ACL, \
            which grants only `Authenticated Users: Modify` — WRITE_OWNER is missing. \
            Recommended: run nono from a working directory under your user profile \
            (e.g. %USERPROFILE%\\nono-poc or %TEMP%\\nono-poc). \
            Local override: grant FullControl on the current path via \
            `icacls {} /grant <user>:(OI)(CI)F` (this widens the DACL beyond \
            default inheritance — explicit user choice, not a default).",
           path.display(),
       ),
       Ok(false) | Err(_) => {
           "Ensure the target file is writable by the current user and is on NTFS (not ReFS or a network share).".to_string()
       }
   }
   ```

   The Ok(true) hint is the v1 hint string verbatim — same literal `WRITE_OWNER`, `%USERPROFILE%\nono-poc`, `%TEMP%\nono-poc`, `icacls {} /grant` substrings. The Ok(false) | Err(_) hint is the existing catch-all string. The dispatch is documented inline with a 13-line comment explaining the threat model and the rationale for falling through on ownership-query errors (don't mask the real apply failure's hresult).

4. **Trimmed imports** at lines 22-25 of the top-level `use` block:
   - **Removed** (only consumer was `path_has_write_owner`, now deleted): `GetEffectiveRightsFromAclW`, `NO_MULTIPLE_TRUSTEE`, `TRUSTEE_IS_SID`, `TRUSTEE_IS_USER`, `TRUSTEE_W`, and `use windows_sys::Win32::Storage::FileSystem::WRITE_OWNER;` (separate use line, also deleted).
   - **Kept** in the same `Authorization::{...}` block: `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `GetNamedSecurityInfoW`, `SetNamedSecurityInfoW`, `SDDL_REVISION_1`, `SE_FILE_OBJECT` — all still consumed.

5. **Moved import location for `DACL_SECURITY_INFORMATION`:** the negative test still uses it (lines 3634, 3684), but with `path_has_write_owner` deleted, the lib-level `use windows_sys::Win32::Security::{... DACL_SECURITY_INFORMATION ...}` became dead under non-test clippy (`cargo clippy -p nono -- -D warnings`). Moved the import from the top-level `use` block into the negative test's local `use windows_sys::Win32::Security::{...}` block (joining the existing `PROTECTED_DACL_SECURITY_INFORMATION` and `GetSecurityDescriptorDacl` local-imports — same pattern v1 used for the latter). Net: same logical scope, narrower import surface.

### Tests

1. **Deleted:** `path_has_write_owner_returns_true_for_userprofile_tempdir` (was at lines 3699-3714). The function it tested is gone.

2. **Renamed + revised doc-comment header:** `try_set_mandatory_label_surfaces_directive_when_write_owner_missing` → `try_set_mandatory_label_surfaces_directive_when_user_owned_apply_fails`. The function body (synthetic-DACL setup, current-user SID lookup, `SetNamedSecurityInfoW(DACL | PROTECTED_DACL)` apply with mask `0x1301BF`, `try_set_mandatory_label(&path, 0x4)` invocation, cleanup that restores DACL inheritance, and the three remaining assertions — `matches!(err, NonoError::LabelApplyFailed { .. })`, `msg.contains("WRITE_OWNER")`, `msg.contains("%USERPROFILE%") || msg.contains("%TEMP%")`) is unchanged. Only the `expect_err` message string was tweaked to clarify the new failure path: `"try_set_mandatory_label must fail when the apply call hits ACCESS_DENIED on a user-owned WRITE_OWNER-stripped path"`.

   The doc-comment header was rewritten to describe v2 semantics: tests that the WRITE_OWNER directive hint surfaces from the catch-all `ERROR_ACCESS_DENIED` branch (NOT from a pre-flight, which no longer exists). The "Why explicit user SID" rationale was retitled and reworked to explain the rationale in terms of the access-checked trustee under the filtered token, NOT in terms of `GetEffectiveRightsFromAclW` group walking (since that function is gone).

   The test passes because `path_is_owned_by_current_user` returns `Ok(true)` on a `tempfile::tempdir()`-created path (proven by the existing regression test `path_is_owned_by_current_user_returns_true_for_tempfile`), and the synthesized DACL deterministically forces `ERROR_ACCESS_DENIED` from the actual `SetNamedSecurityInfoW(LABEL_*)` call.

## Commits

| # | Hash | Subject |
|---|------|---------|
| 1 | `e101b03a` | `fix(windows-il): drop broken GetEffectiveRightsFromAclW pre-flight; gate WRITE_OWNER hint on path ownership (260522-wn0)` |

Commit includes DCO sign-off (`Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>`) and `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` trailers.

## Verification

All gates pass on the Windows host (`x86_64-pc-windows-msvc`):

| Check | Result |
|-------|--------|
| `cargo clippy --target x86_64-pc-windows-msvc -p nono -- -D warnings -D clippy::unwrap_used` | clean (3.45s) |
| `cargo clippy --target x86_64-pc-windows-msvc -p nono --tests -- -D warnings -D clippy::unwrap_used` | clean (20.33s) |
| `cargo test --target x86_64-pc-windows-msvc -p nono try_set_mandatory_label_surfaces_directive_when_user_owned_apply_fails` | 1 passed |
| `cargo test --target x86_64-pc-windows-msvc -p nono path_is_owned_by_current_user` (regression) | 2 passed |
| `cargo test --target x86_64-pc-windows-msvc -p nono-cli --bins guard_apply_then_drop_reverts_label_for_fresh_file` (regression) | 1 passed |
| `cargo build --release --target x86_64-pc-windows-msvc -p nono-cli` | clean (4m 00s) |
| `git diff --stat HEAD~1 HEAD -- crates/nono/src/error.rs` (cross-target gate) | empty — N/A as designed |
| Commit hygiene: DCO + Co-Authored-By trailers present | 1/1 + 1/1 |
| `git diff --diff-filter=D --name-only HEAD~1 HEAD` (file deletions) | none — only line-level edits inside `windows.rs` |

### Grep spot-checks (final source state)

| Pattern | Result |
|---------|--------|
| `path_has_write_owner` in `crates/nono/src/sandbox/windows.rs` | 0 matches — function and all references fully removed |
| `GetEffectiveRightsFromAclW` in `crates/nono/src/sandbox/windows.rs` | 0 matches (also removed from a test doc-comment to keep grep clean) |
| `TRUSTEE_W \| TRUSTEE_IS_SID \| TRUSTEE_IS_USER \| NO_MULTIPLE_TRUSTEE` in `crates/nono/src/sandbox/windows.rs` | 0 matches |
| `use windows_sys::Win32::Storage::FileSystem::WRITE_OWNER` in `crates/nono/src/sandbox/windows.rs` | 0 matches — import removed |
| `DACL_SECURITY_INFORMATION` in `crates/nono/src/sandbox/windows.rs` | 6 matches — all in the negative test (local-use line + 2 SetNamedSecurityInfoW calls + 3 documentation/comments). Top-level lib-use line is gone. |
| `try_set_mandatory_label_surfaces_directive_when_user_owned_apply_fails` | 1 match (function definition); old name (`..._when_write_owner_missing`) — 0 matches |
| `path_is_owned_by_current_user` in `crates/nono/src/sandbox/windows.rs` | matches at function definition (~line 845), new catch-all branch call site, and 2 existing regression tests — all intact |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue, build hygiene] `DACL_SECURITY_INFORMATION` lib-level import became dead under non-test clippy**

- **Found during:** First `cargo clippy --target x86_64-pc-windows-msvc -p nono -- -D warnings -D clippy::unwrap_used` run after the six in-source edits. The non-test lib build emitted `error: unused import: 'DACL_SECURITY_INFORMATION'` at line 29.
- **Root cause:** The plan's `<line_anchors>` chunk 1 said "KEEP: `DACL_SECURITY_INFORMATION` on line 30 is still used by the negative test (line 3877, 3927)" — which is true, but the negative test is inside `#[cfg(test)] mod tests`, so under non-test clippy (`cargo clippy -p nono` without `--tests`) the lib-level import has no consumer. With `path_has_write_owner` deleted, the only non-test consumer is gone.
- **Fix:** Moved `DACL_SECURITY_INFORMATION` from the top-level `use windows_sys::Win32::Security::{...}` block into the negative test's local `use windows_sys::Win32::Security::{...}` block, joining the already-test-local `GetSecurityDescriptorDacl` and `PROTECTED_DACL_SECURITY_INFORMATION` (same import-hygiene pattern v1 already used for `GetSecurityDescriptorDacl`).
- **Why this is build-hygiene only (not a security/behavior concern):** The constant is a compile-time `u32` (= `0x00000004`) used identically inside the test; moving the `use` to a narrower scope changes no runtime behavior, no compiled output, no test semantics.
- **Verification after fix:** non-test clippy clean (3.45s), test clippy clean (20.33s), all named tests pass.
- **Files modified:** `crates/nono/src/sandbox/windows.rs` (top-level `use` block + the negative test's local `use` block, both inside the same commit).
- **Commit:** rolled into `e101b03a` before the commit landed (no separate commit needed).

**2. [Cosmetic — doc-comment cleanup, not a Rule deviation] Removed `GetEffectiveRightsFromAclW` literal from the renamed test's doc-comment**

- **Found during:** Final grep spot-check before commit. The renamed test's doc-comment contained the phrase "v2 removed the broken `GetEffectiveRightsFromAclW` pre-flight", which would have shown up as 1 grep hit against the success-criteria pattern `GetEffectiveRightsFromAclW`.
- **Plan stance:** Plan `<verification>` line 322 explicitly says `WRITE_OWNER` matches in comments / hint format strings / test assertion messages are OK; by symmetry the same applies to `GetEffectiveRightsFromAclW` in a doc-comment describing v1's flaw. But to keep the SUMMARY grep gate clean and unambiguous, I reworded the doc-comment to "v2 removed the broken effective-rights pre-flight" — same semantic content, no literal symbol reference.
- **Why this isn't a meaningful deviation:** the change is in a `///` doc-comment on the test function, no code path is affected, no test semantics change. Documenting it here for completeness.
- **Files modified:** `crates/nono/src/sandbox/windows.rs` (the renamed test's doc-comment only).
- **Commit:** rolled into `e101b03a` before the commit landed.

### No other deviations

The implementation matches the LOCKED orchestrator decisions (1-11) exactly:

- v1 `path_has_write_owner` function fully removed (no Rust code references remain).
- v1 import set narrowed to exactly the prescribed subset: `GetEffectiveRightsFromAclW`, `TRUSTEE_W`, `TRUSTEE_IS_SID`, `TRUSTEE_IS_USER`, `NO_MULTIPLE_TRUSTEE`, `WRITE_OWNER` all removed from the top-level `use` block. `DACL_SECURITY_INFORMATION` retained logically but moved to a narrower (test-local) scope.
- `try_set_mandatory_label` ACCESS_DENIED arm dispatches on `path_is_owned_by_current_user`: user-owned → WRITE_OWNER directive hint (v1 hint string verbatim); not-user-owned or ownership-query-error → existing catch-all hint.
- Ownership-query errors fall through to catch-all (do NOT propagate) — actual apply-failure hresult surfaces unchanged.
- Both hint strings preserved as separate branches (no mega-hint merge — LOCKED #4).
- Positive test deleted; negative test renamed + doc-rewritten with the function body untouched.
- `error.rs` not modified (LOCKED #8). Cross-target clippy gate N/A.
- Workspace version unchanged at 0.53.1 (LOCKED #9).
- Single atomic commit with DCO + Co-Authored-By trailers (LOCKED #10).

## Post-merge MANUAL verification (USER, NOT EXECUTOR — LOCKED #11)

After the user rebuilds `nono.exe` from this branch:

```powershell
cd C:\poc\temp
nono run --allow . -- cmd /c echo hello
```

**Expected new behavior:** Fails with the WRITE_OWNER directive error naming `%USERPROFILE%\nono-poc` or `%TEMP%\nono-poc` (the v1 hint string, verbatim). NOT the old "Ensure the target file is writable...NTFS..." catch-all. The structural guarantee vs v1: this hint now surfaces from the actual `SetNamedSecurityInfoW(LABEL_*)` ACCESS_DENIED arm (after the kernel rejected the apply under the UAC-filtered token), gated by an ownership query that runs under the same effective identity — so local-admin POC users will no longer see the misleading catch-all when the apply genuinely fails.

Then from a recommended location:

```powershell
mkdir $env:USERPROFILE\nono-poc -Force
cd $env:USERPROFILE\nono-poc
nono run --allow . -- cmd /c echo hello
```

**Expected:** prints `hello` (label apply succeeds, child runs).

Once the user confirms both shapes, the orchestrator moves `.planning/debug/il-label-apply-access-denied.md` → `.planning/debug/resolved/` per the debug-session resolution convention. This v2 fix closes that debug session.

## Self-Check: PASSED

- `crates/nono/src/sandbox/windows.rs`: FOUND, modified per plan (1 file changed, 63 insertions(+), 305 deletions(-)).
- Function `path_has_write_owner` (was line 1050): FULLY REMOVED. `grep -n "path_has_write_owner" crates/nono/src/sandbox/windows.rs` → 0 matches.
- v1 pre-flight in `try_set_mandatory_label`: FULLY REMOVED. The function body's first statement after the local `use` block is now the existing `let wide_path: Vec<u16> = ...`.
- New ownership-conditional dispatch in the ACCESS_DENIED arm: PRESENT and tested.
- v1 imports removed (`GetEffectiveRightsFromAclW`, `NO_MULTIPLE_TRUSTEE`, `TRUSTEE_IS_SID`, `TRUSTEE_IS_USER`, `TRUSTEE_W`, `WRITE_OWNER`): 0 matches each.
- Positive test `path_has_write_owner_returns_true_for_userprofile_tempdir`: REMOVED.
- Negative test renamed to `try_set_mandatory_label_surfaces_directive_when_user_owned_apply_fails`: PRESENT and passes.
- Commit `e101b03a`: FOUND in `git log -1`, has DCO + Co-Authored-By trailers.
- `crates/nono/src/error.rs`: NOT MODIFIED. `git diff --stat HEAD~1 HEAD -- crates/nono/src/error.rs` is empty.
- No file deletions in the commit (`git diff --diff-filter=D --name-only HEAD~1 HEAD` → empty).
- All five gate commands (lib clippy strict, test clippy strict, new negative test, two regression sweeps, release build of `nono-cli`) passed.
