---
quick_id: 260405-vjj
description: Fix PR 555 DCO signoffs, commit PR 583 review feedback fixes, push current changes
date: 2026-04-06
status: ready
---

# Quick Task 260405-vjj: Fix PR 555 signoffs, address PR 583 feedback, push

## Context

Three open PRs:
- **PR 530**: green, no action needed
- **PR 555** (branch `pr/windows-epic12-clean-v2`, current branch): DCO check failing — 54 commits have missing/wrong sign-offs. Also has 18 uncommitted working tree files (fixes for PR 583 review feedback). Remote head: `bccc5bca`.
- **PR 583** (branch `pr555/windows-epic12-clean-v3`): Gemini code review raised 8 issues (buffer over-read, hardcoded paths, busy-wait, /dev/null, sandbox_prepare redundancy, test env races, WFP cleanup). All 8 are addressed in the current working tree changes. PR 583 has already had response comments posted explaining the fixes.

**DCO details:** The DCO bot found 54 commits with issues (missing sign-off or wrong email). The correct sign-off is `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>`. Bot recommends: `git rebase HEAD~183 --signoff` (when PR head was `bccc5bca`). We have 48 more local commits since then, so after committing working tree (49 total), the correct rebase count is `HEAD~232`.

**Git user:** `oscarmackjr-twg <oscar.mack.jr@gmail.com>`

## Plan

### Task 1: Commit working tree changes to PR 555 branch

**Files:** All 18 modified files in working tree (already known from `git diff --stat HEAD`):
- `crates/nono-cli/src/app_runtime.rs`
- `crates/nono-cli/src/bin/nono-wfp-service.rs`
- `crates/nono-cli/src/bin/test-connector.rs`
- `crates/nono-cli/src/exec_strategy_windows/launch.rs`
- `crates/nono-cli/src/exec_strategy_windows/mod.rs`
- `crates/nono-cli/src/exec_strategy_windows/restricted_token.rs`
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs`
- `crates/nono-cli/src/launch_runtime.rs`
- `crates/nono-cli/src/pty_proxy_windows.rs`
- `crates/nono-cli/src/rollback_commands.rs`
- `crates/nono-cli/src/rollback_runtime.rs`
- `crates/nono-cli/src/session.rs`
- `crates/nono-cli/src/session_commands_windows.rs`
- `crates/nono-cli/src/setup.rs`
- `crates/nono-cli/src/startup_runtime.rs`
- `crates/nono-cli/src/supervised_runtime.rs`
- `crates/nono/src/undo/snapshot.rs`
- `crates/nono/src/undo/types.rs`

**Action:** `git add <files> && git commit -s -m "fix(windows): address gemini code review feedback from PR 583\n\nFix 8 issues identified in gemini-code-assist review:\n- Rebuild TOKEN_MANDATORY_LABEL buffer as single allocation (eliminates over-read)\n- Derive Windows root from SystemRoot/windir env vars instead of hardcoding C:\\Windows\n- Use explicit file vs directory classification instead of extension().is_some()\n- Replace busy-wait in supervisor with WaitForMultipleObjects\n- Use NUL instead of /dev/null for Windows null device\n- Remove redundant Sandbox::is_supported() shortcut in sandbox_prepare\n- Wrap env-mutating test in lock_env() to prevent parallel test races\n- Add cleanup_stale_network_enforcement_artifacts() for orphaned WFP resources\n\nSigned-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>"`

**Verify:** `git log --oneline -1` shows the new commit; `git diff HEAD` is empty.

### Task 2: Push new commit to PR 583 branch as well

PR 583's branch (`pr555/windows-epic12-clean-v3`) also needs the same fixes (for the gemini review to see them resolved).

**Action:**
```bash
# Get the hash of the commit we just made
NEW_COMMIT=$(git rev-parse HEAD)

# Fetch the remote state of PR 583's branch
git fetch origin pr555/windows-epic12-clean-v3

# Check out PR 583's branch, cherry-pick our new commit, push
git checkout pr555/windows-epic12-clean-v3
git cherry-pick $NEW_COMMIT
git push origin pr555/windows-epic12-clean-v3

# Return to PR 555's branch
git checkout pr/windows-epic12-clean-v2
```

**Verify:** `git log --oneline -1 origin/pr555/windows-epic12-clean-v3` shows the cherry-picked commit.

### Task 3: Fix DCO sign-offs on PR 555 via rebase

**Action:**
```bash
# After Task 1 commit, we have 49 new commits above bccc5bca
# DCO bot checked 183 commits when PR head was bccc5bca
# Total to rebase: 183 + 49 = 232
git rebase HEAD~232 --signoff
```

This replays the last 232 commits adding `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>` to each. Since it's replaying existing content (not changing base), should be conflict-free.

**Verify:** `git log --format="%H %s%n%b" -5 | grep -c "Signed-off-by"` returns 5+; check the previously failing commits now have correct sign-offs.

### Task 4: Force-push PR 555

**Action:**
```bash
git push --force-with-lease origin pr/windows-epic12-clean-v2
```

**Verify:** `gh pr view 555 --repo always-further/nono --json statusCheckRollup` — wait for DCO check to re-run (may take a minute); confirm it shows SUCCESS.

## must_haves

- [ ] 18 working tree files committed with proper sign-off
- [ ] PR 583 branch updated with cherry-picked commit
- [ ] All 54 failing DCO commits now have `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>`
- [ ] `pr/windows-epic12-clean-v2` force-pushed to remote
- [ ] No merge conflicts during rebase
