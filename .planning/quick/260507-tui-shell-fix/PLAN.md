---
slug: 260507-tui-shell-fix
date: 2026-05-07
status: in-progress
type: docs
---

# Fix Windows POC cookbook: recommend `nono shell` for TUI agents

## Goal

The cookbook currently tells POC users to run `nono run --profile claude-code -- claude` as the happy path. On Windows that command appears to hang. Root cause confirmed in source: the supervised path on Windows never allocates a ConPTY for `nono run`, only for `nono shell`. TUI children (claude, codex, etc.) get anonymous pipes and cannot render their UI.

This fix updates the cookbook to recommend `nono shell --profile claude-code` for any interactive agent, keeps `nono run` for non-interactive smokes, and documents the limitation explicitly so POC users do not hit the same wall.

## Root cause (for the SUMMARY narrative)

- `crates/nono-cli/src/supervised_runtime.rs:105-111` — Windows branch of `should_allocate_pty` returns `interactive_pty` only.
- `crates/nono-cli/src/launch_runtime.rs:311` — `nono run` hard-codes `interactive_pty: false`.
- `crates/nono-cli/src/command_runtime.rs:132` — `nono shell` hard-codes `interactive_pty: true`.
- `crates/nono-cli/src/launch_runtime.rs:490` — `select_exec_strategy` always returns `Supervised`.

Net effect: `nono run` on Windows always opens anonymous pipes; non-interactive children (echo, type, cargo, `claude --version`) work fine, but TUIs cannot render. Historical reason in `.planning/debug/resolved/windows-supervised-exec-cascade.md`: combining `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` with `DETACHED_PROCESS` crashed grandchildren with `STATUS_DLL_INIT_FAILED (0xC0000142)`. Disabling PTY entirely on the Windows supervised path was the conservative fix; it locked out attached TUI use.

## Tasks

Single file: `docs/cli/development/windows-poc-handoff.mdx`.

1. **Top-of-doc Note (line 11)** — soften the "doc-vs-binary drift" claim. Acknowledge: profile-backed runs ARE supported, and `nono shell`/`nono wrap` ARE available on Windows 10 17763+ via ConPTY. But `nono run -- <TUI>` cannot host an interactive TUI on Windows because the supervised path uses anonymous pipes, not ConPTY. The legacy `windows-preview-pilot.mdx` that flagged this limitation is correct in spirit; what's stale there is the broader claim about profile-backed runs being blocked.

2. **Step 4 "First Claude Code run"** — keep the dry-run line for policy verification, change the live line from `nono run --profile claude-code -- claude` to `nono shell --profile claude-code --allow-cwd` followed by typing `claude` inside the sandboxed shell.

3. **Step 5 smoke checklist** — replace the two `claude --version` lines (the "Live with profile" and "Block-net" smokes that pass `claude --version` to `nono run`) with manual `nono shell` verification blocks. The non-TUI smokes (`cmd /c echo hello`, `cmd /c type`) stay on `nono run` — they don't need a ConPTY.

4. **New subsection between Step 5 and Step 6:** "Known limitation: `nono run` cannot host TUI agents on Windows." One paragraph explaining the anonymous-pipes vs ConPTY situation with a pointer to `.planning/debug/resolved/windows-supervised-exec-cascade.md`.

5. **Step 6 POC handoff table** — Happy path row → `nono shell --profile claude-code --allow-cwd`. Add new "TUI agents (claude, codex, etc.)" row. Read-only review and Offline rows → `nono shell` form. Keep the Install / symlink / triage / not-supported / uninstall rows as-is.

## Out of scope

The actual code fix (allocate a PTY in the Windows supervised path when `!detached_start` and `stdout.is_terminal()`). That work needs to demonstrate it doesn't reintroduce the `STATUS_DLL_INIT_FAILED` crash from the resolved debug session — separate `/gsd-debug` task.

## Commit plan

- Single commit: `docs(windows-poc): recommend nono shell for TUI agents on Windows`.
- Follow-up: `docs(state): record quick task 260507-tui-shell-fix complete`.
- DCO: `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>`.
