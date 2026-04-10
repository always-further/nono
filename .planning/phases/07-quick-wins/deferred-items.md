# Deferred Items — Phase 07 Quick Wins

## Pre-existing Test Failures (Out of Scope)

These test failures existed before plan 07-01 execution and are unrelated to wrap/session command changes:

1. `profile::builtin::tests::test_all_profiles_signal_mode_resolves`
   - Failure: `XDG_CONFIG_HOME` validation fails with `/home/nono-test/.config` (Unix path on Windows)
   - File: `crates/nono-cli/src/profile/builtin.rs:361`
   - Root cause: Test sets `XDG_CONFIG_HOME` to a Unix-style path; Windows env var validation rejects it
   - Suggested fix: Use a Windows-compatible absolute path in the test, or use save/restore pattern per CLAUDE.md

2. `query_ext::tests::test_query_path_sensitive_policy_includes_policy_source`
   - Failure: assertion `left == right` failed — `path_not_granted` != `sensitive_path`
   - File: `crates/nono-cli/src/query_ext.rs:468`
   - Root cause: Unknown; likely a Windows-specific path policy detection issue
   - Suggested fix: Investigate sensitive path detection on Windows vs Unix

Both confirmed pre-existing by running same tests against HEAD~1 (before plan 07-01 changes).
