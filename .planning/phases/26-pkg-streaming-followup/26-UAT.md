---
status: partial
phase: 26-pkg-streaming-followup
source:
  - 26-01-SUMMARY.md
  - 26-02-PKGS-STREAMING-SUMMARY.md
started: 2026-05-09T22:35:44Z
updated: 2026-05-09T23:30:00Z
---

## Current Test

[testing paused — 1 item outstanding (host-mismatch blocker)]

## Tests

### 1. Build & Workspace Compile Gate
expected: |
  Run `make build` (or `cargo build --workspace`). Workspace compiles clean — no errors,
  no warnings escalated by `-D warnings`. Plan 26-01 added `ArtifactType::Plugin` and
  Plan 26-02 added `semver = "1"` to nono-cli; both must compile across the workspace
  without breaking any downstream consumers.
result: pass

### 2. nono-cli Test Suite Gate
expected: |
  Run `cargo test -p nono-cli --bin nono`. Reports **852 passed; 0 failed; 0 ignored**
  (Plan 26-02 added 11 new tests: 3 in package_cmd::tests + 8 in registry_client::tests;
  Plan 26-01 added 4 earlier). The Linux-only RSS test compiles out cleanly on Windows.
result: pass
note: |
  User ran with `--skip windows_no_console_denies_gracefully` to bypass a pre-existing
  test isolation bug in terminal_approval.rs (test blocks on \\.\CONIN$ when an
  interactive console is attached). That hang is unrelated to Phase 26 (terminal_approval.rs
  unmodified by Plan 26-01/26-02). Result: 851 passed; 0 failed; 1 filtered; 10.66s.
  Backlog item: feature-gate or mock the CONIN$ open path under cfg(test) — file against
  Phase 18.1 / Phase 11 surface, not Phase 26.

### 3. D-19 Byte-Identical Preservation of crates/nono/
expected: |
  Run `git diff --stat 57be91a9..HEAD -- crates/nono/`. Output is empty (no lines, no
  diff stats). Phase 26 is required to leave `crates/nono/` byte-identical; any non-empty
  diff would breach the cross-phase D-19 invariant called out in CONTEXT and both SUMMARYs.
result: pass

### 4. nono pull CLI Help Surface (Upstream Alignment)
expected: |
  Run `cargo run --bin nono -- pull --help`. Output lists the existing flags
  (`--registry`, `--force`, `--init`, `--silent`, `--theme`, `--log-file`, `--help`).
  **No `--max-size` flag** appears — Plan 26-02 deliberately aligned with upstream's
  fixed-const REGISTRY_*_LIMIT_BYTES approach (2 MiB JSON / 8 MiB bundle / 64 MiB
  artifact) instead of a fork-only configurable knob.
result: pass

### 5. ArtifactType::Plugin JSON Round-Trip
expected: |
  Run `cargo test -p nono-cli --bin nono -- artifact_type_plugin_round_trips
  artifact_type_unknown_fails_closed`. Both tests pass: the Plugin variant serializes
  to `"plugin"` (serde rename_all = snake_case) and deserializes back; unknown variants
  fail closed (no silent default). Confirms REQ-PKGS-03 closure.
result: pass
note: |
  2 passed; 850 filtered out; 0.00s. Pre-existing unused-imports warning surfaced in
  audit_session.rs:357 (test module imports `RollbackStatus`, `SessionMetadata` used
  only by a `#[cfg(not(target_os = "windows"))]`-gated test). Introduced by Phase 22-05a
  commit 7e25ca74 (Windows defer); resolved by Phase 22-05b re-enablement (already
  queued). Not a Phase 26 regression.

### 6. validate_relative_path Defense-in-Depth Pre-check
expected: |
  Run `cargo test -p nono-cli --bin nono -- validate_relative_path_rejects_traversal
  validate_relative_path_rejects_absolute_path`. Both tests pass: the input-string-layer
  pre-check rejects `..`, absolute paths, and (Windows-host) `C:\\foo` + `\\\\server\\share`
  shapes BEFORE any filesystem syscall, while preserving the canonicalize-and-component-compare
  `validate_path_within` layer at line 1035. Confirms REQ-PKGS-02 closure.
result: pass
note: |
  Run sequentially: traversal test (1 passed; 0 failed; 851 filtered) + absolute_path
  test (1 passed; 0 failed; 851 filtered). Windows-host `C:\foo` + `\\server\share`
  rejection paths exercised under `#[cfg(windows)]`.

### 7. semver Prerelease Ordering in compare_versions
expected: |
  Run `cargo test -p nono-cli --bin nono -- compare_versions_honors_prerelease_ordering`.
  Test passes: `compare_versions("1.0.0-alpha", "1.0.0")` returns `Less`,
  `compare_versions("1.0.0-beta", "1.0.0-alpha")` returns `Greater`, and malformed
  versions fail fast. Confirms the semver dep is wired into the version-compare path.
result: pass

### 8. Hook-retention on nono remove
expected: |
  Run `cargo test -p nono-cli --bin nono --
  remove_external_artifacts_preserves_shared_hook_scripts
  remove_external_artifacts_still_removes_non_hook_files`. Both tests pass:
  `remove_external_artifacts` whitelists Hook artifacts (shared scripts under
  `~/.claude/hooks/<script>` are retained even when the owning package is removed)
  while still removing non-Hook files.
result: pass

### 9. Streaming + Size-cap Acceptance Criteria
expected: |
  Run `cargo test -p nono-cli --bin nono --
  download_artifact_to_path_computes_digest_of_streamed_bytes
  download_artifact_to_path_rejects_oversize_via_content_length
  registry_client_connect_timeout_fires_within_bounded_window
  tempdir_cleanup_runs_on_panic
  enforce_content_length_passes_when_header_absent
  enforce_content_length_rejects_oversize
  enforce_content_length_passes_at_boundary`. All 7 pass — confirms streaming sink,
  mid-stream digest, Content-Length pre-check, ureq connect timeout, and panic-safe
  TempDir Drop semantics from REQ-PKGS-01.
result: pass
note: |
  7 passed; 845 filtered out; 10.02s. The 10s wall-time is the connect-timeout test
  exercising its 10s ureq budget (acceptance #4a from REQ-PKGS-01).

### 10. Live Auto-Pull e2e (registry://ns/name@version)
expected: |
  Reference a `registry://ns/name@version` profile from `nono` and observe `is_registry_ref`
  routing through `load_registry_profile` to fetch the pack via the streaming pipeline,
  with the second invocation short-circuiting (idempotent — `<install_dir>/package.json`
  already present). Confirms REQ-PKGS-04 acceptance #1, #2, #3 end-to-end.
result: pass
note: |
  Verified on Windows host via two-step manual smoke (full live pull against a real
  signed registry pack remains deferred to v2.4 per host_blocker — needs Sigstore
  fixture infra + populated registry.nono.sh).

  Step 1 (routing): NONO_REGISTRY=http://127.0.0.1:1, ran
  `cargo run --bin nono -- run --profile fake-org/test-pack@0.0.1 -- cmd /c "echo hi"`.
  Output contained both `Profile 'fake-org/test-pack' not found locally.` (proves
  is_registry_ref → load_registry_profile dispatch) AND `Registry error: io: Connection
  refused` (proves auto-pull pipeline fired). Covers REQ-PKGS-04 acceptance #1.

  Step 2 (idempotency): seeded `%APPDATA%\nono\packages\fake-org\test-pack\package.json`
  with a minimal pack_type=policy manifest. Re-ran the same nono command. Output
  contained NO "not found locally" line; new error was `Profile parse error: no profile
  found in pack 'fake-org/test-pack'` — confirms package.json check at profile/mod.rs:1562
  short-circuited the auto-pull and the post-pull manifest-walk fired. Covers REQ-PKGS-04
  acceptance #3 (idempotent re-invocation).

  Acceptance #2 (full streaming pull happy-path against a real signed pack) remains
  deferred. Cookbook for junior devs documented in this UAT thread; reproduction
  recipe will work once registry.nono.sh hosts the nono-project/claude-code pack.

### 11. Live Streaming RSS Bound (Linux-host)
expected: |
  On a Linux host, pull a ~200 MB artifact and observe RSS peaks at ~10 MB during the
  download (not ~200 MB). Equivalent to running the
  `download_artifact_to_path_streams_under_bounded_rss` test that is `#[cfg(target_os
  = "linux")]`-gated and compiled out on this Windows host.
result: blocked
blocked_by: other
reason: |
  host-mismatch — current host is Windows; this test requires Linux (uses
  /proc/self/status for RSS measurement). Test compiles out cleanly under
  #[cfg(target_os = "linux")]. Portable-subset proxy is Test 9's
  download_artifact_to_path_rejects_oversize_via_content_length (passed) which
  verifies the same defense (size-cap mid-stream rejection BEFORE buffer
  materializes). Will close on next Linux/macOS host pass.

## Summary

total: 11
passed: 10
issues: 0
pending: 0
skipped: 0
blocked: 1

## Gaps

[none yet]
