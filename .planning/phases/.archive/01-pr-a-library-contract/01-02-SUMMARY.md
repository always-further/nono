---
phase: 01-pr-a-library-contract
plan: "02"
subsystem: sandbox
tags: [rust, windows, sandbox, apply, library-contract, green-phase]

# Dependency graph
requires:
  - 01-01  # RED phase that wrote the 9 contract tests
provides:
  - "Real validate-and-signal apply() body for Windows sandbox"
  - "WINDOWS_PREVIEW_SUPPORTED flipped to true"
  - "support_info() returns SupportStatus::Supported"
  - "All 9 LIBCON-04 contract tests GREEN"
affects:
  - 01-03-pr-b-cli-messaging  # CLI messaging cleanup now has honest library contract to reference

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Validate-and-signal apply() pattern: classify shapes, return explicit UnsupportedPlatform errors for rejected shapes, Ok(()) for accepted shapes"
    - "Unsupported-shape classification in compile_filesystem_policy and compile_network_policy"

key-files:
  created: []
  modified:
    - "crates/nono/src/sandbox/windows.rs"
    - "crates/nono-cli/src/setup.rs"

key-decisions:
  - "Tests that asserted old behavior (single-file/write-only accepted by compile functions, preview_runtime_status treating them as advisory) were updated to assert the correct promoted behavior — these are correctness fixes, not deviations"
  - "Pre-existing nono-cli test failure (query_ext::tests::test_query_path_sensitive_policy_includes_policy_source) confirmed as out-of-scope pre-existing issue; not introduced by this plan"

# Metrics
duration: ~7min
completed: 2026-04-03
---

# Phase 01 Plan 02: PR-A Library Contract GREEN Summary

**Real validate-and-signal apply() body implemented; WINDOWS_PREVIEW_SUPPORTED flipped to true; support_info() returns Supported; all 9 contract tests pass GREEN**

## Performance

- **Duration:** ~7 min
- **Started:** 2026-04-03T22:28:55Z
- **Completed:** 2026-04-03T22:35:20Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Activated unsupported-shape classification in `compile_filesystem_policy`: single-file grants go to `unsupported` vec, write-only directory grants go to `unsupported` vec, only directory read/read-write grants go to `rules`
- Activated unsupported-shape classification in `compile_network_policy`: `tcp_connect_ports`, `tcp_bind_ports`, and `localhost_ports` allowlists now each push to `unsupported` vec
- Replaced `apply()` stub (`let _ = caps; Err(UnsupportedPlatform(...))`) with validate-and-signal body that checks all 7 rejection axes: filesystem shape, network shape, signal_mode, process_info_mode, ipc_mode, extensions_enabled, platform_rules
- Flipped `WINDOWS_PREVIEW_SUPPORTED` to `true`
- Replaced `WINDOWS_PREVIEW_DETAILS` constant with `WINDOWS_SUPPORTED_DETAILS` describing the promoted supported subset
- Updated `support_info()` to return `SupportStatus::Supported` and `WINDOWS_SUPPORTED_DETAILS`
- Removed setup.rs `println!("Windows CLI/release support is defined by that supported command surface; the embedded library \`Sandbox::apply()\` contract remains partial on Windows.")` (LIBCON-05)
- All 547 nono library tests pass; 61 Windows-specific tests pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Activate unsupported-shape classification in compile functions** - `fc155ec` (feat)
2. **Task 2: Implement apply() validate-and-signal body, flip constants, update support_info(), remove setup.rs line** - `b0af511` (feat)

## Files Created/Modified

- `crates/nono/src/sandbox/windows.rs` - compile function classification, apply() body, constants, support_info(), 9 test updates
- `crates/nono-cli/src/setup.rs` - removed partial-claim println (LIBCON-05)

## Decisions Made

- Tests asserting old compile-function behavior (single-file/write-only accepted as rules) were updated to assert the correct promoted classification — these are correctness corrections driven by the classification activation, not out-of-scope test changes
- 3 additional tests beyond the plan-specified 3 (`validate_launch_paths_accepts_supported_single_file_policy_shapes`, `preview_runtime_status_allows_single_file_only_policy_without_directory_coverage`, `preview_runtime_status_allows_write_only_directory_when_workdir_is_inside_allowlist`) were also updated since they would have become red from the same classification change — all are direct consequences of Task 1

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed 3 additional tests that broke from Task 1 classification activation**

- **Found during:** Task 1
- **Issue:** Beyond the 3 tests specified in the plan, 3 more tests asserted that single-file and write-only directory caps would produce advisory-only preview status or validate successfully, which contradicted the new classification behavior
- **Fix:** Renamed and updated `validate_launch_paths_accepts_supported_single_file_policy_shapes` -> `rejects_single_file_policy_shapes_as_unsupported`; `preview_runtime_status_allows_single_file_only_policy_without_directory_coverage` -> `reports_requires_enforcement_for_single_file_policy`; `preview_runtime_status_allows_write_only_directory_when_workdir_is_inside_allowlist` -> `reports_requires_enforcement_for_write_only_directory`
- **Files modified:** `crates/nono/src/sandbox/windows.rs`
- **Commit:** `fc155ec`

## Issues Encountered

- Pre-existing nono-cli test failure: `query_ext::tests::test_query_path_sensitive_policy_includes_policy_source` was failing before this plan began (confirmed by stash/restore check). Out of scope — logged as deferred.

## Known Stubs

None — `apply()` is now a real validate-and-signal function, not a stub. `is_supported()` returns true. `support_info()` returns Supported.

## Self-Check: PASSED

- FOUND: `crates/nono/src/sandbox/windows.rs`
- FOUND: `crates/nono-cli/src/setup.rs`
- FOUND: commit `fc155ec`
- FOUND: commit `b0af511`

---
*Phase: 01-pr-a-library-contract*
*Completed: 2026-04-03*
