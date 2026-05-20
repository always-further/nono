---
id: 44-class-d-validator-preflight-investigation
opened: 2026-05-20
opened_by: Phase 44 Plan 44-02 (REQ-TEST-HYG-01 follow-up per D-44-C3)
priority: low
category: bug-investigation
tags: [linux, landlock, deny-overlap, validator, policy.rs]
affects:
  - crates/nono-cli/src/policy.rs
  - crates/nono-cli/tests/deny_overlap_run.rs
resolves_phase: null
---

# validate_deny_overlaps pre-flight investigation (Linux host required)

## Context

Phase 44 REQ-TEST-HYG-01 closed via assertion update (D-44-C1) — the
Class D test now passes whether `validate_deny_overlaps` pre-flights
on Linux CI or the runtime Landlock filesystem denial kicks in. The
either-or assertion proves security equivalence: both shapes deny
the read, neither leaks the secret.

However: the validator pre-flight NOT firing on CI Linux is a real
latent bug. The originally-expected error message
("Landlock deny-overlap") never reaches stderr, suggesting
`validate_deny_overlaps` in `crates/nono-cli/src/policy.rs:1032-1088`
is either short-circuiting or not being called at the right point
in the policy pipeline on this CI Linux configuration.

## Hypothesis Branches (carried forward from Plan 41-10 todo lines 41-46)

1. The deny rule's path canonicalization on CI Linux yields a
   different canonicalized form than the allow rule's path, so the
   overlap check returns false negatively.
2. The validator runs at a stage where the deny rule isn't yet
   present (ordering issue between profile load + validator
   dispatch).
3. The validator IS firing but the diagnostic string was changed
   in an intermediate commit and the test fixture is stale (less
   likely; the string is greppable in the source).
4. CI Linux's filesystem implementation (overlayfs / tmpfs) is
   creating a canonical-path edge case the validator wasn't
   designed for.
5. The validator IS firing but its output is being captured by
   an earlier-stage error path that converts it to a different
   message before reaching the test's stderr capture.

## Investigation Steps (Linux dev host required)

1. On a Linux host, instrument `validate_deny_overlaps` with
   `tracing::debug!` at entry + each early-return path; rerun
   the test with `RUST_LOG=trace`. The trace output will pinpoint
   which branch fires (or doesn't).
2. Add a "did we get here" assertion in the validator's caller in
   `policy.rs` to detect the ordering bug (hypothesis 2).
3. `strace -f -e openat,readlink` on the test execution to catch
   filesystem-canonicalization edge cases (hypothesis 1 + 4).
4. Compare the diagnostic-string emission path against the
   test's stderr-capture path to detect interception (hypothesis 5).

## Acceptance Criteria

1. Root-cause of "Landlock deny-overlap" not appearing on Linux
   CI is identified and documented.
2. EITHER the validator pre-flight is fixed (the original
   expected behavior) OR the diagnostic string is updated to
   match what the validator actually emits.
3. The Class D test's either-or assertion can be tightened back
   to a single-branch assertion in a follow-up commit (optional
   — the either-or is acceptable indefinitely if both branches
   prove security equivalence).

## Estimated Cost

Small-to-medium: 4-8 hours of focused Linux-host work. The
instrumentation is straightforward; the puzzle is finding the
right hypothesis branch. Tag for the Phase 46 + 47 batch (UAT
backlog needs a Linux host anyway, so this folds in).

## References

- .planning/todos/done/41-10-linux-deny-overlap-regression.md (the
  original todo that motivated REQ-TEST-HYG-01)
- .planning/phases/44-review-polish-test-hygiene-drain/44-CONTEXT.md
  § Decisions D-44-C3 (this follow-up's chartering decision)
- crates/nono-cli/src/policy.rs:1032-1088 (validator source)
