# Deferred Items — Phase 28 Plan 01

## Pre-existing clippy errors in crates/nono/src/manifest.rs (out of scope)

Two `clippy::collapsible_match` errors at `crates/nono/src/manifest.rs:103` and one
similar location existed before Phase 28 began (verified by `git stash` + `cargo clippy
--package nono --lib`). They are unrelated to Authenticode chain-walker work and are
in the `nono` crate (which Phase 28 must NOT modify per D-19 byte-identical
preservation invariant). Logged here for a future maintenance pass.

## Probe test removed

The `_probe_embedded_signed_candidates` test (used during Task 5 fixture discovery
to identify which Windows-shipped binaries are embedded-signed vs catalog-signed) was
removed before final commit to keep the test surface tidy. Probe output is preserved
in the SUMMARY.md and the FIXTURE_PATH doc-comment which documents the catalog-vs-
embedded distinction discovered.
