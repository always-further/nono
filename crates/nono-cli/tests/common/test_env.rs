//! Integration-test copy of the `EnvVarGuard` RAII primitive.
//!
//! `crates/nono-cli` is a binary-only crate; its `#[cfg(test)] mod test_env`
//! in `src/test_env.rs` is therefore NOT visible from the integration test
//! compilation unit in `tests/`.  This file mirrors the canonical abstraction
//! verbatim so integration tests can use the same Drop-restore pattern without
//! reaching across the crate boundary.
//!
//! The source of truth for the guard contract is `crates/nono-cli/src/test_env.rs`.
//! If that file changes, update this mirror in lockstep.
//!
//! Phase 41 Plan 09 (REQ-CI-01 SC#4 gap closure, Gap 5): the sole caller
//! is `crates/nono-cli/tests/env_vars.rs:1047` inside a
//! `#[cfg(target_os = "windows")]` test (line 1039). On Linux/macOS the
//! test compiles out, leaving the entire mirror orphaned and triggering
//! `clippy::dead_code` under `-Dwarnings`. Gate the whole module to
//! Windows so the mirror exists only where it is used.

#![cfg(target_os = "windows")]

/// Restores a set of environment variables when dropped.
///
/// Identical to `crates/nono-cli/src::test_env::EnvVarGuard` — see that type
/// for design rationale.  Duplicated here because integration tests cannot
/// import from a binary-only crate's `#[cfg(test)]` modules (Phase 41-05,
/// REQ-CI-02).
pub struct EnvVarGuard {
    original: Vec<(&'static str, Option<String>)>,
}

#[allow(clippy::disallowed_methods)] // This IS the safe wrapper around env var mutation.
impl EnvVarGuard {
    /// Set multiple env vars, capturing originals for restore on drop.
    #[must_use]
    pub fn set_all(vars: &[(&'static str, &str)]) -> Self {
        let original = vars
            .iter()
            .map(|(key, _)| (*key, std::env::var(key).ok()))
            .collect::<Vec<_>>();

        for (key, value) in vars {
            std::env::set_var(key, value);
        }

        Self { original }
    }
}

#[allow(clippy::disallowed_methods)] // Restoring env vars is the other half of the safe wrapper.
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, value) in self.original.iter().rev() {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
