# Testing Patterns

**Analysis Date:** 2025-04-05

## Test Framework

**Runner:**
- `cargo test`: Standard Rust test runner for unit and documentation tests.
- `bash`: Used for integration test suites via `tests/run_integration_tests.sh`.
- `pwsh`: Used for Windows-specific test suites via `scripts/windows-test-harness.ps1`.

**Assertion Library:**
- Standard Rust: `assert!`, `assert_eq!`, `assert_ne!`.
- Shell tests: Custom functions in `tests/lib/test_helpers.sh` like `run_test`, `expect_success`, `expect_failure`.

**Run Commands:**
```bash
make test             # Run all tests (library, CLI, and FFI)
cargo test --workspace # Run all unit and doc tests
./tests/run_integration_tests.sh # Run integration tests (requires nono-cli built with test-trust-overrides)
pwsh scripts/windows-test-harness.ps1 -Suite smoke # Run Windows smoke tests
```

## Test File Organization

**Location:**
- Unit Tests: Co-located in source files using `#[cfg(test)] mod tests { ... }`.
- Integration Tests: 
    - `crates/nono/tests/`: Rust-based library integration tests.
    - `tests/integration/`: Bash-based CLI integration tests.

**Naming:**
- Unit test functions: `test_<feature>_<scenario>` (e.g., `test_path_covered_basic`).
- Integration test scripts: `test_<feature>.sh` (e.g., `test_fs_access.sh`).

**Structure:**
```
crates/nono/src/[file].rs       # Contains unit tests at the end
tests/
├── lib/
│   └── test_helpers.sh         # Common functions for shell tests
├── integration/
│   ├── test_fs_access.sh       # Script for specific feature tests
│   └── ...
└── run_integration_tests.sh    # Central integration test runner
```

## Test Structure

**Suite Organization:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_feature_scenario() {
        // Setup
        let dir = tempdir().unwrap();
        // Action
        let result = ...;
        // Assertion
        assert!(result.is_ok());
    }
}
```

**Patterns:**
- **Setup:** `tempfile::tempdir()` for filesystem tests.
- **Teardown:** Handled automatically by `tempfile` scope or script `trap` commands.
- **Assertion:** Direct value comparison or output string matching.

## Mocking

**Framework:** None detected (manual mocking or behavioral testing preferred).

**Patterns:**
- Behavioral testing: Using real files and processes in a controlled sandbox.
- Feature flags: `test-trust-overrides` enables testing of security policies without real signatures.

**What to Mock:**
- Environment variables via `std::env::set_var` (using `Serial` if necessary).
- Platform-specific behavior is often tested via separate scripts or `#[cfg]`.

**What NOT to Mock:**
- Kernel-level sandboxing (Seatbelt, Landlock): These are tested via probe logic in `probe_sandbox_availability`.

## Fixtures and Factories

**Test Data:**
- Builder pattern used to create `CapabilitySet` for tests.
- `tempfile` used for ephemeral test directories and files.

**Location:**
- Inline in test functions.
- `crates/nono-cli/data/` for some static test data (if applicable).

## Coverage

**Requirements:** None explicitly stated, but high coverage is maintained for core capability logic.

**View Coverage:**
- Not currently integrated into CI, but can be run locally using `cargo-tarpaulin` or `llvm-cov`.

## Test Types

**Unit Tests:**
- Scope: Individual modules (e.g., `capability`, `keystore`, `net_filter`).
- Approach: Direct function calls and state assertions.

**Integration Tests:**
- Scope: CLI end-to-end behavior.
- Approach: Spawning the `nono` binary and checking exit codes and output strings.
- Infrastructure: `tests/run_integration_tests.sh` provides parallel execution and summary reporting.

**Windows-Specific Tests:**
- Specialized harness in `scripts/windows-test-harness.ps1` for `build`, `smoke`, `integration`, `security`, and `regression` suites.

## Common Patterns

**Async Testing:**
- `#[tokio::test]` is used for testing asynchronous functions.

**Error Testing:**
```rust
#[test]
fn test_error_case() {
    let result = function_that_fails();
    assert!(matches!(result, Err(NonoError::SpecificVariant(_))));
}
```

**Platform-Specific Tests:**
- Use of `#[cfg(unix)]`, `#[cfg(target_os = "macos")]`, etc., to gate tests for specific platforms.

---

*Testing analysis: 2025-04-05*
