.PHONY: all build release test lint format audit clean

all: build

# Debug build
build:
	cargo build

# Release build with optimizations
release:
	cargo build --release

# Run all tests
test:
	cargo test

# Run clippy linter with strict settings
# change to (when unwraps gone): cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used
lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Format code
format:
	cargo fmt

# Check formatting without modifying files
format-check:
	cargo fmt -- --check

# Security audit dependencies
audit:
	cargo audit
	cargo deny check

# Run all checks (useful for CI)
check: format-check lint test audit

# Clean build artifacts
clean:
	cargo clean
