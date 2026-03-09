//! Integration tests for environment variable CLI flag equivalents.
//!
//! These run as separate processes via `--dry-run`, so env vars are isolated
//! and cannot race with parallel unit tests.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

/// Combine stdout + stderr for assertion checking (nono writes UX to stderr).
fn combined_output(output: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&output.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&output.stderr));
    s
}

#[test]
fn env_nono_allow_comma_separated() {
    let output = nono_bin()
        .env("NONO_ALLOW", "/tmp/a,/tmp/b")
        .args(["run", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        text.contains("/tmp/a") && text.contains("/tmp/b"),
        "expected both paths in dry-run output, got:\n{text}"
    );
}

#[test]
fn env_nono_block_net() {
    let output = nono_bin()
        .env("NONO_BLOCK_NET", "1")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        text.contains("blocked"),
        "expected network blocked in dry-run output, got:\n{text}"
    );
}

#[test]
fn env_nono_block_net_accepts_true() {
    let output = nono_bin()
        .env("NONO_BLOCK_NET", "true")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_BLOCK_NET=true should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn legacy_env_nono_net_block_still_works() {
    let output = nono_bin()
        .env("NONO_NET_BLOCK", "1")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        text.contains("blocked"),
        "expected legacy NONO_NET_BLOCK to still block network, got:\n{text}"
    );
}

#[test]
fn env_nono_profile() {
    let output = nono_bin()
        .env("NONO_PROFILE", "claude-code")
        .args(["run", "--dry-run", "--allow-cwd", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_PROFILE=claude-code should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_network_profile() {
    let output = nono_bin()
        .env("NONO_NETWORK_PROFILE", "claude-code")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_NETWORK_PROFILE should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_flag_overrides_env_var() {
    // CLI --profile should override NONO_PROFILE env var.
    // "nonexistent-profile-from-env" would fail if used, but CLI wins.
    let output = nono_bin()
        .env("NONO_PROFILE", "nonexistent-profile-from-env")
        .args([
            "run",
            "--profile",
            "claude-code",
            "--dry-run",
            "--allow-cwd",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "CLI --profile should override env var, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_conflict_allow_net_and_block_net() {
    let output = nono_bin()
        .env("NONO_ALLOW_NET", "true")
        .env("NONO_BLOCK_NET", "true")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "NONO_ALLOW_NET + NONO_BLOCK_NET should conflict"
    );
}
