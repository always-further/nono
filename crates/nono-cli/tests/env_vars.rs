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
fn env_nono_external_proxy() {
    let output = nono_bin()
        .env("NONO_EXTERNAL_PROXY", "squid.corp:3128")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_EXTERNAL_PROXY should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_external_proxy_bypass_comma_separated() {
    let output = nono_bin()
        .env("NONO_EXTERNAL_PROXY", "squid.corp:3128")
        .env("NONO_EXTERNAL_PROXY_BYPASS", "internal.corp,*.private.net")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_EXTERNAL_PROXY_BYPASS should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_external_proxy_bypass_requires_external_proxy() {
    // NONO_EXTERNAL_PROXY_BYPASS without NONO_EXTERNAL_PROXY should fail
    let output = nono_bin()
        .env("NONO_EXTERNAL_PROXY_BYPASS", "internal.corp")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "NONO_EXTERNAL_PROXY_BYPASS without NONO_EXTERNAL_PROXY should fail"
    );
}

#[test]
fn env_allow_net_conflicts_with_external_proxy() {
    // NONO_ALLOW_NET + NONO_EXTERNAL_PROXY should conflict at the clap level.
    let output = nono_bin()
        .env("NONO_EXTERNAL_PROXY", "squid.corp:3128")
        .env("NONO_ALLOW_NET", "true")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "NONO_ALLOW_NET + NONO_EXTERNAL_PROXY should conflict"
    );
}

#[test]
fn allow_net_overrides_profile_external_proxy() {
    // A profile with external_proxy should be overridden by --allow-net,
    // resulting in unrestricted network (no proxy mode activation).
    let dir = tempfile::tempdir().expect("tmpdir");
    let profile_path = dir.path().join("ext-proxy-profile.json");
    std::fs::write(
        &profile_path,
        r#"{
            "meta": { "name": "ext-proxy-test" },
            "network": { "external_proxy": "squid.corp:3128" }
        }"#,
    )
    .expect("write profile");

    let output = nono_bin()
        .args([
            "run",
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--allow-net",
            "--allow",
            "/tmp",
            "--dry-run",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "--allow-net should override profile external_proxy, stderr: {text}"
    );
    // Should show "allowed" network, not proxy mode
    assert!(
        text.contains("allowed"),
        "expected unrestricted network in dry-run output, got:\n{text}"
    );
}

#[test]
fn env_nono_no_hooks() {
    let output = nono_bin()
        .env("NONO_NO_HOOKS", "true")
        .args([
            "run",
            "--profile",
            "claude-code",
            "--allow-cwd",
            "--dry-run",
            "claude",
        ])
        .output()
        .expect("failed to run nono");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "NONO_NO_HOOKS=true should be accepted, stderr: {stderr}",
    );
    assert!(
        !stderr.contains("Installing hook"),
        "hooks should not be installed with NONO_NO_HOOKS=true, got: {stderr}",
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
