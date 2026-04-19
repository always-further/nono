//! Integration tests for canonical `nono profile` subcommands (inspection, comparison, validation).
//!
//! These run as separate processes, so they are fully isolated from unit tests.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

#[test]
fn test_groups_list_output() {
    let output = nono_bin()
        .args(["profile", "groups", "--all-platforms"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("deny_credentials"),
        "expected deny_credentials in output, got:\n{stdout}"
    );
}

#[test]
fn test_groups_detail_output() {
    let output = nono_bin()
        .args(["profile", "groups", "deny_credentials"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".ssh"),
        "expected .ssh in deny_credentials detail, got:\n{stdout}"
    );
    assert!(
        stdout.contains(".aws"),
        "expected .aws in deny_credentials detail, got:\n{stdout}"
    );
}

#[test]
fn test_groups_unknown_exits_error() {
    let output = nono_bin()
        .args(["profile", "groups", "nonexistent_group_xyz"])
        .output()
        .expect("failed to run nono");

    assert!(!output.status.success(), "expected non-zero exit");
}

#[test]
fn test_list_output() {
    let output = nono_bin()
        .args(["profile", "list"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("claude-code"),
        "expected claude-code in profiles list, got:\n{stdout}"
    );
    assert!(
        stdout.contains("default"),
        "expected default in profiles list, got:\n{stdout}"
    );
}

#[test]
fn test_show_profile_output() {
    let output = nono_bin()
        .args(["profile", "show", "default"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Security groups"),
        "expected Security groups section, got:\n{stdout}"
    );
}

#[test]
fn test_show_profile_json() {
    let output = nono_bin()
        .args(["profile", "show", "default", "--json"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("expected valid JSON output");
    assert!(
        val.get("security").is_some(),
        "expected security key in JSON"
    );
}

#[test]
fn test_diff_output() {
    let output = nono_bin()
        .args(["profile", "diff", "default", "claude-code"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains('+'),
        "expected + lines in diff output, got:\n{stdout}"
    );
}

#[test]
fn test_validate_valid_profile() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("valid-profile.json");
    std::fs::write(
        &path,
        r#"{
            "meta": { "name": "test", "description": "test profile" },
            "security": { "groups": ["deny_credentials"] },
            "workdir": { "access": "readwrite" }
        }"#,
    )
    .expect("write");

    let output = nono_bin()
        .args(["profile", "validate", path.to_str().expect("path")])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0 for valid profile, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_validate_invalid_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bad-profile.json");
    std::fs::write(
        &path,
        r#"{
            "meta": { "name": "test" },
            "security": { "groups": ["fake_group_that_does_not_exist"] }
        }"#,
    )
    .expect("write");

    let output = nono_bin()
        .args(["profile", "validate", path.to_str().expect("path")])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "expected non-zero exit for invalid group"
    );
}

#[test]
fn test_groups_json() {
    let output = nono_bin()
        .args(["profile", "groups", "--json", "--all-platforms"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("expected valid JSON output");
    assert!(val.is_array(), "expected JSON array");
    let arr = val.as_array().expect("array");
    assert!(arr.len() > 10, "expected many groups in JSON output");
}

// ---------------------------------------------------------------------------
// nono profile show --format manifest
// ---------------------------------------------------------------------------

#[test]
fn test_show_format_manifest_default_profile() {
    let output = nono_bin()
        .args(["profile", "show", "default", "--format", "manifest"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value =
        serde_json::from_str(&stdout).expect("expected valid JSON manifest");
    assert_eq!(
        val.get("version").and_then(|v| v.as_str()),
        Some("0.1.0"),
        "manifest must have version 0.1.0"
    );
    assert!(
        val.get("$schema").is_some(),
        "manifest should include $schema"
    );
}

#[test]
fn test_show_format_manifest_claude_code_profile() {
    let output = nono_bin()
        .args(["profile", "show", "claude-code", "--format", "manifest"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value =
        serde_json::from_str(&stdout).expect("expected valid JSON manifest");
    assert_eq!(val.get("version").and_then(|v| v.as_str()), Some("0.1.0"));
    // claude-code profile has filesystem grants
    assert!(
        val.get("filesystem").is_some(),
        "claude-code manifest should have filesystem grants"
    );
    let grants = val["filesystem"]["grants"]
        .as_array()
        .expect("grants array");
    assert!(
        !grants.is_empty(),
        "claude-code should have at least one filesystem grant"
    );
}

#[test]
fn test_show_format_manifest_round_trip() {
    // Build a minimal manifest with paths that exist everywhere,
    // then feed it back via --config --dry-run.
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("manifest.json");
    std::fs::write(
        &manifest_path,
        r#"{
            "version": "0.1.0",
            "filesystem": {
                "grants": [{ "path": "/tmp", "access": "read" }]
            },
            "network": { "mode": "blocked" }
        }"#,
    )
    .expect("write manifest");

    let output = nono_bin()
        .args([
            "run",
            "--config",
            manifest_path.to_str().expect("path"),
            "--dry-run",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "round-trip failed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_show_format_manifest_all_builtins_succeed() {
    // All built-in profiles should export without errors
    let list_output = nono_bin()
        .args(["profile", "list", "--json"])
        .output()
        .expect("failed to run nono");
    assert!(list_output.status.success());

    let stdout = String::from_utf8_lossy(&list_output.stdout);
    let profiles: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let arr = profiles.as_array().expect("array of profiles");

    for profile_val in arr {
        let name = profile_val
            .get("name")
            .and_then(|n| n.as_str())
            .expect("profile name");

        let output = nono_bin()
            .args(["profile", "show", name, "--format", "manifest"])
            .output()
            .expect("failed to run nono");

        assert!(
            output.status.success(),
            "profile '{}' failed manifest export, stderr: {}",
            name,
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("profile '{}' produced invalid JSON: {}", name, e));
        assert_eq!(
            val.get("version").and_then(|v| v.as_str()),
            Some("0.1.0"),
            "profile '{}' manifest missing version",
            name
        );
    }
}
