//! Integration tests for `nono run --config <manifest>`.

use std::io::Write;
use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

#[cfg(target_os = "windows")]
fn test_command() -> [&'static str; 4] {
    ["--", "cmd", "/c", "echo"]
}

#[cfg(not(target_os = "windows"))]
fn test_command() -> [&'static str; 2] {
    ["--", "echo"]
}

fn escaped_temp_dir() -> String {
    std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "\\\\")
}

#[test]
fn config_with_valid_manifest_is_accepted() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    write!(
        f,
        r#"{{
            "version": "0.1.0",
            "filesystem": {{
                "grants": [{{ "path": "{}", "access": "read" }}]
            }},
            "network": {{ "mode": "blocked" }}
        }}"#,
        escaped_temp_dir()
    )
    .expect("write manifest");

    let mut command = nono_bin();
    command.args([
        "run",
        "--config",
        f.path().to_str().expect("path"),
        "--dry-run",
    ]);
    command.args(test_command());
    command.arg("hello");
    let output = command.output().expect("failed to run nono");

    #[cfg(not(target_os = "windows"))]
    assert!(
        output.status.success(),
        "expected success, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    #[cfg(target_os = "windows")]
    {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "expected Windows manifest dry-run to succeed, stderr: {stderr}"
        );
        assert!(
            stderr.contains("Capabilities:"),
            "expected capability summary in Windows manifest dry-run output, got: {stderr}"
        );
        assert!(
            stderr.contains("dry-run sandbox would be applied with above capabilities"),
            "expected cross-platform dry-run wording in Windows manifest output, got: {stderr}"
        );
        assert!(
            !stderr.contains("dry-run validates the current Windows command surface"),
            "manifest dry-run should not regress to stale Windows-specific wording, got: {stderr}"
        );
    }
}

#[test]
fn config_with_invalid_json_fails() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    write!(f, "not json at all").expect("write");

    let output = nono_bin()
        .args([
            "run",
            "--config",
            f.path().to_str().expect("path"),
            "--dry-run",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "expected failure for invalid JSON"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("error"),
        "expected error message, got: {stderr}"
    );
}

#[test]
fn config_with_missing_version_fails() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    write!(f, r#"{{ "filesystem": {{ }} }}"#).expect("write");

    let output = nono_bin()
        .args([
            "run",
            "--config",
            f.path().to_str().expect("path"),
            "--dry-run",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "expected failure for missing version"
    );
}

#[test]
fn config_conflicts_with_allow() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    write!(f, r#"{{ "version": "0.1.0" }}"#).expect("write");

    let output = nono_bin()
        .args([
            "run",
            "--config",
            f.path().to_str().expect("path"),
            "--allow",
            "/tmp",
            "--dry-run",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "expected failure: --config conflicts with --allow"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "expected conflict error, got: {stderr}"
    );
}

#[test]
fn config_conflicts_with_profile() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    write!(f, r#"{{ "version": "0.1.0" }}"#).expect("write");

    let output = nono_bin()
        .args([
            "run",
            "--config",
            f.path().to_str().expect("path"),
            "--profile",
            "default",
            "--dry-run",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "expected failure: --config conflicts with --profile"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "expected conflict error, got: {stderr}"
    );
}

#[test]
fn config_nonexistent_file_fails() {
    let output = nono_bin()
        .args([
            "run",
            "--config",
            "/tmp/nono-test-does-not-exist-12345.json",
            "--dry-run",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "expected failure for nonexistent file"
    );
}

#[test]
fn config_semantic_validation_rejects_bad_inject() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    write!(
        f,
        r#"{{
            "version": "0.1.0",
            "credentials": [{{
                "name": "test",
                "source": "env://TOKEN",
                "upstream": "https://api.example.com",
                "inject": {{ "mode": "url_path" }}
            }}]
        }}"#
    )
    .expect("write");

    let output = nono_bin()
        .args([
            "run",
            "--config",
            f.path().to_str().expect("path"),
            "--dry-run",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "expected failure: url_path without path_pattern"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("url_path") || stderr.contains("path_pattern"),
        "expected validation error about url_path, got: {stderr}"
    );
}
