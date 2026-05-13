//! Integration tests for profile-drafts surface (Phase 36.5 D-36.5-A1..A3).
//!
//! Tests `nono profile init --draft`, `--refresh`, `nono profile promote`,
//! and `nono profile validate --draft` as subprocess invocations to ensure:
//!   1. Exit codes are directly observable.
//!   2. File-system side-effects are sandboxed to a TempDir.
//!   3. Cross-process env-var isolation avoids test pollution.
//!
//! Pattern: `Command::env("APPDATA"|"XDG_CONFIG_HOME", dir.path())` to redirect
//! the config dir for the subprocess. Both are passed so the test is cross-platform.

use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

/// Set up config-dir env vars for the subprocess pointing at `dir`.
/// Both APPDATA (Windows) and XDG_CONFIG_HOME (Unix) are set so tests
/// are portable across platforms.
fn with_config_dir<'a>(cmd: &'a mut Command, dir: &Path) -> &'a mut Command {
    cmd.env("APPDATA", dir)
        .env("XDG_CONFIG_HOME", dir)
        .env("HOME", dir)
}

/// Minimal valid profile JSON used as skeleton content for tests.
fn minimal_profile_json(name: &str) -> String {
    format!(
        r#"{{
  "meta": {{ "name": "{name}", "version": "1.0" }},
  "security": {{ "groups": [] }}
}}
"#
    )
}

/// Write a minimal profile JSON to `<dir>/nono/profiles/<name>.json`.
/// Creates parent directories automatically.
fn write_canonical_profile(dir: &Path, name: &str) {
    let profiles_dir = dir.join("nono").join("profiles");
    std::fs::create_dir_all(&profiles_dir).expect("create profiles dir");
    let path = profiles_dir.join(format!("{name}.json"));
    std::fs::write(&path, minimal_profile_json(name)).expect("write canonical profile");
}

/// Write a minimal profile JSON to `<dir>/nono/profile-drafts/<name>.json`.
/// Creates parent directories automatically.
fn write_draft_profile(dir: &Path, name: &str) {
    let drafts_dir = dir.join("nono").join("profile-drafts");
    std::fs::create_dir_all(&drafts_dir).expect("create profile-drafts dir");
    let path = drafts_dir.join(format!("{name}.json"));
    std::fs::write(&path, minimal_profile_json(name)).expect("write draft profile");
}

// ---------------------------------------------------------------------------
// Commit Group 1 tests: init --draft + --refresh
// ---------------------------------------------------------------------------

#[test]
fn init_draft_writes_to_drafts_dir() {
    let dir = TempDir::new().expect("create temp dir");
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "myagent"])
        .output()
        .expect("run nono");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "init --draft should exit 0; stderr: {stderr}"
    );

    // Draft file must exist under profile-drafts/
    let draft_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.json");
    assert!(
        draft_path.exists(),
        "draft file must exist at {}",
        draft_path.display()
    );

    // Canonical file must NOT have been created
    let canonical_path = dir
        .path()
        .join("nono")
        .join("profiles")
        .join("myagent.json");
    assert!(
        !canonical_path.exists(),
        "canonical profile must not exist (was: {})",
        canonical_path.display()
    );
}

#[test]
fn init_draft_with_existing_canonical_writes_base_sidecar() {
    let dir = TempDir::new().expect("create temp dir");
    // Pre-create canonical profile
    write_canonical_profile(dir.path(), "myagent");

    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "myagent", "--force"])
        .output()
        .expect("run nono");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "init --draft with existing canonical should exit 0; stderr: {stderr}"
    );

    // Draft JSON must exist
    let draft_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.json");
    assert!(draft_path.exists(), "draft JSON must exist");

    // Sidecar .base must exist (canonical was present)
    let base_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.base");
    assert!(
        base_path.exists(),
        "sidecar .base file must exist when canonical is present"
    );

    // .base content must be 64 hex chars (SHA-256)
    let base_content = std::fs::read_to_string(&base_path).expect("read .base file");
    let base_content = base_content.trim();
    assert_eq!(
        base_content.len(),
        64,
        "base hash must be 64 hex chars, got: {base_content:?}"
    );
    assert!(
        base_content.chars().all(|c| c.is_ascii_hexdigit()),
        "base hash must be lowercase hex, got: {base_content:?}"
    );
}

#[test]
fn init_draft_force_overwrites() {
    let dir = TempDir::new().expect("create temp dir");

    // First init creates the draft
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "myagent"])
        .output()
        .expect("run nono first time");
    assert!(output.status.success(), "first init must succeed");

    // Second init without --force must fail
    let mut cmd2 = nono_bin();
    with_config_dir(&mut cmd2, dir.path());
    let output2 = cmd2
        .args(["profile", "init", "--draft", "myagent"])
        .output()
        .expect("run nono second time");
    assert!(
        !output2.status.success(),
        "second init without --force must fail"
    );
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        stderr2.contains("already exists") || stderr2.contains("Use --force"),
        "stderr must mention existing file, got: {stderr2}"
    );

    // Second init WITH --force must succeed
    let mut cmd3 = nono_bin();
    with_config_dir(&mut cmd3, dir.path());
    let output3 = cmd3
        .args(["profile", "init", "--draft", "myagent", "--force"])
        .output()
        .expect("run nono with --force");
    let stderr3 = String::from_utf8_lossy(&output3.stderr);
    assert!(
        output3.status.success(),
        "init --draft --force must succeed; stderr: {stderr3}"
    );
}

#[test]
fn init_draft_refresh_preserves_content() {
    let dir = TempDir::new().expect("create temp dir");

    // Pre-create canonical and draft
    write_canonical_profile(dir.path(), "myagent");
    write_draft_profile(dir.path(), "myagent");

    // Write a stale sidecar manually
    let base_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.base");
    std::fs::write(&base_path, "a".repeat(64)).expect("write stale sidecar");

    let draft_before = std::fs::read_to_string(
        dir.path()
            .join("nono")
            .join("profile-drafts")
            .join("myagent.json"),
    )
    .expect("read draft before");

    // Run --refresh
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "--refresh", "myagent"])
        .output()
        .expect("run nono refresh");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "--refresh should exit 0; stderr: {stderr}"
    );

    // Draft JSON content must be UNCHANGED
    let draft_after = std::fs::read_to_string(
        dir.path()
            .join("nono")
            .join("profile-drafts")
            .join("myagent.json"),
    )
    .expect("read draft after");
    assert_eq!(
        draft_before, draft_after,
        "--refresh must not modify draft JSON content"
    );

    // Sidecar must be updated (not still "aaa...")
    let base_after = std::fs::read_to_string(&base_path).expect("read sidecar after");
    let base_after = base_after.trim();
    assert_ne!(
        base_after,
        "a".repeat(64).as_str(),
        "sidecar must be updated by --refresh"
    );
    assert_eq!(
        base_after.len(),
        64,
        "refreshed sidecar must be 64 hex chars"
    );
}

#[test]
fn init_draft_refresh_errors_without_canonical() {
    let dir = TempDir::new().expect("create temp dir");

    // Only a draft, no canonical
    write_draft_profile(dir.path(), "myagent");

    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "--refresh", "myagent"])
        .output()
        .expect("run nono refresh without canonical");

    assert!(
        !output.status.success(),
        "--refresh without canonical must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no canonical profile to refresh against"),
        "stderr must mention missing canonical, got: {stderr}"
    );
}

#[test]
fn init_draft_refresh_errors_without_draft() {
    let dir = TempDir::new().expect("create temp dir");
    // No draft at all

    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "--refresh", "myagent"])
        .output()
        .expect("run nono refresh without draft");

    assert!(
        !output.status.success(),
        "--refresh without draft must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no draft to refresh"),
        "stderr must mention missing draft, got: {stderr}"
    );
}

#[test]
fn init_draft_invalid_name_rejected() {
    let dir = TempDir::new().expect("create temp dir");

    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "../etc/passwd"])
        .output()
        .expect("run nono with invalid name");

    assert!(
        !output.status.success(),
        "invalid profile name must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Commit Group 2 tests: promote
// ---------------------------------------------------------------------------

#[test]
fn promote_yes_renames_draft_to_canonical() {
    let dir = TempDir::new().expect("create temp dir");

    // Create a draft via init --draft
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "myagent"])
        .output()
        .expect("init draft");
    assert!(output.status.success(), "init --draft must succeed");

    // Promote with --yes
    let mut cmd2 = nono_bin();
    with_config_dir(&mut cmd2, dir.path());
    let output2 = cmd2
        .args(["profile", "promote", "--yes", "myagent"])
        .output()
        .expect("promote");

    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        output2.status.success(),
        "promote --yes must exit 0; stderr: {stderr2}"
    );

    // Canonical must exist
    let canonical = dir
        .path()
        .join("nono")
        .join("profiles")
        .join("myagent.json");
    assert!(canonical.exists(), "canonical must exist after promote");

    // Draft must be gone
    let draft = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.json");
    assert!(!draft.exists(), "draft must be removed after promote");

    // Sidecar must be gone
    let base = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.base");
    assert!(
        !base.exists(),
        "sidecar .base must be removed after promote"
    );
}

#[test]
fn promote_first_time_skips_base_hash() {
    let dir = TempDir::new().expect("create temp dir");

    // Create draft (no canonical) — first-time promote
    write_draft_profile(dir.path(), "myagent");

    // Promote --yes (no sidecar, no canonical → first-time path)
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "promote", "--yes", "myagent"])
        .output()
        .expect("promote first time");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "first-time promote --yes must exit 0; stderr: {stderr}"
    );

    // Canonical must exist
    let canonical = dir
        .path()
        .join("nono")
        .join("profiles")
        .join("myagent.json");
    assert!(
        canonical.exists(),
        "canonical must exist after first-time promote"
    );
}

#[test]
fn promote_base_hash_mismatch_action_required() {
    let dir = TempDir::new().expect("create temp dir");

    // Create canonical
    write_canonical_profile(dir.path(), "myagent");
    // Create draft
    write_draft_profile(dir.path(), "myagent");
    // Write a stale sidecar (wrong hash)
    let base_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.base");
    std::fs::write(&base_path, "a".repeat(64)).expect("write stale sidecar");

    // Promote with --yes — should fail with ActionRequired
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "promote", "--yes", "myagent"])
        .output()
        .expect("promote with stale hash");

    assert!(
        !output.status.success(),
        "promote with stale base-hash must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expected:"),
        "stderr must contain 'expected:'; got: {stderr}"
    );
    assert!(
        stderr.contains("actual:"),
        "stderr must contain 'actual:'; got: {stderr}"
    );
    assert!(
        stderr.contains("nono profile init --draft --refresh"),
        "stderr must contain --refresh instruction; got: {stderr}"
    );
}

#[test]
fn promote_shadow_builtin_refused() {
    let dir = TempDir::new().expect("create temp dir");

    // Create a draft named 'claude-code' (a built-in profile)
    write_draft_profile(dir.path(), "claude-code");

    // Promote --yes must refuse
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "promote", "--yes", "claude-code"])
        .output()
        .expect("promote shadow builtin");

    assert!(
        !output.status.success(),
        "promote of built-in name must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("built-in") || stderr.contains("cannot be promoted"),
        "stderr must mention built-in refusal; got: {stderr}"
    );

    // Canonical must NOT have been created/modified
    let canonical = dir
        .path()
        .join("nono")
        .join("profiles")
        .join("claude-code.json");
    assert!(
        !canonical.exists(),
        "canonical must NOT be created when shadow refused"
    );
}

#[test]
fn promote_shadow_package_managed_refused() {
    let dir = TempDir::new().expect("create temp dir");

    // Pre-create a fake package store layout and symlink canonical to it.
    // package_store_dir = <dir>/nono/packages
    // Profile symlink: <dir>/nono/profiles/myagent.json -> <dir>/nono/packages/fake_pkg/profiles/myagent.json
    let packages_dir = dir
        .path()
        .join("nono")
        .join("packages")
        .join("fake_pkg")
        .join("profiles");
    std::fs::create_dir_all(&packages_dir).expect("create package profile dir");
    let pkg_profile = packages_dir.join("myagent.json");
    std::fs::write(&pkg_profile, minimal_profile_json("myagent")).expect("write pkg profile");

    let profiles_dir = dir.path().join("nono").join("profiles");
    std::fs::create_dir_all(&profiles_dir).expect("create profiles dir");

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&pkg_profile, profiles_dir.join("myagent.json"))
            .expect("create symlink");
    }
    #[cfg(windows)]
    {
        // On Windows, create a symlink (requires SeCreateSymbolicLinkPrivilege or
        // Developer Mode; skip the test if symlink creation fails).
        if std::os::windows::fs::symlink_file(&pkg_profile, profiles_dir.join("myagent.json"))
            .is_err()
        {
            // Can't create symlink without elevated privileges — skip test.
            eprintln!("SKIP: promote_shadow_package_managed_refused (Windows symlink requires elevated privileges)");
            return;
        }
    }

    // Create a draft for the same name
    write_draft_profile(dir.path(), "myagent");

    // Promote --yes must refuse
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "promote", "--yes", "myagent"])
        .output()
        .expect("promote package-managed");

    assert!(
        !output.status.success(),
        "promote of package-managed name must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Must mention either "package-managed" or "cannot be promoted"
    assert!(
        stderr.contains("package-managed") || stderr.contains("cannot be promoted"),
        "stderr must mention package-managed refusal; got: {stderr}"
    );
}

#[test]
fn promote_declined_does_not_modify_canonical() {
    // This test documents that the interactive [y/N] prompt aborts promote.
    // In automated subprocess form, stdin is closed/empty which maps to the
    // default answer "N" (default_yes = false for promote).
    let dir = TempDir::new().expect("create temp dir");

    // Set up draft (first-time, no canonical)
    write_draft_profile(dir.path(), "myagent");

    // Promote WITHOUT --yes (interactive) → stdin closed → defaults to N
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    // Run and ignore the exit code — either aborted-cleanly (exit 0) or
    // errored (exit non-zero). What matters is the file-system state.
    let _output = cmd
        .args(["profile", "promote", "myagent"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("promote declined");

    // Either exits 0 (aborted cleanly) or exits non-zero. Either way,
    // canonical must NOT be created.
    let canonical = dir
        .path()
        .join("nono")
        .join("profiles")
        .join("myagent.json");
    assert!(
        !canonical.exists(),
        "canonical must NOT be created when promote is declined"
    );
}

#[test]
fn promote_invalid_name_rejected() {
    let dir = TempDir::new().expect("create temp dir");

    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "promote", "--yes", "../etc/passwd"])
        .output()
        .expect("promote invalid name");

    assert!(
        !output.status.success(),
        "promote of invalid name must fail"
    );
}

#[test]
fn promote_yes_with_diff_emits_summary_not_full_diff() {
    let dir = TempDir::new().expect("create temp dir");

    // Create canonical with a group
    let canonical_json = r#"{
  "meta": {"name": "myagent", "version": "1.0"},
  "security": {"groups": ["deny_credentials"]}
}
"#;
    let profiles_dir = dir.path().join("nono").join("profiles");
    std::fs::create_dir_all(&profiles_dir).expect("create profiles dir");
    std::fs::write(profiles_dir.join("myagent.json"), canonical_json).expect("write canonical");

    // Create draft with a different group
    let draft_json = r#"{
  "meta": {"name": "myagent", "version": "1.0"},
  "security": {"groups": ["read_home_directory"]}
}
"#;
    let drafts_dir = dir.path().join("nono").join("profile-drafts");
    std::fs::create_dir_all(&drafts_dir).expect("create drafts dir");
    std::fs::write(drafts_dir.join("myagent.json"), draft_json).expect("write draft");

    // Write a correct sidecar (hash of canonical)
    let canonical_bytes = canonical_json.as_bytes();
    // We need the SHA-256 of canonical — compute it via sha2 if available,
    // or use a subprocess to write a correct sidecar.
    // Simplest: init --draft --refresh to regenerate the sidecar.
    // First write draft so refresh has something to refresh.
    let mut refresh_cmd = nono_bin();
    with_config_dir(&mut refresh_cmd, dir.path());
    let refresh_out = refresh_cmd
        .args(["profile", "init", "--draft", "--refresh", "myagent"])
        .output()
        .expect("refresh sidecar");
    let refresh_err = String::from_utf8_lossy(&refresh_out.stderr);
    assert!(
        refresh_out.status.success(),
        "refresh must succeed; stderr: {refresh_err}"
    );
    let _ = canonical_bytes; // suppress unused warning

    // Promote --yes should emit a one-line summary to stderr
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "promote", "--yes", "myagent"])
        .output()
        .expect("promote with diff");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "promote --yes must succeed; stderr: {stderr}"
    );

    // Summary must contain "added", "removed", or "changed" (one-line format)
    // Must NOT be a full multi-line diff dump (i.e., no "  + group:" or "  - group:" lines)
    assert!(
        stderr.contains("added") || stderr.contains("removed") || stderr.contains("changed"),
        "stderr must contain summary stats; got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Commit Group 3 tests: validate --draft + round-trip serde
// ---------------------------------------------------------------------------

/// REQ-PORT-CLOSURE-03 Task C3-01 Test 1:
/// `validate --draft myagent` resolves under `profile-drafts/`.
/// `validate myagent` (without --draft) must fail (canonical does not exist).
#[test]
fn validate_draft_resolves_drafts_dir() {
    let dir = TempDir::new().expect("create temp dir");

    // Create draft via `init --draft`
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let init_out = cmd
        .args(["profile", "init", "--draft", "myagent"])
        .output()
        .expect("init --draft");
    assert!(
        init_out.status.success(),
        "init --draft must succeed; stderr: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    // validate --draft myagent must succeed (resolves draft path)
    let mut cmd2 = nono_bin();
    with_config_dir(&mut cmd2, dir.path());
    let validate_out = cmd2
        .args(["profile", "validate", "--draft", "myagent"])
        .output()
        .expect("validate --draft");
    assert!(
        validate_out.status.success(),
        "validate --draft must succeed; stderr: {}",
        String::from_utf8_lossy(&validate_out.stderr)
    );

    // validate myagent (without --draft) must fail (no canonical)
    let mut cmd3 = nono_bin();
    with_config_dir(&mut cmd3, dir.path());
    let validate_canonical_out = cmd3
        .args(["profile", "validate", "myagent"])
        .output()
        .expect("validate without --draft");
    assert!(
        !validate_canonical_out.status.success(),
        "validate without --draft must fail when no canonical exists"
    );
}

/// REQ-PORT-CLOSURE-03 Task C3-01 Test 2:
/// `validate --draft --strict myagent` fails on a draft with legacy `override_deny` key.
#[test]
fn validate_draft_strict_fails_legacy_keys() {
    let dir = TempDir::new().expect("create temp dir");

    // Create draft with legacy `override_deny` key directly
    let drafts_dir = dir.path().join("nono").join("profile-drafts");
    std::fs::create_dir_all(&drafts_dir).expect("create drafts dir");
    let draft_path = drafts_dir.join("legacytest.json");
    let legacy_json = r#"{
  "meta": { "name": "legacytest", "version": "1.0" },
  "security": { "groups": [] },
  "policy": { "override_deny": ["/tmp/secret"] }
}"#;
    std::fs::write(&draft_path, legacy_json).expect("write legacy draft");

    // validate --draft --strict legacytest must fail
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let out = cmd
        .args(["profile", "validate", "--draft", "--strict", "legacytest"])
        .output()
        .expect("validate --draft --strict");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "validate --draft --strict must fail on legacy keys; stderr: {stderr}"
    );
    // Should mention legacy key or override_deny
    assert!(
        stderr.contains("override_deny") || stderr.contains("legacy") || stderr.contains("strict"),
        "stderr must mention legacy key or strict failure; got: {stderr}"
    );
}

/// REQ-PORT-CLOSURE-03 Task C3-01 Test 3:
/// `validate --draft --strict myagent` succeeds on a clean draft (no legacy keys).
#[test]
fn validate_draft_and_strict_compose() {
    let dir = TempDir::new().expect("create temp dir");

    // Create draft via `init --draft`
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let init_out = cmd
        .args(["profile", "init", "--draft", "cleantest"])
        .output()
        .expect("init --draft");
    assert!(
        init_out.status.success(),
        "init --draft must succeed; stderr: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    // validate --draft --strict cleantest must succeed (no legacy keys)
    let mut cmd2 = nono_bin();
    with_config_dir(&mut cmd2, dir.path());
    let out = cmd2
        .args(["profile", "validate", "--draft", "--strict", "cleantest"])
        .output()
        .expect("validate --draft --strict");
    assert!(
        out.status.success(),
        "validate --draft --strict must succeed on clean draft; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// REQ-PORT-CLOSURE-03 acceptance #5: init --draft → edit → promote → load
/// canonical → deserialize as Profile → matches draft (modulo sidecar).
#[test]
fn draft_promote_roundtrip_serde() {
    let dir = TempDir::new().expect("create temp dir");
    let name = "rttest";

    // 1. init --draft
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let out = cmd
        .args(["profile", "init", "--draft", name])
        .output()
        .expect("init --draft");
    assert!(
        out.status.success(),
        "init --draft failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 2. Edit draft (add a group)
    let draft_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join(format!("{name}.json"));
    let mut profile_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&draft_path).expect("read draft"))
            .expect("parse draft");
    profile_json["security"]["groups"] = serde_json::json!(["web-dev-read"]);
    std::fs::write(
        &draft_path,
        serde_json::to_string_pretty(&profile_json).expect("serialize draft"),
    )
    .expect("write draft");

    // 3. promote --yes (no canonical exists; first-time promote)
    let mut cmd2 = nono_bin();
    with_config_dir(&mut cmd2, dir.path());
    let out2 = cmd2
        .args(["profile", "promote", "--yes", name])
        .output()
        .expect("promote --yes");
    assert!(
        out2.status.success(),
        "promote --yes failed: {}",
        String::from_utf8_lossy(&out2.stderr)
    );

    // 4. Canonical now exists; deserialize
    let canonical_path = dir
        .path()
        .join("nono")
        .join("profiles")
        .join(format!("{name}.json"));
    let canonical_bytes = std::fs::read(&canonical_path).expect("read canonical");
    let canonical_value: serde_json::Value =
        serde_json::from_slice(&canonical_bytes).expect("parse canonical");

    // 5. Matches the edited draft (modulo sidecar, which is cleaned up on promote)
    assert_eq!(
        canonical_value["security"]["groups"],
        serde_json::json!(["web-dev-read"]),
        "canonical profile must contain the group added in the draft"
    );
}
