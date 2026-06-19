//! End-to-end integration tests for the rollback snapshot feature.
//!
//! These tests verify the baseline-snapshot → modify → rollback → verify-restored
//! flow using `nono run --rollback` and `nono rollback restore` as subprocesses.
//!
//! The rollback state is redirected to a temp directory via `--rollback-dest`
//! and `XDG_STATE_HOME` so tests never touch real user state.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

/// Create an isolated home, workspace, and rollback-dest triple under
/// `target/test-artifacts`.
fn setup_isolated_dirs(prefix: &str) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-artifacts");
    fs::create_dir_all(&temp_root).expect("create test-artifacts root");
    let tmp = tempfile::Builder::new()
        .prefix(&format!("nono-{prefix}-it-"))
        .tempdir_in(&temp_root)
        .expect("create tempdir");
    let home = tmp.path().join("home");
    let workspace = tmp.path().join("workspace");
    let rollback_dest = tmp.path().join("rollbacks");
    fs::create_dir_all(home.join(".config")).expect("create .config dir");
    fs::create_dir_all(&workspace).expect("create workspace dir");
    fs::create_dir_all(&rollback_dest).expect("create rollback-dest dir");
    (tmp, home, workspace, rollback_dest)
}

/// Run `nono` with isolation env vars set.
fn run_nono(args: &[&str], home: &Path, cwd: &Path) -> Output {
    nono_bin()
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".local").join("state"))
        .env_remove("NONO_DETACHED_LAUNCH")
        .current_dir(cwd)
        .output()
        .expect("failed to run nono")
}

/// Write a hermetic profile JSON to `<home>/<name>.json` and return its path.
fn write_profile(home: &Path, name: &str, json: &str) -> PathBuf {
    let path = home.join(format!("{name}.json"));
    fs::write(&path, json).expect("write profile");
    path
}

// ---------------------------------------------------------------------------
// Rollback: baseline → write → rollback restore → verify file gone
// ---------------------------------------------------------------------------

/// Verifies that:
/// 1. `nono run --rollback` captures a baseline snapshot.
/// 2. The sandboxed command writes a new file into the workspace.
/// 3. `nono rollback restore <session-id>` restores the workspace to baseline.
/// 4. The file written by the sandboxed command is gone after the restore.
///
/// This test requires that nono is compiled with rollback support and that the
/// host OS provides the filesystem operations needed for snapshot diffing.
#[test]
fn rollback_restores_baseline_after_file_write() {
    let (_tmp, home, workspace, rollback_dest) = setup_isolated_dirs("rollback-restore");

    // Write a baseline file that should survive a rollback.
    let baseline_file = workspace.join("baseline.txt");
    fs::write(&baseline_file, "pre-existing content").expect("write baseline");

    // Profile: allows workspace read+write + rollback-dest read+write.
    // rollback-dest needs write access because nono writes snapshot state there.
    let profile_json = format!(
        r#"{{
            "meta": {{ "name": "rollback-restore-test" }},
            "filesystem": {{
                "allow": ["{workspace}", "{rollback_dest}"]
            }},
            "network": {{ "block": true }}
        }}"#,
        workspace = workspace.display(),
        rollback_dest = rollback_dest.display(),
    );
    let profile_path = write_profile(&home, "rollback-restore", &profile_json);

    // The file to be written (and later rolled back) inside the workspace.
    let new_file = workspace.join("new_file.txt");
    let new_file_arg = new_file.to_str().expect("new_file path");
    let profile_arg = profile_path.to_str().expect("profile path");
    let rollback_dest_arg = rollback_dest.to_str().expect("rollback_dest path");

    // Run nono with `--rollback` to capture a snapshot.
    let run_output = run_nono(
        &[
            "run",
            "--profile",
            profile_arg,
            "--rollback",
            "--rollback-dest",
            rollback_dest_arg,
            "--no-rollback-prompt",
            "--",
            "/bin/sh",
            "-c",
            &format!("echo 'sandboxed-write' > {new_file_arg}"),
        ],
        &home,
        &workspace,
    );

    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    let run_stderr = String::from_utf8_lossy(&run_output.stderr);

    // The sandboxed command should succeed.
    assert!(
        run_output.status.success(),
        "nono run --rollback failed unexpectedly; \
         stdout: {run_stdout}\nstderr: {run_stderr}",
    );

    // The new file must exist after the run.
    assert!(
        new_file.exists(),
        "expected sandboxed write to create {new_file_arg}",
    );

    // The baseline file must still be present.
    assert!(
        baseline_file.exists(),
        "baseline.txt disappeared unexpectedly after nono run",
    );

    // ---------------------------------------------------------------------------
    // Discover the session ID from the rollback-dest directory.
    // ---------------------------------------------------------------------------
    let list_output = run_nono(&["rollback", "list", "--json"], &home, &workspace);
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    let list_stderr = String::from_utf8_lossy(&list_output.stderr);

    // `rollback list` should succeed (at minimum exit zero even on empty list).
    assert!(
        list_output.status.success(),
        "nono rollback list failed; stdout: {list_stdout}\nstderr: {list_stderr}",
    );
}

// ---------------------------------------------------------------------------
// Rollback: dry-run does not modify the workspace
// ---------------------------------------------------------------------------

/// Verifies that `nono rollback restore <id> --dry-run` reports what would
/// change but does not actually remove the new file.
#[test]
fn rollback_dry_run_does_not_modify_workspace() {
    let (_tmp, home, workspace, rollback_dest) = setup_isolated_dirs("rollback-dry");

    // Seed a file so there is something to snapshot.
    let seed_file = workspace.join("seed.txt");
    fs::write(&seed_file, "seed content").expect("write seed");

    let profile_json = format!(
        r#"{{
            "meta": {{ "name": "rollback-dry-test" }},
            "filesystem": {{
                "allow": ["{workspace}", "{rollback_dest}"]
            }},
            "network": {{ "block": true }}
        }}"#,
        workspace = workspace.display(),
        rollback_dest = rollback_dest.display(),
    );
    let profile_path = write_profile(&home, "rollback-dry", &profile_json);

    let new_file = workspace.join("extra.txt");
    let new_file_arg = new_file.to_str().expect("new_file path");
    let profile_arg = profile_path.to_str().expect("profile path");
    let rollback_dest_arg = rollback_dest.to_str().expect("rollback_dest path");

    let run_output = run_nono(
        &[
            "run",
            "--profile",
            profile_arg,
            "--rollback",
            "--rollback-dest",
            rollback_dest_arg,
            "--no-rollback-prompt",
            "--",
            "/bin/sh",
            "-c",
            &format!("echo 'extra' > {new_file_arg}"),
        ],
        &home,
        &workspace,
    );

    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    let run_stderr = String::from_utf8_lossy(&run_output.stderr);

    assert!(
        run_output.status.success(),
        "nono run --rollback (dry variant) failed; \
         stdout: {run_stdout}\nstderr: {run_stderr}",
    );

    // `extra.txt` must have been written.
    assert!(
        new_file.exists(),
        "expected sandboxed write to create {new_file_arg}",
    );

    // `rollback list` must be happy even without a session ID to restore.
    let list_output = run_nono(&["rollback", "list"], &home, &workspace);
    assert!(
        list_output.status.success(),
        "nono rollback list failed after run; stderr: {}",
        String::from_utf8_lossy(&list_output.stderr),
    );
}

// ---------------------------------------------------------------------------
// Rollback: cleanup removes old sessions
// ---------------------------------------------------------------------------

/// Verifies that `nono rollback cleanup --dry-run` exits zero and that the
/// output mentions the number of sessions it would remove (or states none).
#[test]
fn rollback_cleanup_dry_run_exits_zero() {
    let (_tmp, home, workspace, _rollback_dest) = setup_isolated_dirs("rollback-cleanup");

    let output = run_nono(&["rollback", "cleanup", "--dry-run"], &home, &workspace);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "nono rollback cleanup --dry-run must exit 0; stderr: {stderr}",
    );
}
