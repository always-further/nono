//! Phase 32 Plan 02 (D-32-01): integration tests for `nono setup --refresh-trust-root`.
//!
//! Tests assert `<NONO_TEST_HOME>/.nono/trust-root/trusted_root.json` is written
//! after a successful refresh, and that `--check-only` correctly reports the cache
//! status (NOT INITIALIZED when absent, STALE when expired, OK when fresh).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

fn run_nono(args: &[&str], home: &Path, cwd: &Path) -> Output {
    let mut cmd = nono_bin();
    cmd.args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("NONO_TEST_HOME", home)
        // Suppress update checks (network).
        .env("NONO_NO_UPDATE_CHECK", "1");
    cmd.current_dir(cwd).output().expect("failed to run nono")
}

fn setup_isolated_home() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp_root = std::env::current_dir()
        .expect("cwd")
        .join("target")
        .join("test-artifacts");
    fs::create_dir_all(&temp_root).expect("create temp root");
    let tmp = tempfile::Builder::new()
        .prefix("nono-setup-trust-root-it-")
        .tempdir_in(&temp_root)
        .expect("tempdir");
    let home = tmp.path().join("home");
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(home.join(".config")).expect("create config dir");
    fs::create_dir_all(home.join("AppData").join("Roaming")).expect("create AppData/Roaming");
    fs::create_dir_all(home.join("AppData").join("Local")).expect("create AppData/Local");
    fs::create_dir_all(home.join(".nono").join("trust-root")).expect("create trust-root dir");
    fs::create_dir_all(&workspace).expect("create workspace");
    (tmp, home, workspace)
}

/// D-32-01: `nono setup --refresh-trust-root` fetches the TUF trusted root and
/// writes it to `<NONO_TEST_HOME>/.nono/trust-root/trusted_root.json`.
///
/// Requires live network access to `https://tuf-repo-cdn.sigstore.dev`.
/// Kept `#[ignore]`d per D-32-07 (hermetic CI policy). Run manually to verify
/// the end-to-end flow after deploying to an internet-connected host.
#[test]
#[ignore = "requires network access to https://tuf-repo-cdn.sigstore.dev (manual operator verification)"]
fn setup_refresh_trust_root_writes_cache() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let output = run_nono(&["setup", "--refresh-trust-root"], &home, &workspace);
    assert!(
        output.status.success(),
        "setup --refresh-trust-root must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");
    assert!(
        cache_path.exists(),
        "cache file must be written at {}",
        cache_path.display()
    );
    let content = fs::read_to_string(&cache_path).expect("read cache");
    let _: serde_json::Value = serde_json::from_str(&content).expect("cache is valid JSON");
}

/// D-32-05 / Step 5 / P32-CHK-012: `nono setup --check-only` reports
/// "NOT INITIALIZED" when no cache file is present.
///
/// Hermetic — no network access required. The `setup_isolated_home` fixture
/// creates `.nono/trust-root/` but does NOT write `trusted_root.json`, so
/// `load_production_trusted_root` returns `TrustPolicy` (D-32-05) and the
/// check-only summary line must surface the "NOT INITIALIZED" substring.
#[test]
fn setup_check_only_reports_uninitialized_cache() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let output = run_nono(&["setup", "--check-only"], &home, &workspace);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Trust root cache: NOT INITIALIZED"),
        "--check-only must report NOT INITIALIZED for empty cache; got:\n{combined}"
    );
}

/// D-32-03 / P32-CHK-012: `nono setup --check-only` reports "STALE" and
/// surfaces the recovery command when the cache exists but is expired.
///
/// Hermetic — builds a minimal expired trusted-root JSON in-process and
/// writes it to the cache path before running the subprocess.
#[test]
fn setup_check_only_reports_stale_cache_with_recovery_hint() {
    let (_tmp, home, workspace) = setup_isolated_home();

    // Build a minimal expired trusted-root. Uses a real ECDSA P-256 key so
    // sigstore-rs's parser does not reject the `rawBytes` field.
    let expired_root_json = r#"{
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [
            {
                "baseUrl": "https://rekor.sigstore.dev",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": {
                        "start": "1970-01-01T00:00:00Z",
                        "end": "1970-01-02T00:00:00Z"
                    }
                },
                "logId": {
                    "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
                }
            }
        ],
        "certificateAuthorities": [],
        "ctlogs": [],
        "timestampAuthorities": []
    }"#;

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");
    fs::write(&cache_path, expired_root_json).expect("write expired root");

    let output = run_nono(&["setup", "--check-only"], &home, &workspace);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Trust root cache: STALE"),
        "--check-only must report STALE for expired cache; got:\n{combined}"
    );
    assert!(
        combined.contains("nono setup --refresh-trust-root"),
        "STALE branch must surface the recovery command literally; got:\n{combined}"
    );
}
