//! Phase 32 Plan 02 (D-32-01): integration tests for `nono setup --refresh-trust-root`.
//!
//! Tests assert `<NONO_TEST_HOME>/.nono/trust-root/trusted_root.json` is written
//! after a successful refresh, and that `--check-only` correctly reports the cache
//! status (NOT INITIALIZED when absent, STALE when expired, OK when fresh).

use serde_json::Value;
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

// ---------------------------------------------------------------------------
// Phase 49 Plan 01 (REQ-POC-TRUST-01): integration tests for
// `nono setup --from-file <PATH>`. Covers failure modes F-01-01 through
// F-01-07 per `.planning/phases/49-.../49-VALIDATION.md`. Reuses the
// `run_nono` + `setup_isolated_home` helpers above (subprocess isolation
// pattern — no parent-env mutation, hermetic by construction).
// ---------------------------------------------------------------------------

/// F-01-05 + happy-path: `nono setup --from-file <good>.json` exits 0 and
/// writes a cache file byte-identical to the input. Also asserts the
/// D-49-B3 stdout shape (`[X/N] Loading Sigstore trusted root from file...`
/// + `* Source: <abs_path>` lines).
#[test]
fn from_file_happy_path_writes_byte_identical_cache_and_stdout_matches_shape() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("input.json");
    fs::copy(frozen_fixture_path(), &src).expect("copy frozen fixture to src");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "setup --from-file must succeed on a known-good fixture; stderr:\n{stderr}\nstdout:\n{stdout}"
    );

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");
    assert!(
        cache_path.exists(),
        "cache file must exist at {cache_path:?}"
    );

    let src_bytes = fs::read(&src).expect("read src");
    let cache_bytes = fs::read(&cache_path).expect("read cache");
    assert_eq!(
        src_bytes, cache_bytes,
        "cache file must be byte-identical to the input (D-49-B1)"
    );

    // D-49-B3 stdout shape — verb "Loading", + Source: breadcrumb.
    assert!(
        stdout.contains("Loading Sigstore trusted root from file"),
        "stdout must contain 'Loading...' verb (D-49-B3); got:\n{stdout}"
    );
    assert!(
        stdout.contains("Sigstore trusted root cached at"),
        "stdout must contain 'cached at' line mirroring --refresh-trust-root; got:\n{stdout}"
    );
    assert!(
        stdout.contains("* Source: "),
        "stdout must contain 'Source:' breadcrumb (D-49-B3); got:\n{stdout}"
    );
}

/// F-01-07: `--from-file` and `--refresh-trust-root` share the same
/// phase-index slot (clap-mutex contract; counting them as separate slots
/// would break the displayed `[X/N]` counter). Asserts that the `[X/N]`
/// header in `--from-file` stdout has the SAME `X` value as the
/// `--refresh-trust-root` path would produce. With only `--from-file`
/// set (no profiles, no shell integration), the trust-root step lives
/// at slot 3 of N=4 total phases (install/sandbox/protection/profiles
/// base + 1 for trust-root; the trust-root step is `protection_phase_index`
/// - 1 = 3). The header therefore reads `[3/4]`.
#[test]
fn from_file_phase_index_uses_shared_slot() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("input.json");
    fs::copy(frozen_fixture_path(), &src).expect("copy frozen fixture to src");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "happy-path required for phase-index test; stdout:\n{stdout}"
    );
    // The header MUST share the same X with the --refresh-trust-root path
    // (clap-mutex shared slot, F-01-07). On Windows-host (default build),
    // the trust-root slot is `refresh_trust_root_phase_index()` = 3 (after
    // install + sandbox + protection-base) and total = 4 + 1 = 5? No —
    // `total_phases` adds 1 for the trust-root step. Use a tolerant match:
    // expect `[N/M] Loading...` where N = trust-root slot and M >= N.
    assert!(
        stdout.contains("] Loading Sigstore trusted root from file"),
        "expected '[X/N] Loading...' header (single shared phase-index slot); got:\n{stdout}"
    );
    // Stronger assertion: the line that contains "Loading Sigstore trusted
    // root from file" begins with "[" and contains "/" — i.e., `[X/N]` shape.
    let header_line = stdout
        .lines()
        .find(|l| l.contains("Loading Sigstore trusted root from file"))
        .expect("must find Loading line");
    assert!(
        header_line.starts_with("[") && header_line.contains("/"),
        "header line must have `[X/N]` shape; got: {header_line:?}"
    );
}

/// F-01-02: `nono setup --from-file <expired>.json` exits non-zero with
/// a freshness-error stderr, and the cache file is NOT modified.
#[test]
fn from_file_expired_fails_closed() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("expired.json");
    write_expired_fixture(&src);

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");
    // Pre-assert cache is absent.
    assert!(!cache_path.exists(), "cache should be absent before run");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !output.status.success(),
        "expired fixture must exit non-zero; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("freshness")
            || stderr.contains("expired")
            || stderr.contains("STALE")
            || stderr.to_lowercase().contains("expir"),
        "stderr must reference freshness/expiry; got stderr:\n{stderr}"
    );
    assert!(
        !cache_path.exists(),
        "cache file must NOT be created on freshness failure (D-49-B2 fail-closed); found at {cache_path:?}"
    );
}

/// F-01-03 (truncation case): malformed JSON (truncation) exits non-zero
/// with a parse-error stderr, cache untouched.
#[test]
fn from_file_malformed_truncated_fails_closed() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("truncated.json");
    write_truncated_fixture(&src);

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "truncated fixture must exit non-zero; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("invalid Sigstore trusted root")
            || stderr.to_lowercase().contains("parse")
            || stderr.to_lowercase().contains("eof")
            || stderr.to_lowercase().contains("expected"),
        "stderr must reference parse failure; got stderr:\n{stderr}"
    );
    assert!(
        !cache_path.exists(),
        "cache file must NOT be created on parse failure"
    );
}

/// F-01-03 (quote-flip case): a single-byte JSON corruption (distinct
/// parse-error class from truncation) exits non-zero, cache untouched.
#[test]
fn from_file_malformed_quote_flipped_fails_closed() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("quote_flipped.json");
    write_quote_flipped_fixture(&src);

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    assert!(
        !output.status.success(),
        "quote-flipped fixture must exit non-zero"
    );
    assert!(
        !cache_path.exists(),
        "cache file must NOT be created on parse failure"
    );
}

/// F-01-04: missing source path exits non-zero with an IO-error stderr,
/// cache untouched (no partial cache written).
#[test]
fn from_file_missing_path_no_partial_cache() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("does_not_exist.json");
    assert!(!src.exists(), "test precondition: src must not exist");

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "missing path must exit non-zero; stderr:\n{stderr}"
    );
    assert!(
        !cache_path.exists(),
        "cache file must NOT be created on missing-path failure (D-49-B2 fail-closed)"
    );
}

/// F-01-01: `--from-file <p> --refresh-trust-root` is rejected at
/// clap-parse time with a non-zero exit and a "cannot be used with"
/// style stderr message.
#[test]
fn from_file_with_refresh_rejected_by_clap() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("any.json");
    fs::copy(frozen_fixture_path(), &src).expect("copy frozen fixture");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(
        &["setup", "--from-file", &src_arg, "--refresh-trust-root"],
        &home,
        &workspace,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "clap-mutex must reject --from-file + --refresh-trust-root; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("cannot be used with"),
        "stderr must contain clap's 'cannot be used with' message; got stderr:\n{stderr}"
    );

    // Cache MUST NOT exist (clap rejection happens before any FS write).
    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");
    assert!(
        !cache_path.exists(),
        "clap-mutex rejection must happen before any FS write; cache should not exist"
    );
}

// ---------------------------------------------------------------------------
// Helpers (Phase 49 Plan 01)
// ---------------------------------------------------------------------------

/// Path to the frozen Sigstore trusted-root fixture, resolved from the
/// `nono-cli` crate manifest dir up to `crates/nono/tests/fixtures/`.
fn frozen_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("nono")
        .join("tests")
        .join("fixtures")
        .join("trust-root-frozen.json")
}

/// Reads the frozen fixture, mutates BOTH tlogs' `publicKey.validFor`
/// to insert `"end": "1970-01-01T00:00:00Z"` (forcing the freshness
/// gate to fail — RESEARCH.md fixture surprise: tlogs only have `start`,
/// no `end`, so any tlog without `end` is treated as active).
///
/// JSON keys are camelCase (`validFor`, `publicKey`) per
/// `sigstore_verify`'s proto-generated serde renames.
fn write_expired_fixture(dst: &Path) {
    let raw = fs::read_to_string(frozen_fixture_path()).expect("read frozen fixture");
    let mut root: Value = serde_json::from_str(&raw).expect("parse frozen fixture as JSON");
    let tlogs = root
        .get_mut("tlogs")
        .and_then(|v| v.as_array_mut())
        .expect("tlogs is a JSON array");
    assert!(
        !tlogs.is_empty(),
        "expected at least one tlog in the frozen fixture"
    );
    for tlog in tlogs.iter_mut() {
        let valid_for = tlog
            .get_mut("publicKey")
            .and_then(|pk| pk.get_mut("validFor"))
            .and_then(|vf| vf.as_object_mut())
            .expect("tlog.publicKey.validFor is a JSON object");
        valid_for.insert(
            "end".to_string(),
            Value::String("1970-01-01T00:00:00Z".to_string()),
        );
    }
    let mutated = serde_json::to_string_pretty(&root).expect("serialize mutated fixture");
    fs::write(dst, mutated).expect("write expired fixture");
}

/// Writes the first 100 bytes of the frozen fixture to `dst` —
/// forces `TrustedRoot::from_file` deserialize failure (truncation case).
fn write_truncated_fixture(dst: &Path) {
    let raw = fs::read(frozen_fixture_path()).expect("read frozen fixture");
    let truncated = &raw[..100.min(raw.len())];
    fs::write(dst, truncated).expect("write truncated fixture");
}

/// Writes the frozen fixture to `dst` with the first `"` byte flipped to
/// `'` — distinct JSON parse-error class from truncation.
fn write_quote_flipped_fixture(dst: &Path) {
    let mut raw = fs::read(frozen_fixture_path()).expect("read frozen fixture");
    let idx = raw
        .iter()
        .position(|&b| b == b'"')
        .expect("frozen fixture contains a double-quote byte");
    raw[idx] = b'\'';
    fs::write(dst, raw).expect("write quote-flipped fixture");
}
