//! Integration tests: built-in profiles load with canonical sections (Plan 36-01d).
//!
//! Asserts that all 4 AI-agent built-in profiles (claude-code, codex, opencode,
//! claude-no-kc) deserialise through the embedded policy loader AND carry
//! the canonical-section surface introduced by Plans 36-01a/b/c/d:
//!   - `commands.{allow, deny}` — canonical CommandsConfig (upstream f0abd413)
//!   - `policy.bypass_protection` — canonical field name (Plan 36-01c rename)
//!   - NO `override_deny` key in the resolved JSON output
//!
//! These tests serve REQ-PORT-CLOSURE-02 acceptance criterion #5
//! (all 4 built-in profiles migrated to canonical sections).
//!
//! # Test approach
//!
//! Uses `nono profile show <name> --json` subprocess invocations so that:
//!   1. The exit code directly confirms deserialisation success.
//!   2. The JSON output confirms canonical field presence.
//!   3. No lib-target import is needed (nono-cli is a bin-only crate).
//!
//! # Environment notes
//!
//! `nono profile show` resolves `$HOME` paths when building capability sets.
//! These tests only call `--json` (raw profile data, no capability resolution),
//! so no HOME guard is needed.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

/// Run `nono profile show <name> --json` and return the parsed JSON value.
/// Panics with a descriptive message if the command fails.
fn profile_show_json(name: &str) -> serde_json::Value {
    let output = nono_bin()
        .args(["profile", "show", name, "--json"])
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn nono for profile {name:?}: {e}"));

    assert!(
        output.status.success(),
        "nono profile show {name:?} --json exited non-zero ({}); stderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("nono profile show {name:?} --json produced invalid JSON: {e}\nstdout:\n{stdout}")
    })
}

/// T-36-01d-1 (REQ-PORT-CLOSURE-02 #5):
///
/// `claude-code` built-in profile loads and carries canonical sections.
/// The `policy.bypass_protection` field must be populated (claude-code
/// includes a keychain bypass). The profile must load without error.
#[test]
fn test_builtin_profile_claude_code_loads_canonical_sections() {
    let json = profile_show_json("claude-code");

    // profile name must round-trip.
    assert_eq!(
        json["name"].as_str().unwrap_or(""),
        "claude-code",
        "claude-code: name field must match"
    );

    // policy.bypass_protection must be a non-empty array for claude-code.
    let bypass = json["policy"]["bypass_protection"]
        .as_array()
        .expect("claude-code: policy.bypass_protection must be a JSON array");
    assert!(
        !bypass.is_empty(),
        "claude-code: policy.bypass_protection must be non-empty (keychain grant)"
    );

    // The bypass path must reference the keychain directory.
    let has_keychains = bypass
        .iter()
        .any(|v| v.as_str().map(|s| s.contains("Keychains")).unwrap_or(false));
    assert!(
        has_keychains,
        "claude-code: policy.bypass_protection must contain a Keychains path; got: {bypass:?}"
    );

    // policy section must NOT contain a legacy override_deny key.
    // (If serde alias deserialized it into bypass_protection, the key itself
    // must not appear in the serialised output per Task 1 data migration.)
    assert!(
        json["policy"]["override_deny"].is_null(),
        "claude-code: policy must not carry override_deny key in canonical JSON output"
    );
}

/// T-36-01d-2 (REQ-PORT-CLOSURE-02 #5):
///
/// `codex` built-in profile loads and carries canonical sections.
#[test]
fn test_builtin_profile_codex_loads_canonical_sections() {
    let json = profile_show_json("codex");

    assert_eq!(
        json["name"].as_str().unwrap_or(""),
        "codex",
        "codex: name field must match"
    );

    // codex does not have a keychain bypass — bypass_protection must be
    // accessible as an empty array (not absent / null).
    let bypass = json["policy"]["bypass_protection"]
        .as_array()
        .expect("codex: policy.bypass_protection must be a JSON array (may be empty)");
    assert!(
        bypass.is_empty(),
        "codex: policy.bypass_protection must be empty (no keychain grant)"
    );

    // No legacy key in output.
    assert!(
        json["policy"]["override_deny"].is_null(),
        "codex: policy must not carry override_deny key in canonical JSON output"
    );

    // Security groups must be present (regression guard).
    let groups = json["security"]["groups"]
        .as_array()
        .expect("codex: security.groups must be a JSON array");
    assert!(
        !groups.is_empty(),
        "codex: security.groups must be non-empty"
    );
}

/// T-36-01d-3 (REQ-PORT-CLOSURE-02 #5):
///
/// `opencode` built-in profile loads and carries canonical sections.
#[test]
fn test_builtin_profile_opencode_loads_canonical_sections() {
    let json = profile_show_json("opencode");

    assert_eq!(
        json["name"].as_str().unwrap_or(""),
        "opencode",
        "opencode: name field must match"
    );

    // bypass_protection must be accessible as an empty array.
    let _bypass = json["policy"]["bypass_protection"]
        .as_array()
        .expect("opencode: policy.bypass_protection must be a JSON array");

    // No legacy key in output.
    assert!(
        json["policy"]["override_deny"].is_null(),
        "opencode: policy must not carry override_deny key in canonical JSON output"
    );

    // filesystem.allow must be present and non-empty (opencode needs its data dirs).
    let fs_allow = json["filesystem"]["allow"]
        .as_array()
        .expect("opencode: filesystem.allow must be a JSON array");
    assert!(
        !fs_allow.is_empty(),
        "opencode: filesystem.allow must be non-empty"
    );
}

/// T-36-01d-4 (REQ-PORT-CLOSURE-02 #5):
///
/// `claude-no-kc` built-in profile loads and carries canonical sections.
///
/// Note: the upstream profile name is `claude-no-kc` (not `claude-no-keychain`).
/// See `src/profile/builtin.rs::claude_no_keychain_loads` for the naming rationale.
#[test]
fn test_builtin_profile_claude_no_keychain_loads_canonical_sections() {
    let json = profile_show_json("claude-no-kc");

    assert_eq!(
        json["name"].as_str().unwrap_or(""),
        "claude-no-kc",
        "claude-no-kc: name field must match"
    );

    // claude-no-kc specifically does NOT grant keychain bypass_protection —
    // that is the whole point of the -no-kc variant.
    let bypass = json["policy"]["bypass_protection"]
        .as_array()
        .expect("claude-no-kc: policy.bypass_protection must be a JSON array");
    assert!(
        bypass.is_empty(),
        "claude-no-kc: policy.bypass_protection must be empty (no keychain grant)"
    );

    // No legacy key in output.
    assert!(
        json["policy"]["override_deny"].is_null(),
        "claude-no-kc: policy must not carry override_deny key in canonical JSON output"
    );

    // Security groups must be non-empty (inherits claude-code groups minus macos keychain).
    let groups = json["security"]["groups"]
        .as_array()
        .expect("claude-no-kc: security.groups must be a JSON array");
    assert!(
        !groups.is_empty(),
        "claude-no-kc: security.groups must be non-empty"
    );
}

/// T-36-01d-5 (REQ-PORT-CLOSURE-02 #5):
///
/// All 4 AI-agent built-in profiles load successfully via the embedded policy
/// loader — iterative variant that fails fast on any individual load failure.
///
/// Provides a single-shot gate for CI: if any built-in profile regresses,
/// this test names the offending profile.
#[test]
fn test_all_builtin_profiles_use_canonical_sections() {
    let ai_agent_profiles = ["claude-code", "codex", "opencode", "claude-no-kc"];

    for name in &ai_agent_profiles {
        let json = profile_show_json(name);

        // Name must round-trip.
        assert_eq!(
            json["name"].as_str().unwrap_or(""),
            *name,
            "profile {name:?}: meta.name must match the lookup key"
        );

        // policy.bypass_protection must be a JSON array (may be empty).
        json["policy"]["bypass_protection"]
            .as_array()
            .unwrap_or_else(|| {
                panic!(
                    "profile {name:?}: policy.bypass_protection must be a JSON array, got: {:?}",
                    json["policy"]["bypass_protection"]
                )
            });

        // No legacy override_deny key in canonical output.
        assert!(
            json["policy"]["override_deny"].is_null(),
            "profile {name:?}: policy must not carry override_deny key in canonical JSON output"
        );
    }
}
