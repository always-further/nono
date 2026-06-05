//! Snapshot tests for the checked-in JSON profile schema.
//!
//! These tests assert the canonical shape of
//! `crates/nono-cli/data/nono-profile.schema.json` after issue #594
//! phase 2 restructuring. Any future accidental reintroduction of the
//! legacy patch namespace or legacy security subkeys will fail here.

use serde_json::Value;

fn load_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("nono-profile.schema.json");
    let content = std::fs::read_to_string(&path).expect("read embedded profile schema");
    serde_json::from_str(&content).expect("embedded profile schema is valid JSON")
}

#[test]
fn test_schema_has_canonical_top_level_groups() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/groups").is_some(),
        "schema is missing canonical /properties/groups"
    );
}

#[test]
fn test_schema_has_canonical_top_level_commands() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/commands").is_some(),
        "schema is missing canonical /properties/commands"
    );
}

#[test]
fn test_schema_has_linux_af_unix_mediation() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/linux").is_some(),
        "schema is missing canonical /properties/linux"
    );
    let props = schema
        .pointer("/$defs/LinuxConfig/properties")
        .and_then(Value::as_object)
        .expect("LinuxConfig.properties is an object");
    assert!(
        props.contains_key("af_unix_mediation"),
        "LinuxConfig.af_unix_mediation missing from canonical schema"
    );
}

#[test]
fn test_schema_groups_has_include_and_exclude() {
    let schema = load_schema();
    let props = schema
        .pointer("/$defs/GroupsConfig/properties")
        .and_then(Value::as_object)
        .expect("GroupsConfig.properties is an object");
    assert!(
        props.contains_key("include"),
        "GroupsConfig.include missing"
    );
    assert!(
        props.contains_key("exclude"),
        "GroupsConfig.exclude missing"
    );
}

#[test]
fn test_schema_commands_has_allow_and_deny() {
    let schema = load_schema();
    let props = schema
        .pointer("/$defs/CommandsConfig/properties")
        .and_then(Value::as_object)
        .expect("CommandsConfig.properties is an object");
    assert!(props.contains_key("allow"), "CommandsConfig.allow missing");
    assert!(props.contains_key("deny"), "CommandsConfig.deny missing");
}

#[test]
fn test_schema_filesystem_has_deny_and_bypass_protection() {
    let schema = load_schema();
    let props = schema
        .pointer("/$defs/FilesystemConfig/properties")
        .and_then(Value::as_object)
        .expect("FilesystemConfig.properties is an object");
    assert!(
        props.contains_key("deny"),
        "FilesystemConfig.deny missing from canonical schema"
    );
    assert!(
        props.contains_key("bypass_protection"),
        "FilesystemConfig.bypass_protection missing from canonical schema"
    );
    assert!(
        props.contains_key("suppress_save_prompt"),
        "FilesystemConfig.suppress_save_prompt missing from canonical schema"
    );
}

#[test]
fn test_schema_does_not_advertise_legacy_policy_namespace() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/policy").is_none(),
        "schema still advertises legacy /properties/policy; it must be removed per issue #594 phase 2"
    );
    assert!(
        schema.pointer("/$defs/PolicyPatchConfig").is_none(),
        "schema still carries the legacy /$defs/PolicyPatchConfig definition; it must be removed per issue #594 phase 2"
    );
}

#[test]
fn test_schema_has_session_hooks_property_and_defs() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/session_hooks").is_some(),
        "schema is missing canonical /properties/session_hooks"
    );

    let hooks_props = schema
        .pointer("/$defs/SessionHooks/properties")
        .and_then(Value::as_object)
        .expect("SessionHooks.properties is an object");
    assert!(
        hooks_props.contains_key("before"),
        "SessionHooks.before missing"
    );
    assert!(
        hooks_props.contains_key("after"),
        "SessionHooks.after missing"
    );

    let hook_props = schema
        .pointer("/$defs/SessionHook/properties")
        .and_then(Value::as_object)
        .expect("SessionHook.properties is an object");
    assert!(
        hook_props.contains_key("script"),
        "SessionHook.script missing"
    );
    assert!(
        hook_props.contains_key("timeout_secs"),
        "SessionHook.timeout_secs missing"
    );

    // Both objects must reject unknown fields to match the Rust struct's
    // #[serde(deny_unknown_fields)] guarantee.
    assert_eq!(
        schema.pointer("/$defs/SessionHooks/additionalProperties"),
        Some(&Value::Bool(false)),
        "SessionHooks must set additionalProperties: false"
    );
    assert_eq!(
        schema.pointer("/$defs/SessionHook/additionalProperties"),
        Some(&Value::Bool(false)),
        "SessionHook must set additionalProperties: false"
    );
}

#[test]
fn test_schema_security_has_no_legacy_groups_or_allowed_commands() {
    let schema = load_schema();
    let props = schema
        .pointer("/$defs/SecurityConfig/properties")
        .and_then(Value::as_object)
        .expect("SecurityConfig.properties is an object");
    assert!(
        !props.contains_key("groups"),
        "SecurityConfig.groups still present; canonical location is top-level /properties/groups"
    );
    assert!(
        !props.contains_key("allowed_commands"),
        "SecurityConfig.allowed_commands still present; canonical location is top-level /properties/commands"
    );
}
