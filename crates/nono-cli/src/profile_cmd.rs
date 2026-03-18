//! Profile authoring subcommand implementations
//!
//! Handles `nono profile init|schema|guide` for creating and managing
//! nono profiles with scaffolding, schema, and guidance.

use crate::cli::{
    ProfileCmdArgs, ProfileCommands, ProfileGuideArgs, ProfileInitArgs, ProfileSchemaArgs,
};
use crate::config::embedded;
use crate::policy;
use crate::profile;
use crate::theme;
use colored::Colorize;
use nono::{NonoError, Result};
use std::fs;
use std::io::Write;

/// Prefix used for all profile command output
fn prefix() -> colored::ColoredString {
    let t = theme::current();
    theme::fg("nono profile", t.brand).bold()
}

/// Dispatch to the appropriate profile subcommand.
pub fn run_profile(args: ProfileCmdArgs) -> Result<()> {
    match args.command {
        ProfileCommands::Init(args) => cmd_init(args),
        ProfileCommands::Schema(args) => cmd_schema(args),
        ProfileCommands::Guide(args) => cmd_guide(args),
    }
}

// ---------------------------------------------------------------------------
// nono profile init
// ---------------------------------------------------------------------------

fn cmd_init(args: ProfileInitArgs) -> Result<()> {
    // Validate profile name
    if !profile::is_valid_profile_name(&args.name) {
        return Err(NonoError::ProfileParse(format!(
            "Invalid profile name '{}': must be alphanumeric with hyphens, no leading/trailing hyphens",
            args.name
        )));
    }

    // Determine output path
    let output_path = match &args.output {
        Some(path) => path.clone(),
        None => profile::get_user_profile_path(&args.name)?,
    };

    // Check for existing file
    if output_path.exists() && !args.force {
        return Err(NonoError::ProfileParse(format!(
            "Profile file already exists: {}\nUse --force to overwrite",
            output_path.display()
        )));
    }

    // Validate --extends target exists
    if let Some(ref base) = args.extends {
        if !profile_exists(base) {
            return Err(NonoError::ProfileParse(format!(
                "Base profile '{}' not found (built-in or user profile)",
                base
            )));
        }
    }

    // Validate --groups against embedded policy
    if !args.groups.is_empty() {
        let pol = policy::load_embedded_policy()?;
        for group in &args.groups {
            if !pol.groups.contains_key(group.as_str()) {
                return Err(NonoError::ProfileParse(format!(
                    "Unknown security group '{}'. Use `nono policy groups` to list available groups",
                    group
                )));
            }
        }
    }

    // Build skeleton JSON
    let skeleton = build_skeleton(&args);

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            NonoError::ProfileParse(format!(
                "Failed to create directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    // Write file
    let json = serde_json::to_string_pretty(&skeleton)
        .map_err(|e| NonoError::ProfileParse(format!("JSON serialization failed: {e}")))?;

    fs::write(&output_path, format!("{json}\n")).map_err(|e| {
        NonoError::ProfileParse(format!(
            "Failed to write profile to {}: {}",
            output_path.display(),
            e
        ))
    })?;

    eprintln!(
        "{} Created profile at {}",
        prefix(),
        output_path.display().to_string().bold()
    );
    eprintln!(
        "{} Validate with: nono policy validate {}",
        prefix(),
        output_path.display()
    );
    eprintln!(
        "{} For editor autocomplete: nono profile schema -o nono-profile.schema.json",
        prefix()
    );

    Ok(())
}

/// Build a skeleton profile JSON value with controlled field ordering.
fn build_skeleton(args: &ProfileInitArgs) -> serde_json::Value {
    let mut root = serde_json::Map::new();

    if let Some(ref base) = args.extends {
        root.insert(
            "extends".to_string(),
            serde_json::Value::String(base.clone()),
        );
    }

    // meta
    let mut meta = serde_json::Map::new();
    meta.insert(
        "name".to_string(),
        serde_json::Value::String(args.name.clone()),
    );
    if let Some(ref desc) = args.description {
        meta.insert(
            "description".to_string(),
            serde_json::Value::String(desc.clone()),
        );
    }
    root.insert("meta".to_string(), serde_json::Value::Object(meta));

    // security
    let mut security = serde_json::Map::new();
    let groups: Vec<serde_json::Value> = args
        .groups
        .iter()
        .map(|g| serde_json::Value::String(g.clone()))
        .collect();
    security.insert("groups".to_string(), serde_json::Value::Array(groups));
    root.insert("security".to_string(), serde_json::Value::Object(security));

    // workdir
    let mut workdir = serde_json::Map::new();
    workdir.insert(
        "access".to_string(),
        serde_json::Value::String("readwrite".to_string()),
    );
    root.insert("workdir".to_string(), serde_json::Value::Object(workdir));

    // filesystem (minimal has allow + read; full adds all fields)
    let mut filesystem = serde_json::Map::new();
    filesystem.insert("allow".to_string(), serde_json::Value::Array(vec![]));
    filesystem.insert("read".to_string(), serde_json::Value::Array(vec![]));
    if args.full {
        filesystem.insert("write".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("allow_file".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("read_file".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("write_file".to_string(), serde_json::Value::Array(vec![]));
    }
    root.insert(
        "filesystem".to_string(),
        serde_json::Value::Object(filesystem),
    );

    // Full skeleton adds additional sections
    if args.full {
        // policy
        let mut pol = serde_json::Map::new();
        pol.insert(
            "exclude_groups".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_allow_read".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_allow_write".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_allow_readwrite".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_deny_access".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "override_deny".to_string(),
            serde_json::Value::Array(vec![]),
        );
        root.insert("policy".to_string(), serde_json::Value::Object(pol));

        // network
        // NOTE: network_profile is intentionally omitted. Emitting null would
        // clear an inherited proxy profile (e.g., "developer" from python-dev),
        // silently broadening network access. Absent = inherit from base.
        let mut network = serde_json::Map::new();
        network.insert("block".to_string(), serde_json::Value::Bool(false));
        network.insert("proxy_allow".to_string(), serde_json::Value::Array(vec![]));
        network.insert(
            "proxy_credentials".to_string(),
            serde_json::Value::Array(vec![]),
        );
        network.insert("port_allow".to_string(), serde_json::Value::Array(vec![]));
        network.insert(
            "custom_credentials".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
        root.insert("network".to_string(), serde_json::Value::Object(network));

        // env_credentials
        root.insert(
            "env_credentials".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );

        // hooks
        root.insert(
            "hooks".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );

        // rollback
        let mut rollback = serde_json::Map::new();
        rollback.insert(
            "exclude_patterns".to_string(),
            serde_json::Value::Array(vec![]),
        );
        rollback.insert(
            "exclude_globs".to_string(),
            serde_json::Value::Array(vec![]),
        );
        root.insert("rollback".to_string(), serde_json::Value::Object(rollback));

        // NOTE: open_urls and allow_launch_services are intentionally omitted.
        // Emitting them would replace inherited values from base profiles like
        // claude-code (which grants OAuth2 origins and launch services).
        // Absent = inherit from base. Authors who need to override these
        // should add them explicitly.
    }

    serde_json::Value::Object(root)
}

/// Check if a profile exists (built-in or user).
fn profile_exists(name: &str) -> bool {
    // Check built-in profiles
    if profile::builtin::get_builtin(name).is_some() {
        return true;
    }
    // Check user profiles
    if let Ok(path) = profile::get_user_profile_path(name) {
        return path.exists();
    }
    false
}

// ---------------------------------------------------------------------------
// nono profile schema
// ---------------------------------------------------------------------------

fn cmd_schema(args: ProfileSchemaArgs) -> Result<()> {
    let schema = embedded::embedded_profile_schema();

    match args.output {
        Some(path) => {
            fs::write(&path, schema).map_err(|e| {
                NonoError::ProfileParse(format!(
                    "Failed to write schema to {}: {}",
                    path.display(),
                    e
                ))
            })?;
            eprintln!(
                "{} Schema written to {}",
                prefix(),
                path.display().to_string().bold()
            );
        }
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(schema.as_bytes())
                .map_err(|e| NonoError::ProfileParse(format!("Failed to write to stdout: {e}")))?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono profile guide
// ---------------------------------------------------------------------------

fn cmd_guide(_args: ProfileGuideArgs) -> Result<()> {
    let guide = embedded::embedded_profile_guide();
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(guide.as_bytes())
        .map_err(|e| NonoError::ProfileParse(format!("Failed to write to stdout: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use std::path::PathBuf;

    #[test]
    fn test_minimal_skeleton_is_valid_profile() {
        let args = ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");
        let profile: Profile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile.meta.name, "test-profile");
    }

    #[test]
    fn test_full_skeleton_is_valid_profile() {
        let args = ProfileInitArgs {
            name: "full-test".to_string(),
            extends: Some("default".to_string()),
            groups: vec![],
            description: Some("A full test profile".to_string()),
            full: true,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");
        let profile: Profile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile.meta.name, "full-test");
        assert_eq!(profile.extends, Some(vec!["default".to_string()]));
        assert_eq!(
            profile.meta.description,
            Some("A full test profile".to_string())
        );
    }

    #[test]
    fn test_skeleton_with_groups() {
        let args = ProfileInitArgs {
            name: "grouped".to_string(),
            extends: None,
            groups: vec!["deny_credentials".to_string()],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let groups = skeleton["security"]["groups"].as_array().expect("array");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], "deny_credentials");
    }

    #[test]
    fn test_skeleton_omits_schema_url() {
        let args = ProfileInitArgs {
            name: "schema-test".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        // $schema is not emitted because the URL is not hosted;
        // users export the schema locally via `nono profile schema`
        assert!(skeleton.get("$schema").is_none());
    }

    #[test]
    fn test_invalid_profile_name() {
        let result = cmd_init(ProfileInitArgs {
            name: "-bad-name-".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-bad.json")),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("Invalid profile name"));
    }

    #[test]
    fn test_invalid_group_name() {
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec!["nonexistent_group_xyz".to_string()],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-badgroup.json")),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("Unknown security group"));
    }

    #[test]
    fn test_invalid_extends_target() {
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: Some("nonexistent-base-profile-xyz".to_string()),
            groups: vec![],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-badextends.json")),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_force_overwrite() {
        use std::io::Write;

        let tmp = std::env::temp_dir().join("nono-test-force-overwrite.json");
        // Create existing file
        let mut f = fs::File::create(&tmp).expect("create");
        f.write_all(b"{}").expect("write");
        drop(f);

        // Without force: should fail
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(tmp.clone()),
            force: false,
        });
        assert!(result.is_err());

        // With force: should succeed
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(tmp.clone()),
            force: true,
        });
        assert!(result.is_ok());

        // Verify file was written with correct content
        let content = fs::read_to_string(&tmp).expect("read");
        let profile: Profile = serde_json::from_str(&content).expect("parse");
        assert_eq!(profile.meta.name, "test-profile");

        // Cleanup
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_full_vs_minimal_differences() {
        let minimal_args = ProfileInitArgs {
            name: "minimal".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let full_args = ProfileInitArgs {
            name: "full".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: true,
            output: None,
            force: false,
        };
        let minimal = build_skeleton(&minimal_args);
        let full = build_skeleton(&full_args);

        let minimal_obj = minimal.as_object().expect("object");
        let full_obj = full.as_object().expect("object");

        // Full has more keys than minimal
        assert!(full_obj.len() > minimal_obj.len());

        // Full has sections that minimal does not
        assert!(full_obj.contains_key("policy"));
        assert!(full_obj.contains_key("network"));
        assert!(full_obj.contains_key("env_credentials"));
        assert!(full_obj.contains_key("hooks"));
        assert!(full_obj.contains_key("rollback"));

        // open_urls and allow_launch_services are intentionally omitted
        // to avoid silently overriding inherited values from base profiles
        assert!(!full_obj.contains_key("open_urls"));
        assert!(!full_obj.contains_key("allow_launch_services"));

        assert!(!minimal_obj.contains_key("policy"));
        assert!(!minimal_obj.contains_key("network"));
        assert!(!minimal_obj.contains_key("hooks"));

        // Full filesystem has all fields
        let full_fs = full_obj["filesystem"].as_object().expect("fs object");
        assert!(full_fs.contains_key("write"));
        assert!(full_fs.contains_key("allow_file"));
        assert!(full_fs.contains_key("read_file"));
        assert!(full_fs.contains_key("write_file"));

        // Minimal filesystem has only allow + read
        let min_fs = minimal_obj["filesystem"].as_object().expect("fs object");
        assert!(!min_fs.contains_key("write"));
        assert!(!min_fs.contains_key("allow_file"));

        // Full policy has add_deny_access
        let full_pol = full_obj["policy"].as_object().expect("policy object");
        assert!(full_pol.contains_key("add_deny_access"));

        // Full network has all fields
        let full_net = full_obj["network"].as_object().expect("network object");
        assert!(full_net.contains_key("proxy_allow"));
        assert!(full_net.contains_key("proxy_credentials"));
        assert!(full_net.contains_key("port_allow"));
        assert!(full_net.contains_key("custom_credentials"));
    }
}
