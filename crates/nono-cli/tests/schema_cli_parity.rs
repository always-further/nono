//! Parity check: every policy field on `Profile` (transitively)
//! must be categorized in `mapping_table()` as flag-backed, deprecated, or
//! deliberately profile-only. New fields with no entry fail CI.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

/// Categorize a new `Profile` field by adding a `mapping_table()` entry:
/// `Flag("<long-name>")` if backed by a CLI flag, `ProfileOnly("reason")`
/// if deliberately profile-only, `Deprecated("reason")` if a back-compat
/// alias. The reason strings are documentation for reviewers, not used
/// programmatically.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum Category {
    /// Long-flag name, without leading `--`.
    Flag(&'static str),
    Deprecated(&'static str),
    ProfileOnly(&'static str),
    NestedRecurse,
}

#[allow(clippy::type_complexity)]
fn mapping_table() -> Vec<(&'static str, &'static str, Category)> {
    use Category::*;
    vec![
        (
            "Profile",
            "extends",
            ProfileOnly("profile inheritance is structural; set at authoring time, not per-run"),
        ),
        (
            "Profile",
            "meta",
            ProfileOnly(
                "profile metadata block (name/version/description/author); not a runtime knob",
            ),
        ),
        ("Profile", "security", NestedRecurse),
        ("Profile", "groups", NestedRecurse),
        ("Profile", "commands", NestedRecurse),
        ("Profile", "filesystem", NestedRecurse),
        ("Profile", "network", NestedRecurse),
        ("Profile", "diagnostics", NestedRecurse),
        ("Profile", "linux", NestedRecurse),
        ("Profile", "env_credentials", Flag("env-credential")),
        ("Profile", "environment", NestedRecurse),
        ("Profile", "workdir", NestedRecurse),
        (
            "Profile",
            "hooks",
            ProfileOnly(
                "event-driven application hooks; profile-authored multi-key map, not a flag",
            ),
        ),
        (
            "Profile",
            "session_hooks",
            ProfileOnly("lifecycle hooks run with host privileges; profile-only by design"),
        ),
        ("Profile", "rollback", NestedRecurse),
        ("Profile", "open_urls", NestedRecurse),
        (
            "Profile",
            "allow_launch_services",
            Flag("allow-launch-services"),
        ),
        ("Profile", "allow_gpu", Flag("allow-gpu")),
        (
            "Profile",
            "allow_parent_of_protected",
            ProfileOnly("opt-in macOS-only escape hatch; deliberately not exposed as a flag"),
        ),
        (
            "Profile",
            "interactive",
            Deprecated(
                "parsed for backward compatibility but ignored; supervised mode preserves TTY by default",
            ),
        ),
        ("Profile", "skipdirs", Flag("skip-dir")),
        (
            "Profile",
            "packs",
            ProfileOnly(
                "pack dependencies are part of the profile contract, not per-run overrides",
            ),
        ),
        (
            "Profile",
            "binary",
            ProfileOnly("default binary fallback when no `-- <cmd>` is given; profile-authored"),
        ),
        (
            "Profile",
            "command_args",
            ProfileOnly("default args appended to the child command; profile-authored, not a flag"),
        ),
        (
            "Profile",
            "unsafe_macos_seatbelt_rules",
            ProfileOnly("deliberately unsafe expert escape hatch; profile-only by design"),
        ),
        (
            "SecurityConfig",
            "signal_mode",
            ProfileOnly("isolation mode selection; backsweep candidate (#1027 PR 2)"),
        ),
        (
            "SecurityConfig",
            "process_info_mode",
            ProfileOnly("isolation mode selection; backsweep candidate (#1027 PR 2)"),
        ),
        (
            "SecurityConfig",
            "ipc_mode",
            ProfileOnly("isolation mode selection; backsweep candidate (#1027 PR 2)"),
        ),
        (
            "SecurityConfig",
            "capability_elevation",
            Flag("capability-elevation"),
        ),
        (
            "SecurityConfig",
            "wsl2_proxy_policy",
            ProfileOnly("WSL2-specific fallback knob; backsweep candidate (#1027 PR 2)"),
        ),
        (
            "GroupsConfig",
            "include",
            ProfileOnly(
                "policy group composition is part of the profile contract, not a runtime override",
            ),
        ),
        (
            "GroupsConfig",
            "exclude",
            ProfileOnly(
                "policy group composition is part of the profile contract, not a runtime override",
            ),
        ),
        (
            "CommandsConfig",
            "allow",
            Deprecated("v0.33.0 startup-only allow list; --allow-command kept for compat"),
        ),
        (
            "CommandsConfig",
            "deny",
            Deprecated("v0.33.0 startup-only deny list; --block-command kept for compat"),
        ),
        ("FilesystemConfig", "allow", Flag("allow")),
        ("FilesystemConfig", "read", Flag("read")),
        ("FilesystemConfig", "write", Flag("write")),
        ("FilesystemConfig", "allow_file", Flag("allow-file")),
        ("FilesystemConfig", "read_file", Flag("read-file")),
        ("FilesystemConfig", "write_file", Flag("write-file")),
        ("FilesystemConfig", "unix_socket", Flag("allow-unix-socket")),
        (
            "FilesystemConfig",
            "unix_socket_bind",
            Flag("allow-unix-socket-bind"),
        ),
        (
            "FilesystemConfig",
            "unix_socket_dir",
            Flag("allow-unix-socket-dir"),
        ),
        (
            "FilesystemConfig",
            "unix_socket_dir_bind",
            Flag("allow-unix-socket-dir-bind"),
        ),
        (
            "FilesystemConfig",
            "unix_socket_subtree",
            Flag("allow-unix-socket-subtree"),
        ),
        (
            "FilesystemConfig",
            "unix_socket_subtree_bind",
            Flag("allow-unix-socket-subtree-bind"),
        ),
        (
            "FilesystemConfig",
            "deny",
            ProfileOnly(
                "deny rules are policy-level; per-run extensions go through bypass_protection instead",
            ),
        ),
        (
            "FilesystemConfig",
            "bypass_protection",
            Flag("bypass-protection"),
        ),
        (
            "FilesystemConfig",
            "suppress_save_prompt",
            Flag("suppress-save-prompt"),
        ),
        ("NetworkConfig", "block", Flag("block-net")),
        ("NetworkConfig", "network_profile", Flag("network-profile")),
        ("NetworkConfig", "allow_domain", Flag("allow-domain")),
        ("NetworkConfig", "credentials", Flag("credential")),
        ("NetworkConfig", "open_port", Flag("open-port")),
        ("NetworkConfig", "listen_port", Flag("listen-port")),
        ("NetworkConfig", "connect_port", Flag("allow-connect-port")),
        (
            "NetworkConfig",
            "custom_credentials",
            ProfileOnly(
                "custom credential service definitions are complex per-service maps; profile-only",
            ),
        ),
        ("NetworkConfig", "upstream_proxy", Flag("upstream-proxy")),
        ("NetworkConfig", "upstream_bypass", Flag("upstream-bypass")),
        (
            "DiagnosticsConfig",
            "suppress_system_services",
            ProfileOnly("diagnostic UX filter; not enforcement, profile-only by design"),
        ),
        (
            "LinuxConfig",
            "af_unix_mediation",
            ProfileOnly("opt-in Linux pathname AF_UNIX mediation mode; profile-only by design"),
        ),
        ("WorkdirConfig", "access", Flag("allow-cwd")),
        (
            "RollbackConfig",
            "exclude_patterns",
            Flag("rollback-exclude"),
        ),
        (
            "RollbackConfig",
            "exclude_globs",
            ProfileOnly("glob excludes are profile-only today; backsweep candidate (#1027 PR 2)"),
        ),
        (
            "EnvironmentConfig",
            "allow_vars",
            ProfileOnly("env var allow-list; backsweep candidate (#1027 PR 2)"),
        ),
        (
            "EnvironmentConfig",
            "deny_vars",
            ProfileOnly("env var deny-list; backsweep candidate (#1027 PR 2)"),
        ),
        (
            "OpenUrlConfig",
            "allow_origins",
            ProfileOnly("URL origin allowlist for OAuth flows; profile-authored"),
        ),
        (
            "OpenUrlConfig",
            "allow_localhost",
            ProfileOnly("OAuth localhost callback toggle; profile-authored"),
        ),
        (
            "ProfileMeta",
            "name",
            ProfileOnly("profile metadata, not policy enforcement"),
        ),
        (
            "ProfileMeta",
            "version",
            ProfileOnly("profile metadata, not policy enforcement"),
        ),
        (
            "ProfileMeta",
            "description",
            ProfileOnly("profile metadata, not policy enforcement"),
        ),
        (
            "ProfileMeta",
            "author",
            ProfileOnly("profile metadata, not policy enforcement"),
        ),
    ]
}

/// Structs the BFS treats as leaves: no fixed field set (`#[serde(flatten)]`
/// over a HashMap) or already covered by their parent's mapping entry.
fn opaque_structs() -> &'static [&'static str] {
    &[
        "HooksConfig",         // serde(flatten) HashMap<String, HookConfig>
        "HookConfig",          // per-application hook spec; profile-authored
        "SessionHooks",        // before/after session hooks; profile-authored
        "SessionHook",         // single hook spec; profile-authored
        "SecretsConfig",       // serde(flatten) HashMap<String, String>
        "ProfileDeserialize",  // private deserialization helper
        "CustomCredentialDef", // per-service credential def; profile-only via custom_credentials map
    ]
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or(manifest_dir)
}

fn profile_source() -> String {
    let path = workspace_root()
        .join("crates")
        .join("nono-cli")
        .join("src")
        .join("profile")
        .join("mod.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

#[derive(Debug)]
struct FieldInfo {
    name: String,
    /// Identifiers from the field's type expression. Filtered downstream
    /// against parsed struct names - stdlib generics, enums, primitives,
    /// and types from other crates fall through as leaves.
    type_idents: Vec<String>,
}

/// Parse `profile/mod.rs` as the source of truth for the policy surface.
/// We don't use `nono-profile.schema.json` because it's hand-maintained and
/// drifts (e.g. `connect_port` exists in the struct but not the schema -
/// itself a #1027-class drift). `syn` understands multi-line types, raw
/// idents, attributes, etc. - anything `cargo check` accepts.
fn parse_struct_fields(source: &str) -> BTreeMap<String, Vec<FieldInfo>> {
    let file: syn::File = syn::parse_file(source).expect("failed to parse profile/mod.rs as Rust");
    let mut out: BTreeMap<String, Vec<FieldInfo>> = BTreeMap::new();
    for item in &file.items {
        let syn::Item::Struct(item_struct) = item else {
            continue;
        };
        if !matches!(item_struct.vis, syn::Visibility::Public(_)) {
            continue;
        }
        let syn::Fields::Named(named) = &item_struct.fields else {
            continue;
        };
        let struct_name = item_struct.ident.to_string();
        let mut fields: Vec<FieldInfo> = Vec::new();
        for field in &named.named {
            let Some(ident) = &field.ident else { continue };
            if !matches!(field.vis, syn::Visibility::Public(_)) {
                continue;
            }
            let mut idents = Vec::new();
            collect_type_idents(&field.ty, &mut idents);
            fields.push(FieldInfo {
                name: ident.to_string(),
                type_idents: idents,
            });
        }
        out.insert(struct_name, fields);
    }
    out
}

fn collect_type_idents(ty: &syn::Type, out: &mut Vec<String>) {
    match ty {
        syn::Type::Path(type_path) => {
            for segment in &type_path.path.segments {
                out.push(segment.ident.to_string());
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    for arg in &args.args {
                        if let syn::GenericArgument::Type(inner) = arg {
                            collect_type_idents(inner, out);
                        }
                    }
                }
            }
        }
        syn::Type::Reference(r) => collect_type_idents(&r.elem, out),
        syn::Type::Array(a) => collect_type_idents(&a.elem, out),
        syn::Type::Slice(s) => collect_type_idents(&s.elem, out),
        syn::Type::Tuple(t) => {
            for elem in &t.elems {
                collect_type_idents(elem, out);
            }
        }
        syn::Type::Group(g) => collect_type_idents(&g.elem, out),
        syn::Type::Paren(p) => collect_type_idents(&p.elem, out),
        _ => {}
    }
}

/// Scrape `--flag` long forms out of `nono run --help`. We shell out because
/// `nono-cli` is `[[bin]]`-only - no library target - so tests can't import
/// `Cli` to enumerate flags directly.
fn parse_cli_flags() -> BTreeSet<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_nono"))
        .args(["run", "--help"])
        .output()
        .expect("failed to invoke `nono run --help`");
    assert!(
        output.status.success(),
        "`nono run --help` exited non-zero: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8_lossy(&output.stdout);

    let mut flags = BTreeSet::new();
    for line in help.lines() {
        let mut rest = line;
        while let Some(idx) = rest.find("--") {
            // Only count `--` preceded by start-of-line or a separator -
            // skips matches inside descriptive text like ALIAS(canonical="--foo")
            // and (default: --foo).
            let before_ok = idx == 0
                || matches!(
                    line.as_bytes().get(idx.wrapping_sub(1)),
                    Some(b' ') | Some(b',') | Some(b'\t')
                );
            let after = &rest[idx + 2..];
            if !before_ok {
                rest = after;
                continue;
            }
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !name.is_empty() {
                flags.insert(name);
            }
            rest = after;
        }
    }
    flags
}

#[test]
fn schema_fields_are_categorized() {
    let source = profile_source();
    let parsed = parse_struct_fields(&source);
    let table = mapping_table();
    let opaque: BTreeSet<&str> = opaque_structs().iter().copied().collect();

    let known_structs: BTreeSet<&str> = parsed.keys().map(String::as_str).collect();
    let mut reachable: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = vec!["Profile".to_string()];
    while let Some(s) = queue.pop() {
        if !reachable.insert(s.clone()) {
            continue;
        }
        if opaque.contains(s.as_str()) {
            continue;
        }
        let Some(fields) = parsed.get(&s) else {
            continue;
        };
        for f in fields {
            for ident in &f.type_idents {
                if known_structs.contains(ident.as_str()) && !reachable.contains(ident) {
                    queue.push(ident.clone());
                }
            }
        }
    }
    assert!(
        reachable.contains("Profile"),
        "Profile struct not found in {}/crates/nono-cli/src/profile/mod.rs - \
         did the file move or the parser break?",
        workspace_root().display()
    );

    let mut schema_fields: BTreeSet<(String, String)> = BTreeSet::new();
    for struct_name in &reachable {
        if opaque.contains(struct_name.as_str()) {
            continue;
        }
        let Some(fields) = parsed.get(struct_name) else {
            continue;
        };
        for f in fields {
            schema_fields.insert((struct_name.clone(), f.name.clone()));
        }
    }

    let mut errors: Vec<String> = Vec::new();

    let mut table_keys: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (s, f, _) in &table {
        *table_keys
            .entry((s.to_string(), f.to_string()))
            .or_insert(0) += 1;
    }
    for (key, count) in &table_keys {
        if *count > 1 {
            errors.push(format!(
                "duplicate mapping entry: {}.{} appears {} times",
                key.0, key.1, count
            ));
        }
        if !schema_fields.contains(key) {
            errors.push(format!(
                "stale mapping entry: {}.{} is in the parity table but not in \
                 crates/nono-cli/src/profile/mod.rs (struct removed, field \
                 renamed, or struct now in opaque_structs?)",
                key.0, key.1
            ));
        }
    }

    for (struct_name, field_name) in &schema_fields {
        if !table_keys.contains_key(&(struct_name.clone(), field_name.clone())) {
            errors.push(format!(
                "uncategorized policy field: {struct_name}.{field_name} - \
                 add a Flag/Deprecated/ProfileOnly entry to mapping_table() \
                 in crates/nono-cli/tests/schema_cli_parity.rs (issue #1027)"
            ));
        }
    }

    if !errors.is_empty() {
        let n = errors.len();
        panic!(
            "schema↔CLI parity check failed ({} error{}):\n  - {}\n\nSee \
             crates/nono-cli/tests/schema_cli_parity.rs for context.",
            n,
            if n == 1 { "" } else { "s" },
            errors.join("\n  - ")
        );
    }
}

/// Forward direction only: `Flag(name)` mappings must point at real flags.
/// We don't check the inverse (every CLI flag maps to a policy field).
#[test]
fn flag_backed_fields_have_real_cli_flags() {
    let cli_flags = parse_cli_flags();
    let table = mapping_table();
    let mut errors: Vec<String> = Vec::new();

    for (s, f, cat) in &table {
        if let Category::Flag(name) = cat
            && !cli_flags.contains(*name)
        {
            errors.push(format!(
                "mapping says {s}.{f} → --{name}, but `nono run --help` \
                 does not list --{name} (renamed flag? typo? \
                 macOS-conditional flag absent on this build?)"
            ));
        }
    }

    if !errors.is_empty() {
        let n = errors.len();
        panic!(
            "flag-existence check failed ({} error{}):\n  - {}",
            n,
            if n == 1 { "" } else { "s" },
            errors.join("\n  - ")
        );
    }
}

/// Synthetic-fixture test for the parser + BFS. Real-source coverage lives
/// in `schema_fields_are_categorized`; this one's just the unit-level guard.
#[test]
fn bfs_descends_into_unknown_sub_structs() {
    let synthetic = r#"
#[derive(Debug)]
pub struct Profile {
    pub gpu: Option<GpuConfig>,
    pub credentials: std::collections::HashMap<
        String,
        CredentialEntry,
    >,
    pub deeply_nested: Vec<Option<Vec<DeepLeaf>>>,
    secret: SecretLeaf,
}

pub struct GpuConfig {
    pub mode: String,
    pub vendor: Option<GpuVendor>,
}

pub struct GpuVendor {
    pub name: String,
}

pub struct CredentialEntry {
    pub key: String,
}

pub struct DeepLeaf {
    pub n: u32,
}

pub struct OpaqueWrapper(pub String);

struct SecretLeaf {
    pub leaked: bool,
}
"#;
    let parsed = parse_struct_fields(synthetic);

    assert!(parsed.contains_key("Profile"));
    assert!(parsed.contains_key("GpuConfig"));
    assert!(parsed.contains_key("CredentialEntry"));
    assert!(parsed.contains_key("DeepLeaf"));
    assert!(
        !parsed.contains_key("SecretLeaf"),
        "private struct must not be parsed (visibility filter)"
    );
    assert!(
        !parsed.contains_key("OpaqueWrapper"),
        "tuple struct must not be parsed (no named fields)"
    );

    let profile_fields = parsed.get("Profile").expect("Profile present");
    let field_names: Vec<&str> = profile_fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        field_names,
        vec!["gpu", "credentials", "deeply_nested"],
        "private `secret` field must be filtered out"
    );

    let credentials_idents: BTreeSet<&str> = profile_fields
        .iter()
        .find(|f| f.name == "credentials")
        .expect("credentials field")
        .type_idents
        .iter()
        .map(String::as_str)
        .collect();
    assert!(
        credentials_idents.contains("CredentialEntry"),
        "multi-line generic type lost CredentialEntry: got {credentials_idents:?}"
    );

    let deeply_idents: BTreeSet<&str> = profile_fields
        .iter()
        .find(|f| f.name == "deeply_nested")
        .expect("deeply_nested field")
        .type_idents
        .iter()
        .map(String::as_str)
        .collect();
    assert!(
        deeply_idents.contains("DeepLeaf"),
        "deeply nested generics lost DeepLeaf: got {deeply_idents:?}"
    );

    let known: BTreeSet<&str> = parsed.keys().map(String::as_str).collect();
    let mut reachable: BTreeSet<String> = BTreeSet::new();
    let mut queue = vec!["Profile".to_string()];
    while let Some(s) = queue.pop() {
        if !reachable.insert(s.clone()) {
            continue;
        }
        let Some(fields) = parsed.get(&s) else {
            continue;
        };
        for f in fields {
            for ident in &f.type_idents {
                if known.contains(ident.as_str()) && !reachable.contains(ident) {
                    queue.push(ident.clone());
                }
            }
        }
    }

    assert!(reachable.contains("Profile"));
    assert!(
        reachable.contains("GpuConfig"),
        "BFS failed to follow Profile.gpu: Option<GpuConfig> into GpuConfig"
    );
    assert!(
        reachable.contains("GpuVendor"),
        "BFS failed to follow GpuConfig.vendor: Option<GpuVendor> into GpuVendor - \
         transitive descent is broken, sub-sub-structs would slip through"
    );
    assert!(
        reachable.contains("CredentialEntry"),
        "BFS failed to descend through multi-line HashMap into CredentialEntry"
    );
    assert!(
        reachable.contains("DeepLeaf"),
        "BFS failed to descend through Vec<Option<Vec<...>>> into DeepLeaf"
    );
    assert!(
        !reachable.contains("SecretLeaf"),
        "private struct must not be reachable"
    );
}
