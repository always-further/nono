//! Package-status enforcement surface. Phase 36.5 D-36.5-C3.
//!
//! D-20 manual-replay of upstream 829c341a `package_status.rs`. Fork
//! adaptations applied:
//! - `ActionRequired` is the struct-shaped variant `{ expected, actual,
//!   resolve_via }` (upstream uses a single-tuple shape — RESEARCH §Pitfall 1).
//! - `depends_on_official_pack_profile` uses `profile::load_profile_extends`
//!   (which returns `Option<Vec<String>>`) instead of upstream's
//!   `find_pack_store_profile` (RESEARCH §Pitfall 2).
//! - Advisory-default posture: lockfile-load failure, missing-installed-version,
//!   and network-fetch failure all silently return `Ok(())` by default, matching
//!   upstream 829c341a best-effort posture (documented in
//!   `docs/cli/features/profiles-groups.mdx`).
//! - Strict mode: when `NONO_REQUIRE_PACK_STATUS=1` AND the active profile is
//!   in `OFFICIAL_PACK_STATUS_TARGETS`, ALL three silent-Ok paths become fatal
//!   `NonoError::ConfigRead` (lockfile) or `NonoError::ActionRequired` (install /
//!   network). Implements CLAUDE.md § Permission Scope: "Configuration load
//!   failures must be fatal" for security-critical deployments.

use crate::package::{self, PackageRef, PackageStatusResponse};
use crate::profile;
use crate::registry_client::{resolve_registry_url, RegistryClient};
use nono::{NonoError, Result};
use tracing::warn;

/// An official pack target with its associated profile names.
struct OfficialPackStatusTarget {
    namespace: &'static str,
    name: &'static str,
    profiles: &'static [&'static str],
}

const CLAUDE_PACK: OfficialPackStatusTarget = OfficialPackStatusTarget {
    namespace: "nono-official",
    name: "claude",
    profiles: &["claude-code", "claude-no-keychain"],
};

const CODEX_PACK: OfficialPackStatusTarget = OfficialPackStatusTarget {
    namespace: "nono-official",
    name: "codex",
    profiles: &["codex"],
};

const OPENCODE_PACK: OfficialPackStatusTarget = OfficialPackStatusTarget {
    namespace: "nono-official",
    name: "opencode",
    profiles: &["opencode"],
};

const OFFICIAL_PACK_STATUS_TARGETS: &[&OfficialPackStatusTarget] =
    &[&CLAUDE_PACK, &CODEX_PACK, &OPENCODE_PACK];

/// Enforce package-status for the active profile. Iterates the official pack
/// target list; for each matching pack:
/// - If yanked: returns `Err(NonoError::ActionRequired { .. })`.
/// - If outdated: emits a stderr advisory (unless `silent`).
/// - If current / status unknown / not applicable: returns `Ok(())`.
///
/// **Advisory-default posture (default, no env var):** lockfile-load failure,
/// missing installed version, and network-fetch failure all silently return
/// `Ok(())`. This is a best-effort posture matching upstream 829c341a.
///
/// **Strict posture (opt-in, `NONO_REQUIRE_PACK_STATUS=1`):** when the active
/// profile is in `OFFICIAL_PACK_STATUS_TARGETS`, all three silent paths become
/// fatal errors. See `docs/cli/features/profiles-groups.mdx` for details.
///
/// Phase 36.5 D-36.5-C3.
pub(crate) fn enforce_for_active_profile(profile_name: Option<&str>, silent: bool) -> Result<()> {
    for target in OFFICIAL_PACK_STATUS_TARGETS {
        enforce_official_pack_status(target, profile_name, silent)?;
    }
    Ok(())
}

fn enforce_official_pack_status(
    target: &OfficialPackStatusTarget,
    profile_name: Option<&str>,
    silent: bool,
) -> Result<()> {
    // Only enforce if the active profile is (or extends) an official-pack profile.
    let applies = match profile_name {
        Some(name) => depends_on_official_pack_profile(target, name),
        None => false,
    };
    if !applies {
        return Ok(());
    }

    // STRICT MODE GATE — Phase 36.5 D-36.5-C3 + CLAUDE.md § Permission Scope.
    //
    // Default behavior: package-status enforcement is ADVISORY-ONLY. On
    // lockfile-load failure or network-fetch failure the function returns
    // `Ok(())` (best-effort posture matching upstream 829c341a, which is
    // documented in docs/cli/features/profiles-groups.mdx).
    //
    // When `NONO_REQUIRE_PACK_STATUS=1` is set AND the active profile is
    // in OFFICIAL_PACK_STATUS_TARGETS (already checked above via `applies`),
    // ALL silent-Ok paths become fatal errors:
    //   - lockfile load failure → fatal NonoError::ConfigRead
    //   - installed_version: None when profile depends on the pack → fatal
    //     NonoError::ActionRequired (operator must install or remove the
    //     pack profile dependency)
    //   - network-fetch failure → fatal NonoError::ActionRequired
    //
    // This implements CLAUDE.md § Permission Scope: "Configuration load
    // failures must be fatal. If security lists fail to load, abort." —
    // gated behind an opt-in env var so the default advisory posture is
    // preserved for v2.4 while strict mode is available for security-
    // critical deployments (CI, regulated environments, etc.). Strict-mode
    // semantics + the env-var name are documented in docs/cli/features/
    // profiles-groups.mdx (Task C3-04).
    let strict = std::env::var("NONO_REQUIRE_PACK_STATUS").is_ok_and(|v| v == "1");

    let lockfile = match package::read_lockfile() {
        Ok(lf) => lf,
        Err(e) => {
            if strict {
                return Err(NonoError::ConfigRead {
                    path: package::lockfile_path()
                        .unwrap_or_else(|_| std::path::PathBuf::from("<lockfile>")),
                    source: std::io::Error::other(format!(
                        "NONO_REQUIRE_PACK_STATUS=1: lockfile load failed for official \
                         pack '{}/{}' enforcement: {e}",
                        target.namespace, target.name
                    )),
                });
            }
            // advisory mode: no lockfile = nothing installed = no enforcement
            return Ok(());
        }
    };

    let pkg_ref = PackageRef {
        namespace: target.namespace.to_string(),
        name: target.name.to_string(),
        version: None,
    };

    // Look up by the BTreeMap key which is PackageRef::key() format: "<ns>/<name>".
    let pack_key = pkg_ref.key();
    let installed_version = lockfile.packages.get(&pack_key).map(|p| p.version.clone());

    if installed_version.is_none() {
        if strict {
            return Err(NonoError::ActionRequired {
                expected: format!("{}/{}", target.namespace, target.name),
                actual: "installed: <none>".to_string(),
                resolve_via: format!(
                    "NONO_REQUIRE_PACK_STATUS=1: profile depends on official pack '{}/{}' \
                     but it is not installed. Install via `nono package install {}/{}`.",
                    target.namespace, target.name, target.namespace, target.name,
                ),
            });
        }
        // advisory mode: not installed
        return Ok(());
    }
    let installed = installed_version.unwrap_or_default();

    let registry_url = resolve_registry_url(None);
    let client = RegistryClient::new(registry_url);
    let status = match client.fetch_package_status(&pkg_ref, Some(&installed)) {
        Ok(s) => s,
        Err(e) => {
            if !silent {
                warn!(
                    "Failed to fetch package status for {}/{}: {e}",
                    pkg_ref.namespace, pkg_ref.name
                );
            }
            if strict {
                return Err(NonoError::ActionRequired {
                    expected: format!("{}/{}", pkg_ref.namespace, pkg_ref.name),
                    actual: format!("network-fetch failed: {e}"),
                    resolve_via: format!(
                        "NONO_REQUIRE_PACK_STATUS=1: package-status fetch for \
                         '{}/{}@{installed}' failed and strict mode is enabled. Ensure \
                         the registry is reachable, or unset NONO_REQUIRE_PACK_STATUS \
                         for advisory mode.",
                        pkg_ref.namespace, pkg_ref.name,
                    ),
                });
            }
            // advisory mode: best-effort — do not block profile load on network error
            return Ok(());
        }
    };

    match status.installed_status.as_deref() {
        Some("yanked") => {
            let msg = yanked_message(&pkg_ref, &installed, &status);
            Err(NonoError::ActionRequired {
                expected: format!("{}/{}", pkg_ref.namespace, pkg_ref.name),
                actual: format!("installed: {installed} (status: yanked)"),
                resolve_via: msg,
            })
        }
        Some("current") | None => Ok(()),
        Some(_other) => {
            if !silent {
                // Display-only: stderr advisory rendering. The unwrap_or_default
                // here is acceptable because (a) the status string is already
                // present (we just matched on it), and (b) latest_version is
                // optional in the registry response shape. This is NOT a security
                // boundary — it is an operator-facing advisory line only.
                eprintln!(
                    "  Note: package {}/{} status: {} (latest: {})",
                    pkg_ref.namespace,
                    pkg_ref.name,
                    status.installed_status.unwrap_or_default(),
                    status.latest_version.unwrap_or_default()
                );
            }
            Ok(())
        }
    }
}

/// Build the multi-line operator-facing message for a yanked package.
/// Includes the reason, advisory, and update command. All fields are from the
/// `PackageStatusResponse` and `pkg_ref`/`installed` — no env vars, credentials,
/// or registry URLs are embedded (V7 / T-36.5-07 constraint).
fn yanked_message(pkg_ref: &PackageRef, installed: &str, status: &PackageStatusResponse) -> String {
    let mut parts = vec![format!(
        "Package {}/{} version {} has been yanked.",
        pkg_ref.namespace, pkg_ref.name, installed
    )];
    if let Some(reason) = &status.yanked_reason {
        parts.push(format!("Reason: {reason}"));
    }
    if let Some(adv) = &status.advisory {
        parts.push(format!("Advisory ({}): {}", adv.severity, adv.summary));
    }
    if let Some(replacement) = &status.replacement_version {
        parts.push(format!(
            "Update via: nono package install {}/{}@{}",
            pkg_ref.namespace, pkg_ref.name, replacement
        ));
    } else if let Some(latest) = &status.latest_version {
        parts.push(format!(
            "Update via: nono package install {}/{}@{}",
            pkg_ref.namespace, pkg_ref.name, latest
        ));
    }
    parts.join("\n  ")
}

/// Returns `true` if `name_or_path` is directly an official-pack profile OR
/// if any profile in its `extends` chain is. Recursion terminates when
/// `profile::load_profile_extends` returns `None` (profile not found / no
/// extends chain) or the chain is exhausted.
fn depends_on_official_pack_profile(target: &OfficialPackStatusTarget, name_or_path: &str) -> bool {
    if is_official_profile_name(target, name_or_path) {
        return true;
    }
    // Walk the extends chain (D-20 fork adaptation: upstream uses
    // `find_pack_store_profile`; fork uses `load_profile_extends` which returns
    // `Option<Vec<String>>` for the immediate parent names — RESEARCH §Pitfall 2).
    match profile::load_profile_extends(name_or_path) {
        Some(extends_chain) => extends_chain
            .iter()
            .any(|ext| is_official_profile_name(target, ext)),
        None => false,
    }
}

fn is_official_profile_name(target: &OfficialPackStatusTarget, name: &str) -> bool {
    target.profiles.contains(&name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::package::{PackageAdvisory, PackageStatusResponse};

    // -----------------------------------------------------------------------
    // Test 1 (port from upstream): yanked_message includes CVE reason,
    // advisory, and latest version.
    // -----------------------------------------------------------------------

    #[test]
    fn yanked_message_pins_latest_when_available() {
        let pkg_ref = PackageRef {
            namespace: "nono-official".into(),
            name: "claude".into(),
            version: None,
        };
        let status = PackageStatusResponse {
            namespace: "nono-official".into(),
            name: "claude".into(),
            installed_status: Some("yanked".into()),
            latest_version: Some("v2.0".into()),
            yanked_reason: Some("CVE-2026-9999".into()),
            replacement_version: None,
            advisory: Some(PackageAdvisory {
                severity: "high".into(),
                summary: "Critical vulnerability in profile loader".into(),
            }),
        };
        let msg = yanked_message(&pkg_ref, "v1.0", &status);
        assert!(
            msg.contains("v2.0"),
            "yanked_message must include latest version; got: {msg}"
        );
        assert!(
            msg.contains("CVE-2026-9999"),
            "yanked_message must include CVE reason; got: {msg}"
        );
        assert!(
            msg.contains("Critical vulnerability"),
            "yanked_message must include advisory summary; got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2 (port from upstream): official profile names are recognized.
    // -----------------------------------------------------------------------

    #[test]
    fn official_profile_names_include_claude_and_codex() {
        assert!(
            is_official_profile_name(&CLAUDE_PACK, "claude-code"),
            "claude-code must be an official claude-pack profile"
        );
        assert!(
            is_official_profile_name(&CLAUDE_PACK, "claude-no-keychain"),
            "claude-no-keychain must be an official claude-pack profile"
        );
        assert!(
            is_official_profile_name(&CODEX_PACK, "codex"),
            "codex must be an official codex-pack profile"
        );
        assert!(
            !is_official_profile_name(&CLAUDE_PACK, "myagent"),
            "myagent must NOT be an official claude-pack profile"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3 (port from upstream): canonical package refs are recognized.
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_package_refs_target_official_packs() {
        // CLAUDE_PACK should match a PackageRef with nono-official/claude
        let claude_ref = PackageRef {
            namespace: "nono-official".into(),
            name: "claude".into(),
            version: Some("v1.0".into()),
        };
        let matches_claude = OFFICIAL_PACK_STATUS_TARGETS
            .iter()
            .any(|t| t.namespace == claude_ref.namespace && t.name == claude_ref.name);
        assert!(
            matches_claude,
            "nono-official/claude must be in OFFICIAL_PACK_STATUS_TARGETS"
        );

        // A random ref should not match
        let random_ref = PackageRef {
            namespace: "acme".into(),
            name: "custom-pack".into(),
            version: None,
        };
        let matches_random = OFFICIAL_PACK_STATUS_TARGETS
            .iter()
            .any(|t| t.namespace == random_ref.namespace && t.name == random_ref.name);
        assert!(
            !matches_random,
            "acme/custom-pack must NOT be in OFFICIAL_PACK_STATUS_TARGETS"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4 (fork addition): enforce_for_active_profile returns Ok when
    // profile does not depend on an official pack (advisory mode, no env var).
    // -----------------------------------------------------------------------

    #[test]
    fn enforce_for_active_profile_non_official_profile_ok() {
        // "my-custom-agent" is not an official profile → must return Ok(())
        // regardless of network or lockfile state.
        let result = enforce_for_active_profile(Some("my-custom-agent"), true);
        assert!(
            result.is_ok(),
            "Non-official profile must return Ok(()) in advisory mode; got: {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // Test 5 (fork addition): enforce_for_active_profile returns Ok for None
    // profile name (no active profile).
    // -----------------------------------------------------------------------

    #[test]
    fn enforce_for_active_profile_no_profile_ok() {
        let result = enforce_for_active_profile(None, true);
        assert!(
            result.is_ok(),
            "None profile must return Ok(()) in advisory mode; got: {:?}",
            result
        );
    }
}
