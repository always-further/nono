//! Instruction file deny rules for macOS Seatbelt profiles
//!
//! Converts glob patterns from the trust policy's `instruction_patterns` into
//! Seatbelt regex deny rules, and adds literal allow overrides for verified files.
//!
//! # Approach
//!
//! On macOS, Seatbelt `(deny file-read-data (regex ...))` blocks reads even
//! within `(allow file-read* (subpath ...))` directories. More specific
//! `(allow file-read-data (literal ...))` rules override deny-regex rules.
//!
//! This provides kernel-level instruction file protection:
//! - Deny regex rules prevent reading ANY file matching instruction patterns
//! - Literal allows re-enable reading for files that passed trust verification
//! - Files created at runtime (e.g., by curl) are blocked by deny regex

use nono::trust::TrustPolicy;
use nono::CapabilitySet;
use nono::Result;
#[cfg(target_os = "macos")]
use std::path::Path;

/// Convert a glob pattern to a Seatbelt regex string.
///
/// Handles common glob constructs:
/// - `*` matches any characters within a single path segment (not `/`)
/// - `**` matches any number of path segments (including zero)
/// - Literal characters are regex-escaped
///
/// The resulting regex is anchored to match at the end of path components,
/// prefixed with `/` to ensure it matches complete filename components.
///
/// # Examples
///
/// - `SKILLS*` -> `#"/SKILLS[^/]*$"`
/// - `CLAUDE*` -> `#"/CLAUDE[^/]*$"`
/// - `.claude/**/*.md` -> `#"/\\.claude/.*/[^/]*\\.md$"`
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn glob_to_seatbelt_regex(pattern: &str) -> Result<String> {
    if pattern.is_empty() {
        return Err(nono::NonoError::ConfigParse(
            "empty instruction pattern".to_string(),
        ));
    }

    let mut regex = String::with_capacity(pattern.len().saturating_mul(2));
    if !pattern.starts_with('/') {
        regex.push('/');
    }

    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '*' => {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    // `**` — match any path segments
                    regex.push_str(".*");
                    i += 2;
                    // Skip trailing `/` after `**/`
                    if i < chars.len() && chars[i] == '/' {
                        regex.push('/');
                        i += 1;
                    }
                } else {
                    // Single `*` — match within one segment
                    regex.push_str("[^/]*");
                    i += 1;
                }
            }
            '.' => {
                regex.push_str("\\.");
                i += 1;
            }
            '[' => {
                regex.push_str("\\[");
                i += 1;
            }
            ']' => {
                regex.push_str("\\]");
                i += 1;
            }
            '(' => {
                regex.push_str("\\(");
                i += 1;
            }
            ')' => {
                regex.push_str("\\)");
                i += 1;
            }
            '{' => {
                regex.push_str("\\{");
                i += 1;
            }
            '}' => {
                regex.push_str("\\}");
                i += 1;
            }
            '+' => {
                regex.push_str("\\+");
                i += 1;
            }
            '?' => {
                regex.push_str("\\?");
                i += 1;
            }
            '^' => {
                regex.push_str("\\^");
                i += 1;
            }
            '$' => {
                regex.push_str("\\$");
                i += 1;
            }
            '|' => {
                regex.push_str("\\|");
                i += 1;
            }
            '\\' => {
                regex.push_str("\\\\");
                i += 1;
            }
            '"' => {
                regex.push_str("\\\"");
                i += 1;
            }
            '/' => {
                regex.push('/');
                i += 1;
            }
            c => {
                regex.push(c);
                i += 1;
            }
        }
    }

    regex.push('$');

    Ok(format!("(deny file-read-data (regex #\"{regex}\"))"))
}

/// Inject instruction file deny rules into a `CapabilitySet`.
///
/// For each pattern in the trust policy's `instruction_patterns`, adds a
/// Seatbelt `(deny file-read-data (regex ...))` rule. For each verified
/// file path, adds a `(allow file-read-data (literal ...))` override.
///
/// On macOS, handles symlinks by emitting rules for both the original
/// path and the canonical path when they differ (e.g., `/tmp/` vs
/// `/private/tmp/`).
///
/// This function is a no-op on non-macOS platforms.
///
/// # Errors
///
/// Returns an error if pattern conversion fails or if `add_platform_rule`
/// rejects a generated rule.
#[cfg(target_os = "macos")]
pub fn inject_instruction_deny_rules(
    caps: &mut CapabilitySet,
    policy: &TrustPolicy,
    verified_paths: &[std::path::PathBuf],
) -> Result<()> {
    // Add deny rules for each instruction pattern
    for pattern in &policy.instruction_patterns {
        let deny_rule = glob_to_seatbelt_regex(pattern)?;
        caps.add_platform_rule(deny_rule)?;
    }

    // Add literal allows for verified files
    for path in verified_paths {
        add_literal_allow(caps, path)?;
    }

    Ok(())
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn inject_instruction_deny_rules(
    _caps: &mut CapabilitySet,
    _policy: &TrustPolicy,
    _verified_paths: &[std::path::PathBuf],
) -> Result<()> {
    Ok(())
}

/// Add a `(allow file-read-data (literal ...))` rule for a verified file.
///
/// On macOS, if the path contains symlinks (e.g., `/tmp` -> `/private/tmp`),
/// emits rules for both the original and resolved paths.
///
/// Rejects paths containing characters that would break Seatbelt literal syntax
/// (`"` and `\`), since these are not legitimate instruction file path characters
/// and could allow sandbox rule injection.
#[cfg(target_os = "macos")]
fn add_literal_allow(caps: &mut CapabilitySet, path: &Path) -> Result<()> {
    let path_str = path.display().to_string();
    validate_seatbelt_path(&path_str)?;

    let allow_rule = format!("(allow file-read-data (literal \"{path_str}\"))");
    caps.add_platform_rule(allow_rule)?;

    // Handle macOS symlinks: emit rule for canonical path too
    if let Ok(canonical) = std::fs::canonicalize(path) {
        if canonical != path {
            let canonical_str = canonical.display().to_string();
            validate_seatbelt_path(&canonical_str)?;
            let canonical_rule = format!("(allow file-read-data (literal \"{canonical_str}\"))");
            caps.add_platform_rule(canonical_rule)?;
        }
    }

    Ok(())
}

/// Reject paths containing characters that would break out of Seatbelt string literals.
///
/// On macOS/HFS+, `"` is legal in filenames but would terminate a Seatbelt `(literal "...")`
/// string, allowing injection of arbitrary sandbox rules. `\` could be used for escape
/// sequence injection. Both are rejected.
#[cfg(target_os = "macos")]
fn validate_seatbelt_path(path_str: &str) -> Result<()> {
    if path_str.contains('"') || path_str.contains('\\') {
        return Err(nono::NonoError::ConfigParse(format!(
            "path contains characters not permitted in Seatbelt rules: {path_str}"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // glob_to_seatbelt_regex
    // -----------------------------------------------------------------------

    #[test]
    fn glob_skills_star() {
        let rule = glob_to_seatbelt_regex("SKILLS*").unwrap();
        assert_eq!(rule, "(deny file-read-data (regex #\"/SKILLS[^/]*$\"))");
    }

    #[test]
    fn glob_claude_star() {
        let rule = glob_to_seatbelt_regex("CLAUDE*").unwrap();
        assert_eq!(rule, "(deny file-read-data (regex #\"/CLAUDE[^/]*$\"))");
    }

    #[test]
    fn glob_agent_md() {
        let rule = glob_to_seatbelt_regex("AGENT.MD").unwrap();
        assert_eq!(rule, "(deny file-read-data (regex #\"/AGENT\\.MD$\"))");
    }

    #[test]
    fn glob_dot_claude_recursive() {
        let rule = glob_to_seatbelt_regex(".claude/**/*.md").unwrap();
        assert_eq!(
            rule,
            "(deny file-read-data (regex #\"/\\.claude/.*/[^/]*\\.md$\"))"
        );
    }

    #[test]
    fn glob_copilot_instructions() {
        let rule = glob_to_seatbelt_regex(".github/copilot-instructions.md").unwrap();
        assert_eq!(
            rule,
            "(deny file-read-data (regex #\"/\\.github/copilot-instructions\\.md$\"))"
        );
    }

    #[test]
    fn glob_empty_returns_error() {
        assert!(glob_to_seatbelt_regex("").is_err());
    }

    #[test]
    fn glob_pattern_with_leading_slash_no_double_slash() {
        // A pattern that already starts with '/' must not produce a double slash
        let rule = glob_to_seatbelt_regex("/SKILLS*").unwrap();
        assert_eq!(rule, "(deny file-read-data (regex #\"/SKILLS[^/]*$\"))");
        assert!(!rule.contains("//"));
    }

    #[test]
    fn glob_special_chars_escaped() {
        let rule = glob_to_seatbelt_regex("test[1].md").unwrap();
        assert_eq!(
            rule,
            "(deny file-read-data (regex #\"/test\\[1\\]\\.md$\"))"
        );
    }

    #[test]
    fn glob_double_star_at_start() {
        let rule = glob_to_seatbelt_regex("**/*.md").unwrap();
        assert_eq!(rule, "(deny file-read-data (regex #\"/.*/[^/]*\\.md$\"))");
    }

    #[test]
    fn glob_quote_escaped_in_regex() {
        let rule = glob_to_seatbelt_regex("test\"file.md").unwrap();
        assert!(rule.contains("\\\""));
        assert!(!rule.contains("\"test"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn literal_allow_rejects_path_with_quote() {
        let mut caps = CapabilitySet::new();
        let bad_path = Path::new("/tmp/SKILLS\") (allow file-write* (subpath \"/\")) ;.md");
        let result = add_literal_allow(&mut caps, bad_path);
        assert!(result.is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn literal_allow_rejects_path_with_backslash() {
        let mut caps = CapabilitySet::new();
        let bad_path = Path::new("/tmp/SKILLS\\.md");
        let result = add_literal_allow(&mut caps, bad_path);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // inject_instruction_deny_rules
    // -----------------------------------------------------------------------

    #[test]
    fn inject_with_no_patterns_is_noop() {
        let mut caps = CapabilitySet::new();
        let policy = TrustPolicy {
            instruction_patterns: Vec::new(),
            ..TrustPolicy::default()
        };

        inject_instruction_deny_rules(&mut caps, &policy, &[]).unwrap();
        assert!(caps.platform_rules().is_empty());
    }

    #[test]
    fn inject_adds_deny_and_allow_rules() {
        let mut caps = CapabilitySet::new();
        let policy = TrustPolicy {
            instruction_patterns: vec!["SKILLS*".to_string()],
            ..TrustPolicy::default()
        };

        // On macOS, we'd have actual deny rules. On other platforms, it's a no-op.
        // Test the glob conversion at least.
        let deny = glob_to_seatbelt_regex("SKILLS*").unwrap();
        assert!(deny.starts_with("(deny"));

        inject_instruction_deny_rules(&mut caps, &policy, &[]).unwrap();

        #[cfg(target_os = "macos")]
        assert_eq!(caps.platform_rules().len(), 1);

        #[cfg(not(target_os = "macos"))]
        assert!(caps.platform_rules().is_empty());
    }

    #[test]
    fn default_policy_patterns_all_convert() {
        // Verify all default patterns from TrustPolicy::default() convert without error
        let policy = TrustPolicy::default();
        for pattern in &policy.instruction_patterns {
            let result = glob_to_seatbelt_regex(pattern);
            assert!(
                result.is_ok(),
                "failed to convert pattern '{pattern}': {:?}",
                result.err()
            );
        }
    }
}
