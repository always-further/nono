//! Helpers for rendering user-supplied commands for display.
//!
//! Commands passed to `nono` (e.g. after `--`) preserve each argument as a
//! separate `String`. When we echo those commands back to the user — in the
//! `nono learn` "Run with:" hint, the dry-run banner, `nono ps` details,
//! audit/rollback listings — we want the rendered line to round-trip: a user
//! copy-pasting it into a shell must execute the exact same argv that was
//! learned or recorded.
//!
//! A naive `command.join(" ")` breaks that contract as soon as any argument
//! contains whitespace, quotes, `$`, backslashes, etc. `echo 'foo bar' baz`
//! becomes `echo foo bar baz` (three args instead of two). See issue #660.
//!
//! This module centralises shell-quoting via [`shlex::try_quote`] so all
//! display sites stay consistent.

use std::borrow::Cow;

/// Quote a single argument for POSIX shell display.
///
/// Returns the input unchanged when it is already safe to display unquoted
/// (e.g. a simple identifier like `echo`). Falls back to a single-quoted
/// form when the argument contains a NUL byte, which `shlex::try_quote`
/// rejects. NUL cannot appear in a real shell argument, so this fallback
/// is only about keeping display infallible — we still want the user to
/// see *something* if a recorded command contains corrupt data.
fn quote_arg(arg: &str) -> Cow<'_, str> {
    match shlex::try_quote(arg) {
        Ok(quoted) => quoted,
        Err(_) => Cow::Owned(format!("'{}'", arg.replace('\'', "'\\''"))),
    }
}

/// Render a command (program + args) as a single shell-quoted line suitable
/// for display or copy-paste back into a terminal.
///
/// Each element is quoted independently with [`shlex::try_quote`] and joined
/// with spaces. Empty `command` returns an empty string.
pub(crate) fn format_command_line(command: &[String]) -> String {
    command
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_args_unquoted() {
        assert_eq!(
            format_command_line(&["echo".to_string(), "hello".to_string()]),
            "echo hello"
        );
    }

    #[test]
    fn args_with_spaces_are_quoted() {
        let out =
            format_command_line(&["echo".to_string(), "foo bar".to_string(), "baz".to_string()]);
        // Must preserve "foo bar" as a single argument when re-parsed.
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "foo bar", "baz"]);
    }

    #[test]
    fn args_with_single_quotes_are_quoted() {
        let out = format_command_line(&["echo".to_string(), "it's".to_string()]);
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "it's"]);
    }

    #[test]
    fn args_with_double_quotes_are_quoted() {
        let out = format_command_line(&["echo".to_string(), "a\"b".to_string()]);
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "a\"b"]);
    }

    #[test]
    fn args_with_dollar_and_backslash_are_quoted() {
        let out =
            format_command_line(&["echo".to_string(), "$HOME".to_string(), "a\\b".to_string()]);
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "$HOME", "a\\b"]);
    }

    #[test]
    fn empty_arg_is_quoted() {
        let out = format_command_line(&["echo".to_string(), String::new()]);
        let reparsed = shlex::split(&out).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", ""]);
    }

    #[test]
    fn empty_command_returns_empty_string() {
        assert_eq!(format_command_line(&[]), "");
    }

    #[test]
    fn issue_660_repro() {
        // From issue #660: `nono learn -- echo 'foo bar' 'baz'` must not
        // render as `echo foo bar baz`.
        let rendered =
            format_command_line(&["echo".to_string(), "foo bar".to_string(), "baz".to_string()]);
        let naive = ["echo", "foo bar", "baz"].join(" ");
        assert_eq!(naive, "echo foo bar baz"); // what the bug produced
        assert_ne!(rendered, naive);
        let reparsed = shlex::split(&rendered).expect("round-trips through shlex");
        assert_eq!(reparsed, vec!["echo", "foo bar", "baz"]);
    }
}
