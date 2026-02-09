# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-02-09

### Added

- Add shell command
- Add execution strategy with fork+wait diagnostics and Claude Code hooks

### Changed

- Dedupe logic
- Dedupe logic
- Print interactive exit hint in run_shell and drop execute_sandboxed flag
- Merge pull request #46 from jaydenfyi/feature/shell-command

feat: Add `shell` command
- Bump dirs from 5.0.1 to 6.0.0

Bumps [dirs](https://github.com/soc/dirs-rs) from 5.0.1 to 6.0.0.
- [Commits](https://github.com/soc/dirs-rs/commits)

---
updated-dependencies:
- dependency-name: dirs
  dependency-version: 6.0.0
  dependency-type: direct:production
  update-type: version-update:semver-major
...

Signed-off-by: dependabot[bot] <support@github.com>
- Merge pull request #38 from lukehinds/dependabot/cargo/dirs-6.0.0

Bump dirs from 5.0.1 to 6.0.0
- Make fork+exec async-signal-safe for keyring compatibility

When secrets are loaded from the system keystore, the keyring crate
spawns background threads for D-Bus/Security.framework communication.
These threads caused execute_monitor() to fail the single-thread check
before fork().

The previous child process implementation used Command::new() after
fork, which allocates memory. If a keyring thread holds the allocator
lock at fork time, the child deadlocks waiting for a lock that will
never be released.

This refactor ensures async-signal-safety after fork:

Parent (safe to allocate):
- Resolve program path using `which` crate
- Convert all strings to CString for execve
- Build complete environment as CString array
- Validate threading context before fork

Child (no allocations allowed):
- Close inherited FDs from keyring/other sources
- Redirect stdout/stderr with dup2
- Call libc::execve with pre-prepared pointers
- Exit with libc::_exit(127) on failure

Threading model:
- Add ThreadingContext enum (Strict/KeyringExpected)
- Allow up to 4 threads when secrets loaded (keyring expected)
- Strict mode still enforces single-threaded for other cases

Also fixes:
- shell --dry-run now correctly shows dry-run message
- Doc comment about diagnostic output (stdout only, not both)
- Add Linux test script
- Fix CI
- Merge pull request #63 from lukehinds/exec-strat

Execution strategy with fork+wait diagnostics
- Bump colored from 2.2.0 to 3.1.1

Bumps [colored](https://github.com/mackwic/colored) from 2.2.0 to 3.1.1.
- [Release notes](https://github.com/mackwic/colored/releases)
- [Changelog](https://github.com/colored-rs/colored/blob/master/CHANGELOG.md)
- [Commits](https://github.com/mackwic/colored/compare/v2.2.0...v3.1.1)

---
updated-dependencies:
- dependency-name: colored
  dependency-version: 3.1.1
  dependency-type: direct:production
  update-type: version-update:semver-major
...

Signed-off-by: dependabot[bot] <support@github.com>
- Merge pull request #40 from lukehinds/dependabot/cargo/colored-3.1.1

Bump colored from 2.2.0 to 3.1.1
- Revise alpha release warning in README

Updated warning section to clarify alpha release status and ongoing changes.
- Revise README to enhance project description

Updated project description to clarify functionality and added information about protections and future features.
- Add nono learn command and fix opencode profile for Linux

- Add Linux locale-langpack path to system read paths for TUI apps.
- Add $HOME read access to opencode profile for Landlock path traversal.

Document nono learn command in CLI reference and troubleshooting guide.
- Fix formatting
- Merge pull request #67 from lukehinds/devrandom

Add nono learn command and fix opencode profile for Linux
- Use c-style unescape for strace and learn mode

Learn mode improvements:
- Add comprehensive C-style unescape for strace output
  (handles \xNN hex, \NNN octal, \0 null, \n \t \r \\ \")
- Add tests for unescape function
- Ensure correct validation and handling in strace
- Process 2-digit hex escape in tests
- Reduce DRY in learn parsing
- Merge pull request #68 from lukehinds/strace-match

Use c-style unescape for strace and learn mode
- Bump toml from 0.8.23 to 0.9.11+spec-1.1.0

Bumps [toml](https://github.com/toml-rs/toml) from 0.8.23 to 0.9.11+spec-1.1.0.
- [Commits](https://github.com/toml-rs/toml/compare/toml-v0.8.23...toml-v0.9.11)

---
updated-dependencies:
- dependency-name: toml
  dependency-version: 0.9.11+spec-1.1.0
  dependency-type: direct:production
  update-type: version-update:semver-minor
...

Signed-off-by: dependabot[bot] <support@github.com>
- Merge pull request #41 from lukehinds/dependabot/cargo/toml-0.9.11spec-1.1.0

Bump toml from 0.8.23 to 0.9.11+spec-1.1.0
- Rem mistaken commit
- Enable for semver in cliff
- Address cliff semver confusion
- Use bump_rules instead of features_always_bump_minor
- Merge pull request #69 from lukehinds/cliff-amendment

Enable for semver in cliff
- Merge pull request #65 from boegel/fix_link_dev_guide

fix link to development guide in Installation docs page
- Remove platform specific nix

When Dependabot updates nix, it's likely only updating ONE of these entries (probably just the general one to 0.31.1), leaving the platform-specific entries at 0.29. This causes two different versions of nix to be compiled.
- Merge pull request #70 from lukehinds/nix-pkg

Remove platform specific nix

### Fixed

- Pass shell path as OsString and remove lossy UTF-8 conversion
- Restore NONO_CAP_FILE-only env contract and harden SHELL fallback
- Delete old home.mdx page
- Add missing --dry-run handling for shell subcommand
- Address Gemini code review feedback for PR #63
- Fix link to development guide in Installation docs page
- Fix path to development guide (use absolute path)

### Miscellaneous

- Wrap ShellArgs in Box

### Testing

- Add integration coverage for --dry-run, --net-block, and invalid --shell path

## [Unreleased]

### Added

- `nono shell` for starting an interactive shell inside the sandbox

## [0.2.7] - 2026-02-04

### Changed

- Set release to un-draft

## [0.2.6] - 2026-02-04

### Changed

- Remove signing for now and mark placeholder
- Add roadmap and re-org client docs
- Update links to documentation in README.md
- Revise README for installation and build instructions

Updated installation instructions and removed outdated sections.
- Add MacOS installation instructions to README

Added installation instructions for MacOS to README.
- Refactor CWD handling into profile-driven [workdir] config and remove cargo-build profile

Introduce a [workdir] section in profiles to declare working directory
access requirements (read, readwrite, none). This replaces the previous
$WORKDIR variable approach and enables automatic CWD inclusion with a
y/N confirmation prompt. Add --allow-cwd flag to skip the prompt.

Remove the cargo-build built-in profile and all references to it.
Update client documentation to reflect simplified usage commands.

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Fix CWD prompt decline to continue gracefully instead of aborting

Declining the CWD sharing prompt now logs an info message and continues
execution without CWD access, instead of returning a fatal error. This
fixes a regression where commands that don't need filesystem access
(e.g., nono run -- curl ...) would fail if the user declined the prompt.

Remove the now-unused UserDeclinedCwd error variant. Fix confusing
installation docs sentence that referenced the Usage guide for
installation details.

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Merge pull request #55 from lukehinds/profiles-update

Refactor CWD handling into profile-driven [workdir] config and remove…
- Fix documentation to match current code state

Audit all docs against source code and fix 17 discrepancies:

- landlock.mdx: Remove RemoveDir from Write access, add Refer
- seatbelt.mdx: Replace blanket (allow process*) with actual rules
- README.md: Fix nono why syntax, correct kernel protection claims
  about file deletion scope, fix defense layers table
- security/index.mdx: Fix typo ~/.gitcredentials -> ~/.git-credentials
- claude-code.mdx: Fix ~/.claude.json access level to read+write
- flags.mdx: Add missing --allow-command, --block-command, --allow-cwd
- profiles.mdx: Add [workdir] section, fix built-in profile examples,
  add $TMPDIR/$UID to env vars, fix filesystem field format
- development/index.mdx: Add missing run subcommand to cargo run
  example, add -D clippy::unwrap_used to clippy command
- vs-containers.mdx: Fix broken internal links
- secrets.mdx: Fix broken link to profiles page
- data/profiles/opencode.toml: Sync paths with builtin.rs
- data/profiles/claude-code.toml: Replace silently-ignored
  [filesystem.files] subsection with flat allow_file field
- data/profiles/openclaw.toml: Same [filesystem.files] fix

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Merge pull request #56 from lukehinds/docs-refresh

Fix documentation to match current code state
- Some tests require new --allow-cwd
- Patch gofmt
- Merge pull request #57 from lukehinds/integration-test-fix

Some tests require new --allow-cwd
- Merge pull request #58 from zemberdotnet/fix-readme-dev-guide-link

docs: fix broken Development Guide link in README

### Documentation

- Fix broken Development Guide link in README

## [0.2.5] - 2026-02-03

### Changed

- Fix atomic writes by adding required Landlock permissions

Applications using atomic write patterns (write to .tmp → rename to target)
were failing with EACCES: permission denied, even when the directory was
in the --allow list.

Root cause: The FsAccess::Write mapping was missing three Landlock flags
required for rename() operations:
- LANDLOCK_ACCESS_FS_REFER: required for rename/hard link operations
- LANDLOCK_ACCESS_FS_REMOVE_FILE: required for rename source removal
- LANDLOCK_ACCESS_FS_TRUNCATE: common write operation (ABI v3+)

Per the Landlock kernel docs, rename() requires REMOVE_FILE permission
on the source's parent directory, treating it as "removing" the source.

Security analysis: When users grant --write to a directory, they expect
sandboxed processes to create, modify, AND delete files within that path.
The previous overly-defensive approach broke legitimate use cases while
providing minimal additional security benefit.

Changes:
- Add RemoveFile, Refer, and Truncate to FsAccess::Write mapping
- Update CLI documentation to clarify what write permissions include
- Update tests to verify new permissions are granted
- Still exclude RemoveDir for defense-in-depth (directory deletion)

This fixes atomic writes for Node.js, Python, and other tools that use
this standard pattern for safe configuration updates.

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Remove mistaken agents file
- Merge pull request #51 from lukehinds/linux-fsaccess

Fix atomic writes by adding required Landlock permissions

## [0.2.4] - 2026-02-03

### Changed

- Fix release workflow: add tag_name parameter
- Fix crates.io publish with --allow-dirty flag
- Bump actions/cache from 4.3.0 to 5.0.3

Bumps [actions/cache](https://github.com/actions/cache) from 4.3.0 to 5.0.3.
- [Release notes](https://github.com/actions/cache/releases)
- [Changelog](https://github.com/actions/cache/blob/main/RELEASES.md)
- [Commits](https://github.com/actions/cache/compare/0057852bfaa89a56745cba8c7296529d2fc39830...cdf6c1fa76f9f475f3d7449005a359c84ca0f306)

---
updated-dependencies:
- dependency-name: actions/cache
  dependency-version: 5.0.3
  dependency-type: direct:production
  update-type: version-update:semver-major
...

Signed-off-by: dependabot[bot] <support@github.com>
- Merge pull request #36 from lukehinds/dependabot/github_actions/actions/cache-5.0.3

Bump actions/cache from 4.3.0 to 5.0.3
- Replace environment variable introspection with advisory API

This replaces the NONO_* environment variables (NONO_ACTIVE, NONO_ALLOWED,
NONO_BLOCKED, NONO_NET, NONO_HELP, NONO_CONTEXT) with a structured query
API that enables AI agents to pre-check if operations will be allowed
before attempting them. Instead of parsing environment variables,
sandboxed processes now call `nono why --self` to get a programmatic
JSON response explaining why an operation is allowed or denied.

The old `nono why <path>` command is reimplemented with a more powerful
interface that supports filesystem path queries (`--path` and `--op`),
network queries (`--host` and `--port`), JSON output for programmatic
use, and the ability to query current sandbox state from inside the
sandbox with `--self`. Capability context can be provided via the
existing flags (--allow, --read, --write, --profile, etc.) to check
what would be allowed under different configurations.

The sandbox state is now written to a temp file and passed via
NONO_CAP_FILE, which allows `nono why --self` to reconstruct the
capability set from inside the sandbox and answer questions about
what operations are allowed.

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Merge pull request #45 from lukehinds/advisory-api

Replace environment variable introspection with advisory API
- Add Claude Instructions
- Add Claude Instructions
- Update release script with cargo build

## [0.2.3] - 2026-02-03

### Changed

- Add workflow_dispatch to manually trigger releases

## [0.2.3] - 2026-02-03

## [0.2.2] - 2026-02-03

### Changed

- Merge pull request #25 from lukehinds/usr-local-fix

Usr local fix
- Rem broken image
- Add /nix
- Merge pull request #26 from lukehinds/bug-19

Add /nix
- Deny process-info for other processes to prevent info leaks

The Seatbelt profile used (allow process*) could allow sandboxed
processes to inspect other processes via ps aux, top, etc. This could
leak secrets from command-line arguments of other programs running as
the same user.

Replace blanket process* with targeted permissions:
- process-exec* and process-fork for execution
- process-info* (target self) for dyld/code signing
- process-info* (target others) DENIED to block inspection

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Assertions to include \n for exact rule matching
- Merge pull request #28 from lukehinds/process-hardening

Deny process-info for other processes to prevent info leaks
- Revise warning for early alpha release

Updated warning message to clarify the alpha release status and encourage bug reporting.
- Add integration test suite and development documentation

Introduce comprehensive shell-based integration tests that build nono
and verify sandbox behavior from the user's perspective. Tests cover:

- Filesystem access control (read/write permissions, single file grants)
- Sensitive path protection (~/.ssh, ~/.aws, ~/.gnupg, etc.)
- System path protection (/usr/bin, /etc, /System/Library)
- Binary execution (shells, text tools, language runtimes)
- Network blocking (--net-block flag)
- Dangerous command blocking (rm, chmod, sudo, pip, etc.)
- Edge cases (symlinks, path variations, env vars, dry-run mode)

Tests gracefully handle platform differences (macOS TMPDIR behavior,
Homebrew-installed runtimes) with skip functionality.

Also adds Development section to documentation with contributor guide
and detailed testing documentation.

New files:
- tests/lib/test_helpers.sh
- tests/run_integration_tests.sh
- tests/integration/test_*.sh (7 test suites)
- docs/development/index.mdx
- docs/development/testing.mdx

Modified:
- .github/workflows/ci.yml (add integration job)
- docs/docs.json (add Development navigation)

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Fix Linux Landlock sandbox for Ubuntu 24.04 and address review comments

The integration tests were failing on ubuntu-latest because the Landlock
sandbox was missing paths required for program execution on modern
Debian/Ubuntu systems.

Linux Landlock fixes:
- Add multiarch library paths (/lib/x86_64-linux-gnu, /usr/lib/x86_64-linux-gnu,
  and aarch64 variants) required by dynamically linked binaries
- Add /tmp and /var/tmp to system read paths for programs that need temp access
- Automatically grant read access to current working directory, as many
  programs need cwd access to function properly

Review comment fixes (gemini-code-assist):
- Replace manual test blocks with run_test helper function in:
  - test_commands.sh (2 instances)
  - test_fs_access.sh (1 instance)
  - test_edge_cases.sh (2 instances)

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- CI was caching the target directory

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Narrow out ubuntu tests that fail with tmp ops
- Skip ubuntu intehration tests involving tmp ops
- Fixed the ownership bug

- restructured to use early continue and ? propagation so ruleset

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Remove Linux, lets get seperate profiles and then return
- Merge pull request #30 from lukehinds/integration-tests

Add integration test suite and development documentation
- Add Roadmap
- Update with explicit sec guidance
- Refactor for more idiomatic rust
- Merge pull request #42 from lukehinds/process-harde

fix(security): prevent path collision bypass in macOS sandbox
- Bump actions/checkout from 4 to 6

Bumps [actions/checkout](https://github.com/actions/checkout) from 4 to 6.
- [Release notes](https://github.com/actions/checkout/releases)
- [Commits](https://github.com/actions/checkout/compare/v4...v6)

---
updated-dependencies:
- dependency-name: actions/checkout
  dependency-version: '6'
  dependency-type: direct:production
  update-type: version-update:semver-major
...

Signed-off-by: dependabot[bot] <support@github.com>
- Merge pull request #33 from lukehinds/dependabot/github_actions/actions/checkout-6

Bump actions/checkout from 4 to 6
- Bump actions/download-artifact from 4 to 7

Bumps [actions/download-artifact](https://github.com/actions/download-artifact) from 4 to 7.
- [Release notes](https://github.com/actions/download-artifact/releases)
- [Commits](https://github.com/actions/download-artifact/compare/v4...v7)

---
updated-dependencies:
- dependency-name: actions/download-artifact
  dependency-version: '7'
  dependency-type: direct:production
  update-type: version-update:semver-major
...

Signed-off-by: dependabot[bot] <support@github.com>
- Merge pull request #34 from lukehinds/dependabot/github_actions/actions/download-artifact-7

Bump actions/download-artifact from 4 to 7
- Silent Failure on Config Load Error

The get_sensitive_paths function has a silent failure which
could be used to conceal an attack

Signed-off-by: Luke Hinds <lukehinds@gmail.com>
- Formatting
- Merge pull request #43 from lukehinds/silent-fail

Silent Failure on Config Load Error

### Fixed

- Prevent path collision bypass in macOS sandbox

## [Unreleased]

### Security
- **Fixed macOS Seatbelt allowing all file reads** - Removed blanket `(allow file-read*)` that made `--allow` ineffective. Now uses explicit allow-listing matching Linux Landlock behavior.
- Implemented "Allow Discovery, Deny Content" strategy for sensitive paths:
  - `file-read-metadata` allowed (stat, existence checks)
  - `file-read-data` denied (actual content reads blocked)
- Narrowed `system*` permissions to only `system-socket`, `system-fsctl`, `system-info`
- Narrowed `sysctl*` to `sysctl-read` (blocks kernel parameter writes)
- Fixed sensitive path override logic to require explicit grants (granting `~` no longer bypasses `~/.ssh` protection)
- Fixed Seatbelt rule ordering so user-granted paths can delete files while global unlink is blocked
- Added `file-map-executable` permission (required for dyld)
- Expanded sensitive path protection:
  - Browser data (Chrome, Firefox, Safari, Edge, Arc, Brave)
  - macOS private data (Messages, Mail, Cookies, MobileSync)
  - Password managers (Keychains, 1Password, pass)
  - Shell configs and history files

### Changed
- Expanded `security-lists.toml` with comprehensive macOS system paths (dyld, ssl, locale, terminfo, system, user_library)
- Improved Seatbelt documentation with technical clarifications:
  - Added note about private `sandbox_init()` API stability
  - Clarified network filtering capabilities (IP filtering possible, domain filtering not)
  - Explained APFS firmlinks and path resolution on macOS 10.15+
  - Added common debugging issues table

## [0.1.0] - 2025-02-01

### Added
- Filesystem sandboxing with Landlock (Linux) and Seatbelt (macOS)
- Network blocking capability (`--net-block`)
- Profile system for reusable configurations
- `nono run` command for executing sandboxed processes
- `nono why` command for debugging path access
- `nono setup` command for system configuration
- Sensitive path protection (SSH keys, credentials, shell configs)
- Silent mode (`--silent`) for scripting
- Dry-run mode for testing configurations

### Security
- Blocks access to ~/.ssh, ~/.aws, ~/.gnupg, and other sensitive paths by default
- Uses OS-enforced sandboxing (no escape hatch)
- All child processes inherit sandbox restrictions

[Unreleased]: https://github.com/lukehinds/nono/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lukehinds/nono/releases/tag/v0.1.0
