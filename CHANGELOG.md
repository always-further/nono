# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
