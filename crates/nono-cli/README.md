# nono-cli

CLI for capability-based sandboxing using Landlock (Linux) and Seatbelt (macOS).

## Installation

### Homebrew (macOS)

```bash
brew tap always-further/nono
brew install nono
```

### Cargo

```bash
cargo install nono-cli
```

### From Source

```bash
git clone https://github.com/always-further/nono
cd nono
cargo build --release
```

## Usage

```bash
# Allow read+write to current directory
nono run --allow-cwd -- command

# Separate read and write permissions
nono run --read ./src --write ./output -- cargo build

# Multiple paths
nono run --allow ./project-a --allow ./project-b -- command

# Block network access
nono run --allow-cwd --net-block -- command

# Use a built-in profile
nono run --profile claude-code -- claude

# Start an interactive shell inside the sandbox
nono shell --allow-cwd

# Check why a path would be blocked
nono why --path ~/.ssh/id_rsa --op read

# Dry run (show what would be sandboxed)
nono run --allow-cwd --dry-run -- command
```

## Built-in Profiles

| Profile | Command |
|---------|---------|
| Claude Code | `nono run --profile claude-code -- claude` |
| OpenCode | `nono run --profile opencode -- opencode` |
| OpenClaw | `nono run --profile openclaw -- openclaw gateway` |

## Rollback

Rollback snapshots automatically exclude known regenerable directories (`.git`, `target`, `node_modules`, etc.) and any directory with more than 10,000 files to prevent hangs on large projects.

```bash
# Zero-flag usage — auto-excludes large directories
nono run --rollback --allow-cwd -- npm test

# Force-include an auto-excluded directory
nono run --rollback --rollback-include target -- cargo build

# Exclude a custom directory from rollback
nono run --rollback --rollback-exclude vendor -- go test ./...

# Include everything (may be slow on large projects)
nono run --rollback --rollback-all -- cargo test

# Disable rollback entirely
nono run --no-rollback --allow-cwd -- npm test
```

> **Note:** Rollback exclusion does not affect sandbox permissions. Excluded directories are still sandboxed — they just can't be rolled back.

## Command Blocking

Dangerous commands are blocked by default:

| Category | Commands |
|----------|----------|
| File destruction | `rm`, `rmdir`, `shred`, `srm` |
| Disk operations | `dd`, `mkfs`, `fdisk`, `parted` |
| Permission changes | `chmod`, `chown`, `chgrp` |
| Privilege escalation | `sudo`, `su`, `doas` |

Override with `--allow-command`:

```bash
nono run --allow-cwd --allow-command rm -- rm ./temp-file.txt
```

## Documentation

- [Full Documentation](https://docs.nono.sh)
- [Client Guides](https://docs.nono.sh/clients)

## License

Apache-2.0
