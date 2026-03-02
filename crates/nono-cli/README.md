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

## Command Blocking

Dangerous commands are blocked by default:

| Category | Commands |
|----------|----------|
| File destruction | `rm`, `rmdir`, `shred`, `srm` |
| Disk operations | `dd`, `mkfs`, `fdisk`, `parted` |
| Permission changes | `chmod`, `chown`, `chgrp` |
| Privilege escalation | `sudo`, `su`, `doas` |

Override per invocation with `--allow-command`, or permanently in a profile with `allowed_commands`:

```bash
# Per invocation
nono run --allow-cwd --allow-command rm -- rm ./temp-file.txt

# Via profile
cat > ~/.config/nono/profiles/my-profile.json << 'EOF'
{
  "meta": { "name": "my-profile" },
  "filesystem": { "allow": ["/tmp"] },
  "security": { "allowed_commands": ["rm"] }
}
EOF
nono run --profile my-profile -- rm /tmp/old-file.txt
```

## Documentation

- [Full Documentation](https://docs.nono.sh)
- [Client Guides](https://docs.nono.sh/clients)

## License

Apache-2.0
