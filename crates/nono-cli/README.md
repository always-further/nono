# nono-cli

CLI for capability-based sandboxing using Landlock (Linux) and Seatbelt (macOS).

## Installation

### Homebrew (macOS/Linux)

```bash
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
nono run --allow . -- command

# Separate read and write permissions
nono run --read ./src --write ./output -- cargo build

# Multiple paths
nono run --allow ./project-a --allow ./project-b -- command

# Block network access
nono run --allow-cwd --block-net -- command

# Use a built-in profile
nono run --profile claude-code -- claude

# Use the Codex profile
nono run --profile codex -- codex

# Keep a profile but temporarily allow unrestricted network
nono run --profile claude-code --allow-net -- claude

# Start an interactive shell inside the sandbox
nono shell --allow .

# Check why a path would be blocked
nono why --path ~/.ssh/id_rsa --op read

# Dry run (show what would be sandboxed)
nono run --allow-cwd --dry-run -- command
```

## Themes

The CLI supports named output themes for banners, summaries, warnings, and status text.

Available themes: `mocha`, `latte`, `frappe`, `macchiato`, `tokyo-night`, `minimal`

```bash
# Per invocation
nono --theme tokyo-night run --allow-cwd -- claude

# Environment variable
export NONO_THEME=latte

# Config file
# ~/.config/nono/config.toml
# [ui]
# theme = "frappe"
```

Precedence is: CLI flag, then `NONO_THEME`, then config file, then the default `mocha`.

## Built-in Profiles

| Profile | Command |
|---------|---------|
| Claude Code | `nono run --profile claude-code -- claude` |
| Codex | `nono run --profile codex -- codex` |
| OpenCode | `nono run --profile opencode -- opencode` |
| OpenClaw | `nono run --profile openclaw -- openclaw gateway` |
| Swival | `nono run --profile swival -- swival` |

## Profile Inheritance

User profiles can extend built-in or other user profiles with the `extends` field. The child inherits all settings from the base and only declares additions or overrides.

```json
{
  "extends": "claude-code",
  "meta": { "name": "my-claude" },
  "filesystem": {
    "allow": ["/opt/my-tools"],
    "read": ["/etc/my-app"]
  }
}
```

You can also extend multiple profiles at once. Bases are merged left-to-right, then the child overrides:

```json
{
  "extends": ["claude-code", "node-dev"],
  "meta": { "name": "my-fullstack" },
  "filesystem": { "allow": ["/opt/extra"] }
}
```

Save to `~/.config/nono/profiles/my-claude.json`, then:

```bash
nono run --profile my-claude -- claude
```

### Merge semantics

- **Lists** (filesystem paths, security groups, rollback patterns): appended and deduplicated
- **HashMaps** (credentials, hooks): merged, child wins on same key
- **Booleans** (`network.block`, `interactive`): OR — either activates
- **Scalars** (`meta`): child overrides
- **Nullable scalars** (`network_profile`): absent inherits, `null` clears, string overrides

When extending multiple bases, they are merged left-to-right using the same rules. The child then overrides the accumulated base.

### Chaining

Profiles can form chains (up to 10 levels deep). Circular dependencies are detected and rejected. Shared transitive bases are deduplicated.

```
my-dev.json → team-base.json → claude-code (built-in)
```

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
- [Client Guides](https://docs.nono.sh/cli/clients/quickstart)

## License

Apache-2.0
