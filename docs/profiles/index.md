# Profiles

!!! info "Coming Soon"
    The profile system is planned for Phase 2. This page documents the planned functionality.

Profiles are pre-configured capability sets for common tools and agents. Instead of specifying flags manually, you can use a profile that defines sensible defaults.

## Why Profiles?

Manually specifying capabilities for every tool is tedious and error-prone:

```bash
# Without profiles - verbose and easy to misconfigure
nono --allow . --read ~/.claude --read-file ~/.claude/config.json --net-allow -- claude
```

Profiles simplify this:

```bash
# With profiles - concise and auditable
nono --profile claude-code -- claude
```

## Profile Sources

Profiles can come from three sources, in order of precedence:

| Source | Location | Trust Level |
|--------|----------|-------------|
| CLI flags | Command line | Highest - explicit user intent |
| User profiles | `~/.config/nono/profiles/` | Medium - user-defined |
| Built-in profiles | Compiled into binary | Base - audited defaults |

CLI flags always override profile settings.

## Profile Format

Profiles use TOML format:

```toml
[meta]
name = "my-agent"
version = "1.0.0"
description = "Profile for my custom agent"

[filesystem]
allow = ["$WORKDIR"]
read = ["$HOME/.config/my-agent"]
write = []

[filesystem.files]
read = ["$HOME/.gitconfig"]
write = []

[network]
allow = true
```

## Environment Variables

Profiles support these environment variables:

| Variable | Expands To |
|----------|------------|
| `$WORKDIR` | Current working directory |
| `$HOME` | User's home directory |
| `$XDG_CONFIG_HOME` | XDG config directory (default: `~/.config`) |
| `$XDG_DATA_HOME` | XDG data directory (default: `~/.local/share`) |

## Using Profiles

```bash
# Use a built-in profile
nono --profile claude-code -- claude

# Use with additional flags (flags take precedence)
nono --profile claude-code --allow ./extra-dir -- claude

# List available profiles
nono --list-profiles
```

## Creating User Profiles

1. Create the profiles directory:
   ```bash
   mkdir -p ~/.config/nono/profiles
   ```

2. Create a TOML file:
   ```bash
   cat > ~/.config/nono/profiles/my-agent.toml << 'EOF'
   [meta]
   name = "my-agent"
   version = "1.0.0"

   [filesystem]
   allow = ["$WORKDIR"]

   [network]
   allow = false
   EOF
   ```

3. Use the profile:
   ```bash
   nono --profile my-agent -- my-agent-command
   ```

## Profile Verification

Built-in profiles are compiled into the nono binary and are cryptographically signed. User profiles can optionally be signed using minisign for integrity verification.

```bash
# Sign a profile
minisign -Sm my-profile.toml

# nono verifies signatures automatically when present
```

## Next Steps

- [Built-in Profiles](built-in.md) - Pre-configured profiles for popular tools
