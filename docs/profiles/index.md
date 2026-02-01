# Profiles

Profiles are pre-configured capability sets for common tools and agents. Instead of specifying flags manually, you can use a profile that defines sensible defaults.

## Why Profiles?

Manually specifying capabilities for every tool is tedious and error-prone:

```bash
# Without profiles - verbose and easy to misconfigure
nono run --allow . --read ~/.claude --read-file ~/.claude/config.json -- claude
```

Profiles simplify this:

```bash
# With profiles - concise and auditable
nono run --profile claude-code -- claude
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
block = false  # Network allowed by default; set to true to block

# See "Secrets Section" below for configuring secrets
```

### Secrets Section

The `[secrets]` section maps keystore account names to environment variable names. Secrets are loaded from the system keystore (macOS Keychain / Linux Secret Service) before the sandbox is applied, then injected as environment variables.

```toml
[secrets]
openai_api_key = "OPENAI_API_KEY"
database_url = "DATABASE_URL"
```

To use secrets from a profile, add the `--secrets` flag:

```bash
nono run --profile my-agent --secrets -- my-command
```

See [Secrets Management](../usage/secrets.md) for details on storing secrets in the keystore.

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
nono run --profile claude-code -- claude

# Use with additional flags (flags take precedence)
nono run --profile claude-code --allow ./extra-dir -- claude

# List available profiles
nono run --list-profiles
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
   block = true  # Block all network access
   EOF
   ```

3. Use the profile:
   ```bash
   nono run --profile my-agent -- my-agent-command
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
