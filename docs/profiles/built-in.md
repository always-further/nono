# Built-in Profiles

!!! info "Coming Soon"
    Built-in profiles are planned for Phase 2. This page documents the planned profiles.

nono ships with built-in profiles for popular AI coding agents. These profiles are compiled into the binary and provide audited, sensible defaults.

## claude-code

Profile for [Anthropic Claude Code](https://claude.ai/code) CLI.

```toml
[meta]
name = "claude-code"
version = "1.0.0"
description = "Anthropic Claude Code CLI"

[filesystem]
allow = ["$WORKDIR"]
read = ["$HOME/.claude"]

[filesystem.files]
read = [
  "$HOME/.gitconfig",
  "$HOME/.claude/config.json"
]

[network]
allow = true
```

**Usage:**
```bash
nono --profile claude-code -- claude
```

**Grants:**

- Read+write access to current working directory
- Read access to `~/.claude` configuration
- Read access to `.gitconfig`
- Full network access (required for API calls)

---

## opencode

Profile for [OpenCode](https://github.com/opencode-ai/opencode) agent.

```toml
[meta]
name = "opencode"
version = "1.0.0"
description = "OpenCode AI agent"

[filesystem]
allow = ["$WORKDIR"]
read = ["$XDG_CONFIG_HOME/opencode"]

[network]
allow = true
```

**Usage:**
```bash
nono --profile opencode -- opencode
```

**Grants:**

- Read+write access to current working directory
- Read access to OpenCode configuration
- Full network access

---

## openclaw

Profile for [OpenClaw](https://github.com/openclaw) messaging gateway.

```toml
[meta]
name = "openclaw"
version = "1.0.0"
description = "OpenClaw messaging gateway"

[filesystem]
allow = ["$WORKDIR"]
read = ["$XDG_CONFIG_HOME/openclaw"]

[network]
allow = true
```

**Usage:**
```bash
nono --profile openclaw -- openclaw
```

**Grants:**

- Read+write access to current working directory
- Read access to OpenClaw configuration
- Full network access

---

## Requesting New Profiles

If you'd like a built-in profile for a tool not listed here:

1. Open an issue on the [nono GitHub repository](https://github.com/lukehinds/nono/issues)
2. Include:
   - Tool name and repository URL
   - Required filesystem access patterns
   - Network requirements
   - Any special considerations

Built-in profiles are reviewed for security before inclusion.

## Overriding Built-in Profiles

CLI flags always take precedence over profile settings:

```bash
# Use claude-code profile but deny network
nono --profile claude-code --no-net -- claude

# Add extra directory access
nono --profile claude-code --allow ~/other-project -- claude
```

You can also create a user profile with the same name to override a built-in profile entirely.
