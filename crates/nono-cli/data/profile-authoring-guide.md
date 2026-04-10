# nono Profile Authoring Guide

This guide is designed for LLM agents helping users create custom nono profiles. It covers the full profile schema, common patterns, and validation workflow.

## 1. Profile File Location

User profiles live at `~/.config/nono/profiles/<name>.json`.

Profile names must be alphanumeric with hyphens only. No leading or trailing hyphens.

Valid: `my-agent`, `ci-build`, `dev2`
Invalid: `-leading`, `trailing-`, `has spaces`, `special_chars!`

User profiles take precedence over built-in profiles of the same name.

## 2. Minimal Profile Example

```json
{
  "meta": {
    "name": "my-agent",
    "description": "Profile for my agent"
  },
  "security": {
    "groups": []
  },
  "workdir": {
    "access": "readwrite"
  }
}
```

## 3. Section Reference

### meta

| Field         | Type   | Required | Description              |
|---------------|--------|----------|--------------------------|
| `name`        | string | yes      | Profile name             |
| `version`     | string | no       | Semver version string    |
| `description` | string | no       | Human-readable summary   |
| `author`      | string | no       | Author name              |

### extends

Inherit from another profile by name:

```json
{
  "extends": "default"
}
```

- Inheritance chain max depth: 10.
- Scalar fields: child overrides base.
- Array fields (`groups`, `filesystem.*`, `policy.*`, `allow_domain`, `open_port`, `listen_port`, `rollback.*`, `upstream_bypass`): child values are appended to base values and deduplicated. To remove inherited entries, use `policy.exclude_groups` for groups; there is no mechanism to remove inherited filesystem paths.
- Map fields (`env_credentials`, `hooks`, `custom_credentials`): child entries are merged into base; child keys override matching base keys.
- `network_profile` supports three-state inheritance via `InheritableValue`: absent = inherit base value, `null` = explicitly clear, string = override. This is the only field that supports null-clearing.
- `open_urls`: if the child provides the field (even as `{}`), it replaces the base entirely. If absent, the base value is inherited. Setting to `null` in JSON is equivalent to omitting it (both inherit the base).
- `workdir`: child overrides base unless child is `"none"` (which inherits the base value instead).

### security

| Field                 | Type            | Default      | Description |
|-----------------------|-----------------|--------------|-------------|
| `groups`              | array of string | `[]`         | Policy group names from `policy.json`. Use `nono policy groups` to list available groups. |
| `allowed_commands`    | array of string | `[]`         | Commands to allow even when blocked by deny groups (e.g., `["rm"]`). |
| `signal_mode`         | string          | `"isolated"` | One of: `"isolated"`, `"allow_same_sandbox"`, `"allow_all"`. |
| `process_info_mode`   | string          | `"isolated"` | One of: `"isolated"`, `"allow_same_sandbox"`, `"allow_all"`. |
| `ipc_mode`            | string          | `"shared_memory_only"` | One of: `"shared_memory_only"`, `"full"`. Use `"full"` for multiprocessing (enables POSIX semaphores). macOS only. |
| `capability_elevation`| boolean         | `false`      | Enable runtime capability elevation via seccomp-notify. Linux only. |
| `wsl2_proxy_policy`  | string          | `"error"`    | WSL2 only. Controls behavior when proxy-only network mode cannot be kernel-enforced. `"error"`: refuse to run (fail-secure). `"insecure_proxy"`: allow degraded execution where credential proxy runs but child is not prevented from bypassing it. See [WSL2 docs](https://nono.sh/docs/cli/internals/wsl2). |

### filesystem

| Field        | Type            | Description |
|--------------|-----------------|-------------|
| `allow`      | array of string | Directories with read+write access. |
| `read`       | array of string | Directories with read-only access. |
| `write`      | array of string | Directories with write-only access. |
| `allow_file` | array of string | Single files with read+write access. |
| `read_file`  | array of string | Single files with read-only access. |
| `write_file` | array of string | Single files with write-only access. |

All path fields support variable expansion (see Section 6).

### workdir

| Field    | Type   | Default  | Description |
|----------|--------|----------|-------------|
| `access` | string | `"none"` | One of: `"none"`, `"read"`, `"write"`, `"readwrite"`. Controls automatic CWD sharing with the sandboxed process. |

### policy (patches)

Provides subtractive and additive composition on top of inherited groups and filesystem configuration.

| Field                | Type            | Description |
|----------------------|-----------------|-------------|
| `exclude_groups`     | array of string | Group names to remove from the resolved group set, including inherited defaults. |
| `add_allow_read`     | array of string | Additional read-only path grants. |
| `add_allow_write`    | array of string | Additional write-only path grants. |
| `add_allow_readwrite`| array of string | Additional read+write path grants. |
| `add_deny_access`    | array of string | Additional deny paths. |
| `add_deny_commands`  | array of string | Command names (basename only) to block. Blocks execution of the named binaries regardless of where they are installed. Checked before the sandbox enforces filesystem rules. |
| `override_deny`      | array of string | Paths to exempt from deny groups. Each path must also be granted via `filesystem` or `add_allow_*`. Does not implicitly grant access; only removes the deny rule. |

### network

| Field                   | Type                              | Default  | Description |
|-------------------------|-----------------------------------|----------|-------------|
| `block`                 | boolean                           | `false`  | Block all network access. |
| `network_profile`       | string or null                    | inherit  | Name from `network-policy.json` for proxy filtering. Set to `null` to clear inherited value. |
| `allow_domain`          | array of string                   | `[]`     | Additional domains to allow through the proxy. Aliases: `proxy_allow`, `allow_proxy`. |
| `credentials`           | array of string                   | `[]`     | Credential services to enable via reverse proxy. Alias: `proxy_credentials`. |
| `open_port`             | array of integer                  | `[]`     | Localhost TCP ports for bidirectional IPC. Aliases: `port_allow`, `allow_port`. |
| `listen_port`           | array of integer                  | `[]`     | TCP ports the sandboxed child may listen on. |
| `custom_credentials`    | map of string to credential def   | `{}`     | Custom credential route definitions (see below). |
| `upstream_proxy`        | string                            | `null`   | Enterprise proxy address (`host:port`). Alias: `external_proxy`. |
| `upstream_bypass`       | array of string                   | `[]`     | Hosts to bypass the upstream proxy. Supports `*.` wildcard suffixes. Alias: `external_proxy_bypass`. |

#### custom_credentials entry

Define a custom reverse proxy credential route for services not in `network-policy.json`:

```json
{
  "upstream": "https://api.example.com",
  "credential_key": "example_api_key",
  "inject_mode": "header",
  "inject_header": "Authorization",
  "credential_format": "Bearer {}"
}
```

| Field               | Type   | Required    | Description |
|---------------------|--------|-------------|-------------|
| `upstream`          | string | yes         | Upstream URL. Must be HTTPS (HTTP only for loopback). |
| `credential_key`    | string | yes         | Keystore account name, `op://` URI, or `apple-password://` URI. |
| `inject_mode`       | string | no          | One of: `"header"` (default), `"url_path"`, `"query_param"`, `"basic_auth"`. |
| `inject_header`     | string | header mode | HTTP header name. Default: `"Authorization"`. |
| `credential_format` | string | header mode | Format string with `{}` placeholder. Default: `"Bearer {}"`. |
| `path_pattern`      | string | url_path    | Pattern to match in URL path. Use `{}` for placeholder. |
| `path_replacement`  | string | url_path    | Replacement pattern. Defaults to `path_pattern`. |
| `query_param_name`  | string | query_param | Query parameter name for credential injection. |
| `env_var`           | string | URI keys    | Environment variable name for SDK API key. Required when `credential_key` is a URI. |

### env_credentials (alias: secrets)

Maps keystore account names to environment variable names. Secrets are loaded from the system keystore (macOS Keychain / Linux Secret Service) under the service name "nono".

```json
{
  "env_credentials": {
    "openai_api_key": "OPENAI_API_KEY",
    "op://vault/item/field": "ANTHROPIC_API_KEY"
  }
}
```

Supported key formats:
- Bare keystore account name: `"openai_api_key"`
- 1Password URI: `"op://vault/item/field"`
- Apple Passwords URI: `"apple-password://account/name"`
- Environment reference: `"env://EXISTING_VAR"`

### hooks

Map of application name to hook configuration:

```json
{
  "hooks": {
    "claude-code": {
      "event": "PostToolUseFailure",
      "matcher": "Read|Write|Edit|Bash",
      "script": "nono-hook.sh"
    }
  }
}
```

| Field     | Type   | Description |
|-----------|--------|-------------|
| `event`   | string | Trigger event name. |
| `matcher` | string | Regex for tool name matching. |
| `script`  | string | Script filename from embedded hooks. |

### rollback (alias: undo)

| Field              | Type            | Description |
|--------------------|-----------------|-------------|
| `exclude_patterns` | array of string | Path component patterns to exclude from snapshots. |
| `exclude_globs`    | array of string | Glob patterns for filename exclusion. |

### open_urls

Controls supervisor-delegated URL opening (e.g., OAuth2 login flows).

| Field             | Type            | Default | Description |
|-------------------|-----------------|---------|-------------|
| `allow_origins`   | array of string | `[]`    | Allowed URL origins (scheme + host, e.g., `"https://console.anthropic.com"`). |
| `allow_localhost`  | boolean         | `false` | Allow `http://localhost` and `http://127.0.0.1` URLs. |

To replace inherited URL-opening permissions, provide `open_urls` with an explicit empty object: `"open_urls": { "allow_origins": [], "allow_localhost": false }`. Omitting `open_urls` inherits the base profile's configuration.

## 4. Common Patterns

### Developer profile (extending default)

```json
{
  "extends": "default",
  "meta": {
    "name": "developer",
    "description": "General development"
  },
  "workdir": {
    "access": "readwrite"
  },
  "filesystem": {
    "read": ["$HOME/.config"]
  }
}
```

### CI profile (locked down)

```json
{
  "meta": {
    "name": "ci-build",
    "description": "CI build environment"
  },
  "security": {
    "groups": ["deny_credentials", "deny_ssh_keys"]
  },
  "workdir": {
    "access": "readwrite"
  },
  "network": {
    "block": true
  }
}
```

### Agent with API access

```json
{
  "extends": "default",
  "meta": {
    "name": "api-agent",
    "description": "Agent with API access"
  },
  "workdir": {
    "access": "readwrite"
  },
  "env_credentials": {
    "openai_api_key": "OPENAI_API_KEY"
  },
  "network": {
    "network_profile": "standard"
  }
}
```

### Linux host compatibility

On Linux, the built-in `default` profile keeps host runtime, sysfs, and shared temp reads out of the base policy. If your tool needs access to paths like `/run`, `/var/run`, `/sys`, or `/tmp`, extend the built-in compatibility preset:

```json
{
  "extends": "linux-host-compat",
  "meta": {
    "name": "linux-desktop-agent",
    "description": "Agent with Linux host runtime compatibility"
  },
  "workdir": {
    "access": "readwrite"
  }
}
```

### Profile with deny overrides

When a deny group blocks a path you need access to, use `override_deny` together with an explicit grant:

```json
{
  "extends": "default",
  "meta": {
    "name": "shell-config-reader",
    "description": "Needs to read shell configs"
  },
  "workdir": {
    "access": "readwrite"
  },
  "filesystem": {
    "read_file": ["$HOME/.bashrc", "$HOME/.zshrc"]
  },
  "policy": {
    "override_deny": ["$HOME/.bashrc", "$HOME/.zshrc"]
  }
}
```

### Denying specific project files

Block access to a file in the working directory while keeping the rest accessible. Use `$WORKDIR` to reference the current working directory — relative paths like `./` are not expanded:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-dotenv",
    "description": "Claude Code without .env access"
  },
  "policy": {
    "add_deny_access": ["$WORKDIR/.env"]
  }
}
```

**macOS**: This works directly. Seatbelt can deny a specific file within an allowed directory.

**Linux**: Landlock is strictly allow-list and cannot deny a child of an allowed parent. Use supervised mode instead, which intercepts file opens via seccomp-notify and checks them against the deny list before granting access:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-dotenv",
    "description": "Claude Code without .env access"
  },
  "security": {
    "capability_elevation": true
  },
  "policy": {
    "add_deny_access": ["$WORKDIR/.env"]
  }
}
```

With `capability_elevation` enabled, nono runs in supervised mode where every file access outside the initial grant set is trapped and evaluated. The deny list is checked before the supervisor prompts for approval, so denied paths are blocked regardless of platform.

### Blocking container access (Docker, Podman, kubectl)

Use `add_deny_access` together with `add_deny_commands` for defense-in-depth when you want to prevent an agent from reaching the Docker daemon or similar container runtimes:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-docker",
    "description": "Claude Code without Docker access"
  },
  "policy": {
    "add_deny_access": ["/var/run/docker.sock"],
    "add_deny_commands": ["docker", "docker-compose", "podman", "kubectl"]
  }
}
```

On macOS, `add_deny_access` on a socket path also emits a Seatbelt `network-outbound` deny — Seatbelt treats `connect(2)` as a network operation so a file deny alone won't block it. `add_deny_commands` blocks the CLI tools as defense-in-depth, catching cases where an agent reaches the daemon through a forwarded or alternate socket path. Both are visible in `nono policy show` under **Policy patches**.

### Allowing parent-of-protected-root grants (macOS only)

By default, granting a parent directory of `~/.nono` (e.g. `--allow ~`) is rejected because it would expose nono's internal state. On macOS, Seatbelt can express deny-within-allow rules, so this restriction can be relaxed when the profile opts in with `allow_parent_of_protected`:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "home-access",
    "description": "Claude Code with full home directory access"
  },
  "allow_parent_of_protected": true
}
```

When `allow_parent_of_protected` is `true` and the platform is macOS, nono permits the parent grant and emits Seatbelt deny rules that protect `~/.nono` from reads and writes. On Linux this field is ignored — Landlock cannot deny a child of an allowed parent, so the pre-flight check always rejects parent-of-protected grants.

### Profile with group exclusion

Remove an inherited deny group that is too restrictive for your use case:

```json
{
  "extends": "default",
  "meta": {
    "name": "browser-tool",
    "description": "Needs browser data access"
  },
  "workdir": {
    "access": "readwrite"
  },
  "policy": {
    "exclude_groups": ["deny_browser_data_macos", "deny_browser_data_linux"]
  }
}
```

### Profile with custom credential routing

```json
{
  "extends": "default",
  "meta": {
    "name": "telegram-bot",
    "description": "Telegram bot with credential injection"
  },
  "workdir": {
    "access": "readwrite"
  },
  "network": {
    "custom_credentials": {
      "telegram": {
        "upstream": "https://api.telegram.org",
        "credential_key": "telegram_bot_token",
        "inject_mode": "url_path",
        "path_pattern": "/bot{}/",
        "path_replacement": "/bot{}/"
      }
    },
    "credentials": ["telegram"]
  }
}
```

## 5. Validation

Run these commands to verify a profile:

```
nono policy validate <path>       # Check a profile file for errors
nono policy show <name>           # Show the fully resolved profile (after inheritance)
nono policy groups                # List available security groups
nono policy diff <a> <b>          # Compare two profiles
```

## 6. Variable Expansion

The following variables are expanded in all path fields (`filesystem.*`, `policy.add_allow_*`, `policy.add_deny_access`, `policy.override_deny`).

| Variable           | Expands to |
|--------------------|------------|
| `$HOME`            | User's home directory |
| `$WORKDIR`         | Working directory (from `--workdir` flag or cwd) |
| `$TMPDIR`          | System temporary directory |
| `$UID`             | Current user ID |
| `$XDG_CONFIG_HOME` | XDG config directory (default: `$HOME/.config`) |
| `$XDG_DATA_HOME`   | XDG data directory (default: `$HOME/.local/share`) |
| `$XDG_STATE_HOME`  | XDG state directory (default: `$HOME/.local/state`) |
| `$XDG_CACHE_HOME`  | XDG cache directory (default: `$HOME/.cache`) |
| `$XDG_RUNTIME_DIR` | XDG runtime directory (no default; left unexpanded when unset) |

Always use these variables instead of hardcoded absolute paths to keep profiles portable across machines and users.

## 7. Key Rules

- A profile with no `security.groups` has no deny rules. Always include appropriate deny groups for untrusted workloads.
- `override_deny` only removes the deny rule. It does not grant access. You must also add the path via `filesystem` or `policy.add_allow_*`.
- `exclude_groups` removes groups from the resolved set. This weakens the sandbox. Use it only when you understand which protections you are removing.
- `extends` chains resolve recursively up to depth 10. Circular inheritance is an error.
- Platform-specific groups (suffix `_macos` or `_linux`) are filtered at resolution time. Include both variants for cross-platform profiles.
- `network.block: true` blocks all network access. It cannot be combined with proxy settings.
- `custom_credentials` upstream URLs must use HTTPS. HTTP is only accepted for loopback addresses (localhost, 127.0.0.1, ::1).
