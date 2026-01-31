# CLI Reference

Complete reference for all nono command-line flags.

## Synopsis

```bash
nono [OPTIONS] -- <COMMAND> [ARGS...]
```

## Directory Permissions

These flags grant recursive access to directories and all their contents.

### `--allow`, `-a`

Grant read and write access to a directory.

```bash
nono --allow ./project -- command
nono -a ./src -a ./tests -- command
```

Can be specified multiple times to allow multiple directories.

### `--read`, `-r`

Grant read-only access to a directory.

```bash
nono --read ./config -- command
nono -r /etc/myapp -- command
```

Useful for source code directories that shouldn't be modified.

### `--write`, `-w`

Grant write-only access to a directory.

```bash
nono --write ./output -- command
nono -w ./logs -- command
```

Useful for output directories where reading existing content isn't needed.

## File Permissions

These flags grant access to individual files only (non-recursive).

### `--allow-file`

Grant read and write access to a single file.

```bash
nono --allow-file ./database.sqlite -- command
```

### `--read-file`

Grant read-only access to a single file.

```bash
nono --read-file ./config.toml -- command
nono --read-file ~/.gitconfig -- command
```

### `--write-file`

Grant write-only access to a single file.

```bash
nono --write-file ./output.log -- command
```

## Network Control

### `--net-allow`

Enable all outbound network access. Network is blocked by default.

```bash
nono --allow . --net-allow -- curl https://api.example.com
```

!!! warning "All or Nothing"
    Currently network access is binary - either all outbound connections are allowed, or none are. Per-host filtering is planned for a future release.

## Operational Flags

### `--dry-run`

Show what capabilities would be granted without actually executing the command or applying the sandbox.

```bash
nono --allow . --read /etc --net-allow --dry-run -- my-agent
```

Output:
```
Capabilities that would be granted:
  [rw] /Users/luke/project
  [r-] /etc
  [net] allowed

Would execute: my-agent
```

### `--verbose`, `-v`

Increase logging verbosity. Can be specified multiple times.

| Flag | Level | Output |
|------|-------|--------|
| (none) | Error | Only errors |
| `-v` | Warn | Warnings and errors |
| `-vv` | Info | Informational messages |
| `-vvv` | Debug | Detailed debug output |

```bash
nono -vvv --allow . -- command
```

### `--config`, `-c`

Specify a configuration file path.

```bash
nono --config ./nono.toml -- command
```

!!! note "Coming Soon"
    Configuration file support is planned for a future release.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command executed successfully |
| 1 | nono error (invalid arguments, sandbox failure) |
| * | Exit code from the executed command |

## Path Resolution

All paths are canonicalized before the sandbox is applied:

- Relative paths are resolved to absolute paths
- Symlinks are followed and resolved
- Parent directory references (`..`) are resolved

This prevents symlink escape attacks where a malicious agent creates a symlink pointing outside the allowed directory.

```bash
# These are equivalent if ./project resolves to /home/user/project
nono --allow ./project -- command
nono --allow /home/user/project -- command
```

## Combining Flags

Flags can be combined freely:

```bash
nono \
  --allow ./project \
  --read ~/.config/myapp \
  --write ./logs \
  --read-file ~/.gitconfig \
  --net-allow \
  -vv \
  -- my-agent --arg1 --arg2
```

## Examples

See the [Examples](examples.md) page for common usage patterns.
