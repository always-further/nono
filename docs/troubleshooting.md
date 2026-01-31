# Troubleshooting

Common issues and solutions when using nono.

## Permission Denied Errors

### Symptom

Command fails with "Permission denied" or "Operation not permitted" errors.

### Diagnosis

1. **Check what access was granted**:
   ```bash
   nono --allow . --dry-run -- command
   ```

2. **Check environment variables inside the sandbox**:
   ```bash
   nono --allow . -- sh -c 'echo "Allowed: $NONO_ALLOWED"'
   nono --allow . -- sh -c 'echo "Blocked: $NONO_BLOCKED"'
   ```

3. **Run with verbose logging**:
   ```bash
   nono -vvv --allow . -- command
   ```

### Common Causes

| Cause | Solution |
|-------|----------|
| Path not in allowed list | Add path with `--allow`, `--read`, or `--write` |
| Sensitive path blocked | These paths cannot be granted (see below) |
| Relative path resolved differently | Use absolute paths |
| Symlink target outside sandbox | Grant access to the symlink target |

### Sensitive Paths

These paths are always blocked, even if a parent directory is allowed:

- `~/.ssh/` - SSH keys
- `~/.aws/` - AWS credentials
- `~/.gnupg/` - GPG keys
- `~/.kube/` - Kubernetes config
- `~/.docker/` - Docker credentials
- Shell history files
- Shell configuration files

**Why?** These paths commonly contain secrets that an AI agent should never access.

---

## Network Connection Failed

### Symptom

Commands like `curl`, `wget`, or API calls fail with connection errors.

### Cause

Network is blocked by default.

### Solution

Add `--net-allow` to enable network access:

```bash
nono --allow . --net-allow -- curl https://example.com
```

---

## Command Not Found

### Symptom

```
nono: command not found
```

or

```
error: No such file or directory: my-command
```

### Solutions

1. **nono not in PATH**:
   ```bash
   # Add to PATH
   export PATH="$PATH:/path/to/nono/target/release"
   ```

2. **Target command not in PATH**:
   ```bash
   # Use absolute path
   nono --allow . -- /usr/local/bin/my-command

   # Or ensure PATH is set correctly
   nono --allow . -- sh -c 'which my-command'
   ```

---

## Sandbox Initialization Failed

### Symptom

```
Error: Sandbox initialization failed: ...
```

### Linux (Landlock)

1. **Check kernel version**:
   ```bash
   uname -r
   # Must be 5.13+ for Landlock
   ```

2. **Check Landlock is enabled**:
   ```bash
   cat /sys/kernel/security/lsm
   # Should include "landlock"
   ```

3. **Enable Landlock** (if missing):
   Add `lsm=landlock,...` to kernel boot parameters

### macOS (Seatbelt)

1. **Check macOS version**:
   ```bash
   sw_vers
   # Should be 10.15 (Catalina) or later
   ```

2. **Check for SIP issues**:
   Some system integrity protection settings can interfere. This is rare.

---

## Dry Run Shows Different Paths

### Symptom

Paths in dry-run output don't match what you specified.

### Explanation

nono canonicalizes all paths:

- Relative paths become absolute
- Symlinks are resolved
- `..` and `.` are normalized

This is intentional to prevent symlink escape attacks.

### Example

```bash
$ pwd
/home/user/project

$ nono --allow . --dry-run -- command
Capabilities:
  [rw] /home/user/project    # Resolved from "."
```

---

## Child Process Doesn't Inherit Sandbox

### Symptom

You expect a child process to be sandboxed but it seems to have more access.

### This Shouldn't Happen

Child processes always inherit sandbox restrictions. If you're seeing this:

1. **Verify the parent is sandboxed**:
   ```bash
   nono --allow . -- sh -c 'echo $NONO_ACTIVE'
   # Should print "1"
   ```

2. **Check if you're testing correctly**:
   ```bash
   # Parent and child are BOTH sandboxed
   nono --allow . -- sh -c 'sh -c "cat /etc/passwd"'
   # Should fail if /etc is not allowed
   ```

If you have a reproducible case where a child escapes the sandbox, please report it as a security issue.

---

## Performance Issues

### Symptom

Commands run slower under nono.

### Explanation

There is minimal overhead from sandbox initialization (microseconds). If you're seeing significant slowdowns:

1. **First run may be slower** due to path canonicalization
2. **Many file operations** may show overhead from kernel permission checks

### Solutions

- Grant access to larger directories instead of many individual files
- Use `--read` for directories that don't need write access (slightly faster path)

---

## Using Environment Variables for Debugging

When running inside nono, these variables are set:

```bash
# Check if running under nono
nono --allow . -- sh -c 'echo $NONO_ACTIVE'

# See what paths are allowed
nono --allow . -- sh -c 'echo $NONO_ALLOWED'

# See what paths are blocked (sensitive)
nono --allow . -- sh -c 'echo $NONO_BLOCKED'

# Check network status
nono --allow . -- sh -c 'echo $NONO_NET'

# Get help text for requesting more access
nono --allow . -- sh -c 'echo $NONO_HELP'
```

---

## Platform-Specific Issues

### macOS: "killed: 9" or Immediate Termination

This usually means the Seatbelt profile was malformed. Run with `-vvv` to see the generated profile:

```bash
nono -vvv --allow . -- command
```

### Linux: "Landlock not supported"

Your kernel may not have Landlock enabled. Check:

```bash
# Verify kernel version
uname -r

# Check LSM list
cat /sys/kernel/security/lsm
```

### Linux: Network Restrictions Not Working

Network filtering requires Landlock ABI v4 (kernel 6.7+):

```bash
# Check kernel version
uname -r

# If < 6.7, network filtering is unavailable via Landlock
```

---

## Getting Help

If you're still stuck:

1. **Search existing issues**: [GitHub Issues](https://github.com/lukehinds/nono/issues)
2. **Open a new issue** with:
   - nono version (`nono --version`)
   - OS and kernel version
   - Full command that failed
   - Error message
   - Output of `nono --dry-run` with same flags
