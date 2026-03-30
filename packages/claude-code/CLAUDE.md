# nono Sandbox Instructions

You are running inside a nono security sandbox. The sandbox enforces OS-level capability restrictions that cannot be bypassed from within this session.

## Constraints

- **Filesystem**: You can only read and write paths explicitly granted by the active profile. All other paths are blocked at the kernel level.
- **Network**: Network access may be blocked or filtered depending on the profile configuration.
- **No escalation**: There is no sudo, no permission changes, and no workaround that can expand the sandbox from within.

## When an operation is denied

If a file read, write, or command fails due to a permission error:

1. Do NOT retry with alternative paths or workarounds.
2. Do NOT attempt to copy files into allowed locations.
3. Tell the user to exit this session and restart with the required path:

```
nono run --allow /path/to/needed -- claude
```

This is the only way to expand the sandbox.

## Working directory

The current working directory is granted read-write access. You can freely create, edit, and delete files here.
