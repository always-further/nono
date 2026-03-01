# DESIGN: Rollback Preflight and Directory Failsafe

Addresses: [#160](https://github.com/always-further/nono/issues/160)

## Problem

When `--allow-cwd` (or `--allow`, `--read`, `--write` with a directory) points at a
directory containing large subtrees (`.git/`, `target/`, `node_modules/`), nono hangs
during rollback baseline creation. The user sees no output and must force-kill the
process.

The hang is **not** in sandbox enforcement — both Seatbelt (macOS) and Landlock
(Linux) operate on directory-level subpath rules and are O(1). The hang occurs in the
rollback snapshot system:

1. `SnapshotManager::create_baseline()` calls `walk_and_store()`, which uses `WalkDir`
   to enumerate every file under tracked writable directories, hash each file's
   contents with SHA-256, and copy it to the content-addressable object store.

2. `collect_atomic_temp_files()` performs a second full `WalkDir` walk.

3. A compounding bug: the `ExclusionFilter` is applied **per-file after traversal**,
   not at directory-entry time. Even directories that are fully excluded (like `.git/`)
   are descended into — `WalkDir` enters `.git/objects/` (tens of thousands of loose
   objects) and stats every entry before the filter skips it.

A typical Rust project with `.git/` and `target/` can contain 200,000+ files. The
combination of full-tree traversal, SHA-256 hashing, and file copying makes baseline
creation take minutes or appear to hang indefinitely.

## Design

### Approach: Defense-in-Depth (Three Layers)

The fix uses three complementary layers. Each is independently valuable and addresses
a different failure mode.

```
Layer 1: Fix walk pruning          — Perf fix, eliminates the common case
Layer 2: Library hard budget       — Safety net, race-safe enforcement
Layer 3: CLI preflight + prompt    — UX, early warning with actionable guidance
```

### Layer 1: Walk Pruning (Library)

**Location:** `crates/nono/src/undo/snapshot.rs` — `walk_and_store()`,
`walk_current()`, `collect_atomic_temp_files()`

**Change:** Replace the current per-file exclusion check with `WalkDir`'s
`filter_entry()` to prune entire subtrees at directory-entry time.

Current code:

```rust
for entry in WalkDir::new(tracked)
    .follow_links(false)
    .into_iter()
    .filter_map(|e| e.ok())
{
    let path = entry.path();
    if self.exclusion.is_excluded(path) {
        continue;
    }
    // ... hash and store
}
```

Proposed:

```rust
for entry in WalkDir::new(tracked)
    .follow_links(false)
    .into_iter()
    .filter_entry(|e| !self.exclusion.is_excluded(e.path()))
    .filter_map(|e| e.ok())
{
    // ... hash and store (already non-excluded)
}
```

`filter_entry()` prevents `WalkDir` from descending into excluded directories. For a
typical project where `.git/` and `target/` are excluded, this eliminates the vast
majority of filesystem operations.

**Additionally**, expand the base exclusion list in `rollback_base_exclusions()`
(`crates/nono-cli/src/main.rs`):

```rust
pub(crate) fn rollback_base_exclusions() -> Vec<String> {
    [
        // VCS internals — restoring partial .git/ corrupts the repository
        ".git", ".hg", ".svn",
        // Build artifacts — fully regenerable from source
        "target", "node_modules", "__pycache__", ".venv",
        // OS metadata
        ".DS_Store",
    ]
    .iter()
    .map(|s| String::from(*s))
    .collect()
}
```

These directories are all generated/derived content. Including them in rollback
provides zero value (they can be regenerated) while causing significant performance
cost. The alternative — hanging indefinitely — provides zero rollback value anyway.

**Impact:** This layer alone resolves the hang for the overwhelming majority of users.
It is a small, low-risk change that can ship independently.

### Layer 2: Library Hard Budget (Library)

**Location:** `crates/nono/src/undo/snapshot.rs` — inside walk methods

**Purpose:** Catch cases where Layer 1 is insufficient (directories not in the
exclusion list, or exclusions not configured). Also race-safe: if the directory grows
between a CLI preflight check and the actual walk, the library budget catches it.

**Mechanism:** Add saturating counters to `walk_and_store()` that track entries
visited. When a configurable budget is exceeded, return an error instead of continuing
indefinitely.

```rust
pub struct WalkBudget {
    /// Maximum entries (files + dirs) to visit. 0 = unlimited.
    pub max_entries: usize,
    /// Maximum total bytes (sum of file sizes via metadata). 0 = unlimited.
    pub max_bytes: u64,
}

impl Default for WalkBudget {
    fn default() -> Self {
        Self {
            max_entries: 300_000,
            max_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
        }
    }
}
```

When exceeded, the error includes actionable guidance:

```
Rollback budget exceeded: visited 300,000 entries (limit: 300,000).
Consider adding exclusion patterns for large directories,
or disable rollback with --no-rollback.
```

The budget is configurable via `SnapshotManager::new()` parameters so the CLI can
pass user-configured values through. The library itself has no opinion on the right
threshold — it only enforces what the caller sets.

### Layer 3: CLI Preflight + Interactive Prompt (CLI)

**Location:** New module `crates/nono-cli/src/rollback_preflight.rs`, called from
`main.rs` before `SnapshotManager::new()`.

**Purpose:** Give the user early, actionable feedback before committing to a
potentially long operation.

#### Detection: Two-Phase Scan

**Phase 1 — Sentinel check (O(1) per tracked directory):**

Read only the immediate children of each tracked writable directory. Check for
known heavy directory names that are NOT already covered by the effective exclusion
list:

```
Known heavy: .git, target, node_modules, __pycache__, .venv, .tox,
             dist, build, .next, .nuxt, .gradle, .cache
```

If all detected heavy directories are already excluded, skip Phase 2.

**Phase 2 — Bounded walk (O(min(N, cap))):**

Walk the directory tree with:
- Entry cap: 5,000 entries visited
- Time cap: 2 seconds wall-clock
- Exclusion rules applied during walk (so excluded dirs are not counted)

Whichever limit is hit first, stop. The result is a lower-bound estimate.

#### Behavior

**Interactive (TTY detected):**

```
[nono] Rollback preflight: /Users/joe/workspace/my-project
       Detected: target/ (build artifacts), node_modules/ (dependencies)
       These are not in the exclusion list and will be walked + hashed.
       Probe: >5,000 files found in 0.8s (lower bound)

       Options:
         [1] Exclude detected directories and continue (recommended)
         [2] Continue without exclusions (may be slow)
         [3] Disable rollback for this session
         [4] Abort

       Choice [1]:
```

Default to the safest fast option (exclude and continue). The prompt writes to
`/dev/tty` to avoid polluting stdout/stderr that the child process might capture.

**Non-interactive (no TTY, piped, CI):**

Fail closed with an actionable error:

```
[nono] Error: Rollback preflight detected large unexcluded directories.
       Detected: target/, node_modules/

       To fix, add one of:
         --rollback-exclude target --rollback-exclude node_modules
         --rollback-exclude-preset generated
         --no-rollback

       Or set NONO_ROLLBACK_LARGE_OK=1 to override.
```

### New CLI Flags

Add to `RunArgs` in `crates/nono-cli/src/cli.rs`:

| Flag | Type | Description |
|------|------|-------------|
| `--rollback-exclude <PATTERN>` | `Vec<String>`, repeatable | Exclude directory pattern from rollback snapshots |
| `--rollback-exclude-glob <GLOB>` | `Vec<String>`, repeatable | Exclude files matching glob from rollback snapshots |
| `--rollback-exclude-preset <NAME>` | `Option<String>` | Named preset: `generated` covers target/, node_modules/, __pycache__/, .venv/, dist/, build/ |
| `--rollback-large-ok` | `bool` | Override the large-directory preflight warning |
| `--no-rollback` | `bool` | Disable rollback entirely (convenience alias) |

Flag names are prefixed with `rollback-` to make clear they affect rollback scope,
**not** sandbox scope. Excluding a directory from rollback does NOT exclude it from
the sandbox — the kernel still enforces the full capability set.

Note: `--rollback-exclude` and `--rollback-exclude-glob` already exist in
`PreparedSandbox` as profile-sourced fields. The new CLI flags extend these with
user-specified values (CLI takes precedence, additive on profile + base).

### Dry-Run Integration

When `--dry-run` is combined with `--rollback`, include the preflight results:

```
[nono] Dry run — rollback preflight:
       Tracked writable paths: /Users/joe/workspace/my-project
       Effective exclusions: .git, .hg, .svn, target, node_modules, __pycache__, .venv, .DS_Store
       Heavy directories detected: (none unexcluded)
       Estimated scope: ~3,200 files
```

### Audit Trail Integration

Sessions where the preflight triggered exclusions or where rollback was disabled due
to directory size are marked in session metadata:

```json
{
  "rollback_coverage": "partial",
  "excluded_by_preflight": ["target", "node_modules"],
  "preflight_file_estimate": 5000
}
```

This surfaces in `nono audit show` and `nono rollback show` so users know which
directories are not covered by rollback.

## Security Considerations

### Rollback Exclusion != Sandbox Exclusion

This is the most important invariant. Excluding `target/` from rollback means changes
there cannot be rolled back. The sandbox still enforces the full capability set — the
sandboxed process can only access `target/` if it was in an allowed path. The security
boundary is unaffected.

### Information Leakage

Preflight warnings could leak directory structure information if captured by a
sandboxed process. Mitigations:

- Default to coarse messages (directory names only, not exact file counts)
- Write interactive prompts to `/dev/tty`, not inherited stdout/stderr
- Never serialize preflight metrics into environment variables or `NONO_CAP_FILE`

### Symlink / TOCTOU

The preflight scan is **advisory only** — it informs user decisions but is not a
security control. The actual enforcement is the library budget (Layer 2), which runs
during the real walk and catches any growth between preflight and execution.

- Scan canonical paths (already canonicalized at capability grant time)
- Do not follow symlinks during walk (`follow_links(false)`)

### Network Mounts / FUSE

`stat()` calls can block indefinitely on remote filesystems. The time-budget in the
preflight (2 second cap) provides a natural failsafe. If the preflight itself hangs,
it times out and fails closed.

### Social Engineering via Prompts

The interactive prompt offers only narrow, safe options:

- Exclude specific detected directories
- Continue as-is
- Disable rollback
- Abort

It **never** suggests broader paths, alternative directories, or permission
escalation. Display text for directory names is not influenced by the sandboxed
process (it runs before the child is spawned).

## Implementation Plan

### Phase 1: Walk Pruning + Expanded Exclusions (Immediate)

1. Add `filter_entry()` pruning in `snapshot.rs` walker methods
2. Expand `rollback_base_exclusions()` with `target`, `node_modules`, `__pycache__`,
   `.venv`
3. Tests: verify excluded directories are not descended into

**This phase alone resolves the reported issue for most users.**

### Phase 2: Library Hard Budget

1. Add `WalkBudget` struct and thread it through `SnapshotManager`
2. Add entry/byte counters to `walk_and_store()`, `walk_current()`,
   `collect_atomic_temp_files()`
3. Return `NonoError::Snapshot` when budget exceeded
4. Tests: verify budget enforcement with synthetic directory trees

### Phase 3: CLI Preflight + Flags

1. Add `--rollback-exclude`, `--rollback-exclude-glob`, `--rollback-exclude-preset`,
   `--rollback-large-ok`, `--no-rollback` flags to `cli.rs`
2. Create `rollback_preflight.rs` module with two-phase detection
3. Wire preflight into `main.rs` before `SnapshotManager::new()`
4. Interactive prompt with TTY detection
5. Dry-run integration
6. Audit trail metadata
7. Tests: preflight detection, prompt behavior, flag interactions

### Phase 4: Documentation

1. Update `docs/cli/usage/flags.mdx` with new flags
2. Update `docs/cli/features/` with rollback preflight documentation
3. Add examples to relevant profile documentation

## Alternatives Considered

### Snapshot-on-Write

Instead of pre-scanning, only snapshot files when a write is about to occur (via
fsevents/inotify/fanotify). This eliminates startup latency entirely but adds
significant complexity (filesystem event monitoring, race conditions with rapid
writes, platform-specific implementations). Worth exploring as a future optimization
but not appropriate as the first fix.

### Async/Streaming Baseline

Start the baseline scan in a background thread while the child process begins
executing. Files modified before their baseline is captured fall back to "no baseline
available." This reduces perceived latency but introduces complex ordering guarantees
and partial-coverage semantics. Better suited as a Phase 2+ optimization.

### Global `--force` Flag

A single `--force` that overrides all warnings. Rejected because it's too broad for a
security tool — users should make explicit, scoped decisions about what they're
overriding. The rollback-scoped `--rollback-large-ok` is more appropriate.

### Silent Auto-Exclusion of All Heavy Directories

Automatically exclude `target/`, `node_modules/`, etc. without user interaction.
Rejected because it silently changes rollback coverage, violating the "explicit over
implicit" principle. The expanded base exclusions (Layer 1) are acceptable because
`.git/`, `target/`, etc. are already documented as excluded-by-default in the rollback
system, and restoring partial contents of these directories would corrupt them.
