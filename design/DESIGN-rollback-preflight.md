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
Layer 1: Fix walk pruning             — Perf fix, eliminates the common case
Layer 2: Library hard budget          — Safety net, race-safe enforcement
Layer 3: CLI preflight + auto-exclude — UX, zero-config handling of large dirs
```

### Layer 1: Walk Pruning (Library)

**Location:** `crates/nono/src/undo/snapshot.rs` — `walk_and_store()`,
`walk_current()`, `collect_atomic_temp_files()`

**Change:** Replace the current per-file exclusion check with `WalkDir`'s
`filter_entry()` to prune entire subtrees at directory-entry time.

```rust
// Before: descends into excluded directories, filters per-file
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

// After: prunes entire subtrees at directory-entry time
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

**Additionally**, the base exclusion list in `rollback_base_exclusions()` is expanded:

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

**Impact:** This layer alone resolves the hang for the overwhelming majority of users.

### Layer 2: Library Hard Budget (Library)

**Location:** `crates/nono/src/undo/snapshot.rs` — inside walk methods

**Purpose:** Catch cases where Layer 1 is insufficient (directories not in the
exclusion list, or exclusions not configured). Also race-safe: if the directory grows
between a CLI preflight check and the actual walk, the library budget catches it.

**Mechanism:** Saturating counters in `walk_and_store()`, `walk_current()`, and
`collect_atomic_temp_files()` that track entries visited and bytes seen. When a
configurable budget is exceeded, return an error instead of continuing indefinitely.

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

The budget is threaded through `SnapshotManager::new()` so the CLI can pass
user-configured values. The library itself has no opinion on the right threshold —
it only enforces what the caller sets.

### Layer 3: CLI Preflight + Auto-Exclude (CLI)

**Location:** `crates/nono-cli/src/rollback_preflight.rs`, called from `main.rs`
before `SnapshotManager::new()`.

**Purpose:** Automatically handle large directories without user intervention. The
design goal is **zero extra flags needed for 90% of users** — rollback Just Works
on projects of any size.

#### Detection: Two Strategies

**Strategy 1 — Name-based (O(1) per tracked directory):**

Read only the immediate children of each tracked writable directory. Check for
known heavy directory names that are NOT already covered by the effective exclusion
list:

```
Known heavy: .git, target, node_modules, __pycache__, .venv, .tox,
             dist, build, .next, .nuxt, .gradle, .cache
```

**Strategy 2 — Size-based (bounded walk per candidate):**

Any immediate-child directory not matched by name undergoes a bounded file count.
If it contains more than 10,000 files, it is flagged for auto-exclusion. Each
directory scan is capped at 1 second wall-clock to keep total preflight latency
bounded.

```rust
const SIZE_THRESHOLD: usize = 10_000;
const SIZE_CHECK_TIME_CAP: Duration = Duration::from_secs(1);
```

If the time cap is hit before counting finishes, directories with >5,000 files
counted so far are conservatively treated as large.

**Scope estimation:** After detection, a bounded walk (5,000 entries / 2 seconds)
produces a lower-bound file estimate for the notice message.

#### Behavior: Auto-Exclude with Transparency Notice

When preflight detects unexcluded heavy directories:

1. Auto-exclude them by rebuilding the `ExclusionFilter` with their names added
2. Print a one-line notice to stderr:

```
[nono] Rollback: auto-excluded /path/to/target (build artifacts), /path/to/data (large directory (>10000 files)) [>5000 files] in 0.8s. Use --rollback-all to include.
```

**No interactive prompt. No blocking. No fail-closed in CI.** The behavior is
identical in interactive and non-interactive contexts.

Directories listed in `--rollback-include` are kept (not auto-excluded), giving
users explicit opt-in control over specific directories.

### CLI Flags

Added to `RunArgs` in `crates/nono-cli/src/cli.rs`:

| Flag | Type | Description |
|------|------|-------------|
| `--no-rollback` | `bool` | Disable rollback entirely (no snapshots, no restore) |
| `--rollback-exclude <PATTERN>` | `Vec<String>`, repeatable | Exclude directory pattern from rollback snapshots |
| `--rollback-exclude-glob <GLOB>` | `Vec<String>`, repeatable | Exclude files matching glob from rollback snapshots |
| `--rollback-include <PATH>` | `Vec<String>`, repeatable | Force-include a directory that would otherwise be auto-excluded |
| `--rollback-all` | `bool` | Override ALL auto-exclusions for full snapshot coverage |

Flag names are prefixed with `rollback-` to make clear they affect rollback scope,
**not** sandbox scope. Excluding a directory from rollback does NOT exclude it from
the sandbox — the kernel still enforces the full capability set.

`--rollback-exclude` and `--rollback-exclude-glob` are additive with profile-sourced
exclusion patterns (CLI values are merged with profile values).

#### Examples

```bash
# Zero-flag usage — auto-excludes target/, node_modules/, etc.
nono run --rollback --allow-cwd -- npm test

# Force-include a specific auto-excluded directory
nono run --rollback --rollback-include target -- cargo build

# Force-include multiple directories
nono run --rollback --rollback-include target --rollback-include dist -- make build

# Include everything (may be slow on large projects)
nono run --rollback --rollback-all -- cargo test

# Exclude an additional custom directory
nono run --rollback --rollback-exclude vendor -- go test ./...

# Disable rollback entirely
nono run --no-rollback --allow-cwd -- npm test
```

## Security Considerations

### Rollback Exclusion != Sandbox Exclusion

This is the most important invariant. Excluding `target/` from rollback means changes
there cannot be rolled back. The sandbox still enforces the full capability set — the
sandboxed process can only access `target/` if it was in an allowed path. The security
boundary is unaffected.

### Information Leakage

Preflight notices are written to stderr before the child process is spawned. The
notice includes directory paths and approximate file counts. Mitigations:

- Notice runs before child process exists (no capture possible)
- Never serialize preflight metrics into environment variables or `NONO_CAP_FILE`

### Symlink / TOCTOU

The preflight scan is **advisory only** — it is not a security control. The actual
enforcement is the library budget (Layer 2), which runs during the real walk and
catches any growth between preflight and execution.

- Scan canonical paths (already canonicalized at capability grant time)
- Do not follow symlinks during walk (`follow_links(false)`)

### Network Mounts / FUSE

`stat()` calls can block indefinitely on remote filesystems. Time caps at every
level provide natural failsafes:

- Size-based detection: 1 second per directory
- Scope estimation: 2 seconds total
- Library budget: entry/byte limits catch any remaining cases

## Alternatives Considered

### Interactive Prompt Instead of Auto-Exclude

The initial design proposed an interactive 4-option prompt (exclude / continue /
disable rollback / abort) with fail-closed behavior in non-interactive contexts.
**Rejected** in favor of auto-exclude because:

- Interactive prompts block CI/CD pipelines and require environment variable overrides
- Fail-closed in non-interactive mode creates friction for scripted usage
- The 90% use case is "just exclude regenerable directories" — prompting for this adds
  no value
- Existing nono patterns (e.g., `prompt_cwd_sharing`, `TerminalApproval`) degrade
  gracefully rather than blocking

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
overriding. The rollback-scoped `--rollback-all` is more appropriate.

### Preset-Based Exclusions (`--rollback-exclude-preset`)

Named presets like `generated` covering target/, node_modules/, etc. Replaced by
auto-exclude, which provides the same benefit without requiring any flag. Users who
want fine-grained control use `--rollback-exclude` and `--rollback-include` directly.

## Future Work

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

Sessions where the preflight triggered exclusions could be marked in session metadata:

```json
{
  "rollback_coverage": "partial",
  "excluded_by_preflight": ["target", "node_modules"],
  "preflight_file_estimate": 5000
}
```

This would surface in `nono audit show` and `nono rollback show` so users know which
directories are not covered by rollback.
