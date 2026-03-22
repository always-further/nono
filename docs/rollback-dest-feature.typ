// ─────────────────────────────────────────────────────────────────────────────
// nono · --rollback-dest Feature Documentation
// ─────────────────────────────────────────────────────────────────────────────

#let accent   = rgb("#1a56a0")
#let pass-col = rgb("#1e7e34")
#let code-bg  = rgb("#f4f4f4")
#let head-bg  = rgb("#eaeff7")
#let alt-bg   = rgb("#f9fafc")

// ── Page setup ───────────────────────────────────────────────────────────────
#set page(
  paper: "a4",
  margin: (top: 2.2cm, bottom: 2.4cm, left: 2.4cm, right: 2.4cm),
  header: context {
    if counter(page).get().first() > 1 {
      set text(size: 8pt, fill: luma(150))
      grid(
        columns: (1fr, 1fr),
        align(left)[nono · #text(weight: "bold")[--rollback-dest] Feature],
        align(right)[v0.20.0 · March 2026],
      )
      line(length: 100%, stroke: 0.4pt + luma(200))
    }
  },
  footer: context {
    line(length: 100%, stroke: 0.4pt + luma(200))
    set text(size: 8pt, fill: luma(150))
    align(center)[Page #counter(page).display() of #counter(page).final().first()]
  }
)

// ── Typography ───────────────────────────────────────────────────────────────
#set text(font: "Charter", size: 10.5pt, lang: "en")
#set par(justify: true, leading: 0.72em, spacing: 1.1em)
#set heading(numbering: "1.")
#show link: it => text(fill: accent, it)

// Inline code
#show raw.where(block: false): it => box(
  fill: code-bg,
  inset: (x: 3.5pt, y: 2pt),
  radius: 2.5pt,
  baseline: 1.5pt,
  text(font: "Menlo", size: 9pt, fill: rgb("#333333"), it)
)

// Block code
#show raw.where(block: true): it => block(
  fill: code-bg,
  stroke: 0.5pt + luma(210),
  inset: (x: 12pt, y: 10pt),
  radius: 4pt,
  width: 100%,
  text(font: "Menlo", size: 8.8pt, fill: rgb("#1a1a1a"), it)
)

// Headings
#show heading.where(level: 1): it => {
  v(1.4em)
  block[
    #text(size: 13pt, weight: "bold", fill: accent, it.body)
    #v(-0.5em)
    #line(length: 100%, stroke: 1.5pt + accent)
  ]
  v(0.5em)
}

#show heading.where(level: 2): it => {
  v(0.9em)
  text(size: 11pt, weight: "bold", fill: luma(40), it.body)
  v(0.2em)
}

// ── Helpers ──────────────────────────────────────────────────────────────────
#let pass-badge = box(
  fill: rgb("#e6f4ea"),
  stroke: 0.5pt + rgb("#a8d5b0"),
  inset: (x: 5pt, y: 2.5pt),
  radius: 3pt,
  text(font: "Menlo", size: 8pt, weight: "bold", fill: pass-col)[PASS]
)

#let badge(content, bg, fg) = box(
  fill: bg,
  stroke: 0.5pt + fg.lighten(40%),
  inset: (x: 5pt, y: 2.5pt),
  radius: 3pt,
  text(font: "Menlo", size: 8pt, weight: "bold", fill: fg, content)
)

// ─────────────────────────────────────────────────────────────────────────────
// TITLE BLOCK
// ─────────────────────────────────────────────────────────────────────────────
#block(
  fill: accent,
  inset: (x: 22pt, y: 20pt),
  radius: 6pt,
  width: 100%,
)[
  #text(size: 22pt, weight: "bold", fill: white, font: "Charter")[
    nono — --rollback-dest Flag
  ]
  #linebreak()
  #v(2pt)
  #text(size: 12pt, fill: white.darken(15%), font: "Charter")[
    Custom Rollback Snapshot Destination
  ]
  #linebreak()
  #v(6pt)
  #grid(
    columns: (auto, 1fr),
    gutter: 8pt,
    box(fill: white.transparentize(75%), inset: (x:6pt, y:3pt), radius: 3pt,
      text(size: 8.5pt, fill: white, font: "Menlo")[nono v0.20.0]
    ),
    box(fill: white.transparentize(75%), inset: (x:6pt, y:3pt), radius: 3pt,
      text(size: 8.5pt, fill: white, font: "Menlo")[March 2026 · macOS aarch64]
    ),
  )
]

// ─────────────────────────────────────────────────────────────────────────────
// 1. OVERVIEW
// ─────────────────────────────────────────────────────────────────────────────
= Overview

By default, nono saves rollback snapshots to `~/.nono/rollbacks/`. The
`--rollback-dest` flag lets users redirect snapshot storage to any writable
path covered by the sandbox's write capabilities.

This is useful in two main scenarios:

#block(
  fill: alt-bg,
  stroke: (left: 3pt + accent),
  inset: (left: 14pt, right: 10pt, top: 8pt, bottom: 8pt),
  radius: (right: 4pt),
)[
  *Docker / container environments* — `~/.nono/rollbacks/` is ephemeral inside
  a container. Mounting a host volume and pointing `--rollback-dest` at it keeps
  snapshots across container restarts.
]

#v(0.4em)

#block(
  fill: alt-bg,
  stroke: (left: 3pt + accent),
  inset: (left: 14pt, right: 10pt, top: 8pt, bottom: 8pt),
  radius: (right: 4pt),
)[
  *Shared or audited storage* — teams that centralise audit artefacts to a
  specific path (e.g. `/var/nono/log`) can direct all sessions there without
  changing the system-wide default.
]

// ─────────────────────────────────────────────────────────────────────────────
// 2. FLAG REFERENCE
// ─────────────────────────────────────────────────────────────────────────────
= Flag Reference

#table(
  columns: (2.8cm, 1fr),
  stroke: 0.5pt + luma(210),
  fill: (_, row) => if calc.odd(row) { alt-bg } else { white },
  inset: (x: 9pt, y: 7pt),
  table.header(
    table.cell(fill: head-bg)[*Flag*],
    table.cell(fill: head-bg)[*Description*],
  ),
  [`--rollback-dest`],
  [Override the rollback snapshot destination directory (default:
   `~/.nono/rollbacks/`). Requires `--rollback`. The path must be covered by a
   sandbox write capability — nono exits with a clear error before the sandbox
   is applied if not.],
)

#v(0.6em)

*Constraints enforced at runtime:*

#list(
  indent: 1em,
  [*Requires `--rollback`* — clap rejects `--rollback-dest` without `--rollback` (exit 2).],
  [*Write-capability precheck* — the destination (or its nearest existing ancestor)
    is checked against sandbox write capabilities before the sandbox locks in.],
  [*Auto-create* — if the path does not yet exist, nono creates it via
    `create_dir_all` (the precheck walks up to the nearest existing ancestor for
    symlink-safe canonicalisation on macOS).],
)

// ─────────────────────────────────────────────────────────────────────────────
// 3. USAGE EXAMPLES
// ─────────────────────────────────────────────────────────────────────────────
= Usage Examples

== Basic custom destination

```sh
nono run --rollback --rollback-dest /var/nono/log \
         --allow /path/to/project  --allow /var/nono/log \
         -- claude
```

The session directory is created under `/var/nono/log/` using the standard
`YYYYMMDD-HHMMSS-<PID>` naming convention.

== Docker volume mount

```yaml
# docker-compose.yml
volumes:
  - ./snapshots:/var/nono/snapshots
```

```sh
nono run --rollback --rollback-dest /var/nono/snapshots \
         --allow /workspace --allow /var/nono/snapshots \
         -- claude
```

Snapshots persist on the host at `./snapshots/` even after the container exits.

== Nested path under an allowed parent

The precheck uses ancestor resolution, so `--allow` on a parent directory is
sufficient:

```sh
nono run --rollback --rollback-dest /var/nono/log/sessions \
         --allow /path/to/project  --allow /var/nono/log \
         -- my-agent
```

== Permission denied — error output

If `--rollback-dest` points to a path not covered by sandbox write permissions,
nono exits before the sandbox is applied:

```
nono: --rollback-dest '/home/user/snapshots' is not covered by
      sandbox write permissions.
      Add --allow /home/user/snapshots to grant access, or omit
      --rollback-dest to use the default path (~/.nono/rollbacks/).
```

// ─────────────────────────────────────────────────────────────────────────────
// 4. IMPLEMENTATION NOTES
// ─────────────────────────────────────────────────────────────────────────────
= Implementation Notes

Four files were modified. Total diff: +100 lines, −2 lines.

#table(
  columns: (3.8cm, 1fr),
  stroke: 0.5pt + luma(210),
  fill: (_, row) => if calc.odd(row) { alt-bg } else { white },
  inset: (x: 9pt, y: 7pt),
  table.header(
    table.cell(fill: head-bg)[*File*],
    table.cell(fill: head-bg)[*Change*],
  ),
  [#text(size: 8.5pt, font: "Menlo")[cli.rs]],
  [`--rollback-dest PATH` added to `RunArgs` in the `ROLLBACK` help group.
   `requires = "rollback"` enforces co-presence via clap. (+13 lines)],

  [#text(size: 8.5pt, font: "Menlo")[main.rs]],
  [`rollback_dest` field added to `ExecutionFlags` struct and `defaults()`.
   Precheck block added before `execute_sandboxed()`. Hardcoded
   `home/.nono/rollbacks` replaced with `rollback_root_with_override()`.
   (+44 lines, −2 lines)],

  [#text(size: 8.5pt, font: "Menlo")[rollback_session.rs]],
  [New `rollback_root_with_override(Option<&PathBuf>)` — returns the
   override when `Some`, otherwise delegates to `rollback_root()`.
   (+12 lines)],

  [#text(size: 8.5pt, font: "Menlo")[test_rollback.sh]],
  [Three new integration tests: happy path, directory verification, and
   the permission-denied failure case. (+33 lines)],
)

#v(0.6em)

*Symlink canonicalisation bug found during testing.* A plain `canonicalize()`
call fails on nonexistent paths and falls back to the raw path, e.g.
`/var/folders/…`. Sandbox capabilities store the resolved path,
`/private/var/folders/…`. These do not match, so the precheck falsely rejects
valid destinations that don't yet exist. Fixed by walking up parent directories
until one exists and can be canonicalised before comparing.

// ─────────────────────────────────────────────────────────────────────────────
// 5. TEST RESULTS
// ─────────────────────────────────────────────────────────────────────────────
= Test Results

All tests run on nono v0.20.0, macOS 14 (aarch64), release build.

== CI suite — `make ci`

#table(
  columns: (1fr, auto, auto),
  stroke: 0.5pt + luma(210),
  fill: (_, row) => if calc.odd(row) { alt-bg } else { white },
  inset: (x: 9pt, y: 7pt),
  table.header(
    table.cell(fill: head-bg)[*Check*],
    table.cell(fill: head-bg, align: center)[*Count*],
    table.cell(fill: head-bg, align: center)[*Result*],
  ),
  [Clippy — workspace, all targets, `-D warnings`],
  table.cell(align: center)[—], table.cell(align: center)[#pass-badge],
  [rustfmt check],
  table.cell(align: center)[—], table.cell(align: center)[#pass-badge],
  [nono library unit tests],
  table.cell(align: center)[424], table.cell(align: center)[#pass-badge],
  [nono-cli unit + integration tests],
  table.cell(align: center)[—], table.cell(align: center)[#pass-badge],
  [nono-ffi unit tests],
  table.cell(align: center)[39], table.cell(align: center)[#pass-badge],
  [cargo audit — 958 advisories, 392 dependencies],
  table.cell(align: center)[392], table.cell(align: center)[#pass-badge],
)

== Rollback integration tests — `test_rollback.sh`

#table(
  columns: (1fr, auto),
  stroke: 0.5pt + luma(210),
  fill: (_, row) => if calc.odd(row) { alt-bg } else { white },
  inset: (x: 9pt, y: 7pt),
  table.header(
    table.cell(fill: head-bg)[*Test*],
    table.cell(fill: head-bg, align: center)[*Result*],
  ),
  [rollback list exits 0], table.cell(align: center)[#pass-badge],
  [rollback session with file modification], table.cell(align: center)[#pass-badge],
  [rollback session with file creation], table.cell(align: center)[#pass-badge],
  [rollback list after sessions exits 0], table.cell(align: center)[#pass-badge],
  [rollback list shows workdir], table.cell(align: center)[#pass-badge],
  [rollback show session succeeds], table.cell(align: center)[#pass-badge],
  [rollback verify session succeeds], table.cell(align: center)[#pass-badge],
  [`--rollback-dest` creates session in custom dir], table.cell(align: center)[#pass-badge],
  [Session directory created under `--rollback-dest`], table.cell(align: center)[#pass-badge],
  [`--rollback-dest` without write permission fails], table.cell(align: center)[#pass-badge],
  table.cell(fill: head-bg)[*Total*],
  table.cell(fill: head-bg, align: center)[*10 / 10*],
)

== Edge-case tests — `test_rollback_dest_edge_cases.sh`

#table(
  columns: (1fr, auto),
  stroke: 0.5pt + luma(210),
  fill: (_, row) => if calc.odd(row) { alt-bg } else { white },
  inset: (x: 9pt, y: 7pt),
  table.header(
    table.cell(fill: head-bg)[*Test*],
    table.cell(fill: head-bg, align: center)[*Result*],
  ),
  [`--rollback-dest` without `--rollback` rejected by clap (exit 2)],
  table.cell(align: center)[#pass-badge],
  [Explicit `--allow` on dest passes precheck],
  table.cell(align: center)[#pass-badge],
  [Session created in explicit `--allow` dest],
  table.cell(align: center)[#pass-badge],
  [Dest outside sandbox write caps fails (exit 1)],
  table.cell(align: center)[#pass-badge],
  [Error message mentions `--rollback-dest`],
  table.cell(align: center)[#pass-badge],
  [Error message suggests `--allow` fix],
  table.cell(align: center)[#pass-badge],
  [Nested dest covered by `--allow` parent passes],
  table.cell(align: center)[#pass-badge],
  [Session created inside nested dest],
  table.cell(align: center)[#pass-badge],
  [Nonexistent dest created via `create_dir_all` ★],
  table.cell(align: center)[#pass-badge],
  [Session present after nonexistent dest creation],
  table.cell(align: center)[#pass-badge],
  [`~/.nono/rollbacks` not polluted when dest overridden],
  table.cell(align: center)[#pass-badge],
  [Session correctly placed in custom dest],
  table.cell(align: center)[#pass-badge],
  [Dest pointing to a file (not a dir) fails],
  table.cell(align: center)[#pass-badge],
  [Multiple runs accumulate sessions in custom dest],
  table.cell(align: center)[#pass-badge],
  [Dest equals tracked workdir (overlap edge case)],
  table.cell(align: center)[#pass-badge],
  table.cell(fill: head-bg)[*Total*],
  table.cell(fill: head-bg, align: center)[*16 / 16*],
)

#v(0.5em)
#block(
  fill: rgb("#fffbea"),
  stroke: 0.5pt + rgb("#e0c84a"),
  inset: (x: 10pt, y: 8pt),
  radius: 4pt,
)[
  #text(size: 9pt)[
    *★ Bug found during testing* — the nonexistent-dest test exposed a symlink
    canonicalisation issue: `canonicalize()` fails on paths that don't yet exist and
    returns the raw path (`/var/folders/…`), which does not match the resolved
    capability path (`/private/var/folders/…`) on macOS. The precheck was updated
    to walk up parent directories until finding an existing ancestor to canonicalise,
    ensuring consistent path comparison.
  ]
]
