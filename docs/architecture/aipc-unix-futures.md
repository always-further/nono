# AIPC Unix Futures

**Status:** Accepted
**Date:** 2026-04-29
**Phase:** 25 (v2.3 Cross-Platform RESL + AIPC Unix Design)
**Requirement:** REQ-AIPC-NIX-01

## Context

Phase 18 + 18.1 (v2.1) shipped AIPC — Agent IPC handle brokering — as a Windows-only subsystem. Sandboxed agents request access to Windows kernel objects (Files, Sockets, Pipes, Job Objects, Events, Mutexes) via a u32 `HandleKind` discriminant carried over the supervisor IPC channel. The supervisor brokers the actual `HANDLE` across the trust boundary using `DuplicateHandle` with reduced rights (the v2.1 Phase 18 D-05 "MAP DOWN, not DUPLICATE_SAME_ACCESS" decision). Windows-side enforcement was made observable on the audit-ledger wire by Phase 23's `RejectStage` discriminator (v2.2): every supervisor decision now records whether the rejection happened *before* the user prompt (mask gate) or *after* (G-04 broker-failure flip), giving operators a structured trace of why a request was denied.

Going into v2.4 cross-platform AIPC planning, the foundational question is not "how do we port AIPC to Unix?" but "which HandleKinds *can* be ported, which *cannot*, and what should Unix users reach for in the cases where they cannot?" Two of the six discriminants are obvious in either direction (File trivially yes, JobObject obviously no). The middle four — Socket, Pipe, Event, Mutex — each require a deliberate verdict because Unix has *something* in the neighborhood for each, but only Sockets and Pipes admit a *handle-brokering* shape (FD passing via Unix-domain sockets with `SCM_RIGHTS`). The other two (Event, Mutex) have Unix-side primitives that fill similar functional roles, but those primitives are not handle-brokerable in the same way — they require either shared memory (pthread mutex with `PTHREAD_PROCESS_SHARED`) or path-based addressing (cgroup v2 for JobObject equivalence).

Without this ADR locked in, every v2.4 Unix-AIPC discussion will re-litigate the same six rows of the decision table and three alternate-mechanism mappings. This document records the locked decision so v2.4 implementation phases can build *against* it rather than re-derive it from first principles each time.

### Goals

This ADR commits to:

- A clear, falsifiable yes/no verdict for each of the six pinned HandleKind discriminants (0..=5) on the question "does Unix admit a backend handler?"
- For each "No" verdict, an explicit named alternate Unix mechanism that fills the equivalent functional role.
- A consistent diagnostic shape ("Windows-only; use {alternate}") that future Unix supervisors emit when they receive an AIPC request whose HandleKind has a "No" verdict.
- A reversibility process documenting under what circumstances the decision can be revisited and how (Status field transition, ADR supersession).

### Non-goals

This ADR explicitly does NOT commit to:

- Any specific timeline for shipping a Unix AIPC backend (v2.4, v2.5, or beyond — separate scoping decision).
- Any API surface, function signatures, or pseudocode for the eventual Socket/Pipe/File brokers.
- Any sequence-level or architecture-level design diagrams.
- A position on AIPC G-04 wire-protocol compile-time tightening (referenced as a reversibility trigger only).
- Any opinion on macOS-specific alternatives beyond noting the absence of a cgroup analog.
- Any change to the existing Windows AIPC implementation. The Windows broker remains exactly as Phase 18.1 + Phase 23 left it.

## Decision Table

| HandleKind | Discriminant | Unix backend? | Mechanism / Alternate |
|---|---|---|---|
| File | 0 | Yes | Already cross-platform; FDs are FDs |
| Socket | 1 | Yes | Unix-domain socket + `SCM_RIGHTS` ancillary FD passing |
| Pipe | 2 | Yes | Unix-domain socket + `SCM_RIGHTS` (passes anonymous-pipe FD) |
| JobObject | 3 | No | Alternate: cgroup v2 (Plan 25-01) — different shape, not brokerable |
| Event | 4 | No | Alternate: `pipe(2)` for one-shot signaling |
| Mutex | 5 | No | Alternate: `flock(2)` for cross-process advisory locks |

The table mirrors the discriminant ordering pinned by const assertions in `crates/nono/src/supervisor/aipc_sdk.rs`. Discriminants are append-only — see `.planning/PROJECT.md` § Key Decisions, "AIPC HandleKind discriminators 0..=5 PINNED" entry — so the same numeric values that ship on the Windows wire today remain stable on any future Unix wire. Adding a hypothetical seventh HandleKind (e.g., `Timer`, `Semaphore`) would take discriminant 6, never reuse holes, and require a separate ADR addressing its Unix-side feasibility.

### Discriminant-ordered index

The same six rows ordered by discriminant number for tooling that keys on the wire-protocol numeric values (audit-ledger parsers, child SDK demultiplexer, profile validators):

| Discriminant | Kind | Verdict | Notes |
|---|---|---|---|
| 0 | File | Yes | Already cross-platform; FDs are FDs |
| 1 | Socket | Yes | Unix-domain socket + SCM_RIGHTS ancillary FD passing |
| 2 | Pipe | Yes | Unix-domain socket + SCM_RIGHTS (passes anonymous-pipe FD) |
| 3 | JobObject | No | Alternate: cgroup v2 (Plan 25-01) — different shape, not brokerable |
| 4 | Event | No | Alternate: pipe(2) for one-shot signaling |
| 5 | Mutex | No | Alternate: flock(2) for cross-process advisory locks |

Both tables encode the same decision; the two orderings exist for grep/tooling convenience (one is HandleKind-keyed, one is Discriminant-keyed). Any divergence between them is a bug — the canonical source is the const assertion in `aipc_sdk.rs`.

## Per-HandleKind Rationale

### HandleKind 0: File — Yes

File descriptors and Windows file `HANDLE`s both represent kernel-mediated access to filesystem objects. On Unix, FD passing via `SCM_RIGHTS` ancillary messages on Unix-domain sockets is the established cross-process primitive for handing access across a trust boundary. On Windows, the AIPC broker already passes File HANDLEs via `DuplicateHandle`. The AIPC abstraction maps cleanly onto Unix without any new mechanism beyond what SCM_RIGHTS already provides for the Socket and Pipe brokers below — the same ancillary-message machinery handles all three.

A File request from a sandboxed agent on Unix returns a usable FD with the requested access mode (read-only, write-only, read-write), respecting the broker's MAP-DOWN semantics (the child receives an FD with strictly fewer rights than the supervisor's source FD, never more). The broker's responsibility is to validate the requested path against the capability allowlist and resolve symlinks at the trust boundary before duplication, identical to the Windows path. The Unix-side broker can additionally apply `O_NOFOLLOW` and `O_CLOEXEC` flags by default to prevent symlink-traversal and FD-leak footguns that don't have direct Windows analogs but are idiomatic Unix hardening.

Two cross-platform invariants are worth calling out for File. First, the broker's path-canonicalization step (per CLAUDE.md § Path Handling, "always use path component comparison, not string operations") is the same on both platforms — it runs on the supervisor side before the broker call, and the trust boundary has already been crossed by the time `SCM_RIGHTS` or `DuplicateHandle` fires. Second, the access-mode mapping is structurally identical: `O_RDONLY` ↔ `GENERIC_READ`, `O_WRONLY` ↔ `GENERIC_WRITE`, `O_RDWR` ↔ `GENERIC_READ | GENERIC_WRITE`. The broker's allowlist resolver returns a triple of (path, mode, capability-source) on both platforms; the Unix broker just translates the mode at FD-open time rather than at HANDLE-duplicate time.

### HandleKind 1: Socket — Yes

Sockets are the canonical SCM_RIGHTS use case on Unix. Passing a `SOCKET` across the supervisor IPC boundary on Linux/macOS is a Unix-domain socket `sendmsg(2)` with `cmsg(SCM_RIGHTS)`; the receiver's `recvmsg(2)` yields a usable FD with the same connection state, address family, and protocol that the supervisor created. The AIPC wire protocol's discriminant + payload shape maps onto `sendmsg`/`recvmsg` cleanly: the broker creates the socket via `socket(2)` + `bind(2)` + `connect(2)` (for Connect role) or `listen(2)` (for Bind role), validates the request against the capability allowlist, and passes the FD via the ancillary message in the response.

The fork already uses Tokio's `UnixStream` in its bootstrap path on non-Windows targets (`crates/nono-cli/src/cli_bootstrap.rs`), so the broker layer would extend existing Unix IPC machinery rather than introduce a new transport. The privileged-port unconditional deny carries over directly from the Windows Phase 18 D-05 decision: the broker rejects `port <= 1023` BEFORE any profile-widening check, structurally identical to the Windows path, no Linux-specific `CAP_NET_BIND_SERVICE` reasoning needed. WR-01 reject-stage classification (Phase 23 `RejectStage` enum) carries over verbatim — Socket requests reject AFTER the user prompt under G-04 broker-failure flip semantics on both platforms.

### HandleKind 2: Pipe — Yes

Anonymous pipes on Unix are a `pipe(2)` pair of FDs; passing one end across a Unix-domain socket via `SCM_RIGHTS` is identical mechanically to the Socket case above. Named pipes on Linux are FIFOs (`mkfifo(3)`), also FD-based, also brokerable via the same ancillary-message machinery. One asymmetry to call out: Windows distinguishes anonymous pipe HANDLEs from named pipe HANDLEs at the WinAPI level — anonymous pipes use `CreatePipe`, named pipes use `CreateNamedPipeW` with a different SDDL surface — but on Unix both reduce to FDs over `SCM_RIGHTS`. The AIPC HandleKind=2 discriminant covers both shapes and the Unix backend collapses them into a single broker handler.

The broker's direction-control invariant (read end vs write end of an anonymous pipe pair, request direction = `Read` vs `Write` in the wire payload) is preserved by passing only the requested end of the pipe pair, mirroring the v2.1 Phase 18 Pipe broker direction-validation logic. The "AfterPrompt" reject-stage classification (Phase 23 `RejectStage::AfterPrompt`) for Pipe requests is unchanged — direction validation happens post-approval on both platforms. Cross-platform regression tests for Pipe direction-validation can share assertions across Windows + Unix backends since the validation logic lives at the `policy.rs` layer (already cross-platform) above the platform-specific broker.

### HandleKind 3: JobObject — No (Windows-only by design)

Job Objects are a Windows-specific process-containment primitive. They enforce per-process-tree resource limits (memory, CPU rate, handle count, UI restrictions, kill-on-job-close, atomic-stop semantics) at kernel level via `AssignProcessToJobObject` and `SetInformationJobObject`. The Job Object is referenced by HANDLE; the broker can `DuplicateHandle` that HANDLE across the trust boundary, and the child can call `IsProcessInJob` or query Job Object information through its received HANDLE.

Linux's nearest equivalent — cgroup v2 — is conceptually similar (kernel-enforced resource limits over a process group), but is *not handle-brokerable*. Cgroups are referenced by filesystem path under `/sys/fs/cgroup/`, not by FD/HANDLE that can be duplicated across a trust boundary. The supervisor model requires the broker to *hand* a child a constrained reference; cgroups require the broker to *write* the child's PID into a `cgroup.procs` file, which is a fundamentally different control flow. There is no FD shape that, when received by the child, gives the child the same kind of "I am running inside this resource boundary" semantics that a Job Object HANDLE provides on Windows.

macOS has no equivalent at all — sandbox profiles fill a related role but operate at a different layer (Seatbelt rules), are not process-tree containers, and don't enforce numeric resource limits. The macOS-side analog for `--memory` / `--max-processes` enforcement is `setrlimit(2)` (per-process, not per-process-tree), which has its own limitations (RLIMIT_AS measures address-space, not RSS; RLIMIT_CPU is CPU-time, not wall-clock).

**Alternate Unix mechanism:** cgroup v2 — already shipping in Phase 25 Plan 25-01. Not handle-brokerable, but achieves the equivalent process-containment outcome via a different shape (path-based control rather than HANDLE-based brokering). A sandboxed agent on Unix needing JobObject-equivalent behavior gets it *implicitly* through the supervisor's Plan 25-01 cgroup placement at session bring-up, not through a JobObject AIPC request. The supervisor remains in control of the resource boundary; the agent neither requests it nor manipulates it — which is arguably a stronger security posture than the Windows shape (where the agent at least sees the Job Object HANDLE and can query its own limits).

A subtler point worth surfacing: the Linux kernel has been adding HANDLE-like primitives for processes (`pidfd_open`, `pidfd_send_signal`) over the last several kernel releases, and these *are* FD-based and thus brokerable via `SCM_RIGHTS`. But pidfd addresses process-identity and signal-delivery, not resource-limit-tree containment — a pidfd lets you signal a process safely without PID-reuse races, but it does not let you say "all descendants of this process are subject to memory.max=512M". So pidfd does not change the JobObject verdict. If a future kernel introduces a "cgroupfd" or similar (FD reference to a cgroup that can be brokered and used to enroll processes), that would warrant re-opening this ADR.

### HandleKind 4: Event — No (Windows-only by design)

Windows kernel Events are a cross-process signaling primitive. One process signals (`SetEvent`), another process waits (`WaitForSingleObject`), and the kernel mediates ownership and reset semantics (manual-reset events stay signaled until explicitly reset; auto-reset events reset on the first wake). The Event HANDLE is brokerable via `DuplicateHandle`, and the child can wait on it concurrently with other waitable HANDLEs via `WaitForMultipleObjects`.

The closest Unix primitive — `eventfd(2)` (Linux-specific) — is not a clean match. While an `eventfd` FD *can* technically be passed via `SCM_RIGHTS` to give cross-process signaling, the receiver doesn't gain the same multi-waiter cross-process semantics that `WaitForMultipleObjects` provides on Windows. eventfd's counter semantics also differ from Event's binary-state semantics, requiring the application to layer a one-byte protocol on top to recover Event-like behavior — at which point the application is already paying the abstraction cost of `pipe(2)`.

The right Unix idiom for cross-process one-shot signaling is `pipe(2)`: the writer closes its end (or writes a single byte), and the reader's `read()` returns. This is handle-brokerable — Pipe is HandleKind 2 already — so users wanting Event-like semantics on Unix get them via the existing Pipe broker plus a one-byte protocol convention, without introducing a new HandleKind 4 handler. For multi-waiter scenarios, `epoll(7)` / `kqueue(2)` over a set of pipe FDs replaces `WaitForMultipleObjects` cleanly.

**Alternate Unix mechanism:** `pipe(2)` for one-shot signaling, brokered via the existing Pipe (HandleKind 2) backend. A documentation note in v2.4 implementation will spell out the protocol convention (write any non-empty byte = signal; close write end = permanent signal).

A note on `epoll(7)` vs `WaitForMultipleObjects`: while the Unix idiom for waiting on multiple FDs is `epoll`/`kqueue`/`select`, those primitives don't translate to the Windows model directly — Windows lets you wait on any waitable HANDLE (Events, Mutexes, Semaphores, Threads, Processes) homogeneously through the same wait call. Unix requires the application to know it's waiting on FDs and use the FD-monitoring API. This is a deliberate Unix-vs-Windows architectural difference, not a gap to be papered over by AIPC. v2.4 implementations exposing pipe-based signaling should document the FD-monitoring expectation in their child SDK, not attempt to mock `WaitForMultipleObjects` semantics.

### HandleKind 5: Mutex — No (Windows-only by design)

Windows kernel Mutexes are cross-process locks. `WaitForSingleObject` acquires, `ReleaseMutex` releases, and the kernel mediates ownership and recursive-acquisition semantics — the same thread can re-enter the mutex; another thread cannot. Abandoned-owner detection (the kernel marks a mutex as `WAIT_ABANDONED` if the holding thread exits without releasing) is automatic and observable to other waiters. The Mutex HANDLE is brokerable via `DuplicateHandle` and survives process boundaries.

POSIX has two related primitives, neither of which fits cleanly. Pthread mutexes are process-local unless allocated in shared memory with `PTHREAD_PROCESS_SHARED`, and even then the lock state lives in shared memory rather than in a kernel object referenced by HANDLE/FD — so pthread mutexes don't fit the AIPC broker model (the broker can't *hand* a child a reference to shared-memory state in the same way it hands an FD across the trust boundary). `flock(2)` advisory file locks are cross-process and FD-based — the lock is associated with the open file description, which is what an FD is — and brokerable via `SCM_RIGHTS` through the File HandleKind. `flock` also has automatic owner-death cleanup (the kernel releases the lock when the holding FD is closed, including on process exit), which is the Unix-idiomatic answer to Windows' WAIT_ABANDONED.

So cross-process locking on Unix is achieved via the existing File (HandleKind 0) broker plus an `flock(LOCK_EX)` call, not via a new Mutex HandleKind. The protocol convention is straightforward: the broker hands a File FD to a well-known lockfile path; the child calls `flock(fd, LOCK_EX)` to acquire and `flock(fd, LOCK_UN)` (or simply `close(fd)`) to release. Recursive acquisition is not directly supported by `flock`, but applications needing recursion can layer it on the broker side (the broker tracks per-agent acquisition counts).

**Alternate Unix mechanism:** `flock(2)` advisory file locks on a broker-passed File FD (HandleKind 0). For recursion or fairness guarantees beyond what `flock` provides, applications can use POSIX semaphores via `sem_open(3)` (named, kernel-persistent) — but those don't broker via FD either, so they're a separate-protocol fallback rather than an AIPC HandleKind.

## Alternate Mechanisms

For the three "No" verdicts, Unix users reach for the following primitives instead. None require new AIPC HandleKind discriminants — they ride on existing primitives or sit outside the broker channel entirely.

| Windows HandleKind | Unix alternate    | Brokerable via AIPC?         | Phase / Plan reference |
|--------------------|-------------------|------------------------------|------------------------|
| JobObject (3)      | cgroup v2         | No (path-based)              | Phase 25 Plan 25-01    |
| Event (4)          | `pipe(2)` + byte  | Yes, via HandleKind 2 (Pipe) | This ADR (no new code) |
| Mutex (5)          | `flock(2)` on FD  | Yes, via HandleKind 0 (File) | This ADR (no new code) |

The implication for v2.4+ implementation: a Unix AIPC backend needs *only three* HandleKind handlers — File, Socket, Pipe — not six. JobObject/Event/Mutex requests from a sandboxed agent on Unix will return a structured "not supported on this platform; use {alternate}" diagnostic — not a silent failure, and not a cross-platform-shimmed mock. This is consistent with the fork's "fail secure on any unsupported shape — never silently degrade" constraint (CLAUDE.md § Constraints) and with the v2.2 Phase 22 POLY-01 fail-closed posture for orphan profile entries.

The supervisor's diagnostic message for these cases SHOULD include the alternate-mechanism pointer (e.g., "JobObject brokering is Windows-only; on Linux/macOS, resource limits are applied by the supervisor at session bring-up via cgroup v2 / setrlimit — see Phase 25 Plan 25-01"). This keeps the user-facing surface honest about the platform difference rather than leaving them to discover it from a bare error code. v2.4 implementation should also surface the alternate-mechanism pointer in `nono audit show <id>` output for the corresponding `Denied` ledger event, so operators investigating audit logs see the same context.

The "use {alternate}" diagnostic shape also has audit-trail implications worth calling out. The Phase 23 `RejectStage` discriminator (`BeforePrompt | AfterPrompt`) classifies *why* a request was denied; for the three "No" verdicts on Unix, the rejection is structurally `BeforePrompt` because the supervisor can determine platform-unsupportedness before any user-prompt machinery runs. This means a sandboxed agent on Unix attempting a JobObject request gets the same auditable-and-fast-path treatment as a Windows sandboxed agent attempting an out-of-policy mask gate. Operators reading the audit ledger see a consistent shape across platforms even when the underlying capability decision differs.

The contract for v2.4 implementation is therefore minimal but precise: the Unix supervisor MUST emit a `capability_decision` ledger event with `decision=Denied`, `reason="<HandleKind> is Windows-only on this platform; use <alternate>"`, and `reject_stage=Some(BeforePrompt)` for any incoming AIPC request whose HandleKind is one of {3, 4, 5}. The reason string carries the alternate-mechanism pointer; ledger consumers can extract it with a simple substring match on `"is Windows-only"`. This is the only behavioral contract this ADR imposes on v2.4 — everything else (Socket/Pipe/File broker implementation, allowlist validation, FD-passing protocol details) is deferred.

### Implications for v2.4 implementation (informative)

This ADR is decision-only; the bullets below are non-normative pointers to keep the v2.4 implementation phase scoped:

- A v2.4 Unix-AIPC backend implements **three** broker handlers (File, Socket, Pipe), not six.
- The three "No" verdicts (JobObject, Event, Mutex) are handled by a single shared rejection path that emits the structured "Windows-only; use {alternate}" diagnostic with `RejectStage::BeforePrompt`.
- The Phase 18.1 `wr01_*` regression tests retain their reject-stage classification on the AfterPrompt side for Pipe/Socket; on Unix they verify the same broker-failure flip semantics through the SCM_RIGHTS path.
- The `capabilities.aipc` profile-widening schema (Phase 18.1 Plan 18.1-03) carries over to Unix without schema changes — the same allowlist resolver runs cross-platform; only the broker dispatch differs.
- Audit-ledger emissions on Unix MUST match the Windows `capability_decision` event shape (Phase 23 contract): same fields, same `RejectStage` values, same redaction rules. Cross-platform `nono audit show` must render Unix events identically to Windows events for the three Yes verdicts.
- The Phase 23 `T-23-01` sanitization regression (no raw session token bytes in NDJSON) applies on Unix verbatim.

### Migration considerations (informative)

For users running mixed-platform fleets where some agents run on Windows and others on Unix:

- **AIPC profiles** (those declaring `capabilities.aipc.<kind>` widening) work identically on both platforms for the three Yes verdicts. No profile changes needed.
- **Profiles requesting JobObject/Event/Mutex** will fail closed on Unix with a `Denied` ledger event. Migration path: rewrite the profile to use the alternate primitive (cgroup v2 for resource limits via `--memory`/`--cpu-percent`/etc.; brokered Pipe with byte-protocol for signaling; brokered File with `flock` for cross-process locks).
- **Audit-ledger consumers** (downstream parsers of `audit-events.ndjson`) see the same `RejectStage` field on both platforms; no parser changes needed. The `reason` field's wording differs (Unix has "Windows-only; use {alternate}" pointer text), but both platforms use the same JSON schema.
- **Compliance teams** auditing capability decisions across platforms can use the same query shape: `decision=Denied AND handle_kind IN (3,4,5)` reliably identifies cross-platform-unsupported requests on Unix.

## Reversibility

This decision can be revisited if and when AIPC G-04 (wire-protocol compile-time tightening, currently deferred to the v2.4 backlog) lands. G-04 may reshape the discriminant table in ways that affect Unix-backend feasibility, particularly if the `(Approved, ResourceGrant)` tuple gets restructured at the wire-protocol type level — that restructuring could open the door to per-HandleKind protocol variants where, for instance, a Unix-only "FD with associated `flock` token" shape becomes a first-class Mutex variant. The decision should also be revisited if Linux gains a primitive that brokers JobObject/Event/Mutex shapes the way Windows does today (none currently do; cgroup v2 is the closest and remains path-based; recent kernel work on `pidfd_open` brings process-handle semantics closer to Windows but doesn't address resource-tree containment).

Until either of those holds, the verdicts above are stable. Re-opening this ADR requires updating both this file's Status field (Accepted → Superseded) and the cross-link in `.planning/PROJECT.md` § Upstream Parity Process to point at the superseding document. The discriminant table itself is append-only and cannot be re-numbered — a hypothetical "JobObject Unix-equivalent" landing in v2.5+ would take HandleKind 6 (the next sequential discriminant), not reclaim HandleKind 3.

Specific reversibility triggers and their disposition:

- **Linux `cgroupfd` or equivalent (FD-based cgroup reference)** — would invalidate the JobObject "No" verdict if the FD shape supports the same enroll-and-constrain semantics as a Windows Job Object HANDLE. Re-open ADR; document the Linux-side broker handler.
- **macOS gains a process-tree resource-limit primitive** — would invalidate the JobObject "No" verdict on macOS specifically; might lead to a per-OS verdict matrix rather than a single "Unix" verdict. Re-open ADR; consider splitting the table by Unix flavor.
- **Linux `eventfd` semantics expanded** to support the multi-waiter cross-process shape — would warrant re-opening Event verdict. Currently no signal of this in the kernel mailing list; treat as low-probability.
- **POSIX evolution** introduces a kernel-mediated cross-process mutex with FD-based brokering — would warrant re-opening Mutex verdict. Currently no signal of this in POSIX working-group activity; treat as low-probability.
- **AIPC G-04 wire-protocol tightening lands** — automatic re-open trigger. Update this ADR alongside the G-04 implementation phase.

The ADR's Status field transition path is: Accepted → Superseded (when a new ADR replaces this one) or Accepted → Deprecated (when the underlying AIPC subsystem is itself replaced or removed). Direct edits to Accepted ADRs are reserved for clerical fixes (typos, broken links); semantic changes require the supersession path.

### Decision history (informative)

This decision is the third major step in AIPC's evolution; the timeline below is provided for future readers who land on this ADR without the surrounding milestone context:

- **Phase 18 (v2.1, 2026-04-19)** — AIPC introduced as a Windows-only subsystem. HandleKinds 0..=5 (File, Socket, Pipe, JobObject, Event, Mutex) pinned via const assertions in `aipc_sdk.rs`. MAP-DOWN access-mask semantics chosen over `DUPLICATE_SAME_ACCESS` (D-05). Cross-platform question deferred to a future phase.
- **Phase 18.1 (v2.1, 2026-04-21)** — Five HUMAN-UAT gaps closed (G-02..G-06). G-04 (broker-failure flip via flow-control enforcement) deferred wire-protocol compile-time tightening to v2.2+ backlog. Profile widening end-to-end via `Profile::resolve_aipc_allowlist()`.
- **Phase 23 (v2.2, 2026-04-29)** — `RejectStage` discriminator (`BeforePrompt | AfterPrompt`) added to `AuditEventPayload::CapabilityDecision`. AIPC supervisor decisions now record reject-stage explicitly per event, locking the WR-01 verdict-matrix asymmetry on the wire. `nono audit show <id>` surfaces capability-decision counter + JSON array.
- **Phase 25 Plan 25-02 (v2.3, this ADR, 2026-04-29)** — Cross-platform decision recorded. Three Yes verdicts, three No verdicts, three alternate mechanisms. v2.4 implementation phase will build against this decision, not re-derive it.
- **(Future) v2.4+** — Unix AIPC backend implementation phase: File / Socket / Pipe broker handlers via SCM_RIGHTS. Optional reversibility trigger if AIPC G-04 wire-protocol tightening lands first.

### Glossary (informative)

Terms used in this ADR with their fork-specific or platform-specific meanings:

- **AIPC** — Agent IPC. The subsystem that brokers kernel-object access between sandboxed agents and the supervisor over the Phase 11 capability-pipe transport.
- **HandleKind** — A u32 discriminant on the AIPC wire protocol identifying which kind of kernel object is being requested. Discriminants 0..=5 are pinned (File, Socket, Pipe, JobObject, Event, Mutex); future kinds get the next sequential discriminant.
- **MAP-DOWN** — The access-mask semantics chosen at Phase 18 D-05. The supervisor passes `dwOptions=0` plus an explicit, allowlist-validated mask to `DuplicateHandle`, ensuring the child handle is the validated subset of the supervisor's source rights, never the full ALL_ACCESS.
- **RejectStage** — Phase 23 audit-ledger discriminator. `BeforePrompt` = rejected by mask gate or pre-stage check; `AfterPrompt` = rejected by G-04 broker-failure flip post-approval. Locked on the wire by v2.2.
- **WR-01** — Phase 18.1 reject-stage verdict matrix. Locked by `wr01_*` regression tests in `capability_handler_tests`. Event/Mutex/JobObject reject `BeforePrompt`; Pipe/Socket reject `AfterPrompt`. Unification deferred to v2.3 Phase 29.
- **G-04** — AIPC wire-protocol compile-time tightening. `Approved(ResourceGrant)` inline at the wire type so `(Approved, grant=None)` becomes a compile-time error. Deferred to v2.4 backlog; reversibility trigger for this ADR.
- **`SCM_RIGHTS`** — POSIX ancillary message type for passing FDs over Unix-domain sockets. The Unix equivalent of Windows' `DuplicateHandle` for cross-process resource handing.
- **cgroup v2** — Linux kernel resource-control hierarchy (memory, CPU, pids). Path-based, not FD-based. The alternate mechanism for HandleKind 3 (JobObject); shipped in Phase 25 Plan 25-01.
- **`flock(2)`** — POSIX advisory file lock primitive. FD-based; brokerable via SCM_RIGHTS through HandleKind 0 (File). The alternate mechanism for HandleKind 5 (Mutex).

### Frequently-asked questions (informative)

**Q: Why not implement Event via `eventfd` if it's technically brokerable?**
A: `eventfd` is brokerable via `SCM_RIGHTS`, but its semantics (counter, not binary state) differ from Windows Event semantics enough that the application must layer a one-byte protocol on top to recover Event-like behavior. At that point, `pipe(2)` is the cleaner primitive and reuses the existing HandleKind 2 broker. We chose the simpler path.

**Q: Why not introduce a Unix-only HandleKind 6 for `flock`-based locking?**
A: A new HandleKind for Unix-only would create a discriminant-table asymmetry where Windows ignores HandleKind 6 and Unix ignores HandleKinds 3/4/5. That asymmetry would force every cross-platform consumer (audit-ledger parsers, profile validators, child SDK demultiplexer) to know about it. Reusing HandleKind 0 (File) + `flock(2)` keeps the wire protocol symmetric across platforms.

**Q: What if a future kernel adds the right primitives?**
A: That's exactly the reversibility trigger documented in the previous section. We re-open this ADR, write a new one (e.g., `aipc-unix-futures-v2.md`), set this file's Status to Superseded, and update the cross-link in `PROJECT.md`. The discriminant table itself never changes — append-only is invariant.

**Q: Does this ADR commit the fork to ever shipping a Unix AIPC backend?**
A: No. This ADR only commits the fork to a *consistent diagnostic shape* on Unix when AIPC requests are made (the "Windows-only; use {alternate}" pattern with `RejectStage::BeforePrompt`). Whether a Unix backend ships in v2.4, v2.5, or never is a separate scoping decision. The decision recorded here is "if/when a Unix backend is built, here's which HandleKinds it covers."

## References

### Internal (planning artifacts)

- `.planning/PROJECT.md` § Key Decisions — "AIPC HandleKind discriminators 0..=5 PINNED" entry (Phase 18 origin) and "AIPC access-mask MAP DOWN, not DUPLICATE_SAME_ACCESS" entry (Phase 18 broker semantics).
- `.planning/PROJECT.md` § Upstream Parity Process — cross-link target for this ADR (added by Phase 24 Plan 24-02; this ADR is one of the linked architecture references).
- `.planning/REQUIREMENTS.md` § AIPC-NIX-01 — this ADR's source requirement (v2.3 milestone scope-lock 2026-04-29).
- `.planning/ROADMAP.md` § Phase 25 — phase that contains this ADR (Plan 25-02) and the Linux/macOS RESL backends (Plan 25-01).
- `.planning/ROADMAP.md` § Backlog (v2.4 carry-forward) — AIPC G-04 wire-protocol compile-time tightening as a deferred item; potential reversibility trigger for this ADR.

### Phase summaries (historical context)

- Phase 18 SUMMARY files (`.planning/milestones/v2.1-phases/18-extended-ipc/`) — original AIPC handle-brokering implementation context: HandleKinds pinned, MAP-DOWN access-mask semantics chosen, privileged-port unconditional deny.
- Phase 18.1 SUMMARY files (`.planning/milestones/v2.1-phases/18.1-extended-ipc-gaps/`) — five HUMAN-UAT gaps closed (G-02..G-06); profile widening end-to-end via `Profile::resolve_aipc_allowlist()`; G-04 wire-protocol tightening deferred.
- Phase 23 SUMMARY (`.planning/phases/23-windows-audit-event-retrofit/23-01-SUMMARY.md`) — `RejectStage` discriminator added to `AuditEventPayload::CapabilityDecision`; AIPC enforcement-stage taxonomy locked on the wire; cross-platform question scoped here as the next-phase work.
- Phase 25 Plan 25-01 PLAN.md (`.planning/phases/25-cross-platform-resl-aipc-unix-design/25-01-RESL-NIX-PLAN.md`) — Linux RESL via cgroup v2 (the alternate mechanism for HandleKind 3); macOS RESL via setrlimit. Planned 2026-04-29.

### Source code (read-only references)

- `crates/nono/src/supervisor/aipc_sdk.rs` — `HandleKind` enum + discriminant pinning via const assertions (read-only reference; no changes in this ADR).
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` — Windows supervisor broker dispatch in `handle_windows_supervisor_message` (read-only reference; no changes in this ADR).
- `crates/nono/src/audit_integrity.rs` — `AuditEventPayload::CapabilityDecision` definition with `RejectStage` field (read-only reference; cross-platform code, no changes needed for this ADR).

### External (Unix primitives mentioned)

- `unix(7)` — Unix-domain sockets manual page; `SCM_RIGHTS` ancillary message reference.
- `cgroups(7)` — cgroup v2 manual page; controller hierarchy and delegation model.
- `pipe(2)`, `flock(2)`, `eventfd(2)` — POSIX/Linux primitive manual pages referenced in the Per-HandleKind Rationale section.
- `pidfd_open(2)`, `pidfd_send_signal(2)` — Linux process-handle primitives mentioned in Reversibility (not currently a reversibility trigger).

### Cross-platform standards

- POSIX.1-2017 (IEEE Std 1003.1-2017) — `flock` is non-POSIX (BSD/Linux), but the surrounding FD model is POSIX-aligned.
- Microsoft Windows SDK reference — `DuplicateHandle`, `WaitForSingleObject`, `WaitForMultipleObjects`, `AssignProcessToJobObject` for the Windows-side semantics referenced in the Per-HandleKind Rationale.
- macOS `setrlimit(2)` and `sandbox-exec` — referenced in HandleKind 3 rationale for the "no equivalent at all" claim on macOS.

### Authoring notes

- This ADR follows the "Architecture Decision Record" lightweight format popularized by Michael Nygard (2011): Status / Context / Decision / Consequences. The fork's variation expands "Decision" into a multi-section structure (Decision Table, Per-HandleKind Rationale, Alternate Mechanisms) and surfaces "Consequences" implicitly through the Implications and Migration subsections.
- Future ADRs in `docs/architecture/` should follow the same H2 structure for consistency: Status frontmatter, Context, Decision, Implications, Reversibility, References. Optional H3 subsections for topic-specific elaboration.
