# Phase 6: WFP Enforcement Activation - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.

**Date:** 2026-04-05
**Phase:** 06 — wfp-enforcement-activation

---

## Area 1: Driver check gate

**Question:** The service requires `nono-wfp-driver.sys` to exist before installing any filters. How should this gate be handled now that user-mode WFP is the chosen backend?

**Options presented:**
- Remove the check entirely
- Gate to driver-mode requests only
- Placeholder artifact

**User selected:** Remove it entirely

**Captured decision:** D-01 — Remove the driver binary existence check from `activate_policy_mode()` unconditionally.

---

## Area 2: SID vs App-ID filtering

**Question:** `session_sid: None` means App-ID filtering today. Phase 3 decided SID-based. What is the approach?

**Options presented:**
- Full SID path (correct, covers child processes)
- App-ID first (simpler, ships faster)
- Both with fallback

**User selected:** Both with fallback

**Captured decision:** D-02 — SID-based when available, App-ID fallback when not.

---

## Area 3: Token creation plumbing

**Question:** If SID-based, where in the exec flow is the restricted token created and how does the SID string reach the request?

**Options presented:**
- CLI creates restricted token with session-unique SID before forking
- Service derives SID from child process token (user SID, not session-unique)
- Start with user SID now, add restricted token later

**User selected:** CLI creates restricted token with session-unique SID before forking

**Captured decision:** D-03 — CLI owns token creation. SID threads through `ExecConfig` into the activation request.

---

## Area 4: Test strategy

**Question:** WFP filter installation requires admin. How should Phase 6 be tested?

**Options presented:**
- Mock pipe unit tests only
- Snapshot tests on request shape only
- Both mock pipe + snapshot tests
- Integration tests requiring admin

**User selected:** Both 1 and 3

**Captured decision:** D-04 — Mock pipe unit tests + snapshot tests on request serialization. No admin required.

---

*Discussion completed: 2026-04-05*
