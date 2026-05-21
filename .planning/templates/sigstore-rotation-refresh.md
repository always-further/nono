# Sigstore Trust-Root Rotation Refresh Checklist

**Read this template before committing a refreshed `crates/nono/tests/fixtures/trust-root-frozen.json`.**

**Source:** Phase 49 (Sigstore TUF root rotation resilience, v2.6) — supersedes P32-DEFER-005. Established 2026-05-21 after three recurrences of the `sigstore-verify` embedded-anchor staleness failure (0.6.5 → 0.6.6 → 0.7.0).

---

## Scope

This checklist applies whenever Sigstore announces a TUF root rotation (root signing-key set change). Indicators:
- Sigstore mailing list announcement on https://groups.google.com/g/sigstore-dev.
- Sigstore blog post tagged with "root rotation" or "root signing".
- `sigstore-rs` CI failures on `TrustedRoot::production()` after an upstream key rotation.
- Local POC user report: `nono setup --refresh-trust-root` fails with `Signature threshold of N not met for role root (0 valid signatures)`.

Does NOT apply to:
- `sigstore-verify` minor version bumps that do NOT involve a root rotation (those go through the standard UPST cadence).
- POC user reports of a STALE cache that resolves with a successful `nono setup --refresh-trust-root` (no fixture refresh needed).

## Decision Tree

**Step 1 — Capture the new root.** Fetch the current upstream root:

```bash
curl -L https://raw.githubusercontent.com/sigstore/root-signing/main/repository/trusted_root.json -o /tmp/trusted_root.new.json
```

If `sigstore/root-signing@main` has moved to a different layout, consult the Sigstore blog or `sigstore/cosign` README for the current canonical path. Do NOT capture from a CDN that re-serializes — bytes must round-trip cleanly.

**Step 2 — Byte-diff vs the current frozen fixture.**

```bash
diff -u crates/nono/tests/fixtures/trust-root-frozen.json /tmp/trusted_root.new.json | head -100
```

Inspect the diff. Expect: changed `keyId`, `rawBytes`, `validFor.start` per rotated tlog/CA/CT-log key. If the diff is empty, no refresh needed (the upstream has not rotated since the last capture).

**Step 3 — Replace and run the regression smoke.**

```bash
cp /tmp/trusted_root.new.json crates/nono/tests/fixtures/trust-root-frozen.json
cargo test -p nono trust::bundle::load_test_trusted_root_smoke
```

The `load_test_trusted_root_smoke` test deserializes the fixture and exercises the same code path `nono trust verify` uses. If it fails, the new fixture is malformed at the schema layer — do NOT commit.

**Step 4 — Run the cross-platform smoke script as the pre-commit gate** (D-49-C3):

```bash
# Unix:
./scripts/verify-trust-root-cached.sh crates/nono/tests/fixtures/trust-root-frozen.json

# Windows:
pwsh scripts/verify-trust-root-cached.ps1 crates/nono/tests/fixtures/trust-root-frozen.json
```

Exit 0 confirms `nono setup --from-file <fixture>` succeeds and the cache is populated byte-identically. Non-zero exit means the fixture fails the same fail-closed contract Phase 49-01 enforces — do NOT commit. Re-capture from a clean source.

**Step 5 — Commit, with DCO sign-off:**

```bash
git add crates/nono/tests/fixtures/trust-root-frozen.json
git commit -s -m "chore(trust-root): refresh frozen fixture for Sigstore root rotation <date>"
```

DCO sign-off (`-s`) is mandatory per CLAUDE.md § Coding Standards → Commits. The commit message should reference the Sigstore announcement (mailing-list archive URL or blog post URL) in the body.

**Step 6 — Forward pointer to the release-asset gate.** The next tagged release will run the byte-identity assert at `.github/workflows/release.yml`'s `Generate checksums` step (Phase 49-02). After the release tag is pushed, verify:

```bash
gh release view <tag> --json assets | jq '.assets[].name' | grep trusted_root.json   # asset present
gh release download <tag> -p trusted_root.json
diff trusted_root.json crates/nono/tests/fixtures/trust-root-frozen.json   # exit 0
```

Both gates green = end-to-end provenance chain holds: committed fixture → CI byte-identity assert → release asset → POC user `--from-file`.

## Anti-Patterns (do NOT do)

- **Anti-pattern 1:** Refresh without running the regression smoke in Step 3. A malformed capture (truncated, re-serialized with different whitespace, missing tlog entries) will deserialize-fail at `nono trust verify` time — POC users see the bug, not the maintainer.
- **Anti-pattern 2:** Commit a fixture that the smoke script (`scripts/verify-trust-root-cached.{sh,ps1}`) rejects. The smoke script exercises the same fail-closed contract `nono setup --from-file` enforces; if it rejects the fixture, the fixture is broken.
- **Anti-pattern 3:** Ship a refresh without bumping a release tag. POC users `--from-file` against the GitHub Release asset; if the maintainer commits a new fixture but the most recent release still ships the old one, the release asset is silently stale.
- **Anti-pattern 4:** Skip DCO sign-off. The repo's DCO policy is workspace-wide (CLAUDE.md); commits without `-s` will be rejected by the upstream PR gates.
- **Anti-pattern 5:** Bump `sigstore-verify` as the response to a rotation. This template exists specifically to exit the dep-bump treadmill (Phase 49 D-49-A1 + SPEC.md "out of scope: bumping sigstore-verify"). Dep bumps belong in UPST cadence, not in rotation response.

## Enforcement

This checklist is referenced from:
- `docs/cli/development/windows-poc-handoff.mdx` § Known issue: Sigstore TUF root rotation (Plan 49-03).
- `.github/workflows/release.yml` Generate checksums step inline comment (Plan 49-02).
- Future `/gsd-verify-phase` invocations on phases that touch `crates/nono/tests/fixtures/trust-root-frozen.json` (verifier reads this template before flipping POC-TRUST REQs to VERIFIED).

Established 2026-05-21 by Phase 49 Plan 49-03 (REQ-POC-TRUST-03) — closes the maintainer-cadence gap that left previous rotations as ad-hoc inbox-scrolling exercises.
