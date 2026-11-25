# Changelog

All notable changes to this project. This project adheres to semantic versioning.

## v0.2.3 — 2026-11-24

- Window: Schedule check-in can repeat — every N days, M times — in one revision
- Window: a View as filter shows "my items" for a role alias (work addressed to the alias or the
  role it stands for), plus a due-state filter
- Window: Verify handoff checks a bundle decrypts and its journal chain is intact, without importing it
- core: `narrow()` applies the same filters to a state you already have (`state_from` uses it)
- Offscreen GUI tests that drive the real window
- Add a verified one-line Linux installer (`install.sh`)

## v0.2.2 — 2026-11-16

- Attach a CycloneDX SBOM to each release (covered by the signed checksums)

## v0.2.1 — 2026-11-15

- Sign release checksums with Sigstore (keyless) and attach the `.sigstore.json` bundle
- Add property/fuzz hardening tests for the AES-256-GCM + scrypt envelope

## v0.2.0 — 2026-11-14

- Add handoff-verify to check a bundle without importing
- Add a 'my items' filter by role alias
- Add Markdown export of a plan
- Filter the state view by due status
- Add recurring check-ins: a cadence series in one revision
- Filter the state view by assignee
- Add iCal (.ics) export of due dates
- Add a coloured --pretty table to the state command
- Docs: point install at the live v0.1.0 release

## v0.1.0

- Initial public release.
