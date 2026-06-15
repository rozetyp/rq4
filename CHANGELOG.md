# Changelog

All notable changes to RQ4 are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [2.0.1] — 2026-06-16

### Validated

- **§6.6 evasion model independently confirmed.** The context-aware HTTP client architecture identified in v2.0.0 as the only effective RQ4-S bypass was empirically observed defeating unrelated top-tier commercial within-session bot detection products in production testing. The spec's symmetric prediction — same architecture defeats both RQ4-S and top-tier commercial within-session scoring — held in independent testing without coordinated effort.
- See [SPEC.md §6.4.1](SPEC.md#641-evasion-symmetry--independent-commercial-confirmation) for the detailed methodology and result.
- No spec or implementation changes; this is empirical confirmation of v2.0.0's evasion analysis from the bypass side.

### Changed

- Bumped package.json version `2.0.0 → 2.0.1`.
- README "Validated" block reformatted as a bidirectional list (detection-side + evasion-side dates).

---

## [2.0.0] — 2026-06-14

### Added

- **RQ4-S: Session-Level Extension** ([SPEC.md §6](SPEC.md#6-session-level-extension-rq4-s)). Correlates per-request RQ4 fingerprints across a cookie session to detect the cookie-reuse attack: real browser solves a WAF challenge, the resulting session cookies are transferred to an HTTP client (curl_cffi, etc.) for fast automated requests. Zero false positives across all tested scenarios. Catches the handoff on the first bot request after cookie transfer.
- Reference TypeScript implementation: [`src/rq4s.ts`](src/rq4s.ts). Exports `trackSession`, `getSessionId`, `MemorySessionStore`, `CloudflareKVStore`. ~200 lines.
- Empirical validation against a production Imperva Incapsula reese84 deployment (April 2026). Imperva did not flag the cookie handoff; RQ4-S did, on the first bot request.
- False-positive testing across Chrome, Firefox, Safari, Edge, Android WebView, Service Workers, native mobile apps, header-stripping browser extensions. Zero false positives.
- Evasion analysis: identifies context-aware HTTP clients (~400 LOC of custom request dispatch logic) as the technique that defeats RQ4-S. No public scraping framework implements this by default.
- §9.4 Future Work: multi-session correlation as a planned extension for detecting coordinated cookie-farming.

### Changed

- Bumped specification version `1.0 → 2.0`.
- Renumbered SPEC sections: old §6 (Relationship to Other Standards) → §7; old §7 (Reference Implementation) → §8; old §8 (Future Work) → §9.
- Updated package.json version `1.0.0 → 2.0.0` and description to mention RQ4-S.
- README Quick Start now includes both per-request RQ4 and the RQ4-S session-tracking example.

### Citation

```
RQ4: Request Context Fingerprinting. Version 2.0, June 2026.
AZ. https://rq4.dev
```

---

## [1.0.0] — 2026-03

### Added

- Initial public release.
- Four-dimension request context fingerprint: Mode (M), Upgrade (U), Identity (I), Transfer (T).
- TypeScript reference implementation ([`src/rq4.ts`](src/rq4.ts)).
- Live demo at https://rq4.dev.
- Specification (CC BY 4.0) and reference implementation (MIT).
