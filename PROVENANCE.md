# Provenance

Source repository: `ai-workspace-xstream/xconnect-app`.

Source ref: `origin/codex/xconnect-batch-08-signed-config-v2`.

Pinned source commit: `18d328e5c7b171a4c53f6e2a1d387155901c9715`.

Extracted on 2026-09-07 directly from Git objects, without checking out or
modifying the source working tree:

- `go_core/overlay/**` → `overlay/**`, including every test and JSON fixture.
- `go_core/cmd/xconnect/**` → `cmd/xconnect/**`.
- Root `LICENSE` → `LICENSE`, unchanged (Apache-2.0, Copyright 2025 svc.plus).

Changes from the pinned source: rewrite `go_core/overlay/` imports to
`github.com/ai-workspace-xstream/XConnect-One/overlay/` and mark modified Go files;
replace the application module definition with a standalone standard-library-only
module; add repository documentation, ignore rules and CI. Safety changes disable
cached `up` in favor of verified `sync`, route unhealthy `down` through owned
cleanup, preflight interface names, record interface indexes and refuse blind
cleanup after failed startup. Regression tests cover these changes, and original
lifecycle tests were adapted to the intentionally restricted `up` behavior.
Protocol, session, signature and generation-floor semantics remain inherited.
No upstream NOTICE file was present at the source commit.

The application Go module's Flutter/FFI, tray, embedded Xray, libXray local
replacement, and unrelated third-party dependencies are not part of this
extraction. Xray and WireGuard must be installed independently. Original
attribution is retained in LICENSE; the new NOTICE describes this extraction
without asserting ownership of the upstream work.

This repository has independent Git metadata, release/build configuration and
module identity. It must not share mutable state with the application checkout.
