# Stogas Gateway

Public Stogas AI gateway fork built on Maxim Bifrost `core` and provider translation logic.

This repository intentionally keeps only the runtime Go surface and Stogas-owned release tooling:

- `core/`: upstream Bifrost Go module, synced from `maximhq/bifrost` by allowlist.
- `transports/`: Stogas public HTTP transport and gateway entrypoint.
- `stogas/`: Stogas catalog workbench and deterministic SEV-SNP IGVM release pipeline.
- `.github/`: Stogas-owned CI and release workflows.

License and attribution:

- The upstream Bifrost-derived work is Apache-2.0. The upstream license text and
  copyright notice are preserved in `LICENSE`.
- Stogas changes and repository-scope notes are summarized in `NOTICE`.
- Only `core/` is treated as imported Bifrost runtime code. The remaining
  repository surface is Stogas-owned runtime/release tooling; upstream Bifrost
  deployment, application, and non-runtime artifacts are intentionally unused.

This fork does not support full upstream merges. Import upstream changes by applying only the approved runtime allowlist:

```bash
git diff --binary <last-synced-upstream-commit>..upstream/main -- .editorconfig .gitattributes LICENSE core | git apply --3way
```

## Local Commands

```bash
bun run build
bun run check
bun run release:verify-pins
bun run release:build -- v0.0.0 dist/gateway/v0.0.0
```

Go unit tests use conventional `*_test.go` filenames beside their package sources under `transports/**` when they cover package-private behavior. Public gateway behavior coverage is centralized in the private monorepo test harness under `apps/tests`.

The release artifact is the measured `gateway.igvm` built by `stogas/release`. Outputs should be written under this repository's `dist/` directory. See `stogas/release/BUILD_AUDIT.md` for the public reproducible-build audit map.

GitHub draft releases use official GitHub artifact attestation and a faster
single-build path so release candidates do not spend CI time doing a redundant
Guix rebuild check. The GitHub build still uses pinned public inputs and the
final no-substitutes Guix build. The Stogas publish/signing step independently
rebuilds and compares locally before any measurement is accepted into Control.
