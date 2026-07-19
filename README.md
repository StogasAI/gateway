# Stogas Gateway

Public Stogas AI gateway fork built on Maxim Bifrost `core` and provider translation logic.

This repository contains the runtime Go surface and the reproducible release evidence needed to audit a gateway build:

- `core/`: upstream Bifrost Go module, synced from `maximhq/bifrost` by allowlist.
- `transports/`: Stogas public HTTP transport and gateway entrypoint.
- `stogas/`: Stogas catalog workbench and deterministic SEV-SNP IGVM release pipeline.
- `.github/`: Stogas-owned CI and release workflows.

License and attribution:

- The repository is Apache-2.0 under the canonical root `LICENSE`.
- Upstream Bifrost attribution, Stogas LLC ownership, and repository-scope notes are preserved in
  `NOTICE`.
- Only `core/` is treated as imported Bifrost runtime code. The remaining
  repository surface is Stogas-owned runtime/release tooling; upstream Bifrost
  deployment, application, and non-runtime artifacts are intentionally unused.

The inference listener defaults to port `5185`. Readiness is not part of that public router: a separate HTTP listener on port `5186` serves only `GET /ready` and must remain on the private guest/host network. Local callers can select another readiness port with `-private-readiness-port`.

The release artifact is the measured `gateway.igvm` built by `stogas/release`; launch policy v1 binds the IGVM and SNP launch fields, while the release manifest records four measured VPs. Host memory and topology remain infrastructure configuration. Outputs should be written under this repository's `dist/` directory. See `stogas/release/BUILD_AUDIT.md` for the public reproducible-build audit map.

Host SMT is allowed. Host CPU pinning is a performance-only placement choice, not a hostile-hypervisor control; the SEV-SNP security boundary does not rely on dedicated physical cores.

Published releases include official GitHub artifact attestations. Stogas independently rebuilds the same pinned Guix derivation and authorizes a launch measurement only when the IGVM hash and measurement match the GitHub artifact exactly.
