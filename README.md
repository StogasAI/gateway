# Stogas Gateway

The open-source, OpenAI-compatible gateway that runs inside Stogas confidential VMs, with its reproducible AMD SEV-SNP IGVM build.

[Documentation](https://stogas.ai/docs) · [Build audit](stogas/release/BUILD_AUDIT.md) · [Security](SECURITY.md)

## What it does

- Serves Chat Completions and Responses over ordinary HTTPS, attested TLS, and end-to-end encryption over HTTPS.
- Verifies the signed evidence for its environment before serving and loads the newest approved catalog for its release.
- Keeps credentials, decryption, provider calls, receipts, and response encryption inside the guest. `Stogas-Metadata: v1` returns a signed receipt for each request.
- Applies organization policies, redaction, and opt-in plugins such as [export](https://stogas.ai/docs/plugins/export).

## Repository

- `core/`: the allowlisted Maxim Bifrost runtime and provider layer
- `transports/`: the Stogas API transport, signed catalog loader, routing, policies, and entrypoint
- `stogas/`: the reproducible IGVM release pipeline

The public listener uses port `5185`; private readiness uses `5186` and TLS diagnostics `5187`. Confidential ingress requires a PROXYv2 header before TLS, so allow backend access only from trusted load balancers.

## Build and test

Install Bun and Go, then run:

```console
bun install --frozen-lockfile
bun run check
bun run build
```

`check` validates the embedded emergency catalog and runs the transport Go tests.

## Releases

Tagged releases build `gateway.igvm` and a manifest that binds its hash, build inputs, SNP launch policies, and launch measurement. GitHub attests the manifest and image. Stogas rebuilds the same pinned Guix derivation independently and signs the manifest only when the result matches.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for upstream attribution.
