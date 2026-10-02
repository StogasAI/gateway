# Stogas Gateway

The public OpenAI-compatible Stogas gateway and its reproducible AMD SEV-SNP IGVM build.

The repository contains:

- `core/`: the allowlisted Maxim Bifrost runtime/provider layer;
- `transports/`: the Stogas API transport, signed catalog loader, routing, and gateway entrypoint;
- `stogas/`: the reproducible IGVM release pipeline.

The gateway verifies the current evidence package for its selected environment before serving.
It matches its measured release and loads the newest approved catalog compatible with that
release. Catalog artifacts and vendor collateral are verified locally.

The public inference listener uses port `5185`. Private `GET /ready` on port `5186` returns only readiness. Confidential deployments serve versioned `GET /diagnostics/v1` on port `5187` with TLS 1.3 and a pinned client-certificate key. Neither private route is part of the public API; diagnostics are never served over plaintext.

Confidential ingress requires a PROXYv2 TCP header before TLS. Restrict backend access to trusted load balancers and authorized monitors; PROXY metadata is not authenticated client identity. Both passthrough and terminating load balancers must preserve the original connection address, including when reusing backend connections. HTTP forwarding headers do not override that address. Clients connect to the load balancer with ordinary HTTPS and do not send PROXY headers.

Native attested TLS uses TLS 1.3 with X25519MLKEM768 and fresh challenge-bound evidence in the
handshake. Ordinary HTTPS remains available on the same listener for compatible clients.
E2EE establishes a reusable session through `POST /v1/session`, then carries encrypted binary
records on the inference routes. Each session belongs to one confidential guest; its authenticated
owner identity directs later requests to that guest. Credentials, decryption, provider dispatch,
receipts and response encryption remain inside the guest. Clients verify the final authenticated
record before reporting stream completion.

`Stogas-Metadata: v1` requests metadata and one signed receipt. A buffered response adds one final top-level
`stogas` object. A stream emits the same compact JSON in an ignored `: stogas {...}` SSE comment
before `[DONE]`, `response.completed`, or `response.incomplete`. The receipt binds the request,
response and canonical final metadata, excluding the receipt itself. Provider-specific metadata
uses the same signature.

Direct Chat Completions and Responses requests have a 60-minute lifecycle, including provider transport. Streaming clients can use that full period while they keep accepting bytes. A downstream socket write that makes no progress for one minute is closed; model silence does not start this timer. Final response delivery cannot continue more than one minute past the request deadline. Process cleanup has a separate five-minute bound after the request-drain wait, which keeps the guest shutdown hard cap at 65 minutes.

The measured guest profile has four vCPUs and 16 GiB RAM. Its current conservative starting limits are a 10 GiB Go soft limit and a 4 GiB aggregate request/stream admission budget. Request admission accounts for five times the body size, with a 1 MiB minimum; this is a capacity weight, not an allocation or a claim that five copies exist. Stream state accounts for cumulative framed bytes once, and each downstream data frame adds one exact temporary reservation until the client reads it or disconnects. Provider and downstream queues each hold one item, and each stream is capped at 64 MiB. Private diagnostics expose actual RSS, Go-managed memory, garbage collection, reservation classes, peaks, and capacity failures so these starting values can be calibrated from real load.

The MVP inference wire is text-only in both directions. Catalog modalities describe the true upstream
model and deployment capabilities; they do not grant support for those modalities through the Stogas
API. Requests containing image, audio, video, file, or PDF content are rejected, and responses never
expose binary or file artifacts. Supported hosted tools can return text, citations, and control records.

Policies select structured PII and secret detectors, bounded custom RE2 patterns and literal rules.
The gateway replaces matches with irreversible typed placeholders before token estimation and
provider conversion. Parent requirements cannot be weakened by a child policy. Only configured detectors apply. Signed and
encrypted reasoning payloads remain unchanged.

Requests authenticate with a Stogas API key. Each key assigns an ordered list of credentials to
its providers. Requests unlock customer-encrypted credentials with labeled `encryption_keys`;
they never submit raw provider credentials. A missing matching key excludes that credential.
Catalog selection includes each candidate's credential policy. Credential order breaks ties for
one deployment, and only explicit policy fallback permits a second local preparation attempt.
The selected request is transformed once, and provider errors never switch credentials. Every
hold checks current assignments, policy revisions, and credential status. Stored credentials and
customer-encrypted credentials use their registered IDs in analytics; plaintext secrets and
customer encryption keys are never persisted.

Request analytics begin when a billing hold is authorized. Every admitted request retains one
logical final record, including provider errors, cancellations, and zero-cost failures. Records
contain bounded accounting and outcome metadata, never prompts, responses, or raw error messages.
Verified-identity rejections are grouped in request history; anonymous protocol failures use fixed
diagnostic counters. Operational failures use code-owned categories and source locations, cumulative counts,
and at most one emitted line per minute per group. Client logging preferences cannot disable accounting.

## Build and test

Install Bun and Go, then run:

```console
bun install --frozen-lockfile
bun run check
bun run build
```

`check` validates the embedded emergency catalog and runs the complete transport Go test suite. Pull requests also verify dependency hydration, vulnerability data, release pins, and reproducible-build inputs.

## Confidential release

Tagged releases build `gateway.igvm` and a canonical manifest that binds its hash, build inputs, embedded SNP launch policies, and the measurement computed from the completed IGVM. GitHub attests both the manifest and IGVM bytes. Stogas independently rebuilds the same pinned Guix derivation and signs the identical manifest only when the complete result matches.

Release evidence contains `schema: "stogas.release-evidence.v1"`, `manifest`, `signature`, and `attested_builds`. The Stogas signature proves approval of that manifest, not that the independent rebuild happened. The current evidence does not attest the Stogas builder or establish that it did not copy GitHub's output.

See [the reproducible-build audit](stogas/release/BUILD_AUDIT.md) for build inputs and verification details.

## License

Licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for upstream attribution.
