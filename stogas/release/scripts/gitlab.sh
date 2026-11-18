#!/usr/bin/env bash
# GitLab's rebuild of a release tag, which .gitlab-ci.yml runs with only the variables it names:
# build the release as GitHub's build does, with Guix packages from the other Guix build farm first,
# and sign a build proof for the manifest and the image.
set -euo pipefail
test "$(git rev-parse HEAD)" = "$CI_COMMIT_SHA"
test -z "$(git status --porcelain)"

stogas/release/scripts/install-guix-bootstrap.sh
stogas/release/scripts/build-release.sh "$CI_COMMIT_TAG" /builds/release
node stogas/release/scripts/provenance.mjs /builds/release > /builds/statement.json

curl --fail --location --silent --show-error --output /usr/local/bin/cosign \
  https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64
echo '424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  /usr/local/bin/cosign' |
  sha256sum --check --strict -
chmod 755 /usr/local/bin/cosign
# Cosign signs with a Fulcio certificate for the job's ID token and logs the proof in Rekor.
cosign attest-blob --statement /builds/statement.json --bundle gitlab-attestation.jsonl --yes
