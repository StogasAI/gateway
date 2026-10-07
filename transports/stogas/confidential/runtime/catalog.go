package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func (summary evidenceSummary) activeCatalogApproved(gatewayID string) bool {
	var sequence uint64
	found := false
	for _, gateway := range summary.Gateways {
		if gateway.ID == gatewayID {
			sequence, found = gateway.Release.Sequence, true
			break
		}
	}
	if !found {
		return false
	}
	for _, approved := range summary.Catalogs {
		release := approved.Release
		if release.MinimumGatewaySequence <= sequence && catalog.ActiveMatchesApproved(catalog.Identity{Sequence: release.Sequence, Digest: release.RuntimeDigest}, release.PublicDigest) {
			return true
		}
	}
	return false
}

func (e *currentEvidence) updateCatalog(parent context.Context, gatewayID string) error {
	approved, ok := e.summary.catalog(gatewayID)
	if !ok {
		return errors.New("no approved compatible catalog")
	}
	release := approved.Release
	identity := catalog.Identity{Sequence: release.Sequence, Digest: release.RuntimeDigest}
	if catalog.ActiveMatchesApproved(identity, release.PublicDigest) {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, evidenceAcquisitionTimeout)
	defer cancel()
	runtimeBytes, err := e.artifact(ctx, release.RuntimeDigest, release.RuntimeSizeBytes, catalog.MaxRuntimeBytes)
	if err != nil {
		return err
	}
	publicBytes, err := e.artifact(ctx, release.PublicDigest, release.PublicSizeBytes, catalog.MaxPublicBytes)
	if err != nil {
		return err
	}
	return catalog.InstallApproved(runtimeBytes, publicBytes, identity, release.PublicDigest)
}

func (e *currentEvidence) artifact(ctx context.Context, digest string, size, limit int64) ([]byte, error) {
	if size < 1 || size > limit {
		return nil, errors.New("invalid approved artifact size")
	}
	hexDigest, ok := strings.CutPrefix(digest, "sha256:")
	decoded, err := hex.DecodeString(hexDigest)
	if !ok || err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != hexDigest {
		return nil, errors.New("invalid approved artifact digest")
	}
	var failures []error
	for _, origin := range e.origins {
		bytes, err := e.fetchArtifact(ctx, origin.url+"/catalog/blobs/sha256/"+hexDigest+".json", size)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		sum := sha256.Sum256(bytes)
		if int64(len(bytes)) != size || hex.EncodeToString(sum[:]) != hexDigest {
			failures = append(failures, errors.New("catalog artifact digest differs"))
			continue
		}
		return bytes, nil
	}
	return nil, errors.Join(failures...)
}

func (e *currentEvidence) fetchArtifact(parent context.Context, url string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, evidenceAttemptTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := e.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("catalog artifact delivery failed")
	}
	bytes, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(bytes)) > limit {
		return nil, errors.New("catalog artifact exceeds decoded size limit")
	}
	return bytes, nil
}
