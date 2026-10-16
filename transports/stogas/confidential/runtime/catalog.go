package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// Catalog failure classes double as readiness reasons. They are fixed text because
// the fleet monitor discards reasons it does not recognize.
var (
	errCatalogUnapproved  = errors.New("no approved catalog is compatible with this gateway")
	errCatalogUnavailable = errors.New("approved catalog could not be downloaded")
	// errCatalogIncompatible marks verified catalog bytes that this binary refused.
	errCatalogIncompatible = errors.New("approved catalog is incompatible with this gateway")
)

// catalogReason names the class of a catalog failure for readiness.
func catalogReason(err error) string {
	for _, class := range []error{errCatalogUnapproved, errCatalogUnavailable, errCatalogIncompatible} {
		if errors.Is(err, class) {
			return class.Error()
		}
	}
	return "approved compatible catalog is not installed"
}

// catalogRejection identifies a refused catalog. Installation of verified bytes is
// deterministic, so the same approval is not downloaded again by this process.
type catalogRejection struct {
	identity     catalog.Identity
	publicDigest string
}

func (approved approvedCatalog) identity() catalog.Identity {
	return catalog.Identity{Sequence: approved.Release.Sequence, Digest: approved.Release.RuntimeDigest}
}

func (approved approvedCatalog) active() bool {
	return catalog.ActiveMatchesApproved(approved.identity(), approved.Release.PublicDigest)
}

func (approved approvedCatalog) rejection() catalogRejection {
	return catalogRejection{identity: approved.identity(), publicDigest: approved.Release.PublicDigest}
}

func (summary evidenceSummary) activeCatalogApproved(gatewayID string) bool {
	return slices.ContainsFunc(summary.catalogs(gatewayID), approvedCatalog.active)
}

// updateCatalog installs the newest approved compatible catalog that this binary
// accepts. A refused catalog leaves older approved catalogs eligible, so a catalog
// whose stated minimum gateway is too low cannot take down gateways while an older
// approved catalog remains readable. A failed download ends the search because it
// says nothing about whether this binary can read the catalog.
func (e *currentEvidence) updateCatalog(parent context.Context, gatewayID string) error {
	candidates := e.summary.catalogs(gatewayID)
	// Forget refusals of catalogs that are no longer approved, so the list stays
	// bounded by the approval set and a later approval of the same bytes is retried.
	e.refusedCatalogs = slices.DeleteFunc(e.refusedCatalogs, func(refused catalogRejection) bool {
		return !slices.ContainsFunc(candidates, func(approved approvedCatalog) bool { return approved.rejection() == refused })
	})
	if len(candidates) == 0 {
		return errCatalogUnapproved
	}
	refusal := errCatalogIncompatible
	for _, approved := range candidates {
		if approved.active() {
			return nil
		}
		if slices.Contains(e.refusedCatalogs, approved.rejection()) {
			continue
		}
		err := e.installCatalog(parent, approved)
		if !errors.Is(err, errCatalogIncompatible) {
			return err
		}
		e.refusedCatalogs = append(e.refusedCatalogs, approved.rejection())
		refusal = err
	}
	return refusal
}

// refusedCatalogSequences lists the approved compatible catalogs this binary refused.
func (e *currentEvidence) refusedCatalogSequences() []uint64 {
	sequences := make([]uint64, 0, len(e.refusedCatalogs))
	for _, refused := range e.refusedCatalogs {
		sequences = append(sequences, refused.identity.Sequence)
	}
	slices.Sort(sequences)
	return sequences
}

func (e *currentEvidence) installCatalog(parent context.Context, approved approvedCatalog) error {
	release := approved.Release
	ctx, cancel := context.WithTimeout(parent, evidenceAcquisitionTimeout)
	defer cancel()
	runtimeBytes, err := e.artifact(ctx, release.RuntimeDigest, release.RuntimeSizeBytes, catalog.MaxRuntimeBytes)
	if err != nil {
		return errors.Join(errCatalogUnavailable, err)
	}
	publicBytes, err := e.artifact(ctx, release.PublicDigest, release.PublicSizeBytes, catalog.MaxPublicBytes)
	if err != nil {
		return errors.Join(errCatalogUnavailable, err)
	}
	if err := catalog.InstallApproved(runtimeBytes, publicBytes, approved.identity(), release.PublicDigest); err != nil {
		return errors.Join(errCatalogIncompatible, err)
	}
	return nil
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
