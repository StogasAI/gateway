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
	"time"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"golang.org/x/sync/errgroup"
)

// artifactBytesPerSecond is the slowest delivery that a catalog download waits for beyond the
// evidence timeouts, so a large catalog has time to arrive and a stalled origin still fails over.
const artifactBytesPerSecond = 4 << 20

// partDownloads is how many parts of a catalog download at once.
const partDownloads = 8

// transferTime is how long size bytes take at the slowest delivery a download waits for.
func transferTime(size int64) time.Duration {
	return time.Duration(size) * time.Second / artifactBytesPerSecond
}

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

// identity names an approved release by its sequence and the digest of its root, which also
// identifies a refused release: installing verified bytes is deterministic, so this process does
// not download the same approval again.
func (approved approvedCatalog) identity() catalog.Identity {
	return catalog.Identity{Sequence: approved.Release.Sequence, Digest: approved.Release.RootDigest}
}

func (approved approvedCatalog) active() bool {
	return catalog.ActiveMatchesApproved(approved.identity())
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
	e.refusedCatalogs = slices.DeleteFunc(e.refusedCatalogs, func(refused catalog.Identity) bool {
		return !slices.ContainsFunc(candidates, func(approved approvedCatalog) bool { return approved.identity() == refused })
	})
	if len(candidates) == 0 {
		return errCatalogUnapproved
	}
	refusal := errCatalogIncompatible
	for _, approved := range candidates {
		if approved.active() {
			return nil
		}
		if slices.Contains(e.refusedCatalogs, approved.identity()) {
			continue
		}
		err := e.installCatalog(parent, approved)
		if !errors.Is(err, errCatalogIncompatible) {
			return err
		}
		e.refusedCatalogs = append(e.refusedCatalogs, approved.identity())
		refusal = err
	}
	return refusal
}

// refusedCatalogSequences lists the approved compatible catalogs this binary refused.
func (e *currentEvidence) refusedCatalogSequences() []uint64 {
	sequences := make([]uint64, 0, len(e.refusedCatalogs))
	for _, refused := range e.refusedCatalogs {
		sequences = append(sequences, refused.Sequence)
	}
	slices.Sort(sequences)
	return sequences
}

// installCatalog installs an approved release with the parts in effect now: those that hold a
// record that has not retired.
func (e *currentEvidence) installCatalog(parent context.Context, approved approvedCatalog) error {
	release := approved.Release
	ctx, cancel := context.WithTimeout(parent, evidenceAcquisitionTimeout+transferTime(release.RootSizeBytes))
	defer cancel()
	root, err := e.artifact(ctx, release.RootDigest, release.RootSizeBytes, catalog.MaxRootBytes)
	if err != nil {
		return errors.Join(errCatalogUnavailable, err)
	}
	now := e.now()
	files, err := catalog.PartsInEffect(root, now)
	if err != nil {
		return errors.Join(errCatalogIncompatible, err)
	}
	parts, err := e.parts(parent, files)
	if err != nil {
		return errors.Join(errCatalogUnavailable, err)
	}
	if err := catalog.InstallApproved(root, parts, approved.identity(), now); err != nil {
		return errors.Join(errCatalogIncompatible, err)
	}
	return nil
}

// parts gets each of a root's parts that files names. The active release supplies each part
// that it shares with the new one, so a release downloads only the parts that changed.
func (e *currentEvidence) parts(parent context.Context, files []catalog.PartFile) (map[string][]byte, error) {
	parts := make(map[string][]byte, len(files))
	var missing []catalog.PartFile
	var size int64
	for _, file := range files {
		if data, ok := catalog.ActiveCatalogPart(file.SHA256); ok {
			parts[file.SHA256] = data
			continue
		}
		missing = append(missing, file)
		size += file.Size
	}
	ctx, cancel := context.WithTimeout(parent, evidenceAcquisitionTimeout+transferTime(size))
	defer cancel()
	downloaded := make([][]byte, len(missing))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(partDownloads)
	for index, file := range missing {
		group.Go(func() error {
			// The root checked each size against the limit of a part.
			data, err := e.artifact(groupContext, "sha256:"+file.SHA256, file.Size, file.Size)
			downloaded[index] = data
			return err
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	for index, file := range missing {
		parts[file.SHA256] = downloaded[index]
	}
	return parts, nil
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
	ctx, cancel := context.WithTimeout(parent, evidenceAttemptTimeout+transferTime(limit))
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
