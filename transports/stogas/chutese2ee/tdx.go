package chutese2ee

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"golang.org/x/sync/singleflight"
)

const (
	maxTDXQuoteSize          = 128 << 10
	maxEvidenceCertSize      = 128 << 10
	maxEvidenceSignatureSize = 16 << 10
	maxAttestedBodySize      = 16 << 20
	maxCollateralSize        = 8 << 20
	maxCollateralEntries     = 64
	collateralCacheTTL       = 30 * time.Minute
	collateralHTTPTimeout    = 20 * time.Second
)

var intelCollateralHosts = map[string]struct{}{
	"api.trustedservices.intel.com":          {},
	"certificates.trustedservices.intel.com": {},
}

//go:embed intel-sgx-root-ca.pem
var intelSGXRootCAPEM []byte

func loadIntelTrustedRoots() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(intelSGXRootCAPEM) {
		return nil, errors.New("parse pinned Intel SGX root CA")
	}
	return pool, nil
}

type collateralEntry struct {
	headers   map[string][]string
	body      []byte
	expiresAt time.Time
}

type collateralGetter struct {
	client *http.Client
	mu     sync.RWMutex
	cache  map[string]collateralEntry
	flight singleflight.Group
}

func newCollateralGetter() *collateralGetter {
	return &collateralGetter{
		client: &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2:      true,
				MaxIdleConns:           16,
				MaxIdleConnsPerHost:    8,
				IdleConnTimeout:        30 * time.Second,
				TLSHandshakeTimeout:    10 * time.Second,
				MaxResponseHeaderBytes: 64 << 10,
				TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			},
			Timeout: collateralHTTPTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("disallowed Intel collateral redirect")
			},
		},
		cache: make(map[string]collateralEntry),
	}
}

func (g *collateralGetter) get(ctx context.Context, rawURL string) (map[string][]string, []byte, error) {
	now := time.Now()
	g.mu.RLock()
	entry, ok := g.cache[rawURL]
	g.mu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return cloneHeaders(entry.headers), slices.Clone(entry.body), nil
	}
	resultChannel := g.flight.DoChan(rawURL, func() (any, error) {
		now := time.Now()
		g.mu.RLock()
		cached, exists := g.cache[rawURL]
		g.mu.RUnlock()
		if exists && now.Before(cached.expiresAt) {
			return cached, nil
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" || parsed.Port() != "" {
			return nil, errors.New("invalid Intel collateral URL")
		}
		if _, allowed := intelCollateralHosts[parsed.Hostname()]; !allowed {
			return nil, errors.New("disallowed Intel collateral URL host")
		}
		requestContext, cancel := context.WithTimeout(context.Background(), collateralHTTPTimeout)
		defer cancel()
		headers, body, err := g.fetch(requestContext, parsed.String())
		if err != nil {
			return nil, err
		}
		storedAt := time.Now()
		fresh := collateralEntry{
			headers:   headers,
			body:      slices.Clone(body),
			expiresAt: storedAt.Add(collateralCacheTTL),
		}
		g.store(rawURL, fresh, storedAt)
		return fresh, nil
	})
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case result := <-resultChannel:
		if result.Err != nil {
			return nil, nil, result.Err
		}
		entry = result.Val.(collateralEntry)
		return cloneHeaders(entry.headers), slices.Clone(entry.body), nil
	}
}

func (g *collateralGetter) fetch(ctx context.Context, rawURL string) (map[string][]string, []byte, error) {
	var headers map[string][]string
	var body []byte
	err := retryChutesRead(ctx, false, 2*time.Second, func() error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		response, err := g.client.Do(request)
		if err != nil {
			return err
		}
		candidate, readErr := io.ReadAll(io.LimitReader(response.Body, maxCollateralSize+1))
		closeErr := response.Body.Close()
		switch {
		case readErr != nil:
			return readErr
		case closeErr != nil:
			return closeErr
		case len(candidate) > maxCollateralSize:
			return errors.New("oversized Intel collateral response")
		case response.StatusCode == http.StatusOK:
			headers = cloneHeaders(response.Header)
			body = candidate
			return nil
		default:
			return &httpStatusError{
				Operation:  "GET Intel collateral",
				StatusCode: response.StatusCode,
				RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
			}
		}
	})
	return headers, body, err
}

func (g *collateralGetter) store(rawURL string, fresh collateralEntry, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, cached := range g.cache {
		if !now.Before(cached.expiresAt) {
			delete(g.cache, key)
		}
	}
	if _, exists := g.cache[rawURL]; !exists && len(g.cache) >= maxCollateralEntries {
		var oldestKey string
		var oldestExpiry time.Time
		for key, cached := range g.cache {
			if oldestKey == "" || cached.expiresAt.Before(oldestExpiry) ||
				(cached.expiresAt.Equal(oldestExpiry) && key < oldestKey) {
				oldestKey = key
				oldestExpiry = cached.expiresAt
			}
		}
		delete(g.cache, oldestKey)
	}
	g.cache[rawURL] = fresh
}

type scopedCollateralGetter struct {
	ctx    context.Context
	shared *collateralGetter
}

func (g scopedCollateralGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	return g.shared.get(g.ctx, rawURL)
}

func (g *collateralGetter) close() {
	if g == nil || g.client == nil {
		return
	}
	if transport, ok := g.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func cloneHeaders(source map[string][]string) map[string][]string {
	clone := make(map[string][]string, len(source))
	for key, values := range source {
		clone[key] = slices.Clone(values)
	}
	return clone
}

func verifyTDXEvidence(
	ctx context.Context,
	evidence instanceEvidence,
	nonce string,
	publicKey string,
	policy *policySnapshot,
	getter *collateralGetter,
	trustedRoots *x509.CertPool,
	now time.Time,
) (*measurementPolicy, bool, error) {
	quoteBytes, err := base64.StdEncoding.Strict().DecodeString(evidence.Quote)
	if err != nil || len(quoteBytes) == 0 || len(quoteBytes) > maxTDXQuoteSize {
		return nil, false, fmt.Errorf("%w: malformed TDX quote", ErrAttestationFailed)
	}
	parsedAny, err := abi.QuoteToProto(quoteBytes)
	if err != nil {
		return nil, false, fmt.Errorf("%w: parse TDX quote", ErrAttestationFailed)
	}
	quote, ok := parsedAny.(*tdxpb.QuoteV4)
	if !ok {
		return nil, false, fmt.Errorf("%w: unsupported TDX quote type %T", ErrAttestationFailed, parsedAny)
	}
	if quote.GetTdQuoteBody() == nil {
		return nil, false, fmt.Errorf("%w: TDX quote body is missing", ErrAttestationFailed)
	}
	body := quote.GetTdQuoteBody()
	if err := validateTDAttributes(body.GetTdAttributes()); err != nil {
		return nil, false, err
	}

	certificateDER, err := base64.StdEncoding.Strict().DecodeString(evidence.Certificate)
	if err != nil || len(certificateDER) == 0 || len(certificateDER) > maxEvidenceCertSize {
		return nil, false, fmt.Errorf("%w: malformed evidence certificate", ErrAttestationFailed)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, false, fmt.Errorf("%w: parse evidence certificate", ErrAttestationFailed)
	}
	keyPossessionVerified, err := verifyEvidenceKeyPossession(evidence, certificate)
	if err != nil {
		return nil, false, err
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, false, fmt.Errorf("%w: encode evidence certificate key", ErrAttestationFailed)
	}
	bindingHash := sha256.Sum256([]byte(nonce + publicKey))
	certificateHash := sha256.Sum256(publicKeyDER)
	expectedReportData := make([]byte, 0, sha256.Size*2)
	expectedReportData = append(expectedReportData, bindingHash[:]...)
	expectedReportData = append(expectedReportData, certificateHash[:]...)
	if len(body.GetReportData()) != len(expectedReportData) ||
		subtle.ConstantTimeCompare(body.GetReportData(), expectedReportData) != 1 {
		return nil, false, fmt.Errorf("%w: TDX report data is not bound to the requested key", ErrAttestationFailed)
	}

	measurement, err := matchMeasurement(quote, policy)
	if err != nil {
		return nil, false, err
	}
	mrtd, _ := decodeMeasurementHex(measurement.MRTD)
	rtmrs := make([][]byte, 4)
	for index := 0; index < 4; index++ {
		rtmrs[index], _ = decodeMeasurementHex(measurement.RuntimeRTMRs[fmt.Sprintf("RTMR%d", index)])
	}
	if err := validate.RawTdxQuote(quoteBytes, &validate.Options{
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			MrTd:       mrtd,
			Rtmrs:      rtmrs,
			ReportData: expectedReportData,
		},
	}); err != nil {
		return nil, false, fmt.Errorf("%w: TDX quote policy validation", ErrAttestationFailed)
	}
	if err := verify.RawTdxQuote(quoteBytes, &verify.Options{
		CheckRevocations: true,
		GetCollateral:    true,
		Getter:           scopedCollateralGetter{ctx: ctx, shared: getter},
		Now:              now,
		TrustedRoots:     trustedRoots,
	}); err != nil {
		return nil, false, fmt.Errorf("%w: TDX signature or collateral validation", ErrAttestationFailed)
	}
	return measurement, keyPossessionVerified, nil
}

func verifyEvidenceKeyPossession(evidence instanceEvidence, certificate *x509.Certificate) (bool, error) {
	if evidence.Signature == "" && evidence.AttestedBody == "" {
		return false, fmt.Errorf("%w: evidence key-possession proof is missing", ErrAttestationFailed)
	}
	if evidence.Signature == "" || evidence.AttestedBody == "" || certificate == nil {
		return false, fmt.Errorf("%w: incomplete evidence key-possession proof", ErrAttestationFailed)
	}
	if base64.StdEncoding.DecodedLen(len(evidence.Signature)) > maxEvidenceSignatureSize ||
		base64.StdEncoding.DecodedLen(len(evidence.AttestedBody)) > maxAttestedBodySize {
		return false, fmt.Errorf("%w: evidence key-possession proof is too large", ErrAttestationFailed)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(evidence.Signature)
	if err != nil || len(signature) == 0 || len(signature) > maxEvidenceSignatureSize {
		return false, fmt.Errorf("%w: malformed evidence key-possession signature", ErrAttestationFailed)
	}
	body, err := base64.StdEncoding.Strict().DecodeString(evidence.AttestedBody)
	if err != nil || len(body) == 0 || len(body) > maxAttestedBodySize {
		return false, fmt.Errorf("%w: malformed attested evidence body", ErrAttestationFailed)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N == nil || publicKey.Size() < 256 {
		return false, fmt.Errorf("%w: unsupported evidence certificate key", ErrAttestationFailed)
	}
	digest := sha256.Sum256(body)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return false, fmt.Errorf("%w: evidence key-possession signature validation", ErrAttestationFailed)
	}
	if err := verifyAttestedEvidenceBody(body, evidence); err != nil {
		return false, err
	}
	return true, nil
}

func verifyAttestedEvidenceBody(body []byte, evidence instanceEvidence) error {
	var attested struct {
		Evidence struct {
			TDXQuote        string          `json:"tdx_quote"`
			NVTrustEvidence json.RawMessage `json:"nvtrust_evidence"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(body, &attested); err != nil || attested.Evidence.TDXQuote == "" ||
		len(attested.Evidence.NVTrustEvidence) == 0 {
		return fmt.Errorf("%w: malformed signed evidence body", ErrAttestationFailed)
	}
	outerQuote, outerErr := base64.StdEncoding.Strict().DecodeString(evidence.Quote)
	attestedQuote, attestedErr := base64.StdEncoding.Strict().DecodeString(attested.Evidence.TDXQuote)
	if outerErr != nil || attestedErr != nil || len(outerQuote) == 0 ||
		subtle.ConstantTimeCompare(outerQuote, attestedQuote) != 1 {
		return fmt.Errorf("%w: signed TDX quote does not match evidence", ErrAttestationFailed)
	}
	var encodedGPUEvidence string
	if err := json.Unmarshal(attested.Evidence.NVTrustEvidence, &encodedGPUEvidence); err != nil || encodedGPUEvidence == "" {
		return fmt.Errorf("%w: malformed signed GPU evidence", ErrAttestationFailed)
	}
	var attestedGPUEvidence []map[string]any
	if err := json.Unmarshal([]byte(encodedGPUEvidence), &attestedGPUEvidence); err != nil {
		return fmt.Errorf("%w: malformed signed GPU evidence", ErrAttestationFailed)
	}
	attestedGPUJSON, attestedErr := json.Marshal(attestedGPUEvidence)
	outerGPUJSON, outerErr := json.Marshal(evidence.GPUEvidence)
	if attestedErr != nil || outerErr != nil || !bytes.Equal(attestedGPUJSON, outerGPUJSON) {
		return fmt.Errorf("%w: signed GPU evidence does not match evidence", ErrAttestationFailed)
	}
	return nil
}

func validateTDAttributes(attributes []byte) error {
	if len(attributes) != 8 || attributes[0]&1 != 0 {
		return fmt.Errorf("%w: TDX debug mode is enabled or attributes are invalid", ErrAttestationFailed)
	}
	return nil
}
