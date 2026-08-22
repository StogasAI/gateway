package chutese2ee

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

const (
	nrasIssuer       = "https://nras.attestation.nvidia.com"
	nrasEndpoint     = nrasIssuer + "/v4/attest/gpu"
	nrasJWKSEndpoint = nrasIssuer + "/.well-known/jwks.json"
	nrasKeyTTL       = time.Hour
	nrasTimeout      = 30 * time.Second
	maxJWTSize       = 512 << 10
)

var (
	gpuLabelPattern          = regexp.MustCompile(`^GPU-([0-9]+)$`)
	requiredGPUBooleanClaims = []string{
		"x-nvidia-gpu-driver-rim-schema-validated",
		"x-nvidia-gpu-attestation-report-cert-chain-validated",
		"x-nvidia-gpu-vbios-rim-signature-verified",
		"x-nvidia-gpu-vbios-rim-fetched",
		"x-nvidia-gpu-attestation-report-nonce-match",
		"x-nvidia-gpu-vbios-index-no-conflict",
		"x-nvidia-gpu-vbios-rim-cert-validated",
		"x-nvidia-gpu-attestation-report-parsed",
		"x-nvidia-gpu-driver-rim-signature-verified",
		"x-nvidia-gpu-arch-check",
		"x-nvidia-gpu-driver-rim-measurements-available",
		"x-nvidia-gpu-attestation-report-signature-verified",
		"x-nvidia-gpu-driver-rim-fetched",
		"x-nvidia-gpu-vbios-rim-schema-validated",
		"x-nvidia-gpu-driver-rim-cert-validated",
		"x-nvidia-gpu-vbios-rim-measurements-available",
	}
)

type nrasVerifier struct {
	client       *http.Client
	endpoint     string
	jwksEndpoint string
	mu           sync.RWMutex
	keys         map[string]*ecdsa.PublicKey
	keysUntil    time.Time
	flight       singleflight.Group
}

type nrasJWKSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Kid string `json:"kid"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

func newNRASVerifier() *nrasVerifier {
	return &nrasVerifier{
		client: &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2:      true,
				MaxIdleConns:           16,
				MaxIdleConnsPerHost:    8,
				IdleConnTimeout:        30 * time.Second,
				TLSHandshakeTimeout:    10 * time.Second,
				MaxResponseHeaderBytes: 64 << 10,
				TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13},
			},
			Timeout: nrasTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("NVIDIA attestation redirects are not permitted")
			},
		},
		endpoint:     nrasEndpoint,
		jwksEndpoint: nrasJWKSEndpoint,
		keys:         make(map[string]*ecdsa.PublicKey),
	}
}

func (v *nrasVerifier) close() {
	if v == nil || v.client == nil {
		return
	}
	if transport, ok := v.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (v *nrasVerifier) verify(
	ctx context.Context,
	evidence []map[string]any,
	expectedNonce string,
	expectedGPUCount int,
	expectedGPUFamilies []string,
	now time.Time,
) error {
	if len(evidence) != expectedGPUCount || expectedGPUCount < 1 {
		return fmt.Errorf("%w: GPU count does not match the TEE policy", ErrGPUAttestationFailed)
	}
	allowedFamilies := make(map[string]struct{}, len(expectedGPUFamilies))
	for _, family := range expectedGPUFamilies {
		if _, accepted := acceptedGPUFamilies[family]; !accepted {
			return fmt.Errorf("%w: GPU family is not accepted", ErrGPUAttestationFailed)
		}
		allowedFamilies[family] = struct{}{}
	}
	if len(allowedFamilies) == 0 {
		return fmt.Errorf("%w: GPU family policy is empty", ErrGPUAttestationFailed)
	}
	arch := ""
	items := make([]map[string]string, 0, len(evidence))
	for _, raw := range evidence {
		itemArch, ok := raw["arch"].(string)
		itemArch = strings.ToUpper(strings.TrimSpace(itemArch))
		if !ok || (itemArch != "BLACKWELL" && itemArch != "HOPPER") || (arch != "" && arch != itemArch) {
			return fmt.Errorf("%w: inconsistent GPU architecture", ErrGPUAttestationFailed)
		}
		arch = itemArch
		report, reportOK := raw["evidence"].(string)
		certificate, certificateOK := raw["certificate"].(string)
		if !reportOK || !certificateOK || report == "" || certificate == "" || len(report) > 4<<20 || len(certificate) > 1<<20 {
			return fmt.Errorf("%w: malformed GPU evidence", ErrGPUAttestationFailed)
		}
		items = append(items, map[string]string{"evidence": report, "certificate": certificate})
	}
	payload, err := json.Marshal(map[string]any{
		"nonce":          expectedNonce,
		"evidence_list":  items,
		"arch":           arch,
		"claims_version": "2.0",
	})
	if err != nil {
		return err
	}
	body, err := v.request(ctx, http.MethodPost, v.endpoint, payload)
	if err != nil {
		return fmt.Errorf("%w: NVIDIA remote verifier: %w", ErrGPUAttestationFailed, err)
	}
	var envelope []json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil || len(envelope) != 2 {
		return fmt.Errorf("%w: malformed NVIDIA token envelope", ErrGPUAttestationFailed)
	}
	var overallEnvelope []string
	var detachedTokens map[string]string
	if err := json.Unmarshal(envelope[0], &overallEnvelope); err != nil || len(overallEnvelope) != 2 || overallEnvelope[0] != "JWT" || len(overallEnvelope[1]) > maxJWTSize {
		return fmt.Errorf("%w: malformed NVIDIA overall token", ErrGPUAttestationFailed)
	}
	if err := json.Unmarshal(envelope[1], &detachedTokens); err != nil || len(detachedTokens) != expectedGPUCount {
		return fmt.Errorf("%w: malformed NVIDIA detached tokens", ErrGPUAttestationFailed)
	}

	overall, err := v.parseToken(ctx, overallEnvelope[1], now)
	if err != nil {
		return err
	}
	if subject, _ := overall.GetSubject(); subject != "NVIDIA-PLATFORM-ATTESTATION" ||
		claimString(overall, "x-nvidia-ver") != "2.0" ||
		!claimBool(overall, "x-nvidia-overall-att-result") ||
		!constantTimeStringEqual(claimString(overall, "eat_nonce"), expectedNonce) {
		return fmt.Errorf("%w: invalid NVIDIA overall claims", ErrGPUAttestationFailed)
	}
	overallTimes, err := validateTokenTimes(overall, now)
	if err != nil {
		return err
	}
	submods, ok := overall["submods"].(map[string]any)
	if !ok || len(submods) != expectedGPUCount {
		return fmt.Errorf("%w: invalid NVIDIA submodule claims", ErrGPUAttestationFailed)
	}
	if err := validateGPULabels(submods, expectedGPUCount); err != nil {
		return err
	}

	labels := make([]string, 0, len(detachedTokens))
	for label := range detachedTokens {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	uniqueIDs := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		tokenString := detachedTokens[label]
		if len(tokenString) == 0 || len(tokenString) > maxJWTSize {
			return fmt.Errorf("%w: invalid NVIDIA detached token size", ErrGPUAttestationFailed)
		}
		digestClaim, exists := submods[label]
		if !exists || !validSubmoduleDigest(digestClaim, tokenString) {
			return fmt.Errorf("%w: NVIDIA detached token digest mismatch", ErrGPUAttestationFailed)
		}
		claims, err := v.parseToken(ctx, tokenString, now)
		if err != nil {
			return err
		}
		hardwareModel := claimString(claims, "hwmodel")
		family, exactFamily := gpuFamilyForHardwareModel(hardwareModel)
		if !constantTimeStringEqual(claimString(claims, "eat_nonce"), expectedNonce) {
			return fmt.Errorf("%w: NVIDIA detached nonce mismatch", ErrGPUAttestationFailed)
		}
		if claimString(claims, "dbgstat") != "disabled" {
			return fmt.Errorf("%w: NVIDIA GPU debug mode is not disabled", ErrGPUAttestationFailed)
		}
		if claimString(claims, "measres") != "success" {
			return fmt.Errorf("%w: NVIDIA GPU measurements failed", ErrGPUAttestationFailed)
		}
		if !claimBool(claims, "secboot") {
			return fmt.Errorf("%w: NVIDIA GPU secure boot is not enabled", ErrGPUAttestationFailed)
		}
		if exactFamily {
			if _, allowed := allowedFamilies[family]; !allowed {
				return fmt.Errorf("%w: NVIDIA GPU family is not allowed by the TEE policy", ErrGPUAttestationFailed)
			}
			if !gpuFamilyMatchesArchitecture(family, arch) {
				return fmt.Errorf("%w: NVIDIA GPU family and architecture disagree", ErrGPUAttestationFailed)
			}
		} else {
			hardwareArchitecture, known := gpuArchitectureForHardwareModel(hardwareModel)
			if !known {
				return fmt.Errorf("%w: NVIDIA GPU hardware model %q is unknown", ErrGPUAttestationFailed, hardwareModel)
			}
			if hardwareArchitecture != arch || !gpuPolicyAllowsArchitecture(allowedFamilies, arch) {
				return fmt.Errorf("%w: NVIDIA GPU hardware architecture does not match the TEE policy", ErrGPUAttestationFailed)
			}
		}
		if claimString(claims, "x-nvidia-gpu-driver-version") == "" || claimString(claims, "x-nvidia-gpu-vbios-version") == "" {
			return fmt.Errorf("%w: NVIDIA GPU firmware identity is missing", ErrGPUAttestationFailed)
		}
		for _, name := range requiredGPUBooleanClaims {
			if !claimBool(claims, name) {
				return fmt.Errorf("%w: required NVIDIA claim is false", ErrGPUAttestationFailed)
			}
		}
		if warning, exists := claims["x-nvidia-attestation-warning"]; exists && !emptyAttestationWarning(warning) {
			return fmt.Errorf("%w: NVIDIA attestation warning is present", ErrGPUAttestationFailed)
		}
		times, err := validateTokenTimes(claims, now)
		if err != nil || times != overallTimes {
			return fmt.Errorf("%w: inconsistent NVIDIA token times", ErrGPUAttestationFailed)
		}
		uniqueID := claimString(claims, "ueid")
		if uniqueID == "" {
			return fmt.Errorf("%w: NVIDIA GPU identity is missing", ErrGPUAttestationFailed)
		}
		if _, duplicate := uniqueIDs[uniqueID]; duplicate {
			return fmt.Errorf("%w: duplicate NVIDIA GPU identity", ErrGPUAttestationFailed)
		}
		uniqueIDs[uniqueID] = struct{}{}
	}
	return nil
}

func (v *nrasVerifier) parseToken(ctx context.Context, tokenString string, now time.Time) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES384"}),
		jwt.WithJSONNumber(),
		jwt.WithIssuer(nrasIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != "ES384" {
			return nil, errors.New("unexpected NVIDIA JWT algorithm")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("NVIDIA JWT key ID is missing")
		}
		return v.key(ctx, kid)
	})
	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("%w: NVIDIA JWT verification failed", ErrGPUAttestationFailed)
	}
	return claims, nil
}

func (v *nrasVerifier) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	now := time.Now()
	v.mu.RLock()
	key := v.keys[kid]
	valid := now.Before(v.keysUntil)
	v.mu.RUnlock()
	if key != nil && valid {
		return key, nil
	}
	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	key = v.keys[kid]
	v.mu.RUnlock()
	if key == nil {
		return nil, errors.New("NVIDIA JWT key ID is unknown")
	}
	return key, nil
}

func (v *nrasVerifier) refreshKeys(ctx context.Context) error {
	_, err, _ := v.flight.Do("jwks", func() (any, error) {
		body, err := v.request(ctx, http.MethodGet, v.jwksEndpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("fetch NVIDIA JWKS: %w", err)
		}
		var set nrasJWKSet
		if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 || len(set.Keys) > 256 {
			return nil, errors.New("invalid NVIDIA JWKS")
		}
		keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
		for _, item := range set.Keys {
			if item.Kty != "EC" || item.Crv != "P-384" || item.Kid == "" || len(item.Kid) > 256 {
				return nil, errors.New("invalid NVIDIA JWK")
			}
			xBytes, xErr := base64.RawURLEncoding.Strict().DecodeString(item.X)
			yBytes, yErr := base64.RawURLEncoding.Strict().DecodeString(item.Y)
			if xErr != nil || yErr != nil || len(xBytes) != 48 || len(yBytes) != 48 {
				return nil, errors.New("invalid NVIDIA JWK coordinates")
			}
			encodedKey := make([]byte, 1+len(xBytes)+len(yBytes))
			encodedKey[0] = 4
			copy(encodedKey[1:], xBytes)
			copy(encodedKey[1+len(xBytes):], yBytes)
			key, keyErr := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), encodedKey)
			if keyErr != nil {
				return nil, errors.New("NVIDIA JWK is not on P-384")
			}
			if _, duplicate := keys[item.Kid]; duplicate {
				return nil, errors.New("duplicate NVIDIA JWK key ID")
			}
			keys[item.Kid] = key
		}
		v.mu.Lock()
		v.keys = keys
		v.keysUntil = time.Now().Add(nrasKeyTTL)
		v.mu.Unlock()
		return nil, nil
	})
	return err
}

func (v *nrasVerifier) request(ctx context.Context, method, endpoint string, payload []byte) ([]byte, error) {
	var body []byte
	err := retryChutesRead(ctx, false, 2*time.Second, func() error {
		var requestBody io.Reader
		if payload != nil {
			requestBody = bytes.NewReader(payload)
		}
		request, err := http.NewRequestWithContext(ctx, method, endpoint, requestBody)
		if err != nil {
			return err
		}
		request.Header.Set("Accept", "application/json")
		if payload != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := v.client.Do(request)
		if err != nil {
			return err
		}
		candidate, readErr := io.ReadAll(io.LimitReader(response.Body, maxNRASBody+1))
		closeErr := response.Body.Close()
		switch {
		case readErr != nil:
			return readErr
		case closeErr != nil:
			return closeErr
		case len(candidate) > maxNRASBody:
			return errors.New("NVIDIA response is too large")
		case response.StatusCode == http.StatusOK:
			body = candidate
			return nil
		default:
			return &httpStatusError{
				Operation:  method + " NVIDIA attestation",
				StatusCode: response.StatusCode,
				RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
			}
		}
	})
	return body, err
}

type tokenTimes struct {
	IssuedAt  int64
	NotBefore int64
	ExpiresAt int64
}

func validateTokenTimes(claims jwt.MapClaims, now time.Time) (tokenTimes, error) {
	issuedAt, issuedErr := claims.GetIssuedAt()
	notBefore, notBeforeErr := claims.GetNotBefore()
	expiresAt, expiresErr := claims.GetExpirationTime()
	if issuedErr != nil || notBeforeErr != nil || expiresErr != nil || issuedAt == nil || notBefore == nil || expiresAt == nil {
		return tokenTimes{}, fmt.Errorf("%w: NVIDIA token times are missing", ErrGPUAttestationFailed)
	}
	result := tokenTimes{IssuedAt: issuedAt.Unix(), NotBefore: notBefore.Unix(), ExpiresAt: expiresAt.Unix()}
	if issuedAt.After(now.Add(30*time.Second)) || issuedAt.Before(now.Add(-5*time.Minute)) ||
		notBefore.After(now.Add(30*time.Second)) || !expiresAt.After(now) ||
		expiresAt.Sub(issuedAt.Time) <= 0 || expiresAt.Sub(issuedAt.Time) > 2*time.Hour {
		return tokenTimes{}, fmt.Errorf("%w: NVIDIA token freshness is invalid", ErrGPUAttestationFailed)
	}
	return result, nil
}

func validateGPULabels(submods map[string]any, expected int) error {
	indices := make([]int, 0, len(submods))
	for label := range submods {
		matches := gpuLabelPattern.FindStringSubmatch(label)
		if len(matches) != 2 {
			return fmt.Errorf("%w: invalid NVIDIA GPU label", ErrGPUAttestationFailed)
		}
		var index int
		if _, err := fmt.Sscanf(matches[1], "%d", &index); err != nil {
			return fmt.Errorf("%w: invalid NVIDIA GPU index", ErrGPUAttestationFailed)
		}
		indices = append(indices, index)
	}
	sort.Ints(indices)
	for index, value := range indices {
		if value != index || index >= expected {
			return fmt.Errorf("%w: non-contiguous NVIDIA GPU labels", ErrGPUAttestationFailed)
		}
	}
	return nil
}

func validSubmoduleDigest(claim any, token string) bool {
	outer, ok := claim.([]any)
	if !ok || len(outer) != 2 || outer[0] != "DIGEST" {
		return false
	}
	inner, ok := outer[1].([]any)
	if !ok || len(inner) != 2 || inner[0] != "SHA-256" {
		return false
	}
	expectedHex, ok := inner[1].(string)
	if !ok {
		return false
	}
	expected, err := hex.DecodeString(expectedHex)
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	actual := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(expected, actual[:]) == 1
}

func claimString(claims jwt.MapClaims, name string) string {
	value, _ := claims[name].(string)
	return value
}

func claimBool(claims jwt.MapClaims, name string) bool {
	value, _ := claims[name].(bool)
	return value
}

func emptyAttestationWarning(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case []any:
		return len(typed) == 0
	default:
		return false
	}
}

func constantTimeStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func gpuFamilyForHardwareModel(model string) (string, bool) {
	normalized := strings.ToLower(strings.NewReplacer("_", " ", "-", " ").Replace(strings.TrimSpace(model)))
	switch {
	case normalized == "gb110":
		return "b300", true
	case strings.Contains(normalized, "b300"):
		return "b300", true
	case strings.Contains(normalized, "b200"):
		return "b200", true
	case strings.Contains(normalized, "h200"):
		return "h200", true
	case strings.Contains(normalized, "pro 6000"):
		return "pro_6000", true
	default:
		return "", false
	}
}

func gpuFamilyMatchesArchitecture(family, architecture string) bool {
	switch family {
	case "h200":
		return architecture == "HOPPER"
	case "b200", "b300", "pro_6000":
		return architecture == "BLACKWELL"
	default:
		return false
	}
}

func gpuArchitectureForHardwareModel(model string) (string, bool) {
	if family, ok := gpuFamilyForHardwareModel(model); ok {
		if gpuFamilyMatchesArchitecture(family, "HOPPER") {
			return "HOPPER", true
		}
		if gpuFamilyMatchesArchitecture(family, "BLACKWELL") {
			return "BLACKWELL", true
		}
	}
	switch strings.ToUpper(strings.TrimSpace(model)) {
	case "GB20X", "GB100", "GB200", "GB300":
		return "BLACKWELL", true
	case "GH100":
		return "HOPPER", true
	default:
		return "", false
	}
}

func gpuPolicyAllowsArchitecture(families map[string]struct{}, architecture string) bool {
	for family := range families {
		if gpuFamilyMatchesArchitecture(family, architecture) {
			return true
		}
	}
	return false
}
