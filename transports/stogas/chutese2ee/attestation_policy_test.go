package chutese2ee

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

func TestMeasurementPolicyValidationAndMatching(t *testing.T) {
	measurement := validMeasurementForTest()
	measurements := []measurementPolicy{measurement}
	digest, err := validateAndDigestMeasurements(measurements)
	if err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	if len(digest) != sha256.Size*2 {
		t.Fatalf("policy digest length = %d", len(digest))
	}
	quote := quoteForMeasurementForTest(measurements[0])
	matched, err := matchMeasurement(quote, &policySnapshot{Measurements: measurements, Digest: digest})
	if err != nil {
		t.Fatalf("match measurement: %v", err)
	}
	if matched.Name != measurement.Name || matched.Version != measurement.Version {
		t.Fatalf("matched policy = %#v", matched)
	}

	quote.TdQuoteBody.Rtmrs[3][0] ^= 1
	if _, err := matchMeasurement(quote, &policySnapshot{Measurements: measurements}); err == nil {
		t.Fatal("expected changed runtime measurement to be rejected")
	}
}

func TestMeasurementPolicyRejectsMalformedOrAmbiguousRecords(t *testing.T) {
	tests := map[string]func(*measurementPolicy){
		"unknown GPU": func(value *measurementPolicy) { value.ExpectedGPUs = []string{"future_gpu"} },
		"zero GPUs":   func(value *measurementPolicy) { value.GPUCount = 0 },
		"bad MRTD":    func(value *measurementPolicy) { value.MRTD = "00" },
		"missing RTMR": func(value *measurementPolicy) {
			delete(value.RuntimeRTMRs, "RTMR3")
		},
		"duplicate GPU": func(value *measurementPolicy) {
			value.ExpectedGPUs = []string{"h200", "H200"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			measurement := validMeasurementForTest()
			mutate(&measurement)
			if _, err := validateAndDigestMeasurements([]measurementPolicy{measurement}); err == nil {
				t.Fatal("expected policy validation failure")
			}
		})
	}

	first := validMeasurementForTest()
	second := validMeasurementForTest()
	second.Name = "same-measurement-different-policy"
	second.GPUCount = 4
	snapshot := &policySnapshot{Measurements: []measurementPolicy{first, second}}
	if _, err := matchMeasurement(quoteForMeasurementForTest(first), snapshot); err == nil {
		t.Fatal("expected ambiguous GPU policy to be rejected")
	}
}

func TestTDXAttributesRejectDebugMode(t *testing.T) {
	if err := validateTDAttributes(make([]byte, 8)); err != nil {
		t.Fatalf("safe attributes rejected: %v", err)
	}
	debug := make([]byte, 8)
	debug[0] = 1
	if err := validateTDAttributes(debug); err == nil {
		t.Fatal("expected TDX debug mode to be rejected")
	}
	if err := validateTDAttributes(make([]byte, 7)); err == nil {
		t.Fatal("expected malformed TDX attributes to be rejected")
	}
}

func TestPinnedIntelRootCA(t *testing.T) {
	block, rest := pem.Decode(intelSGXRootCAPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("invalid pinned Intel root PEM")
	}
	fingerprint := sha256.Sum256(block.Bytes)
	if got, want := hex.EncodeToString(fingerprint[:]), "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"; got != want {
		t.Fatalf("Intel root fingerprint = %s, want %s", got, want)
	}
	if roots, err := loadIntelTrustedRoots(); err != nil || roots == nil {
		t.Fatalf("load Intel trusted roots: roots=%v err=%v", roots, err)
	}
}

func TestCollateralCacheIsBoundedAndPrunesExpiredEntries(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	getter := &collateralGetter{cache: make(map[string]collateralEntry)}
	getter.cache["expired"] = collateralEntry{expiresAt: now}
	for index := 0; index < maxCollateralEntries; index++ {
		key := fmt.Sprintf("entry-%02d", index)
		getter.store(key, collateralEntry{expiresAt: now.Add(time.Duration(index+1) * time.Minute)}, now)
	}
	getter.store("new", collateralEntry{expiresAt: now.Add(time.Hour)}, now)

	if len(getter.cache) != maxCollateralEntries {
		t.Fatalf("collateral cache entries = %d, want %d", len(getter.cache), maxCollateralEntries)
	}
	if _, ok := getter.cache["expired"]; ok {
		t.Fatal("expired collateral was not pruned")
	}
	if _, ok := getter.cache["entry-00"]; ok {
		t.Fatal("earliest collateral entry was not evicted")
	}
	if _, ok := getter.cache["new"]; !ok {
		t.Fatal("new collateral entry was not cached")
	}
}

func TestCollateralFetchRetriesOnlyTransientFailures(t *testing.T) {
	var calls atomic.Int32
	getter := &collateralGetter{
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			status := http.StatusOK
			body := []byte("collateral")
			if calls.Add(1) == 1 {
				status = http.StatusServiceUnavailable
				body = []byte("temporarily unavailable")
			}
			return &http.Response{
				StatusCode: status,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		})},
		cache: make(map[string]collateralEntry),
	}
	_, body, err := getter.get(
		context.Background(),
		"https://api.trustedservices.intel.com/tdx/certification/v4/pckcrl?ca=platform",
	)
	if err != nil || string(body) != "collateral" || calls.Load() != 2 {
		t.Fatalf("collateral body=%q calls=%d error=%v", body, calls.Load(), err)
	}
}

func TestAttestationCacheRequiresAnExactFreshBinding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	targetA := ModelTarget{ChuteID: "chute-a", GPUCount: testGPUCount}
	targetB := ModelTarget{ChuteID: "chute-b", GPUCount: testGPUCount}
	verification := verifiedInstance{
		InstanceID:        "instance-a",
		PublicKey:         "public-key-a",
		GPUCount:          testGPUCount,
		MeasurementDigest: "policy-a",
		ValidUntil:        now.Add(time.Minute),
	}
	cache := &attestor{cache: make(map[string]verifiedInstance)}
	cache.storeCachedInstances(targetA, map[string]verifiedInstance{verification.InstanceID: verification})

	matching := cache.cachedInstances(
		targetA,
		[]discoveredInstance{{ID: verification.InstanceID, PublicKey: verification.PublicKey}},
		verification.MeasurementDigest,
		now,
	)
	if got, ok := matching[verification.InstanceID]; !ok || got != verification {
		t.Fatalf("matching attestation cache entry = %#v, %t", got, ok)
	}
	rotatedKey := cache.cachedInstances(
		targetA,
		[]discoveredInstance{{ID: verification.InstanceID, PublicKey: "public-key-b"}},
		verification.MeasurementDigest,
		now,
	)
	if len(rotatedKey) != 0 {
		t.Fatal("rotated instance key reused cached attestation")
	}
	otherChute := cache.cachedInstances(
		targetB,
		[]discoveredInstance{{ID: verification.InstanceID, PublicKey: verification.PublicKey}},
		verification.MeasurementDigest,
		now,
	)
	if len(otherChute) != 0 {
		t.Fatal("attestation cache entry crossed chute boundaries")
	}
	differentGPUCount := cache.cachedInstances(
		ModelTarget{ChuteID: targetA.ChuteID, GPUCount: 1},
		[]discoveredInstance{{ID: verification.InstanceID, PublicKey: verification.PublicKey}},
		verification.MeasurementDigest,
		now,
	)
	if len(differentGPUCount) != 0 {
		t.Fatal("attestation cache entry crossed assigned GPU-count boundaries")
	}

	changedPolicy := cache.cachedInstances(
		targetA,
		[]discoveredInstance{{ID: verification.InstanceID, PublicKey: verification.PublicKey}},
		"policy-b",
		now,
	)
	if len(changedPolicy) != 0 || len(cache.cache) != 0 {
		t.Fatal("changed measurement policy did not invalidate cached attestation")
	}

	cache.storeCachedInstances(targetA, map[string]verifiedInstance{verification.InstanceID: verification})
	expired := cache.cachedInstances(
		targetA,
		[]discoveredInstance{{ID: verification.InstanceID, PublicKey: verification.PublicKey}},
		verification.MeasurementDigest,
		verification.ValidUntil,
	)
	if len(expired) != 0 || len(cache.cache) != 0 {
		t.Fatal("expired attestation remained cached")
	}
}

func TestAttestationCacheIsBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	target := ModelTarget{ChuteID: "chute-a", GPUCount: testGPUCount}
	cache := &attestor{cache: make(map[string]verifiedInstance)}
	for index := 0; index <= maximumAttestationCacheEntries; index++ {
		verification := verifiedInstance{
			InstanceID:        fmt.Sprintf("instance-%04d", index),
			PublicKey:         fmt.Sprintf("public-key-%04d", index),
			GPUCount:          testGPUCount,
			MeasurementDigest: "policy-a",
			ValidUntil:        now.Add(time.Duration(index+1) * time.Second),
		}
		cache.storeCachedInstances(target, map[string]verifiedInstance{verification.InstanceID: verification})
	}

	if len(cache.cache) != maximumAttestationCacheEntries {
		t.Fatalf("attestation cache entries = %d, want %d", len(cache.cache), maximumAttestationCacheEntries)
	}
	if _, ok := cache.cache[attestationCacheKey(target, "instance-0000", "public-key-0000")]; ok {
		t.Fatal("earliest attestation cache entry was not evicted")
	}
	if _, ok := cache.cache[attestationCacheKey(
		target,
		fmt.Sprintf("instance-%04d", maximumAttestationCacheEntries),
		fmt.Sprintf("public-key-%04d", maximumAttestationCacheEntries),
	)]; !ok {
		t.Fatal("new attestation cache entry was not stored")
	}
}

func TestBYOKDiscoveryUsesCustomerKeyWhileEvidenceUsesManagedKey(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(instanceKey.EncapsulationKey().Bytes())
	now := time.Now()
	measurement := validMeasurementForTest()
	measurements := []measurementPolicy{measurement}
	digest, err := validateAndDigestMeasurements(measurements)
	if err != nil {
		t.Fatal(err)
	}
	var discoveryAuthorization string
	var evidenceAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case discoveryPathPrefix + testChuteID:
			discoveryAuthorization = request.Header.Get("Authorization")
			_ = json.NewEncoder(response).Encode(discoveryResponse{
				Instances: []discoveredInstance{{
					ID:        testInstanceID,
					PublicKey: publicKey,
					Tickets:   []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
				}},
				ExpiresIn:     60,
				ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
			})
		case evidencePathPrefix + testChuteID + "/evidence":
			evidenceAuthorization = request.Header.Get("Authorization")
			_ = json.NewEncoder(response).Encode(evidenceResponse{
				FailedInstanceIDs: []string{testInstanceID},
			})
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	managedAPI, err := newAPIClient("managed-key", server.URL, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer managedAPI.close()
	byokAPI, err := managedAPI.withAPIKey("customer-key")
	if err != nil {
		t.Fatal(err)
	}
	defer byokAPI.close()
	attestor := &attestor{
		api:         managedAPI,
		diagnostics: &diagnostics{},
		policies: &policyCache{api: managedAPI, value: &policySnapshot{
			Measurements: measurements,
			Digest:       digest,
			FetchedAt:    now,
			ExpiresAt:    now.Add(time.Minute),
		}},
		cache:    make(map[string]verifiedInstance),
		observed: make(map[string]map[string]observedAttestationInstance),
		refresh:  make(map[string]*attestationRefreshState),
	}
	verification := verifiedInstance{
		InstanceID:        testInstanceID,
		PublicKey:         publicKey,
		GPUCount:          testGPUCount,
		MeasurementDigest: digest,
		VerifiedAt:        now.Add(-time.Minute),
		ValidUntil:        now.Add(time.Minute),
	}
	attestor.storeCachedInstances(testModelTarget, map[string]verifiedInstance{testInstanceID: verification})
	pool := newPoolState(byokAPI, attestor, &diagnostics{})
	defer pool.close()
	discovered, _, err := pool.discover(testModelTarget)
	if err != nil {
		t.Fatalf("discover with BYOK key: %v", err)
	}

	cached, err := attestor.verify(context.Background(), testModelTarget, discovered, false)
	if err != nil || !cached.Complete {
		t.Fatalf("use fresh cached attestation: result=%#v err=%v", cached, err)
	}
	if evidenceAuthorization != "" {
		t.Fatal("fresh cache caused an evidence request")
	}
	refreshed, err := attestor.verify(context.Background(), testModelTarget, discovered, true)
	if err == nil || refreshed == nil || refreshed.Complete {
		t.Fatalf("failed forced refresh was accepted: result=%#v err=%v", refreshed, err)
	}
	if discoveryAuthorization != "Bearer customer-key" {
		t.Fatalf("discovery authorization = %q", discoveryAuthorization)
	}
	if evidenceAuthorization != "Bearer managed-key" {
		t.Fatalf("evidence authorization = %q", evidenceAuthorization)
	}
	retained, ok := attestor.cachedInstance(testModelTarget, discovered[0], time.Now())
	if !ok || !retained.ValidUntil.Equal(verification.ValidUntil) {
		t.Fatal("failed evidence refresh extended or removed the valid fallback")
	}
	attestor.refreshMu.Lock()
	nextAttempt := attestor.refresh[testChuteID].NextAttempt
	attestor.refreshMu.Unlock()
	if until := time.Until(nextAttempt); until < 0 || until > attestationRetryMaximum+time.Second {
		t.Fatalf("failed refresh retry = %s, want at most %s", until, attestationRetryMaximum)
	}
}

func TestGPUHardwarePolicyMappings(t *testing.T) {
	tests := []struct {
		model        string
		family       string
		architecture string
	}{
		{model: "NVIDIA H200 NVL", family: "h200", architecture: "HOPPER"},
		{model: "NVIDIA B200", family: "b200", architecture: "BLACKWELL"},
		{model: "NVIDIA B300", family: "b300", architecture: "BLACKWELL"},
		{model: "GB110", family: "b300", architecture: "BLACKWELL"},
		{model: "NVIDIA RTX PRO 6000 Blackwell Server Edition", family: "pro_6000", architecture: "BLACKWELL"},
	}
	for _, test := range tests {
		family, ok := gpuFamilyForHardwareModel(test.model)
		if !ok || family != test.family {
			t.Fatalf("model %q mapped to %q, %t", test.model, family, ok)
		}
		if !gpuFamilyMatchesArchitecture(family, test.architecture) {
			t.Fatalf("family %q did not match %q", family, test.architecture)
		}
	}
	if _, ok := gpuFamilyForHardwareModel("NVIDIA future GPU"); ok {
		t.Fatal("unknown GPU model must fail closed")
	}
	if gpuFamilyMatchesArchitecture("h200", "BLACKWELL") {
		t.Fatal("H200 must not match the Blackwell architecture")
	}
	if architecture, ok := gpuArchitectureForHardwareModel("GB20X"); !ok || architecture != "BLACKWELL" {
		t.Fatalf("GB20X architecture = %q, %t", architecture, ok)
	}
	if !gpuPolicyAllowsArchitecture(map[string]struct{}{"pro_6000": {}}, "BLACKWELL") {
		t.Fatal("Blackwell policy did not accept its signed hardware architecture")
	}
}

func TestNVIDIARemoteAttestationClaims(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	nonce := hex.EncodeToString(bytes.Repeat([]byte{0x5a}, sha256.Size))
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	detachedClaims := validDetachedClaimsForTest(now, nonce)
	detached := signNRASClaimsForTest(t, privateKey, detachedClaims)
	detachedDigest := sha256.Sum256([]byte(detached))
	overallClaims := jwt.MapClaims{
		"iss":                         nrasIssuer,
		"sub":                         "NVIDIA-PLATFORM-ATTESTATION",
		"iat":                         now.Add(-10 * time.Second).Unix(),
		"nbf":                         now.Add(-10 * time.Second).Unix(),
		"exp":                         now.Add(10 * time.Minute).Unix(),
		"eat_nonce":                   nonce,
		"x-nvidia-ver":                "2.0",
		"x-nvidia-overall-att-result": true,
		"submods": map[string]any{
			"GPU-0": []any{"DIGEST", []any{"SHA-256", hex.EncodeToString(detachedDigest[:])}},
		},
	}
	overall := signNRASClaimsForTest(t, privateKey, overallClaims)
	envelope, err := json.Marshal([]any{
		[]string{"JWT", overall},
		map[string]string{"GPU-0": detached},
	})
	if err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("NRAS method = %s", request.Method)
		}
		var payload struct {
			Nonce         string              `json:"nonce"`
			Architecture  string              `json:"arch"`
			ClaimsVersion string              `json:"claims_version"`
			Evidence      []map[string]string `json:"evidence_list"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode NRAS request: %v", err)
		}
		if payload.Nonce != nonce || payload.Architecture != "HOPPER" || payload.ClaimsVersion != "2.0" || len(payload.Evidence) != 1 {
			t.Errorf("unexpected NRAS request: %#v", payload)
		}
		if requests.Add(1) == 1 {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(envelope)
	}))
	defer server.Close()

	verifier := newNRASVerifier()
	defer verifier.close()
	verifier.endpoint = server.URL
	verifier.keys["test-key"] = &privateKey.PublicKey
	verifier.keysUntil = now.Add(time.Hour)
	err = verifier.verify(
		context.Background(),
		[]map[string]any{{"arch": "HOPPER", "evidence": "gpu-evidence", "certificate": "gpu-certificate"}},
		nonce,
		1,
		[]string{"h200"},
		now,
	)
	if err != nil {
		t.Fatalf("verify NVIDIA claims: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("NRAS requests = %d, want 2", requests.Load())
	}
}

func TestNVIDIAClaimHelpersFailClosed(t *testing.T) {
	if !emptyAttestationWarning(nil) || !emptyAttestationWarning("") || !emptyAttestationWarning([]any{}) {
		t.Fatal("empty warning forms must be accepted")
	}
	if emptyAttestationWarning("warning") || emptyAttestationWarning([]any{"warning"}) || emptyAttestationWarning(map[string]any{}) {
		t.Fatal("non-empty or unknown warning forms must be rejected")
	}
	if err := validateGPULabels(map[string]any{"GPU-0": nil, "GPU-2": nil}, 2); err == nil {
		t.Fatal("expected non-contiguous GPU labels to be rejected")
	}
	if validSubmoduleDigest([]any{"DIGEST", []any{"SHA-256", "00"}}, "token") {
		t.Fatal("expected malformed submodule digest to be rejected")
	}

	now := time.Unix(1_800_000_000, 0)
	claims := jwt.MapClaims{
		"iat": now.Add(-10 * time.Minute).Unix(),
		"nbf": now.Add(-10 * time.Minute).Unix(),
		"exp": now.Add(time.Minute).Unix(),
	}
	if _, err := validateTokenTimes(claims, now); err == nil {
		t.Fatal("expected stale NVIDIA token to be rejected")
	}
}

func validMeasurementForTest() measurementPolicy {
	return measurementPolicy{
		Version: "1.3.1",
		Name:    "8xh200",
		MRTD:    hex.EncodeToString(bytes.Repeat([]byte{0x11}, 48)),
		BootRTMRs: map[string]string{
			"RTMR0": hex.EncodeToString(bytes.Repeat([]byte{0x20}, 48)),
			"RTMR1": hex.EncodeToString(bytes.Repeat([]byte{0x21}, 48)),
			"RTMR2": hex.EncodeToString(bytes.Repeat([]byte{0x22}, 48)),
			"RTMR3": hex.EncodeToString(bytes.Repeat([]byte{0x00}, 48)),
		},
		RuntimeRTMRs: map[string]string{
			"RTMR0": hex.EncodeToString(bytes.Repeat([]byte{0x20}, 48)),
			"RTMR1": hex.EncodeToString(bytes.Repeat([]byte{0x21}, 48)),
			"RTMR2": hex.EncodeToString(bytes.Repeat([]byte{0x22}, 48)),
			"RTMR3": hex.EncodeToString(bytes.Repeat([]byte{0x23}, 48)),
		},
		ExpectedGPUs: []string{"H200"},
		GPUCount:     8,
	}
}

func quoteForMeasurementForTest(measurement measurementPolicy) *tdxpb.QuoteV4 {
	mrtd, _ := decodeMeasurementHex(measurement.MRTD)
	rtmrs := make([][]byte, 4)
	for index := range rtmrs {
		rtmrs[index], _ = decodeMeasurementHex(measurement.RuntimeRTMRs["RTMR"+string(rune('0'+index))])
	}
	return &tdxpb.QuoteV4{TdQuoteBody: &tdxpb.TDQuoteBody{MrTd: mrtd, Rtmrs: rtmrs}}
}

func validDetachedClaimsForTest(now time.Time, nonce string) jwt.MapClaims {
	claims := jwt.MapClaims{
		"iss":                          nrasIssuer,
		"sub":                          "NVIDIA-GPU-ATTESTATION",
		"iat":                          now.Add(-10 * time.Second).Unix(),
		"nbf":                          now.Add(-10 * time.Second).Unix(),
		"exp":                          now.Add(10 * time.Minute).Unix(),
		"eat_nonce":                    nonce,
		"dbgstat":                      "disabled",
		"measres":                      "success",
		"secboot":                      true,
		"hwmodel":                      "NVIDIA H200 NVL",
		"ueid":                         "gpu-identity-1",
		"x-nvidia-gpu-driver-version":  "driver",
		"x-nvidia-gpu-vbios-version":   "vbios",
		"x-nvidia-attestation-warning": []any{},
	}
	for _, name := range requiredGPUBooleanClaims {
		claims[name] = true
	}
	return claims
}

func signNRASClaimsForTest(t *testing.T, key *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
