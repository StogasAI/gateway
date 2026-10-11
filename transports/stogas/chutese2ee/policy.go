package chutese2ee

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"golang.org/x/sync/singleflight"
)

const measurementPolicyTTL = 5 * time.Minute

var acceptedGPUFamilies = map[string]struct{}{
	"b200":     {},
	"b300":     {},
	"h200":     {},
	"pro_6000": {},
}

type policySnapshot struct {
	Measurements []measurementPolicy
	Digest       string
	FetchedAt    time.Time
	ExpiresAt    time.Time
}

type policyCache struct {
	api    *apiClient
	mu     sync.RWMutex
	value  *policySnapshot
	flight singleflight.Group
}

func (c *policyCache) current(ctx context.Context) (*policySnapshot, error) {
	now := time.Now()
	c.mu.RLock()
	value := c.value
	c.mu.RUnlock()
	if value != nil && now.Before(value.ExpiresAt) {
		return value, nil
	}
	result, err, _ := c.flight.Do("measurements", func() (any, error) {
		now := time.Now()
		c.mu.RLock()
		cached := c.value
		c.mu.RUnlock()
		if cached != nil && now.Before(cached.ExpiresAt) {
			return cached, nil
		}
		var records []measurementPolicy
		fetchErr := retryChutesRead(ctx, false, 5*time.Second, func() error {
			records = nil
			_, _, requestErr := c.api.requestJSON(
				ctx,
				http.MethodGet,
				measurementsPath,
				nil,
				maxMeasurementBody,
				&records,
			)
			return requestErr
		})
		if fetchErr != nil {
			return nil, fmt.Errorf("fetch measurement policy: %w", fetchErr)
		}
		measurements, digest, err := validateAndDigestMeasurements(records)
		if err != nil {
			return nil, err
		}
		snapshot := &policySnapshot{
			Measurements: measurements,
			Digest:       digest,
			FetchedAt:    now,
			ExpiresAt:    now.Add(measurementPolicyTTL),
		}
		c.mu.Lock()
		c.value = snapshot
		c.mu.Unlock()
		return snapshot, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(*policySnapshot), nil
}

// validateAndDigestMeasurements returns the distinct supported measurements in
// a stable order and their digest. Chutes repeats a measurement for each host
// class it covers and names the class in an extra `fingerprint` field. A quote
// cannot prove its host class, so records that agree on every verified field are
// one measurement. A malformed record rejects the whole list.
func validateAndDigestMeasurements(records []measurementPolicy) ([]measurementPolicy, string, error) {
	if len(records) == 0 || len(records) > 256 {
		return nil, "", fmt.Errorf("%w: invalid record count", ErrMeasurementPolicy)
	}
	unique := make(map[string]measurementPolicy, len(records))
	for _, measurement := range records {
		measurement.Version = strings.TrimSpace(measurement.Version)
		measurement.Name = strings.TrimSpace(measurement.Name)
		if measurement.Version == "" || measurement.Name == "" || measurement.GPUCount < 1 || measurement.GPUCount > 16 {
			return nil, "", fmt.Errorf("%w: invalid measurement metadata", ErrMeasurementPolicy)
		}
		if _, err := decodeMeasurementHex(measurement.MRTD); err != nil {
			return nil, "", fmt.Errorf("%w: invalid MRTD", ErrMeasurementPolicy)
		}
		if err := validateRTMRSet(measurement.BootRTMRs); err != nil {
			return nil, "", fmt.Errorf("%w: invalid boot RTMRs", ErrMeasurementPolicy)
		}
		if err := validateRTMRSet(measurement.RuntimeRTMRs); err != nil {
			return nil, "", fmt.Errorf("%w: invalid runtime RTMRs", ErrMeasurementPolicy)
		}
		if len(measurement.ExpectedGPUs) == 0 || len(measurement.ExpectedGPUs) > 4 {
			return nil, "", fmt.Errorf("%w: invalid GPU families", ErrMeasurementPolicy)
		}
		gpuSeen := map[string]struct{}{}
		supported := true
		for gpuIndex, family := range measurement.ExpectedGPUs {
			family = strings.ToLower(strings.TrimSpace(family))
			if _, duplicate := gpuSeen[family]; duplicate {
				return nil, "", fmt.Errorf("%w: duplicate GPU family", ErrMeasurementPolicy)
			}
			gpuSeen[family] = struct{}{}
			_, accepted := acceptedGPUFamilies[family]
			supported = supported && accepted
			measurement.ExpectedGPUs[gpuIndex] = family
		}
		if !supported {
			// NRAS verification rejects these GPUs, so no instance can match the record.
			continue
		}
		slices.Sort(measurement.ExpectedGPUs)
		identity, err := json.Marshal(measurement)
		if err != nil {
			return nil, "", fmt.Errorf("%w: encode measurement", ErrMeasurementPolicy)
		}
		unique[string(identity)] = measurement
	}
	if len(unique) == 0 {
		return nil, "", fmt.Errorf("%w: no supported measurement", ErrMeasurementPolicy)
	}
	identities := slices.Sorted(maps.Keys(unique))
	measurements := make([]measurementPolicy, 0, len(identities))
	for _, identity := range identities {
		measurements = append(measurements, unique[identity])
	}
	encoded, err := json.Marshal(measurements)
	if err != nil {
		return nil, "", fmt.Errorf("%w: encode policy", ErrMeasurementPolicy)
	}
	digest := sha256.Sum256(encoded)
	return measurements, hex.EncodeToString(digest[:]), nil
}

func validateRTMRSet(values map[string]string) error {
	if len(values) != 4 {
		return errors.New("RTMR set must contain four values")
	}
	for index := 0; index < 4; index++ {
		value, ok := values[fmt.Sprintf("RTMR%d", index)]
		if !ok {
			return errors.New("RTMR key is missing")
		}
		if _, err := decodeMeasurementHex(value); err != nil {
			return err
		}
	}
	return nil
}

func decodeMeasurementHex(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if len(value) != 96 {
		return nil, errors.New("measurement must contain 48 bytes")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 48 {
		return nil, errors.New("measurement is not canonical hexadecimal")
	}
	return decoded, nil
}

func matchMeasurement(quote *tdxpb.QuoteV4, snapshot *policySnapshot) (*measurementPolicy, error) {
	if quote == nil || quote.GetTdQuoteBody() == nil || snapshot == nil {
		return nil, ErrMeasurementPolicy
	}
	body := quote.GetTdQuoteBody()
	matches := make([]measurementPolicy, 0, 1)
	for _, measurement := range snapshot.Measurements {
		mrtd, _ := decodeMeasurementHex(measurement.MRTD)
		if !slices.Equal(body.GetMrTd(), mrtd) || len(body.GetRtmrs()) != 4 {
			continue
		}
		matched := true
		for index := 0; index < 4; index++ {
			expected, _ := decodeMeasurementHex(measurement.RuntimeRTMRs[fmt.Sprintf("RTMR%d", index)])
			if !slices.Equal(body.GetRtmrs()[index], expected) {
				matched = false
				break
			}
		}
		if matched {
			matches = append(matches, measurement)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: quote measurements are not accepted", ErrAttestationFailed)
	}
	selected := matches[0]
	for _, candidate := range matches[1:] {
		if candidate.GPUCount != selected.GPUCount || !slices.Equal(candidate.ExpectedGPUs, selected.ExpectedGPUs) {
			return nil, fmt.Errorf("%w: ambiguous measurement policy", ErrMeasurementPolicy)
		}
	}
	return &selected, nil
}
