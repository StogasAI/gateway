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
		measurements, digest, err := supportedMeasurements(records)
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

// supportedMeasurements returns the records a quote can match, in a stable order,
// and their digest. The list is an allowlist, so dropping a record can only
// narrow it: a malformed record, or one for GPUs that NRAS verification rejects,
// is skipped instead of disabling every chute. The provider drift check reports
// skipped records.
func supportedMeasurements(records []measurementPolicy) ([]measurementPolicy, string, error) {
	unique := make(map[string]measurementPolicy, len(records))
	for _, record := range records {
		measurement, ok := normalizeMeasurement(record)
		if !ok {
			continue
		}
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

func normalizeMeasurement(measurement measurementPolicy) (measurementPolicy, bool) {
	measurement.Version = strings.TrimSpace(measurement.Version)
	measurement.Name = strings.TrimSpace(measurement.Name)
	if measurement.Version == "" || measurement.Name == "" || measurement.GPUCount < 1 || measurement.GPUCount > 16 ||
		len(measurement.ExpectedGPUs) == 0 || len(measurement.ExpectedGPUs) > 4 {
		return measurement, false
	}
	registers := []*string{&measurement.MRTD, &measurement.RTMR0, &measurement.RTMR1, &measurement.RTMR2, &measurement.RTMR3}
	for _, register := range registers {
		decoded, err := decodeMeasurementHex(*register)
		if err != nil {
			return measurement, false
		}
		*register = hex.EncodeToString(decoded)
	}
	families := make([]string, 0, len(measurement.ExpectedGPUs))
	for _, family := range measurement.ExpectedGPUs {
		family = strings.ToLower(strings.TrimSpace(family))
		if _, accepted := acceptedGPUFamilies[family]; !accepted || slices.Contains(families, family) {
			return measurement, false
		}
		families = append(families, family)
	}
	slices.Sort(families)
	measurement.ExpectedGPUs = families
	return measurement, true
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
	if len(body.GetRtmrs()) != 4 {
		return nil, fmt.Errorf("%w: quote has no RTMR set", ErrAttestationFailed)
	}
	matches := make([]measurementPolicy, 0, 1)
	for _, measurement := range snapshot.Measurements {
		matched := true
		for index, register := range [][]byte{body.GetMrTd(), body.GetRtmrs()[0], body.GetRtmrs()[1], body.GetRtmrs()[2], body.GetRtmrs()[3]} {
			expected, _ := decodeMeasurementHex(measurement.registers()[index])
			if !slices.Equal(register, expected) {
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
