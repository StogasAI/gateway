package chutese2ee

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
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
		var measurements []measurementPolicy
		var fetchErr error
		for attempt := 0; attempt < maximumSafeReadAttempts; attempt++ {
			measurements = nil
			_, _, fetchErr = c.api.requestJSON(ctx, "GET", measurementsPath, nil, maxMeasurementBody, &measurements)
			if fetchErr == nil || attempt+1 >= maximumSafeReadAttempts || !retryableChutesRead(fetchErr, false) {
				break
			}
			delay, ok := chutesReadRetryDelay(fetchErr, attempt, 5*time.Second)
			if !ok || !waitForChutesRetry(ctx, delay) {
				break
			}
		}
		if fetchErr != nil {
			return nil, fmt.Errorf("fetch measurement policy: %w", fetchErr)
		}
		digest, err := validateAndDigestMeasurements(measurements)
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

func validateAndDigestMeasurements(measurements []measurementPolicy) (string, error) {
	if len(measurements) == 0 || len(measurements) > 256 {
		return "", fmt.Errorf("%w: invalid record count", ErrMeasurementPolicy)
	}
	seen := make(map[string]struct{}, len(measurements))
	for index := range measurements {
		measurement := &measurements[index]
		measurement.Version = strings.TrimSpace(measurement.Version)
		measurement.Name = strings.TrimSpace(measurement.Name)
		if measurement.Version == "" || measurement.Name == "" || measurement.GPUCount < 1 || measurement.GPUCount > 16 {
			return "", fmt.Errorf("%w: invalid measurement metadata", ErrMeasurementPolicy)
		}
		if _, err := decodeMeasurementHex(measurement.MRTD); err != nil {
			return "", fmt.Errorf("%w: invalid MRTD", ErrMeasurementPolicy)
		}
		if err := validateRTMRSet(measurement.BootRTMRs); err != nil {
			return "", fmt.Errorf("%w: invalid boot RTMRs", ErrMeasurementPolicy)
		}
		if err := validateRTMRSet(measurement.RuntimeRTMRs); err != nil {
			return "", fmt.Errorf("%w: invalid runtime RTMRs", ErrMeasurementPolicy)
		}
		if len(measurement.ExpectedGPUs) == 0 || len(measurement.ExpectedGPUs) > 4 {
			return "", fmt.Errorf("%w: invalid GPU families", ErrMeasurementPolicy)
		}
		gpuSeen := map[string]struct{}{}
		for gpuIndex, family := range measurement.ExpectedGPUs {
			family = strings.ToLower(strings.TrimSpace(family))
			if _, ok := acceptedGPUFamilies[family]; !ok {
				return "", fmt.Errorf("%w: unknown GPU family", ErrMeasurementPolicy)
			}
			if _, duplicate := gpuSeen[family]; duplicate {
				return "", fmt.Errorf("%w: duplicate GPU family", ErrMeasurementPolicy)
			}
			gpuSeen[family] = struct{}{}
			measurement.ExpectedGPUs[gpuIndex] = family
		}
		slices.Sort(measurement.ExpectedGPUs)
		identity := measurementIdentity(*measurement)
		if _, duplicate := seen[identity]; duplicate {
			return "", fmt.Errorf("%w: duplicate measurement", ErrMeasurementPolicy)
		}
		seen[identity] = struct{}{}
	}
	sort.Slice(measurements, func(left, right int) bool {
		return measurementIdentity(measurements[left]) < measurementIdentity(measurements[right])
	})
	encoded, err := json.Marshal(measurements)
	if err != nil {
		return "", fmt.Errorf("%w: encode policy", ErrMeasurementPolicy)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
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

func measurementIdentity(measurement measurementPolicy) string {
	return strings.Join([]string{
		measurement.Version,
		measurement.Name,
		strings.ToUpper(measurement.MRTD),
		strings.ToUpper(measurement.RuntimeRTMRs["RTMR0"]),
		strings.ToUpper(measurement.RuntimeRTMRs["RTMR1"]),
		strings.ToUpper(measurement.RuntimeRTMRs["RTMR2"]),
		strings.ToUpper(measurement.RuntimeRTMRs["RTMR3"]),
		fmt.Sprintf("%d", measurement.GPUCount),
		strings.Join(measurement.ExpectedGPUs, ","),
	}, "|")
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
