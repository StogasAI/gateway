package billing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/maximhq/bifrost/transports/stogas/money"
)

const (
	ZeroChargeUSD = "0"
	maximumUSD    = "1000000000000"
)

func createHoldParamsHash(providerKey string, productKey string, upstreamTargetJSON ...string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(providerKey))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(productKey))
	_, _ = hasher.Write([]byte{0})
	if len(upstreamTargetJSON) > 0 {
		_, _ = hasher.Write([]byte(upstreamTargetJSON[0]))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func cloneOrZero(value *money.USD) *money.USD {
	if value == nil {
		return new(money.USD)
	}
	return new(money.USD).Set(value)
}

// ParseNonnegativeInteger accepts only the canonical base-10 form used by
// billing and pricing records.
func ParseNonnegativeInteger(value string) (*big.Int, error) {
	if value == "" {
		return nil, fmt.Errorf("value is empty")
	}
	if value != "0" && value[0] == '0' {
		return nil, fmt.Errorf("value is not canonical")
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return nil, fmt.Errorf("value is not a nonnegative integer")
		}
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("value is not a nonnegative integer")
	}
	return parsed, nil
}

// ParseUSD validates the canonical amount range accepted by the database
// settlement functions.
func ParseUSD(value string) (*money.USD, error) {
	parsed, err := money.Parse(value)
	if err != nil {
		return nil, err
	}
	maximum, _ := money.Parse(maximumUSD)
	if parsed.Sign() < 0 || parsed.Cmp(maximum) > 0 || parsed.String() != value {
		return nil, fmt.Errorf("USD amount exceeds settlement contract")
	}
	return parsed, nil
}
