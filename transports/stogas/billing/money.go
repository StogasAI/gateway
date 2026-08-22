package billing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	ZeroChargeUSDAtoms    = "0"
	maximumUSDAtoms       = "1000000000000000000000000000000"
	maximumUSDAtomsDigits = len(maximumUSDAtoms)
)

func createHoldParamsHash(providerKey string, productKey string, passthroughByokID string, upstreamTargetJSON ...string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(providerKey))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(productKey))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(passthroughByokID))
	_, _ = hasher.Write([]byte{0})
	if len(upstreamTargetJSON) > 0 {
		_, _ = hasher.Write([]byte(upstreamTargetJSON[0]))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func settlementStatus(authorizedAmount *big.Int, availableAfter *big.Int, actual *big.Int) string {
	authorized := cloneOrZero(authorizedAmount)
	available := cloneOrZero(availableAfter)
	refund := new(big.Int).Sub(authorized, actual)
	switch {
	case refund.Sign() >= 0:
		return "complete"
	default:
		if new(big.Int).Add(available, refund).Sign() < 0 {
			return "negative_balance"
		}
		return "under_reserved"
	}
}

func cloneOrZero(value *big.Int) *big.Int {
	if value == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(value)
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

// ParseUSDAtoms validates the canonical amount range accepted by the database
// settlement functions.
func ParseUSDAtoms(value string) (*big.Int, error) {
	if len(value) > maximumUSDAtomsDigits ||
		(len(value) == maximumUSDAtomsDigits && value > maximumUSDAtoms) {
		return nil, fmt.Errorf("USD atom amount exceeds the settlement limit")
	}
	return ParseNonnegativeInteger(value)
}
