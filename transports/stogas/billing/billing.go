package billing

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

const ZeroChargeUSDAtoms = "0"

func CreateHoldParamsHash(providerKey string, productKey string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(providerKey))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(productKey))
	return hex.EncodeToString(hasher.Sum(nil))
}

func SettlementStatus(authorizedAmount *big.Int, availableAfter *big.Int, actualCost string) string {
	authorized := cloneOrZero(authorizedAmount)
	available := cloneOrZero(availableAfter)
	actual := parseMoneyOrZero(actualCost)
	refund := new(big.Int).Sub(authorized, actual)
	switch {
	case refund.Sign() == 0:
		return "complete"
	case refund.Sign() > 0:
		return "over_reserved"
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

func parseMoneyOrZero(value string) *big.Int {
	if value == "" {
		return big.NewInt(0)
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return big.NewInt(0)
	}
	return parsed
}
