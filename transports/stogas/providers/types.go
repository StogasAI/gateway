package providers

import (
	"errors"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

const (
	MeterInputTokens             = billing.MeterInputTokens
	MeterCachedInputTokens       = billing.MeterCachedInputTokens
	MeterCacheWrite5mInputTokens = billing.MeterCacheWrite5mInputTokens
	MeterCacheWrite1hInputTokens = billing.MeterCacheWrite1hInputTokens
	MeterOutputTokens            = billing.MeterOutputTokens

	RatePerMillionTokens         = billing.RatePerMillionTokens
	RatePerMillionContextLTE272K = billing.RatePerMillionContextLTE272K
	RatePerMillionContextGT272K  = billing.RatePerMillionContextGT272K
	RatePerThousandCalls         = billing.RatePerThousandCalls

	LongContextThresholdTokens = billing.LongContextThresholdTokens
	MillionTokens              = billing.MillionTokens
	ThousandCalls              = billing.ThousandCalls
)

var (
	ErrUnsupportedTool         = errors.New("unsupported provider tool")
	ErrUnsupportedParameter    = errors.New("unsupported provider parameter")
	ErrUnsupportedInput        = errors.New("unsupported provider input")
	ErrOutputTokenLimitTooLow  = errors.New("output token limit is below provider minimum")
	ErrProviderContainers      = errors.New("provider containers are not supported")
	ErrInvalidProviderToolSpec = errors.New("invalid provider tool specification")
)

type Pricing = billing.Pricing

type MeterEstimate = billing.MeterEstimate
