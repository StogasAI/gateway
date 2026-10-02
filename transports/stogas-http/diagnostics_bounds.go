package stogashttp

import (
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
)

const (
	maximumDiagnosticResponseBytes = 1 << 20
	maximumResourceDiagnosticBytes = 128 << 10
)

// Source registries already bound record counts. Bound variable strings before
// encoding a row, then use its exact encoded size to retain useful detail.
// Six bytes per input byte covers JSON escaping; fixed fields fit in 4 KiB.
func diagnosticStringsFit(values []string, remaining *int) bool {
	for _, value := range values {
		if *remaining < 3 || len(value) > (*remaining-3)/6 {
			return false
		}
		*remaining -= 3 + 6*len(value)
	}
	return true
}

func operationalDiagnosticFits(row stogas.OperationalLogSeries) bool {
	remaining := maximumResourceDiagnosticBytes - 4096
	return diagnosticStringsFit([]string{row.Event, row.ReasonCode, row.ErrorType, row.Severity, row.Source}, &remaining)
}

func chuteDiagnosticFits(row chutese2ee.ChuteDiagnostic) bool {
	remaining := maximumResourceDiagnosticBytes - 4096
	for _, values := range [][]string{
		{row.ChuteID, row.LastDiscovery.Error, row.LastEvidence.Error, row.LastColdPath.Error, row.LastInvoke.Error, row.LastProtocolFailure.Error, row.LastTicketStarvation.Error},
		row.UpstreamModels, row.MeasurementDigests, row.MeasurementVersions,
	} {
		if !diagnosticStringsFit(values, &remaining) {
			return false
		}
	}
	for key := range row.AttestationFailures {
		if remaining < 32 || !diagnosticStringsFit([]string{key}, &remaining) {
			return false
		}
		remaining -= 32
		if remaining < 0 {
			return false
		}
	}
	return true
}

func boundedDiagnosticRows[T any](rows []T, remaining *int, fits func(T) bool) ([]T, int) {
	kept := make([]T, 0, len(rows))
	omitted := 0
	for _, row := range rows {
		if !fits(row) {
			omitted++
			continue
		}
		encoded, err := marshalPayload(row)
		if err != nil || len(encoded)+1 > *remaining {
			omitted++
			continue
		}
		*remaining -= len(encoded) + 1
		kept = append(kept, row)
	}
	return kept, omitted
}

func boundPrivateDiagnostics(node privateNodeDiagnostics) privateNodeDiagnostics {
	logs, chutes := node.OperationalLogs, node.ChutesE2EE.Chutes
	node.OperationalLogs, node.ChutesE2EE.Chutes = nil, nil
	base, err := marshalPayload(node)
	// Reserve space for updated omission counts and [] replacing null. Scalar
	// capacity/failure counters are preserved even when every detail is omitted.
	remaining := maximumResourceDiagnosticBytes - len(base) - 128
	if err != nil || remaining < 0 {
		node.DetailsUnavailable = true
		node.OmittedOperationalLogs, node.OmittedChutes = len(logs), len(chutes)
		return node
	}
	node.OperationalLogs, node.OmittedOperationalLogs = boundedDiagnosticRows(logs, &remaining, operationalDiagnosticFits)
	node.ChutesE2EE.Chutes, node.OmittedChutes = boundedDiagnosticRows(chutes, &remaining, chuteDiagnosticFits)
	return node
}
