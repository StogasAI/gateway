package redaction

import (
	"bytes"
	"net/netip"
)

const maxIPAddressBytes = 128

func scanIPAddresses(text []byte, matches []match) ([]match, error) {
	var err error
	matches, err = scanIPv4Addresses(text, matches)
	if err != nil {
		return nil, err
	}
	return scanIPv6Addresses(text, matches)
}

func scanIPv4Addresses(text []byte, matches []match) ([]match, error) {
	for start := 0; start < len(text); start++ {
		if !isASCIIDigit(text[start]) || !ipv4BoundaryBefore(text, start) {
			continue
		}
		end := start
		for end < len(text) && end-start < maxIPAddressBytes {
			if isASCIIDigit(text[end]) {
				end++
				continue
			}
			if text[end] == '.' {
				end++
				continue
			}
			break
		}
		if end < len(text) && (isASCIIDigit(text[end]) || text[end] == '.') {
			continue
		}
		scannedEnd := end
		for end > start && text[end-1] == '.' {
			end--
		}
		if end-start > 15 || ipv4DotCount(text[start:end]) != 3 || !ipv4BoundaryAfter(text, end, scannedEnd) {
			continue
		}
		address, parseErr := netip.ParseAddr(string(text[start:end]))
		if parseErr != nil || !address.Is4() || address.Zone() != "" {
			continue
		}
		matches, parseErr = appendMatch(matches, start, end, EntityIPAddress, 84)
		if parseErr != nil {
			return nil, parseErr
		}
		start = end - 1
	}
	return matches, nil
}

func scanIPv6Addresses(text []byte, matches []match) ([]match, error) {
	for position := 0; position < len(text); {
		if !ipv6CoreByte(text[position]) {
			position++
			continue
		}
		tokenStart := position
		tokenEnd := position
		for tokenEnd < len(text) && tokenEnd-tokenStart < maxIPAddressBytes && ipv6CoreByte(text[tokenEnd]) {
			tokenEnd++
		}
		if tokenEnd < len(text) && ipv6CoreByte(text[tokenEnd]) {
			position = tokenEnd
			continue
		}

		start := tokenStart
		end := tokenEnd
		for start < end && text[start] == '.' {
			start++
		}
		for end > start && text[end-1] == '.' {
			end--
		}
		if end < len(text) && text[end] == '%' {
			zoneEnd := end + 1
			for zoneEnd < len(text) && zoneEnd-start < maxIPAddressBytes && ipv6ZoneByte(text[zoneEnd]) {
				zoneEnd++
			}
			trimmedZoneEnd := zoneEnd
			for trimmedZoneEnd > end+1 && text[trimmedZoneEnd-1] == '.' {
				trimmedZoneEnd--
			}
			if trimmedZoneEnd > end+1 {
				end = trimmedZoneEnd
				tokenEnd = zoneEnd
			}
		}
		position = tokenEnd
		if start >= end || bytes.IndexByte(text[start:end], ':') < 0 || !ipv6BoundaryBefore(text, start) || !ipv6BoundaryAfter(text, end) {
			continue
		}
		address, parseErr := netip.ParseAddr(string(text[start:end]))
		if parseErr != nil || !address.Is6() {
			continue
		}
		matches, parseErr = appendMatch(matches, start, end, EntityIPAddress, 84)
		if parseErr != nil {
			return nil, parseErr
		}
	}
	return matches, nil
}

func ipv6CoreByte(value byte) bool {
	return isASCIIDigit(value) || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F' || value == ':' || value == '.'
}

func ipv6ZoneByte(value byte) bool {
	return isASCIIAlphanumeric(value) || value == '_' || value == '-' || value == '.'
}

func ipv4BoundaryBefore(text []byte, start int) bool {
	if start == 0 {
		return true
	}
	previous := text[start-1]
	if previous == ':' {
		for position := start - 2; position >= 0 && start-position <= maxIPAddressBytes && ipv6CoreByte(text[position]); position-- {
			if text[position] == ':' {
				return false
			}
		}
	}
	return !ipIdentifierByte(previous) && previous != '.' && previous != '%'
}

func ipv4BoundaryAfter(text []byte, end, scannedEnd int) bool {
	if scannedEnd > end {
		return scannedEnd == len(text) || !ipIdentifierByte(text[scannedEnd])
	}
	if end == len(text) {
		return true
	}
	next := text[end]
	return !ipIdentifierByte(next) && next != '.' && next != '%'
}

func ipv4DotCount(value []byte) int {
	count := 0
	for _, character := range value {
		if character == '.' {
			count++
		}
	}
	return count
}

func ipv6BoundaryBefore(text []byte, start int) bool {
	if start == 0 {
		return true
	}
	previous := text[start-1]
	return !ipIdentifierByte(previous) && previous != ':' && previous != '%'
}

func ipv6BoundaryAfter(text []byte, end int) bool {
	if end == len(text) {
		return true
	}
	next := text[end]
	return !ipIdentifierByte(next) && next != ':' && next != '%'
}

func ipIdentifierByte(value byte) bool {
	return isIdentifierByte(value) || value >= 0x80
}
