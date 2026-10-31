package redaction

import (
	"bytes"
	"net/netip"
	"slices"
)

const maxIPAddressBytes = 128

func scanIPAddresses(text []byte, matches []match) ([]match, error) {
	first := len(matches)
	matches, err := scanIPv4Addresses(text, matches)
	if err != nil {
		return nil, err
	}
	return scanIPv6Addresses(text, matches, slices.Clone(matches[first:]))
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

// scanIPv6Addresses matches IPv6 addresses in each maximal run of IPv6
// characters. ipv4 holds the IPv4 matches in order.
//
// A later pass over the redacted text must find nothing more, so no candidate
// is rejected for a byte that a match replaces. Placeholders split a run that
// is not one address at its IPv4 matches; a zone, which a colon may end, and
// the run after it are matched independently.
func scanIPv6Addresses(text []byte, matches []match, ipv4 []match) ([]match, error) {
	scanner := ipv6Scanner{text: text, matches: matches, matchEnd: -1}
	next := 0
	for position := 0; position < len(text); {
		if !ipv6CoreByte(text[position]) {
			position++
			continue
		}
		runEnd := position
		for runEnd < len(text) && ipv6CoreByte(text[runEnd]) {
			runEnd++
		}
		// A zone can take an IPv4 address after a hyphen; that run is done.
		for next < len(ipv4) && ipv4[next].end <= position {
			next++
		}
		first := next
		for next < len(ipv4) && ipv4[next].start < runEnd {
			next++
		}
		var err error
		position, err = scanner.run(position, runEnd, ipv4[first:next])
		if err != nil {
			return nil, err
		}
	}
	return scanner.matches, nil
}

type ipv6Scanner struct {
	text    []byte
	matches []match
	// matchEnd is where the last IPv6 match ended. A run that starts there
	// borders its placeholder rather than its zone.
	matchEnd int
}

// run scans text[runStart:runEnd] and returns where scanning resumes. A run
// that holds IPv4 matches but is not one address, as ::ffff:192.0.2.128 is,
// is scanned as the parts between them.
func (s *ipv6Scanner) run(runStart, runEnd int, ipv4 []match) (int, error) {
	if len(ipv4) > 0 && runEnd-runStart <= maxIPAddressBytes {
		if start, end, resume, ok := s.candidate(runStart, runEnd, runStart == s.matchEnd, false); ok {
			return resume, s.add(start, end)
		}
	}
	partStart, afterIPv4 := runStart, false
	for _, address := range ipv4 {
		if _, err := s.part(partStart, address.start, afterIPv4, true); err != nil {
			return 0, err
		}
		partStart, afterIPv4 = address.end, true
	}
	return s.part(partStart, runEnd, afterIPv4, false)
}

// part scans text[partStart:partEnd], whose edges may border redacted IPv4
// addresses. A part longer than an address is scanned in windows; only the
// window that ends it can match.
func (s *ipv6Scanner) part(partStart, partEnd int, afterIPv4, beforeIPv4 bool) (int, error) {
	position := partStart
	for position < partEnd {
		tokenEnd := min(partEnd, position+maxIPAddressBytes)
		if tokenEnd < partEnd {
			position = tokenEnd
			continue
		}
		openBefore := position == s.matchEnd || afterIPv4 && position == partStart
		start, end, resume, ok := s.candidate(position, tokenEnd, openBefore, beforeIPv4)
		position = resume
		if ok {
			if err := s.add(start, end); err != nil {
				return 0, err
			}
		}
	}
	return max(position, partEnd), nil
}

func (s *ipv6Scanner) add(start, end int) error {
	var err error
	s.matches, err = appendMatch(s.matches, start, end, EntityIPAddress, 84)
	s.matchEnd = end
	return err
}

// candidate reports the address in text[tokenStart:tokenEnd], with any zone
// after it, and where scanning resumes. An open edge borders a placeholder.
func (s *ipv6Scanner) candidate(tokenStart, tokenEnd int, openBefore, openAfter bool) (int, int, int, bool) {
	text := s.text
	start := tokenStart
	end := tokenEnd
	for start < end && text[start] == '.' {
		start++
	}
	for end > start && text[end-1] == '.' {
		end--
	}
	// Without a colon the token is no address, and it must not take a zone: the
	// dots left after a placeholder would take one that they do not take here.
	if bytes.IndexByte(text[start:end], ':') < 0 {
		return 0, 0, tokenEnd, false
	}
	zoned := false
	if !openAfter && end < len(text) && text[end] == '%' {
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
			zoned = true
		}
	}
	if !(openBefore && start == tokenStart || ipv6BoundaryBefore(text, start)) ||
		!(openAfter && end == tokenEnd || ipv6BoundaryAfter(text, end, zoned)) {
		return 0, 0, tokenEnd, false
	}
	address, err := netip.ParseAddr(string(text[start:end]))
	if err != nil || !address.Is6() {
		return 0, 0, tokenEnd, false
	}
	return start, end, tokenEnd, true
}

func ipv6CoreByte(value byte) bool {
	return isASCIIDigit(value) || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F' || value == ':' || value == '.'
}

func ipv6ZoneByte(value byte) bool {
	return isASCIIAlphanumeric(value) || value == '_' || value == '-' || value == '.'
}

// An IPv4 address after a colon stays a candidate even inside an IPv6-like run:
// normalizeMatches unions it with a valid IPv6 match that ends in it, and an
// invalid run must not hide it, since redacting the run's other addresses
// would then expose it on the next pass.
func ipv4BoundaryBefore(text []byte, start int) bool {
	if start == 0 {
		return true
	}
	previous := text[start-1]
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

// A colon after a zone starts the next run, which a match may replace.
func ipv6BoundaryAfter(text []byte, end int, zoned bool) bool {
	if end == len(text) {
		return true
	}
	next := text[end]
	return !ipIdentifierByte(next) && (zoned || next != ':') && next != '%'
}

func ipIdentifierByte(value byte) bool {
	return isIdentifierByte(value) || value >= 0x80
}
