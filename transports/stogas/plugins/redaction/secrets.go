package redaction

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

type secretCharacterClass uint8

const (
	secretAlphanumeric secretCharacterClass = iota + 1
	secretToken
	secretBase64
	secretHex
	secretUpperAlphanumeric
	secretLetters
	secretTokenEquals
	secretAge
	secretExtendedToken
)

type secretSpec struct {
	prefix      string
	minimumBody int
	maximumBody int
	characters  secretCharacterClass
	strict      bool
}

var secretSpecsByInitial = func() [256][]secretSpec {
	var grouped [256][]secretSpec
	for _, spec := range []secretSpec{
		{prefix: "AKIA", minimumBody: 16, maximumBody: 16, characters: secretUpperAlphanumeric},
		{prefix: "ASIA", minimumBody: 16, maximumBody: 16, characters: secretUpperAlphanumeric},
		{prefix: "ABIA", minimumBody: 16, maximumBody: 16, characters: secretUpperAlphanumeric},
		{prefix: "ACCA", minimumBody: 16, maximumBody: 16, characters: secretUpperAlphanumeric},
		{prefix: "A3T", minimumBody: 17, maximumBody: 17, characters: secretUpperAlphanumeric},
		{prefix: "ABSK", minimumBody: 109, maximumBody: 271, characters: secretBase64},
		{prefix: "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t", minimumBody: 0, maximumBody: 0, characters: secretToken},
		{prefix: "ghp_", minimumBody: 36, maximumBody: 36, characters: secretAlphanumeric},
		{prefix: "gho_", minimumBody: 36, maximumBody: 36, characters: secretAlphanumeric},
		{prefix: "ghu_", minimumBody: 36, maximumBody: 36, characters: secretAlphanumeric},
		{prefix: "ghs_", minimumBody: 36, maximumBody: 36, characters: secretAlphanumeric},
		{prefix: "ghr_", minimumBody: 36, maximumBody: 36, characters: secretAlphanumeric},
		{prefix: "glpat-", minimumBody: 20, maximumBody: 20, characters: secretToken, strict: true},
		{prefix: "glagent-", minimumBody: 50, maximumBody: 50, characters: secretToken},
		{prefix: "gloas-", minimumBody: 64, maximumBody: 64, characters: secretToken},
		{prefix: "gldt-", minimumBody: 20, maximumBody: 20, characters: secretToken},
		{prefix: "glft-", minimumBody: 20, maximumBody: 20, characters: secretToken},
		{prefix: "glffct-", minimumBody: 20, maximumBody: 20, characters: secretToken},
		{prefix: "glimt-", minimumBody: 25, maximumBody: 25, characters: secretToken},
		{prefix: "glrt-", minimumBody: 20, maximumBody: 20, characters: secretToken, strict: true},
		{prefix: "glsoat-", minimumBody: 20, maximumBody: 20, characters: secretToken},
		{prefix: "glptt-", minimumBody: 40, maximumBody: 40, characters: secretHex},
		{prefix: "GR1348941", minimumBody: 20, maximumBody: 20, characters: secretToken, strict: true},
		{prefix: "AIza", minimumBody: 35, maximumBody: 35, characters: secretToken},
		{prefix: "xoxb-", minimumBody: 10, maximumBody: 72, characters: secretToken, strict: true},
		{prefix: "xoxp-", minimumBody: 10, maximumBody: 72, characters: secretToken, strict: true},
		{prefix: "xoxa-", minimumBody: 10, maximumBody: 72, characters: secretToken, strict: true},
		{prefix: "xoxr-", minimumBody: 10, maximumBody: 72, characters: secretToken, strict: true},
		{prefix: "xoxs-", minimumBody: 10, maximumBody: 72, characters: secretToken, strict: true},
		{prefix: "xoxc-", minimumBody: 10, maximumBody: 72, characters: secretToken, strict: true},
		{prefix: "xoxe-", minimumBody: 10, maximumBody: 72, characters: secretToken, strict: true},
		{prefix: "sk-ant-", minimumBody: 24, maximumBody: 255, characters: secretToken},
		{prefix: "sk-proj-", minimumBody: 40, maximumBody: 255, characters: secretToken},
		{prefix: "sk-svcacct-", minimumBody: 40, maximumBody: 255, characters: secretToken, strict: true},
		{prefix: "sk-admin-", minimumBody: 40, maximumBody: 255, characters: secretToken, strict: true},
		{prefix: "sk-", minimumBody: 32, maximumBody: 255, characters: secretAlphanumeric, strict: true},
		{prefix: "sk_live_", minimumBody: 24, maximumBody: 99, characters: secretAlphanumeric},
		{prefix: "sk_test_", minimumBody: 24, maximumBody: 99, characters: secretAlphanumeric},
		{prefix: "rk_live_", minimumBody: 24, maximumBody: 99, characters: secretAlphanumeric},
		{prefix: "rk_test_", minimumBody: 24, maximumBody: 99, characters: secretAlphanumeric},
		{prefix: "sk_prod_", minimumBody: 16, maximumBody: 99, characters: secretAlphanumeric, strict: true},
		{prefix: "rk_prod_", minimumBody: 16, maximumBody: 99, characters: secretAlphanumeric, strict: true},
		{prefix: "hf_", minimumBody: 34, maximumBody: 34, characters: secretLetters},
		{prefix: "api_org_", minimumBody: 34, maximumBody: 34, characters: secretLetters},
		{prefix: "gsk_", minimumBody: 40, maximumBody: 64, characters: secretAlphanumeric, strict: true},
		{prefix: "npm_", minimumBody: 36, maximumBody: 36, characters: secretAlphanumeric},
		{prefix: "ya29.", minimumBody: 20, maximumBody: 255, characters: secretToken, strict: true},
		{prefix: "pypi-AgEIcHlwaS5vcmc", minimumBody: 50, maximumBody: 1000, characters: secretToken},
		{prefix: "dp.pt.", minimumBody: 43, maximumBody: 43, characters: secretAlphanumeric, strict: true},
		{prefix: "ops_eyJ", minimumBody: 250, maximumBody: 4096, characters: secretBase64, strict: true},
		{prefix: "pscale_tkn_", minimumBody: 32, maximumBody: 64, characters: secretExtendedToken, strict: true},
		{prefix: "pscale_oauth_", minimumBody: 32, maximumBody: 64, characters: secretExtendedToken, strict: true},
		{prefix: "pscale_pw_", minimumBody: 32, maximumBody: 64, characters: secretExtendedToken, strict: true},
		{prefix: "pul-", minimumBody: 40, maximumBody: 40, characters: secretHex, strict: true},
		{prefix: "sntryu_", minimumBody: 64, maximumBody: 64, characters: secretHex, strict: true},
		{prefix: "hvs.", minimumBody: 24, maximumBody: 255, characters: secretToken},
		{prefix: "hvb.", minimumBody: 24, maximumBody: 255, characters: secretToken},
		{prefix: "hvr.", minimumBody: 24, maximumBody: 255, characters: secretToken},
		{prefix: "dapi", minimumBody: 32, maximumBody: 32, characters: secretHex},
		{prefix: "dop_v1_", minimumBody: 64, maximumBody: 64, characters: secretHex},
		{prefix: "doo_v1_", minimumBody: 64, maximumBody: 64, characters: secretHex},
		{prefix: "dor_v1_", minimumBody: 64, maximumBody: 64, characters: secretHex},
		{prefix: "pplx-", minimumBody: 48, maximumBody: 48, characters: secretAlphanumeric},
		{prefix: "SK", minimumBody: 32, maximumBody: 32, characters: secretHex},
		{prefix: "shpat_", minimumBody: 32, maximumBody: 32, characters: secretHex},
		{prefix: "shpca_", minimumBody: 32, maximumBody: 32, characters: secretHex},
		{prefix: "shppa_", minimumBody: 32, maximumBody: 32, characters: secretHex},
		{prefix: "shpss_", minimumBody: 32, maximumBody: 32, characters: secretHex},
		{prefix: "lin_api_", minimumBody: 40, maximumBody: 40, characters: secretAlphanumeric},
		{prefix: "ATATT3", minimumBody: 186, maximumBody: 186, characters: secretTokenEquals},
		{prefix: "AGE-SECRET-KEY-1", minimumBody: 58, maximumBody: 58, characters: secretAge},
	} {
		grouped[spec.prefix[0]] = append(grouped[spec.prefix[0]], spec)
	}
	return grouped
}()

func scanSecrets(text []byte, matches []match, enabled entityMask) ([]match, error) {
	var err error
	if enabled.has(EntityPrivateKey) {
		matches, err = scanPrivateKeys(text, matches)
		if err != nil {
			return nil, err
		}
	}
	if enabled.has(EntityVendorToken) {
		matches, err = scanKnownSecretPrefixes(text, matches)
		if err != nil {
			return nil, err
		}
		matches, err = scanCompositeSecrets(text, matches)
		if err != nil {
			return nil, err
		}
	}
	if enabled.has(EntityJSONWebToken) {
		matches, err = scanJWTs(text, matches)
		if err != nil {
			return nil, err
		}
	}
	if enabled.has(EntityCredential) || enabled.has(EntityDatabaseCredential) {
		matches, err = scanDatabaseCredentials(text, matches, enabled)
		if err != nil {
			return nil, err
		}
	}
	if enabled.has(EntityCredential) {
		matches, err = scanCredentialAssignments(text, matches, enabled)
		if err != nil {
			return nil, err
		}
	}
	return matches, nil
}

func scanCompositeSecrets(text []byte, matches []match) ([]match, error) {
	var err error
	for start := 0; start < len(text); start++ {
		end := 0
		switch text[start] {
		case 'h':
			end = slackWebhookEnd(text, start)
		case 'x':
			end = slackAppTokenEnd(text, start)
		case 'A':
			end = onePasswordSecretKeyEnd(text, start)
		case 'g':
			end = githubFineGrainedTokenEnd(text, start)
			if end == 0 {
				end = gitlabCompositeTokenEnd(text, start)
			}
		case 'n':
			end = notionTokenEnd(text, start)
		case 'd':
			end = databricksTokenEnd(text, start)
		}
		if end > 0 {
			matches, err = appendMatch(matches, start, end, EntityVendorToken, 98)
			if err != nil {
				return nil, err
			}
			start = end - 1
			continue
		}
		if start+3 < len(text) && text[start] == 'S' && text[start+1] == 'G' && text[start+2] == '.' && wordBoundaryBeforeSecret(text, start) {
			firstEnd := start + 3
			for firstEnd < len(text) && firstEnd-start <= 64 && secretCharacterAllowed(text[firstEnd], secretToken) {
				firstEnd++
			}
			if firstEnd-start == 25 && firstEnd < len(text) && text[firstEnd] == '.' {
				end := firstEnd + 1
				for end < len(text) && end-firstEnd <= 64 && secretCharacterAllowed(text[end], secretToken) {
					end++
				}
				if end-firstEnd == 44 && (end == len(text) || !secretCharacterAllowed(text[end], secretToken)) &&
					!allEqual(text[start+3:firstEnd]) && !allEqual(text[firstEnd+1:end]) {
					matches, err = appendMatch(matches, start, end, EntityVendorToken, 98)
					if err != nil {
						return nil, err
					}
					start = end - 1
					continue
				}
			}
		}

		if !isASCIIDigit(text[start]) || !wordBoundaryBeforeSecret(text, start) {
			continue
		}
		colon := start
		for colon < len(text) && colon-start <= 16 && isASCIIDigit(text[colon]) {
			colon++
		}
		if colon-start < 5 || colon-start > 16 || colon+1 >= len(text) || text[colon] != ':' || text[colon+1] != 'A' {
			continue
		}
		end = colon + 2
		for end < len(text) && end-(colon+2) < 34 && secretCharacterAllowed(text[end], secretToken) {
			end++
		}
		if end-(colon+2) != 34 || (end < len(text) && secretCharacterAllowed(text[end], secretToken)) ||
			!hasSecretDiversity(text[colon+1:end], 16) {
			continue
		}
		matches, err = appendMatch(matches, start, end, EntityVendorToken, 98)
		if err != nil {
			return nil, err
		}
		start = end - 1
	}
	return matches, nil
}

func slackWebhookEnd(text []byte, start int) int {
	baseEnd := 0
	for _, prefix := range []string{"https://hooks.slack.com/", "http://hooks.slack.com/", "hooks.slack.com/"} {
		if secretPrefixAt(text, start, prefix) {
			baseEnd = start + len(prefix)
			break
		}
	}
	if baseEnd == 0 {
		return 0
	}
	if hasPrefixFoldASCII(text[baseEnd:], "services/") {
		pathStart := baseEnd + len("services/")
		firstEnd := slackSegmentEnd(text, pathStart, start+512)
		if firstEnd >= len(text) || text[firstEnd] != '/' {
			return 0
		}
		secondStart := firstEnd + 1
		secondEnd := slackSegmentEnd(text, secondStart, start+512)
		if secondEnd >= len(text) || text[secondEnd] != '/' {
			return 0
		}
		thirdStart := secondEnd + 1
		end := slackSegmentEnd(text, thirdStart, start+512)
		first := text[pathStart:firstEnd]
		second := text[secondStart:secondEnd]
		third := text[thirdStart:end]
		if len(first) < 9 || first[0] != 'T' || len(second) < 9 || second[0] != 'B' || len(third) < 20 ||
			slackPlaceholder(first, second, third) || !hasSecretDiversity(third, 20) {
			return 0
		}
		return end
	}
	for _, route := range []string{"workflows/", "triggers/"} {
		if !hasPrefixFoldASCII(text[baseEnd:], route) {
			continue
		}
		bodyStart := baseEnd + len(route)
		end := bodyStart
		for end < len(text) && end-bodyStart < 56 && slackWorkflowCharacter(text[end]) {
			end++
		}
		if end-bodyStart < 43 || end < len(text) && slackWorkflowCharacter(text[end]) || !hasSecretDiversity(text[bodyStart:end], 43) {
			return 0
		}
		return end
	}
	return 0
}

func slackWorkflowCharacter(value byte) bool {
	return isASCIIAlphanumeric(value) || value == '+' || value == '/'
}

func slackAppTokenEnd(text []byte, start int) int {
	const prefix = "xapp-"
	if !secretPrefixAt(text, start, prefix) {
		return 0
	}
	position := start + len(prefix)
	if position+2 > len(text) || !isASCIIDigit(text[position]) || text[position+1] != '-' {
		return 0
	}
	position += 2
	upperStart := position
	for position < len(text) && (isASCIIDigit(text[position]) || text[position] >= 'A' && text[position] <= 'Z') {
		position++
	}
	if position == upperStart || position >= len(text) || text[position] != '-' {
		return 0
	}
	position++
	digitStart := position
	for position < len(text) && isASCIIDigit(text[position]) {
		position++
	}
	if position == digitStart || position >= len(text) || text[position] != '-' {
		return 0
	}
	position++
	lowerStart := position
	for position < len(text) && (isASCIIDigit(text[position]) || text[position] >= 'a' && text[position] <= 'z') {
		position++
	}
	if position == lowerStart || !secretBoundaryAfter(text, position) || !hasSecretDiversity(text[start+len(prefix):position], 24) {
		return 0
	}
	return position
}

func onePasswordSecretKeyEnd(text []byte, start int) int {
	const prefix = "A3-"
	if !secretPrefixAt(text, start, prefix) {
		return 0
	}
	bodyStart := start + len(prefix)
	end := bodyStart
	for end < len(text) && end-bodyStart < 38 && (secretCharacterAllowed(text[end], secretUpperAlphanumeric) || text[end] == '-') {
		end++
	}
	if !secretBoundaryAfter(text, end) {
		return 0
	}
	var segmentLengths [6]int
	segmentCount := 0
	segmentLength := 0
	var compact [32]byte
	compactLength := 0
	for _, character := range text[bodyStart:end] {
		if character == '-' {
			if segmentLength == 0 || segmentCount >= len(segmentLengths) {
				return 0
			}
			segmentLengths[segmentCount] = segmentLength
			segmentCount++
			segmentLength = 0
			continue
		}
		if compactLength == len(compact) {
			return 0
		}
		compact[compactLength] = character
		compactLength++
		segmentLength++
	}
	if segmentLength == 0 || segmentCount >= len(segmentLengths) {
		return 0
	}
	segmentLengths[segmentCount] = segmentLength
	segmentCount++
	standard := segmentCount == 5 && segmentLengths == [6]int{6, 11, 5, 5, 5}
	split := segmentCount == 6 && segmentLengths == [6]int{6, 6, 5, 5, 5, 5}
	if (!standard && !split) || !hasSecretDiversity(compact[:compactLength], 16) {
		return 0
	}
	return end
}

func slackSegmentEnd(text []byte, start, limit int) int {
	if limit > len(text) {
		limit = len(text)
	}
	end := start
	for end < limit && (isASCIIAlphanumeric(text[end]) || text[end] == '_' || text[end] == '-') {
		end++
	}
	return end
}

func slackPlaceholder(first, second, third []byte) bool {
	return len(first) > 1 && len(second) > 1 && allEqual(first[1:]) && allEqual(second[1:]) && allEqual(third)
}

func githubFineGrainedTokenEnd(text []byte, start int) int {
	const prefix = "github_pat_"
	const firstPartLength = 22
	if !secretPrefixAt(text, start, prefix) {
		return 0
	}
	bodyStart := start + len(prefix)
	end := bodyStart + 82
	separator := bodyStart + firstPartLength
	if end > len(text) || text[separator] != '_' || !secretBoundaryAfter(text, end) {
		return 0
	}
	for index, character := range text[bodyStart:end] {
		if index == firstPartLength {
			continue
		}
		if !isASCIIAlphanumeric(character) {
			return 0
		}
	}
	if !hasSecretDiversity(text[bodyStart:end], 16) {
		return 0
	}
	return end
}

func gitlabCompositeTokenEnd(text []byte, start int) int {
	switch {
	case secretPrefixAt(text, start, "glpat-"):
		return gitlabRoutableBodyEnd(text, start+len("glpat-"))
	case secretPrefixAt(text, start, "glrt-t"):
		bodyStart := start + len("glrt-t")
		if bodyStart+2 > len(text) || !isASCIIDigit(text[bodyStart]) || text[bodyStart+1] != '_' {
			return 0
		}
		return gitlabRoutableBodyEnd(text, bodyStart+2)
	case secretPrefixAt(text, start, "glcbt-"):
		bodyStart := start + len("glcbt-")
		separator := bodyStart
		for separator < len(text) && separator-bodyStart < 5 && isASCIIAlphanumeric(text[separator]) {
			separator++
		}
		end := separator + 1 + 20
		if separator == bodyStart || separator >= len(text) || text[separator] != '_' || end > len(text) ||
			!allSecretCharacters(text[separator+1:end], secretToken) || !secretBoundaryAfter(text, end) ||
			allEqual(text[separator+1:end]) {
			return 0
		}
		return end
	default:
		return 0
	}
}

func gitlabRoutableBodyEnd(text []byte, bodyStart int) int {
	dot := bodyStart
	for dot < len(text) && dot-bodyStart < 300 && secretCharacterAllowed(text[dot], secretToken) {
		dot++
	}
	end := dot + 10
	if dot-bodyStart < 27 || dot >= len(text) || text[dot] != '.' || end > len(text) ||
		!allASCIILowerAlphanumeric(text[dot+1:end]) || !secretBoundaryAfter(text, end) ||
		!looksRandomSecret(text[bodyStart:dot], 16) {
		return 0
	}
	return end
}

func notionTokenEnd(text []byte, start int) int {
	const prefix = "ntn_"
	if !secretPrefixAt(text, start, prefix) {
		return 0
	}
	bodyStart := start + len(prefix)
	end := bodyStart + 46
	if end > len(text) || !allASCIIDigits(text[bodyStart:bodyStart+11]) ||
		!allASCIIAlphanumeric(text[bodyStart+11:end]) || !secretBoundaryAfter(text, end) ||
		allEqual(text[bodyStart+11:end]) {
		return 0
	}
	return end
}

func databricksTokenEnd(text []byte, start int) int {
	const prefix = "dapi"
	if !secretPrefixAt(text, start, prefix) {
		return 0
	}
	bodyStart := start + len(prefix)
	baseEnd := bodyStart + 32
	if baseEnd+2 > len(text) || !allSecretCharacters(text[bodyStart:baseEnd], secretHex) ||
		text[baseEnd] != '-' || !isASCIIDigit(text[baseEnd+1]) || !secretBoundaryAfter(text, baseEnd+2) ||
		allEqual(text[bodyStart:baseEnd]) {
		return 0
	}
	return baseEnd + 2
}

func secretPrefixAt(text []byte, start int, prefix string) bool {
	return start+len(prefix) <= len(text) && bytes.Equal(text[start:start+len(prefix)], []byte(prefix)) &&
		wordBoundaryBeforeSecret(text, start)
}

func secretBoundaryAfter(text []byte, end int) bool {
	return end >= len(text) || !isIdentifierByte(text[end])
}

func allSecretCharacters(value []byte, class secretCharacterClass) bool {
	for _, character := range value {
		if !secretCharacterAllowed(character, class) {
			return false
		}
	}
	return len(value) > 0
}

func allASCIILowerAlphanumeric(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		if !isASCIIDigit(character) && (character < 'a' || character > 'z') {
			return false
		}
	}
	return true
}

func scanPrivateKeys(text []byte, matches []match) ([]match, error) {
	const maxPrivateKeyBytes = 1 << 20
	position := 0
	for position < len(text) {
		relative := bytes.Index(text[position:], []byte("-----BEGIN "))
		if relative < 0 {
			break
		}
		start := position + relative
		kindStart := start + len("-----BEGIN ")
		lineEndRelative := bytes.Index(text[kindStart:], []byte("-----"))
		if lineEndRelative < 0 {
			break
		}
		kindEnd := kindStart + lineEndRelative
		kind := text[kindStart:kindEnd]
		endMarker := privateKeyEndMarker(kind)
		if endMarker == "" {
			position = kindEnd + 5
			continue
		}
		searchStart := kindEnd + 5
		searchEnd := searchStart + maxPrivateKeyBytes
		if searchEnd > len(text) {
			searchEnd = len(text)
		}
		endRelative := bytes.Index(text[searchStart:searchEnd], []byte(endMarker))
		if endRelative < 0 {
			position = searchStart
			continue
		}
		end := searchStart + endRelative + len(endMarker)
		var err error
		matches, err = appendMatch(matches, start, end, EntityPrivateKey, 100)
		if err != nil {
			return nil, err
		}
		position = end
	}
	return matches, nil
}

func privateKeyEndMarker(kind []byte) string {
	switch string(kind) {
	case "PRIVATE KEY":
		return "-----END PRIVATE KEY-----"
	case "RSA PRIVATE KEY":
		return "-----END RSA PRIVATE KEY-----"
	case "EC PRIVATE KEY":
		return "-----END EC PRIVATE KEY-----"
	case "DSA PRIVATE KEY":
		return "-----END DSA PRIVATE KEY-----"
	case "OPENSSH PRIVATE KEY":
		return "-----END OPENSSH PRIVATE KEY-----"
	case "PGP PRIVATE KEY BLOCK":
		return "-----END PGP PRIVATE KEY BLOCK-----"
	default:
		return ""
	}
}

func scanKnownSecretPrefixes(text []byte, matches []match) ([]match, error) {
	for start, character := range text {
		for _, spec := range secretSpecsByInitial[character] {
			if start+len(spec.prefix)+spec.minimumBody > len(text) || !bytes.Equal(text[start:start+len(spec.prefix)], []byte(spec.prefix)) || !wordBoundaryBeforeSecret(text, start) {
				continue
			}
			end := start + len(spec.prefix)
			limit := end + spec.maximumBody
			if limit > len(text) {
				limit = len(text)
			}
			for end < limit && secretCharacterAllowed(text[end], spec.characters) {
				end++
			}
			body := text[start+len(spec.prefix) : end]
			if len(body) < spec.minimumBody ||
				!secretEndBoundary(text, end, spec.characters) ||
				(len(body) > 0 && allEqual(body)) ||
				(spec.strict && !looksRandomSecret(body, 16)) ||
				knownPublicSecret(text[start:end]) {
				continue
			}
			var err error
			matches, err = appendMatch(matches, start, end, EntityVendorToken, 96)
			if err != nil {
				return nil, err
			}
		}
	}
	return matches, nil
}

func knownPublicSecret(value []byte) bool {
	switch string(value) {
	case "AKIAIOSFODNN7EXAMPLE",
		"AIzaSyabcdefghijklmnopqrstuvwxyz1234567",
		"AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",
		"AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",
		"AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
		"AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",
		"AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",
		"AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
		"AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",
		"AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",
		"AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
		"AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",
		"AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",
		"AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
		"AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",
		"AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",
		"AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY":
		return true
	default:
		return false
	}
}

func wordBoundaryBeforeSecret(text []byte, start int) bool {
	return start == 0 || !isIdentifierByte(text[start-1])
}

func secretEndBoundary(text []byte, end int, class secretCharacterClass) bool {
	if end >= len(text) {
		return true
	}
	return !secretCharacterAllowed(text[end], class) && !isIdentifierByte(text[end])
}

func secretCharacterAllowed(value byte, class secretCharacterClass) bool {
	switch class {
	case secretAlphanumeric:
		return isASCIIAlphanumeric(value)
	case secretToken:
		return isASCIIAlphanumeric(value) || value == '_' || value == '-'
	case secretBase64:
		return isASCIIAlphanumeric(value) || value == '+' || value == '/' || value == '='
	case secretHex:
		return isASCIIDigit(value) || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
	case secretUpperAlphanumeric:
		return isASCIIDigit(value) || value >= 'A' && value <= 'Z'
	case secretLetters:
		return isASCIILetter(value)
	case secretTokenEquals:
		return isASCIIAlphanumeric(value) || value == '_' || value == '-' || value == '='
	case secretAge:
		return containsByte([]byte("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"), value)
	case secretExtendedToken:
		return isASCIIAlphanumeric(value) || value == '_' || value == '-' || value == '.' || value == '='
	default:
		return false
	}
}

func scanJWTs(text []byte, matches []match) ([]match, error) {
	for start := 0; start+12 < len(text); start++ {
		if text[start] != 'e' || text[start+1] != 'y' || text[start+2] != 'J' || !wordBoundaryBeforeSecret(text, start) {
			continue
		}
		end := start
		dots := 0
		for end < len(text) && end-start <= 8192 {
			character := text[end]
			if character == '.' {
				if dots == 2 {
					break
				}
				dots++
				end++
				continue
			}
			if isASCIIAlphanumeric(character) || character == '_' || character == '-' {
				end++
				continue
			}
			break
		}
		// A third dot followed by another compact-token segment is not sentence
		// punctuation. Do not redact only the prefix of a larger value.
		if dots != 2 || end-start > 8192 ||
			(end+1 < len(text) && text[end] == '.' && isJWTCharacter(text[end+1])) ||
			!jwtValid(text[start:end]) {
			continue
		}
		var err error
		matches, err = appendMatch(matches, start, end, EntityJSONWebToken, 98)
		if err != nil {
			return nil, err
		}
		start = end - 1
	}
	return matches, nil
}

func isJWTCharacter(value byte) bool {
	return isASCIIAlphanumeric(value) || value == '_' || value == '-'
}

func jwtValid(value []byte) bool {
	first := bytes.IndexByte(value, '.')
	last := bytes.LastIndexByte(value, '.')
	if first < 4 || last <= first+2 || last+9 > len(value) || first > 512 {
		return false
	}
	header, ok := decodeJWTPart(value[:first], 512)
	if !ok {
		return false
	}
	var parsed struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if json.Unmarshal(header, &parsed) != nil || parsed.Alg == "" {
		return false
	}
	payload, ok := decodeJWTPart(value[first+1:last], 8192)
	if !ok {
		return false
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	signature, ok := decodeJWTPart(value[last+1:], 8192)
	return ok && len(signature) >= 6
}

func decodeJWTPart(value []byte, maximum int) ([]byte, bool) {
	if len(value) == 0 || len(value)%4 == 1 {
		return nil, false
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(value)))
	written, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	if err != nil || written == 0 || written > maximum {
		return nil, false
	}
	return decoded[:written], true
}

func scanDatabaseCredentials(text []byte, matches []match, enabled entityMask) ([]match, error) {
	type credentialScheme struct {
		name             string
		entity           Entity
		emptyUserIsValid bool
	}
	schemes := [...]credentialScheme{
		{name: "postgres", entity: EntityDatabaseCredential}, {name: "postgresql", entity: EntityDatabaseCredential},
		{name: "cockroachdb", entity: EntityDatabaseCredential}, {name: "mysql", entity: EntityDatabaseCredential},
		{name: "mariadb", entity: EntityDatabaseCredential}, {name: "mongodb", entity: EntityDatabaseCredential},
		{name: "mongodb+srv", entity: EntityDatabaseCredential}, {name: "mssql", entity: EntityDatabaseCredential},
		{name: "redis", entity: EntityDatabaseCredential, emptyUserIsValid: true},
		{name: "rediss", entity: EntityDatabaseCredential, emptyUserIsValid: true},
		{name: "amqp", entity: EntityDatabaseCredential}, {name: "amqps", entity: EntityDatabaseCredential},
		{name: "http", entity: EntityCredential}, {name: "https", entity: EntityCredential},
		{name: "ftp", entity: EntityCredential}, {name: "ftps", entity: EntityCredential}, {name: "sftp", entity: EntityCredential},
	}
	position := 0
	for position < len(text) {
		relative := bytes.IndexByte(text[position:], ':')
		if relative < 0 {
			break
		}
		colon := position + relative
		position = colon + 1
		if colon+2 >= len(text) || text[colon+1] != '/' || text[colon+2] != '/' {
			continue
		}
		for _, scheme := range schemes {
			if !enabled.has(scheme.entity) {
				continue
			}
			start := colon - len(scheme.name)
			if start < 0 || !equalFoldASCII(text[start:colon], scheme.name) || !wordBoundaryBeforeSecret(text, start) {
				continue
			}
			end := colon + 3
			for end < len(text) && end-start <= 4096 && !databaseURLTerminator(text[end]) {
				end++
			}
			if end < len(text) && !databaseURLTerminator(text[end]) {
				continue
			}
			userinfoStart := colon + 3
			at := bytes.IndexByte(text[userinfoStart:end], '@')
			if at < 1 {
				continue
			}
			userinfo := text[userinfoStart : userinfoStart+at]
			passwordSeparator := bytes.IndexByte(userinfo, ':')
			emptyUsernameAllowed := scheme.emptyUserIsValid && passwordSeparator == 0
			if (passwordSeparator < 1 && !emptyUsernameAllowed) || passwordSeparator == len(userinfo)-1 ||
				!databasePasswordValid(userinfo[passwordSeparator+1:]) {
				continue
			}
			var err error
			matches, err = appendMatch(matches, start, end, scheme.entity, 99)
			if err != nil {
				return nil, err
			}
		}
	}
	return matches, nil
}

func databaseURLTerminator(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n', '"', '\'', '<', '>', '`', ')', ']', '}', ',', ';':
		return true
	default:
		return false
	}
}

func databasePasswordValid(value []byte) bool {
	return len(value) > 0 && !placeholderValue(value) && !maskedPasswordValue(value)
}

func scanCredentialAssignments(text []byte, matches []match, enabled entityMask) ([]match, error) {
	for start := 0; start < len(text); start++ {
		if !isASCIILetter(text[start]) || !wordBoundaryBefore(text, start) {
			continue
		}
		wordEnd := start + 1
		for wordEnd < len(text) && (isIdentifierByte(text[wordEnd]) || text[wordEnd] == '-') {
			wordEnd++
		}
		word := text[start:wordEnd]
		kind := credentialWordKind(word)
		if kind == 0 {
			start = wordEnd - 1
			continue
		}
		valueStart, quoted, explicit, ok := assignmentValueStart(text, wordEnd)
		if !ok {
			start = wordEnd - 1
			continue
		}
		valueEnd := credentialValueEnd(text, valueStart, quoted)
		if valueEnd <= valueStart {
			start = wordEnd - 1
			continue
		}
		value := text[valueStart:valueEnd]
		if knownPublicSecret(value) {
			start = wordEnd - 1
			continue
		}
		valid := false
		entity := EntityCredential
		switch kind {
		case 1:
			valid = passwordValueValid(value, explicit)
		case 2:
			valid = looksRandomSecret(value, 16)
		case 3:
			valid = bearerValueValid(value)
		case 4:
			valid = basicCredentialValid(value)
			entity = EntityCredential
		case 5:
			valid = !canonicalUUID(value) && looksRandomSecret(value, 16)
		}
		if valid && enabled.has(entity) {
			var err error
			matches, err = appendMatch(matches, valueStart, valueEnd, entity, 90)
			if err != nil {
				return nil, err
			}
		}
		start = wordEnd - 1
	}
	return matches, nil
}

// 1=password, 2=strong secret assignment, 3=bearer, 4=basic,
// 5=weak token assignment.
func credentialWordKind(word []byte) uint8 {
	for _, value := range []string{"password", "passwordhash", "passwd", "pwd"} {
		if credentialWordEqual(word, value) {
			return 1
		}
	}
	for _, value := range []string{
		"secret", "secretkey", "apikey", "serviceapikey", "apitoken", "accesskey", "accesstoken", "authtoken",
		"clientsecret", "privatekey", "credential", "credentials", "databaseurl", "dburl",
		"connectionstring", "awssecretaccesskey", "awssessiontoken", "sastoken", "auth", "xapikey",
	} {
		if credentialWordEqual(word, value) {
			return 2
		}
	}
	if credentialWordEqual(word, "token") || credentialWordDelimitedSuffix(word, "token") {
		return 5
	}
	for _, suffix := range []string{"password", "secret", "apikey", "accesskey"} {
		if credentialWordDelimitedSuffix(word, suffix) {
			return 2
		}
	}
	if credentialWordEqual(word, "bearer") {
		return 3
	}
	if credentialWordEqual(word, "basic") {
		return 4
	}
	return 0
}

func credentialWordDelimitedSuffix(word []byte, expected string) bool {
	expectedIndex := len(expected) - 1
	start := len(word)
	for index := len(word) - 1; index >= 0 && expectedIndex >= 0; index-- {
		if word[index] == '_' || word[index] == '-' {
			continue
		}
		if lowerASCII(word[index]) != expected[expectedIndex] {
			return false
		}
		start = index
		expectedIndex--
	}
	if expectedIndex >= 0 || start == len(word) {
		return false
	}
	if start == 0 || word[start-1] == '_' || word[start-1] == '-' {
		return true
	}
	return word[start] >= 'A' && word[start] <= 'Z' &&
		(word[start-1] >= 'a' && word[start-1] <= 'z' || isASCIIDigit(word[start-1]))
}

func credentialWordEqual(word []byte, expected string) bool {
	position := 0
	for _, character := range word {
		if character == '_' || character == '-' {
			continue
		}
		if position >= len(expected) || lowerASCII(character) != expected[position] {
			return false
		}
		position++
	}
	return position == len(expected)
}

func assignmentValueStart(text []byte, position int) (int, byte, bool, bool) {
	index := position
	separated := false
	explicit := false

	// A quoted JSON or YAML key leaves the closing quote immediately after the
	// matched word. Consume it only when a key separator follows.
	if index < len(text) && (text[index] == '"' || text[index] == '\'') {
		next := index + 1
		for next < len(text) && next-index <= 16 && (text[next] == ' ' || text[next] == '\t') {
			next++
		}
		if next < len(text) && (text[next] == ':' || text[next] == '=') {
			index = next
		}
	}

	for index < len(text) && index-position <= 24 {
		switch text[index] {
		case ' ', '\t':
			separated = true
			index++
		case ':', '=':
			separated = true
			explicit = true
			index++
		case '"', '\'':
			if !separated {
				return index, 0, false, false
			}
			return index + 1, text[index], explicit, true
		default:
			return index, 0, explicit, separated
		}
	}
	return index, 0, false, false
}

func credentialValueEnd(text []byte, start int, quote byte) int {
	end := start
	for end < len(text) {
		character := text[end]
		if quote != 0 {
			if character == quote && !escapedByteAt(text, start, end) {
				break
			}
		} else {
			switch character {
			case ' ', '\t', '\r', '\n', ',', ';', '&', '}', ']', '"', '\'', '`':
				return end
			}
		}
		end++
	}
	return end
}

func escapedByteAt(text []byte, start, position int) bool {
	backslashes := 0
	for index := position - 1; index >= start && text[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func placeholderValue(value []byte) bool {
	if len(value) == 0 || value[0] == '$' || value[0] == '<' || value[0] == '{' || value[0] == '%' && value[len(value)-1] == '%' {
		return true
	}
	for _, placeholder := range []string{
		"password", "secret", "token", "changeme", "change_me", "example", "dummy", "test", "testing",
		"todo", "null", "none", "redacted", "undefined", "placeholder", "your_token", "your_key",
		"your-key-here", "your_key_here", "replace_me", "insert_here",
	} {
		if equalFoldASCII(value, placeholder) {
			return true
		}
	}
	return false
}

func passwordValueValid(value []byte, explicit bool) bool {
	if len(value) < 6 || placeholderValue(value) {
		return false
	}
	if explicit {
		return !maskedPasswordValue(value)
	}
	classes := characterClasses(value)
	return classes >= 2 && !allEqual(value)
}

func maskedPasswordValue(value []byte) bool {
	return len(value) > 0 && allEqual(value) && (value[0] == 'x' || value[0] == 'X' || value[0] == '*')
}

func bearerValueValid(value []byte) bool {
	return len(value) >= 16 && !placeholderValue(value) && (jwtValid(value) || looksRandomSecret(value, 16))
}

func basicCredentialValid(value []byte) bool {
	if len(value) < 8 || len(value) > 4096 {
		return false
	}
	encoded := string(value)
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.RawStdEncoding.EncodeToString(decoded) != encoded {
			return false
		}
	}
	if len(decoded) < 3 {
		return false
	}
	colon := bytes.IndexByte(decoded, ':')
	if colon <= 0 || colon == len(decoded)-1 || maskedBasicValue(decoded[colon+1:]) {
		return false
	}
	for _, character := range decoded {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func maskedBasicValue(value []byte) bool {
	if len(value) < 4 || !allEqual(value) {
		return false
	}
	return value[0] == 'x' || value[0] == 'X' || value[0] == '*'
}

func looksRandomSecret(value []byte, minimum int) bool {
	if !hasSecretDiversity(value, minimum) {
		return false
	}
	var lower, upper, digit, symbol bool
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
			lower = true
		case character >= 'A' && character <= 'Z':
			upper = true
		case isASCIIDigit(character):
			digit = true
		default:
			symbol = true
		}
	}
	classes := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			classes++
		}
	}
	return (digit || symbol) && classes >= 2
}

func hasSecretDiversity(value []byte, minimum int) bool {
	if len(value) < minimum || placeholderValue(value) || allEqual(value) {
		return false
	}
	var counts [256]int
	unique := 0
	mostFrequent := 0
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
		if counts[character] == 0 {
			unique++
		}
		counts[character]++
		if counts[character] > mostFrequent {
			mostFrequent = counts[character]
		}
	}
	return unique >= 8 && mostFrequent*5 < len(value)*3
}

func canonicalUUID(value []byte) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !secretCharacterAllowed(character, secretHex) {
			return false
		}
	}
	return true
}

func characterClasses(value []byte) int {
	var lower, upper, digit, symbol bool
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
			lower = true
		case character >= 'A' && character <= 'Z':
			upper = true
		case isASCIIDigit(character):
			digit = true
		default:
			symbol = true
		}
	}
	count := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			count++
		}
	}
	return count
}
