package customerkey

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

// Keys belongs to one request. Labels select organization-registered roots;
// envelopes continue binding ciphertext to the immutable root identifier.
type Keys map[string]*Key

var labelPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)

func ParseKeys(encoded map[string]string) (Keys, error) {
	keys := make(Keys, len(encoded))
	for label, value := range encoded {
		if !labelPattern.MatchString(label) {
			keys.Clear()
			return nil, ErrKey
		}
		key, err := Parse(value)
		if err != nil {
			keys.Clear()
			return nil, err
		}
		keys[label] = key
	}
	return keys, nil
}

func (keys Keys) String() string   { return "[redacted]" }
func (keys Keys) GoString() string { return "[redacted]" }

func (keys Keys) Clear() {
	for _, key := range keys {
		key.Clear()
	}
	clear(keys)
}

// Identity distinguishes concurrent cache fills using different supplied roots
// without including root material in a cache key or retaining it in the cache.
func (keys Keys) Identity() string {
	ids := make(map[string]string, len(keys))
	for label, key := range keys {
		ids[label] = key.ID()
	}
	encoded, _ := json.Marshal(ids)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (keys Keys) key(id string) *Key {
	for _, key := range keys {
		if key.Matches(id) {
			return key
		}
	}
	return nil
}

func (keys Keys) Matches(id string) bool { return keys.key(id) != nil }

func (keys Keys) Open(envelope Envelope, organizationID, purpose string, maximum int) ([]byte, error) {
	return keys.key(envelope.KeyID).Open(envelope, organizationID, purpose, maximum)
}

// Validate checks supplied labels even if their roots are not needed by the
// selected candidate. Missing roots are checked only for applicable content.
func (keys Keys) Validate(registered map[string]string) error {
	for label, key := range keys {
		if !key.Matches(registered[label]) {
			return ErrKey
		}
	}
	return nil
}

func ValidateRegistry(registered map[string]string) error {
	if len(registered) == 0 {
		return ErrKey
	}
	seen := make(map[string]bool, len(registered))
	for label, id := range registered {
		if !labelPattern.MatchString(label) || len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" || seen[id] {
			return ErrKey
		}
		seen[id] = true
	}
	return nil
}

func Registered(registered map[string]string, id string) bool {
	for _, current := range registered {
		if current == id {
			return true
		}
	}
	return false
}
