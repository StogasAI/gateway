package redaction

import (
	"strings"
	"testing"
)

var credentialWords = map[string]uint8{
	"password": 1, "passwordhash": 1, "passwd": 1, "pwd": 1,
	"secret": 2, "secretkey": 2, "apikey": 2, "serviceapikey": 2, "apitoken": 2,
	"accesskey": 2, "accesstoken": 2, "authtoken": 2, "clientsecret": 2, "privatekey": 2,
	"credential": 2, "credentials": 2, "databaseurl": 2, "dburl": 2, "connectionstring": 2,
	"awssecretaccesskey": 2, "awssessiontoken": 2, "sastoken": 2, "auth": 2, "xapikey": 2,
	"bearer": 3, "basic": 4, "token": 5,
}

func referenceCredentialKind(word string) uint8 {
	normalize := func(s string) string {
		return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, "_", ""), "-", ""))
	}
	if kind := credentialWords[normalize(word)]; kind != 0 {
		return kind
	}
	for start := range len(word) {
		if start != 0 && word[start-1] != '_' && word[start-1] != '-' &&
			!(word[start] >= 'A' && word[start] <= 'Z' && (word[start-1] >= 'a' && word[start-1] <= 'z' || word[start-1] >= '0' && word[start-1] <= '9')) {
			continue
		}
		switch normalize(word[start:]) {
		case "token":
			return 5
		case "password", "secret", "apikey", "accesskey":
			return 2
		}
	}
	return 0
}

func TestCredentialClassifierCaseAndSeparatorCombinations(t *testing.T) {
	for word, want := range credentialWords {
		for mask := range 1 << len(word) {
			value := []byte(word)
			for i := range value {
				if mask&(1<<i) != 0 {
					value[i] -= 'a' - 'A'
				}
			}
			if got := credentialWordKind(value); got != want {
				t.Fatalf("%q: got %d, want %d", value, got, want)
			}
		}
		for _, separator := range []string{"_", "-", "_-_"} {
			value := strings.Join(strings.Split(word, ""), separator)
			for _, prefix := range []string{"", "service_", "project-", "service", "Service1"} {
				input := prefix + value
				if got, want := credentialWordKind([]byte(input)), referenceCredentialKind(input); got != want {
					t.Fatalf("%q: got %d, want %d", input, got, want)
				}
			}
		}
	}
}

func FuzzCredentialClassifier(f *testing.F) {
	for _, seed := range []string{"serviceSecret", "prefix_API_KEY", "awssessiontoken", "Bearer", "ordinary", strings.Repeat("_", 100) + "secret", strings.Repeat("x", 100) + "Password"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, word string) {
		if len(word) > 4096 {
			return
		}
		// The production scanner passes ASCII identifiers only.
		for _, character := range word {
			if character > 127 {
				return
			}
		}
		if got, want := credentialWordKind([]byte(word)), referenceCredentialKind(word); got != want {
			t.Fatalf("%q: got %d, want %d", word, got, want)
		}
	})
}
