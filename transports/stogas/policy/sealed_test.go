package policy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
)

// sealTest encrypts a value for its place in a policy, as stogas encrypt does.
func sealTest(t *testing.T, root []byte, organizationID, purpose, plaintext string) string {
	t.Helper()
	sum := sha256.Sum256(append([]byte("stogas.customer-key.v1\x00"), root...))
	keyID := hex.EncodeToString(sum[:])
	salt, nonce := make([]byte, 32), make([]byte, 12)
	rand.Read(salt)
	rand.Read(nonce)
	context := strings.Join([]string{"stogas.customer-content.v1", organizationID, purpose, keyID}, "\x00")
	derived, err := hkdf.Key(sha256.New, root, salt, context, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(derived)
	aead, _ := cipher.NewGCM(block)
	encode := base64.RawURLEncoding.EncodeToString
	return fmt.Sprintf(`{"encrypted":{"version":1,"keyId":%q,"salt":%q,"nonce":%q,"blob":%q}}`,
		keyID, encode(salt), encode(nonce), encode(aead.Seal(nil, nonce, []byte(plaintext), []byte(context))))
}

func sealTestKeys(t *testing.T, roots map[string][]byte) customerkey.Keys {
	t.Helper()
	encoded := map[string]string{}
	for label, root := range roots {
		encoded[label] = base64.RawURLEncoding.EncodeToString(root)
	}
	keys, err := customerkey.ParseKeys(encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Clear)
	return keys
}

// Any value inside the export and redaction plugins can be sealed on its own, under
// different roots, and opens back in its place. Purposes leave out array indexes,
// so reordering a list keeps its values readable.
func TestSealedValuesOpenInTheirPlace(t *testing.T) {
	first, second := make([]byte, 32), make([]byte, 32)
	rand.Read(first)
	rand.Read(second)
	const org = "org"
	url := sealTest(t, first, org, "plugins/export/destinations/url", ` "https://logs.example.com/a?token=secret"   `)
	destination := sealTest(t, second, org, "plugins/export/destinations",
		`{"url":"https://audit.example.com/b","headers":{"Authorization":"Bearer secret"}}`)
	group := sealTest(t, first, org, "plugins/redaction/literals", `{"values":["Project Falcon"],"ignoreCase":true}`)
	for _, order := range [][2]string{{`{"url":` + url + `,"content":false}`, destination}, {destination, `{"url":` + url + `,"content":false}`}} {
		raw := `{"plugins":{"export":{"destinations":[` + order[0] + `,` + order[1] + `]},"redaction":{"literals":[` + group + `]}}}`
		document, err := ParseSourceDocument([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if ids := document.EncryptionKeyIDs(); len(ids) != 2 || document.EncryptedUnits() != permissionExport|permissionRedaction {
			t.Fatalf("roots %v and units %v", ids, document.EncryptedUnits())
		}
		if _, err := document.Open(org, sealTestKeys(t, map[string][]byte{"first": first})); !errors.Is(err, customerkey.ErrKey) {
			t.Fatalf("opened without the second root: %v", err)
		}
		source, err := document.Open(org, sealTestKeys(t, map[string][]byte{"first": first, "second": second}))
		if err != nil {
			t.Fatal(err)
		}
		var urls []string
		for _, sent := range source.Config.Plugins.Export.Destinations {
			urls = append(urls, sent.URL)
		}
		slices.Sort(urls)
		if !slices.Equal(urls, []string{"https://audit.example.com/b", "https://logs.example.com/a?token=secret"}) {
			t.Fatalf("destinations %v", urls)
		}
		literals, _ := json.Marshal(source.Config.Plugins.Redaction)
		if !strings.Contains(strings.ToLower(string(literals)), "project falcon") {
			t.Fatalf("redaction %s", literals)
		}
	}
}

// A sealed value opens only in the setting and organization it was sealed for.
func TestSealedValuesStayInTheirSetting(t *testing.T) {
	root := make([]byte, 32)
	rand.Read(root)
	keys := sealTestKeys(t, map[string][]byte{"root": root})
	url := sealTest(t, root, "org", "plugins/export/destinations/url", `"https://logs.example.com"`)
	whole := sealTest(t, root, "org", "plugins/export", `{"destinations":[{"url":"https://logs.example.com"}]}`)
	for name, raw := range map[string]string{
		"a url as a whole destination": `{"plugins":{"export":{"destinations":[` + url + `]}}}`,
		"a plugin as one destination":  `{"plugins":{"export":{"destinations":[` + whole + `]}}}`,
		"an export url in redaction":   `{"plugins":{"redaction":{"literals":[` + url + `]}}}`,
	} {
		document, err := ParseSourceDocument([]byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := document.Open("org", keys); !errors.Is(err, customerkey.ErrEnvelope) {
			t.Fatalf("%s opened: %v", name, err)
		}
	}
	document, err := ParseSourceDocument([]byte(`{"plugins":{"export":{"destinations":[{"url":` + url + `}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := document.Open("other-org", keys); !errors.Is(err, customerkey.ErrEnvelope) {
		t.Fatalf("opened for another organization: %v", err)
	}
}

// Headers carry the destination's credentials, so they are sealed only together
// with the URL that receives them.
func TestSealedHeadersNeedTheirURL(t *testing.T) {
	root := make([]byte, 32)
	rand.Read(root)
	headers := sealTest(t, root, "org", "plugins/export/destinations/headers", `{"Authorization":"Bearer secret"}`)
	value := sealTest(t, root, "org", "plugins/export/destinations/headers/Authorization", `"Bearer secret"`)
	for _, raw := range []string{
		`{"plugins":{"export":{"destinations":[{"url":"https://logs.example.com","headers":` + headers + `}]}}}`,
		`{"plugins":{"export":{"destinations":[{"url":"https://logs.example.com","headers":{"Authorization":` + value + `}}]}}}`,
		`{"rules":{"eu":{"plugins":{"export":{"destinations":[{"url":"https://logs.example.com","headers":` + headers + `}]}}}}}`,
	} {
		if _, err := ParseSourceDocument([]byte(raw)); err == nil || !strings.Contains(err.Error(), "headers together with its url") {
			t.Fatalf("accepted headers apart from their url: %v", err)
		}
	}
}

// Sealed values count by their plaintext against the policy's size limit.
func TestSealedValuesCountTheirPlaintext(t *testing.T) {
	root := make([]byte, 32)
	rand.Read(root)
	large := `{"values":["` + strings.Repeat("a", 200) + `"]}` + strings.Repeat(" ", MaxSourceBytes/2)
	group := sealTest(t, root, "org", "plugins/redaction/literals", large)
	raw := `{"plugins":{"redaction":{"literals":[` + group + `,` + group + `,` + group + `]}}}`
	if _, err := ParseSourceDocument([]byte(raw)); err == nil {
		t.Fatal("accepted sealed values larger than the policy limit")
	}
}
