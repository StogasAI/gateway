package customerkey

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestLabeledRootsBindLabelsWithoutRequiringUnusedRoots(t *testing.T) {
	first, second := strings.Repeat("a", 32), strings.Repeat("b", 32)
	keys, err := ParseKeys(map[string]string{
		"providers": base64.RawURLEncoding.EncodeToString([]byte(first)),
		"redaction": base64.RawURLEncoding.EncodeToString([]byte(second)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Clear()
	registered := map[string]string{"providers": keys["providers"].ID(), "redaction": keys["redaction"].ID()}
	if ValidateRegistry(registered) != nil || keys.Validate(registered) != nil {
		t.Fatal("valid labeled roots rejected")
	}
	providerOnly := Keys{"providers": keys["providers"]}
	if providerOnly.Validate(registered) != nil || !providerOnly.Matches(registered["providers"]) || providerOnly.Matches(registered["redaction"]) {
		t.Fatal("unused root became required or supplied roots were confused")
	}
	for _, invalid := range []Keys{{"providers": keys["redaction"]}, {"unknown": keys["providers"]}} {
		if invalid.Validate(registered) == nil {
			t.Fatal("wrong label or root accepted")
		}
	}
	if keys.Identity() == providerOnly.Identity() {
		t.Fatal("different supplied roots shared a fill identity")
	}
	if keys.Identity() != (Keys{"redaction": keys["redaction"], "providers": keys["providers"]}).Identity() {
		t.Fatal("map order changed fill identity")
	}
	for _, value := range []any{keys, keys["providers"]} {
		if fmt.Sprintf("%v", value) != "[redacted]" || fmt.Sprintf("%#v", value) != "[redacted]" {
			t.Fatal("key formatting exposes material")
		}
	}
	root := keys["providers"]
	keys.Clear()
	if len(keys) != 0 || root.ID() != "" || root.material != [32]byte{} {
		t.Fatal("root material retained after clear")
	}
}

func TestKeyRegistryRejectsAmbiguousLabelsAndIdentifiers(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, registered := range []map[string]string{
		{}, {"A": id}, {"_key": id}, {strings.Repeat("a", 49): id}, {"key": "bad"},
		{"one": id, "two": id}, {"__proto__": id},
	} {
		if ValidateRegistry(registered) == nil {
			t.Fatal("invalid registry accepted")
		}
	}
	for _, encoded := range []map[string]string{{"invalid label": "bad"}, {"key": "bad"}, {"good": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "bad": "invalid"}} {
		if keys, err := ParseKeys(encoded); err == nil || keys != nil {
			t.Fatal("invalid supplied keys accepted")
		}
	}
}
