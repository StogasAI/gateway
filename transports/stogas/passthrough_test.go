package stogas

import (
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestCanonicalPassthroughCredential(t *testing.T) {
	standard, err := CanonicalPassthroughCredential(schemas.OpenAI, "sk-upstream")
	if err != nil || standard != "sk-upstream" {
		t.Fatalf("standard credential = %q, err=%v", standard, err)
	}
	if _, err = CanonicalPassthroughCredential(schemas.Azure, "azure-secret"); err == nil {
		t.Fatal("Azure accepted a pass-through credential")
	}
	if _, err = CanonicalPassthroughCredential(schemas.OpenAI, "unsafe secret"); err == nil {
		t.Fatal("provider accepted an unsafe pass-through credential")
	}
}
