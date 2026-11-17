package stogas

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// A PDF stays a file where the deployment reads it and nothing must read its text. Where
// redaction must read it, or the policy always extracts, the provider gets its pages as text.
func TestPDFBecomesTextWhereAPolicyNeedsItsText(t *testing.T) {
	invoice, err := os.ReadFile("inputfiles/testdata/pdf/invoice.pdf")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"model":"provider:openai gpt-5.5","input":[{"role":"user","content":[{"type":"input_text","text":"Sum it up."},` +
		`{"type":"input_file","filename":"invoice.pdf","file_data":"data:application/pdf;base64,` + base64.StdEncoding.EncodeToString(invoice) + `"}]}]}`)
	sent := func(document string) string {
		t.Helper()
		source, err := policy.CompileSource([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Policy: config, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(resolved.RawBody())
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	const pages = `invoice.pdf (application/pdf)\n## Page 1\n\nInvoice 4471 for hello@example.com\n\n## Page 2\n\nTotal: 12 EUR`
	if got := sent(`{"plugins":{"textExtraction":{"pdf":"auto"}}}`); !strings.Contains(got, "application/pdf;base64,") || strings.Contains(got, "## Page") {
		t.Fatalf("a deployment that reads PDFs did not get the file: %.300s", got)
	}
	if got := sent(`{"plugins":{"textExtraction":{"pdf":"always"}}}`); !strings.Contains(got, pages) || strings.Contains(got, "base64") {
		t.Fatalf("the policy always extracts, and the provider did not get the pages: %.300s", got)
	}
	got := sent(`{"plugins":{"textExtraction":{"pdf":"auto"},"redaction":{"customPattern":"hello@example\\.com"}}}`)
	if strings.Contains(got, "hello@example.com") || strings.Contains(got, "base64") || !strings.Contains(got, `## Page 2\n\nTotal: 12 EUR`) {
		t.Fatalf("redaction did not read the PDF's text: %.300s", got)
	}
}
