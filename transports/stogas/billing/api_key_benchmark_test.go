package billing

import "testing"

func BenchmarkSignedAPIKeyParse(b *testing.B) {
	const secret = "public-benchmark-pepper"
	key := testSignedAPIKey(b, secret, "019de515-eabf-7c0e-89bd-400629a79580",
		"019de516-7df8-71d6-80e4-3c62090d4e94", "019de516-b10f-786f-97f8-b95c71dfe1b6", "", apiKeyVersion)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := parseSignedAPIKey(key, secret); err != nil {
			b.Fatal(err)
		}
	}
}
