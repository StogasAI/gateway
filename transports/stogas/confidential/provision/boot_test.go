package provision

import (
	"reflect"
	"testing"
)

const validSecrets = `{"certificate_pem":"cert","region":"US-VA","secrets":[{"name":"KEY","plaintext":"secret"}]}`

func TestBootSecretsAcceptOnlyCompleteRegisteredContents(t *testing.T) {
	opened, err := ParseBootSecrets([]byte(validSecrets))
	if err != nil {
		t.Fatal(err)
	}
	want := BootSecrets{CertificatePEM: "cert", Region: RegionUSVA, Secrets: []BootSecretValue{{Name: "KEY", Plaintext: "secret"}}}
	if !reflect.DeepEqual(*opened, want) {
		t.Fatal("opened provisioning differs", *opened)
	}
	for name, body := range map[string]string{
		"missing region": `{"certificate_pem":"cert","secrets":[{"name":"KEY","plaintext":"secret"}]}`,
		"unknown region": `{"certificate_pem":"cert","region":"unregistered-region","secrets":[{"name":"KEY","plaintext":"secret"}]}`,
		"malformed":      "{",
		"extra json":     validSecrets + "{}",
		"unknown field":  `{"certificate_pem":"cert","region":"US-VA","secrets":[],"instruction":"execute"}`,
		"no cert":        `{"region":"US-VA","secrets":[{"name":"KEY","plaintext":"secret"}]}`,
		"no secrets":     `{"certificate_pem":"cert","region":"US-VA","secrets":[]}`,
		"bad name":       `{"certificate_pem":"cert","region":"US-VA","secrets":[{"name":"not-a-key","plaintext":"secret"}]}`,
		"empty value":    `{"certificate_pem":"cert","region":"US-VA","secrets":[{"name":"KEY","plaintext":""}]}`,
		"duplicate":      `{"certificate_pem":"cert","region":"US-VA","secrets":[{"name":"KEY","plaintext":"secret"},{"name":"KEY","plaintext":"different"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if opened, err := ParseBootSecrets([]byte(body)); err == nil || opened != nil {
				t.Fatal("accepted invalid provisioning contents")
			}
		})
	}
}
