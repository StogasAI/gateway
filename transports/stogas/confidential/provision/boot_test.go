package provision

import (
	"reflect"
	"testing"
)

const validSecrets = `{"certificate_pem":"cert","region":"US-VA","secrets":[{"key_id":"key","name":"KEY","plaintext":"secret","version":"1"}]}`

func TestBootSecretsAcceptOnlyCompleteRegisteredContents(t *testing.T) {
	opened, err := ParseBootSecrets([]byte(validSecrets))
	if err != nil {
		t.Fatal(err)
	}
	want := BootSecrets{CertificatePEM: "cert", Region: RegionUSVA, Secrets: []BootSecretValue{{KeyID: "key", Name: "KEY", Plaintext: "secret", Version: "1"}}}
	if !reflect.DeepEqual(*opened, want) {
		t.Fatal("opened provisioning differs", *opened)
	}
	for name, body := range map[string]string{
		"missing region": `{"certificate_pem":"cert","secrets":[{"key_id":"key","name":"KEY","plaintext":"secret","version":"1"}]}`,
		"unknown region": `{"certificate_pem":"cert","region":"unregistered-region","secrets":[{"key_id":"key","name":"KEY","plaintext":"secret","version":"1"}]}`,
		"malformed":      "{",
		"extra json":     validSecrets + "{}",
		"unknown field":  `{"certificate_pem":"cert","region":"US-VA","secrets":[],"instruction":"execute"}`,
		"no cert":        `{"region":"US-VA","secrets":[{"key_id":"key","name":"KEY","plaintext":"secret","version":"1"}]}`,
		"no secrets":     `{"certificate_pem":"cert","region":"US-VA","secrets":[]}`,
		"bad name":       `{"certificate_pem":"cert","region":"US-VA","secrets":[{"key_id":"key","name":"not-a-key","plaintext":"secret","version":"1"}]}`,
		"empty value":    `{"certificate_pem":"cert","region":"US-VA","secrets":[{"key_id":"key","name":"KEY","plaintext":"","version":"1"}]}`,
		"duplicate":      `{"certificate_pem":"cert","region":"US-VA","secrets":[{"key_id":"key","name":"KEY","plaintext":"secret","version":"1"},{"key_id":"key","name":"KEY","plaintext":"different","version":"1"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if opened, err := ParseBootSecrets([]byte(body)); err == nil || opened != nil {
				t.Fatal("accepted invalid provisioning contents")
			}
		})
	}
}
