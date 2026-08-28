package redaction

import (
	"bytes"
	"errors"
	"testing"
)

func TestIPAddressPresentations(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{Patterns: []Pattern{PatternIPAddress}})
	tests := []struct {
		source    string
		want      string
		wantItems uint32
	}{
		{source: "public 8.8.8.8.", want: "public <IP_ADDRESS>."},
		{source: "private 192.168.1.1, loopback 127.0.0.1", want: "private <IP_ADDRESS>, loopback <IP_ADDRESS>", wantItems: 2},
		{source: "bounds 0.0.0.0 and 255.255.255.255", want: "bounds <IP_ADDRESS> and <IP_ADDRESS>", wantItems: 2},
		{source: "port 10.0.0.1:8443", want: "port <IP_ADDRESS>:8443"},
		{source: "cidr 10.0.0.0/8", want: "cidr <IP_ADDRESS>/8"},
		{source: "v6 2001:4860:4860::8888", want: "v6 <IP_ADDRESS>"},
		{source: "full 2001:0DB8:85A3:0000:0000:8A2E:0370:7334", want: "full <IP_ADDRESS>"},
		{source: "loopback ::1.", want: "loopback <IP_ADDRESS>."},
		{source: "unspecified ::", want: "unspecified <IP_ADDRESS>"},
		{source: "mapped ::ffff:192.0.2.128", want: "mapped <IP_ADDRESS>"},
		{source: "zone fe80::1%eth0", want: "zone <IP_ADDRESS>"},
		{source: "zone fe80::1%eth0.", want: "zone <IP_ADDRESS>."},
		{source: "bracket [2001:db8::1]:443", want: "bracket [<IP_ADDRESS>]:443"},
		{source: "URL https://[2001:db8::2]/v1", want: "URL https://[<IP_ADDRESS>]/v1"},
		{source: "cidr 2001:db8::/32", want: "cidr <IP_ADDRESS>/32"},
		{source: "hex dead:beef:cafe:babe:feed:face:1234:5678", want: "hex <IP_ADDRESS>"},
		{source: "label IP:192.168.1.1", want: "label IP:<IP_ADDRESS>"},
		{source: "::", want: "<IP_ADDRESS>"},
	}
	for _, test := range tests {
		wantItems := test.wantItems
		if wantItems == 0 {
			wantItems = 1
		}
		redactor := NewWithPolicy(policy)
		out, changed, err := redactor.redactBytes([]byte(test.source))
		if err != nil || !changed || string(out) != test.want || redactor.Summary().ItemsRedacted != wantItems {
			t.Errorf("redaction of %q = %q, want %q, changed=%t summary=%#v err=%v", test.source, out, test.want, changed, redactor.Summary(), err)
		}
	}
}

func TestInvalidAndEmbeddedIPLikeValuesRemainVisible(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{Patterns: []Pattern{PatternIPAddress}})
	for _, source := range []string{
		"192.168.1",
		"192.168.1.256",
		"192.168.001.1",
		"1.2.3.4.5",
		"x192.168.1.1",
		"192.168.1.1x",
		"v1.2.3.4",
		"12:30:45",
		"aa:bb:cc:dd:ee:ff",
		"2001:db8:::1",
		"2001:db8::g1",
		"2001:db8::1x",
		"1:2:3:4:5:6:7:8:9",
		"::ffff:999.1.1.1",
		"用户192.168.1.1",
		"550e8400-e29b-41d4-a716-446655440000",
		"https://host.invalid:443",
	} {
		redactor := NewWithPolicy(policy)
		out, changed, err := redactor.redactBytes([]byte(source))
		if err != nil || changed || string(out) != source || redactor.Summary().ItemsRedacted != 0 {
			t.Errorf("invalid IP-like value %q became %q, changed=%t summary=%#v err=%v", source, out, changed, redactor.Summary(), err)
		}
	}
}

func TestIPAddressesAreOptInAndExactlyCounted(t *testing.T) {
	t.Parallel()
	source := []byte("alice@corp.io 10.0.0.1 [2001:db8::1]")
	defaultRedactor := New()
	defaultOut, changed, err := defaultRedactor.redactBytes(source)
	if err != nil || !changed || string(defaultOut) != "<EMAIL_ADDRESS> 10.0.0.1 [2001:db8::1]" || defaultRedactor.Summary().ItemsRedacted != 1 {
		t.Fatalf("default IP behavior output=%q changed=%t summary=%#v err=%v", defaultOut, changed, defaultRedactor.Summary(), err)
	}

	policy := mustCompilePolicy(t, Options{Patterns: []Pattern{PatternIPAddress}})
	ipRedactor := NewWithPolicy(policy)
	ipOut, changed, err := ipRedactor.redactBytes(source)
	if err != nil || !changed || string(ipOut) != "alice@corp.io <IP_ADDRESS> [<IP_ADDRESS>]" || ipRedactor.Summary().ItemsRedacted != 2 {
		t.Fatalf("IP-only behavior output=%q changed=%t summary=%#v err=%v", ipOut, changed, ipRedactor.Summary(), err)
	}
}

func FuzzIPAddressRedaction(f *testing.F) {
	for _, seed := range []string{
		"8.8.8.8",
		"192.168.001.1",
		"[2001:db8::1]:443",
		"fe80::1%eth0",
		"::ffff:192.0.2.128",
		"aa:bb:cc:dd:ee:ff",
		"\x00\xff malformed",
	} {
		f.Add([]byte(seed))
	}
	policy, err := CompilePolicy(Options{Patterns: []Pattern{PatternIPAddress}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		redactor := NewWithPolicy(policy)
		out, changed, err := redactor.redactBytes(source)
		if errors.Is(err, ErrMatchLimit) {
			return
		}
		if err != nil || changed != !bytes.Equal(source, out) || changed != (redactor.Summary().ItemsRedacted > 0) {
			t.Fatalf("IP result output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
		}
		stable, changed, err := NewWithPolicy(policy).redactBytes(out)
		if err != nil || changed || !bytes.Equal(stable, out) {
			t.Fatalf("IP output was not stable: output=%q changed=%t err=%v", stable, changed, err)
		}
	})
}
