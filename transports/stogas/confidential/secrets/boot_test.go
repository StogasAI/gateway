package secrets

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
)

func TestBootSecretsInstallOnceAndEraseOwnedBytes(t *testing.T) {
	var values []provision.BootSecretValue
	for _, name := range requiredSecretNames {
		values = append(values, provision.BootSecretValue{KeyID: name, Name: name, Plaintext: "secret", Version: "1"})
	}
	store := NewStore()
	for _, bad := range [][]provision.BootSecretValue{nil, values[:1], append(append([]provision.BootSecretValue(nil), values...), values[0])} {
		if err := store.InstallBoot(bad); err == nil || store.Ready() {
			t.Fatal("partial or duplicate secrets installed")
		}
	}
	var installed atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if store.InstallBoot(values) == nil {
				installed.Add(1)
			}
		})
	}
	group.Wait()
	if installed.Load() != 1 || !store.Ready() {
		t.Fatal("boot secrets installed more than once")
	}
	owned := store.secrets[requiredSecretNames[0]].Value
	copy, ok := store.Get(requiredSecretNames[0])
	if !ok {
		t.Fatal("installed secret unavailable")
	}
	copy.Value[0] = '!'
	if string(owned) != "secret" {
		t.Fatal("caller changed retained secret")
	}
	store.Close()
	store.Close()
	if store.Ready() || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("close retained owned secret bytes")
	}
	if store.InstallBoot(values) == nil {
		t.Fatal("closed store reopened")
	}
}
