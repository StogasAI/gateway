package stogas

import (
	"os"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/catalog/catalogtest"
)

// The tests read a catalog that they own, so a change to the real catalog cannot change what
// they check. A test that checks the gateway against every record of the real catalog calls
// catalogtest.UseFallback.
func TestMain(m *testing.M) {
	if err := catalogtest.Install(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
