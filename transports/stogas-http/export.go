package stogashttp

import "github.com/maximhq/bifrost/transports/stogas/plugins/exporter"

type exportMemoryLease struct{ lease *requestMemoryLease }

func (l exportMemoryLease) Grow(n int) bool { return l.lease.grow(n) }
func (l exportMemoryLease) Release()        { l.lease.release() }
func (s *Server) exportLease() exporter.Lease {
	return exportMemoryLease{s.memory.newLease(requestLifetimeMemory)}
}
