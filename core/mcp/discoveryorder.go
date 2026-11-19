package mcp

// beginDiscovery numbers a discovery of clientID's tools as its list begins. writeBackDiscovery
// drops a result that began before the installed one, so a connection check that listed before an
// upstream change cannot put back the tool set that a later refresh installed.
func (m *MCPManager) beginDiscovery(clientID string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.clientMap[clientID]
	if !ok {
		return 0
	}
	state.DiscoverySeq++
	return state.DiscoverySeq
}
