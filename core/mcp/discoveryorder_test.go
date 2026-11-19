package mcp

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A connection check that began listing before a refresh and finished after it must not put
// back the older tool set or fire the change callback for it.
func TestWriteBackDiscoveryDropsADiscoveryThatBeganEarlier(t *testing.T) {
	m := NewMCPManager(context.Background(), schemas.MCPConfig{}, nil, &MockLogger{}, nil)
	config := &schemas.MCPClientConfig{ID: "c", Name: "c"}
	m.mu.Lock()
	m.clientMap[config.ID] = &schemas.MCPClientState{Name: config.Name, ExecutionConfig: config}
	m.mu.Unlock()
	fired := 0
	m.SetDiscoveryChangeCallback(func(string, string, *schemas.MCPDiscovery) { fired++ })

	check := m.beginDiscovery(config.ID)
	refresh := m.beginDiscovery(config.ID)
	require.True(t, m.writeBackDiscovery(config.ID, 0, refresh, &schemas.MCPDiscovery{Tools: map[string]schemas.ChatTool{"old": {}, "new": {}}}, false))
	assert.False(t, m.writeBackDiscovery(config.ID, 0, check, &schemas.MCPDiscovery{Tools: map[string]schemas.ChatTool{"old": {}}}, false))

	assert.Contains(t, m.installedDiscovery(config).GetTools(), "new")
	assert.Equal(t, 1, fired)
}
