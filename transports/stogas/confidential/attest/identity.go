package attest

import "encoding/hex"

var nodeAdjectives = [...]string{
	"amber", "bright", "clear", "direct", "early", "firm", "green", "high",
	"inner", "level", "prime", "quiet", "ready", "solid", "steady", "true",
}

var nodeNouns = [...]string{
	"anchor", "beacon", "bridge", "forge", "guard", "harbor", "index", "keystone",
	"ledger", "marker", "nexus", "pivot", "relay", "signal", "vector", "watch",
}

// SNPNodeID formats the canonical name from the hardware guest's REPORT_ID.
// Formatting alone does not verify a report or authorize its identity.
func SNPNodeID(reportID [32]byte) string {
	return nodeAdjectives[reportID[0]>>4] + "-" + nodeNouns[reportID[0]&15] + "-" + hex.EncodeToString(reportID[:])
}
