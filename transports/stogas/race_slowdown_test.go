//go:build !race

package stogas

// raceSlowdown widens time limits under the race detector; without it, limits apply as written.
const raceSlowdown = 1
