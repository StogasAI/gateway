//go:build race

package stogas

// raceSlowdown widens time limits under the race detector, which the complete test run uses and
// which makes CPU-bound code about ten times slower. A widened limit still fails a change that
// makes the code several times slower.
const raceSlowdown = 4
