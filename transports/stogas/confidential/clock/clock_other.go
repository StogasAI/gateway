//go:build !linux

package clock

// Synchronized requires the Linux kernel's NTP state.
func Synchronized() bool {
	return false
}
