package clock

import "golang.org/x/sys/unix"

// Synchronized reads the kernel's NTP synchronization state.
func Synchronized() bool {
	var timex unix.Timex
	_, err := unix.Adjtimex(&timex)
	return err == nil && timex.Status&unix.STA_UNSYNC == 0
}
