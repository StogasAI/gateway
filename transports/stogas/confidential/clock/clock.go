// Package clock reports whether the guest wall clock agrees with
// authenticated time. The host sets the guest's boot clock, so the guest runs
// an NTS daemon that clears the kernel's unsynchronized flag only after a
// majority of independent sources agree. The kernel sets the flag again when
// its error bound reaches 16 seconds, about nine hours without agreement.
package clock
