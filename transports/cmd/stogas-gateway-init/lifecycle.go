package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var errClockDaemon = errors.New("clock daemon stopped")

// releaseTime is the release commit time in Unix seconds. Release builds set
// it with -X, and local builds leave it empty.
var releaseTime string

// raiseClock moves a boot clock that is earlier than the release up to the
// release time. The host sets the clock at boot, and an earlier clock would let
// the NTS daemon accept TLS certificates that expired before the release.
func raiseClock(output io.Writer, now time.Time, release string, set func(time.Time) error) error {
	if release == "" {
		return nil
	}
	seconds, err := strconv.ParseInt(release, 10, 64)
	if err != nil {
		return err
	}
	floor := time.Unix(seconds, 0)
	if !now.Before(floor) {
		return nil
	}
	if err := set(floor); err != nil {
		return err
	}
	writeInitEvent(output, "guest_init_warning", "warn", initClockRaised)
	return nil
}

func setClock(t time.Time) error {
	tv := syscall.NsecToTimeval(t.UnixNano())
	return syscall.Settimeofday(&tv)
}

// runGuest starts the gateway only after the NTS daemon has synchronized the
// clock, in every mode: Postgres checks the gateway's authorization deadline by
// its own clock, and evidence, registration and certificates check validity
// times. The daemon exits when the clock would need a step larger than its
// limit after boot. The gateway then drains as it does at shutdown, and the
// guest powers off instead of restarting either process.
func runGuest(daemon, gateway *exec.Cmd, shutdown <-chan os.Signal, synchronized func() bool) error {
	if err := daemon.Start(); err != nil {
		return fmt.Errorf("%w: %w", errClockDaemon, err)
	}
	clockExited := make(chan struct{})
	go func() { _ = daemon.Wait(); close(clockExited) }()
	for !synchronized() {
		select {
		case <-shutdown:
			return nil
		case <-clockExited:
			return errClockDaemon
		case <-time.After(time.Second):
		}
	}
	if err := gateway.Start(); err != nil {
		return err
	}
	gatewayExited := make(chan error, 1)
	go func() { gatewayExited <- gateway.Wait() }()
	var err error
	select {
	case err := <-gatewayExited:
		return err
	case <-shutdown:
	case <-clockExited:
		err = errClockDaemon
	}
	_ = gateway.Process.Signal(syscall.SIGTERM)
	return errors.Join(err, <-gatewayExited)
}

func watchPowerButtons(shutdown chan<- os.Signal) func() {
	names, _ := filepath.Glob("/sys/class/input/event*/device/name")
	var files []*os.File
	for _, path := range names {
		name, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(name)) != "Power Button" {
			continue
		}
		device := filepath.Base(filepath.Dir(filepath.Dir(path)))
		file, err := os.Open(filepath.Join("/dev/input", device))
		if err != nil {
			continue
		}
		files = append(files, file)
		go func() { _ = readPowerButton(file, shutdown) }()
	}
	return func() {
		for _, file := range files {
			_ = file.Close()
		}
	}
}

func readPowerButton(reader io.Reader, shutdown chan<- os.Signal) error {
	// Linux x86-64 input_event: two 64-bit timestamps, type/code, 32-bit value.
	var event [24]byte
	for {
		if _, err := io.ReadFull(reader, event[:]); err != nil {
			return err
		}
		if binary.LittleEndian.Uint16(event[16:18]) == 1 && binary.LittleEndian.Uint16(event[18:20]) == 116 && binary.LittleEndian.Uint32(event[20:24]) == 1 {
			select {
			case shutdown <- syscall.SIGTERM:
			default:
			}
		}
	}
}
