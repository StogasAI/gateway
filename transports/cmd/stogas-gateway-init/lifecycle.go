package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

var errClockDaemon = errors.New("clock daemon stopped")

// runGuest starts the NTS daemon before the gateway, which waits for a
// synchronized clock. The daemon exits when the clock would need a step larger
// than its limit after boot. The gateway then drains as it does at shutdown,
// and the guest powers off instead of restarting either process.
func runGuest(clock, gateway *exec.Cmd, shutdown <-chan os.Signal) error {
	if err := clock.Start(); err != nil {
		return fmt.Errorf("%w: %w", errClockDaemon, err)
	}
	clockExited := make(chan struct{})
	go func() { _ = clock.Wait(); close(clockExited) }()
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
