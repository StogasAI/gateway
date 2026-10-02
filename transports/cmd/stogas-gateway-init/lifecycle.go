package main

import (
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func runGateway(command *exec.Cmd, shutdown <-chan os.Signal) error {
	if err := command.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	select {
	case err := <-exited:
		return err
	case <-shutdown:
		_ = command.Process.Signal(syscall.SIGTERM)
		return <-exited
	}
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
