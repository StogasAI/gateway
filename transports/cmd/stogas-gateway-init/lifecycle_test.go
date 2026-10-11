package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"testing/iotest"
	"time"
)

func TestInitSupervisesGatewayAndClockDaemon(t *testing.T) {
	for _, mode := range []string{"drain", "clean-exit", "crash", "clock-exit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			clockInput, clockControl, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer clockInput.Close()
			defer clockControl.Close()
			clock := lifecycleChild(ctx, "exit-on-eof")
			clock.Stdin = clockInput
			gatewayMode := mode
			if mode == "clock-exit" {
				gatewayMode = "drain"
			}
			gateway := lifecycleChild(ctx, gatewayMode)
			output, writer := io.Pipe()
			defer output.Close()
			gateway.Stdout = writer
			shutdown := make(chan os.Signal, 1)
			done := make(chan error, 1)
			go func() { defer writer.Close(); done <- runGuest(clock, gateway, shutdown) }()
			scanner := bufio.NewScanner(output)
			if !scanner.Scan() || scanner.Text() != "ready" {
				t.Fatal("gateway did not start")
			}
			switch mode {
			case "drain":
				shutdown <- syscall.SIGTERM
			case "clock-exit":
				_ = clockControl.Close()
			}
			if gatewayMode == "drain" && (!scanner.Scan() || scanner.Text() != "drained") {
				t.Fatal("init did not let the gateway drain")
			}
			err = <-done
			if errors.Is(err, errClockDaemon) != (mode == "clock-exit") || (err != nil) != (mode == "crash" || mode == "clock-exit") {
				t.Fatalf("exit error: %v", err)
			}
		})
	}
}

func TestInitDoesNotStartTheGatewayWithoutTheClockDaemon(t *testing.T) {
	gateway := lifecycleChild(t.Context(), "clean-exit")
	err := runGuest(exec.Command(filepath.Join(t.TempDir(), "missing")), gateway, make(chan os.Signal))
	if !errors.Is(err, errClockDaemon) || gateway.Process != nil {
		t.Fatal("gateway started without the clock daemon", err)
	}
}

func lifecycleChild(ctx context.Context, mode string) *exec.Cmd {
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInitLifecycleChild$")
	command.Env = append(os.Environ(), "STOGAS_INIT_TEST_CHILD="+mode)
	return command
}

func TestInitLifecycleChild(t *testing.T) {
	mode := os.Getenv("STOGAS_INIT_TEST_CHILD")
	if mode == "" {
		return
	}
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGTERM)
	fmt.Println("ready")
	switch mode {
	case "drain":
		<-shutdown
		fmt.Println("drained")
	case "crash":
		os.Exit(7)
	case "exit-on-eof":
		_, _ = io.Copy(io.Discard, os.Stdin)
	}
	os.Exit(0)
}

func TestPowerButtonFramingAndRepeatedEvents(t *testing.T) {
	encode := func(kind, code uint16, value uint32) []byte {
		encoded := make([]byte, 24)
		binary.LittleEndian.PutUint16(encoded[16:], kind)
		binary.LittleEndian.PutUint16(encoded[18:], code)
		binary.LittleEndian.PutUint32(encoded[20:], value)
		return encoded
	}
	shutdown := make(chan os.Signal, 1)
	ignored := bytes.Join([][]byte{encode(0, 116, 1), encode(1, 115, 1), encode(1, 116, 0), encode(1, 116, 2)}, nil)
	if err := readPowerButton(iotest.OneByteReader(bytes.NewReader(ignored)), shutdown); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if len(shutdown) != 0 {
		t.Fatal("non-press event triggered shutdown")
	}
	if err := readPowerButton(iotest.OneByteReader(bytes.NewReader(bytes.Repeat(encode(1, 116, 1), 100))), shutdown); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if len(shutdown) != 1 || <-shutdown != syscall.SIGTERM {
		t.Fatal("power button did not coalesce shutdown")
	}
	for length := 1; length < 24; length++ {
		if err := readPowerButton(bytes.NewReader(encode(1, 116, 1)[:length]), shutdown); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("length %d: %v", length, err)
		}
		if len(shutdown) != 0 {
			t.Fatal("truncated event triggered shutdown")
		}
	}
}
