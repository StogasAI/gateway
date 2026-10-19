package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
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
			go func() { defer writer.Close(); done <- runGuest(clock, gateway, shutdown, synchronized) }()
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
	err := runGuest(exec.Command(filepath.Join(t.TempDir(), "missing")), gateway, make(chan os.Signal), synchronized)
	if !errors.Is(err, errClockDaemon) || gateway.Process != nil {
		t.Fatal("gateway started without the clock daemon", err)
	}
}

// A guest whose daemon never agrees on the time must still power off when the
// daemon stops or the host asks.
func TestInitStartsTheGatewayOnlyOnceTheClockIsSynchronized(t *testing.T) {
	for _, mode := range []string{"synchronized", "shutdown", "clock-exit"} {
		t.Run(mode, func(t *testing.T) {
			daemonMode := "drain"
			if mode == "clock-exit" {
				daemonMode = "clean-exit"
			}
			gateway := lifecycleChild(t.Context(), "clean-exit")
			shutdown := make(chan os.Signal, 1)
			if mode == "shutdown" {
				shutdown <- syscall.SIGTERM
			}
			checks, early := 0, false
			err := runGuest(lifecycleChild(t.Context(), daemonMode), gateway, shutdown, func() bool {
				checks++
				early = early || gateway.Process != nil
				return mode == "synchronized" && checks == 2
			})
			started := gateway.Process != nil
			if early || started != (mode == "synchronized") || errors.Is(err, errClockDaemon) != (mode == "clock-exit") || (err != nil) != (mode == "clock-exit") {
				t.Fatalf("started %v early %v after %d checks: %v", started, early, checks, err)
			}
		})
	}
}

func synchronized() bool { return true }

func TestInitRaisesAClockThatStartsBeforeTheRelease(t *testing.T) {
	release := time.Unix(1_790_000_000, 0)
	for _, test := range []struct {
		now  time.Time
		want time.Time
	}{
		{now: time.Unix(0, 0), want: release},
		{now: release.Add(-time.Nanosecond), want: release},
		{now: release},
		{now: release.Add(time.Hour)},
	} {
		var set time.Time
		var output bytes.Buffer
		err := raiseClock(&output, test.now, "1790000000", func(t time.Time) error { set = t; return nil })
		if err != nil || !set.Equal(test.want) || (output.Len() > 0) == test.want.IsZero() {
			t.Fatalf("clock %v: set %v, log %q, error %v", test.now, set, output.String(), err)
		}
	}
	if err := raiseClock(io.Discard, time.Unix(0, 0), "", nil); err != nil {
		t.Fatal("a build without a release time changed the clock", err)
	}
	if err := raiseClock(io.Discard, time.Unix(0, 0), "17900000x0", nil); err == nil {
		t.Fatal("init accepted a malformed release time")
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
