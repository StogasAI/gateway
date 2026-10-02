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
	"syscall"
	"testing"
	"testing/iotest"
	"time"
)

func TestInitSupervisesGracefulAndUnexpectedExit(t *testing.T) {
	for _, mode := range []string{"drain", "clean-exit", "crash"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInitLifecycleChild$")
			command.Env = append(os.Environ(), "STOGAS_INIT_TEST_CHILD="+mode)
			output, writer := io.Pipe()
			defer output.Close()
			command.Stdout = writer
			shutdown := make(chan os.Signal, 1)
			done := make(chan error, 1)
			go func() { defer writer.Close(); done <- runGateway(command, shutdown) }()
			scanner := bufio.NewScanner(output)
			if !scanner.Scan() || scanner.Text() != "ready" {
				t.Fatal("child did not start")
			}
			if mode == "drain" {
				shutdown <- syscall.SIGTERM
				if !scanner.Scan() || scanner.Text() != "drained" {
					t.Fatal("init did not let the child drain")
				}
			}
			err := <-done
			if (err != nil) != (mode == "crash") {
				t.Fatalf("exit error: %v", err)
			}
		})
	}
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
