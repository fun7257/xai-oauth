//go:build unix

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fun7257/xai-oauth/client"
)

// captureOut runs fn with stdout and stderr redirected into buffers.
func captureOut(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	doneOut := make(chan string)
	doneErr := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, rOut)
		doneOut <- b.String()
	}()
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, rErr)
		doneErr <- b.String()
	}()
	fn()
	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return <-doneOut, <-doneErr
}

// TestCLIVersionCommand drives the real run() version path (same entry as main).
func TestCLIVersionCommand(t *testing.T) {
	prev := version
	version = "v-test-cli-entry"
	t.Cleanup(func() { version = prev })

	out, _ := captureOut(t, func() {
		if err := run([]string{"version"}); err != nil {
			t.Fatalf("run version: %v", err)
		}
	})
	got := strings.TrimSpace(out)
	if got != "v-test-cli-entry" {
		t.Fatalf("version stdout = %q, want embedded version var", got)
	}
}

// TestCLIUsageListsCommands exercises missing-command / help usage text.
func TestCLIUsageListsCommands(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"help"}} {
		name := "empty"
		if len(args) > 0 {
			name = args[0]
		}
		t.Run(name, func(t *testing.T) {
			_, errOut := captureOut(t, func() {
				err := run(args)
				// empty args and unknown return error after printing usage; help returns nil
				if name == "help" {
					if err != nil {
						t.Fatalf("help: %v", err)
					}
					return
				}
				if err == nil {
					t.Fatal("expected error for missing command")
				}
			})
			for _, cmd := range []string{"serve", "status", "token", "logout", "version"} {
				if !strings.Contains(errOut, cmd) {
					t.Fatalf("usage missing %q; stderr=%q", cmd, errOut)
				}
			}
		})
	}
}

// TestCLIStatusDaemonDown hits the real status command against a missing socket.
func TestCLIStatusDaemonDown(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "xo-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "missing.sock")
	_ = os.Remove(sock)

	t.Setenv(client.EnvSecret, "cli-entry-test-secret")
	t.Setenv(client.EnvSocket, sock)

	out, errOut := captureOut(t, func() {
		err := run([]string{"status"})
		if err == nil {
			t.Fatal("expected status error when daemon is down")
		}
		if !strings.Contains(err.Error(), "not reachable") && !strings.Contains(err.Error(), "daemon") {
			t.Fatalf("error = %v", err)
		}
	})
	combined := out + errOut
	if !strings.Contains(combined, "daemon: down") && !strings.Contains(strings.ToLower(combined), "down") {
		t.Fatalf("expected daemon-down messaging; out=%q err=%q", out, errOut)
	}
}
