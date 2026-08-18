package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/fun7257/xai-oauth/client"
)

func TestDaemonEnvDropsSecret(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		client.EnvSecret + "=super-secret",
		"HOME=/home/u",
		client.EnvSecret + "=dup-entry",
		"HTTPS_PROXY=http://proxy:3128",
		client.EnvSocket + "=/tmp/xo/daemon.sock",
	}
	got := daemonEnv(in)
	want := []string{
		"PATH=/usr/bin",
		"HOME=/home/u",
		"HTTPS_PROXY=http://proxy:3128",
		client.EnvSocket + "=/tmp/xo/daemon.sock",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("daemonEnv = %q, want %q", got, want)
	}
}

func TestServeRejectsShortOperatorSecret(t *testing.T) {
	// Validation happens before any socket probe or login attempt, so this
	// exercises the real serve entry without network or daemon.
	t.Setenv(client.EnvSecret, "short")
	err := run([]string{"serve", "--socket", "/tmp/xo-never-used/never.sock"})
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("err = %v, want too-short secret refusal", err)
	}
}

func TestServeMinLengthSecretPassesValidation(t *testing.T) {
	// A 16-char secret passes the floor; serve then proceeds to the running
	// daemon and fails downstream on secret mismatch — never reaching device
	// login (no network). Distinguishes the floor check from downstream auth.
	sock, _ := startDaemon(t, newReadySession(t), "daemon-real-secret")
	t.Setenv(client.EnvSecret, strings.Repeat("s", minOperatorSecretLen))
	err := run([]string{"serve", "--socket", sock})
	if err == nil || strings.Contains(err.Error(), "too short") {
		t.Fatalf("err = %v, want downstream error, not floor rejection", err)
	}
	if !strings.Contains(err.Error(), "wrong secret") {
		t.Fatalf("err = %v, want wrong-secret refusal", err)
	}
}

func TestDaemonEnvKeepsSimilarNames(t *testing.T) {
	// Only exact XAI_OAUTH_SECRET=… entries are dropped, not lookalikes.
	in := []string{
		client.EnvSecret + "_BACKUP=keep",
		"MY_" + client.EnvSecret + "=keep",
	}
	got := daemonEnv(in)
	if !slices.Equal(got, in) {
		t.Fatalf("daemonEnv = %q, want unchanged %q", got, in)
	}
}
