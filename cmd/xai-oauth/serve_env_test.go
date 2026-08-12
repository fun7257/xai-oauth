//go:build unix

package main

import (
	"slices"
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
