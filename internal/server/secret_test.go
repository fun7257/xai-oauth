package server

import "testing"

func TestSecretEqual(t *testing.T) {
	if !secretEqual("abc", "abc") {
		t.Fatal("equal")
	}
	if secretEqual("abc", "abd") {
		t.Fatal("unequal")
	}
	if secretEqual("", "x") {
		t.Fatal("empty got")
	}
	if secretEqual("x", "") {
		t.Fatal("empty want")
	}
	if secretEqual("", "") {
		t.Fatal("empty want must never match")
	}
	// Different lengths must not panic and must not match.
	if secretEqual("short", "longer-secret") {
		t.Fatal("length mismatch")
	}
}
