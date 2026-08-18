module github.com/fun7257/xai-oauth

go 1.26

// Minimum patched toolchain: go1.26.5 stdlib has known CVEs reachable from
// this module (net/http server + client, net/url, crypto/tls, encoding/asn1;
// all fixed in 1.26.6). CI enforces this via a govulncheck gate.
toolchain go1.26.6
