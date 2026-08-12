package client_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fun7257/xai-oauth/client"
)

// Fetch one access token and use it manually.
func ExampleClient_Get() {
	// export XAI_OAUTH_SECRET=…  (required; the only secret source)
	c, err := client.New(client.Config{})
	if err != nil {
		panic(err)
	}
	tok, err := c.Get(context.Background())
	switch {
	case errors.Is(err, client.ErrUnreachable):
		fmt.Println("daemon down — run: xai-oauth serve")
	case errors.Is(err, client.ErrReauthRequired):
		fmt.Println("session expired — run: xai-oauth serve")
	case err != nil:
		panic(err)
	}
	_ = tok // Authorization: Bearer <tok> → https://api.x.ai/...
}

// Let the SDK inject the bearer automatically: requests to https://…x.ai
// get a fresh token per call; all other hosts pass through untouched.
func ExampleClient_HTTPClient() {
	c, err := client.New(client.Config{})
	if err != nil {
		panic(err)
	}
	hc := c.HTTPClient()
	resp, err := hc.Get("https://api.x.ai/v1/models")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}

// Block until the daemon is ready, e.g. right after starting xai-oauth serve.
func ExampleClient_WaitReady() {
	c, err := client.New(client.Config{})
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.WaitReady(ctx); err != nil {
		panic(err)
	}
}
