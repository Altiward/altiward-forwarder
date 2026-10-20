// Package webhook posts OCSF records to an HTTPS endpoint, for SIEMs and collectors that
// take JSON over HTTP. The on-Mac hook offers it as a destination.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
)

// Client posts a batch of records as one JSON array. Any 2xx answer means accepted.
type Client struct {
	URL     string
	Headers map[string]string
	HTTP    *http.Client // http.DefaultClient when nil; the caller's context sets the deadline
}

func (c Client) Name() string { return "webhook" }

func (c Client) Send(ctx context.Context, records []ocsf.Record) error {
	body, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("webhook: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}
