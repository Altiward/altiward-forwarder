package main

import "testing"

func TestProbeURL(t *testing.T) {
	cases := map[string]string{
		":8081":          "http://127.0.0.1:8081/healthz",
		"0.0.0.0:9000":   "http://127.0.0.1:9000/healthz",
		"[::]:9000":      "http://127.0.0.1:9000/healthz",
		"127.0.0.1:8081": "http://127.0.0.1:8081/healthz",
		"10.1.2.3:8081":  "http://10.1.2.3:8081/healthz",
	}
	for addr, want := range cases {
		if got := probeURL(addr); got != want {
			t.Errorf("probeURL(%q) = %q, want %q", addr, got, want)
		}
	}
}
