package ocsf

import "testing"

func TestUUIDv5Vector(t *testing.T) {
	// RFC 9562, Appendix A.4.
	dns := mustUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if got := uuid5(dns, "www.example.com"); got != "2ed6657d-e927-568b-95e1-2665a8aea6a2" {
		t.Fatalf("got %s", got)
	}
}
