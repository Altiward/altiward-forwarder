// Package privileges decodes the webhook SAP Privileges sends on each change of admin rights
// (RemoteLogging with ServerType webhook). The body's shape comes from Privileges 2.6's
// MTWebhook.m; testdata/privileges-2.6 has examples.
package privileges

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MaxBody is the largest body Decode accepts. A real body is well under 1 KiB.
const MaxBody = 64 << 10

var ErrTooLarge = errors.New("privileges: body over 64 KiB")

const (
	eventGranted = "corp.sap.privileges.granted"
	eventRevoked = "corp.sap.privileges.revoked"
)

// Event is one change of admin rights, as Privileges reported it.
type Event struct {
	Granted               bool
	User, Machine, Reason string // Machine is the hardware UUID; Machine and Reason may be empty
	At                    time.Time
	Expires               *time.Time // nil when Privileges reports no expiry
	Delayed               bool       // Privileges queued the event and sent it later
	Custom                map[string]any

	// Set by the on-Mac hook, which can read them; the webhook doesn't send them.
	Serial, Hostname, OSVersion string
}

type body struct {
	Admin     *bool           `json:"admin"`
	Custom    json.RawMessage `json:"custom_data"`
	Delayed   bool            `json:"delayed"`
	Event     string          `json:"event"`
	Expires   string          `json:"expires"`
	Machine   string          `json:"machine"`
	Reason    string          `json:"reason"`
	Timestamp string          `json:"timestamp"`
	User      string          `json:"user"`
}

// Decode reads one webhook body. It ignores keys it doesn't know, because Privileges may add
// some, and rejects a body without the event, user and time.
func Decode(data []byte) (Event, error) {
	if len(data) > MaxBody {
		return Event{}, ErrTooLarge
	}
	var b body
	if err := json.Unmarshal(data, &b); err != nil {
		return Event{}, fmt.Errorf("privileges: %w", err)
	}

	var e Event
	switch b.Event {
	case eventGranted:
		e.Granted = true
	case eventRevoked:
	case "":
		return Event{}, errors.New(`privileges: missing "event"`)
	default:
		return Event{}, fmt.Errorf(`privileges: unknown "event" %q`, b.Event)
	}
	// Privileges derives both from the same admin check, so a mismatch isn't Privileges.
	if b.Admin != nil && *b.Admin != e.Granted {
		return Event{}, fmt.Errorf(`privileges: "admin" %v contradicts "event" %q`, *b.Admin, b.Event)
	}
	if b.User == "" {
		return Event{}, errors.New(`privileges: missing "user"`)
	}
	if b.Timestamp == "" {
		return Event{}, errors.New(`privileges: missing "timestamp"`)
	}
	at, err := time.Parse(time.RFC3339, b.Timestamp)
	if err != nil {
		return Event{}, fmt.Errorf(`privileges: "timestamp": %w`, err)
	}
	if b.Expires != "" {
		exp, err := time.Parse(time.RFC3339, b.Expires)
		if err != nil {
			return Event{}, fmt.Errorf(`privileges: "expires": %w`, err)
		}
		e.Expires = &exp
	}
	if len(b.Custom) > 0 {
		// Numbers stay as written: an asset or ticket ID can be too large for a float64.
		dec := json.NewDecoder(bytes.NewReader(b.Custom))
		dec.UseNumber()
		var custom map[string]any
		if dec.Decode(&custom) == nil && len(custom) > 0 {
			e.Custom = custom
		}
	}
	e.User, e.Machine, e.Reason, e.At, e.Delayed = b.User, b.Machine, b.Reason, at, b.Delayed
	return e, nil
}
