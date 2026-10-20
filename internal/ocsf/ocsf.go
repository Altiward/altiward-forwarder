// Package ocsf maps a Privileges event to the OCSF record the Altiward server emits for the
// same change: User Access Management (3005), Assign (1) or Revoke (2) Privileges. Keep it
// field-for-field with the server's backend/internal/ocsf; TestMatchesAltiwardShape checks
// it against the server's golden output.
package ocsf

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/privileges"
)

// Version is the OCSF schema version, the same as the server's.
const Version = "1.9.0"

// Record is one OCSF event, ready to marshal as JSON.
type Record = map[string]any

// Via says how the forwarder heard about a change. It goes in unmapped.altiward.reported_by;
// source stays "privileges", which the SIEM content keys on.
type Via string

const (
	ViaWebhook Via = "privileges_webhook"
	ViaHook    Via = "privileges_hook"
)

// Meta is what the record says about the forwarder rather than the change.
type Meta struct {
	Via                       Via
	ReceivedAt                time.Time
	ProductVersion, TenantUID string // TenantUID is left out when empty
	URLSecretName             string // the URL secret the Mac used, in URL-secret mode
}

// FromPrivileges maps one change. Events are marked unverified: they are the Mac's own
// report, which a local admin can switch off; only the Altiward agent checks them.
func FromPrivileges(e privileges.Event, m Meta) Record {
	activityID, activity, eventType := 2, "Revoke Privileges", "elevation.revoked"
	if e.Granted {
		activityID, activity, eventType = 1, "Assign Privileges", "elevation.granted"
	}

	metadata := map[string]any{
		"version":     Version,
		"uid":         UID(e),
		"logged_time": m.ReceivedAt.UnixMilli(),
		"product":     map[string]any{"name": "Altiward Forwarder", "vendor_name": "Altiward", "version": m.ProductVersion},
	}
	if m.TenantUID != "" {
		metadata["tenant_uid"] = m.TenantUID
	}
	if e.Delayed {
		metadata["labels"] = []string{"delayed"}
	}

	os := map[string]any{"name": "macOS", "type": "macOS", "type_id": 300}
	if e.OSVersion != "" {
		os["version"] = e.OSVersion
	}
	device := map[string]any{"os": os}
	if e.Machine != "" {
		device["uid"] = e.Machine
	}
	if e.Serial != "" {
		device["hw_info"] = map[string]any{"serial_number": e.Serial}
	}
	if e.Hostname != "" {
		device["hostname"] = e.Hostname
	}

	altiward := map[string]any{
		"event_type":  eventType,
		"source":      "privileges",
		"reported_by": string(m.Via),
		"verified":    false,
	}
	if e.Reason != "" {
		altiward["reason"] = e.Reason
	}
	if m.URLSecretName != "" {
		altiward["url_secret_name"] = m.URLSecretName
	}
	if e.Expires != nil {
		altiward["expires_time"] = e.Expires.UnixMilli()
	}
	if e.Custom != nil {
		altiward["custom_data"] = e.Custom
	}

	return Record{
		"class_uid":     3005,
		"class_name":    "User Access Management",
		"category_uid":  3,
		"category_name": "Identity & Access Management",
		"activity_id":   activityID,
		"activity_name": activity,
		"type_uid":      3005*100 + activityID,
		"type_name":     "User Access Management: " + activity,
		"time":          e.At.UnixMilli(),
		"severity_id":   1,
		"severity":      "Informational",
		"status_id":     1,
		"status":        "Success",
		"privileges":    []string{"admin"},
		"message":       message(e),
		"metadata":      metadata,
		"device":        device,
		"user":          map[string]any{"name": e.User},
		"unmapped":      map[string]any{"altiward": altiward},
	}
}

// message matches the server's wording, naming the Mac by serial when it's known.
func message(e privileges.Event) string {
	mac := "an unknown Mac"
	switch {
	case e.Serial != "":
		mac = e.Serial
	case e.Machine != "":
		mac = e.Machine
	}
	msg := e.User + "'s admin rights on " + mac + " were revoked via SAP Privileges"
	if e.Granted {
		msg = e.User + " was granted admin rights on " + mac + " via SAP Privileges"
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

func lookup(r Record, path []string) any {
	var v any = map[string]any(r)
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// Str reads the string at path, or "" when there isn't one.
func Str(r Record, path ...string) string {
	s, _ := lookup(r, path).(string)
	return s
}

// Int reads the number at path, whether the record was built here (int, int64) or decoded
// from JSON (float64, or json.Number with UseNumber). It is 0 when there isn't one.
func Int(r Record, path ...string) int {
	switch v := lookup(r, path).(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			f, _ := v.Float64()
			return int(f)
		}
		return int(n)
	}
	return 0
}
