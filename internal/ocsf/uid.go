package ocsf

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/privileges"
)

// uidNamespace is the forwarder's UUIDv5 namespace. Never change it: SIEMs deduplicate
// resent events by metadata.uid.
var uidNamespace = mustUUID("36b137d3-b12a-425c-9a5e-88aa29c98cbd")

// UID names a change the same way however often Privileges sends it. The versioned,
// structured name preserves source precision and separates configured sites without using
// their secrets. Delayed, receipt time and product version can change on a retry.
func UID(e privileges.Event, m Meta) string {
	expires := ""
	if e.Expires != nil {
		expires = identityTime(*e.Expires, e.ExpiresFractionTail)
	}
	identity := struct {
		Version                         int
		Via                             Via
		Tenant, URLSecret               string
		Machine, Serial, User           string
		Granted                         bool
		At, Expires, Reason, Transition string
		Custom                          map[string]any
	}{
		Version: 2, Via: m.Via, Tenant: m.TenantUID, URLSecret: m.URLSecretName,
		Machine: e.Machine, Serial: e.Serial, User: e.User, Granted: e.Granted,
		At: identityTime(e.At, e.AtFractionTail), Expires: expires, Reason: e.Reason,
		Transition: e.TransitionID, Custom: e.Custom,
	}
	// Custom comes from the JSON decoder (or is nil for the hook), so it contains only
	// JSON values. Marshal sorts object keys, keeping reordered webhook retries stable.
	name, _ := json.Marshal(identity)
	return uuid5(uidNamespace, string(name))
}

func identityTime(at time.Time, fractionTail string) string {
	if fractionTail == "" {
		return at.UTC().Format(time.RFC3339Nano)
	}
	return at.UTC().Format("2006-01-02T15:04:05.000000000") + fractionTail + "Z"
}

// uuid5 is RFC 9562's name-based UUID (section 5.5), using SHA-1.
func uuid5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = u[6]&0x0f | 0x50
	u[8] = u[8]&0x3f | 0x80
	s := hex.EncodeToString(u[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

func mustUUID(s string) [16]byte {
	var u [16]byte
	b, err := hex.DecodeString(s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36])
	if err != nil || len(s) != 36 {
		panic("ocsf: bad UUID " + s)
	}
	copy(u[:], b)
	return u
}
