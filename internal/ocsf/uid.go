package ocsf

import (
	"crypto/sha1"
	"encoding/hex"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/privileges"
)

// uidNamespace is the forwarder's UUIDv5 namespace. Never change it: SIEMs deduplicate
// resent events by metadata.uid.
var uidNamespace = mustUUID("36b137d3-b12a-425c-9a5e-88aa29c98cbd")

// UID names a change the same way however often Privileges sends it, so a resend after a
// lost response is one event in the SIEM.
func UID(e privileges.Event) string {
	event := "corp.sap.privileges.revoked"
	if e.Granted {
		event = "corp.sap.privileges.granted"
	}
	return uuid5(uidNamespace, e.Machine+"|"+event+"|"+e.At.UTC().Format(time.RFC3339)+"|"+e.User)
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
